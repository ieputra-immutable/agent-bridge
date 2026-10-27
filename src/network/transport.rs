//! Bounded authenticated QUIC and encrypted TCP transport. Application policy and persistence live elsewhere.
use super::{
    discovery::{DISCOVERY_TTL, DiscoveryCache},
    wire::{WireRequest, WireResponse},
};
use crate::protocol::MAX_FRAME;
use anyhow::{Context, Result, anyhow};
use either::Either;
use futures::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt, future::BoxFuture,
    stream::FuturesUnordered,
};
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder, autonat, connection_limits,
    core::{Endpoint, transport::PortUse},
    dcutr, identify, mdns,
    multiaddr::Protocol,
    noise, relay, rendezvous,
    request_response::{self, Codec, ProtocolSupport},
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, SwarmEvent, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm, behaviour::toggle::Toggle, dummy,
    },
    tcp, yamux,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    convert::Infallible,
    io,
    sync::{Arc, RwLock},
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};

const CAPACITY: usize = 32;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const PAIRING_FRAME: usize = 4096;
const PAIRING_PROTOCOL: StreamProtocol = StreamProtocol::new("/agent-bridge/pairing/1");
const PROTOCOL: StreamProtocol = StreamProtocol::new("/agent-bridge/message/1");

#[derive(Clone, Default)]
struct JsonCodec;

async fn read_frame<T: AsyncRead + Unpin, R: DeserializeOwned>(io: &mut T) -> io::Result<R> {
    read_frame_limit(io, MAX_FRAME).await
}

async fn read_frame_limit<T: AsyncRead + Unpin, R: DeserializeOwned>(
    io: &mut T,
    limit: usize,
) -> io::Result<R> {
    let mut header = [0; 4];
    io.read_exact(&mut header).await?;
    let length = u32::from_be_bytes(header) as usize;
    if length > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "network frame exceeds limit",
        ));
    }
    let mut body = vec![0; length];
    io.read_exact(&mut body).await?;
    serde_json::from_slice(&body)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid network message"))
}

struct LimitedBuffer(Vec<u8>, usize);

impl io::Write for LimitedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.1.saturating_sub(self.0.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "frame exceeds 256 KiB",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn write_frame<T: AsyncWrite + Unpin, R: Serialize>(io: &mut T, value: R) -> io::Result<()> {
    write_frame_limit(io, value, MAX_FRAME).await
}

async fn write_frame_limit<T: AsyncWrite + Unpin, R: Serialize>(
    io: &mut T,
    value: R,
    limit: usize,
) -> io::Result<()> {
    let mut buffer = LimitedBuffer(Vec::new(), limit);
    serde_json::to_writer(&mut buffer, &value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "network message exceeds frame limit",
        )
    })?;
    io.write_all(&(buffer.0.len() as u32).to_be_bytes()).await?;
    io.write_all(&buffer.0).await?;
    io.close().await
}

impl Codec for JsonCodec {
    type Protocol = StreamProtocol;
    type Request = WireRequest;
    type Response = WireResponse;

    async fn read_request<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<WireRequest> {
        read_frame(io).await
    }
    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<WireResponse> {
        read_frame(io).await
    }
    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        request: WireRequest,
    ) -> io::Result<()> {
        write_frame(io, request).await
    }
    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        response: WireResponse,
    ) -> io::Result<()> {
        write_frame(io, response).await
    }
}

#[derive(Clone, Default)]
struct PairingCodec;
impl Codec for PairingCodec {
    type Protocol = StreamProtocol;
    type Request = Value;
    type Response = Value;
    async fn read_request<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<Value> {
        read_frame_limit(io, PAIRING_FRAME).await
    }
    async fn read_response<T: AsyncRead + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<Value> {
        read_frame_limit(io, PAIRING_FRAME).await
    }
    async fn write_request<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        value: Value,
    ) -> io::Result<()> {
        write_frame_limit(io, value, PAIRING_FRAME).await
    }
    async fn write_response<T: AsyncWrite + Unpin + Send>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        value: Value,
    ) -> io::Result<()> {
        write_frame_limit(io, value, PAIRING_FRAME).await
    }
}

// Opening a pairing window permits authenticated connections, not message access.
// Application message checks always consult `trusted`, independently of this gate.
struct Admission {
    trusted: HashSet<PeerId>,
    pairing_enabled: bool,
    infrastructure: HashSet<PeerId>,
    established: HashMap<ConnectionId, PeerId>,
    contacts: HashMap<ConnectionId, bool>,
}
impl Admission {
    fn enforce(&self, peer: &PeerId) -> Result<(), ConnectionDenied> {
        let peer_limit = if self.infrastructure.contains(peer) {
            3
        } else {
            2
        };
        if self
            .established
            .values()
            .filter(|actual| *actual == peer)
            .count()
            >= peer_limit
        {
            return Err(ConnectionDenied::new(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Peer connection capacity reached",
            )));
        }
        let untrusted = self
            .established
            .values()
            .filter(|peer| !self.trusted.contains(peer) && !self.infrastructure.contains(peer))
            .count();
        if self.trusted.contains(peer)
            || self.infrastructure.contains(peer)
            || (self.pairing_enabled && untrusted < 4)
        {
            Ok(())
        } else {
            Err(ConnectionDenied::new(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "peer is not trusted and pairing is closed",
            )))
        }
    }
}
impl NetworkBehaviour for Admission {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;
    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.enforce(&peer)?;
        Ok(dummy::ConnectionHandler)
    }
    fn handle_pending_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: Option<PeerId>,
        _: &[Multiaddr],
        _: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if let Some(active) = self.contacts.get(&id) {
            if *active {
                return Ok(Vec::new());
            }
            return Err(ConnectionDenied::new(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Contact lookup expired",
            )));
        }
        if let Some(peer) = peer {
            self.enforce(&peer)?;
        }
        Ok(Vec::new())
    }
    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if let Some(active) = self.contacts.get(&id) {
            if *active {
                return Ok(dummy::ConnectionHandler);
            }
            return Err(ConnectionDenied::new(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Contact lookup expired",
            )));
        }
        self.enforce(&peer)?;
        Ok(dummy::ConnectionHandler)
    }
    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(event) => {
                self.established.insert(event.connection_id, event.peer_id);
            }
            FromSwarm::ConnectionClosed(event) => {
                self.established.remove(&event.connection_id);
            }
            _ => {}
        }
    }
    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }
    fn poll(
        &mut self,
        _: &mut TaskContext<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

// Per-second budgets bound both work and identity bookkeeping under key churn.
struct PairingRate {
    started: Instant,
    total: usize,
    peers: HashMap<PeerId, usize>,
}
impl PairingRate {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            total: 0,
            peers: HashMap::new(),
        }
    }
    fn allow(&mut self, peer: PeerId) -> bool {
        if self.started.elapsed() >= Duration::from_secs(1) {
            self.started = Instant::now();
            self.total = 0;
            self.peers.clear();
        }
        if self.total >= 32 {
            return false;
        }
        let count = self.peers.entry(peer).or_default();
        if *count >= 8 {
            return false;
        }
        *count += 1;
        self.total += 1;
        true
    }
}

// NAT protocols are narrower than the connection admission gate. Pairing-only
// peers get dummy handlers; only pinned infrastructure may perform reachability
// probes, and only already trusted endpoints may coordinate hole punching.
#[derive(Clone, Copy, PartialEq, Eq)]
enum NatScope {
    Infrastructure,
    TrustedEndpoint,
}
struct NatPolicy {
    trusted: HashSet<PeerId>,
    infrastructure: HashSet<PeerId>,
    allow_loopback: bool,
    allow_private: bool,
}
impl NatPolicy {
    fn permits(&self, scope: NatScope, peer: &PeerId) -> bool {
        match scope {
            NatScope::Infrastructure => self.infrastructure.contains(peer),
            NatScope::TrustedEndpoint => {
                self.trusted.contains(peer) && !self.infrastructure.contains(peer)
            }
        }
    }
}
struct ScopedNat<B> {
    inner: B,
    scope: NatScope,
    policy: Arc<RwLock<NatPolicy>>,
    connections: HashSet<ConnectionId>,
    pending: HashSet<ConnectionId>,
    attempts: HashMap<PeerId, (Instant, u32)>,
}
impl<B> ScopedNat<B> {
    fn new(inner: B, scope: NatScope, policy: Arc<RwLock<NatPolicy>>) -> Self {
        Self {
            inner,
            scope,
            policy,
            connections: HashSet::new(),
            pending: HashSet::new(),
            attempts: HashMap::new(),
        }
    }
    fn permits(&self, peer: &PeerId) -> bool {
        self.policy.read().unwrap().permits(self.scope, peer)
    }
}
fn direct_quic(
    address: &Multiaddr,
    target: Option<PeerId>,
    allow_loopback: bool,
    allow_private: bool,
) -> Option<Multiaddr> {
    if address.to_string().len() > 256 {
        return None;
    }
    let mut parts = address.iter();
    let ip = match parts.next()? {
        Protocol::Ip4(ip) => std::net::IpAddr::V4(ip),
        Protocol::Ip6(ip) => std::net::IpAddr::V6(ip),
        _ => return None,
    };
    if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() && !allow_loopback {
        return None;
    }
    let nonpublic = match ip {
        std::net::IpAddr::V4(ip) => {
            if ip.is_link_local()
                || ip.is_broadcast()
                || ip.octets()[0] == 0
                || ip.octets()[0] >= 240
                || ip.octets()[..3] == [192, 0, 0]
                || ip.octets()[..3] == [192, 0, 2]
                || ip.octets()[..3] == [198, 51, 100]
                || ip.octets()[..3] == [203, 0, 113]
            {
                return None;
            }
            ip.is_private()
                || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
                || ip.octets()[0] == 198 && (ip.octets()[1] == 18 || ip.octets()[1] == 19)
        }
        std::net::IpAddr::V6(ip) => {
            if ip.is_unicast_link_local()
                || ip.to_ipv4_mapped().is_some()
                || (ip.to_ipv4().is_some() && !ip.is_loopback())
            {
                return None;
            }
            ip.is_unique_local() || ip.segments()[0] & 0xffc0 == 0xfec0
        }
    };
    if nonpublic && !allow_private {
        return None;
    }
    let Protocol::Udp(port) = parts.next()? else {
        return None;
    };
    if port == 0 {
        return None;
    }
    if !matches!(parts.next(), Some(Protocol::QuicV1)) {
        return None;
    }
    if let Some(part) = parts.next() {
        if !matches!(part,Protocol::P2p(peer) if Some(peer)==target) {
            return None;
        }
        if parts.next().is_some() {
            return None;
        }
    }
    let mut bare = Multiaddr::empty();
    match ip {
        std::net::IpAddr::V4(ip) => bare.push(Protocol::Ip4(ip)),
        std::net::IpAddr::V6(ip) => bare.push(Protocol::Ip6(ip)),
    };
    bare.push(Protocol::Udp(port));
    bare.push(Protocol::QuicV1);
    Some(bare)
}
impl<B: NetworkBehaviour> NetworkBehaviour for ScopedNat<B> {
    type ConnectionHandler = Either<THandler<B>, dummy::ConnectionHandler>;
    type ToSwarm = B::ToSwarm;
    fn handle_pending_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: Option<PeerId>,
        addresses: &[Multiaddr],
        role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if self.scope == NatScope::TrustedEndpoint && self.pending.contains(&id) {
            let policy = self.policy.read().unwrap();
            if !peer.is_some_and(|p| policy.permits(self.scope, &p))
                || addresses.is_empty()
                || addresses.len() > 4
                || addresses.iter().any(|a| {
                    direct_quic(a, peer, policy.allow_loopback, policy.allow_private).is_none()
                })
            {
                return Err(ConnectionDenied::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Hole punch destination is not permitted",
                )));
            }
        }
        self.inner
            .handle_pending_outbound_connection(id, peer, addresses, role)
    }
    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if self.permits(&peer)
            && (self.scope == NatScope::TrustedEndpoint
                || !local.iter().any(|p| matches!(p, Protocol::P2pCircuit)))
        {
            let handler = self
                .inner
                .handle_established_inbound_connection(id, peer, local, remote)?;
            self.connections.insert(id);
            Ok(Either::Left(handler))
        } else {
            Ok(Either::Right(dummy::ConnectionHandler))
        }
    }
    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        address: &Multiaddr,
        role: Endpoint,
        port: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if self.permits(&peer)
            && (self.scope == NatScope::TrustedEndpoint
                || !address.iter().any(|p| matches!(p, Protocol::P2pCircuit)))
        {
            let handler = self
                .inner
                .handle_established_outbound_connection(id, peer, address, role, port)?;
            self.connections.insert(id);
            self.pending.remove(&id);
            Ok(Either::Left(handler))
        } else {
            Ok(Either::Right(dummy::ConnectionHandler))
        }
    }
    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::NewExternalAddrCandidate(_) => {}
            FromSwarm::ConnectionEstablished(e) => {
                if self.connections.contains(&e.connection_id) {
                    self.inner.on_swarm_event(event);
                }
            }
            FromSwarm::ConnectionClosed(e) => {
                if self.connections.remove(&e.connection_id) {
                    self.inner.on_swarm_event(event);
                }
            }
            FromSwarm::DialFailure(e) => {
                self.pending.remove(&e.connection_id);
                self.inner.on_swarm_event(event);
            }
            _ => self.inner.on_swarm_event(event),
        }
    }
    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            Either::Left(event) => {
                if self.permits(&peer) && self.connections.contains(&id) {
                    self.inner.on_connection_handler_event(peer, id, event);
                }
            }
            Either::Right(never) => match never {},
        }
    }
    fn poll(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        loop {
            let event = match self.inner.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(event) => event,
            };
            match &event {
                ToSwarm::NotifyHandler { peer_id, .. } if !self.permits(peer_id) => continue,
                ToSwarm::NewExternalAddrCandidate { .. }
                | ToSwarm::NewExternalAddrOfPeer { .. }
                | ToSwarm::ExternalAddrConfirmed(_) => continue,
                ToSwarm::Dial { opts } if self.scope == NatScope::TrustedEndpoint => {
                    let permitted = opts.get_peer_id().is_some_and(|peer| self.permits(&peer));
                    let now = Instant::now();
                    {
                        let policy = self.policy.read().unwrap();
                        let scope = self.scope;
                        self.attempts.retain(|peer, (at, _)| {
                            policy.permits(scope, peer)
                                && now.duration_since(*at) < Duration::from_secs(30)
                        });
                    }
                    let capacity = self.attempts.len() < 32
                        || opts
                            .get_peer_id()
                            .is_some_and(|peer| self.attempts.contains_key(&peer));
                    let allowed = permitted
                        && capacity
                        && self.pending.len() < 16
                        && opts.get_peer_id().is_some_and(|peer| {
                            let (_, count) = self.attempts.entry(peer).or_insert((now, 0));
                            if *count >= 3 {
                                false
                            } else {
                                *count += 1;
                                true
                            }
                        });
                    if !allowed {
                        self.inner.on_swarm_event(FromSwarm::DialFailure(
                            libp2p::swarm::behaviour::DialFailure {
                                peer_id: opts.get_peer_id(),
                                connection_id: opts.connection_id(),
                                error: &libp2p::swarm::DialError::Aborted,
                            },
                        ));
                        continue;
                    }
                    self.pending.insert(opts.connection_id());
                }
                _ => {}
            }
            return Poll::Ready(event.map_in(Either::Left));
        }
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "BehaviourEvent")]
struct Behaviour {
    allowed: Admission,
    limits: connection_limits::Behaviour,
    messages: request_response::Behaviour<JsonCodec>,
    pairing: request_response::Behaviour<PairingCodec>,
    discovery: Toggle<HintOnlyMdns>,
    relay: relay::client::Behaviour,
    rendezvous: rendezvous::client::Behaviour,
    identify: identify::Behaviour,
    dcutr: ScopedNat<dcutr::Behaviour>,
    autonat: ScopedNat<autonat::v2::client::Behaviour>,
}

enum BehaviourEvent {
    Dcutr(dcutr::Event),
    AutoNat(autonat::v2::client::Event),
    Relay(relay::client::Event),
    Rendezvous(rendezvous::client::Event),
    Identify(Box<identify::Event>),
    Message(request_response::Event<WireRequest, WireResponse>),
    Discovery(mdns::Event),
    Pairing(request_response::Event<Value, Value>),
}

impl From<dcutr::Event> for BehaviourEvent {
    fn from(event: dcutr::Event) -> Self {
        Self::Dcutr(event)
    }
}
impl From<autonat::v2::client::Event> for BehaviourEvent {
    fn from(event: autonat::v2::client::Event) -> Self {
        Self::AutoNat(event)
    }
}

impl From<relay::client::Event> for BehaviourEvent {
    fn from(event: relay::client::Event) -> Self {
        Self::Relay(event)
    }
}
impl From<rendezvous::client::Event> for BehaviourEvent {
    fn from(event: rendezvous::client::Event) -> Self {
        Self::Rendezvous(event)
    }
}
impl From<identify::Event> for BehaviourEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(Box::new(event))
    }
}

impl From<request_response::Event<WireRequest, WireResponse>> for BehaviourEvent {
    fn from(event: request_response::Event<WireRequest, WireResponse>) -> Self {
        Self::Message(event)
    }
}

impl From<request_response::Event<Value, Value>> for BehaviourEvent {
    fn from(event: request_response::Event<Value, Value>) -> Self {
        Self::Pairing(event)
    }
}

impl From<mdns::Event> for BehaviourEvent {
    fn from(event: mdns::Event) -> Self {
        Self::Discovery(event)
    }
}

// The upstream behaviour contributes every observed address to dialing. LAN
// advertisements are untrusted, so only the worker's filtered cache may supply
// addresses. Keep the multicast sockets and events without raw dial hints.
struct HintOnlyMdns(mdns::tokio::Behaviour);

impl NetworkBehaviour for HintOnlyMdns {
    type ConnectionHandler = <mdns::tokio::Behaviour as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = mdns::Event;
    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.0
            .handle_established_inbound_connection(id, peer, local, remote)
    }
    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        address: &Multiaddr,
        role: Endpoint,
        port: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.0
            .handle_established_outbound_connection(id, peer, address, role, port)
    }
    fn on_swarm_event(&mut self, event: FromSwarm) {
        self.0.on_swarm_event(event);
    }
    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.0.on_connection_handler_event(peer, id, event);
    }
    fn poll(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        loop {
            match self.0.poll(cx) {
                Poll::Ready(ToSwarm::NewExternalAddrOfPeer { .. }) => continue,
                other => return other,
            }
        }
    }
}

impl From<Infallible> for BehaviourEvent {
    fn from(event: Infallible) -> Self {
        match event {}
    }
}

pub struct Incoming {
    pub peer: PeerId,
    pub request: WireRequest,
    pub response: oneshot::Sender<WireResponse>,
}

pub struct IncomingPairing {
    pub peer: PeerId,
    pub request: Value,
    pub response: oneshot::Sender<Value>,
}

#[derive(Clone)]
pub struct Handle {
    commands: mpsc::Sender<Command>,
}

enum Command {
    ResolveContact {
        address: Multiaddr,
        response: oneshot::Sender<Result<PeerId>>,
    },
    PairingRequest {
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        request: Value,
        response: oneshot::Sender<Result<Value>>,
    },
    SetPairing {
        enabled: bool,
        response: oneshot::Sender<()>,
    },
    Request {
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        request: Box<WireRequest>,
        response: oneshot::Sender<Result<WireResponse>>,
    },
    SetAllowed {
        peers: Vec<PeerId>,
        response: oneshot::Sender<()>,
    },
}

impl Handle {
    /// Resolve address ownership only; no trust or application messages result.
    pub async fn resolve_contact(&self, address: Multiaddr) -> Result<PeerId> {
        anyhow::ensure!(
            address.to_string().len() <= 512
                && !address
                    .iter()
                    .any(|p| matches!(p, Protocol::P2p(_) | Protocol::P2pCircuit)),
            "Contact lookup requires a direct transport address"
        );
        super::store::validate_address(&address.to_string(), false)?;
        let (response, received) = oneshot::channel();
        self.commands
            .try_send(Command::ResolveContact { address, response })
            .map_err(|_| anyhow!("Network transport is stopped or busy"))?;
        tokio::time::timeout(Duration::from_secs(12), received)
            .await
            .context("Contact lookup timed out")?
            .context("Network transport stopped")?
    }

    pub async fn pairing_request(
        &self,
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        request: Value,
    ) -> Result<Value> {
        anyhow::ensure!(
            addresses.len() <= 8,
            "provide at most eight pairing connection addresses"
        );
        anyhow::ensure!(
            serde_json::to_vec(&request)?.len() <= PAIRING_FRAME,
            "pairing frame exceeds 4 KiB"
        );
        let (response, received) = oneshot::channel();
        self.commands
            .try_send(Command::PairingRequest {
                peer,
                addresses,
                request,
                response,
            })
            .map_err(|_| anyhow!("network transport is stopped or busy"))?;
        tokio::time::timeout(Duration::from_secs(15), received)
            .await
            .context("pairing request timed out")?
            .context("network transport stopped")?
    }
    pub async fn set_pairing_enabled(&self, enabled: bool) -> Result<()> {
        let (response, received) = oneshot::channel();
        self.commands
            .try_send(Command::SetPairing { enabled, response })
            .map_err(|_| anyhow!("network transport is stopped or busy"))?;
        tokio::time::timeout(Duration::from_secs(15), received)
            .await
            .context("pairing policy update timed out")?
            .context("network transport stopped")
    }

    pub async fn request(
        &self,
        peer: PeerId,
        address: Multiaddr,
        request: WireRequest,
    ) -> Result<WireResponse> {
        self.request_addresses(peer, vec![address], request).await
    }

    pub async fn request_addresses(
        &self,
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        request: WireRequest,
    ) -> Result<WireResponse> {
        anyhow::ensure!(
            !addresses.is_empty() && addresses.len() <= 8,
            "provide one to eight connection addresses"
        );
        let (response, received) = oneshot::channel();
        self.commands
            .try_send(Command::Request {
                peer,
                addresses,
                request: Box::new(request),
                response,
            })
            .map_err(|_| anyhow!("network transport is stopped or busy"))?;
        tokio::time::timeout(Duration::from_secs(15), received)
            .await
            .context("network request timed out")?
            .context("network transport stopped")?
    }

    pub async fn set_allowed(&self, peers: Vec<PeerId>) -> Result<()> {
        let (response, received) = oneshot::channel();
        self.commands
            .try_send(Command::SetAllowed { peers, response })
            .map_err(|_| anyhow!("network transport is stopped or busy"))?;
        tokio::time::timeout(Duration::from_secs(15), received)
            .await
            .context("network policy update timed out")?
            .context("network transport stopped")
    }
}

pub struct Transport {
    pub handle: Handle,
    pub incoming: mpsc::Receiver<Incoming>,
    pub incoming_pairing: mpsc::Receiver<IncomingPairing>,
    pub status: watch::Receiver<Value>,
    task: JoinHandle<()>,
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Transport {
    pub fn start(
        keypair: libp2p::identity::Keypair,
        listen: Multiaddr,
        allowed: Vec<PeerId>,
    ) -> Result<Self> {
        Self::start_configured(keypair, listen, allowed, false, None, Vec::new())
    }

    pub fn start_lan(
        keypair: libp2p::identity::Keypair,
        listen: Multiaddr,
        allowed: Vec<PeerId>,
    ) -> Result<Self> {
        Self::start_configured(keypair, listen, allowed, true, None, Vec::new())
    }

    /// Advertise a display label without changing the authenticated peer identity.
    pub fn start_named(
        keypair: libp2p::identity::Keypair,
        listen: Multiaddr,
        allowed: Vec<PeerId>,
        lan: bool,
        machine_name: &str,
    ) -> Result<Self> {
        super::machine::validate_name(machine_name)?;
        Self::start_configured(
            keypair,
            listen,
            allowed,
            lan,
            Some(machine_name.to_owned()),
            Vec::new(),
        )
    }

    /// Optional independently configured infrastructure; it never becomes an application peer.
    pub fn start_relayed(
        keypair: libp2p::identity::Keypair,
        listen: Multiaddr,
        allowed: Vec<PeerId>,
        lan: bool,
        machine_name: &str,
        relays: Vec<Multiaddr>,
    ) -> Result<Self> {
        super::machine::validate_name(machine_name)?;
        Self::start_configured(
            keypair,
            listen,
            allowed,
            lan,
            Some(machine_name.to_owned()),
            relays,
        )
    }

    fn start_configured(
        keypair: libp2p::identity::Keypair,
        listen: Multiaddr,
        allowed: Vec<PeerId>,
        lan: bool,
        machine_name: Option<String>,
        relays: Vec<Multiaddr>,
    ) -> Result<Self> {
        anyhow::ensure!(
            relays.len() <= 8,
            "At most eight relay routes may be configured"
        );
        let local_peer = keypair.public().to_peer_id();
        let mut relay_nodes = Vec::new();
        let mut relay_ids = HashSet::new();
        for address in relays {
            let peer = relay_identity(&address).context("Invalid relay address")?;
            anyhow::ensure!(peer != local_peer, "This bridge cannot be its own relay");
            if let Some(node) = relay_nodes
                .iter_mut()
                .find(|node: &&mut RelayNode| node.peer == peer)
            {
                anyhow::ensure!(
                    node.alternatives.len() < 2 && !node.alternatives.contains(&address),
                    "At most two distinct routes per relay operator"
                );
                node.alternatives.push(address);
                node.alternatives.sort_by_key(is_tcp);
                node.address = node.alternatives[0].clone();
            } else {
                anyhow::ensure!(
                    relay_ids.len() < 4,
                    "At most four independent relay operators"
                );
                relay_ids.insert(peer);
                relay_nodes.push(RelayNode::new(peer, address));
            }
        }
        let policy = Arc::new(RwLock::new(NatPolicy {
            trusted: allowed.iter().copied().collect(), infrastructure:relay_ids.clone(),
            allow_loopback: !relay_nodes.is_empty() && relay_nodes.iter().all(|node|matches!(node.address.iter().next(),Some(Protocol::Ip4(ip)) if ip.is_loopback()) || matches!(node.address.iter().next(),Some(Protocol::Ip6(ip)) if ip.is_loopback())),
            allow_private: false,
        }));
        let identify = identify::Behaviour::new(
            identify::Config::new("/agent-bridge/identify/1".into(), keypair.public())
                .with_push_listen_addr_updates(true)
                .with_cache_size(0)
                .with_interval(Duration::from_secs(10)),
        );
        let rendezvous =
            rendezvous::client::Behaviour::new(keypair.clone()).without_address_cache();
        let discovery = if lan {
            let config = mdns::Config {
                ttl: DISCOVERY_TTL,
                query_interval: Duration::from_secs(5),
                enable_ipv6: false,
                machine_name,
            };
            Some(HintOnlyMdns(mdns::tokio::Behaviour::new(
                config, local_peer,
            )?))
        } else {
            None
        };
        let allowlist = Admission {
            trusted: allowed.into_iter().collect(),
            pairing_enabled: false,
            infrastructure: relay_ids,
            established: HashMap::new(),
            contacts: HashMap::new(),
        };
        let mut swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_quic()
            .with_dns()?
            .with_relay_client(noise::Config::new, yamux::Config::default)?
            .with_behaviour(|_, relay| Behaviour {
                relay,
                rendezvous,
                identify,
                dcutr: ScopedNat::new(
                    dcutr::Behaviour::new(local_peer),
                    NatScope::TrustedEndpoint,
                    policy.clone(),
                ),
                autonat: ScopedNat::new(
                    autonat::v2::client::Behaviour::new(
                        rand::make_rng::<rand::rngs::StdRng>(),
                        autonat::v2::client::Config::default()
                            .with_max_candidates(8)
                            .with_probe_interval(Duration::from_secs(5)),
                    ),
                    NatScope::Infrastructure,
                    policy.clone(),
                ),
                allowed: allowlist,
                discovery: discovery.into(),
                limits: connection_limits::Behaviour::new(
                    connection_limits::ConnectionLimits::default()
                        .with_max_pending_incoming(Some(16))
                        .with_max_pending_outgoing(Some(16))
                        .with_max_established(Some(32))
                        .with_max_established_per_peer(Some(3)),
                ),
                pairing: request_response::Behaviour::with_codec(
                    PairingCodec,
                    [(PAIRING_PROTOCOL, ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(REQUEST_TIMEOUT)
                        .with_max_concurrent_streams(CAPACITY),
                ),
                messages: request_response::Behaviour::with_codec(
                    JsonCodec,
                    [(PROTOCOL, ProtocolSupport::Full)],
                    request_response::Config::default()
                        .with_request_timeout(REQUEST_TIMEOUT)
                        .with_max_concurrent_streams(CAPACITY),
                ),
            })?
            .with_swarm_config(|config| {
                config.with_idle_connection_timeout(Duration::from_secs(30))
            })
            .build();
        swarm
            .listen_on(listen)
            .context("Could not listen on transport address")?;
        let (commands, command_rx) = mpsc::channel(CAPACITY);
        let (incoming_tx, incoming) = mpsc::channel(CAPACITY);
        let (pairing_tx, incoming_pairing) = mpsc::channel(CAPACITY);
        let (status_tx, status) = watch::channel(
            json!({"enabled":true,"lan":lan,"listening":[],"connected":[],"discovered":[],"last_error":null}),
        );
        let task = tokio::spawn(run(
            swarm,
            command_rx,
            incoming_tx,
            pairing_tx,
            status_tx,
            lan,
            relay_nodes,
        ));
        Ok(Self {
            handle: Handle { commands },
            incoming,
            incoming_pairing,
            status,
            task,
        })
    }
}

struct PairingPending {
    peer: PeerId,
    response: oneshot::Sender<Result<Value>>,
}
type PendingPairingResponse = BoxFuture<
    'static,
    (
        PeerId,
        request_response::ResponseChannel<Value>,
        Option<Value>,
    ),
>;

struct Pending {
    peer: PeerId,
    response: oneshot::Sender<Result<WireResponse>>,
}

type PendingResponse = BoxFuture<
    'static,
    (
        PeerId,
        request_response::ResponseChannel<WireResponse>,
        Option<WireResponse>,
    ),
>;

const RENDEZVOUS_NAMESPACE: &str = "agent-bridge";
const RENDEZVOUS_TTL: u64 = 30;

fn is_tcp(address: &Multiaddr) -> bool {
    address.iter().any(|part| matches!(part, Protocol::Tcp(_)))
}
fn relay_identity(address: &Multiaddr) -> Result<PeerId> {
    super::relay_config::validate_relay(&address.to_string())?
        .peer_id
        .parse()
        .context("Invalid relay identity")
}

struct RelayNode {
    peer: PeerId,
    address: Multiaddr,
    alternatives: Vec<Multiaddr>,
    route_index: usize,
    dialed: bool,
    dial: Option<ConnectionId>,
    attempt_until: Instant,
    next_udp_probe: Instant,
    listener: Option<libp2p::core::transport::ListenerId>,
    reserved: bool,
    registered: bool,
    next: Instant,
    discover: Instant,
    register: Instant,
    failures: u32,
    error: Option<String>,
    cookie: Option<rendezvous::Cookie>,
}
impl RelayNode {
    fn new(peer: PeerId, address: Multiaddr) -> Self {
        Self {
            peer,
            alternatives: vec![address.clone()],
            address,
            route_index: 0,
            dialed: false,
            dial: None,
            attempt_until: Instant::now() + Duration::from_secs(3),
            next_udp_probe: Instant::now() + Duration::from_secs(60),
            listener: None,
            reserved: false,
            registered: false,
            next: Instant::now(),
            discover: Instant::now(),
            register: Instant::now(),
            failures: 0,
            error: None,
            cookie: None,
        }
    }
    fn failed(&mut self, error: String) {
        self.cookie = None;
        self.reserved = false;
        self.registered = false;
        self.error = Some(error.chars().take(200).collect());
        self.failures = (self.failures + 1).min(5);
        self.next = Instant::now() + Duration::from_secs(1 << self.failures);
        self.rotate();
    }
    fn rotate(&mut self) {
        self.dialed = false;
        self.dial = None;
        self.route_index = (self.route_index + 1) % self.alternatives.len();
        self.address = self.alternatives[self.route_index].clone();
        self.attempt_until = Instant::now() + Duration::from_secs(3);
    }
}
struct RendezvousEntry {
    relay: PeerId,
    peer: PeerId,
    addresses: Vec<String>,
    expires: Instant,
}

fn circuit_route(node: &RelayNode, target: PeerId) -> Multiaddr {
    node.address
        .clone()
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(target))
}

fn remember_rendezvous(
    entries: &mut Vec<RendezvousEntry>,
    node: &RelayNode,
    registrations: Vec<rendezvous::Registration>,
    capacity: usize,
    local: PeerId,
) {
    entries.retain(|entry| entry.expires > Instant::now());
    for registration in registrations.into_iter().take(256) {
        let peer = registration.record.peer_id();
        if peer == local
            || registration.namespace != *RENDEZVOUS_NAMESPACE
            || registration.ttl == 0
            || registration.ttl > 300
        {
            continue;
        }
        let addresses: Vec<String> = node
            .alternatives
            .iter()
            .map(|address| {
                address
                    .clone()
                    .with(Protocol::P2pCircuit)
                    .with(Protocol::P2p(peer))
            })
            .filter(|expected| registration.record.addresses().contains(expected))
            .map(|address| address.to_string())
            .collect();
        if addresses.is_empty() {
            continue;
        }
        let expires = Instant::now() + Duration::from_secs(registration.ttl);
        if let Some(entry) = entries
            .iter_mut()
            .find(|entry| entry.peer == peer && entry.relay == node.peer)
        {
            entry.expires = expires;
            entry.addresses = addresses;
        } else if entries.len() < 256
            && entries
                .iter()
                .filter(|entry| entry.relay == node.peer)
                .count()
                < capacity
        {
            entries.push(RendezvousEntry {
                relay: node.peer,
                peer,
                addresses,
                expires,
            });
        }
    }
}

fn relay_views(nodes: &[RelayNode]) -> Value {
    json!(nodes.iter().flat_map(|node|node.alternatives.iter().map(move|address|{
        let active=address==&node.address;
        json!({"peer_id":node.peer.to_string(),"address":address.to_string(),"transport":if is_tcp(address){"tcp"}else{"quic"},"state":if !active{"standby"}else if node.reserved {"reserved"} else if node.error.is_some() {"error"} else {"connecting"},"registered":active&&node.registered,"last_error":if active{node.error.clone()}else{None}})
    })).collect::<Vec<_>>())
}
fn rendezvous_views(entries: &[RendezvousEntry]) -> Value {
    json!(entries.iter().filter(|entry| entry.expires>Instant::now()).map(|entry| json!({"peer_id":entry.peer.to_string(),"relay_peer_id":entry.relay.to_string(),"addresses":entry.addresses})).collect::<Vec<_>>())
}

struct PathConnection {
    peer: PeerId,
    relayed: bool,
    address: String,
}
struct Observation {
    observer: PeerId,
    address: Multiaddr,
    expires: Instant,
    checked: Instant,
    verified: Option<bool>,
}
struct HoleStatus {
    state: &'static str,
    error: Option<String>,
    attempts: u64,
    updated: Instant,
}
struct NatRuntime {
    advertised: Vec<Multiaddr>,
    observed: Vec<Observation>,
    holes: HashMap<PeerId, HoleStatus>,
    retry: HashMap<PeerId, Instant>,
}
impl NatRuntime {
    fn new() -> Self {
        Self {
            advertised: Vec::new(),
            observed: Vec::new(),
            holes: HashMap::new(),
            retry: HashMap::new(),
        }
    }
    fn observe(&mut self, observer: PeerId, address: Multiaddr) -> bool {
        let now = Instant::now();
        if let Some(old) = self
            .observed
            .iter_mut()
            .find(|entry| entry.observer == observer)
        {
            old.expires = now + Duration::from_secs(120);
            if old.address == address {
                return false;
            }
            old.address = address;
            old.verified = None;
            old.checked = now;
            return true;
        }
        if self.observed.len() < 8 {
            self.observed.push(Observation {
                observer,
                address,
                expires: now + Duration::from_secs(120),
                checked: now,
                verified: None,
            });
            return true;
        }
        false
    }
    fn candidates(&self) -> Vec<Multiaddr> {
        let mut result = Vec::new();
        for entry in &self.observed {
            if entry.expires > Instant::now() && !result.contains(&entry.address) {
                result.push(entry.address.clone());
            }
        }
        // Do not mix private-deployment hints into a public candidate exchange:
        // public-only counterparts correctly reject private dial destinations.
        let public: Vec<_> = result
            .iter()
            .filter(|address| {
                !private_ip(address)
                    && !matches!(address.iter().next(), Some(Protocol::Ip4(ip)) if ip.is_loopback())
                    && !matches!(address.iter().next(), Some(Protocol::Ip6(ip)) if ip.is_loopback())
            })
            .cloned()
            .collect();
        if !public.is_empty() {
            result = public;
        }
        result.sort_by_key(ToString::to_string);
        result
    }
    fn hole(&mut self, peer: PeerId, state: &'static str, error: Option<String>) {
        if !self.holes.contains_key(&peer)
            && self.holes.len() >= 32
            && let Some(old) = self
                .holes
                .iter()
                .min_by_key(|(_, v)| v.updated)
                .map(|(p, _)| *p)
        {
            self.holes.remove(&old);
        }
        let entry = self.holes.entry(peer).or_insert(HoleStatus {
            state,
            error: None,
            attempts: 0,
            updated: Instant::now(),
        });
        entry.state = state;
        entry.error = error;
        entry.attempts = entry
            .attempts
            .saturating_add(u64::from(state == "attempting"));
        entry.updated = Instant::now();
    }
    fn view(&self) -> Value {
        let now = Instant::now();
        let reachability = if self.observed.iter().any(|e| {
            e.expires > now
                && now.duration_since(e.checked) < Duration::from_secs(60)
                && e.verified == Some(true)
        }) {
            "public"
        } else if self.observed.iter().any(|e| {
            e.expires > now
                && now.duration_since(e.checked) < Duration::from_secs(60)
                && e.verified == Some(false)
        }) {
            "private"
        } else {
            "unknown"
        };
        json!({"protocol":"autonat-v2/dcutr","reachability":reachability,"observed_addresses":self.observed.iter().filter(|e|e.expires>now).map(|e|json!({"address":e.address.to_string(),"observer_peer_id":e.observer.to_string(),"verified":e.verified==Some(true)&&now.duration_since(e.checked)<Duration::from_secs(60),"expires_in_seconds":e.expires.saturating_duration_since(now).as_secs()})).collect::<Vec<_>>(),"hole_punch":self.holes.iter().map(|(peer,h)|json!({"peer_id":peer.to_string(),"state":h.state,"last_error":h.error,"attempts":h.attempts})).collect::<Vec<_>>()})
    }
}
fn private_ip(address: &Multiaddr) -> bool {
    match address.iter().next() {
        Some(Protocol::Ip4(ip)) => {
            ip.is_private()
                || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
                || ip.octets()[0] == 198 && (ip.octets()[1] == 18 || ip.octets()[1] == 19)
        }
        Some(Protocol::Ip6(ip)) => ip.is_unique_local() || ip.segments()[0] & 0xffc0 == 0xfec0,
        _ => false,
    }
}
fn refresh_candidates(
    swarm: &mut Swarm<Behaviour>,
    nat: &mut NatRuntime,
    connections: &HashMap<ConnectionId, PathConnection>,
) {
    let candidates = nat.candidates();
    let changed = nat.advertised != candidates;
    nat.advertised = candidates.clone();
    swarm
        .behaviour_mut()
        .autonat
        .inner
        .set_candidates(&candidates);
    swarm
        .behaviour_mut()
        .dcutr
        .inner
        .set_address_candidates(&candidates);
    swarm
        .behaviour()
        .dcutr
        .policy
        .write()
        .unwrap()
        .allow_private = !candidates.is_empty() && candidates.iter().all(private_ip);
    if changed {
        // Existing DCUtR handlers captured the former local addresses. Recreate
        // only endpoint circuits; authenticated direct paths and infrastructure
        // reservations remain intact while queued application work retries.
        let trusted = swarm.behaviour().allowed.trusted.clone();
        for (id, _) in connections
            .iter()
            .filter(|(_, c)| c.relayed && trusted.contains(&c.peer))
        {
            swarm.close_connection(*id);
        }
    }
}

fn path_views(
    connections: &HashMap<ConnectionId, PathConnection>,
    trusted: &HashSet<PeerId>,
) -> Value {
    let peers: BTreeSet<_> = connections
        .values()
        .filter(|c| trusted.contains(&c.peer))
        .map(|c| c.peer)
        .collect();
    json!(peers.into_iter().map(|peer|{
        let direct=connections.values().filter(|c|c.peer==peer&&!c.relayed).count();
        let relayed=connections.values().filter(|c|c.peer==peer&&c.relayed).count();
        json!({"peer_id":peer.to_string(),"path":if direct>0{"direct"}else{"relayed"},"direct_connections":direct,"relayed_connections":relayed,"carrier":if connections.values().filter(|c|c.peer==peer).any(|c|c.address.contains("/quic-v1")){"quic"}else{"tcp"},"addresses":connections.values().filter(|c|c.peer==peer).map(|c|&c.address).collect::<Vec<_>>()})
    }).collect::<Vec<_>>())
}

#[allow(clippy::too_many_arguments)]
fn publish(
    status: &watch::Sender<Value>,
    listening: &BTreeSet<String>,
    connected: &HashMap<PeerId, u32>,
    last_error: &Option<String>,
    discovery: &DiscoveryCache,
    lan: bool,
    relay_nodes: &[RelayNode],
    rendezvous: &[RendezvousEntry],
    nat: &NatRuntime,
    connections: &HashMap<ConnectionId, PathConnection>,
) {
    let peers: BTreeSet<_> = connected.keys().map(ToString::to_string).collect();
    status.send_replace(
        json!({"enabled":true,"lan":lan,"listening":listening,"connected":peers,"discovered":discovery.snapshot(),"last_error":last_error,"relays":relay_views(relay_nodes),"rendezvous":rendezvous_views(rendezvous),"nat":nat.view(),"paths":path_views(connections,&connected.keys().copied().collect())}),
    );
}

async fn run(
    mut swarm: Swarm<Behaviour>,
    mut commands: mpsc::Receiver<Command>,
    incoming: mpsc::Sender<Incoming>,
    incoming_pairing: mpsc::Sender<IncomingPairing>,
    status: watch::Sender<Value>,
    lan: bool,
    mut relay_nodes: Vec<RelayNode>,
) {
    let mut contact_pending: HashMap<ConnectionId, (oneshot::Sender<Result<PeerId>>, Instant)> =
        HashMap::new();
    let mut contact_epoch = Instant::now();
    let mut contact_count = 0u32;
    let mut nat = NatRuntime::new();
    let mut connections: HashMap<ConnectionId, PathConnection> = HashMap::new();
    let per_operator_capacity = 256 / relay_nodes.len().max(1);
    let mut rendezvous_entries: Vec<RendezvousEntry> = Vec::new();
    let mut pending = HashMap::<request_response::OutboundRequestId, Pending>::new();
    let mut responses = FuturesUnordered::<PendingResponse>::new();
    let mut pairing_pending = HashMap::<request_response::OutboundRequestId, PairingPending>::new();
    let mut pairing_responses = FuturesUnordered::<PendingPairingResponse>::new();
    let mut pairing_rate = PairingRate::new();
    let mut outbound_pairing_rate = PairingRate::new();
    let mut all_connected = HashSet::new();
    let mut listening = BTreeSet::new();
    let mut connected = HashMap::<PeerId, u32>::new();
    let mut last_error = None;
    let mut discovery = DiscoveryCache::new(*swarm.local_peer_id());
    let mut expiry = tokio::time::interval(Duration::from_secs(1));
    expiry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::ResolveContact{address,response})=>{
                    if contact_epoch.elapsed()>=Duration::from_secs(60){contact_epoch=Instant::now();contact_count=0;}
                    if contact_pending.len()>=4||contact_count>=8||swarm.behaviour().allowed.contacts.len()>=16 {
                        let _=response.send(Err(anyhow!("Contact lookup capacity reached")));
                    } else {
                        contact_count+=1;
                        let opts=libp2p::swarm::dial_opts::DialOpts::unknown_peer_id().address(address).build();let id=opts.connection_id();
                        swarm.behaviour_mut().allowed.contacts.insert(id,true);
                        match swarm.dial(opts) {
                            Ok(())=>{contact_pending.insert(id,(response,Instant::now()+Duration::from_secs(10)));}
                            Err(error)=>{swarm.behaviour_mut().allowed.contacts.remove(&id);let _=response.send(Err(anyhow!("Contact lookup failed: {error}")));}
                        }
                    }
                }
                Some(Command::SetPairing { enabled, response }) => {
                    swarm.behaviour_mut().allowed.pairing_enabled = enabled;
                    if !enabled {
                        for peer in &all_connected {
                            if !swarm.behaviour().allowed.trusted.contains(peer) && !swarm.behaviour().allowed.infrastructure.contains(peer) { let _ = swarm.disconnect_peer_id(*peer); }
                        }
                        for (_, entry) in pairing_pending.drain() { let _ = entry.response.send(Err(anyhow!("pairing window closed"))); }
                        pairing_responses.clear();
                    }
                    let _ = response.send(());
                }
                Some(Command::PairingRequest { peer, addresses, request, response }) => {
                    if !swarm.behaviour().allowed.pairing_enabled {
                        let _ = response.send(Err(anyhow!("pairing window is closed")));
                    } else if pairing_pending.len() >= CAPACITY || !outbound_pairing_rate.allow(peer) {
                        let _ = response.send(Err(anyhow!("pairing transport is busy")));
                    } else {
                        let id = swarm.behaviour_mut().pairing.send_request_with_addresses(&peer, request, addresses);
                        pairing_pending.insert(id, PairingPending { peer, response });
                    }
                }
                Some(Command::Request { peer, addresses, request, response }) => {
                    if !swarm.behaviour().allowed.trusted.contains(&peer) {
                        let _ = response.send(Err(anyhow!("peer is not trusted")));
                    } else if pending.len() >= CAPACITY {
                        let _ = response.send(Err(anyhow!("network request capacity reached")));
                    } else {
                        let id = swarm.behaviour_mut().messages.send_request_with_addresses(&peer, *request, addresses);
                        pending.insert(id, Pending { peer, response });
                    }
                }
                Some(Command::SetAllowed { peers, response }) => {
                    let next: HashSet<_> = peers.into_iter().collect();
                    let removed: Vec<_> = swarm.behaviour().allowed.trusted.difference(&next).copied().collect();
                    let added: Vec<_> = next.difference(&swarm.behaviour().allowed.trusted).copied().collect();
                    swarm.behaviour().dcutr.policy.write().unwrap().trusted=next.clone();
                    for peer in &added {
                        if !swarm.behaviour().allowed.infrastructure.contains(peer) && all_connected.contains(peer) {
                            let _=swarm.disconnect_peer_id(*peer);
                            connected.remove(peer);
                        }
                    }
                    nat.holes.retain(|peer,_|next.contains(peer));nat.retry.retain(|peer,_|next.contains(peer));
                    for peer in removed {
                        let _ = swarm.disconnect_peer_id(peer);
                        connected.remove(&peer);
                    }
                    swarm.behaviour_mut().allowed.trusted = next.clone();
                    for peer in &all_connected { if next.contains(peer) { connected.entry(*peer).or_insert(1); } }
                    let revoked: Vec<_> = pending.iter().filter_map(|(id, entry)| (!next.contains(&entry.peer)).then_some(*id)).collect();
                    for id in revoked {
                        if let Some(entry) = pending.remove(&id) { let _ = entry.response.send(Err(anyhow!("peer trust was revoked"))); }
                    }
                    publish(&status, &listening, &connected, &last_error, &discovery, lan, &relay_nodes, &rendezvous_entries, &nat, &connections);
                    let _ = response.send(());
                }
                None => break,
            },
            Some((peer, channel, response)) = responses.next(), if !responses.is_empty() => {
                if swarm.behaviour().allowed.trusted.contains(&peer) {
                    let response = response.unwrap_or(WireResponse::Rejected { reason: "request processing timed out".into(), retryable: true });
                    let _ = swarm.behaviour_mut().messages.send_response(channel, response);
                }
            }
            Some((_, channel, response)) = pairing_responses.next(), if !pairing_responses.is_empty() => {
                if swarm.behaviour().allowed.pairing_enabled {
                    let response = response.unwrap_or_else(|| json!({"error":"pairing request processing timed out"}));
                    let _ = swarm.behaviour_mut().pairing.send_response(channel, response);
                }
            }
            _ = expiry.tick() => {
                let now=Instant::now();
                let expired:Vec<_>=contact_pending.iter().filter(|(_, (sender,deadline))|sender.is_closed()||*deadline<=Instant::now()).map(|(id,_)|*id).collect();
                for id in expired {if let Some((sender,_))=contact_pending.remove(&id){swarm.behaviour_mut().allowed.contacts.insert(id,false);let _=sender.send(Err(anyhow!("Contact lookup expired")));}}

                let old_count=nat.observed.len();
                nat.observed.retain(|entry|entry.expires>now);
                if old_count!=nat.observed.len(){refresh_candidates(&mut swarm,&mut nat,&connections);}
                for entry in &mut nat.observed {
                    if now.duration_since(entry.checked)>=Duration::from_secs(60){swarm.behaviour_mut().autonat.inner.recheck_address(&entry.address);entry.checked=now;entry.verified=None;}
                }
                let trusted=swarm.behaviour().allowed.trusted.clone();
                let peers:HashSet<_>=connections.values().filter(|c|c.relayed&&trusted.contains(&c.peer)).map(|c|c.peer).collect();
                nat.retry.retain(|peer,_|peers.contains(peer));
                for peer in peers {
                    if connections.values().any(|c|c.peer==peer&&!c.relayed){continue;}
                    let next=nat.retry.entry(peer).or_insert(now+Duration::from_secs(60));
                    if now>=*next {
                        *next=now+Duration::from_secs(60);
                        for (id,_) in connections.iter().filter(|(_,c)|c.peer==peer&&c.relayed){swarm.close_connection(*id);}
                    }
                }
                rendezvous_entries.retain(|entry|entry.expires>now);
                for node in &mut relay_nodes {
                    if !node.reserved && node.dialed && now>=node.attempt_until {
                        if let Some(id)=node.listener.take(){swarm.remove_listener(id);}
                        swarm.remove_external_address(&circuit_route(node,*swarm.local_peer_id()));
                        for (id,_) in connections.iter().filter(|(_,c)|c.peer==node.peer&&!c.relayed){swarm.close_connection(*id);}
                        node.rotate();node.next=now;
                    }
                    if node.reserved && is_tcp(&node.address) && now>=node.next_udp_probe {
                        node.next_udp_probe=now+Duration::from_secs(60);
                        if !connections.values().any(|c|c.peer==node.peer&&!c.relayed&&c.address.contains("/quic-v1")) && let Some(address)=node.alternatives.iter().find(|address|!is_tcp(address)) {
                            let opts=libp2p::swarm::dial_opts::DialOpts::peer_id(node.peer).addresses(vec![address.clone()]).condition(libp2p::swarm::dial_opts::PeerCondition::Always).build();
                            let _=swarm.dial(opts);
                        }
                    }
                    if node.listener.is_none() && now>=node.next {
                        if !node.dialed {
                            let opts=libp2p::swarm::dial_opts::DialOpts::peer_id(node.peer).addresses(vec![node.address.clone()]).condition(libp2p::swarm::dial_opts::PeerCondition::Always).build();
                            node.dial=Some(opts.connection_id());if let Err(error)=swarm.dial(opts){for (id,_) in connections.iter().filter(|(_,c)|c.peer==node.peer&&!c.relayed){swarm.close_connection(*id);}node.failed(error.to_string());continue;}node.dialed=true;node.attempt_until=now+Duration::from_secs(if is_tcp(&node.address){8}else{3});
                        }
                        if connections.values().any(|c|c.peer==node.peer&&!c.relayed&&c.address.contains("/tcp/")==is_tcp(&node.address)) {
                            match swarm.listen_on(node.address.clone().with(Protocol::P2pCircuit)) {
                                Ok(id) => {node.listener=Some(id);node.next=now+Duration::from_secs(15);},
                                Err(error) => {for (id,_) in connections.iter().filter(|(_,c)|c.peer==node.peer&&!c.relayed){swarm.close_connection(*id);}node.failed(error.to_string());},
                            }
                        } else {node.next=now+Duration::from_secs(1);}
                    }
                    if node.reserved && now>=node.register {
                        node.register=now+Duration::from_secs(60);
                        if let Err(error)=swarm.behaviour_mut().rendezvous.register(rendezvous::Namespace::from_static(RENDEZVOUS_NAMESPACE),node.peer,Some(RENDEZVOUS_TTL)) {node.error=Some(error.to_string());node.register=now+Duration::from_secs(2);}
                    }
                    if node.reserved && now>=node.discover {
                        node.discover=now+Duration::from_secs(5);
                        swarm.behaviour_mut().rendezvous.discover(Some(rendezvous::Namespace::from_static(RENDEZVOUS_NAMESPACE)),node.cookie.clone(),Some(256),node.peer);
                    }
                }
                if discovery.expire_due(now) || !relay_nodes.is_empty() {
                    publish(&status, &listening, &connected, &last_error, &discovery, lan, &relay_nodes, &rendezvous_entries, &nat, &connections);
                }
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, listener_id } => {
                        if address.iter().any(|part| matches!(part,Protocol::P2pCircuit)) {
                            for node in relay_nodes.iter_mut().filter(|node|node.listener==Some(listener_id)){node.reserved=true;node.failures=0;node.error=None;node.register=Instant::now();node.discover=Instant::now();swarm.add_external_address(circuit_route(node,*swarm.local_peer_id()));}
                        }
                        listening.insert(address.to_string());
                    }
                    SwarmEvent::ExpiredListenAddr { address, .. } => {
                        listening.remove(&address.to_string());
                        swarm.remove_external_address(&address);
                    }
                    SwarmEvent::ListenerClosed { listener_id, reason, .. } => {
                        for node in &mut relay_nodes { if node.listener==Some(listener_id) {swarm.remove_external_address(&circuit_route(node,*swarm.local_peer_id()));node.listener=None;for (id,_) in connections.iter().filter(|(_,c)|c.peer==node.peer&&!c.relayed){swarm.close_connection(*id);}node.failed(reason.as_ref().err().map(|e|e.to_string()).unwrap_or_else(||"Relay reservation closed".into()));rendezvous_entries.retain(|entry|entry.relay!=node.peer);} }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id,connection_id,endpoint, .. } => {
                        if let Some((sender,_))=contact_pending.remove(&connection_id) {
                            swarm.behaviour_mut().allowed.contacts.remove(&connection_id);
                            swarm.close_connection(connection_id);
                            let _=sender.send(Ok(peer_id));
                            continue;
                        }

                        if let Some(node)=relay_nodes.iter().find(|node|node.peer==peer_id&&!node.reserved) && endpoint.get_remote_address().iter().any(|p|matches!(p,Protocol::Tcp(_)))!=is_tcp(&node.address) {swarm.close_connection(connection_id);continue;}
                        let relayed=endpoint.is_relayed();
                        connections.insert(connection_id,PathConnection{peer:peer_id,relayed,address:endpoint.get_remote_address().to_string()});
                        if swarm.behaviour().allowed.trusted.contains(&peer_id) {
                            if !relayed {
                                // Only retire redundant endpoint circuits after the new QUIC
                                // connection authenticated the same peer. Keep infrastructure.
                                for (id,_) in connections.iter().filter(|(_,c)|c.peer==peer_id&&c.relayed){swarm.close_connection(*id);}
                                nat.retry.remove(&peer_id);
                                if nat.holes.contains_key(&peer_id) {nat.hole(peer_id,"succeeded",None);}
                            } else if !swarm.behaviour().allowed.infrastructure.contains(&peer_id) {
                                if connections.iter().any(|(id,c)| *id!=connection_id && c.peer==peer_id && !c.relayed) {swarm.close_connection(connection_id);}
                                else {nat.hole(peer_id,"attempting",None);}
                            }
                        }
                        all_connected.insert(peer_id);
                        if swarm.behaviour().allowed.trusted.contains(&peer_id) {
                            *connected.entry(peer_id).or_default() += 1;
                        } else if !swarm.behaviour().allowed.pairing_enabled && !swarm.behaviour().allowed.infrastructure.contains(&peer_id) { let _ = swarm.disconnect_peer_id(peer_id); }
                    }
                    SwarmEvent::ConnectionClosed { peer_id,connection_id, num_established, .. } => {
                        connections.remove(&connection_id);
                        swarm.behaviour_mut().allowed.contacts.remove(&connection_id);
                        if num_established == 0 { connected.remove(&peer_id); all_connected.remove(&peer_id); } else if swarm.behaviour().allowed.trusted.contains(&peer_id) { connected.insert(peer_id, num_established); }
                    }
                    SwarmEvent::OutgoingConnectionError { connection_id,error, .. } => {
                        for node in relay_nodes.iter_mut().filter(|node|node.dial==Some(connection_id)&&!node.reserved){for (id,_) in connections.iter().filter(|(_,c)|c.peer==node.peer&&!c.relayed){swarm.close_connection(*id);}node.failed(error.to_string());}
                        swarm.behaviour_mut().allowed.contacts.remove(&connection_id);
                        if let Some((sender,_))=contact_pending.remove(&connection_id){let _=sender.send(Err(anyhow!("Contact lookup failed: {error}")));}
                        else {last_error = Some(error.to_string());}
                    }
                    SwarmEvent::ListenerError { error, .. } => { last_error = Some(error.to_string()); }

                    SwarmEvent::Behaviour(BehaviourEvent::Dcutr(event)) => {
                        if swarm.behaviour().allowed.trusted.contains(&event.remote_peer_id) {
                            match event.result {Ok(_)=>nat.hole(event.remote_peer_id,"succeeded",None),Err(error)=>nat.hole(event.remote_peer_id,"failed",Some(error.to_string().chars().take(200).collect()))}
                        }
                    },
                    SwarmEvent::Behaviour(BehaviourEvent::AutoNat(event)) => {
                        if swarm.behaviour().allowed.infrastructure.contains(&event.server) {
                            for entry in nat.observed.iter_mut().filter(|entry|entry.address==event.tested_addr&&entry.expires>Instant::now()) {entry.checked=Instant::now();entry.verified=Some(event.result.is_ok());}
                        }
                    },
                    SwarmEvent::Behaviour(BehaviourEvent::Relay(event)) => match event {
                        relay::client::Event::ReservationReqAccepted {..} => {}
                        relay::client::Event::OutboundCircuitEstablished {..} | relay::client::Event::InboundCircuitEstablished {..} => {}
                    },
                    SwarmEvent::Behaviour(BehaviourEvent::Identify(event)) => {
                        if let identify::Event::Received {peer_id,connection_id,info,..}=*event
                            && let Some(node)=relay_nodes.iter().find(|node|node.peer==peer_id) {
                            // Only an authenticated configured observer on its direct
                            // connection can report our own mapping. Ignore all claimed
                            // peer dial addresses and all raw candidate events.
                            let allow_private=private_ip(&node.address);
                            let loopback=swarm.behaviour().dcutr.policy.read().unwrap().allow_loopback;
                            if connections.get(&connection_id).is_some_and(|c|!c.relayed && c.address.contains("/quic-v1"))
                                && let Some(address)=direct_quic(&info.observed_addr,Some(*swarm.local_peer_id()),loopback,allow_private)
                                && nat.observe(peer_id,address) {
                                refresh_candidates(&mut swarm,&mut nat,&connections);
                            }
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Rendezvous(event)) => match event {
                        rendezvous::client::Event::Discovered {rendezvous_node,registrations,cookie} => {
                            if let Some(node)=relay_nodes.iter_mut().find(|node|node.peer==rendezvous_node && node.reserved) {
                                if registrations.is_empty() {node.cookie=None;node.discover=Instant::now()+Duration::from_secs(5);} else {node.cookie=Some(cookie);node.discover=Instant::now()+Duration::from_secs(1);}
                                remember_rendezvous(&mut rendezvous_entries,node,registrations,per_operator_capacity,*swarm.local_peer_id());
                            }
                        }
                        rendezvous::client::Event::Registered {rendezvous_node,ttl,..} => {
                            if let Some(node)=relay_nodes.iter_mut().find(|node|node.peer==rendezvous_node) {node.registered=true;node.error=None;node.register=Instant::now()+Duration::from_secs((ttl/2).clamp(1,150));}
                        }
                        rendezvous::client::Event::RegisterFailed {rendezvous_node,error,..} | rendezvous::client::Event::DiscoverFailed {rendezvous_node,error,..} => {
                            if let Some(node)=relay_nodes.iter_mut().find(|node|node.peer==rendezvous_node) {node.cookie=None;node.error=Some(format!("Rendezvous request failed: {error:?}"));}
                        }
                        rendezvous::client::Event::Expired {..} => {}
                    },
                    SwarmEvent::Behaviour(BehaviourEvent::Discovery(event)) => match event {
                        mdns::Event::Discovered(entries) => {
                            for (peer, address) in entries { discovery.observe(peer, &address, Instant::now()); }
                        }
                        mdns::Event::MachineNames(entries) => {
                            for (peer, address, name) in entries { discovery.set_name(peer, &address, name.as_deref(), Instant::now()); }
                        }
                        mdns::Event::Expired(entries) => {
                            for (peer, address) in entries { discovery.expire(peer, &address); }
                        }
                    },
                    SwarmEvent::Behaviour(BehaviourEvent::Pairing(event)) => match event {
                        request_response::Event::Message { peer, message, .. } => match message {
                            request_response::Message::Request { request, channel, .. } => {
                                if !swarm.behaviour().allowed.pairing_enabled {
                                    let _ = swarm.behaviour_mut().pairing.send_response(channel, json!({"error":"pairing window is closed"}));
                                } else if pairing_responses.len() >= CAPACITY || !pairing_rate.allow(peer) {
                                    let _ = swarm.behaviour_mut().pairing.send_response(channel, json!({"error":"pairing transport is busy"}));
                                } else {
                                    let (response, received) = oneshot::channel();
                                    if incoming_pairing.try_send(IncomingPairing { peer, request, response }).is_err() {
                                        let _ = swarm.behaviour_mut().pairing.send_response(channel, json!({"error":"pairing request queue full"}));
                                    } else {
                                        pairing_responses.push(Box::pin(async move { (peer, channel, tokio::time::timeout(REQUEST_TIMEOUT, received).await.ok().and_then(Result::ok)) }));
                                    }
                                }
                            }
                            request_response::Message::Response { request_id, response } => {
                                if let Some(entry) = pairing_pending.remove(&request_id) {
                                    if entry.peer == peer && swarm.behaviour().allowed.pairing_enabled { let _ = entry.response.send(Ok(response)); }
                                    else { let _ = entry.response.send(Err(anyhow!("pairing response identity mismatch or window closed"))); }
                                }
                            }
                        },
                        request_response::Event::OutboundFailure { request_id, error, .. } => {
                            if let Some(entry) = pairing_pending.remove(&request_id) { let _ = entry.response.send(Err(anyhow!("pairing request failed: {error}"))); }
                        }
                        request_response::Event::InboundFailure { .. } | request_response::Event::ResponseSent { .. } => {}
                    },
                    SwarmEvent::Behaviour(BehaviourEvent::Message(event)) => match event {
                        request_response::Event::Message { peer, message, .. } => match message {
                            request_response::Message::Request { request, channel, .. } => {
                                if !swarm.behaviour().allowed.trusted.contains(&peer) {
                                    let _ = swarm.behaviour_mut().messages.send_response(channel, WireResponse::Rejected { reason: "peer is not trusted".into(), retryable: false });
                                    continue;
                                }
                                if responses.len() >= CAPACITY {
                                    let _ = swarm.behaviour_mut().messages.send_response(channel, WireResponse::Rejected { reason: "network request capacity reached".into(), retryable: true });
                                } else {
                                    let (response, received) = oneshot::channel();
                                    if incoming.try_send(Incoming { peer, request, response }).is_err() {
                                        let _ = swarm.behaviour_mut().messages.send_response(channel, WireResponse::Rejected { reason: "network request queue full".into(), retryable: true });
                                    } else {
                                        responses.push(Box::pin(async move { (peer, channel, tokio::time::timeout(REQUEST_TIMEOUT, received).await.ok().and_then(Result::ok)) }));
                                    }
                                }
                            }
                            request_response::Message::Response { request_id, response } => {
                                if let Some(entry) = pending.remove(&request_id) {
                                    if entry.peer == peer && swarm.behaviour().allowed.trusted.contains(&peer) {
                                        let _ = entry.response.send(Ok(response));
                                    } else { let _ = entry.response.send(Err(anyhow!("response identity mismatch"))); }
                                }
                            }
                        },
                        request_response::Event::OutboundFailure { request_id,connection_id, error, .. } => {
                            if connections.get(&connection_id).is_some_and(|c|!c.relayed&&!swarm.behaviour().allowed.infrastructure.contains(&c.peer)) {swarm.close_connection(connection_id);}
                            last_error = Some(error.to_string());
                            if let Some(entry) = pending.remove(&request_id) { let _ = entry.response.send(Err(anyhow!("network request failed: {error}"))); }
                        }
                        request_response::Event::InboundFailure { error, .. } => { last_error = Some(error.to_string()); }
                        request_response::Event::ResponseSent { .. } => {}
                    },
                    _ => {}
                }
                publish(&status, &listening, &connected, &last_error, &discovery, lan, &relay_nodes, &rendezvous_entries, &nat, &connections);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::wire::Operation;
    use futures::io::Cursor;

    #[test]
    fn hole_punch_addresses_are_scoped_canonical_quic_and_cannot_map_ipv4_policy_through_ipv6() {
        let peer = PeerId::random();
        for address in [
            "/ip4/169.254.169.254/udp/443/quic-v1",
            "/ip6/::ffff:169.254.169.254/udp/443/quic-v1",
            "/ip6/::ffff:127.0.0.1/udp/443/quic-v1",
            "/ip6/::192.168.1.1/udp/443/quic-v1",
            "/ip4/240.1.1.1/udp/443/quic-v1",
            "/ip4/192.0.0.8/udp/443/quic-v1",
            "/ip4/224.0.0.1/udp/443/quic-v1",
            "/ip4/11.1.1.1/tcp/443",
        ] {
            assert!(
                direct_quic(&address.parse().unwrap(), Some(peer), true, true).is_none(),
                "{address}"
            );
        }
        for address in [
            "/ip4/10.1.1.1/udp/4001/quic-v1",
            "/ip4/198.18.1.1/udp/4001/quic-v1",
            "/ip4/100.100.100.200/udp/4001/quic-v1",
            "/ip6/fec0::1/udp/4001/quic-v1",
        ] {
            assert!(direct_quic(&address.parse().unwrap(), Some(peer), false, false).is_none());
            assert!(direct_quic(&address.parse().unwrap(), Some(peer), false, true).is_some());
        }
        assert!(
            direct_quic(
                &format!("/ip4/11.1.1.1/udp/4001/quic-v1/p2p/{}", PeerId::random())
                    .parse()
                    .unwrap(),
                Some(peer),
                false,
                false
            )
            .is_none()
        );
        assert!(
            direct_quic(
                &"/ip4/11.1.1.1/udp/4001/quic-v1".parse().unwrap(),
                Some(peer),
                false,
                false
            )
            .is_some()
        );
    }

    #[test]
    fn public_candidates_take_precedence_over_private_operator_observations() {
        let mut nat = NatRuntime::new();
        let private: Multiaddr = "/ip4/10.1.1.1/udp/4001/quic-v1".parse().unwrap();
        let public: Multiaddr = "/ip4/11.1.1.1/udp/4001/quic-v1".parse().unwrap();
        nat.observe(PeerId::random(), private.clone());
        assert_eq!(nat.candidates(), vec![private]);
        nat.observe(PeerId::random(), public.clone());
        assert_eq!(nat.candidates(), vec![public]);
    }

    #[test]
    fn nat_protocol_scopes_never_treat_pairing_permission_as_trust_or_infrastructure() {
        let trusted = PeerId::random();
        let infra = PeerId::random();
        let unknown = PeerId::random();
        let policy = NatPolicy {
            trusted: HashSet::from([trusted]),
            infrastructure: HashSet::from([infra]),
            allow_loopback: false,
            allow_private: false,
        };
        assert!(policy.permits(NatScope::TrustedEndpoint, &trusted));
        assert!(!policy.permits(NatScope::TrustedEndpoint, &infra));
        assert!(!policy.permits(NatScope::Infrastructure, &trusted));
        assert!(policy.permits(NatScope::Infrastructure, &infra));
        assert!(!policy.permits(NatScope::TrustedEndpoint, &unknown));
    }

    #[test]
    fn observations_replace_expire_and_never_claim_public_without_a_nonce_verified_probe() {
        let observer = PeerId::random();
        let mut nat = NatRuntime::new();
        let first: Multiaddr = "/ip4/11.1.1.1/udp/4001/quic-v1".parse().unwrap();
        let second: Multiaddr = "/ip4/11.1.1.2/udp/4001/quic-v1".parse().unwrap();
        assert!(nat.observe(observer, first.clone()));
        assert_eq!(nat.view()["reachability"], "unknown");
        nat.observed[0].verified = Some(true);
        assert_eq!(nat.view()["reachability"], "public");
        assert!(nat.observe(observer, second.clone()));
        assert_eq!(nat.candidates(), vec![second]);
        assert_eq!(nat.view()["reachability"], "unknown");
        nat.observed[0].expires = Instant::now() - Duration::from_secs(1);
        assert!(nat.candidates().is_empty());
        assert_eq!(nat.view()["reachability"], "unknown");
    }

    #[test]
    fn pairing_budget_bounds_peer_floods_and_rotating_identities() {
        let mut rate = PairingRate::new();
        let one = PeerId::random();
        for _ in 0..8 {
            assert!(rate.allow(one));
        }
        assert!(!rate.allow(one));
        for _ in 0..24 {
            assert!(rate.allow(PeerId::random()));
        }
        assert!(!rate.allow(PeerId::random()));
        assert_eq!(rate.peers.len(), 25);
        rate.started = Instant::now() - Duration::from_secs(2);
        assert!(rate.allow(one));
        assert_eq!(rate.peers.len(), 1);
    }

    #[test]
    fn untrusted_connections_have_separate_budget_from_trusted_connections() {
        let trusted = PeerId::random();
        let mut admission = Admission {
            trusted: HashSet::from([trusted]),
            pairing_enabled: true,
            infrastructure: HashSet::new(),
            established: HashMap::new(),
            contacts: HashMap::new(),
        };
        for _ in 0..4 {
            admission.established.insert(
                ConnectionId::new_unchecked(admission.established.len()),
                PeerId::random(),
            );
        }
        assert!(admission.enforce(&PeerId::random()).is_err());
        assert!(admission.enforce(&trusted).is_ok());
        admission.established.clear();
        assert!(admission.enforce(&PeerId::random()).is_ok());
        admission.pairing_enabled = false;
        assert!(admission.enforce(&PeerId::random()).is_err());
    }

    #[test]
    fn expired_contact_connection_cannot_use_a_later_pairing_window() {
        let id = ConnectionId::new_unchecked(31);
        let mut admission = Admission {
            trusted: HashSet::new(),
            pairing_enabled: true,
            infrastructure: HashSet::new(),
            established: HashMap::new(),
            contacts: HashMap::from([(id, false)]),
        };
        let address: Multiaddr = "/ip4/127.0.0.1/tcp/1234".parse().unwrap();
        assert!(
            admission
                .handle_established_outbound_connection(
                    id,
                    PeerId::random(),
                    &address,
                    Endpoint::Dialer,
                    PortUse::New
                )
                .is_err()
        );
        admission.contacts.insert(id, true);
        assert!(
            admission
                .handle_established_outbound_connection(
                    id,
                    PeerId::random(),
                    &address,
                    Endpoint::Dialer,
                    PortUse::New
                )
                .is_ok()
        );
    }

    #[tokio::test]
    async fn pairing_codec_rejects_oversized_frames_before_reading_body_or_writing_header() {
        let mut input = Cursor::new(((PAIRING_FRAME + 1) as u32).to_be_bytes());
        assert!(
            read_frame_limit::<_, Value>(&mut input, PAIRING_FRAME)
                .await
                .is_err()
        );
        let mut output = Cursor::new(Vec::new());
        assert!(
            write_frame_limit(
                &mut output,
                json!({"oversized":"x".repeat(PAIRING_FRAME)}),
                PAIRING_FRAME
            )
            .await
            .is_err()
        );
        assert!(output.into_inner().is_empty());
    }

    #[test]
    fn public_discovery_keeps_only_identity_bound_configured_relay_paths_with_fair_capacity() {
        let relay = PeerId::random();
        let node = RelayNode::new(
            relay,
            format!("/ip4/127.0.0.1/udp/1234/quic-v1/p2p/{relay}")
                .parse()
                .unwrap(),
        );
        let local = PeerId::random();
        let mut entries = Vec::new();
        for _ in 0..3 {
            let key = libp2p::identity::Keypair::generate_ed25519();
            let peer = key.public().to_peer_id();
            let registration = rendezvous::Registration {
                namespace: rendezvous::Namespace::from_static(RENDEZVOUS_NAMESPACE),
                record: libp2p::core::PeerRecord::new(&key, vec![circuit_route(&node, peer)])
                    .unwrap(),
                ttl: 30,
            };
            remember_rendezvous(&mut entries, &node, vec![registration], 2, local);
        }
        assert_eq!(entries.len(), 2);
        let key = libp2p::identity::Keypair::generate_ed25519();
        let direct = rendezvous::Registration {
            namespace: rendezvous::Namespace::from_static(RENDEZVOUS_NAMESPACE),
            record: libp2p::core::PeerRecord::new(
                &key,
                vec!["/ip4/127.0.0.1/udp/9999/quic-v1".parse().unwrap()],
            )
            .unwrap(),
            ttl: 30,
        };
        remember_rendezvous(&mut entries, &node, vec![direct], 256, local);
        assert_eq!(entries.len(), 2);
        entries[0].expires = Instant::now() - Duration::from_secs(1);
        remember_rendezvous(&mut entries, &node, vec![], 256, local);
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn codec_bounds_and_rejects_admin_and_malformed_frames() {
        let mut oversized = Cursor::new(((MAX_FRAME + 1) as u32).to_be_bytes());
        assert!(read_frame::<_, WireRequest>(&mut oversized).await.is_err());
        let mut truncated = Cursor::new(vec![0, 0, 0, 2, 1]);
        assert!(read_frame::<_, WireRequest>(&mut truncated).await.is_err());
        for value in [
            r#"{"version":1,"operation":{"op":"pause","paused":true}}"#,
            r#"{"version":1,"operation":{"op":"directory"},"unexpected":1}"#,
        ] {
            let mut bytes = (value.len() as u32).to_be_bytes().to_vec();
            bytes.extend_from_slice(value.as_bytes());
            assert!(
                read_frame::<_, WireRequest>(&mut Cursor::new(bytes))
                    .await
                    .is_err()
            );
        }
        let mut output = Cursor::new(Vec::new());
        assert!(
            write_frame(
                &mut output,
                WireResponse::Rejected {
                    reason: "x".repeat(MAX_FRAME),
                    retryable: false
                }
            )
            .await
            .is_err()
        );
        assert!(output.into_inner().is_empty());
        let request = WireRequest::new(Operation::Directory);
        let mut output = Cursor::new(Vec::new());
        write_frame(&mut output, request).await.unwrap();
        output.set_position(0);
        assert!(matches!(
            read_frame::<_, WireRequest>(&mut output)
                .await
                .unwrap()
                .operation,
            Operation::Directory
        ));
    }
}
