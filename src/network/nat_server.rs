//! Bounded AutoNAT v2 service. Reachability probes are not endpoint trust.
use either::Either;
use libp2p::{
    Multiaddr, PeerId, autonat,
    core::{Endpoint, transport::PortUse},
    multiaddr::Protocol,
    swarm::{
        CloseConnection, ConnectionDenied, ConnectionId, DialError, FromSwarm, NetworkBehaviour,
        THandler, THandlerInEvent, THandlerOutEvent, ToSwarm, behaviour::DialFailure,
    },
};
use std::{
    collections::{HashMap, VecDeque},
    io,
    task::{Context, Poll},
    time::{Duration, Instant},
};

type Inner = autonat::v2::server::Behaviour;
const MAX_PENDING: usize = 16;
const GLOBAL_PER_MINUTE: u32 = 256;
const PEER_PER_MINUTE: u32 = 4;

pub struct NatServer {
    inner: Inner,
    connections: HashMap<ConnectionId, (PeerId, Multiaddr)>,
    origins: VecDeque<(PeerId, Multiaddr)>,
    pending: HashMap<ConnectionId, (PeerId, Multiaddr)>,
    callbacks: HashMap<ConnectionId, (PeerId, Instant)>,
    closing: VecDeque<(PeerId, ConnectionId)>,
    epoch: Instant,
    total: u32,
    peers: HashMap<PeerId, u32>,
    capacity: usize,
    pub rejected: u64,
}

/// Compare concrete sockets, not string prefixes, DNS hints or peer-supplied IPs.
fn socket(address: &Multiaddr, expected: PeerId) -> Option<(std::net::IpAddr, u16)> {
    let mut parts = address.iter();
    let ip = match parts.next()? {
        Protocol::Ip4(ip) => std::net::IpAddr::V4(ip),
        Protocol::Ip6(ip) => std::net::IpAddr::V6(ip),
        _ => return None,
    };
    if ip.is_unspecified() || ip.is_multicast() {
        return None;
    }
    let Some(Protocol::Udp(port)) = parts.next() else {
        return None;
    };
    if port == 0 || !matches!(parts.next(), Some(Protocol::QuicV1)) {
        return None;
    }
    match parts.next() {
        None => {}
        Some(Protocol::P2p(id)) if id == expected && parts.next().is_none() => {}
        _ => return None,
    }
    Some((ip, port))
}
impl NatServer {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Inner::default(),
            connections: HashMap::new(),
            origins: VecDeque::new(),
            pending: HashMap::new(),
            callbacks: HashMap::new(),
            closing: VecDeque::new(),
            epoch: Instant::now(),
            total: 0,
            peers: HashMap::new(),
            capacity: capacity.clamp(2, 4096),
            rejected: 0,
        }
    }
    fn allow(&mut self, peer: PeerId) -> bool {
        if self.epoch.elapsed() >= Duration::from_secs(60) {
            self.epoch = Instant::now();
            self.total = 0;
            self.peers.clear();
        }
        if self.total >= GLOBAL_PER_MINUTE
            || (!self.peers.contains_key(&peer) && self.peers.len() >= self.capacity)
        {
            return false;
        }
        let count = self.peers.entry(peer).or_default();
        if *count >= PEER_PER_MINUTE {
            return false;
        }
        *count += 1;
        self.total += 1;
        true
    }
    fn reject(&mut self) {
        self.rejected = self.rejected.saturating_add(1);
    }
    fn aborted(&mut self, id: ConnectionId, peer: Option<PeerId>) {
        self.inner
            .on_swarm_event(FromSwarm::DialFailure(DialFailure {
                peer_id: peer,
                connection_id: id,
                error: &DialError::Aborted,
            }));
    }
}
impl NetworkBehaviour for NatServer {
    type ConnectionHandler = <Inner as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = autonat::v2::server::Event;
    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner
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
        self.inner
            .handle_established_outbound_connection(id, peer, address, role, port)
    }
    fn handle_pending_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: Option<PeerId>,
        addresses: &[Multiaddr],
        role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if let Some((expected, observed)) = self.pending.get(&id) {
            let valid = peer == Some(*expected)
                && addresses.len() == 1
                && socket(observed, *expected)
                    .is_some_and(|source| socket(&addresses[0], *expected) == Some(source));
            if !valid {
                self.reject();
                return Err(ConnectionDenied::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "AutoNAT dialback must match the authenticated requesting socket",
                )));
            }
        }
        self.inner
            .handle_pending_outbound_connection(id, peer, addresses, role)
    }
    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(e) => {
                if self.pending.remove(&e.connection_id).is_some() {
                    self.callbacks
                        .insert(e.connection_id, (e.peer_id, Instant::now()));
                }
                if self.connections.len() < self.capacity
                    && socket(e.endpoint.get_remote_address(), e.peer_id).is_some()
                {
                    self.connections.insert(
                        e.connection_id,
                        (e.peer_id, e.endpoint.get_remote_address().clone()),
                    );
                }
            }
            FromSwarm::ConnectionClosed(e) => {
                self.connections.remove(&e.connection_id);
                self.pending.remove(&e.connection_id);
                self.callbacks.remove(&e.connection_id);
                self.closing.retain(|(_, id)| *id != e.connection_id);
            }
            FromSwarm::AddressChange(e) => {
                if socket(e.new.get_remote_address(), e.peer_id).is_some() {
                    if let Some(entry) = self.connections.get_mut(&e.connection_id) {
                        entry.1 = e.new.get_remote_address().clone();
                    }
                } else {
                    self.connections.remove(&e.connection_id);
                }
            }
            FromSwarm::DialFailure(e) => {
                self.pending.remove(&e.connection_id);
            }
            _ => {}
        }
        self.inner.on_swarm_event(event)
    }
    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        // This variant requests an actual dialback; all status/cleanup events still
        // reach the upstream implementation without consuming probe budget.
        if matches!(&event, Either::Left(Either::Left(_))) && self.callbacks.remove(&id).is_some() {
            self.closing.push_back((peer, id));
        }
        if matches!(&event, Either::Right(Either::Left(_))) {
            let origin = self
                .connections
                .get(&id)
                .filter(|(actual, _)| *actual == peer)
                .map(|(_, address)| address.clone());
            if origin.is_none()
                || self.origins.len() + self.pending.len() + self.callbacks.len() >= MAX_PENDING
                || !self.allow(peer)
            {
                self.reject();
                return;
            }
            self.origins.push_back((peer, origin.unwrap()));
        }
        self.inner.on_connection_handler_event(peer, id, event)
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        // Reclaim only NAT-owned callback sockets. Keep the original relay/control
        // connection, so repeated checks cannot consume its per-peer connection slot.
        let expired: Vec<_> = self
            .callbacks
            .iter()
            .filter(|(_, (_, at))| at.elapsed() >= Duration::from_secs(15))
            .map(|(id, (peer, _))| (*id, *peer))
            .collect();
        for (id, peer) in expired {
            self.callbacks.remove(&id);
            self.closing.push_back((peer, id));
        }
        if let Some((peer_id, id)) = self.closing.pop_front() {
            return Poll::Ready(ToSwarm::CloseConnection {
                peer_id,
                connection: CloseConnection::One(id),
            });
        }
        loop {
            match self.inner.poll(cx) {
                Poll::Ready(ToSwarm::Dial { opts }) => {
                    let expected = opts.get_peer_id();
                    let id = opts.connection_id();
                    let origin = self.origins.pop_front();
                    if let Some((peer, address)) = origin
                        && Some(peer) == expected
                        && self.pending.len() < MAX_PENDING
                    {
                        // Preserve the upstream allocate_new_port flag. Inspect the
                        // actual dial addresses in handle_pending_outbound_connection.
                        self.pending.insert(id, (peer, address));
                        return Poll::Ready(ToSwarm::Dial { opts });
                    }
                    self.reject();
                    self.aborted(id, expected);
                }
                other => return other,
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn callback_target_requires_exact_authenticated_socket_and_peer() {
        let peer = PeerId::random();
        let other = PeerId::random();
        let base: Multiaddr = "/ip4/198.18.0.2/udp/5000/quic-v1".parse().unwrap();
        assert_eq!(
            socket(&base, peer),
            socket(&format!("{base}/p2p/{peer}").parse().unwrap(), peer)
        );
        assert_ne!(
            socket(&base, peer),
            socket(&"/ip4/198.18.0.3/udp/5000/quic-v1".parse().unwrap(), peer)
        );
        assert_ne!(
            socket(&base, peer),
            socket(&"/ip4/198.18.0.2/udp/5001/quic-v1".parse().unwrap(), peer)
        );
        assert!(socket(&format!("{base}/p2p/{other}").parse().unwrap(), peer).is_none());
        assert!(socket(&"/dns/example.com/udp/5000/quic-v1".parse().unwrap(), peer).is_none());
        assert!(socket(&"/ip4/0.0.0.0/udp/5000/quic-v1".parse().unwrap(), peer).is_none());
        assert!(
            socket(
                &format!("{base}/p2p/{peer}/p2p-circuit").parse().unwrap(),
                peer
            )
            .is_none()
        );
    }
    #[test]
    fn probe_budget_is_bounded_under_repeated_requests_and_identity_churn() {
        let mut server = NatServer::new(2);
        let a = PeerId::random();
        let b = PeerId::random();
        for _ in 0..4 {
            assert!(server.allow(a));
        }
        assert!(!server.allow(a));
        assert!(server.allow(b));
        assert!(!server.allow(PeerId::random()));
        assert_eq!(server.peers.len(), 2);
        server.epoch = Instant::now() - Duration::from_secs(61);
        assert!(server.allow(a));
        assert_eq!(server.total, 1);
    }
}

#[cfg(test)]
mod gate_tests {
    use super::*;
    #[test]
    fn dialback_gate_denies_other_ports_and_hosts_and_cleans_failed_attempts() {
        let peer = PeerId::random();
        let id = ConnectionId::new_unchecked(41);
        let observed: Multiaddr = "/ip4/198.18.0.2/udp/5000/quic-v1".parse().unwrap();
        let mut server = NatServer::new(16);
        server.pending.insert(id, (peer, observed.clone()));
        assert!(
            server
                .handle_pending_outbound_connection(
                    id,
                    Some(peer),
                    std::slice::from_ref(&observed),
                    Endpoint::Dialer
                )
                .is_ok()
        );
        for address in [
            "/ip4/198.18.0.2/udp/5001/quic-v1",
            "/ip4/198.18.0.3/udp/5000/quic-v1",
        ] {
            assert!(
                server
                    .handle_pending_outbound_connection(
                        id,
                        Some(peer),
                        &[address.parse().unwrap()],
                        Endpoint::Dialer
                    )
                    .is_err()
            );
        }
        assert!(
            server
                .handle_pending_outbound_connection(
                    id,
                    Some(PeerId::random()),
                    std::slice::from_ref(&observed),
                    Endpoint::Dialer
                )
                .is_err()
        );
        assert!(
            server
                .handle_pending_outbound_connection(
                    id,
                    Some(peer),
                    &[observed.clone(), observed],
                    Endpoint::Dialer
                )
                .is_err()
        );
        assert_eq!(server.rejected, 4);
        server.on_swarm_event(FromSwarm::DialFailure(DialFailure {
            peer_id: Some(peer),
            connection_id: id,
            error: &DialError::Aborted,
        }));
        assert!(server.pending.is_empty());
    }
    #[test]
    fn observed_socket_is_learned_only_after_establishment_and_removed_on_close() {
        use libp2p::{
            core::ConnectedPoint,
            swarm::behaviour::{ConnectionClosed, ConnectionEstablished},
        };
        let mut server = NatServer::new(16);
        let peer = PeerId::random();
        let id = ConnectionId::new_unchecked(42);
        let local: Multiaddr = "/ip4/198.18.0.10/udp/4001/quic-v1".parse().unwrap();
        let remote: Multiaddr = "/ip4/198.18.0.2/udp/5000/quic-v1".parse().unwrap();
        // A handler may be constructed before another behaviour denies the connection.
        let _ = server
            .handle_established_inbound_connection(id, peer, &local, &remote)
            .unwrap();
        assert!(server.connections.is_empty());
        let endpoint = ConnectedPoint::Listener {
            local_addr: local,
            send_back_addr: remote,
        };
        server.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
            peer_id: peer,
            connection_id: id,
            endpoint: &endpoint,
            failed_addresses: &[],
            other_established: 0,
        }));
        assert_eq!(server.connections.len(), 1);
        server.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: peer,
            connection_id: id,
            endpoint: &endpoint,
            cause: None,
            remaining_established: 0,
        }));
        assert!(server.connections.is_empty());
    }
}

#[cfg(test)]
mod callback_tests {
    use super::*;
    #[test]
    fn expired_nat_callback_is_closed_without_retiring_original_control_connection() {
        let mut server = NatServer::new(16);
        let peer = PeerId::random();
        let control = ConnectionId::new_unchecked(91);
        let callback = ConnectionId::new_unchecked(92);
        server.connections.insert(
            control,
            (peer, "/ip4/198.18.0.2/udp/5000/quic-v1".parse().unwrap()),
        );
        server
            .callbacks
            .insert(callback, (peer, Instant::now() - Duration::from_secs(16)));
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(
            matches!(server.poll(&mut context),Poll::Ready(ToSwarm::CloseConnection{peer_id,connection:CloseConnection::One(id)}) if peer_id==peer&&id==callback)
        );
        assert!(server.connections.contains_key(&control));
        assert!(server.callbacks.is_empty());
    }
}
