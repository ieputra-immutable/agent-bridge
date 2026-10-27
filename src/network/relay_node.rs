//! Independently operated rendezvous and Circuit Relay v2 node.
//!
//! The node offers routing, not trust or application administration. It never
//! terminates the encrypted endpoint-to-endpoint stream inside a relay circuit.
use super::identity::Identity;
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, connection_limits,
    core::{Endpoint, transport::PortUse},
    identify, noise, relay, rendezvous,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, SwarmEvent, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm,
    },
    tcp, yamux,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    convert::Infallible,
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant},
};
use tokio::{sync::watch, task::JoinHandle};

pub const NAMESPACE: &str = "agent-bridge";
fn is_tcp(address: &Multiaddr) -> bool {
    address
        .iter()
        .any(|p| matches!(p, libp2p::multiaddr::Protocol::Tcp(_)))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Limits {
    pub max_reservations: usize,
    pub max_circuits: usize,
    pub max_circuit_bytes: u64,
    pub max_circuit_seconds: u64,
    pub reservation_seconds: u64,
    pub max_registrations: usize,
    pub registration_seconds: u64,
    pub max_connections: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_reservations: 128,
            max_circuits: 128,
            max_circuit_bytes: 8 * 1024 * 1024,
            max_circuit_seconds: 300,
            reservation_seconds: 300,
            max_registrations: 128,
            registration_seconds: 300,
            max_connections: 256,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=4096).contains(&self.max_reservations),
            "Reservation limit must be 1–4096"
        );
        ensure!(
            (1..=4096).contains(&self.max_circuits),
            "Circuit limit must be 1–4096"
        );
        ensure!(
            (1024..=1024 * 1024 * 1024).contains(&self.max_circuit_bytes),
            "Circuit byte limit must be 1 KiB–1 GiB"
        );
        ensure!(
            (1..=3600).contains(&self.max_circuit_seconds),
            "Circuit duration must be 1–3600 seconds"
        );
        ensure!(
            (30..=3600).contains(&self.reservation_seconds),
            "Reservation lifetime must be 30–3600 seconds"
        );
        ensure!(
            (1..=4096).contains(&self.max_registrations),
            "Registration limit must be 1–4096"
        );
        ensure!(
            (30..=600).contains(&self.registration_seconds),
            "Registration lifetime must be 30–600 seconds"
        );
        ensure!(
            (2..=4096).contains(&self.max_connections),
            "Connection limit must be 2–4096"
        );
        Ok(())
    }
}

/// Rates rendezvous handler events before the underlying server mutates state.
/// Each request produces only a small number of events; exceeding the budget
/// disconnects the peer rather than growing a queue of delayed work.
struct BoundedRendezvous {
    inner: rendezvous::server::Behaviour,
    epoch: Instant,
    count: u32,
    per_peer: HashMap<PeerId, u32>,
    disconnect: VecDeque<PeerId>,
    capacity: usize,
}
impl BoundedRendezvous {
    fn new(config: rendezvous::server::Config, capacity: usize) -> Self {
        Self {
            inner: rendezvous::server::Behaviour::new(config),
            epoch: Instant::now(),
            count: 0,
            per_peer: HashMap::new(),
            disconnect: VecDeque::new(),
            capacity,
        }
    }
    fn allow(&mut self, peer: PeerId) -> bool {
        if self.epoch.elapsed() >= Duration::from_secs(1) {
            self.epoch = Instant::now();
            self.count = 0;
            self.per_peer.clear();
        }
        if self.count >= 256
            || (!self.per_peer.contains_key(&peer) && self.per_peer.len() >= self.capacity)
        {
            return false;
        }
        let count = self.per_peer.entry(peer).or_default();
        if *count >= 32 {
            return false;
        }
        *count += 1;
        self.count += 1;
        true
    }
}
impl NetworkBehaviour for BoundedRendezvous {
    type ConnectionHandler = <rendezvous::server::Behaviour as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = rendezvous::server::Event;
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
    fn on_swarm_event(&mut self, event: FromSwarm) {
        self.inner.on_swarm_event(event);
    }
    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        if self.allow(peer) {
            self.inner.on_connection_handler_event(peer, id, event);
        } else if self.disconnect.len() < self.capacity && !self.disconnect.contains(&peer) {
            self.disconnect.push_back(peer);
        }
    }
    fn poll(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(peer_id) = self.disconnect.pop_front() {
            return Poll::Ready(ToSwarm::CloseConnection {
                peer_id,
                connection: libp2p::swarm::CloseConnection::All,
            });
        }
        self.inner.poll(cx)
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "Event")]
struct Behaviour {
    limits: connection_limits::Behaviour,
    relay: relay::Behaviour,
    rendezvous: BoundedRendezvous,
    identify: identify::Behaviour,
    autonat: super::nat_server::NatServer,
}
enum Event {
    Relay(relay::Event),
    Rendezvous(Box<rendezvous::server::Event>),
    Identify(Box<identify::Event>),
    AutoNat(Box<libp2p::autonat::v2::server::Event>),
}
impl From<libp2p::autonat::v2::server::Event> for Event {
    fn from(event: libp2p::autonat::v2::server::Event) -> Self {
        Self::AutoNat(Box::new(event))
    }
}
impl From<relay::Event> for Event {
    fn from(event: relay::Event) -> Self {
        Self::Relay(event)
    }
}
impl From<rendezvous::server::Event> for Event {
    fn from(event: rendezvous::server::Event) -> Self {
        Self::Rendezvous(Box::new(event))
    }
}
impl From<identify::Event> for Event {
    fn from(event: identify::Event) -> Self {
        Self::Identify(Box::new(event))
    }
}
impl From<Infallible> for Event {
    fn from(event: Infallible) -> Self {
        match event {}
    }
}

pub struct RunningNode {
    pub peer_id: PeerId,
    pub status: watch::Receiver<Value>,
    task: JoinHandle<()>,
}
impl RunningNode {
    /// Wait for the node's swarm to be dropped before reusing its listener/state.
    pub async fn shutdown(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}
impl Drop for RunningNode {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Starts a node without touching local broker state. Concrete listen addresses
/// are advertised automatically; wildcard binds require an explicit public hint.
pub fn start(
    keypair: libp2p::identity::Keypair,
    listen: Multiaddr,
    advertise: Option<Multiaddr>,
    limits: Limits,
) -> Result<RunningNode> {
    start_with_listeners(keypair, vec![(listen, advertise)], limits)
}

/// Bind QUIC and/or encrypted TCP listeners using one infrastructure identity.
pub fn start_with_listeners(
    keypair: libp2p::identity::Keypair,
    listeners: Vec<(Multiaddr, Option<Multiaddr>)>,
    limits: Limits,
) -> Result<RunningNode> {
    limits.validate()?;
    ensure!(
        !listeners.is_empty() && listeners.len() <= 2,
        "Use one or two relay listeners"
    );
    let mut advertised = Vec::new();
    let mut seen = BTreeSet::new();
    for (listen, advertise) in &listeners {
        super::store::validate_address(&listen.to_string(), true)?;
        ensure!(seen.insert(listen.to_string()), "Duplicate relay listener");
        let wildcard = matches!(listen.iter().next(), Some(libp2p::multiaddr::Protocol::Ip4(ip)) if ip.is_unspecified())
            || matches!(listen.iter().next(), Some(libp2p::multiaddr::Protocol::Ip6(ip)) if ip.is_unspecified());
        ensure!(
            !wildcard || advertise.is_some(),
            "A wildcard relay listener requires an explicit advertised address"
        );
        if let Some(address) = advertise {
            super::store::validate_address(&address.to_string(), false)?;
            ensure!(
                !address.iter().any(|part| matches!(
                    part,
                    libp2p::multiaddr::Protocol::P2p(_) | libp2p::multiaddr::Protocol::P2pCircuit
                )),
                "Relay advertisement must be a direct transport address"
            );
            ensure!(
                is_tcp(address) == is_tcp(listen),
                "Relay advertisement transport must match its listener"
            );
            advertised.push(address.clone());
        }
    }
    let peer_id = keypair.public().to_peer_id();
    let relay_config = relay::Config {
        max_reservations: limits.max_reservations,
        max_reservations_per_peer: 1,
        reservation_duration: Duration::from_secs(limits.reservation_seconds),
        max_circuits: limits.max_circuits,
        max_circuits_per_peer: 4.min(limits.max_circuits),
        max_circuit_duration: Duration::from_secs(limits.max_circuit_seconds),
        max_circuit_bytes: limits.max_circuit_bytes,
        ..Default::default()
    };
    let rendezvous_config = rendezvous::server::Config::default()
        .with_namespace(rendezvous::Namespace::from_static(NAMESPACE))
        .with_min_ttl(30)
        .with_max_ttl(limits.registration_seconds)
        .with_max_registration_per_peer(1)
        .with_max_registration_total(limits.max_registrations)
        .with_max_stored_cookies(limits.max_registrations);
    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_dns()?
        .with_behaviour(|key| Behaviour {
            limits: connection_limits::Behaviour::new(
                connection_limits::ConnectionLimits::default()
                    .with_max_pending_incoming(Some(16))
                    .with_max_pending_outgoing(Some(16))
                    .with_max_established(Some(limits.max_connections))
                    .with_max_established_per_peer(Some(3)),
            ),
            relay: relay::Behaviour::new(peer_id, relay_config),
            autonat: super::nat_server::NatServer::new(limits.max_connections as usize),
            rendezvous: BoundedRendezvous::new(rendezvous_config, limits.max_connections as usize),
            identify: identify::Behaviour::new(
                identify::Config::new("/agent-bridge/relay/1".into(), key.public())
                    .with_push_listen_addr_updates(true),
            ),
        })?
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    for address in &advertised {
        swarm.add_external_address(address.clone());
    }
    for (listen, _) in listeners {
        swarm
            .listen_on(listen)
            .context("Could not listen on relay transport address")?;
    }
    let (sender, status) = watch::channel(
        json!({"peer_id":peer_id.to_string(),"listening":[],"advertised":advertised.first().map(ToString::to_string),"advertised_addresses":advertised.iter().map(ToString::to_string).collect::<Vec<_>>(),"reservations":0,"circuits":0,"registrations":0,"limits":limits,"last_error":null}),
    );
    let task = tokio::spawn(run(swarm, sender, advertised));
    Ok(RunningNode {
        peer_id,
        status,
        task,
    })
}

async fn run(
    mut swarm: Swarm<Behaviour>,
    status: watch::Sender<Value>,
    advertised: Vec<Multiaddr>,
) {
    let mut listening = BTreeSet::new();
    let mut reservations = HashSet::new();
    let mut circuits = HashMap::<(PeerId, PeerId), u32>::new();
    let mut circuits_opened = 0u64;
    let mut registrations = HashSet::new();
    let mut last_error = None;
    let mut autonat_successful = 0u64;
    let mut autonat_failed = 0u64;
    let mut denied_reservations = 0u64;
    let mut denied_circuits = 0u64;
    let mut rejected_registrations = 0u64;
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                listening.insert(address.to_string());
                // Never learn our public address from an unauthenticated peer's
                // Identify claim. Only operator hints or actual concrete listeners.
                if !advertised
                    .iter()
                    .any(|hint| is_tcp(hint) == is_tcp(&address))
                    && super::store::validate_address(&address.to_string(), false).is_ok()
                {
                    swarm.add_external_address(address);
                }
            }
            SwarmEvent::ExpiredListenAddr { address, .. } => {
                listening.remove(&address.to_string());
                if !advertised
                    .iter()
                    .any(|hint| is_tcp(hint) == is_tcp(&address))
                {
                    swarm.remove_external_address(&address);
                }
            }
            SwarmEvent::Behaviour(Event::AutoNat(event)) => {
                if event.result.is_ok() {
                    autonat_successful = autonat_successful.saturating_add(1);
                } else {
                    autonat_failed = autonat_failed.saturating_add(1);
                }
            }
            SwarmEvent::Behaviour(Event::Relay(event)) => match event {
                relay::Event::ReservationReqDenied { .. } => {
                    denied_reservations = denied_reservations.saturating_add(1);
                }
                relay::Event::CircuitReqDenied { .. } => {
                    denied_circuits = denied_circuits.saturating_add(1);
                }
                relay::Event::ReservationReqAccepted { src_peer_id, .. } => {
                    reservations.insert(src_peer_id);
                }
                relay::Event::ReservationClosed { src_peer_id }
                | relay::Event::ReservationTimedOut { src_peer_id } => {
                    reservations.remove(&src_peer_id);
                }
                relay::Event::CircuitReqAccepted {
                    src_peer_id,
                    dst_peer_id,
                } => {
                    *circuits.entry((src_peer_id, dst_peer_id)).or_default() += 1;
                    circuits_opened = circuits_opened.saturating_add(1);
                }
                relay::Event::CircuitClosed {
                    src_peer_id,
                    dst_peer_id,
                    ..
                } => {
                    let key = (src_peer_id, dst_peer_id);
                    if let Some(count) = circuits.get_mut(&key) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            circuits.remove(&key);
                        }
                    }
                }
                _ => {}
            },
            SwarmEvent::Behaviour(Event::Rendezvous(event)) => match *event {
                rendezvous::server::Event::PeerNotRegistered { .. } => {
                    rejected_registrations = rejected_registrations.saturating_add(1);
                }
                rendezvous::server::Event::PeerRegistered { peer, registration } => {
                    registrations.insert((peer, registration.namespace.to_string()));
                }
                rendezvous::server::Event::PeerUnregistered { peer, namespace } => {
                    registrations.remove(&(peer, namespace.to_string()));
                }
                rendezvous::server::Event::RegistrationExpired(registration) => {
                    registrations.remove(&(
                        registration.record.peer_id(),
                        registration.namespace.to_string(),
                    ));
                }
                _ => {}
            },
            // Identity events are deliberately not logged: they carry routing
            // metadata, not trust, and arbitrary observed addresses are ignored.
            SwarmEvent::Behaviour(Event::Identify(event)) => {
                drop(event);
            }
            SwarmEvent::ListenerError { error, .. } => {
                last_error = Some(error.to_string());
            }
            SwarmEvent::OutgoingConnectionError { error, .. } => {
                last_error = Some(error.to_string());
            }
            SwarmEvent::ListenerClosed {
                reason: Err(error), ..
            } => {
                last_error = Some(error.to_string());
            }
            _ => {}
        }
        let mut value = status.borrow().clone();
        value["listening"] = json!(listening);
        value["reservations"] = json!(reservations.len());
        value["circuits"] = json!(circuits.values().sum::<u32>());
        value["circuits_opened"] = json!(circuits_opened);
        value["registrations"] = json!(registrations.len());
        value["last_error"] = json!(last_error);
        value["autonat"] = json!({"successful":autonat_successful,"failed":autonat_failed,"rejected":swarm.behaviour().autonat.rejected});
        value["denied_reservations"] = json!(denied_reservations);
        value["denied_circuits"] = json!(denied_circuits);
        value["rejected_registrations"] = json!(rejected_registrations);
        if *status.borrow() != value {
            status.send_replace(value);
        }
    }
}

fn private_lock(state_dir: &Path, name: &str) -> Result<std::fs::File> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(state_dir.join(name))?;
    let meta = lock.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.nlink() == 1
            && meta.mode() & 0o7777 == 0o600,
        "Relay state lock must be a private regular file"
    );
    lock.try_lock_exclusive()
        .context("Another bridge or relay owns this state directory")?;
    Ok(lock)
}

/// Runs the same executable as a public node using a separate private state dir.
pub async fn serve(
    state_dir: &Path,
    listen: &str,
    advertise: Option<&str>,
    limits: Limits,
) -> Result<()> {
    serve_with_listeners(
        state_dir,
        vec![(listen.to_owned(), advertise.map(str::to_owned))],
        limits,
    )
    .await
}

pub async fn serve_with_listeners(
    state_dir: &Path,
    listeners: Vec<(String, Option<String>)>,
    limits: Limits,
) -> Result<()> {
    crate::broker::private_dir(state_dir)?;
    // Share the broker's exclusion lock while running, without opening its DB.
    // A stopped broker's state must also never become a public relay identity.
    let _service_lock = private_lock(state_dir, "service.lock")?;
    match std::fs::symlink_metadata(state_dir.join("messages.sqlite3")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("Could not inspect relay state directory"),
        Ok(_) => anyhow::bail!(
            "Use a separate relay state directory; this directory contains broker state"
        ),
    }
    let _relay_lock = private_lock(state_dir, "relay.lock")?;
    let identity = Identity::load_or_create(state_dir)?;
    let listeners = listeners
        .into_iter()
        .map(|(listen, advertise)| {
            Ok((
                listen.parse()?,
                advertise.map(|address| address.parse()).transpose()?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut node = start_with_listeners(identity.keypair(), listeners, limits)?;
    let mut previous = node.status.borrow().clone();
    println!("{}", serde_json::to_string(&previous)?);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tick.tick().await;
    loop {
        tokio::select! {
            result=tokio::signal::ctrl_c()=>{result?;break;}
            _=tick.tick()=>{
                let current=node.status.borrow_and_update().clone();
                if current != previous {
                    // Coalesced public counters only; never one log line per request.
                    println!("{}",serde_json::to_string(&current)?);
                    previous=current;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn limits_and_rendezvous_ingress_are_bounded() {
        Limits::default().validate().unwrap();
        let invalid = Limits {
            max_circuits: 0,
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
        let config = rendezvous::server::Config::default();
        let mut rate = BoundedRendezvous::new(config, 2);
        let a = PeerId::random();
        let b = PeerId::random();
        let c = PeerId::random();
        for _ in 0..32 {
            assert!(rate.allow(a));
        }
        assert!(!rate.allow(a));
        assert!(rate.allow(b));
        assert!(!rate.allow(c));
        assert_eq!(rate.per_peer.len(), 2);
    }
}
