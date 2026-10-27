// Copyright 2018 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

mod iface;
mod socket;
mod timer;

use std::{
    collections::{
        VecDeque,
        hash_map::{Entry, HashMap},
    },
    convert::Infallible,
    fmt,
    future::Future,
    io,
    net::IpAddr,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
    time::Instant,
};

use futures::{Stream, StreamExt, channel::mpsc};
use if_watch::IfEvent;
use libp2p_core::{Endpoint, Multiaddr, transport::PortUse};
use libp2p_identity::PeerId;
use libp2p_swarm::{
    ConnectionDenied, ConnectionId, ListenAddresses, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm, behaviour::FromSwarm, dummy,
};
use smallvec::SmallVec;

use self::iface::InterfaceState;
use crate::{
    Config,
    behaviour::{socket::AsyncSocket, timer::Builder},
};

/// An abstraction to allow for compatibility with various async runtimes.
pub trait Provider: 'static {
    /// The Async Socket type.
    type Socket: AsyncSocket;
    /// The Async Timer type.
    type Timer: Builder + Stream;
    /// The IfWatcher type.
    type Watcher: Stream<Item = std::io::Result<IfEvent>> + fmt::Debug + Unpin;

    type TaskHandle: Abort;

    /// Create a new instance of the `IfWatcher` type.
    fn new_watcher() -> Result<Self::Watcher, std::io::Error>;

    #[track_caller]
    fn spawn(task: impl Future<Output = ()> + Send + 'static) -> Self::TaskHandle;
}

#[allow(unreachable_pub)] // Not re-exported.
pub trait Abort {
    fn abort(self);
}

/// The type of a [`Behaviour`] using the `tokio` implementation.
#[cfg(feature = "tokio")]
pub mod tokio {
    use std::future::Future;

    use if_watch::tokio::IfWatcher;
    use tokio::task::JoinHandle;

    use super::Provider;
    use crate::behaviour::{Abort, socket::tokio::TokioUdpSocket, timer::tokio::TokioTimer};

    #[doc(hidden)]
    pub enum Tokio {}

    impl Provider for Tokio {
        type Socket = TokioUdpSocket;
        type Timer = TokioTimer;
        type Watcher = IfWatcher;
        type TaskHandle = JoinHandle<()>;

        fn new_watcher() -> Result<Self::Watcher, std::io::Error> {
            IfWatcher::new()
        }

        fn spawn(task: impl Future<Output = ()> + Send + 'static) -> Self::TaskHandle {
            tokio::spawn(task)
        }
    }

    impl Abort for JoinHandle<()> {
        fn abort(self) {
            JoinHandle::abort(&self)
        }
    }

    pub type Behaviour = super::Behaviour<Tokio>;
}

/// A `NetworkBehaviour` for mDNS. Automatically discovers peers on the local network and adds
/// them to the topology.
#[derive(Debug)]
pub struct Behaviour<P>
where
    P: Provider,
{
    /// InterfaceState config.
    config: Config,

    /// Iface watcher.
    if_watch: P::Watcher,

    /// Handles to tasks running the mDNS queries.
    if_tasks: HashMap<IpAddr, P::TaskHandle>,

    query_response_receiver: mpsc::Receiver<(PeerId, Multiaddr, Instant, Option<String>)>,
    query_response_sender: mpsc::Sender<(PeerId, Multiaddr, Instant, Option<String>)>,

    /// List of nodes that we have discovered, the address, and when their TTL expires.
    ///
    /// Each combination of `PeerId` and `Multiaddr` can only appear once, but the same `PeerId`
    /// can appear multiple times.
    discovered_nodes: SmallVec<[(PeerId, Multiaddr, Instant); 8]>,

    /// Future that fires when the TTL of at least one node in `discovered_nodes` expires.
    ///
    /// `None` if `discovered_nodes` is empty.
    closest_expiration: Option<P::Timer>,

    /// The current set of listen addresses.
    ///
    /// This is shared across all interface tasks using an [`RwLock`].
    /// The [`Behaviour`] updates this upon new [`FromSwarm`]
    /// events where as [`InterfaceState`]s read from it to answer inbound mDNS queries.
    listen_addresses: Arc<RwLock<ListenAddresses>>,

    local_peer_id: PeerId,

    /// Pending behaviour events to be emitted.
    pending_events: VecDeque<ToSwarm<Event, Infallible>>,
}

impl<P> Behaviour<P>
where
    P: Provider,
{
    /// Builds a new `Mdns` behaviour.
    pub fn new(config: Config, local_peer_id: PeerId) -> io::Result<Self> {
        if config
            .machine_name
            .as_deref()
            .is_some_and(|name| !crate::valid_machine_name(name))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid machine name",
            ));
        }
        let (tx, rx) = mpsc::channel(10); // Chosen arbitrarily.

        Ok(Self {
            config,
            if_watch: P::new_watcher()?,
            if_tasks: Default::default(),
            query_response_receiver: rx,
            query_response_sender: tx,
            discovered_nodes: Default::default(),
            closest_expiration: Default::default(),
            listen_addresses: Default::default(),
            local_peer_id,
            pending_events: Default::default(),
        })
    }

    /// Returns true if the given `PeerId` is in the list of nodes discovered through mDNS.
    #[deprecated(note = "Use `discovered_nodes` iterator instead.")]
    pub fn has_node(&self, peer_id: &PeerId) -> bool {
        self.discovered_nodes().any(|p| p == peer_id)
    }

    /// Returns the list of nodes that we have discovered through mDNS and that are not expired.
    pub fn discovered_nodes(&self) -> impl ExactSizeIterator<Item = &PeerId> {
        self.discovered_nodes.iter().map(|(p, _, _)| p)
    }

    /// Expires a node before the ttl.
    #[deprecated(note = "Unused API. Will be removed in the next release.")]
    pub fn expire_node(&mut self, peer_id: &PeerId) {
        let now = Instant::now();
        for (peer, _addr, expires) in &mut self.discovered_nodes {
            if peer == peer_id {
                *expires = now;
            }
        }
        self.closest_expiration = Some(P::Timer::at(now));
    }
}

const MAX_DISCOVERED_ADDRESSES: usize = 1024;
const MAX_BATCH: usize = 32;
const MAX_INTERFACES: usize = 32;

fn record_discovery(
    records: &mut SmallVec<[(PeerId, Multiaddr, Instant); 8]>,
    peer: PeerId,
    address: &Multiaddr,
    expiration: Instant,
) -> bool {
    if let Some((_, _, expires)) = records
        .iter_mut()
        .find(|(p, a, _)| *p == peer && a == address)
    {
        *expires = expiration;
        return true;
    }
    if records.len() >= MAX_DISCOVERED_ADDRESSES {
        return false;
    }
    records.push((peer, address.clone(), expiration));
    true
}

impl<P: Provider> Drop for Behaviour<P> {
    fn drop(&mut self) {
        for (_, task) in self.if_tasks.drain() {
            task.abort();
        }
    }
}

impl<P> NetworkBehaviour for Behaviour<P>
where
    P: Provider,
{
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        _addresses: &[Multiaddr],
        _effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let Some(peer_id) = maybe_peer else {
            return Ok(vec![]);
        };

        Ok(self
            .discovered_nodes
            .iter()
            .filter(|(peer, _, _)| peer == &peer_id)
            .map(|(_, addr, _)| addr.clone())
            .collect())
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        ev: THandlerOutEvent<Self>,
    ) {
        libp2p_core::util::unreachable(ev)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        self.listen_addresses
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .on_swarm_event(&event);
    }

    #[tracing::instrument(level = "trace", name = "NetworkBehaviour::poll", skip(self, cx))]
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        loop {
            // Check for pending events and emit them.
            if let Some(event) = self.pending_events.pop_front() {
                return Poll::Ready(event);
            }

            // Poll ifwatch.
            while let Poll::Ready(Some(event)) = Pin::new(&mut self.if_watch).poll_next(cx) {
                match event {
                    Ok(IfEvent::Up(inet)) => {
                        let addr = inet.addr();
                        if addr.is_loopback() {
                            continue;
                        }
                        if addr.is_ipv4() && self.config.enable_ipv6
                            || addr.is_ipv6() && !self.config.enable_ipv6
                        {
                            continue;
                        }
                        if self.if_tasks.len() >= MAX_INTERFACES {
                            continue;
                        }
                        if let Entry::Vacant(e) = self.if_tasks.entry(addr) {
                            match InterfaceState::<P::Socket, P::Timer>::new(
                                addr,
                                self.config.clone(),
                                self.local_peer_id,
                                self.listen_addresses.clone(),
                                self.query_response_sender.clone(),
                            ) {
                                Ok(iface_state) => {
                                    e.insert(P::spawn(iface_state));
                                }
                                Err(err) => {
                                    tracing::error!("failed to create `InterfaceState`: {}", err)
                                }
                            }
                        }
                    }
                    Ok(IfEvent::Down(inet)) => {
                        if let Some(handle) = self.if_tasks.remove(&inet.addr()) {
                            tracing::info!(instance=%inet.addr(), "dropping instance");

                            handle.abort();
                        }
                    }
                    Err(err) => tracing::error!("if watch returned an error: {}", err),
                }
            }
            // Prune before processing refreshes: a busy peer must not keep
            // expired records occupying the bounded cache forever.
            let now = Instant::now();
            let mut expired = Vec::new();
            self.discovered_nodes.retain(|(peer, addr, expiration)| {
                if *expiration <= now {
                    expired.push((*peer, addr.clone()));
                    return false;
                }
                true
            });
            let mut discovered = Vec::new();
            let mut machine_names = Vec::new();
            for _ in 0..MAX_BATCH {
                let Poll::Ready(Some((peer, addr, expiration, machine_name))) =
                    self.query_response_receiver.poll_next_unpin(cx)
                else {
                    break;
                };
                let expiration = expiration.min(now + self.config.ttl);
                if record_discovery(&mut self.discovered_nodes, peer, &addr, expiration) {
                    // Report refreshes so the application can extend its own TTL.
                    machine_names.push((peer, addr.clone(), machine_name));
                    discovered.push((peer, addr));
                }
            }
            if let Some(closest) = self
                .discovered_nodes
                .iter()
                .map(|(_, _, expires)| *expires)
                .min()
            {
                let mut timer = P::Timer::at(closest);
                let _ = Pin::new(&mut timer).poll_next(cx);
                self.closest_expiration = Some(timer);
            } else {
                self.closest_expiration = None;
            }
            // Expiry must precede a refresh of the same address in this batch.
            if !expired.is_empty() {
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::Expired(expired)));
            }
            if !discovered.is_empty() {
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::Discovered(discovered)));
            }
            if !machine_names.is_empty() {
                self.pending_events
                    .push_back(ToSwarm::GenerateEvent(Event::MachineNames(machine_names)));
            }
            if !self.pending_events.is_empty() {
                continue;
            }

            return Poll::Pending;
        }
    }
}

/// Event that can be produced by the `Mdns` behaviour.
#[derive(Debug, Clone)]
pub enum Event {
    /// Discovered nodes through mDNS.
    Discovered(Vec<(PeerId, Multiaddr)>),

    /// Optional unauthenticated labels associated with the preceding live address announcements.
    MachineNames(Vec<(PeerId, Multiaddr, Option<String>)>),

    /// The given combinations of `PeerId` and `Multiaddr` have expired.
    ///
    /// Each discovered record has a time-to-live. When this TTL expires and the address hasn't
    /// been refreshed, we remove it from the list and emit it as an `Expired` event.
    Expired(Vec<(PeerId, Multiaddr)>),
}

#[cfg(all(test, feature = "tokio"))]
mod hardening_tests {
    use super::{
        Behaviour, Config, Instant, MAX_DISCOVERED_ADDRESSES, PeerId, SmallVec, record_discovery,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[test]
    fn discovery_metadata_has_a_hard_cap_and_refreshes_existing_entries() {
        let mut records = SmallVec::new();
        let peer = PeerId::from_bytes(&[0, 1, 1]).unwrap();
        let now = Instant::now();
        for port in 1..=MAX_DISCOVERED_ADDRESSES {
            let address = format!("/ip4/192.168.1.20/udp/{port}/quic-v1")
                .parse()
                .unwrap();
            assert!(record_discovery(&mut records, peer, &address, now));
        }
        let overflow = "/ip4/192.168.1.20/udp/5000/quic-v1".parse().unwrap();
        assert!(!record_discovery(&mut records, peer, &overflow, now));
        let first = records[0].1.clone();
        let later = now + std::time::Duration::from_secs(1);
        assert!(record_discovery(&mut records, peer, &first, later));
        assert_eq!(records.len(), MAX_DISCOVERED_ADDRESSES);
        assert_eq!(records[0].2, later);
    }

    #[::tokio::test]
    async fn expired_full_cache_is_pruned_while_refreshes_continue() {
        let peer = PeerId::from_bytes(&[0, 1, 1]).unwrap();
        let mut behaviour = Behaviour::<super::tokio::Tokio>::new(Config::default(), peer).unwrap();
        let expired = Instant::now() - std::time::Duration::from_secs(1);
        for port in 1..=MAX_DISCOVERED_ADDRESSES {
            let address = format!("/ip4/192.168.1.20/udp/{port}/quic-v1")
                .parse()
                .unwrap();
            assert!(record_discovery(
                &mut behaviour.discovered_nodes,
                peer,
                &address,
                expired
            ));
        }
        let refresh = behaviour.discovered_nodes[0].1.clone();
        let new_address: super::Multiaddr = "/ip4/192.168.1.20/udp/5000/quic-v1".parse().unwrap();
        let later = Instant::now() + std::time::Duration::from_secs(60);
        behaviour
            .query_response_sender
            .try_send((peer, refresh, later, None))
            .unwrap();
        behaviour
            .query_response_sender
            .try_send((peer, new_address.clone(), later, None))
            .unwrap();
        let mut cx = super::Context::from_waker(futures::task::noop_waker_ref());
        let super::Poll::Ready(super::ToSwarm::GenerateEvent(super::Event::Expired(entries))) =
            super::NetworkBehaviour::poll(&mut behaviour, &mut cx)
        else {
            panic!("expiry must precede refresh")
        };
        assert_eq!(entries.len(), MAX_DISCOVERED_ADDRESSES);
        assert_eq!(behaviour.discovered_nodes.len(), 2);
        assert!(
            behaviour
                .discovered_nodes
                .iter()
                .any(|(_, address, _)| address == &new_address)
        );
        assert!(
            behaviour
                .discovered_nodes
                .iter()
                .all(|(_, _, deadline)| *deadline <= Instant::now() + behaviour.config.ttl)
        );
    }

    #[::tokio::test]
    async fn dropping_behaviour_aborts_interface_tasks() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let flag = dropped.clone();
        let handle = ::tokio::spawn(async move {
            let _guard = Dropped(flag);
            std::future::pending::<()>().await;
        });
        let abort = handle.abort_handle();
        ::tokio::task::yield_now().await;
        let peer = PeerId::from_bytes(&[0, 1, 1]).unwrap();
        let mut behaviour = Behaviour::<super::tokio::Tokio>::new(Config::default(), peer).unwrap();
        behaviour
            .if_tasks
            .insert("192.168.1.20".parse().unwrap(), handle);
        drop(behaviour);
        ::tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !abort.is_finished() {
                ::tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(dropped.load(Ordering::SeqCst));
    }
}
