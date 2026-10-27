use agent_bridge::network::relay_node::{self, Limits};
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, SwarmBuilder, identify, noise, relay, rendezvous,
    swarm::{NetworkBehaviour, SwarmEvent},
    yamux,
};
use serde_json::{Value, json};
use std::{convert::Infallible, time::Duration};
use tokio::sync::{mpsc, watch};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "ClientEvent")]
struct ClientBehaviour {
    relay: relay::client::Behaviour,
    rendezvous: rendezvous::client::Behaviour,
    identify: identify::Behaviour,
}
#[derive(Debug)]
enum ClientEvent {
    Relay(relay::client::Event),
    Rendezvous(rendezvous::client::Event),
    Identify(Box<identify::Event>),
}
impl From<relay::client::Event> for ClientEvent {
    fn from(event: relay::client::Event) -> Self {
        Self::Relay(event)
    }
}
impl From<rendezvous::client::Event> for ClientEvent {
    fn from(event: rendezvous::client::Event) -> Self {
        Self::Rendezvous(event)
    }
}
impl From<identify::Event> for ClientEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(Box::new(event))
    }
}
impl From<Infallible> for ClientEvent {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

enum Command {
    Register(u64),
    Discover,
}
struct Client {
    peer: PeerId,
    commands: mpsc::Sender<Command>,
    status: watch::Receiver<Value>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Client {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Client {
    fn start(node: PeerId, address: Multiaddr, reserve: bool) -> Self {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let peer = key.public().to_peer_id();
        let mut swarm = SwarmBuilder::with_existing_identity(key.clone())
            .with_tokio()
            .with_quic()
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .unwrap()
            .with_behaviour(|key, relay| ClientBehaviour {
                relay,
                rendezvous: rendezvous::client::Behaviour::new(key.clone()),
                identify: identify::Behaviour::new(identify::Config::new(
                    "/test/relay-node/1".into(),
                    key.public(),
                )),
            })
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
            .build();
        swarm
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        let mut relay_address = address.clone();
        relay_address.push(libp2p::multiaddr::Protocol::P2p(node));
        if reserve {
            relay_address.push(libp2p::multiaddr::Protocol::P2pCircuit);
            swarm.listen_on(relay_address).unwrap();
        } else {
            swarm.dial(relay_address).unwrap();
        }
        let (commands, mut receiver) = mpsc::channel(8);
        let (sender, status) = watch::channel(json!({}));
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    command=receiver.recv()=>match command {
                        Some(Command::Register(ttl))=>{let result=swarm.behaviour_mut().rendezvous.register(rendezvous::Namespace::from_static(relay_node::NAMESPACE),node,Some(ttl));if let Err(error)=result {sender.send_modify(|s|s["error"]=json!(error.to_string()));}},
                        Some(Command::Discover)=>swarm.behaviour_mut().rendezvous.discover(Some(rendezvous::Namespace::from_static(relay_node::NAMESPACE)),None,Some(16),node),
                        None=>break,
                    },
                    event=swarm.select_next_some()=>match event {
                        SwarmEvent::NewListenAddr {address,..}=>{swarm.add_external_address(address);sender.send_modify(|s|s["listening"]=json!(true));}
                        SwarmEvent::ConnectionEstablished {peer_id,..} if peer_id==node=>{sender.send_modify(|s|s["connected"]=json!(true));}
                        SwarmEvent::Behaviour(ClientEvent::Relay(relay::client::Event::ReservationReqAccepted {..}))=>{sender.send_modify(|s|s["reserved"]=json!(true));}
                        SwarmEvent::ListenerError {error,..}=>{sender.send_modify(|s|s["reservation_error"]=json!(error.to_string()));}
                    SwarmEvent::ListenerClosed {reason:Err(error),..}=>{sender.send_modify(|s|s["reservation_error"]=json!(error.to_string()));}
                        SwarmEvent::Behaviour(ClientEvent::Rendezvous(rendezvous::client::Event::Registered {ttl,..}))=>{sender.send_modify(|s|{s["registered"]=json!(true);s["ttl"]=json!(ttl);});}
                        SwarmEvent::Behaviour(ClientEvent::Rendezvous(rendezvous::client::Event::RegisterFailed {error,..}))=>{sender.send_modify(|s|s["registration_error"]=json!(format!("{error:?}")));}
                        SwarmEvent::Behaviour(ClientEvent::Rendezvous(rendezvous::client::Event::Discovered {registrations,..}))=>{sender.send_modify(|s|s["discovered"]=json!(registrations.iter().map(|r|r.record.peer_id().to_string()).collect::<Vec<_>>()));}
                        SwarmEvent::Behaviour(ClientEvent::Identify(event))=>{drop(event);}
                        _=>{}
                    }
                }
            }
        });
        Self {
            peer,
            commands,
            status,
            task,
        }
    }
}
async fn wait(status: &watch::Receiver<Value>, predicate: impl Fn(&Value) -> bool) -> Value {
    let mut status = status.clone();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let value = status.borrow_and_update().clone();
            if predicate(&value) {
                return value;
            }
            status.changed().await.unwrap();
        }
    })
    .await
    .unwrap_or_else(|_| panic!("status timeout: {}", *status.borrow()))
}
async fn node(limits: Limits) -> (relay_node::RunningNode, Multiaddr) {
    let node = relay_node::start(
        libp2p::identity::Keypair::generate_ed25519(),
        "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        None,
        limits,
    )
    .unwrap();
    let status = wait(&node.status, |s| {
        s["listening"].as_array().is_some_and(|a| !a.is_empty())
    })
    .await;
    let address = status["listening"][0].as_str().unwrap().parse().unwrap();
    (node, address)
}

#[tokio::test]
async fn public_node_enforces_reservation_cap_and_closes_on_drop() {
    let limits = Limits {
        max_reservations: 1,
        ..Default::default()
    };
    let (node, address) = node(limits).await;
    let first = Client::start(node.peer_id, address.clone(), true);
    wait(&first.status, |s| s["reserved"] == true).await;
    wait(&node.status, |s| s["reservations"] == 1).await;
    let second = Client::start(node.peer_id, address.clone(), true);
    wait(&node.status, |s| s["denied_reservations"] == 1).await;
    assert_ne!(second.status.borrow()["reserved"], true);
    assert_eq!(node.status.borrow()["reservations"], 1);
    let status = node.status.clone();
    drop(node);
    let mut status = status.clone();
    tokio::time::timeout(Duration::from_secs(2), async {
        while status.changed().await.is_ok() {}
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rendezvous_register_discover_renew_and_global_quota_are_bounded() {
    let limits = Limits {
        max_registrations: 1,
        ..Default::default()
    };
    let (node, address) = node(limits).await;
    let first = Client::start(node.peer_id, address.clone(), false);
    let second = Client::start(node.peer_id, address, false);
    wait(&first.status, |s| {
        s["connected"] == true && s["listening"] == true
    })
    .await;
    wait(&second.status, |s| {
        s["connected"] == true && s["listening"] == true
    })
    .await;
    first.commands.send(Command::Register(120)).await.unwrap();
    wait(&first.status, |s| s["registered"] == true).await;
    wait(&node.status, |s| s["registrations"] == 1).await;
    first.commands.send(Command::Register(120)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!first.status.borrow()["registration_error"].is_string());
    assert_eq!(node.status.borrow()["registrations"], 1);
    second.commands.send(Command::Register(120)).await.unwrap();
    wait(&second.status, |s| s["registration_error"].is_string()).await;
    second.commands.send(Command::Discover).await.unwrap();
    let discovered = wait(&second.status, |s| s["discovered"].is_array()).await;
    assert_eq!(discovered["discovered"], json!([first.peer.to_string()]));
    assert_eq!(node.status.borrow()["registrations"], 1);
}

#[test]
fn node_rejects_unbounded_limits_and_invalid_public_advertisements() {
    let key = libp2p::identity::Keypair::generate_ed25519();
    let listen = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
    let limits = Limits {
        max_connections: u32::MAX,
        ..Default::default()
    };
    assert!(relay_node::start(key.clone(), listen, None, limits).is_err());
    assert!(
        relay_node::start(
            key.clone(),
            "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
            Some("/ip4/0.0.0.0/udp/4001/quic-v1".parse().unwrap()),
            Limits::default()
        )
        .is_err()
    );
    assert!(
        relay_node::start(
            key,
            "/ip4/0.0.0.0/udp/4001/quic-v1".parse().unwrap(),
            None,
            Limits::default()
        )
        .is_err()
    );
    let relay = PeerId::random();
    let endpoint = PeerId::random();
    let circuit = format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{relay}/p2p-circuit/p2p/{endpoint}");
    assert!(
        relay_node::start(
            libp2p::identity::Keypair::generate_ed25519(),
            "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
            Some(circuit.parse().unwrap()),
            Limits::default()
        )
        .is_err()
    );
}

#[tokio::test]
async fn public_node_refuses_broker_state_and_occupied_service_identity() {
    use fs2::FileExt;
    use std::os::unix::fs::OpenOptionsExt;
    let root = tempfile::tempdir().unwrap();
    let broker_state = root.path().join("broker");
    agent_bridge::broker::private_dir(&broker_state).unwrap();
    std::fs::write(broker_state.join("messages.sqlite3"), b"existing broker").unwrap();
    assert!(
        relay_node::serve(
            &broker_state,
            "/ip4/127.0.0.1/udp/0/quic-v1",
            None,
            Limits::default()
        )
        .await
        .is_err()
    );
    assert!(!broker_state.join("identity.key").exists());
    let state = root.path().join("occupied");
    agent_bridge::broker::private_dir(&state).unwrap();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(state.join("service.lock"))
        .unwrap();
    lock.lock_exclusive().unwrap();
    assert!(
        relay_node::serve(
            &state,
            "/ip4/127.0.0.1/udp/0/quic-v1",
            None,
            Limits::default()
        )
        .await
        .is_err()
    );
    assert!(!state.join("identity.key").exists());
}

async fn endpoint_pair(
    limits: Limits,
) -> (
    relay_node::RunningNode,
    agent_bridge::network::transport::Transport,
    agent_bridge::network::transport::Transport,
    Multiaddr,
    PeerId,
) {
    use agent_bridge::network::transport::Transport;
    let (node, address) = node(limits).await;
    let relay = address.with(libp2p::multiaddr::Protocol::P2p(node.peer_id));
    let akey = libp2p::identity::Keypair::generate_ed25519();
    let bkey = libp2p::identity::Keypair::generate_ed25519();
    let bid = bkey.public().to_peer_id();
    let a = Transport::start_relayed(
        akey,
        "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        vec![],
        false,
        "quota-a",
        vec![relay.clone()],
    )
    .unwrap();
    let b = Transport::start_relayed(
        bkey,
        "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        vec![],
        false,
        "quota-b",
        vec![relay.clone()],
    )
    .unwrap();
    // Test actual relay quotas without a trusted-peer direct upgrade bypassing
    // the circuit. Pairing admission carries bounded plaintext test frames only.
    a.handle.set_pairing_enabled(true).await.unwrap();
    b.handle.set_pairing_enabled(true).await.unwrap();
    for endpoint in [&a, &b] {
        wait(&endpoint.status, |s| s["relays"][0]["state"] == "reserved").await;
    }
    let route = relay
        .with(libp2p::multiaddr::Protocol::P2pCircuit)
        .with(libp2p::multiaddr::Protocol::P2p(bid));
    (node, a, b, route, bid)
}

#[tokio::test]
async fn relayed_ciphertext_is_cut_off_at_the_operator_byte_budget() {
    let (_node, a, mut b, route, bid) = endpoint_pair(Limits {
        max_circuit_bytes: 1024,
        ..Default::default()
    })
    .await;
    let result = a
        .handle
        .pairing_request(bid, vec![route], json!({"payload":"x".repeat(2048)}))
        .await;
    assert!(result.is_err());
    // Without the byte cap, this valid-sized application frame would reach B even
    // though no worker responds to it. Verify it never reached the plaintext queue.
    assert!(b.incoming_pairing.try_recv().is_err());
}

#[tokio::test]
async fn established_relay_circuit_expires_at_the_operator_duration_limit() {
    let (node, a, mut b, route, bid) = endpoint_pair(Limits {
        max_circuit_seconds: 2,
        ..Default::default()
    })
    .await;
    let handle = a.handle.clone();
    let request = tokio::spawn(async move {
        handle
            .pairing_request(bid, vec![route], json!({"op":"quota_test"}))
            .await
    });
    let incoming = tokio::time::timeout(Duration::from_secs(5), b.incoming_pairing.recv())
        .await
        .unwrap()
        .unwrap();
    incoming.response.send(json!({"ok":true})).unwrap();
    assert!(request.await.unwrap().is_ok());
    wait(&node.status, |s| {
        s["circuits"].as_u64().unwrap_or_default() > 0
    })
    .await;
    // Endpoint idle timeout is 30s; a 2s close is the relay's circuit quota.
    wait(&node.status, |s| s["circuits"] == 0).await;
}
