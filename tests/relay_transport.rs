use agent_bridge::network::{
    relay_node::{self, Limits},
    transport::Transport,
    wire::{Operation, WireRequest, WireResponse},
};
use libp2p::{Multiaddr, PeerId, identity::Keypair, multiaddr::Protocol};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::time::timeout;

async fn wait(mut inspect: impl FnMut() -> Option<Value>) -> Value {
    timeout(Duration::from_secs(20), async {
        loop {
            if let Some(value) = inspect() {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .expect("relay condition timed out")
}
async fn node() -> (relay_node::RunningNode, Multiaddr) {
    node_with_limits(Limits::default()).await
}
async fn node_with_limits(limits: Limits) -> (relay_node::RunningNode, Multiaddr) {
    let node = relay_node::start(
        Keypair::generate_ed25519(),
        "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        None,
        limits,
    )
    .unwrap();
    let address = wait(|| {
        node.status.borrow()["listening"]
            .as_array()?
            .first()
            .cloned()
    })
    .await;
    let address: Multiaddr = address.as_str().unwrap().parse().unwrap();
    let address = if matches!(address.iter().last(), Some(Protocol::P2p(_))) {
        address
    } else {
        address.with(Protocol::P2p(node.peer_id))
    };
    (node, address)
}
fn client(key: Keypair, allowed: Vec<PeerId>, relay: Multiaddr) -> Transport {
    Transport::start_relayed(
        key,
        "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        allowed,
        false,
        "relay-test",
        vec![relay],
    )
    .unwrap()
}
async fn reserved(transport: &Transport) {
    wait(|| {
        let status = transport.status.borrow();
        status["relays"]
            .as_array()?
            .iter()
            .find(|entry| entry["state"] == "reserved" && entry["registered"] == true)
            .cloned()
    })
    .await;
}
async fn discovered(transport: &Transport, peer: PeerId) -> Multiaddr {
    let value = wait(|| {
        transport.status.borrow()["rendezvous"]
            .as_array()?
            .iter()
            .find(|entry| entry["peer_id"] == peer.to_string())
            .cloned()
    })
    .await;
    value["addresses"][0].as_str().unwrap().parse().unwrap()
}

#[tokio::test]
async fn relay_discovery_and_end_to_end_requests_use_only_circuit_routes() {
    let (node, relay) = node().await;
    let ka = Keypair::generate_ed25519();
    let kb = Keypair::generate_ed25519();
    let a_id = ka.public().to_peer_id();
    let b_id = kb.public().to_peer_id();
    let a = client(ka, vec![b_id], relay.clone());
    let mut b = client(kb, vec![a_id], relay.clone());
    reserved(&a).await;
    reserved(&b).await;
    let route = discovered(&a, b_id).await;
    assert!(
        route
            .iter()
            .any(|part| matches!(part, Protocol::P2pCircuit))
    );
    assert_eq!(route.iter().last(), Some(Protocol::P2p(b_id)));
    assert_eq!(a.status.borrow()["connected"], json!([]));
    let handle = a.handle.clone();
    let task = tokio::spawn(async move {
        handle
            .request(b_id, route, WireRequest::new(Operation::Directory))
            .await
    });
    let incoming = timeout(Duration::from_secs(10), b.incoming.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(incoming.peer, a_id);
    incoming
        .response
        .send(WireResponse::Directory { agents: vec![] })
        .unwrap();
    assert!(matches!(
        task.await.unwrap().unwrap(),
        WireResponse::Directory { .. }
    ));
    assert_eq!(a.status.borrow()["connected"], json!([b_id.to_string()]));
    wait(|| {
        (node.status.borrow()["circuits_opened"]
            .as_u64()
            .unwrap_or_default()
            > 0)
        .then_some(Value::Null)
    })
    .await;
}

#[tokio::test]
async fn relay_infrastructure_and_discovery_do_not_grant_application_trust() {
    let (_node, relay) = node().await;
    let ka = Keypair::generate_ed25519();
    let kb = Keypair::generate_ed25519();
    let a_id = ka.public().to_peer_id();
    let b_id = kb.public().to_peer_id();
    let a = client(ka, vec![], relay.clone());
    let mut b = client(kb, vec![], relay);
    reserved(&a).await;
    reserved(&b).await;
    let route = discovered(&a, b_id).await;
    assert!(
        a.handle
            .request(b_id, route.clone(), WireRequest::new(Operation::Directory))
            .await
            .is_err()
    );
    a.handle.set_pairing_enabled(true).await.unwrap();
    b.handle.set_pairing_enabled(true).await.unwrap();
    let handle = a.handle.clone();
    let p = tokio::spawn(async move {
        handle
            .pairing_request(b_id, vec![route], json!({"op":"probe"}))
            .await
    });
    let incoming = timeout(Duration::from_secs(10), b.incoming_pairing.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(incoming.peer, a_id);
    incoming.response.send(json!({"ok":true})).unwrap();
    assert_eq!(p.await.unwrap().unwrap(), json!({"ok":true}));
    assert!(b.incoming.try_recv().is_err());
    assert_eq!(b.status.borrow()["connected"], json!([]));
}

#[tokio::test]
async fn failed_operator_does_not_prevent_reserving_an_independent_operator() {
    // The lowest valid operator TTL must remain compatible with all clients.
    let (node, good) = node_with_limits(Limits {
        registration_seconds: 30,
        ..Limits::default()
    })
    .await;
    let mut wrong = good.clone();
    wrong.pop();
    wrong.push(Protocol::P2p(
        Keypair::generate_ed25519().public().to_peer_id(),
    ));
    let client = Transport::start_relayed(
        Keypair::generate_ed25519(),
        "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        vec![],
        false,
        "multi-relay",
        vec![wrong, good],
    )
    .unwrap();
    wait(|| {
        let status = client.status.borrow();
        let nodes = status["relays"].as_array()?;
        (nodes.iter().any(|entry| {
            entry["peer_id"] == node.peer_id.to_string()
                && entry["state"] == "reserved"
                && entry["registered"] == true
        }) && nodes
            .iter()
            .any(|entry| entry["peer_id"] != node.peer_id.to_string() && entry["state"] == "error"))
        .then_some(status.clone())
    })
    .await;
    assert_eq!(client.status.borrow()["connected"], json!([]));
}
