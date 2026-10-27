use agent_bridge::network::{
    relay_node::{self, Limits},
    transport::Transport,
    wire::{Operation, WireRequest, WireResponse},
};
use libp2p::{Multiaddr, identity::Keypair, multiaddr::Protocol};
use serde_json::Value;
use std::time::Duration;
use tokio::time::timeout;

async fn wait(mut check: impl FnMut() -> Option<Value>) -> Value {
    timeout(Duration::from_secs(20), async {
        loop {
            if let Some(value) = check() {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .expect("internet transport condition timed out")
}
async fn node() -> (relay_node::RunningNode, Multiaddr) {
    let node = relay_node::start(
        Keypair::generate_ed25519(),
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        None,
        Limits::default(),
    )
    .unwrap();
    let value = wait(|| {
        node.status.borrow()["listening"]
            .as_array()?
            .first()
            .cloned()
    })
    .await;
    let mut address: Multiaddr = value.as_str().unwrap().parse().unwrap();
    if !matches!(address.iter().last(), Some(Protocol::P2p(_))) {
        address.push(Protocol::P2p(node.peer_id));
    }
    (node, address)
}
fn client(key: Keypair, trusted: Vec<libp2p::PeerId>, routes: Vec<Multiaddr>) -> Transport {
    Transport::start_relayed(
        key,
        "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        trusted,
        false,
        "internet-test",
        routes,
    )
    .unwrap()
}
async fn reserved(transport: &Transport) -> Value {
    wait(|| {
        transport.status.borrow()["relays"]
            .as_array()?
            .iter()
            .find(|entry| entry["state"] == "reserved" && entry["registered"] == true)
            .cloned()
    })
    .await
}
#[tokio::test]
async fn tcp_dns_relay_preserves_end_to_end_authentication() {
    let (_node, address) = node().await;
    let port = address
        .iter()
        .find_map(|p| {
            if let Protocol::Tcp(port) = p {
                Some(port)
            } else {
                None
            }
        })
        .unwrap();
    let id = address
        .iter()
        .find_map(|p| {
            if let Protocol::P2p(id) = p {
                Some(id)
            } else {
                None
            }
        })
        .unwrap();
    let dns: Multiaddr = format!("/dns4/localhost/tcp/{port}/p2p/{id}")
        .parse()
        .unwrap();
    let ka = Keypair::generate_ed25519();
    let kb = Keypair::generate_ed25519();
    let a_id = ka.public().to_peer_id();
    let b_id = kb.public().to_peer_id();
    let a = client(ka, vec![b_id], vec![dns.clone()]);
    let mut b = client(kb, vec![a_id], vec![dns]);
    assert_eq!(reserved(&a).await["transport"], "tcp");
    reserved(&b).await;
    let entry = wait(|| {
        a.status.borrow()["rendezvous"]
            .as_array()?
            .iter()
            .find(|e| e["peer_id"] == b_id.to_string())
            .cloned()
    })
    .await;
    let route: Multiaddr = entry["addresses"][0].as_str().unwrap().parse().unwrap();
    assert!(route.to_string().starts_with("/dns4/localhost/tcp/"));
    let revoked_route = route.clone();
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
    a.handle.set_allowed(vec![]).await.unwrap();
    assert!(
        a.handle
            .request(b_id, revoked_route, WireRequest::new(Operation::Directory))
            .await
            .is_err()
    );
}
#[tokio::test]
async fn same_operator_falls_back_from_blocked_udp_to_tcp() {
    let (node, tcp) = node().await;
    let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let quic: Multiaddr = format!(
        "/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{}",
        blackhole.local_addr().unwrap().port(),
        node.peer_id
    )
    .parse()
    .unwrap();
    let transport = client(Keypair::generate_ed25519(), vec![], vec![tcp, quic]);
    let live = reserved(&transport).await;
    assert_eq!(live["transport"], "tcp");
    assert_eq!(
        transport.status.borrow()["connected"],
        serde_json::json!([])
    );
}
#[tokio::test]
async fn explicit_contact_lookup_returns_authenticated_key_without_trust() {
    let key = Keypair::generate_ed25519();
    let expected = key.public().to_peer_id();
    let remote = Transport::start(key, "/ip4/127.0.0.1/tcp/0".parse().unwrap(), vec![]).unwrap();
    remote.handle.set_pairing_enabled(true).await.unwrap();
    let address = wait(|| {
        remote.status.borrow()["listening"]
            .as_array()?
            .first()
            .cloned()
    })
    .await;
    let local = client(Keypair::generate_ed25519(), vec![], vec![]);
    assert_eq!(
        local
            .handle
            .resolve_contact(address.as_str().unwrap().parse().unwrap())
            .await
            .unwrap(),
        expected
    );
    assert_eq!(local.status.borrow()["connected"], serde_json::json!([]));
    let pinned: Multiaddr = format!("{}/p2p/{expected}", address.as_str().unwrap())
        .parse()
        .unwrap();
    assert!(local.handle.resolve_contact(pinned).await.is_err());
}

#[tokio::test]
async fn wrong_operator_pin_cannot_reserve_and_contact_lookups_are_rate_bounded() {
    let (_node, address) = node().await;
    let mut wrong = address.clone();
    wrong.pop();
    wrong.push(Protocol::P2p(libp2p::PeerId::random()));
    let transport = client(Keypair::generate_ed25519(), vec![], vec![wrong]);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !transport.status.borrow()["relays"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["state"] == "reserved")
    );
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let address: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();
    for _ in 0..8 {
        assert!(
            transport
                .handle
                .resolve_contact(address.clone())
                .await
                .is_err()
        );
    }
    let error = transport.handle.resolve_contact(address).await.unwrap_err();
    assert!(error.to_string().contains("capacity"));
}
