use agent_bridge::network::{
    relay_node::{self, Limits},
    transport::Transport,
    wire::{Operation, WireRequest, WireResponse},
};
use libp2p::{Multiaddr, PeerId, identity::Keypair};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::time::timeout;
async fn wait(
    transport: &Transport,
    label: &str,
    mut f: impl FnMut(&Value) -> Option<Value>,
) -> Value {
    timeout(Duration::from_secs(25), async {
        loop {
            if let Some(v) = f(&transport.status.borrow()) {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{label}: {}", *transport.status.borrow()))
}
async fn node() -> (relay_node::RunningNode, Multiaddr) {
    let node = relay_node::start(
        Keypair::generate_ed25519(),
        "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        None,
        Limits::default(),
    )
    .unwrap();
    let addr = timeout(Duration::from_secs(5), async {
        loop {
            if let Some(a) = node.status.borrow()["listening"]
                .as_array()
                .and_then(|a| a.first())
                .cloned()
            {
                break a;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let address = format!("{}/p2p/{}", addr.as_str().unwrap(), node.peer_id)
        .parse()
        .unwrap();
    (node, address)
}
fn client(key: Keypair, allowed: Vec<PeerId>, relay: Multiaddr) -> Transport {
    Transport::start_relayed(
        key,
        "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        allowed,
        false,
        "nat-test",
        vec![relay],
    )
    .unwrap()
}
async fn route(a: &Transport, peer: PeerId) -> Multiaddr {
    let row = wait(a, "rendezvous", |s| {
        s["rendezvous"]
            .as_array()?
            .iter()
            .find(|r| r["peer_id"] == peer.to_string())
            .cloned()
    })
    .await;
    row["addresses"][0].as_str().unwrap().parse().unwrap()
}
async fn exchange(a: &Transport, b: &mut Transport, bid: PeerId, address: Multiaddr) {
    for _ in 0..4 {
        let h = a.handle.clone();
        let address = address.clone();
        let mut task = tokio::spawn(async move {
            h.request(bid, address, WireRequest::new(Operation::Directory))
                .await
        });
        let delivered = timeout(Duration::from_secs(12), async {
            loop {
                tokio::select! {
                    result=&mut task=>return result.unwrap().is_ok(),
                    incoming=b.incoming.recv()=>{
                        let incoming=incoming.unwrap();
                        let _=incoming.response.send(WireResponse::Directory{agents:vec![]});
                    }
                }
            }
        })
        .await
        .unwrap();
        if delivered {
            return;
        }
    }
    panic!("exchange did not recover after upgrade");
}

#[tokio::test]
async fn trusted_circuit_upgrades_to_authenticated_direct_quic_and_keeps_relay_reservation() {
    let (node, relay) = node().await;
    let ka = Keypair::generate_ed25519();
    let kb = Keypair::generate_ed25519();
    let aid = ka.public().to_peer_id();
    let bid = kb.public().to_peer_id();
    let a = client(ka, vec![bid], relay.clone());
    let mut b = client(kb, vec![aid], relay);
    let address = route(&a, bid).await;
    route(&b, aid).await;
    wait(&a, "observer", |s| {
        (!s["nat"]["observed_addresses"].as_array()?.is_empty()).then_some(Value::Null)
    })
    .await;
    wait(&b, "observer", |s| {
        (!s["nat"]["observed_addresses"].as_array()?.is_empty()).then_some(Value::Null)
    })
    .await;
    exchange(&a, &mut b, bid, address.clone()).await;
    wait(&a, "direct upgrade", |s| {
        s["paths"]
            .as_array()?
            .iter()
            .find(|p| {
                p["peer_id"] == bid.to_string()
                    && p["path"] == "direct"
                    && p["relayed_connections"] == 0
            })
            .cloned()
    })
    .await;
    wait(&b, "direct upgrade", |s| {
        s["paths"]
            .as_array()?
            .iter()
            .find(|p| p["peer_id"] == aid.to_string() && p["path"] == "direct")
            .cloned()
    })
    .await;
    exchange(&a, &mut b, bid, address).await;
    assert!(node.status.borrow()["circuits_opened"].as_u64().unwrap() > 0);
    assert_eq!(a.status.borrow()["relays"][0]["state"], "reserved");
    a.handle.set_allowed(vec![]).await.unwrap();
    wait(&a, "revoked path removed", |s| {
        s["paths"].as_array()?.is_empty().then_some(Value::Null)
    })
    .await;
    assert!(
        a.handle
            .request(
                bid,
                "/ip4/127.0.0.1/udp/1/quic-v1".parse().unwrap(),
                WireRequest::new(Operation::Directory)
            )
            .await
            .is_err()
    );
}
#[tokio::test]
async fn pairing_only_circuit_never_hole_punches_until_both_peers_become_trusted() {
    let (_node, relay) = node().await;
    let ka = Keypair::generate_ed25519();
    let kb = Keypair::generate_ed25519();
    let aid = ka.public().to_peer_id();
    let bid = kb.public().to_peer_id();
    let a = client(ka, vec![], relay.clone());
    let mut b = client(kb, vec![], relay);
    let address = route(&a, bid).await;
    route(&b, aid).await;
    a.handle.set_pairing_enabled(true).await.unwrap();
    b.handle.set_pairing_enabled(true).await.unwrap();
    let h = a.handle.clone();
    let addr = address.clone();
    let task = tokio::spawn(async move {
        h.pairing_request(bid, vec![addr], json!({"test":"bounded pairing only"}))
            .await
    });
    let incoming = timeout(Duration::from_secs(12), b.incoming_pairing.recv())
        .await
        .unwrap()
        .unwrap();
    incoming.response.send(json!({"ok":true})).unwrap();
    assert_eq!(task.await.unwrap().unwrap()["ok"], true);
    assert!(
        a.status.borrow()["nat"]["hole_punch"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(a.status.borrow()["connected"], json!([]));
    a.handle.set_allowed(vec![bid]).await.unwrap();
    b.handle.set_allowed(vec![aid]).await.unwrap();
    exchange(&a, &mut b, bid, address).await;
    wait(&a, "trusted transition upgrade", |s| {
        s["paths"]
            .as_array()?
            .iter()
            .find(|p| p["peer_id"] == bid.to_string() && p["path"] == "direct")
            .cloned()
    })
    .await;
}
#[tokio::test]
async fn reachability_requires_real_autonat_v2_nonce_callback_from_configured_operator() {
    let (_node, relay) = node().await;
    let a = client(Keypair::generate_ed25519(), vec![], relay);
    wait(&a, "v2 callback", |s| {
        (s["nat"]["reachability"] == "public").then_some(s["nat"].clone())
    })
    .await;
    assert!(
        a.status.borrow()["nat"]["observed_addresses"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["verified"] == true)
    );
    assert_eq!(a.status.borrow()["connected"], json!([]));
}
