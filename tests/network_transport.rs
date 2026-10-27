use agent_bridge::network::{
    transport::Transport,
    wire::{Operation, WireRequest, WireResponse},
};
use libp2p::{Multiaddr, PeerId, identity::Keypair};
use std::time::Duration;

fn listen() -> Multiaddr {
    "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()
}

async fn address(peer: &mut Transport) -> Multiaddr {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(address) = peer.status.borrow()["listening"]
                .as_array()
                .and_then(|items| items.first())
                .and_then(|address| address.as_str())
            {
                return address.parse().unwrap();
            }
            peer.status.changed().await.unwrap();
        }
    })
    .await
    .expect("transport did not listen")
}

#[tokio::test]
async fn authenticated_request_and_revocation_use_production_transport() {
    let alice_key = Keypair::generate_ed25519();
    let bob_key = Keypair::generate_ed25519();
    let alice_id = alice_key.public().to_peer_id();
    let bob_id = bob_key.public().to_peer_id();
    let alice = Transport::start(alice_key, listen(), vec![bob_id]).unwrap();
    let mut bob = Transport::start(bob_key, listen(), vec![alice_id]).unwrap();
    let bob_address = address(&mut bob).await;
    let handle = alice.handle.clone();
    let outbound_address = bob_address.clone();
    let request = tokio::spawn(async move {
        handle
            .request(
                bob_id,
                outbound_address,
                WireRequest::new(Operation::Directory),
            )
            .await
    });
    let inbound = tokio::time::timeout(Duration::from_secs(5), bob.incoming.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inbound.peer, alice_id);
    assert!(matches!(inbound.request.operation, Operation::Directory));
    inbound
        .response
        .send(WireResponse::Directory { agents: Vec::new() })
        .unwrap();
    assert!(
        matches!(request.await.unwrap().unwrap(), WireResponse::Directory { agents } if agents.is_empty())
    );
    bob.handle.set_allowed(Vec::new()).await.unwrap();
    assert!(
        alice
            .handle
            .request(
                bob_id,
                bob_address.clone(),
                WireRequest::new(Operation::Directory)
            )
            .await
            .is_err()
    );
    assert!(bob.incoming.try_recv().is_err());
    alice.handle.set_allowed(Vec::new()).await.unwrap();
    assert!(
        alice
            .handle
            .request(bob_id, bob_address, WireRequest::new(Operation::Directory))
            .await
            .is_err()
    );
    assert!(
        alice.status.borrow()["connected"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn unpaired_origin_cannot_reach_application_requests() {
    let alice_key = Keypair::generate_ed25519();
    let bob_key = Keypair::generate_ed25519();
    let bob_id = bob_key.public().to_peer_id();
    let alice = Transport::start(alice_key, listen(), vec![bob_id]).unwrap();
    let mut bob = Transport::start(bob_key, listen(), Vec::new()).unwrap();
    let bob_address = address(&mut bob).await;
    assert!(
        alice
            .handle
            .request(bob_id, bob_address, WireRequest::new(Operation::Directory))
            .await
            .is_err()
    );
    assert!(bob.incoming.try_recv().is_err());
}

#[tokio::test]
async fn connection_address_cannot_override_pinned_peer_identity() {
    let alice_key = Keypair::generate_ed25519();
    let bob_key = Keypair::generate_ed25519();
    let alice_id = alice_key.public().to_peer_id();
    let wrong_id = PeerId::random();
    let alice = Transport::start(alice_key, listen(), vec![wrong_id]).unwrap();
    let mut bob = Transport::start(bob_key, listen(), vec![alice_id]).unwrap();
    let bob_address = address(&mut bob).await;
    assert!(
        alice
            .handle
            .request(
                wrong_id,
                bob_address,
                WireRequest::new(Operation::Directory)
            )
            .await
            .is_err()
    );
    assert!(bob.incoming.try_recv().is_err());
}
