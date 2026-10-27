//! Pairing transport admission never authorizes the ordinary application protocol.
use agent_bridge::network::{
    transport::Transport,
    wire::{Operation, WireRequest, WireResponse},
};
use libp2p::{Multiaddr, identity::Keypair};
use serde_json::json;
use std::time::Duration;

fn listen() -> Multiaddr {
    "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()
}
async fn address(transport: &mut Transport) -> Multiaddr {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(value) = transport.status.borrow()["listening"]
                .as_array()
                .and_then(|items| items.first())
                .and_then(|value| value.as_str())
            {
                return value.parse().unwrap();
            }
            transport.status.changed().await.unwrap();
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn pairing_window_allows_authenticated_pairing_without_message_access() {
    let a_key = Keypair::generate_ed25519();
    let b_key = Keypair::generate_ed25519();
    let a_id = a_key.public().to_peer_id();
    let b_id = b_key.public().to_peer_id();
    // Sender trusts B solely to exercise denial at the receiving protocol boundary.
    let a = Transport::start(a_key, listen(), vec![b_id]).unwrap();
    let mut b = Transport::start(b_key, listen(), vec![]).unwrap();
    let b_address = address(&mut b).await;
    a.handle.set_pairing_enabled(true).await.unwrap();
    b.handle.set_pairing_enabled(true).await.unwrap();
    let handle = a.handle.clone();
    let target = b_address.clone();
    let sent = tokio::spawn(async move {
        handle
            .pairing_request(b_id, vec![target], json!({"step":"hello"}))
            .await
    });
    let inbound = tokio::time::timeout(Duration::from_secs(5), b.incoming_pairing.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inbound.peer, a_id);
    assert_eq!(inbound.request, json!({"step":"hello"}));
    inbound.response.send(json!({"step":"reply"})).unwrap();
    assert_eq!(sent.await.unwrap().unwrap(), json!({"step":"reply"}));
    assert!(
        b.status.borrow()["connected"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let denied = a
        .handle
        .request(b_id, b_address, WireRequest::new(Operation::Directory))
        .await
        .unwrap();
    assert!(matches!(
        denied,
        WireResponse::Rejected {
            retryable: false,
            ..
        }
    ));
    assert!(b.incoming.try_recv().is_err());
}

#[tokio::test]
async fn pairing_is_closed_by_default_and_closed_remote_cannot_be_reached() {
    let a_key = Keypair::generate_ed25519();
    let b_key = Keypair::generate_ed25519();
    let b_id = b_key.public().to_peer_id();
    let a = Transport::start(a_key, listen(), vec![]).unwrap();
    let mut b = Transport::start(b_key, listen(), vec![]).unwrap();
    let target = address(&mut b).await;
    let error = a
        .handle
        .pairing_request(b_id, vec![target.clone()], json!({"step":"hello"}))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("closed"));
    a.handle.set_pairing_enabled(true).await.unwrap();
    assert!(
        a.handle
            .pairing_request(b_id, vec![target], json!({"step":"hello"}))
            .await
            .is_err()
    );
    assert!(b.incoming_pairing.try_recv().is_err());
    assert!(b.incoming.try_recv().is_err());
}

#[tokio::test]
async fn closing_pairing_cancels_requests_without_interrupting_trusted_messages() {
    let a_key = Keypair::generate_ed25519();
    let b_key = Keypair::generate_ed25519();
    let a_id = a_key.public().to_peer_id();
    let b_id = b_key.public().to_peer_id();
    let a = Transport::start(a_key, listen(), vec![b_id]).unwrap();
    let mut b = Transport::start(b_key, listen(), vec![a_id]).unwrap();
    let target = address(&mut b).await;
    a.handle.set_pairing_enabled(true).await.unwrap();
    b.handle.set_pairing_enabled(true).await.unwrap();
    let handle = a.handle.clone();
    let request_target = target.clone();
    let pending = tokio::spawn(async move {
        handle
            .pairing_request(b_id, vec![request_target], json!({"step":"wait"}))
            .await
    });
    let held = tokio::time::timeout(Duration::from_secs(5), b.incoming_pairing.recv())
        .await
        .unwrap()
        .unwrap();
    a.handle.set_pairing_enabled(false).await.unwrap();
    assert!(pending.await.unwrap().is_err());
    b.handle.set_pairing_enabled(false).await.unwrap();
    let _ = held.response.send(json!({"late":true}));
    let handle = a.handle.clone();
    let normal = tokio::spawn(async move {
        handle
            .request(b_id, target, WireRequest::new(Operation::Directory))
            .await
    });
    let inbound = tokio::time::timeout(Duration::from_secs(5), b.incoming.recv())
        .await
        .unwrap()
        .unwrap();
    inbound
        .response
        .send(WireResponse::Directory { agents: vec![] })
        .unwrap();
    assert!(matches!(
        normal.await.unwrap().unwrap(),
        WireResponse::Directory { .. }
    ));
}

#[tokio::test]
async fn pairing_frame_limit_is_checked_before_queueing_or_dialing() {
    let a_key = Keypair::generate_ed25519();
    let b_id = Keypair::generate_ed25519().public().to_peer_id();
    let a = Transport::start(a_key, listen(), vec![]).unwrap();
    a.handle.set_pairing_enabled(true).await.unwrap();
    let error = a
        .handle
        .pairing_request(b_id, vec![listen()], json!({"data":"x".repeat(4096)}))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("4 KiB"));
}

#[tokio::test]
async fn unknown_connection_budget_reserves_capacity_for_trusted_peers() {
    let b_key = Keypair::generate_ed25519();
    let trusted_key = Keypair::generate_ed25519();
    let b_id = b_key.public().to_peer_id();
    let trusted_id = trusted_key.public().to_peer_id();
    let mut b = Transport::start(b_key, listen(), vec![trusted_id]).unwrap();
    let target = address(&mut b).await;
    b.handle.set_pairing_enabled(true).await.unwrap();
    let mut strangers = Vec::new();
    for _ in 0..4 {
        let stranger = Transport::start(Keypair::generate_ed25519(), listen(), vec![]).unwrap();
        stranger.handle.set_pairing_enabled(true).await.unwrap();
        let handle = stranger.handle.clone();
        let address = target.clone();
        let request = tokio::spawn(async move {
            handle
                .pairing_request(b_id, vec![address], json!({"step":"hello"}))
                .await
        });
        let incoming = tokio::time::timeout(Duration::from_secs(5), b.incoming_pairing.recv())
            .await
            .unwrap()
            .unwrap();
        incoming.response.send(json!({"ok":true})).unwrap();
        assert_eq!(request.await.unwrap().unwrap(), json!({"ok":true}));
        strangers.push(stranger);
    }
    let extra = Transport::start(Keypair::generate_ed25519(), listen(), vec![]).unwrap();
    extra.handle.set_pairing_enabled(true).await.unwrap();
    assert!(
        extra
            .handle
            .pairing_request(b_id, vec![target.clone()], json!({"step":"hello"}))
            .await
            .is_err()
    );
    assert!(b.incoming_pairing.try_recv().is_err());
    let trusted = Transport::start(trusted_key, listen(), vec![b_id]).unwrap();
    let handle = trusted.handle.clone();
    let request = tokio::spawn(async move {
        handle
            .request(b_id, target, WireRequest::new(Operation::Directory))
            .await
    });
    let incoming = tokio::time::timeout(Duration::from_secs(5), b.incoming.recv())
        .await
        .unwrap()
        .unwrap();
    incoming
        .response
        .send(WireResponse::Directory { agents: vec![] })
        .unwrap();
    assert!(matches!(
        request.await.unwrap().unwrap(),
        WireResponse::Directory { .. }
    ));
    assert_eq!(strangers.len(), 4); // Keep their authenticated connections live through the check.
}
