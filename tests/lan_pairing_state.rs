use agent_bridge::network::lan_pairing::{Manager, Outgoing};
use serde_json::json;

const NOW: i64 = 1_000_000;
fn identity() -> String {
    libp2p_identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id()
        .to_string()
}
fn managers() -> (String, String, Manager, Manager) {
    let a = identity();
    let b = identity();
    (
        a.clone(),
        b.clone(),
        Manager::new(&a).unwrap(),
        Manager::new(&b).unwrap(),
    )
}
fn packet(manager: &mut Manager) -> Outgoing {
    manager.outgoing(NOW).into_iter().next().unwrap()
}
fn deliver(from: &str, sender: &mut Manager, receiver: &mut Manager) {
    receiver.receive(from, packet(sender).packet, NOW).unwrap();
}
fn begin(a: &str, b: &str, ma: &mut Manager, mb: &mut Manager) -> String {
    mb.open(120, NOW).unwrap();
    let id = ma.start(b, 120, NOW).unwrap().id;
    deliver(a, ma, mb);
    mb.accept(&id, NOW).unwrap();
    deliver(b, mb, ma);
    id
}
fn keys(a: &str, b: &str, ma: &mut Manager, mb: &mut Manager) -> String {
    let id = begin(a, b, ma, mb);
    deliver(a, ma, mb);
    deliver(b, mb, ma);
    id
}
fn code(manager: &mut Manager) -> String {
    manager.list(NOW)[0].verification_code.clone().unwrap()
}

#[test]
fn owners_compare_same_code_and_both_confirm_before_any_trust() {
    let (a, b, mut ma, mut mb) = managers();
    let id = keys(&a, &b, &mut ma, &mut mb);
    let ca = code(&mut ma);
    assert_eq!(ca, code(&mut mb));
    assert!(ca.split('-').all(|part| part.len() == 4));
    assert!(ma.take_trusted(NOW).is_empty());
    assert!(mb.take_trusted(NOW).is_empty());
    ma.confirm(&id, &ca, NOW).unwrap();
    deliver(&a, &mut ma, &mut mb);
    assert!(ma.take_trusted(NOW).is_empty());
    assert!(mb.take_trusted(NOW).is_empty());
    assert!(!mb.list(NOW)[0].local_confirmed);
    assert!(mb.list(NOW)[0].remote_confirmed);
    mb.confirm(&id, &ca, NOW).unwrap();
    deliver(&b, &mut mb, &mut ma);
    let ta = ma.take_trusted(NOW);
    let tb = mb.take_trusted(NOW);
    assert_eq!(ta[0].peer, b);
    assert_eq!(tb[0].peer, a);
    assert!(ma.take_trusted(NOW).is_empty());
    assert!(mb.take_trusted(NOW).is_empty());
    ma.mark_paired(&id).unwrap();
    mb.mark_paired(&id).unwrap();
    assert_eq!(ma.list(NOW)[0].state, "paired");
    // Final MACs continue to be retried until expiry, even after local commit.
    assert!(ma.window_open(NOW));
    assert!(mb.window_open(NOW));
    assert_eq!(packet(&mut mb).packet["op"], "confirm");
    assert!(
        !serde_json::to_string(&packet(&mut mb).packet)
            .unwrap()
            .contains(&ca)
    );
}

#[test]
fn responder_can_confirm_before_its_public_key_is_delivered() {
    let (a, b, mut ma, mut mb) = managers();
    let id = begin(&a, &b, &mut ma, &mut mb);
    deliver(&a, &mut ma, &mut mb);
    let c = code(&mut mb);
    assert!(ma.list(NOW)[0].verification_code.is_none());
    mb.confirm(&id, &c, NOW).unwrap();
    assert_eq!(packet(&mut mb).packet["op"], "key");
    deliver(&b, &mut mb, &mut ma);
    assert_eq!(code(&mut ma), c);
    ma.confirm(&id, &c, NOW).unwrap();
    deliver(&a, &mut ma, &mut mb);
    assert_eq!(packet(&mut mb).packet["op"], "confirm");
    deliver(&b, &mut mb, &mut ma);
    assert_eq!(ma.take_trusted(NOW).len(), 1);
    assert_eq!(mb.take_trusted(NOW).len(), 1);
}

#[test]
fn incorrect_code_cancels_attempt_instead_of_allowing_guesses() {
    let (a, b, mut ma, mut mb) = managers();
    let id = keys(&a, &b, &mut ma, &mut mb);
    let c = code(&mut ma);
    assert!(ma.confirm(&id, "0000-0000-0000", NOW).is_err());
    assert!(ma.confirm(&id, &c, NOW).is_err());
    assert!(ma.take_trusted(NOW).is_empty());
    assert_eq!(ma.list(NOW)[0].state, "cancelled");
    deliver(&a, &mut ma, &mut mb);
    assert_eq!(mb.list(NOW)[0].state, "cancelled");
    assert!(mb.take_trusted(NOW).is_empty());
}

#[test]
fn identity_substitution_commitment_tampering_and_invalid_mac_fail_closed() {
    let (a, b, mut ma, mut mb) = managers();
    let id = begin(&a, &b, &mut ma, &mut mb);
    let p = packet(&mut ma).packet;
    assert!(mb.receive(&identity(), p.clone(), NOW).is_err());
    assert_eq!(mb.list(NOW)[0].state, "exchanging_keys");
    mb.receive(&a, p, NOW).unwrap();
    let mut changed = packet(&mut mb).packet;
    changed["key"] = json!(vodozemac::sas::Sas::new().public_key().to_base64());
    assert!(ma.receive(&b, changed, NOW).is_err());
    assert_eq!(ma.list(NOW)[0].state, "cancelled");
    assert!(ma.take_trusted(NOW).is_empty());
    let (a, b, mut ma, mut mb) = managers();
    let id2 = keys(&a, &b, &mut ma, &mut mb);
    let c = code(&mut ma);
    ma.confirm(&id2, &c, NOW).unwrap();
    let bad = json!({"op":"confirm","id":id2,"mac":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"});
    assert!(ma.receive(&b, bad, NOW).is_err());
    assert!(ma.take_trusted(NOW).is_empty());
    assert_ne!(id, id2);
}

#[test]
fn closed_windows_expiry_restart_and_revocation_remove_pending_trust() {
    let (a, b, mut ma, mut mb) = managers();
    let v = ma.start(&b, 30, NOW).unwrap();
    assert!(mb.receive(&a, packet(&mut ma).packet, NOW).is_err());
    mb.open(120, NOW).unwrap();
    deliver(&a, &mut ma, &mut mb);
    mb.accept(&v.id, NOW).unwrap();
    deliver(&b, &mut mb, &mut ma);
    deliver(&a, &mut ma, &mut mb);
    deliver(&b, &mut mb, &mut ma);
    assert!(ma.confirm(&v.id, "anything", NOW + 30000).is_err());
    assert!(ma.list(NOW + 30000).is_empty());
    let (a, b, mut ma, mut mb) = managers();
    let id = keys(&a, &b, &mut ma, &mut mb);
    let c = code(&mut ma);
    ma.confirm(&id, &c, NOW).unwrap();
    mb.confirm(&id, &c, NOW).unwrap();
    deliver(&a, &mut ma, &mut mb);
    deliver(&b, &mut mb, &mut ma);
    ma.cancel_peer(&b);
    assert!(ma.take_trusted(NOW).is_empty());
    assert!(ma.receive(&b, packet(&mut mb).packet, NOW).is_err());
    mb.close();
    assert!(mb.take_trusted(NOW).is_empty());
    assert!(!mb.window_open(NOW));
    let mut restarted = Manager::new(&a).unwrap();
    assert!(restarted.receive(&b, packet(&mut ma).packet, NOW).is_err());
    assert!(restarted.take_trusted(NOW).is_empty());
}

#[test]
fn requests_are_bounded_deduplicated_and_never_contain_agent_instructions() {
    let local = identity();
    let mut receiver = Manager::new(&local).unwrap();
    receiver.open(600, NOW).unwrap();
    for n in 0..8 {
        let remote = identity();
        let mut sender = Manager::new(&remote).unwrap();
        sender.start(&local, 120, NOW).unwrap();
        let p = packet(&mut sender).packet;
        receiver.receive(&remote, p.clone(), NOW).unwrap();
        receiver.receive(&remote, p.clone(), NOW).unwrap();
        let mut conflict = p;
        conflict["start"]["expires_at"] = json!(NOW + 121000);
        assert!(receiver.receive(&remote, conflict, NOW).is_err());
        assert_eq!(receiver.list(NOW).len(), n + 1);
    }
    let remote = identity();
    let mut sender = Manager::new(&remote).unwrap();
    sender.start(&local, 120, NOW).unwrap();
    assert!(
        receiver
            .receive(&remote, packet(&mut sender).packet, NOW)
            .is_err()
    );
    for value in [
        json!({"op":"send","body":"do something"}),
        json!({"op":"request","start":{},"instructions":"hello"}),
        json!({"op":"key","id":uuid::Uuid::new_v4().to_string(),"key":"x".repeat(4097)}),
    ] {
        assert!(receiver.receive(&remote, value, NOW).is_err());
    }
    receiver.close();
    assert_eq!(receiver.list(NOW).len(), 0);
}

#[test]
fn duplicate_protocol_packets_do_not_reset_keys_or_confirmation_state() {
    let (a, b, mut ma, mut mb) = managers();
    mb.open(120, NOW).unwrap();
    let id = ma.start(&b, 120, NOW).unwrap().id;
    let start = packet(&mut ma).packet;
    mb.receive(&a, start.clone(), NOW).unwrap();
    mb.accept(&id, NOW).unwrap();
    mb.receive(&a, start, NOW).unwrap();
    let commit = packet(&mut mb).packet;
    ma.receive(&b, commit.clone(), NOW).unwrap();
    ma.receive(&b, commit, NOW).unwrap();
    let ikey = packet(&mut ma).packet;
    mb.receive(&a, ikey.clone(), NOW).unwrap();
    mb.receive(&a, ikey, NOW).unwrap();
    let rkey = packet(&mut mb).packet;
    ma.receive(&b, rkey.clone(), NOW).unwrap();
    ma.receive(&b, rkey, NOW).unwrap();
    let c = code(&mut ma);
    assert_eq!(c, code(&mut mb));
    ma.confirm(&id, &c, NOW).unwrap();
    let m = packet(&mut ma).packet;
    mb.receive(&a, m.clone(), NOW).unwrap();
    mb.receive(&a, m, NOW).unwrap();
    assert!(!mb.list(NOW)[0].local_confirmed);
    assert!(mb.take_trusted(NOW).is_empty());
}

#[test]
fn local_start_does_not_implicitly_accept_other_incoming_pairing_requests() {
    let (a, b, mut ma, _) = managers();
    ma.start(&b, 120, NOW).unwrap();
    assert!(ma.window_open(NOW));
    let attacker = identity();
    let mut other = Manager::new(&attacker).unwrap();
    other.start(&a, 120, NOW).unwrap();
    assert!(
        ma.receive(&attacker, packet(&mut other).packet, NOW)
            .is_err()
    );
    assert!(ma.start(&b, 120, NOW).is_err());
    assert!(ma.start(&a, 120, NOW).is_err());
    assert!(ma.start(&identity(), 29, NOW).is_err());
    assert!(ma.open(601, NOW).is_err());
}

#[test]
fn final_confirmation_retries_outlive_the_inbound_acceptance_window() {
    let (a, b, mut ma, mut mb) = managers();
    mb.open(30, NOW).unwrap();
    let id = ma.start(&b, 120, NOW).unwrap().id;
    deliver(&a, &mut ma, &mut mb);
    mb.accept(&id, NOW).unwrap();
    deliver(&b, &mut mb, &mut ma);
    deliver(&a, &mut ma, &mut mb);
    deliver(&b, &mut mb, &mut ma);
    let c = code(&mut ma);
    // The short inbound window has closed, but the accepted request is valid.
    ma.confirm(&id, &c, NOW + 31000).unwrap();
    mb.confirm(&id, &c, NOW + 31000).unwrap();
    mb.receive(&a, packet(&mut ma).packet, NOW + 31000).unwrap();
    let trust = mb.take_trusted(NOW + 31000);
    assert_eq!(trust.len(), 1);
    mb.mark_paired(&id).unwrap();
    assert!(mb.window_open(NOW + 31000));
    // Receiver stays pairing-capable until the initiator gets the final MAC.
    let final_mac = mb.outgoing(NOW + 31000).remove(0).packet;
    ma.receive(&b, final_mac, NOW + 31000).unwrap();
    assert_eq!(ma.take_trusted(NOW + 31000).len(), 1);
    assert!(!mb.window_open(NOW + 120000));
}
