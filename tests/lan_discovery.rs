use agent_bridge::network::{
    discovery::{
        DISCOVERY_TTL, DiscoveryCache, MAX_ADDRESSES_PER_PEER, MAX_DISCOVERED_PEERS,
        normalize_lan_address,
    },
    transport::Transport,
    wire::{Operation, WireRequest},
};
use libp2p::{Multiaddr, PeerId, identity::Keypair};
use std::time::{Duration, Instant};

#[test]
fn lan_hints_reject_self_unsupported_or_nonlocal_addresses_and_normalize_peer_suffixes() {
    let local = PeerId::random();
    let remote = PeerId::random();
    let mut cache = DiscoveryCache::new(local);
    let now = Instant::now();
    assert!(!cache.observe(
        local,
        &"/ip4/192.168.1.20/udp/44001/quic-v1".parse().unwrap(),
        now
    ));
    for address in [
        "/ip4/127.0.0.1/udp/44001/quic-v1",
        "/ip4/8.8.8.8/udp/44001/quic-v1",
        "/ip4/0.0.0.0/udp/44001/quic-v1",
        "/ip4/224.0.0.251/udp/44001/quic-v1",
        "/ip4/192.168.1.20/udp/0/quic-v1",
        "/ip4/192.168.1.20/tcp/44001",
        "/dns4/example.com/udp/44001/quic-v1",
        "/ip6/::1/udp/44001/quic-v1",
        "/ip6/2001:4860:4860::8888/udp/44001/quic-v1",
    ] {
        assert!(
            normalize_lan_address(remote, &address.parse().unwrap()).is_none(),
            "{address}"
        );
    }
    let raw: Multiaddr = format!("/ip4/192.168.1.20/udp/44001/quic-v1/p2p/{remote}")
        .parse()
        .unwrap();
    assert!(cache.observe(remote, &raw, now));
    assert_eq!(
        cache.snapshot()[0].addresses,
        ["/ip4/192.168.1.20/udp/44001/quic-v1"]
    );
    let mismatched = format!("/ip4/192.168.1.20/udp/44001/quic-v1/p2p/{local}")
        .parse()
        .unwrap();
    assert!(normalize_lan_address(remote, &mismatched).is_none());
    for address in [
        "/ip4/169.254.1.20/udp/44001/quic-v1",
        "/ip6/fd00::20/udp/44001/quic-v1",
        "/ip6/fe80::20/udp/44001/quic-v1",
    ] {
        assert!(normalize_lan_address(remote, &address.parse().unwrap()).is_some());
    }
}

#[test]
fn cache_bounds_refresh_and_expiry_preserve_only_live_hints() {
    let mut cache = DiscoveryCache::new(PeerId::random());
    let now = Instant::now();
    let remote = PeerId::random();
    for port in 1..=MAX_ADDRESSES_PER_PEER {
        assert!(
            cache.observe(
                remote,
                &format!("/ip4/192.168.1.20/udp/{port}/quic-v1")
                    .parse()
                    .unwrap(),
                now
            )
        );
    }
    assert!(!cache.observe(
        remote,
        &"/ip4/192.168.1.20/udp/9000/quic-v1".parse().unwrap(),
        now
    ));
    for _ in 1..MAX_DISCOVERED_PEERS {
        assert!(cache.observe(
            PeerId::random(),
            &"/ip4/192.168.1.21/udp/44001/quic-v1".parse().unwrap(),
            now
        ));
    }
    assert!(!cache.observe(
        PeerId::random(),
        &"/ip4/192.168.1.22/udp/44001/quic-v1".parse().unwrap(),
        now
    ));
    let address = "/ip4/192.168.1.20/udp/1/quic-v1".parse().unwrap();
    assert!(cache.observe(remote, &address, now + Duration::from_secs(5)));
    assert!(cache.expire_due(now + DISCOVERY_TTL));
    let entries = cache.snapshot();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].addresses.len(), 1);
    assert_eq!(entries[0].peer_id, remote.to_string());
    assert!(cache.expire(remote, &address));
    assert!(cache.snapshot().is_empty());
}

fn local_lan_ip() -> std::net::Ipv4Addr {
    // UDP connect selects a local route without sending a packet or querying DNS.
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect("192.0.2.1:9").unwrap();
    match socket.local_addr().unwrap().ip() {
        std::net::IpAddr::V4(ip) if ip.is_private() => ip,
        other => panic!("test requires a private IPv4 LAN interface, got {other}"),
    }
}

async fn wait_for_hint(transport: &Transport, peer: PeerId, present: bool) {
    tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            let status = transport.status.borrow().clone();
            let found = status["discovered"].as_array().is_some_and(|entries| {
                entries
                    .iter()
                    .any(|entry| entry["peer_id"] == peer.to_string())
            });
            if found == present {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("multicast hint condition timed out");
}

#[tokio::test]
#[ignore = "requires a multicast-capable private IPv4 LAN; run explicitly"]
async fn real_multicast_discovers_unpaired_peers_without_granting_access_and_drop_expires_hint() {
    let ip = local_lan_ip();
    let alice_key = Keypair::generate_ed25519();
    let alice_id = alice_key.public().to_peer_id();
    let bob_key = Keypair::generate_ed25519();
    let bob_id = bob_key.public().to_peer_id();
    let listen: Multiaddr = format!("/ip4/{ip}/udp/0/quic-v1").parse().unwrap();
    let alice =
        Transport::start_named(alice_key, listen.clone(), vec![], true, "machine-a").unwrap();
    let bob = Transport::start_named(bob_key, listen, vec![], true, "machine-b").unwrap();
    wait_for_hint(&alice, bob_id, true).await;
    wait_for_hint(&bob, alice_id, true).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let named = alice.status.borrow()["discovered"]
                .as_array()
                .is_some_and(|entries| {
                    entries.iter().any(|entry| {
                        entry["peer_id"] == bob_id.to_string()
                            && entry["machine_name"] == "machine-b"
                    })
                });
            if named {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("unverified machine name was not discovered");
    let discovered = alice.status.borrow()["discovered"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["peer_id"] == bob_id.to_string())
        .unwrap()["addresses"][0]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        alice
            .handle
            .request(bob_id, discovered, WireRequest::new(Operation::Directory))
            .await
            .is_err()
    );
    assert!(
        alice.status.borrow()["connected"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    drop(bob);
    wait_for_hint(&alice, bob_id, false).await;
}

#[test]
fn labels_require_live_matching_addresses_and_do_not_establish_identity() {
    let local = PeerId::random();
    let first = PeerId::random();
    let second = PeerId::random();
    let now = Instant::now();
    let address = "/ip4/192.168.1.20/udp/44001/quic-v1".parse().unwrap();
    let other_address = "/ip4/192.168.1.21/udp/44001/quic-v1".parse().unwrap();
    let mut cache = DiscoveryCache::new(local);
    assert!(!cache.set_name(first, &address, Some("machine-b"), now));
    assert!(cache.observe(first, &address, now));
    assert!(!cache.set_name(first, &other_address, Some("machine-b"), now));
    assert!(cache.set_name(first, &address, Some("machine-b"), now));
    assert_eq!(
        cache.snapshot()[0].machine_name.as_deref(),
        Some("machine-b")
    );
    assert!(cache.set_name(first, &address, Some("bad/name"), now));
    assert_eq!(cache.snapshot()[0].machine_name, None);
    assert_eq!(cache.snapshot()[0].addresses.len(), 1);
    cache.set_name(first, &address, Some("machine-b"), now);
    cache.observe(second, &other_address, now);
    cache.set_name(second, &other_address, Some("machine-b"), now);
    let peers = cache.snapshot();
    assert_eq!(peers.len(), 2);
    assert_ne!(peers[0].peer_id, peers[1].peer_id);
    assert!(
        peers
            .iter()
            .all(|peer| peer.machine_name.as_deref() == Some("machine-b"))
    );
}

#[test]
fn name_refresh_never_extends_address_lifetime_and_name_has_its_own_expiry() {
    let peer = PeerId::random();
    let address = "/ip4/192.168.1.20/udp/44001/quic-v1".parse().unwrap();
    let now = Instant::now();
    let mut cache = DiscoveryCache::new(PeerId::random());
    cache.observe(peer, &address, now);
    cache.set_name(
        peer,
        &address,
        Some("machine-b"),
        now + Duration::from_secs(29),
    );
    cache.expire_due(now + DISCOVERY_TTL);
    assert!(cache.snapshot().is_empty());
    assert!(!cache.set_name(peer, &address, Some("machine-b"), now + DISCOVERY_TTL));
    cache.observe(peer, &address, now);
    cache.set_name(peer, &address, Some("machine-b"), now);
    cache.observe(peer, &address, now + Duration::from_secs(5));
    cache.expire_due(now + Duration::from_secs(31));
    assert_eq!(cache.snapshot().len(), 1);
    assert_eq!(cache.snapshot()[0].machine_name, None);
}

#[tokio::test]
async fn reserved_dot_names_are_ignored_as_hints_and_rejected_for_local_advertising() {
    let now = Instant::now();
    let peer = PeerId::random();
    let address = "/ip4/192.168.1.20/udp/44001/quic-v1".parse().unwrap();
    let mut cache = DiscoveryCache::new(PeerId::random());
    cache.observe(peer, &address, now);
    for name in [".", ".."] {
        cache.set_name(peer, &address, Some("machine-b"), now);
        assert!(cache.set_name(peer, &address, Some(name), now));
        assert_eq!(cache.snapshot()[0].machine_name, None);
        assert_eq!(cache.snapshot()[0].addresses.len(), 1);
        assert!(
            Transport::start_named(
                Keypair::generate_ed25519(),
                "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
                vec![],
                true,
                name
            )
            .is_err()
        );
    }
}
