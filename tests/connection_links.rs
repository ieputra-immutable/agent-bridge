use agent_bridge::network::{
    contact::{self, MAX_LINK_BYTES, PREFIX},
    identity::Identity,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use qrcode::{
    Color, EcLevel, QrCode,
    render::{svg, unicode},
};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

fn identity(root: &std::path::Path, name: &str) -> Identity {
    Identity::load_or_create(&root.join(name)).unwrap()
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
fn peer() -> String {
    libp2p_identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id()
        .to_string()
}

#[test]
fn signed_contact_carries_only_public_identity_and_optional_routing_hints() {
    let root = tempfile::tempdir().unwrap();
    let id = identity(root.path(), "issuer");
    let relay = peer();
    let addresses = vec![
        format!("/dns4/relay.example.com/udp/4001/quic-v1/p2p/{relay}"),
        format!("/dns4/relay.example.com/tcp/443/p2p/{relay}"),
    ];
    let contact = contact::create(&id, "machine-b", &addresses, 120).unwrap();
    let parsed = contact::verify(&contact.link, now()).unwrap();
    assert_eq!(parsed.peer_id, id.info().peer_id);
    assert_eq!(parsed.fingerprint, id.info().fingerprint);
    assert_eq!(parsed.machine_name.as_deref(), Some("machine-b"));
    assert_eq!(parsed.relays, addresses);
    assert_eq!(parsed.nonce, contact.nonce);
    assert!(
        !root.path().join("issuer/messages.sqlite3").exists(),
        "Contact metadata must not create trust/grants storage"
    );
    // Contact links are reusable metadata, not single-use grants. Both imports
    // still require local owner approval and fresh SAS confirmation in the broker.
    assert!(contact::verify(&contact.link, now()).is_ok());
    let value = serde_json::to_value(&contact).unwrap();
    assert!(value.get("private_key").is_none());
    assert!(value.get("grants").is_none());
    assert!(contact.link.len() <= MAX_LINK_BYTES);
}

#[test]
fn qr_modules_decode_independently_to_the_exact_link_and_artifacts_match() {
    let root = tempfile::tempdir().unwrap();
    let id = identity(root.path(), "issuer");
    let contact = contact::create(&id, "machine-a", &[], 120).unwrap();
    let code = QrCode::with_error_correction_level(contact.link.as_bytes(), EcLevel::M).unwrap();
    // Validate both actual generated artifacts against the QR module renderer,
    // then decode those modules with an independent QR implementation.
    assert_eq!(
        contact.qr_svg,
        code.render::<svg::Color>()
            .quiet_zone(true)
            .min_dimensions(256, 256)
            .build()
    );
    assert_eq!(
        contact.qr_terminal,
        code.render::<unicode::Dense1x2>().quiet_zone(true).build()
    );
    let scale = 4;
    let quiet = 4;
    let side = (code.width() + 2 * quiet) * scale;
    let mut grayscale = vec![255u8; side * side];
    for y in 0..code.width() {
        for x in 0..code.width() {
            if code[(x, y)] == Color::Dark {
                for dy in 0..scale {
                    for dx in 0..scale {
                        grayscale[((y + quiet) * scale + dy) * side + (x + quiet) * scale + dx] = 0;
                    }
                }
            }
        }
    }
    let mut decoder = quircs::Quirc::default();
    let payloads = decoder
        .identify(side, side, &grayscale)
        .map(|code| code.unwrap().decode().unwrap().payload)
        .collect::<Vec<_>>();
    assert_eq!(payloads, vec![contact.link.as_bytes().to_vec()]);
    assert!(
        !contact.qr_svg.contains(&contact.link),
        "SVG uses modules, not unescaped user-provided markup"
    );
}

#[test]
fn contact_parser_rejects_url_variants_unknown_fields_and_unsigned_mutations() {
    let root = tempfile::tempdir().unwrap();
    let id = identity(root.path(), "issuer");
    let contact = contact::create(&id, "machine-a", &[], 120).unwrap();
    for link in [
        format!(" {}", contact.link),
        format!("{}\n", contact.link),
        format!("{}#anything", contact.link),
        format!("{}?relay=evil", contact.link),
        format!("{}/", contact.link),
        contact.link.replacen("agent-bridge:", "AGENT-BRIDGE:", 1),
        format!("{}=", contact.link),
        "agent-bridge://connect/".into(),
        "https://example.com/redirect".into(),
        format!("{PREFIX}{}", "x".repeat(MAX_LINK_BYTES)),
    ] {
        assert!(
            contact::verify(&link, now()).is_err(),
            "accepted ambiguous/noncanonical link"
        );
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(contact.link.strip_prefix(PREFIX).unwrap())
        .unwrap();
    let original: Value = serde_json::from_slice(&decoded).unwrap();
    for field in [
        "unexpected_top",
        "unexpected_payload",
        "machine_name",
        "expires_at",
        "peer_id",
        "signature",
    ] {
        let mut value = original.clone();
        match field {
            "unexpected_top" => value[field] = true.into(),
            "unexpected_payload" => value["payload"]["grant_receive"] = true.into(),
            "machine_name" => value["payload"][field] = "other-machine".into(),
            "expires_at" => {
                value["payload"][field] = (value["payload"][field].as_i64().unwrap() + 1).into()
            }
            "peer_id" => value["payload"][field] = peer().into(),
            "signature" => value[field] = URL_SAFE_NO_PAD.encode([0u8; 64]).into(),
            _ => unreachable!(),
        }
        let changed = format!(
            "{PREFIX}{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap())
        );
        assert!(
            contact::verify(&changed, now()).is_err(),
            "accepted {field}"
        );
    }
}

#[test]
fn contact_route_capacity_and_qr_budget_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let id = identity(root.path(), "issuer");
    let relays: Vec<_> = (0..5)
        .map(|_| format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{}", peer()))
        .collect();
    assert!(contact::create(&id, "machine-a", &relays, 120).is_err());
    assert!(contact::create(&id, "..", &[], 120).is_err());
    let same = peer();
    let duplicate = format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{same}");
    assert!(contact::create(&id, "machine-a", &[duplicate.clone(), duplicate], 120).is_err());
    let selfrelay = format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{}", id.info().peer_id);
    assert!(contact::create(&id, "machine-a", &[selfrelay], 120).is_err());
    let long_domain = format!(
        "{}.{}.{}.example",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63)
    );
    let mut oversized = Vec::new();
    for _ in 0..4 {
        let relay = peer();
        oversized.push(format!("/dns4/{long_domain}/udp/4001/quic-v1/p2p/{relay}"));
        oversized.push(format!("/dns4/{long_domain}/tcp/443/p2p/{relay}"));
    }
    assert!(
        contact::create(&id, "machine-a", &oversized, 120).is_err(),
        "oversized link cannot silently drop hints or emit unscannable QR"
    );
}
