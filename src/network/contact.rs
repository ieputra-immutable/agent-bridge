//! Signed public contact metadata for owner-approved pairing, not authorization.
//!
//! Links are intentionally reusable until expiry: importing one must never grant
//! trust, restore a revoked peer or import an operator without local consent.
use super::{identity::Identity, machine, relay_config};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use libp2p_identity::{KeyType, PublicKey};
use qrcode::{
    EcLevel, QrCode,
    render::{svg, unicode},
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub const PREFIX: &str = "agent-bridge://connect/";
pub const MAX_LINK_BYTES: usize = 2048;
const MAX_RELAY_ADDRESSES: usize = 8;
const DOMAIN: &[u8] = b"agent-bridge/connection-contact/1\0";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    version: u32,
    peer_id: String,
    public_key: String,
    machine_name: Option<String>,
    issued_at: i64,
    expires_at: i64,
    nonce: String,
    relays: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed {
    payload: Payload,
    signature: String,
}

/// Only public metadata and locally generated QR representations are returned.
#[derive(Serialize)]
pub struct Contact {
    pub link: String,
    pub peer_id: String,
    pub fingerprint: String,
    pub machine_name: Option<String>,
    pub expires_at: i64,
    pub nonce: String,
    pub qr_svg: String,
    pub qr_terminal: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedContact {
    pub peer_id: String,
    pub fingerprint: String,
    pub machine_name: Option<String>,
    pub relays: Vec<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub nonce: String,
}

fn signed_bytes(payload: &Payload) -> Result<Vec<u8>> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(serde_json::to_vec(payload)?);
    Ok(bytes)
}
fn decode_bytes(value: &str, max: usize) -> Result<Vec<u8>> {
    ensure!(
        value.len() <= max.div_ceil(3) * 4,
        "Contact key/signature is too large"
    );
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .context("Invalid contact key/signature encoding")?;
    ensure!(
        bytes.len() <= max && URL_SAFE_NO_PAD.encode(&bytes) == value,
        "Contact key/signature must use canonical base64url"
    );
    Ok(bytes)
}
fn relay_addresses(values: &[String], endpoint: &str) -> Result<()> {
    ensure!(
        values.len() <= MAX_RELAY_ADDRESSES,
        "Contacts allow at most eight relay addresses"
    );
    let mut addresses = HashSet::new();
    let mut carriers = HashSet::new();
    let mut operators = HashMap::<String, usize>::new();
    for address in values {
        let relay = relay_config::validate_relay(address)?;
        ensure!(
            relay.peer_id != endpoint,
            "Contact endpoint cannot also be its relay"
        );
        ensure!(addresses.insert(address), "Duplicate contact relay address");
        ensure!(
            carriers.insert((relay.peer_id.clone(), relay_config::carrier(address)?)),
            "Contacts allow one address per operator and carrier"
        );
        let count = operators.entry(relay.peer_id).or_default();
        *count += 1;
        ensure!(
            *count <= 2,
            "Contacts allow at most two addresses per operator"
        );
    }
    ensure!(
        operators.len() <= relay_config::MAX_RELAYS,
        "Contacts allow at most four independent relay operators"
    );
    Ok(())
}

/// Produce a bounded signed link and QR locally; this changes no pairing policy.
pub fn create(
    identity: &Identity,
    machine_name: &str,
    relays: &[String],
    seconds: u64,
) -> Result<Contact> {
    create_at(identity, machine_name, relays, seconds, crate::db::now())
}
fn create_at(
    identity: &Identity,
    machine_name: &str,
    relays: &[String],
    seconds: u64,
    now: i64,
) -> Result<Contact> {
    ensure!(
        (30..=600).contains(&seconds),
        "Contact lifetime must be 30–600 seconds"
    );
    ensure!(now >= 0, "Invalid local clock");
    machine::validate_name(machine_name)?;
    let info = identity.info();
    relay_addresses(relays, &info.peer_id)?;
    let payload = Payload {
        version: 1,
        peer_id: info.peer_id.clone(),
        public_key: URL_SAFE_NO_PAD.encode(identity.keypair().public().encode_protobuf()),
        machine_name: Some(machine_name.into()),
        issued_at: now,
        expires_at: now
            .checked_add(seconds as i64 * 1000)
            .context("Contact time overflow")?,
        nonce: uuid::Uuid::new_v4().to_string(),
        relays: relays.to_vec(),
    };
    let signature = URL_SAFE_NO_PAD.encode(identity.keypair().sign(&signed_bytes(&payload)?)?);
    let token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Signed {
        payload: payload.clone(),
        signature,
    })?);
    let link = format!("{PREFIX}{token}");
    ensure!(
        link.len() <= MAX_LINK_BYTES,
        "Contact link is too large for a reliable QR code; include fewer relay hints"
    );
    let code = QrCode::with_error_correction_level(link.as_bytes(), EcLevel::M)
        .context("Contact link does not fit a QR code")?;
    let qr_svg = code
        .render::<svg::Color>()
        .quiet_zone(true)
        .min_dimensions(256, 256)
        .build();
    let qr_terminal = code.render::<unicode::Dense1x2>().quiet_zone(true).build();
    let contact = Contact {
        link,
        peer_id: info.peer_id,
        fingerprint: info.fingerprint,
        machine_name: payload.machine_name,
        expires_at: payload.expires_at,
        nonce: payload.nonce,
        qr_svg,
        qr_terminal,
    };
    // Local RPC responses are bounded too. Keep room for the normal result wrapper.
    ensure!(
        serde_json::to_vec(&contact)?.len() <= crate::protocol::MAX_FRAME - 1024,
        "Contact QR output exceeds the local response limit"
    );
    Ok(contact)
}

/// Verify key ownership and expiry only. The caller still obtains owner consent,
/// compares the SAS, and explicitly decides whether to use any carried operators.
pub fn verify(link: &str, now: i64) -> Result<VerifiedContact> {
    ensure!(link.len() <= MAX_LINK_BYTES, "Contact link is too large");
    let token = link
        .strip_prefix(PREFIX)
        .context("Use an agent-bridge://connect/ contact link")?;
    ensure!(!token.is_empty(), "Contact link is empty");
    let decoded = URL_SAFE_NO_PAD
        .decode(token)
        .context("Invalid contact link encoding")?;
    ensure!(
        URL_SAFE_NO_PAD.encode(&decoded) == token,
        "Contact link encoding must be canonical"
    );
    let contact: Signed =
        serde_json::from_slice(&decoded).context("Invalid contact link format")?;
    ensure!(
        serde_json::to_vec(&contact)? == decoded,
        "Contact JSON must be canonical"
    );
    let payload = &contact.payload;
    ensure!(payload.version == 1, "Unsupported contact link version");
    let public = decode_bytes(&payload.public_key, 128)?;
    let signature = decode_bytes(&contact.signature, 64)?;
    ensure!(signature.len() == 64, "Invalid contact signature size");
    let key = PublicKey::try_decode_protobuf(&public).context("Invalid contact public key")?;
    ensure!(
        key.key_type() == KeyType::Ed25519 && key.encode_protobuf() == public,
        "Contact requires a canonical Ed25519 public key"
    );
    ensure!(
        key.to_peer_id().to_string() == payload.peer_id,
        "Contact public key does not match the target identity"
    );
    ensure!(
        key.verify(&signed_bytes(payload)?, &signature),
        "Invalid contact signature"
    );
    let duration = payload
        .expires_at
        .checked_sub(payload.issued_at)
        .context("Invalid contact times")?;
    ensure!(
        (30_000..=600_000).contains(&duration) && payload.issued_at >= 0 && now >= 0,
        "Invalid contact lifetime"
    );
    ensure!(
        payload.issued_at <= now.saturating_add(30_000),
        "Contact was issued in the future; check clocks"
    );
    ensure!(payload.expires_at > now, "Contact expired");
    let nonce = uuid::Uuid::parse_str(&payload.nonce).context("Invalid contact nonce")?;
    ensure!(
        nonce.to_string() == payload.nonce && nonce.get_version() == Some(uuid::Version::Random),
        "Contact nonce must be a canonical random UUID"
    );
    if let Some(name) = &payload.machine_name {
        machine::validate_name(name)?;
    }
    relay_addresses(&payload.relays, &payload.peer_id)?;
    Ok(VerifiedContact {
        peer_id: payload.peer_id.clone(),
        fingerprint: payload.peer_id.clone(),
        machine_name: payload.machine_name.clone(),
        relays: payload.relays.clone(),
        issued_at: payload.issued_at,
        expires_at: payload.expires_at,
        nonce: payload.nonce.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> (tempfile::TempDir, Identity) {
        let dir = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let id = Identity::load_or_create(dir.path()).unwrap();
        (dir, id)
    }
    fn encode(contact: &Signed) -> String {
        format!(
            "{PREFIX}{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(contact).unwrap())
        )
    }
    #[test]
    fn valid_shaped_mutations_and_another_signer_cannot_substitute_contact_identity_or_routes() {
        let (_dir, id) = identity();
        let (_other_dir, other) = identity();
        let contact = create_at(&id, "machine-a", &[], 60, 100_000).unwrap();
        let original: Signed = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(contact.link.strip_prefix(PREFIX).unwrap())
                .unwrap(),
        )
        .unwrap();
        for mutation in 0..6 {
            let mut forged = Signed {
                payload: original.payload.clone(),
                signature: original.signature.clone(),
            };
            match mutation {
                0 => forged.payload.machine_name = Some("machine-b".into()),
                1 => forged.payload.expires_at += 1,
                2 => forged.payload.nonce = uuid::Uuid::new_v4().to_string(),
                3 => forged.payload.peer_id = other.info().peer_id,
                4 => {
                    forged.payload.public_key =
                        URL_SAFE_NO_PAD.encode(other.keypair().public().encode_protobuf())
                }
                5 => {
                    forged.payload.relays = vec![format!(
                        "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{}",
                        other.info().peer_id
                    )]
                }
                _ => unreachable!(),
            }
            assert!(verify(&encode(&forged), 100_000).is_err());
        }
        let mut forged = original;
        forged.signature = URL_SAFE_NO_PAD.encode(
            other
                .keypair()
                .sign(&signed_bytes(&forged.payload).unwrap())
                .unwrap(),
        );
        assert!(verify(&encode(&forged), 100_000).is_err());
        // A signature by the correct key over undomained JSON is still invalid.
        forged.signature = URL_SAFE_NO_PAD.encode(
            id.keypair()
                .sign(&serde_json::to_vec(&forged.payload).unwrap())
                .unwrap(),
        );
        assert!(verify(&encode(&forged), 100_000).is_err());
    }
    #[test]
    fn expiry_future_clock_canonical_json_and_protocol_domains_are_enforced() {
        let (_dir, id) = identity();
        let contact = create_at(&id, "machine-a", &[], 30, 100_000).unwrap();
        assert!(verify(&contact.link, 100_000).is_ok());
        assert!(verify(&contact.link, 129_999).is_ok());
        assert!(verify(&contact.link, 130_000).is_err());
        assert!(verify(&contact.link, 69_999).is_err());
        let decoded = URL_SAFE_NO_PAD
            .decode(contact.link.strip_prefix(PREFIX).unwrap())
            .unwrap();
        let signed: Signed = serde_json::from_slice(&decoded).unwrap();
        assert!(
            verify(
                &format!(
                    "{PREFIX}{}",
                    URL_SAFE_NO_PAD.encode(serde_json::to_vec_pretty(&signed).unwrap())
                ),
                100_000
            )
            .is_err()
        );
        assert!(create_at(&id, "machine-a", &[], 29, 100_000).is_err());
        assert!(create_at(&id, "machine-a", &[], 601, 100_000).is_err());
        let legacy = super::super::invitation::create(&id, &[], 60).unwrap();
        assert!(verify(&format!("{PREFIX}{legacy}"), 100_000).is_err());
    }
    #[test]
    fn correctly_signed_duplicate_carrier_routes_are_rejected() {
        let (_dir, id) = identity();
        let (_relay_dir, relay) = identity();
        let contact = create_at(&id, "machine-a", &[], 60, 100_000).unwrap();
        let mut signed: Signed = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(contact.link.strip_prefix(PREFIX).unwrap())
                .unwrap(),
        )
        .unwrap();
        signed.payload.relays = ["127.0.0.1", "127.0.0.2"]
            .map(|ip| format!("/ip4/{ip}/udp/4001/quic-v1/p2p/{}", relay.info().peer_id))
            .into();
        signed.signature = URL_SAFE_NO_PAD.encode(
            id.keypair()
                .sign(&signed_bytes(&signed.payload).unwrap())
                .unwrap(),
        );
        let error = verify(&encode(&signed), 100_000).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("one address per operator and carrier")
        );
        assert!(create_at(&id, "machine-a", &signed.payload.relays, 60, 100_000).is_err());
    }
}
