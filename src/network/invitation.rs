//! Locally exchanged invitations prove key ownership; owners still verify fingerprints.
use super::{identity::Identity, store::validate_address};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use libp2p_identity::{KeyType, PublicKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const MAX_TOKEN_BYTES: usize = 8192;
const DOMAIN: &[u8] = b"agent-bridge/pairing-invitation/1\0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    version: u32,
    peer_id: String,
    public_key: Vec<u8>,
    issued_at: i64,
    expires_at: i64,
    nonce: String,
    addresses: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedInvitation {
    payload: Payload,
    signature: Vec<u8>,
}

pub struct VerifiedInvitation {
    pub peer_id: String,
    pub nonce: String,
    pub expires_at: i64,
    pub addresses: Vec<String>,
}

fn signed_bytes(payload: &Payload) -> Result<Vec<u8>> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(serde_json::to_vec(payload)?);
    Ok(bytes)
}

fn validate_addresses(addresses: &[String]) -> Result<()> {
    ensure!(
        addresses.len() <= 4,
        "Invitations allow at most four addresses"
    );
    let mut unique = HashSet::new();
    for address in addresses {
        ensure!(address.len() <= 256, "Invitation address is too long");
        validate_address(address, false)?;
        ensure!(unique.insert(address), "Duplicate invitation address");
    }
    Ok(())
}

pub fn create(identity: &Identity, addresses: &[String], seconds: u64) -> Result<String> {
    create_at(identity, addresses, seconds, crate::db::now())
}

fn create_at(identity: &Identity, addresses: &[String], seconds: u64, now: i64) -> Result<String> {
    ensure!(
        (30..=600).contains(&seconds),
        "Invitation lifetime must be 30–600 seconds"
    );
    ensure!(now >= 0, "Invalid local clock");
    validate_addresses(addresses)?;
    let keypair = identity.keypair();
    let payload = Payload {
        version: 1,
        peer_id: identity.info().peer_id,
        public_key: keypair.public().encode_protobuf(),
        issued_at: now,
        expires_at: now
            .checked_add(seconds as i64 * 1000)
            .context("Invitation time overflow")?,
        nonce: uuid::Uuid::new_v4().to_string(),
        addresses: addresses.to_vec(),
    };
    let signature = keypair
        .sign(&signed_bytes(&payload)?)
        .context("Could not sign invitation")?;
    let token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&SignedInvitation {
        payload,
        signature,
    })?);
    ensure!(token.len() <= MAX_TOKEN_BYTES, "Invitation is too large");
    Ok(token)
}

pub fn verify(token: &str, fingerprint: &str) -> Result<VerifiedInvitation> {
    verify_at(token, fingerprint, crate::db::now())
}

fn verify_at(token: &str, fingerprint: &str, now: i64) -> Result<VerifiedInvitation> {
    ensure!(
        !token.is_empty() && token.len() <= MAX_TOKEN_BYTES,
        "Invalid invitation size"
    );
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .context("Invalid invitation encoding")?;
    ensure!(
        URL_SAFE_NO_PAD.encode(&bytes) == token,
        "Invitation encoding must be canonical"
    );
    let invitation: SignedInvitation =
        serde_json::from_slice(&bytes).context("Invalid invitation format")?;
    let payload = &invitation.payload;
    ensure!(payload.version == 1, "Unsupported invitation version");
    ensure!(
        payload.peer_id == fingerprint,
        "Fingerprint does not match invitation identity"
    );
    ensure!(
        payload.public_key.len() <= 128 && invitation.signature.len() == 64,
        "Invalid invitation key or signature size"
    );
    let key = PublicKey::try_decode_protobuf(&payload.public_key)
        .context("Invalid invitation public key")?;
    ensure!(
        key.key_type() == KeyType::Ed25519 && key.encode_protobuf() == payload.public_key,
        "Invitation requires a canonical Ed25519 public key"
    );
    ensure!(
        key.to_peer_id().to_string() == payload.peer_id,
        "Invitation public key does not match peer identity"
    );
    ensure!(
        key.verify(&signed_bytes(payload)?, &invitation.signature),
        "Invalid invitation signature"
    );
    let duration = payload
        .expires_at
        .checked_sub(payload.issued_at)
        .context("Invalid invitation times")?;
    ensure!(
        (30_000..=600_000).contains(&duration) && payload.issued_at >= 0 && now >= 0,
        "Invalid invitation lifetime"
    );
    ensure!(
        payload.issued_at <= now.saturating_add(30_000),
        "Invitation was issued in the future; check clocks"
    );
    ensure!(payload.expires_at > now, "Invitation expired");
    let nonce = uuid::Uuid::parse_str(&payload.nonce).context("Invalid invitation nonce")?;
    ensure!(
        nonce.to_string() == payload.nonce,
        "Invitation nonce must be canonical"
    );
    validate_addresses(&payload.addresses)?;
    Ok(VerifiedInvitation {
        peer_id: payload.peer_id.clone(),
        nonce: payload.nonce.clone(),
        expires_at: payload.expires_at,
        addresses: payload.addresses.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    fn identity() -> (tempfile::TempDir, Identity) {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let identity = Identity::load_or_create(dir.path()).unwrap();
        (dir, identity)
    }

    #[test]
    fn signed_invitation_checks_expiry_future_clock_and_lifetime() {
        let (_dir, identity) = identity();
        let fingerprint = identity.info().fingerprint;
        let token = create_at(&identity, &[], 30, 100_000).unwrap();
        assert!(verify_at(&token, &fingerprint, 100_000).is_ok());
        assert!(verify_at(&token, &fingerprint, 129_999).is_ok());
        assert!(verify_at(&token, &fingerprint, 130_000).is_err());
        assert!(verify_at(&token, &fingerprint, 69_999).is_err());
        assert!(create_at(&identity, &[], 29, 100_000).is_err());
        assert!(create_at(&identity, &[], 601, 100_000).is_err());
    }

    #[test]
    fn tampering_wrong_key_fingerprint_version_and_oversized_tokens_fail() {
        let (_dir, identity) = identity();
        let fingerprint = identity.info().fingerprint;
        let token = create_at(&identity, &[], 60, 100_000).unwrap();
        assert!(verify_at(&token, "wrong fingerprint", 100_000).is_err());
        let original = URL_SAFE_NO_PAD.decode(&token).unwrap();
        for field in [
            "peer_id",
            "public_key",
            "issued_at",
            "expires_at",
            "nonce",
            "addresses",
            "version",
            "signature",
        ] {
            let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
            match field {
                "peer_id" => value["payload"][field] = "fake".into(),
                "public_key" => value["payload"][field] = serde_json::json!(vec![0u8; 64]),
                "issued_at" => value["payload"][field] = 99_999.into(),
                "expires_at" => value["payload"][field] = 161_000.into(),
                "nonce" => value["payload"][field] = uuid::Uuid::new_v4().to_string().into(),
                "addresses" => {
                    value["payload"][field] =
                        serde_json::json!(["/ip4/192.168.1.1/udp/4000/quic-v1"])
                }
                "version" => value["payload"][field] = 2.into(),
                "signature" => value[field] = serde_json::json!(vec![0u8; 64]),
                _ => unreachable!(),
            }
            let changed = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap());
            assert!(
                verify_at(&changed, &fingerprint, 100_000).is_err(),
                "accepted changed {field}"
            );
        }
        assert!(verify_at(&"x".repeat(MAX_TOKEN_BYTES + 1), &fingerprint, 100_000).is_err());
    }

    #[test]
    fn another_key_cannot_sign_for_the_verified_peer_identity() {
        let (_first_dir, first) = identity();
        let (_other_dir, other) = identity();
        let fingerprint = first.info().fingerprint;
        let token = create_at(&first, &[], 60, 100_000).unwrap();
        let mut invitation: SignedInvitation =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token).unwrap()).unwrap();
        let key = other.keypair();
        invitation.payload.public_key = key.public().encode_protobuf();
        invitation.signature = key
            .sign(&signed_bytes(&invitation.payload).unwrap())
            .unwrap();
        let forged = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&invitation).unwrap());
        assert!(verify_at(&forged, &fingerprint, 100_000).is_err());
    }
}
