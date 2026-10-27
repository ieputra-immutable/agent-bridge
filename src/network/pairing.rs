//! Offline mutual pairing. Tokens and full fingerprints must use a trusted channel.
//! Joining trusts the issuer locally; the issuer trusts a responder only after finish.
use super::{identity::Identity, store::validate_address, trust::Peer};
use crate::db::{Db, now, pair_in_transaction};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use libp2p_identity::{KeyType, PublicKey};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::HashSet;

const MAX_TOKEN: usize = 16384;
const OFFER_DOMAIN: &[u8] = b"agent-bridge/mutual-pairing-offer/1\0";
const RESPONSE_DOMAIN: &[u8] = b"agent-bridge/mutual-pairing-response/1\0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OfferPayload {
    version: u32,
    peer_id: String,
    public_key: Vec<u8>,
    nonce: String,
    issued_at: i64,
    expires_at: i64,
    addresses: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponsePayload {
    version: u32,
    peer_id: String,
    public_key: Vec<u8>,
    offer: String,
    addresses: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed<T> {
    payload: T,
    signature: Vec<u8>,
}
#[derive(Serialize)]
pub struct PairingOffer {
    pub offer: String,
    pub nonce: String,
    pub fingerprint: String,
    pub expires_at: i64,
}
#[derive(Serialize)]
pub struct PairingJoined {
    pub response: String,
    pub fingerprint: String,
    pub peer: Peer,
    pub expires_at: i64,
}
fn bytes<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>> {
    let mut out = domain.to_vec();
    out.extend(serde_json::to_vec(value)?);
    Ok(out)
}
fn sign<T: Serialize>(identity: &Identity, domain: &[u8], payload: T) -> Result<String> {
    let signature = identity.keypair().sign(&bytes(domain, &payload)?)?;
    let token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Signed { payload, signature })?);
    ensure!(token.len() <= MAX_TOKEN, "Pairing token is too large");
    Ok(token)
}
fn decode<T: DeserializeOwned + Serialize>(token: &str) -> Result<Signed<T>> {
    ensure!(
        !token.is_empty() && token.len() <= MAX_TOKEN,
        "Invalid pairing token size"
    );
    let decoded = URL_SAFE_NO_PAD
        .decode(token)
        .context("Invalid pairing token encoding")?;
    ensure!(
        URL_SAFE_NO_PAD.encode(&decoded) == token,
        "Pairing encoding must be canonical"
    );
    let signed: Signed<T> = serde_json::from_slice(&decoded).context("Invalid pairing token")?;
    // Reject alternate JSON encodings as well as duplicate and unknown fields.
    ensure!(
        serde_json::to_vec(&signed)? == decoded,
        "Pairing JSON must be canonical"
    );
    Ok(signed)
}
fn verify<T: Serialize>(
    signed: &Signed<T>,
    domain: &[u8],
    peer: &str,
    public: &[u8],
) -> Result<()> {
    ensure!(
        public.len() <= 128 && signed.signature.len() == 64,
        "Invalid pairing key or signature size"
    );
    let key = PublicKey::try_decode_protobuf(public).context("Invalid pairing public key")?;
    ensure!(
        key.key_type() == KeyType::Ed25519 && key.encode_protobuf() == public,
        "Pairing requires canonical Ed25519 keys"
    );
    ensure!(
        key.to_peer_id().to_string() == peer,
        "Pairing public key does not match identity"
    );
    ensure!(
        key.verify(&bytes(domain, &signed.payload)?, &signed.signature),
        "Invalid pairing signature"
    );
    Ok(())
}
fn addresses(values: &[String]) -> Result<()> {
    ensure!(values.len() <= 4, "Pairing allows at most four addresses");
    let mut seen = HashSet::new();
    for value in values {
        ensure!(value.len() <= 256, "Pairing address is too long");
        validate_address(value, false)?;
        ensure!(seen.insert(value), "Duplicate pairing address");
    }
    Ok(())
}
fn offer(token: &str, at: i64) -> Result<OfferPayload> {
    let signed: Signed<OfferPayload> = decode(token)?;
    let value = &signed.payload;
    ensure!(value.version == 1, "Unsupported pairing offer version");
    verify(&signed, OFFER_DOMAIN, &value.peer_id, &value.public_key)?;
    let duration = value
        .expires_at
        .checked_sub(value.issued_at)
        .context("Invalid pairing times")?;
    ensure!(
        (30000..=600000).contains(&duration) && value.issued_at >= 0 && at >= 0,
        "Invalid pairing lifetime"
    );
    ensure!(
        value.issued_at <= at.saturating_add(30000),
        "Pairing offer is from the future; check clocks"
    );
    ensure!(value.expires_at > at, "Pairing offer expired");
    let nonce = uuid::Uuid::parse_str(&value.nonce).context("Invalid pairing nonce")?;
    ensure!(
        nonce.to_string() == value.nonce,
        "Pairing nonce must be canonical"
    );
    addresses(&value.addresses)?;
    Ok(signed.payload)
}
fn import_address(tx: &Transaction<'_>, peer: &str, values: &[String]) -> Result<()> {
    if let Some(address) = values.first() {
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM peer_addresses WHERE peer_id=?)",
            [peer],
            |r| r.get(0),
        )?;
        let count: i64 = tx.query_row("SELECT count(*) FROM peer_addresses", [], |r| r.get(0))?;
        ensure!(
            exists || count < 64,
            "At most 64 explicit peers may have addresses"
        );
        tx.execute("INSERT INTO peer_addresses(peer_id,address) VALUES(?,?) ON CONFLICT(peer_id) DO NOTHING", params![peer,address])?;
    }
    Ok(())
}
impl Db {
    pub fn pairing_offer(
        &mut self,
        identity: &Identity,
        hints: &[String],
        seconds: u64,
    ) -> Result<PairingOffer> {
        ensure!(
            (30..=600).contains(&seconds),
            "Pairing lifetime must be 30–600 seconds"
        );
        addresses(hints)?;
        let at = now();
        ensure!(at >= 0, "Invalid local clock");
        let expires_at = at
            .checked_add(seconds as i64 * 1000)
            .context("Pairing time overflow")?;
        let nonce = uuid::Uuid::new_v4().to_string();
        let fingerprint = identity.info().fingerprint;
        let token = sign(
            identity,
            OFFER_DOMAIN,
            OfferPayload {
                version: 1,
                peer_id: fingerprint.clone(),
                public_key: identity.keypair().public().encode_protobuf(),
                nonce: nonce.clone(),
                issued_at: at,
                expires_at,
                addresses: hints.to_vec(),
            },
        )?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM pairing_offers WHERE expires_at<=?", [at])?;
        let count: i64 = tx.query_row("SELECT count(*) FROM pairing_offers", [], |r| r.get(0))?;
        ensure!(
            count < 1024,
            "Too many pending pairing offers; cancel one or wait for expiry"
        );
        tx.execute(
            "INSERT INTO pairing_offers VALUES(?,?,?)",
            params![nonce, token, expires_at],
        )?;
        tx.commit()?;
        Ok(PairingOffer {
            offer: token,
            nonce,
            fingerprint,
            expires_at,
        })
    }
    /// Local trust is established here; completion on the issuer still requires finish.
    pub fn pairing_join(
        &mut self,
        identity: &Identity,
        token: &str,
        expected: &str,
        alias: Option<&str>,
        hints: &[String],
    ) -> Result<PairingJoined> {
        let value = offer(token, now())?;
        ensure!(
            value.peer_id == expected,
            "Fingerprint does not match pairing issuer"
        );
        let fingerprint = identity.info().fingerprint;
        ensure!(
            value.peer_id != fingerprint,
            "Cannot pair this bridge with itself"
        );
        addresses(hints)?;
        let response = sign(
            identity,
            RESPONSE_DOMAIN,
            ResponsePayload {
                version: 1,
                peer_id: fingerprint.clone(),
                public_key: identity.keypair().public().encode_protobuf(),
                offer: token.into(),
                addresses: hints.to_vec(),
            },
        )?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let at = now();
        ensure!(value.expires_at > at, "Pairing offer expired");
        tx.execute("DELETE FROM pairing_joined WHERE expires_at<=?", [at])?;
        let previous: Option<(String, String, String)> = tx
            .query_row(
                "SELECT local_peer,offer,response FROM pairing_joined WHERE peer_id=? AND nonce=?",
                params![value.peer_id, value.nonce],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((local_peer, original_offer, response)) = previous {
            ensure!(
                local_peer == fingerprint && original_offer == token,
                "Conflicting pairing offer replay"
            );
            let current: Option<(bool, Option<String>)> = tx
                .query_row(
                    "SELECT revoked,alias FROM peers WHERE peer_id=?",
                    [&value.peer_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (revoked, existing_alias) = current.context("Pairing trust no longer exists")?;
            ensure!(!revoked, "Pairing peer was revoked; create a fresh offer");
            ensure!(
                alias.is_none() || alias == existing_alias.as_deref(),
                "Retry cannot change pairing alias"
            );
            tx.commit()?;
            return Ok(PairingJoined {
                response,
                fingerprint,
                peer: self.peer(&value.peer_id)?,
                expires_at: value.expires_at,
            });
        }
        let count: i64 = tx.query_row("SELECT count(*) FROM pairing_joined", [], |r| r.get(0))?;
        ensure!(
            count < 1024,
            "Too many active pairing records; wait for expiry"
        );
        pair_in_transaction(&tx, &value.peer_id, expected, alias)?;
        import_address(&tx, &value.peer_id, &value.addresses)?;
        tx.execute(
            "INSERT INTO pairing_joined VALUES(?,?,?,?,?,?)",
            params![
                value.peer_id,
                value.nonce,
                value.expires_at,
                fingerprint,
                token,
                response
            ],
        )?;
        tx.commit()?;
        Ok(PairingJoined {
            response,
            fingerprint,
            peer: self.peer(&value.peer_id)?,
            expires_at: value.expires_at,
        })
    }
    pub fn pairing_finish(
        &mut self,
        identity: &Identity,
        token: &str,
        expected: &str,
        alias: Option<&str>,
    ) -> Result<Peer> {
        let signed: Signed<ResponsePayload> = decode(token)?;
        let response = &signed.payload;
        ensure!(
            response.version == 1,
            "Unsupported pairing response version"
        );
        ensure!(
            response.peer_id == expected,
            "Fingerprint does not match pairing responder"
        );
        verify(
            &signed,
            RESPONSE_DOMAIN,
            &response.peer_id,
            &response.public_key,
        )?;
        addresses(&response.addresses)?;
        let value = offer(&response.offer, now())?;
        let local = identity.info().peer_id;
        ensure!(
            value.peer_id == local,
            "Pairing offer belongs to another issuer"
        );
        ensure!(
            response.peer_id != local,
            "Cannot pair this bridge with itself"
        );
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure!(value.expires_at > now(), "Pairing offer expired");
        let pending: Option<String> = tx
            .query_row(
                "SELECT offer FROM pairing_offers WHERE nonce=? AND expires_at>?",
                params![value.nonce, now()],
                |r| r.get(0),
            )
            .optional()?;
        ensure!(
            pending.as_deref() == Some(response.offer.as_str()),
            "Pairing offer is unknown, cancelled, expired or already completed"
        );
        pair_in_transaction(&tx, &response.peer_id, expected, alias)?;
        import_address(&tx, &response.peer_id, &response.addresses)?;
        tx.execute("DELETE FROM pairing_offers WHERE nonce=?", [&value.nonce])?;
        tx.commit()?;
        self.peer(&response.peer_id)
    }
    pub fn pairing_cancel(&mut self, nonce: &str) -> Result<()> {
        let parsed = uuid::Uuid::parse_str(nonce).context("Invalid pairing nonce")?;
        ensure!(
            parsed.to_string() == nonce,
            "Pairing nonce must be canonical"
        );
        ensure!(
            self.conn
                .execute("DELETE FROM pairing_offers WHERE nonce=?", [nonce])?
                == 1,
            "Unknown or already completed pairing offer"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    fn identity() -> (tempfile::TempDir, Identity) {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let id = Identity::load_or_create(dir.path()).unwrap();
        (dir, id)
    }
    #[test]
    fn offer_clock_boundaries_signature_and_canonical_json_are_enforced() {
        let (_dir, id) = identity();
        let at = 100000;
        let payload = OfferPayload {
            version: 1,
            peer_id: id.info().peer_id,
            public_key: id.keypair().public().encode_protobuf(),
            nonce: uuid::Uuid::new_v4().to_string(),
            issued_at: at,
            expires_at: at + 30000,
            addresses: vec![],
        };
        let token = sign(&id, OFFER_DOMAIN, payload).unwrap();
        assert!(offer(&token, at).is_ok());
        assert!(offer(&token, at + 29999).is_ok());
        assert!(offer(&token, at + 30000).is_err());
        assert!(offer(&token, at - 30001).is_err());
        let mut signed: Signed<OfferPayload> = decode(&token).unwrap();
        signed.payload.expires_at += 1;
        let forged = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&signed).unwrap());
        assert!(offer(&forged, at).is_err());
        let (_other_dir, other) = identity();
        signed.signature = other
            .keypair()
            .sign(&bytes(OFFER_DOMAIN, &signed.payload).unwrap())
            .unwrap();
        let forged = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&signed).unwrap());
        assert!(offer(&forged, at).is_err());
        let decoded = URL_SAFE_NO_PAD.decode(&token).unwrap();
        let pretty: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        let alternate = URL_SAFE_NO_PAD.encode(serde_json::to_vec_pretty(&pretty).unwrap());
        assert!(offer(&alternate, at).is_err());
    }
    #[test]
    fn response_signature_binds_exact_offer_recipient_and_hints() {
        let (dir, id) = identity();
        let (_other_dir, other) = identity();
        let mut db = Db::open(&dir.path().join("db")).unwrap();
        let offer = db.pairing_offer(&id, &[], 60).unwrap();
        let response = sign(
            &other,
            RESPONSE_DOMAIN,
            ResponsePayload {
                version: 1,
                peer_id: other.info().peer_id,
                public_key: other.keypair().public().encode_protobuf(),
                offer: offer.offer,
                addresses: vec![],
            },
        )
        .unwrap();
        let mut signed: Signed<ResponsePayload> = decode(&response).unwrap();
        signed
            .payload
            .addresses
            .push("/ip4/192.168.1.1/udp/4000/quic-v1".into());
        let forged = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&signed).unwrap());
        assert!(
            db.pairing_finish(&id, &forged, &other.info().fingerprint, None)
                .is_err()
        );
        assert!(db.peers().unwrap().is_empty());
        db.pairing_finish(&id, &response, &other.info().fingerprint, None)
            .unwrap();
    }
}
