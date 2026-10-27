//! Owner-approved LAN verification using vodozemac's SAS primitives.
//!
//! The commitment/key ordering follows Matrix SAS verification (itself based on
//! ZRTP). This is an Agent Bridge protocol, not a Matrix wire implementation.
//! Numeric SAS values are strictly local: users compare them outside this channel.
//! All calls which change owner policy belong behind the private local socket.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use vodozemac::{
    Curve25519PublicKey,
    sas::{EstablishedSas, Mac, Sas},
};

const MAX_SESSIONS: usize = 8;
const MAX_FRAME: usize = 4096;
const DOMAIN: &str = "agent-bridge/lan-pairing/1";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    id: String,
    initiator: String,
    responder: String,
    issued_at: i64,
    expires_at: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Packet {
    Request { start: Start },
    Commitment { id: String, commitment: String },
    Key { id: String, key: String },
    Confirm { id: String, mac: String },
    Cancel { id: String },
}
impl Packet {
    fn id(&self) -> &str {
        match self {
            Self::Request { start } => &start.id,
            Self::Commitment { id, .. }
            | Self::Key { id, .. }
            | Self::Confirm { id, .. }
            | Self::Cancel { id } => id,
        }
    }
}
#[derive(Serialize)]
pub struct View {
    pub id: String,
    pub peer: String,
    pub role: &'static str,
    pub state: &'static str,
    pub expires_at: i64,
    pub verification_code: Option<String>,
    pub local_confirmed: bool,
    pub remote_confirmed: bool,
}
#[derive(Clone)]
pub struct Outgoing {
    pub id: String,
    pub peer: String,
    pub packet: Value,
}
pub struct Trusted {
    pub id: String,
    pub peer: String,
}
struct Session {
    start: Start,
    peer: String,
    initiator: bool,
    accepted: bool,
    sas: Option<Sas>,
    established: Option<EstablishedSas>,
    our_key: Option<String>,
    remote_key: Option<String>,
    commitment: Option<String>,
    code: Option<String>,
    info: Option<String>,
    local_confirmed: bool,
    remote_confirmed: bool,
    emitted: bool,
    paired: bool,
    cancelled: bool,
    deadline: Instant,
    outgoing: Option<Packet>,
}
impl Session {
    fn view(&self) -> View {
        View {
            id: self.start.id.clone(),
            peer: self.peer.clone(),
            role: if self.initiator {
                "initiator"
            } else {
                "responder"
            },
            state: if self.cancelled {
                "cancelled"
            } else if self.paired {
                "paired"
            } else if self.local_confirmed && self.remote_confirmed {
                "verified"
            } else if self.local_confirmed {
                "waiting_peer_confirmation"
            } else if self.code.is_some() {
                "compare_code"
            } else if !self.accepted {
                "awaiting_accept"
            } else {
                "exchanging_keys"
            },
            expires_at: self.start.expires_at,
            verification_code: if self.cancelled {
                None
            } else {
                self.code.clone()
            },
            local_confirmed: self.local_confirmed,
            remote_confirmed: self.remote_confirmed,
        }
    }
    fn active(&self, now: i64) -> bool {
        self.start.expires_at > now && Instant::now() < self.deadline
    }
    fn cancel(&mut self) {
        self.cancelled = true;
        self.sas = None;
        self.established = None;
        self.code = None;
        self.info = None;
        self.outgoing = Some(Packet::Cancel {
            id: self.start.id.clone(),
        });
    }
    fn establish(&mut self, key: String) -> Result<()> {
        canonical_key(&key)?;
        let sas = self
            .sas
            .take()
            .context("Pairing key was already consumed")?;
        let established = sas
            .diffie_hellman_with_raw(&key)
            .context("Invalid pairing key agreement")?;
        let ours = self
            .our_key
            .as_deref()
            .context("Missing local pairing key")?;
        let (initiator_key, responder_key) = if self.initiator {
            (ours, key.as_str())
        } else {
            (key.as_str(), ours)
        };
        let info =
            serde_json::to_string(&(DOMAIN, "sas", &self.start, initiator_key, responder_key))?;
        let (a, b, c) = established.bytes(&info).decimals();
        self.code = Some(format!("{a:04}-{b:04}-{c:04}"));
        self.info = Some(info);
        self.remote_key = Some(key);
        self.established = Some(established);
        Ok(())
    }
    fn confirm_packet(&self) -> Result<Packet> {
        let (role, own_peer) = if self.initiator {
            ("initiator", &self.start.initiator)
        } else {
            ("responder", &self.start.responder)
        };
        let mac = self
            .established
            .as_ref()
            .context("Pairing keys not established")?
            .calculate_mac(own_peer, &self.mac_info(role)?)
            .to_base64();
        Ok(Packet::Confirm {
            id: self.start.id.clone(),
            mac,
        })
    }
    fn mac_info(&self, role: &str) -> Result<String> {
        Ok(serde_json::to_string(&(
            DOMAIN,
            "identity-mac",
            role,
            self.info
                .as_deref()
                .context("Pairing keys not established")?,
        ))?)
    }
}

/// In-memory attempts never survive a restart. Trust is emitted only after local
/// owner confirmation and a valid MAC from the other confirmed owner.
pub struct Manager {
    local_peer: String,
    sessions: BTreeMap<String, Session>,
    accepting_until: i64,
    accepting_deadline: Option<Instant>,
    rate_start: Option<(i64, Instant, u32)>,
}
fn peer(value: &str) -> Result<()> {
    let parsed: libp2p_identity::PeerId = value.parse().context("Invalid pairing peer ID")?;
    ensure!(
        parsed.to_string() == value,
        "Pairing peer ID must be canonical"
    );
    Ok(())
}
fn lifetime(seconds: u64) -> Result<()> {
    ensure!(
        (30..=600).contains(&seconds),
        "Pairing lifetime must be 30–600 seconds"
    );
    Ok(())
}
fn canonical_key(key: &str) -> Result<()> {
    ensure!(key.len() == 43, "Invalid pairing public key size");
    let parsed = Curve25519PublicKey::from_base64(key).context("Invalid pairing public key")?;
    ensure!(
        parsed.to_base64() == key,
        "Pairing public key must be canonical"
    );
    Ok(())
}
fn commitment(key: &str, start: &Start) -> Result<String> {
    let mut h = Sha256::new();
    h.update(serde_json::to_vec(&(DOMAIN, "commitment", key, start))?);
    Ok(STANDARD_NO_PAD.encode(h.finalize()))
}
fn deadline(expires_at: i64, now: i64) -> Instant {
    Instant::now() + Duration::from_millis(expires_at.saturating_sub(now).clamp(0, 600000) as u64)
}
impl Manager {
    pub fn new(local_peer: &str) -> Result<Self> {
        peer(local_peer)?;
        Ok(Self {
            local_peer: local_peer.into(),
            sessions: BTreeMap::new(),
            accepting_until: 0,
            accepting_deadline: None,
            rate_start: None,
        })
    }
    fn prune(&mut self, now: i64) {
        self.sessions.retain(|_, s| s.active(now));
    }
    fn allow_attempt(&mut self, now: i64) -> Result<()> {
        let reset = self.rate_start.as_ref().is_none_or(|(at, instant, _)| {
            now.saturating_sub(*at) >= 60000 && instant.elapsed() >= Duration::from_secs(60)
        });
        if reset {
            self.rate_start = Some((now, Instant::now(), 0));
        }
        let (_, _, count) = self.rate_start.as_mut().unwrap();
        ensure!(
            *count < 8,
            "Pairing attempt rate limit reached; wait one minute"
        );
        *count += 1;
        Ok(())
    }
    pub fn open(&mut self, seconds: u64, now: i64) -> Result<()> {
        lifetime(seconds)?;
        ensure!(now >= 0, "Invalid local clock");
        self.accepting_until = now
            .checked_add(seconds as i64 * 1000)
            .context("Pairing time overflow")?;
        self.accepting_deadline = Some(Instant::now() + Duration::from_secs(seconds));
        Ok(())
    }
    pub fn close(&mut self) {
        self.accepting_until = 0;
        self.accepting_deadline = None;
        self.sessions.clear();
    }
    pub fn reset(&mut self) {
        self.close();
    }
    pub fn window_open(&mut self, now: i64) -> bool {
        self.prune(now);
        self.accepting(now) || self.sessions.values().any(|s| !s.cancelled)
    }
    fn accepting(&self, now: i64) -> bool {
        self.accepting_until > now && self.accepting_deadline.is_some_and(|d| Instant::now() < d)
    }
    pub fn start(&mut self, target: &str, seconds: u64, now: i64) -> Result<View> {
        peer(target)?;
        lifetime(seconds)?;
        ensure!(now >= 0, "Invalid local clock");
        ensure!(
            target != self.local_peer,
            "Cannot pair this bridge with itself"
        );
        self.prune(now);
        ensure!(
            self.sessions.len() < MAX_SESSIONS,
            "Pairing request capacity reached"
        );
        ensure!(
            !self
                .sessions
                .values()
                .any(|s| s.peer == target && !s.cancelled && !s.paired),
            "Pairing already pending for this peer"
        );
        self.allow_attempt(now)?;
        let start = Start {
            id: uuid::Uuid::new_v4().to_string(),
            initiator: self.local_peer.clone(),
            responder: target.into(),
            issued_at: now,
            expires_at: now
                .checked_add(seconds as i64 * 1000)
                .context("Pairing time overflow")?,
        };
        let view = Session {
            peer: target.into(),
            initiator: true,
            accepted: true,
            sas: None,
            established: None,
            our_key: None,
            remote_key: None,
            commitment: None,
            code: None,
            info: None,
            local_confirmed: false,
            remote_confirmed: false,
            emitted: false,
            paired: false,
            cancelled: false,
            deadline: deadline(start.expires_at, now),
            outgoing: Some(Packet::Request {
                start: start.clone(),
            }),
            start,
        };
        let result = view.view();
        self.sessions.insert(result.id.clone(), view);
        Ok(result)
    }
    pub fn list(&mut self, now: i64) -> Vec<View> {
        self.prune(now);
        self.sessions.values().map(Session::view).collect()
    }
    pub fn accept(&mut self, id: &str, now: i64) -> Result<View> {
        self.prune(now);
        let s = self
            .sessions
            .get_mut(id)
            .context("Unknown or expired pairing request")?;
        ensure!(!s.cancelled && !s.paired, "Pairing is no longer pending");
        ensure!(
            !s.initiator,
            "Only incoming pairing requests require acceptance"
        );
        if !s.accepted {
            let sas = Sas::new();
            let key = sas.public_key().to_base64();
            let c = commitment(&key, &s.start)?;
            s.sas = Some(sas);
            s.our_key = Some(key);
            s.commitment = Some(c.clone());
            s.accepted = true;
            s.outgoing = Some(Packet::Commitment {
                id: id.into(),
                commitment: c,
            });
        }
        Ok(s.view())
    }
    pub fn confirm(&mut self, id: &str, code: &str, now: i64) -> Result<View> {
        self.prune(now);
        let s = self
            .sessions
            .get_mut(id)
            .context("Unknown or expired pairing request")?;
        ensure!(!s.cancelled && !s.paired, "Pairing is no longer pending");
        let expected = s
            .code
            .as_deref()
            .context("Pairing verification code is not ready")?;
        if code != expected {
            s.cancel();
            bail!("Verification code does not match; pairing cancelled");
        }
        s.local_confirmed = true;
        // The responder keeps retransmitting its public key until a valid peer
        // MAC proves the initiator received it. Early local confirmation must
        // never replace the last key packet and strand the other endpoint.
        if s.initiator || s.remote_confirmed {
            s.outgoing = Some(s.confirm_packet()?);
        }
        Ok(s.view())
    }
    pub fn cancel(&mut self, id: &str, now: i64) -> Result<()> {
        self.prune(now);
        let s = self
            .sessions
            .get_mut(id)
            .context("Unknown or expired pairing request")?;
        ensure!(!s.paired, "Peer already paired; revoke it explicitly");
        s.cancel();
        Ok(())
    }
    /// Local revocation must invalidate even completed attempts to prevent stale
    /// queued confirmation packets from recreating trust.
    pub fn cancel_peer(&mut self, target: &str) {
        for s in self.sessions.values_mut().filter(|s| s.peer == target) {
            s.cancel();
        }
    }
    pub fn outgoing(&mut self, now: i64) -> Vec<Outgoing> {
        self.prune(now);
        self.sessions
            .values()
            .filter_map(|s| {
                s.outgoing.as_ref().map(|packet| Outgoing {
                    id: s.start.id.clone(),
                    peer: s.peer.clone(),
                    packet: serde_json::to_value(packet).expect("fixed pairing fields serialize"),
                })
            })
            .collect()
    }
    pub fn take_trusted(&mut self, now: i64) -> Vec<Trusted> {
        self.prune(now);
        let mut result = Vec::new();
        for s in self.sessions.values_mut() {
            if !s.cancelled && !s.emitted && s.local_confirmed && s.remote_confirmed {
                s.emitted = true;
                result.push(Trusted {
                    id: s.start.id.clone(),
                    peer: s.peer.clone(),
                });
            }
        }
        result
    }
    pub fn mark_paired(&mut self, id: &str) -> Result<()> {
        let s = self
            .sessions
            .get_mut(id)
            .context("Unknown pairing request")?;
        ensure!(
            !s.cancelled && s.emitted && s.local_confirmed && s.remote_confirmed,
            "Pairing has not been verified"
        );
        s.paired = true;
        Ok(())
    }
    pub fn receive(&mut self, remote: &str, value: Value, now: i64) -> Result<Value> {
        peer(remote)?;
        ensure!(
            remote != self.local_peer,
            "Cannot pair this bridge with itself"
        );
        ensure!(
            serde_json::to_vec(&value)?.len() <= MAX_FRAME,
            "Pairing frame too large"
        );
        let packet: Packet = serde_json::from_value(value).context("Invalid pairing packet")?;
        let id = packet.id().to_string();
        let parsed = uuid::Uuid::parse_str(&id).context("Invalid pairing transaction ID")?;
        ensure!(
            parsed.to_string() == id,
            "Pairing transaction ID must be canonical"
        );
        self.prune(now);
        if let Packet::Request { start } = &packet {
            peer(&start.initiator)?;
            peer(&start.responder)?;
            ensure!(
                start.initiator == remote && start.responder == self.local_peer,
                "Pairing request identity mismatch"
            );
            let duration = start
                .expires_at
                .checked_sub(start.issued_at)
                .context("Invalid pairing times")?;
            ensure!(
                start.issued_at >= 0
                    && now >= 0
                    && (30000..=600000).contains(&duration)
                    && start.issued_at <= now.saturating_add(30000)
                    && start.expires_at > now,
                "Pairing request expired or invalid clock"
            );
            if let Some(existing) = self.sessions.get(&id) {
                ensure!(
                    existing.peer == remote && existing.start == *start && !existing.cancelled,
                    "Conflicting or cancelled pairing request"
                );
                return Ok(json!({"ok":true}));
            }
            ensure!(self.accepting(now), "Pairing window is closed");
            ensure!(
                self.sessions.len() < MAX_SESSIONS,
                "Pairing request capacity reached"
            );
            ensure!(
                !self
                    .sessions
                    .values()
                    .any(|s| s.peer == remote && !s.cancelled && !s.paired),
                "Pairing already pending for this peer"
            );
            self.allow_attempt(now)?;
            self.sessions.insert(
                id,
                Session {
                    start: start.clone(),
                    peer: remote.into(),
                    initiator: false,
                    accepted: false,
                    sas: None,
                    established: None,
                    our_key: None,
                    remote_key: None,
                    commitment: None,
                    code: None,
                    info: None,
                    local_confirmed: false,
                    remote_confirmed: false,
                    emitted: false,
                    paired: false,
                    cancelled: false,
                    deadline: deadline(start.expires_at, now),
                    outgoing: None,
                },
            );
            return Ok(json!({"ok":true}));
        }
        let s = self
            .sessions
            .get_mut(&id)
            .context("Unknown or expired pairing request")?;
        ensure!(s.peer == remote, "Pairing response identity mismatch");
        ensure!(!s.cancelled, "Pairing request was cancelled");
        let result = Self::advance(s, packet);
        if result.is_err() && !s.paired {
            s.cancel();
        }
        result?;
        Ok(json!({"ok":true}))
    }
    fn advance(s: &mut Session, packet: Packet) -> Result<()> {
        let id = s.start.id.clone();
        match packet {
            Packet::Commitment { commitment: c, .. } => {
                ensure!(s.initiator && s.accepted, "Unexpected pairing commitment");
                ensure!(
                    c.len() == 43 && STANDARD_NO_PAD.decode(&c)?.len() == 32,
                    "Invalid pairing commitment"
                );
                if let Some(old) = &s.commitment {
                    ensure!(old == &c, "Pairing commitment changed");
                    return Ok(());
                }
                let sas = Sas::new();
                let key = sas.public_key().to_base64();
                s.sas = Some(sas);
                s.our_key = Some(key.clone());
                s.commitment = Some(c);
                s.outgoing = Some(Packet::Key { id, key });
            }
            Packet::Key { key, .. } => {
                ensure!(
                    s.accepted && s.commitment.is_some(),
                    "Pairing request has not been accepted"
                );
                canonical_key(&key)?;
                if let Some(old) = &s.remote_key {
                    ensure!(old == &key, "Pairing public key changed");
                    return Ok(());
                }
                if s.initiator {
                    ensure!(
                        s.commitment.as_deref() == Some(commitment(&key, &s.start)?.as_str()),
                        "Pairing commitment mismatch"
                    );
                }
                s.establish(key)?;
                if !s.initiator {
                    s.outgoing = Some(Packet::Key {
                        id,
                        key: s.our_key.clone().context("Missing local pairing key")?,
                    });
                }
            }
            Packet::Confirm { mac, .. } => {
                ensure!(mac.len() == 43, "Invalid pairing MAC size");
                let tag = Mac::from_base64(&mac).context("Invalid pairing MAC")?;
                ensure!(tag.to_base64() == mac, "Pairing MAC must be canonical");
                let role = if s.initiator {
                    "responder"
                } else {
                    "initiator"
                };
                s.established
                    .as_ref()
                    .context("Pairing keys not established")?
                    .verify_mac(&s.peer, &s.mac_info(role)?, &tag)
                    .context("Pairing confirmation MAC mismatch")?;
                s.remote_confirmed = true;
                if s.local_confirmed {
                    s.outgoing = Some(s.confirm_packet()?);
                }
            }
            Packet::Cancel { .. } => {
                ensure!(!s.paired, "Peer already paired; revoke it explicitly");
                s.cancel();
                s.outgoing = None;
            }
            Packet::Request { .. } => unreachable!(),
        }
        Ok(())
    }
}
