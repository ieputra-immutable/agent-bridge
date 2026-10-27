//! Explicit infrastructure configuration and strictly scoped rendezvous routes.
use crate::db::Db;
use anyhow::{Context, Result, ensure};
use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const MAX_RELAYS: usize = 4;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayNode {
    pub peer_id: String,
    pub address: String,
}

/// DNS names are locations, never identities. Keep ASCII canonical hostnames bounded.
pub fn valid_dns(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.is_ascii()
        && name == name.to_ascii_lowercase()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Accepted direct contacts/listeners: canonical IP/DNS, QUIC or encrypted TCP.
pub fn validate_direct(address: &str, listening: bool) -> Result<Multiaddr> {
    ensure!(address.len() <= 512, "Contact address too long");
    let parsed: Multiaddr = address.parse().context("Invalid direct multiaddress")?;
    ensure!(parsed.to_string() == address, "Address must be canonical");
    let mut parts = parsed.iter();
    match parts.next() {
        Some(Protocol::Ip4(ip)) => ensure!(
            !ip.is_multicast() && (listening || !ip.is_unspecified()),
            "Invalid contact IP"
        ),
        Some(Protocol::Ip6(ip)) => ensure!(
            !ip.is_multicast() && (listening || !ip.is_unspecified()),
            "Invalid contact IP"
        ),
        Some(Protocol::Dns(name) | Protocol::Dns4(name) | Protocol::Dns6(name)) => ensure!(
            !listening && valid_dns(&name),
            "Use a canonical DNS name for dialing, a concrete IP for listening"
        ),
        _ => anyhow::bail!("Use an IP or DNS contact location"),
    }
    match parts.next() {
        Some(Protocol::Udp(port)) => ensure!(
            (listening || port != 0) && matches!(parts.next(), Some(Protocol::QuicV1)),
            "QUIC requires a UDP port and quic-v1"
        ),
        Some(Protocol::Tcp(port)) => ensure!(listening || port != 0, "TCP requires a nonzero port"),
        _ => anyhow::bail!("Use UDP/QUIC or TCP transport"),
    }
    ensure!(
        parts.next().is_none(),
        "Unexpected contact address components"
    );
    Ok(parsed)
}
pub fn carrier(address: &str) -> Result<&'static str> {
    let parsed: Multiaddr = address.parse()?;
    if parsed.iter().any(|p| matches!(p, Protocol::Tcp(_))) {
        Ok("tcp")
    } else if parsed.iter().any(|p| matches!(p, Protocol::QuicV1)) {
        Ok("quic")
    } else {
        anyhow::bail!("Unknown transport")
    }
}

/// Infrastructure addresses always pin their cryptographic operator identity.
pub fn validate_relay(address: &str) -> Result<RelayNode> {
    ensure!(address.len() <= 512, "Relay address too long");
    let mut parsed: Multiaddr = address.parse().context("Invalid relay multiaddress")?;
    ensure!(
        parsed.to_string() == address,
        "Relay address must be canonical"
    );
    let Some(Protocol::P2p(id)) = parsed.pop() else {
        anyhow::bail!("Relay address must pin its /p2p/PEER_ID");
    };
    validate_direct(&parsed.to_string(), false)?;
    Ok(RelayNode {
        peer_id: id.to_string(),
        address: address.into(),
    })
}

/// A circuit pins both the infrastructure key and the final endpoint key.
pub fn validate_circuit(address: &str, target: Option<&str>) -> Result<Multiaddr> {
    ensure!(address.len() <= 768, "Circuit address too long");
    let parsed: Multiaddr = address.parse().context("Invalid circuit address")?;
    ensure!(
        parsed.to_string() == address,
        "Circuit address must be canonical"
    );
    let mut base = parsed.clone();
    let Some(Protocol::P2p(endpoint)) = base.pop() else {
        anyhow::bail!("Circuit must pin its final endpoint");
    };
    ensure!(
        matches!(base.pop(), Some(Protocol::P2pCircuit)),
        "Expected p2p-circuit"
    );
    let relay = validate_relay(&base.to_string())?;
    ensure!(
        relay.peer_id != endpoint.to_string(),
        "Relay cannot be its own endpoint"
    );
    if let Some(target) = target {
        ensure!(
            endpoint.to_string() == target,
            "Circuit endpoint does not match peer"
        );
    }
    Ok(parsed)
}

/// Parse an address-only contact without resolving or trusting its hostname.
/// Bare host:port and tcp:// default to TCP; quic:// explicitly selects QUIC.
pub fn contact_location(location: &str) -> Result<Multiaddr> {
    if location.starts_with('/') {
        return validate_direct(location, false);
    }
    ensure!(
        location.len() <= 512 && !location.chars().any(char::is_whitespace),
        "Invalid contact location"
    );
    let (transport, hostport) = if let Some(v) = location.strip_prefix("tcp://") {
        ("tcp", v)
    } else if let Some(v) = location.strip_prefix("quic://") {
        ("quic", v)
    } else {
        ("tcp", location)
    };
    ensure!(
        !hostport.contains(['/', '@', '?', '#', '%']),
        "Use only host:port, without credentials, paths or URL fields"
    );
    let (host, port) = if let Some(v) = hostport.strip_prefix('[') {
        let (host, port) = v.split_once("]:").context("Use [IPv6]:PORT")?;
        (host, port)
    } else {
        hostport
            .rsplit_once(':')
            .context("Contact requires a port")?
    };
    let port: u16 = port.parse().context("Invalid contact port")?;
    ensure!(port != 0, "Contact requires a nonzero port");
    let host = match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => format!("/ip4/{ip}"),
        Ok(std::net::IpAddr::V6(ip)) => format!("/ip6/{ip}"),
        Err(_) => {
            ensure!(valid_dns(host), "Use a canonical ASCII DNS hostname");
            format!("/dns/{host}")
        }
    };
    validate_direct(
        &if transport == "tcp" {
            format!("{host}/tcp/{port}")
        } else {
            format!("{host}/udp/{port}/quic-v1")
        },
        false,
    )
}

/// Manual circuit hints also require an explicitly configured infrastructure operator.
pub fn configured_circuit(address: &str, target: &str, relays: &[RelayNode]) -> Result<Multiaddr> {
    let route = validate_circuit(address, Some(target))?;
    ensure!(
        relays
            .iter()
            .any(|relay| address == format!("{}/p2p-circuit/p2p/{target}", relay.address)),
        "Circuit requires an explicitly configured relay operator"
    );
    Ok(route)
}

/// Rendezvous may supply hints, never authority or arbitrary direct dial targets.
pub fn rendezvous_routes(
    records: &Value,
    relays: &[RelayNode],
    local: &str,
) -> BTreeMap<String, Vec<Multiaddr>> {
    let mut routes = BTreeMap::new();
    for record in records.as_array().into_iter().flatten().take(256) {
        let Some(target) = record["peer_id"].as_str() else {
            continue;
        };
        let Ok(id) = target.parse::<PeerId>() else {
            continue;
        };
        if id.to_string() != target || target == local || relays.iter().any(|r| r.peer_id == target)
        {
            continue;
        }
        for address in record["addresses"]
            .as_array()
            .into_iter()
            .flatten()
            .take(8)
            .filter_map(Value::as_str)
        {
            let Ok(address) = validate_circuit(address, Some(target)) else {
                continue;
            };
            if !relays.iter().any(|relay| {
                address.to_string() == format!("{}/p2p-circuit/p2p/{target}", relay.address)
            }) {
                continue;
            }
            let candidates: &mut Vec<Multiaddr> = routes.entry(target.to_owned()).or_default();
            if candidates.len() < MAX_RELAYS * 2 && !candidates.contains(&address) {
                candidates.push(address);
            }
        }
    }
    routes
}

impl Db {
    pub fn relay_nodes(&self) -> Result<Vec<RelayNode>> {
        let mut statement = self
            .conn
            .prepare("SELECT peer_id,address FROM relay_nodes ORDER BY peer_id,transport")?;
        Ok(statement
            .query_map([], |row| {
                Ok(RelayNode {
                    peer_id: row.get(0)?,
                    address: row.get(1)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?)
    }
    pub fn add_relay(&mut self, address: &str) -> Result<Vec<RelayNode>> {
        self.add_relays(&[address.to_string()])
    }
    /// Atomic explicit adoption of contact infrastructure; no trust/grants/networkenable.
    pub fn add_relays(&mut self, addresses: &[String]) -> Result<Vec<RelayNode>> {
        ensure!(
            addresses.len() <= 8,
            "At most eight relay routes may be supplied"
        );
        let nodes: Vec<_> = addresses
            .iter()
            .map(|a| validate_relay(a))
            .collect::<Result<_>>()?;
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        for node in nodes {
            tx.execute("INSERT INTO relay_nodes(peer_id,transport,address) VALUES(?,?,?) ON CONFLICT(peer_id,transport) DO UPDATE SET address=excluded.address",params![node.peer_id,carrier(&node.address)?,node.address])?;
        }
        let count: i64 =
            tx.query_row("SELECT count(DISTINCT peer_id) FROM relay_nodes", [], |r| {
                r.get(0)
            })?;
        ensure!(
            count <= MAX_RELAYS as i64,
            "At most four independent relays may be configured"
        );
        tx.commit()?;
        self.relay_nodes()
    }
    pub fn pair_peer_contact(
        &mut self,
        peer: &str,
        address: &str,
    ) -> Result<crate::network::trust::Peer> {
        validate_direct(address, false)?;
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        crate::db::pair_in_transaction(&tx, peer, peer, None)?;
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
        tx.execute("INSERT INTO peer_addresses(peer_id,address) VALUES(?,?) ON CONFLICT(peer_id) DO NOTHING",params![peer,address])?;
        tx.commit()?;
        self.peer(peer)
    }
    pub fn remove_relay(&mut self, peer: &str) -> Result<Vec<RelayNode>> {
        let id: PeerId = peer.parse().context("Invalid relay peer ID")?;
        ensure!(id.to_string() == peer, "Relay peer ID must be canonical");
        ensure!(
            self.conn
                .execute("DELETE FROM relay_nodes WHERE peer_id=?", [peer])?
                != 0,
            "Relay is not configured"
        );
        self.relay_nodes()
    }
}
