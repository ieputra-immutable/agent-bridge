//! Unauthenticated LAN connection hints. These records never grant peer trust.
use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

pub const MAX_DISCOVERED_PEERS: usize = 256;
pub const MAX_ADDRESSES_PER_PEER: usize = 4;
pub const DISCOVERY_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveredPeer {
    pub peer_id: String,
    pub addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_name: Option<String>,
}

pub struct DiscoveryCache {
    local_peer: PeerId,
    entries: BTreeMap<PeerId, BTreeMap<String, Instant>>,
    names: BTreeMap<PeerId, (String, Instant)>,
}

impl DiscoveryCache {
    pub fn new(local_peer: PeerId) -> Self {
        Self {
            local_peer,
            entries: BTreeMap::new(),
            names: BTreeMap::new(),
        }
    }

    pub fn observe(&mut self, peer: PeerId, address: &Multiaddr, now: Instant) -> bool {
        if peer == self.local_peer {
            return false;
        }
        let Some(address) = normalize_lan_address(peer, address) else {
            return false;
        };
        self.expire_due(now);
        if !self.entries.contains_key(&peer) && self.entries.len() >= MAX_DISCOVERED_PEERS {
            return false;
        }
        let addresses = self.entries.entry(peer).or_default();
        let address = address.to_string();
        if !addresses.contains_key(&address) && addresses.len() >= MAX_ADDRESSES_PER_PEER {
            return false;
        }
        addresses.insert(address, now + DISCOVERY_TTL);
        true
    }

    pub fn expire(&mut self, peer: PeerId, address: &Multiaddr) -> bool {
        let Some(address) = normalize_lan_address(peer, address) else {
            return false;
        };
        let Some(addresses) = self.entries.get_mut(&peer) else {
            return false;
        };
        let changed = addresses.remove(&address.to_string()).is_some();
        if addresses.is_empty() {
            self.entries.remove(&peer);
            self.names.remove(&peer);
        }
        changed
    }

    pub fn expire_due(&mut self, now: Instant) -> bool {
        let before: usize =
            self.entries.values().map(BTreeMap::len).sum::<usize>() + self.names.len();
        self.entries.retain(|_, addresses| {
            addresses.retain(|_, expires| *expires > now);
            !addresses.is_empty()
        });
        self.names
            .retain(|peer, (_, expires)| *expires > now && self.entries.contains_key(peer));
        before != self.entries.values().map(BTreeMap::len).sum::<usize>() + self.names.len()
    }

    /// A name may label only a currently observed address and never extends that address's TTL.
    pub fn set_name(
        &mut self,
        peer: PeerId,
        address: &Multiaddr,
        name: Option<&str>,
        now: Instant,
    ) -> bool {
        let Some(address) = normalize_lan_address(peer, address) else {
            return false;
        };
        if !self
            .entries
            .get(&peer)
            .and_then(|addresses| addresses.get(&address.to_string()))
            .is_some_and(|expires| *expires > now)
        {
            return false;
        }
        match name.filter(|name| super::machine::validate_name(name).is_ok()) {
            Some(name) => {
                self.names
                    .insert(peer, (name.to_owned(), now + DISCOVERY_TTL));
            }
            None => {
                self.names.remove(&peer);
            }
        }
        true
    }

    pub fn snapshot(&self) -> Vec<DiscoveredPeer> {
        self.entries
            .iter()
            .map(|(peer, addresses)| DiscoveredPeer {
                peer_id: peer.to_string(),
                addresses: addresses.keys().cloned().collect(),
                machine_name: self.names.get(peer).map(|(name, _)| name.clone()),
            })
            .collect()
    }
}

/// Only direct private/link-local IP QUIC hints are eligible for automatic LAN dialing.
/// A trailing peer component must agree with the advertised identity.
pub fn normalize_lan_address(peer: PeerId, address: &Multiaddr) -> Option<Multiaddr> {
    let mut parts = address.iter();
    match parts.next()? {
        Protocol::Ip4(ip) if ip.is_private() || ip.is_link_local() => {}
        Protocol::Ip6(ip) if ip.is_unique_local() || ip.is_unicast_link_local() => {}
        _ => return None,
    }
    if !matches!(parts.next(), Some(Protocol::Udp(port)) if port != 0) {
        return None;
    }
    if !matches!(parts.next(), Some(Protocol::QuicV1)) {
        return None;
    }
    match parts.next() {
        None => Some(address.clone()),
        Some(Protocol::P2p(id)) if id == peer && parts.next().is_none() => {
            let mut normalized = address.clone();
            normalized.pop();
            Some(normalized)
        }
        _ => None,
    }
}
