//! Local, directional permissions. A trusted bridge vouches for its source agents.
use crate::protocol::Provider;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Discover,
    Send,
    Receive,
}

impl Permission {
    pub fn label(self) -> &'static str {
        match self {
            Self::Discover => "discover",
            Self::Send => "send",
            Self::Receive => "receive",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub provider: Provider,
    pub session: String,
    pub permission: Permission,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub peer_id: String,
    pub alias: Option<String>,
    pub machine_name: Option<String>,
    pub display_name: String,
    pub revoked: bool,
    pub grants: Vec<Grant>,
}
