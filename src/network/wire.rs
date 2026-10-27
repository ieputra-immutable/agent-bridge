//! Network messages are deliberately separate from the privileged local Request API.
use crate::protocol::Provider;
use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 1;
pub const PAGE_SIZE: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteAgent {
    pub name: String,
    pub provider: Provider,
    pub session: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub peer_id: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub origin_peer: String,
    pub id: String,
    pub source: RemoteAgent,
    pub destination_peer: String,
    pub destination: RemoteAgent,
    pub body: String,
    pub parent: Option<Reference>,
    pub hops: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    /// Optional metadata exchange. Older peers can refuse it without affecting messaging.
    Hello {
        machine_name: String,
    },
    Directory,
    Send {
        envelope: Box<Envelope>,
    },
    Sync {
        after: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireRequest {
    pub version: u32,
    pub operation: Operation,
}

impl WireRequest {
    pub fn new(operation: Operation) -> Self {
        Self {
            version: VERSION,
            operation,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusEvent {
    pub sequence: u64,
    pub id: String,
    pub state: String,
    pub detail: Option<String>,
    pub updated: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireResponse {
    Hello { machine_name: String },
    Directory { agents: Vec<RemoteAgent> },
    Accepted { id: String },
    Status { events: Vec<StatusEvent> },
    Rejected { reason: String, retryable: bool },
}
