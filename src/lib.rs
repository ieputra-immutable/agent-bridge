pub mod board;
mod board_clipboard;
pub mod board_interaction;
mod board_notifications;
mod board_selection;
pub mod board_tui;
pub mod broker;
pub mod claude_discovery;
pub mod db;
pub mod delivery;
pub mod discovery;
pub mod hook;
pub mod mcp;
pub mod migrations;
pub mod network;
pub mod protocol;
pub mod service;

pub mod monitor;
mod monitor_data;

mod codex_queue;
mod pairing_notifications;

/// Application version selected by the release tag or packaged source metadata.
pub const VERSION: &str = env!("AGENT_BRIDGE_VERSION");

/// Source revision provided by the release build workflow.
pub const BUILD_COMMIT: Option<&str> = option_env!("AGENT_BRIDGE_BUILD_COMMIT");
