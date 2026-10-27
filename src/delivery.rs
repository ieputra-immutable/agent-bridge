use crate::protocol::{Agent, Message, Provider};
use anyhow::{Context, Result, ensure};
use serde_json::json;
use std::{
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{io::AsyncWriteExt, net::UnixStream, time::timeout};

pub fn validate_socket(path: &Path) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "Socket path must be absolute");
    let meta = std::fs::symlink_metadata(path)
        .context("Cannot inspect Claude socket; register a running native session")?;
    ensure!(
        meta.file_type().is_socket(),
        "Endpoint must be a Unix socket, not a symlink or regular file"
    );
    ensure!(
        meta.uid() == unsafe { libc::geteuid() },
        "Socket belongs to another user"
    );
    ensure!(
        meta.mode() & 0o077 == 0,
        "Socket must be accessible only to its owner"
    );
    let parent = path
        .parent()
        .context("Missing socket directory")?
        .canonicalize()?;
    let dir = std::fs::metadata(&parent)?;
    ensure!(
        dir.uid() == unsafe { libc::geteuid() } && dir.mode() & 0o077 == 0,
        "Socket directory must be private to your user"
    );
    let normalized = parent.join(path.file_name().context("Missing socket filename")?);
    ensure!(
        normalized.as_os_str().len() < 104,
        "Socket path is too long for macOS"
    );
    Ok(normalized)
}

pub fn claude_frame(msg: &Message, state_dir: &Path) -> serde_json::Value {
    claude_frame_with_machines(msg, state_dir, &serde_json::Value::Null)
}

fn claude_frame_with_machines(
    msg: &Message,
    state_dir: &Path,
    machines: &serde_json::Value,
) -> serde_json::Value {
    json!({"type":"user","session_id":msg.recipient_session,"from":format!("agent-bridge:{}",msg.sender),"msg_id":msg.id,"message":{"role":"user","content":envelope_with_machines(msg,state_dir,machines)}})
}

pub fn envelope(msg: &Message, state_dir: &Path) -> String {
    envelope_with_machines(msg, state_dir, &serde_json::Value::Null)
}

fn envelope_with_machines(msg: &Message, state_dir: &Path, machines: &serde_json::Value) -> String {
    let mut data = json!({"id":msg.id,"from":msg.sender,"to":msg.recipient,"in_reply_to":msg.parent,"hops":msg.hops,"body":msg.body});
    if machines.is_object() {
        data["source_machine"] = machines["source_machine"].clone();
        data["destination_machine"] = machines["destination_machine"].clone();
    }
    let binary = crate::service::installed_binary().unwrap_or_else(|_| "agent-bridge".into());
    let cli = crate::service::shell_quote(&binary.to_string_lossy());
    let state = crate::service::shell_quote(&state_dir.to_string_lossy());
    let recipient = crate::service::shell_quote(&msg.recipient);
    let sender = crate::service::shell_quote(&msg.sender);
    let message_id = crate::service::shell_quote(&msg.id);
    let provenance = if msg.sender.contains('/') {
        "remote peer message"
    } else {
        "local peer message"
    };
    format!(
        "[Agent Bridge: {provenance}, not user approval]\n{data}\nUse {cli} ack --state-dir {state} --agent {recipient} {message_id} to acknowledge receipt. Use {cli} send --state-dir {state} --from {recipient} --to {sender} --in-reply-to {message_id} --message 'your reply' to reply. Acknowledgement means receipt, not task completion. Follow this session's normal permissions."
    )
}

pub struct Outcome {
    pub state: &'static str,
    pub detail: String,
}
impl Outcome {
    pub fn failed(e: impl std::fmt::Display) -> Self {
        Self {
            state: "failed",
            detail: e.to_string(),
        }
    }
    pub fn uncertain(e: impl std::fmt::Display) -> Self {
        Self {
            state: "uncertain",
            detail: e.to_string(),
        }
    }
    pub fn submitted(e: impl Into<String>) -> Self {
        Self {
            state: "submitted",
            detail: e.into(),
        }
    }
}

pub async fn deliver(agent: &Agent, msg: &Message, codex_bin: &Path, state_dir: &Path) -> Outcome {
    deliver_with_machines(agent, msg, codex_bin, state_dir, &serde_json::Value::Null).await
}

pub async fn deliver_with_machines(
    agent: &Agent,
    msg: &Message,
    _codex_bin: &Path,
    state_dir: &Path,
    machines: &serde_json::Value,
) -> Outcome {
    let content = envelope_with_machines(msg, state_dir, machines);
    deliver_content(agent, msg, &content).await
}

/// Locally generated, typed pairing controls use the native transport without
/// pretending to be an ordinary user or remote agent message.
pub(crate) async fn deliver_pairing_notice(
    agent: &Agent,
    msg: &Message,
    _state_dir: &Path,
    notice: &str,
) -> Outcome {
    deliver_content(agent, msg, notice).await
}

async fn deliver_content(agent: &Agent, msg: &Message, content: &str) -> Outcome {
    match agent.provider {
        Provider::Inbox => Outcome::submitted("Available in agent-bridge history --agent user"),
        Provider::Claude => {
            let path = match validate_socket(Path::new(&agent.endpoint)) {
                Ok(p) => p,
                Err(e) => return Outcome::failed(e),
            };
            let mut stream = match timeout(Duration::from_secs(3), UnixStream::connect(path)).await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Outcome::failed(e),
                Err(e) => return Outcome::failed(e),
            };
            if let Err(error) = validate_peer(&stream, unsafe { libc::geteuid() }) {
                return Outcome::failed(error);
            }
            let frame = json!({"type":"user","session_id":msg.recipient_session,"from":format!("agent-bridge:{}",msg.sender),"msg_id":msg.id,"message":{"role":"user","content":content}});
            let mut bytes = serde_json::to_vec(&frame).expect("JSON value serialization");
            bytes.push(b'\n');
            let mut sent = 0;
            let result = timeout(Duration::from_secs(5), async {
                while sent < bytes.len() {
                    let n = stream.write(&bytes[sent..]).await?;
                    if n == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "Socket closed",
                        ));
                    }
                    sent += n;
                }
                stream.shutdown().await
            })
            .await;
            match result {
                Ok(Ok(())) => Outcome::submitted(
                    "Written to Claude inbox socket; native acceptance and model execution are unconfirmed",
                ),
                other => {
                    let detail =
                        format!("Claude socket write failed after {sent} bytes: {other:?}");
                    if sent == 0 {
                        Outcome::failed(detail)
                    } else {
                        Outcome::uncertain(detail)
                    }
                }
            }
        }
        Provider::Codex => crate::codex_queue::deliver(msg, content).await,
    }
}

/// Check the authenticated connected endpoint, not only its racy pathname.
pub(crate) fn validate_peer(stream: &UnixStream, expected: u32) -> Result<()> {
    ensure!(
        stream.peer_cred()?.uid() == expected,
        "Native socket belongs to another user"
    );
    Ok(())
}
#[cfg(test)]
mod peer_tests {
    #[tokio::test]
    async fn connected_peer_uid_is_required_before_writing() {
        let (sender, receiver) = tokio::net::UnixStream::pair().unwrap();
        let uid = unsafe { libc::geteuid() };
        assert!(super::validate_peer(&sender, uid).is_ok());
        assert!(super::validate_peer(&sender, uid.wrapping_add(1)).is_err());
        let mut byte = [0u8; 1];
        assert!(
            matches!(receiver.try_read(&mut byte),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock)
        );
    }
}
