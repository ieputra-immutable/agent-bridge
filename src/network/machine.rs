//! Cosmetic machine labels. Cryptographic peer IDs remain the routing identity.
use crate::db::Db;
use anyhow::Context;
use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, params};

pub fn validate_name(name: &str) -> Result<()> {
    ensure!(
        crate::db::valid_name(name) && name != "." && name != "..",
        "Machine names use 1–100 ASCII letters, digits, dots, underscores or hyphens"
    );
    Ok(())
}

pub fn default_name() -> String {
    let mut buffer = [0u8; 256];
    // Leave a trailing NUL even when the OS truncates its hostname.
    let ok = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len() - 1) } == 0;
    if !ok {
        return "agent-bridge".into();
    }
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    hostname_label(&String::from_utf8_lossy(&buffer[..end]))
}

fn hostname_label(hostname: &str) -> String {
    let name: String = hostname
        .split('.')
        .next()
        .unwrap_or_default()
        .chars()
        .take(63)
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '-'
            }
        })
        .collect();
    let name = name.trim_matches('-');
    if name.is_empty() {
        "agent-bridge".into()
    } else {
        name.into()
    }
}

impl Db {
    pub fn machine_name(&self) -> Result<String> {
        let name: String = self.conn.query_row(
            "SELECT value FROM settings WHERE key='machine_name'",
            [],
            |row| row.get(0),
        )?;
        validate_name(&name).context("Invalid stored machine name")?;
        Ok(name)
    }

    pub fn set_machine_name(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        ensure!(
            self.conn.execute(
                "UPDATE settings SET value=? WHERE key='machine_name'",
                [name]
            )? == 1,
            "Machine name setting is missing"
        );
        Ok(())
    }

    /// Only call with the peer identity supplied by an authenticated connection.
    pub fn remember_peer_name(&self, peer_id: &str, name: &str) -> Result<()> {
        validate_name(name)?;
        let parsed: libp2p_identity::PeerId = peer_id.parse().context("Invalid peer ID")?;
        ensure!(
            parsed.to_string() == peer_id,
            "Peer ID must use its canonical encoding"
        );
        ensure!(
            self.conn.execute(
                "UPDATE peers SET machine_name=? WHERE peer_id=? AND revoked=0",
                params![name, peer_id]
            )? == 1,
            "Peer is unknown or revoked"
        );
        Ok(())
    }

    fn peer_suffix(&self, peer_id: &str) -> Result<String> {
        let mut statement = self
            .conn
            .prepare("SELECT peer_id FROM peers WHERE peer_id<>?")?;
        let others = statement
            .query_map([peer_id], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for length in 8.min(peer_id.len())..=peer_id.len() {
            let suffix = &peer_id[peer_id.len() - length..];
            if !others.iter().any(|other| other.ends_with(suffix)) {
                return Ok(suffix.into());
            }
        }
        Ok(peer_id.into())
    }

    pub(crate) fn peer_display_name(
        &self,
        peer_id: &str,
        alias: Option<&str>,
        name: Option<&str>,
    ) -> Result<String> {
        if let Some(alias) = alias {
            return Ok(alias.into());
        }
        let suffix = self.peer_suffix(peer_id)?;
        let Some(name) = name else {
            return Ok(format!("peer [{suffix}]"));
        };
        let duplicate: bool = self.conn.query_row("SELECT EXISTS(SELECT 1 FROM peers WHERE peer_id<>?1 AND COALESCE(alias,machine_name)=?2)", params![peer_id,name], |row| row.get(0))?;
        Ok(if duplicate {
            format!("{name} [{suffix}]")
        } else {
            name.into()
        })
    }

    /// Suggest an owner-local routing alias; a claimed display name never routes directly.
    pub fn suggest_peer_alias(&self, peer_id: &str, claimed_name: &str) -> Result<String> {
        let parsed: libp2p_identity::PeerId = peer_id.parse().context("Invalid peer ID")?;
        ensure!(
            parsed.to_string() == peer_id,
            "Peer ID must use its canonical encoding"
        );
        validate_name(claimed_name)?;
        let existing: Option<Option<String>> = self
            .conn
            .query_row(
                "SELECT alias FROM peers WHERE peer_id=?",
                [peer_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(Some(alias)) = existing {
            return Ok(alias);
        }
        let available = |name: &str| -> Result<bool> {
            if name.parse::<libp2p_identity::PeerId>().is_ok() {
                return Ok(false);
            }
            Ok(!self.conn.query_row("SELECT EXISTS(SELECT 1 FROM peers WHERE peer_id<>?1 AND (alias=?2 OR (alias IS NULL AND machine_name=?2)))", params![peer_id,name], |row| row.get::<_,bool>(0))?)
        };
        if available(claimed_name)? {
            return Ok(claimed_name.into());
        }
        let suffix = self.peer_suffix(peer_id)?;
        for number in 1..=1024 {
            let suffix = if number == 1 {
                suffix.clone()
            } else {
                format!("{suffix}-{number}")
            };
            let length = 100usize
                .saturating_sub(suffix.len() + 1)
                .min(claimed_name.len());
            let candidate = format!("{}-{suffix}", &claimed_name[..length]);
            if available(&candidate)? {
                return Ok(candidate);
            }
        }
        anyhow::bail!("Cannot suggest a unique peer alias; supply an explicit alias")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_labels_are_short_safe_and_do_not_include_domain_names() {
        assert_eq!(hostname_label("machine-b.example.test"), "machine-b");
        assert_eq!(hostname_label("Work Mac"), "Work-Mac");
        assert_eq!(hostname_label("..."), "agent-bridge");
        assert!(hostname_label(&"a".repeat(200)).len() <= 63);
        validate_name(&default_name()).unwrap();
    }
}
