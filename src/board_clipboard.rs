//! Write selected text to the terminal clipboard without reading its contents.
//! OSC 52 keeps clipboard handling on the terminal side, including remote shells.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::io::Write;

pub(crate) const MAX_CLIPBOARD_BYTES: usize = 64 * 1024;

fn sequence(text: &str) -> Result<Option<String>> {
    ensure!(
        text.len() <= MAX_CLIPBOARD_BYTES,
        "Selection exceeds the 64 KiB clipboard limit; select a smaller region"
    );
    if text.is_empty() {
        // An empty OSC 52 payload can clear the existing clipboard.
        return Ok(None);
    }
    // Only base64 enters the control string; even hostile text cannot insert
    // another terminal command or terminate this sequence early. Constant `c`
    // targets the clipboard. We never use the `?` clipboard-read operation.
    Ok(Some(format!("\x1b]52;c;{}\x1b\\", STANDARD.encode(text))))
}

pub(crate) fn copy_to_terminal(text: &str) -> Result<()> {
    let Some(sequence) = sequence(text)? else {
        return Ok(());
    };
    let mut output = std::io::stdout().lock();
    output
        .write_all(sequence.as_bytes())
        .context("Cannot send the selection to the terminal clipboard")?;
    output.flush().context("Cannot flush the clipboard request")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_text_and_unicode_remain_one_write_only_clipboard_payload() {
        let text = "selected café 地球 👩‍💻\n\x1b]52;c;other\x07\x1b\\";
        let encoded = sequence(text).unwrap().unwrap();
        let payload = encoded
            .strip_prefix("\x1b]52;c;")
            .unwrap()
            .strip_suffix("\x1b\\")
            .unwrap();
        assert_eq!(STANDARD.decode(payload).unwrap(), text.as_bytes());
        assert!(
            payload
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        );
        assert_eq!(encoded.matches('\x1b').count(), 2);
        assert!(!payload.contains('?'));
    }

    #[test]
    fn empty_and_oversized_selections_never_produce_a_clipboard_command() {
        assert!(sequence("").unwrap().is_none());
        assert!(
            sequence(&"a".repeat(MAX_CLIPBOARD_BYTES))
                .unwrap()
                .is_some()
        );
        assert!(sequence(&"a".repeat(MAX_CLIPBOARD_BYTES + 1)).is_err());
        let unicode = "地".repeat(MAX_CLIPBOARD_BYTES / 3 + 1);
        assert!(sequence(&unicode).is_err());
    }
}
