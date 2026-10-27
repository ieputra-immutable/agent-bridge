//! A local Markdown document with revision-checked, atomic incremental edits.
//!
//! The broker serializes operations. Callers which edit the file outside the
//! broker must coordinate with active writers; filesystem editors do not share
//! the broker's transaction boundary.
use anyhow::{Context, Result, ensure};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

pub const MAX_BOARD_BYTES: usize = 64 * 1024;
pub const MAX_EDITS: usize = 32;
const BOARD_NAME: &str = "main";
const DIRECTORY: &CStr = c"boards";
const DOCUMENT: &CStr = c"main.md";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub name: String,
    pub markdown: String,
    pub revision: String,
    pub path: PathBuf,
    pub exists: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Edit {
    /// Replace exactly one occurrence; missing or ambiguous text is a conflict.
    Replace {
        old: String,
        new: String,
    },
    Append {
        text: String,
    },
    Prepend {
        text: String,
    },
    Set {
        markdown: String,
    },
}

#[derive(Debug)]
pub struct Conflict {
    pub current: Snapshot,
}
impl std::fmt::Display for Conflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Board changed; read the current revision and retry the intended edits"
        )
    }
}
impl std::error::Error for Conflict {}

fn snapshot(state_dir: &Path, markdown: String, exists: bool) -> Snapshot {
    Snapshot {
        name: BOARD_NAME.into(),
        revision: Sha256::digest(markdown.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        markdown,
        path: state_dir.join("boards").join("main.md"),
        exists,
    }
}

fn root(state_dir: &Path) -> Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(state_dir)
        .context("Cannot open the private board state directory")?;
    validate_directory(&directory)?;
    Ok(directory)
}

fn validate_directory(directory: &File) -> Result<()> {
    let metadata = directory.metadata()?;
    ensure!(metadata.is_dir(), "Board directory must be a directory");
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o7777 == 0o700,
        "Board directories must be owned by this user with mode 0700"
    );
    Ok(())
}

fn open_at(directory: &File, name: &CStr, flags: libc::c_int) -> std::io::Result<File> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn board_directory(state: &File, create: bool) -> Result<Option<File>> {
    match open_at(state, DIRECTORY, libc::O_RDONLY | libc::O_DIRECTORY) {
        Ok(directory) => {
            validate_directory(&directory)?;
            Ok(Some(directory))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let result = unsafe { libc::mkdirat(state.as_raw_fd(), DIRECTORY.as_ptr(), 0o700) };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(error).context("Cannot create private board directory");
                }
            }
            let directory = open_at(state, DIRECTORY, libc::O_RDONLY | libc::O_DIRECTORY)
                .context("Cannot open private board directory")?;
            validate_directory(&directory)?;
            // Persist the parent's new directory entry as well as the document
            // and boards directory synced by the subsequent atomic write.
            state
                .sync_all()
                .context("Cannot persist board directory creation")?;
            Ok(Some(directory))
        }
        Err(error) => Err(error).context("Board directory must not be a symbolic link"),
    }
}

fn read_document(state_dir: &Path, directory: &File) -> Result<Snapshot> {
    let file = match open_at(directory, DOCUMENT, libc::O_RDONLY) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(snapshot(state_dir, String::new(), false));
        }
        Err(error) => {
            return Err(error).context("Cannot open board document without following links");
        }
    };
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o7777 == 0o600
            && metadata.nlink() == 1,
        "Board document must be a regular, single-link, user-owned file with mode 0600"
    );
    ensure!(
        metadata.len() <= MAX_BOARD_BYTES as u64,
        "Board exceeds 64 KiB"
    );
    let mut bytes = Vec::new();
    file.take(MAX_BOARD_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_BOARD_BYTES, "Board exceeds 64 KiB");
    let markdown =
        String::from_utf8(bytes).context("Board document must contain UTF-8 Markdown")?;
    Ok(snapshot(state_dir, markdown, true))
}

/// Reading an absent board returns an empty document without creating a file.
pub fn read(state_dir: &Path) -> Result<Snapshot> {
    let state = root(state_dir)?;
    let Some(directory) = board_directory(&state, false)? else {
        return Ok(snapshot(state_dir, String::new(), false));
    };
    read_document(state_dir, &directory)
}

fn apply(markdown: &mut String, edit: &Edit) -> Result<()> {
    match edit {
        Edit::Replace { old, new } => {
            ensure!(
                !old.is_empty(),
                "Replacement text must not be empty; use set or append to initialize the board"
            );
            let Some(index) = markdown.find(old.as_str()) else {
                anyhow::bail!("Replacement text was not found; read the board and retry");
            };
            ensure!(
                markdown.rfind(old.as_str()) == Some(index),
                "Replacement text is ambiguous; select a unique row or section"
            );
            let final_length = markdown
                .len()
                .checked_sub(old.len())
                .and_then(|len| len.checked_add(new.len()))
                .context("Board size overflow")?;
            ensure!(final_length <= MAX_BOARD_BYTES, "Board exceeds 64 KiB");
            markdown.replace_range(index..index + old.len(), new);
        }
        Edit::Append { text } => {
            ensure!(
                markdown.len().saturating_add(text.len()) <= MAX_BOARD_BYTES,
                "Board exceeds 64 KiB"
            );
            markdown.push_str(text);
        }
        Edit::Prepend { text } => {
            ensure!(
                markdown.len().saturating_add(text.len()) <= MAX_BOARD_BYTES,
                "Board exceeds 64 KiB"
            );
            markdown.insert_str(0, text);
        }
        Edit::Set {
            markdown: replacement,
        } => {
            ensure!(replacement.len() <= MAX_BOARD_BYTES, "Board exceeds 64 KiB");
            markdown.clone_from(replacement);
        }
    }
    Ok(())
}

/// Validate all edits against an exact content revision before atomically replacing
/// the file. Validation/conflict failures leave it unchanged; an I/O failure after
/// rename may mean the new content was applied but durability is unconfirmed.
/// Read again before retrying an ambiguous failure with a fresh revision.
/// Concurrent callers must be serialized by the broker's administration mutex.
pub fn update(state_dir: &Path, expected_revision: &str, edits: &[Edit]) -> Result<Snapshot> {
    ensure!(
        expected_revision.len() == 64
            && expected_revision
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "Expected revision must be a full SHA-256 hash returned by board_read"
    );
    ensure!(
        (1..=MAX_EDITS).contains(&edits.len()),
        "A board update requires 1–32 edits"
    );
    let state = root(state_dir)?;
    let existing_directory = board_directory(&state, false)?;
    let current = match &existing_directory {
        Some(directory) => read_document(state_dir, directory)?,
        None => snapshot(state_dir, String::new(), false),
    };
    if current.revision != expected_revision {
        return Err(Conflict { current }.into());
    }
    let mut markdown = current.markdown.clone();
    for edit in edits {
        apply(&mut markdown, edit)?;
    }
    let directory = match existing_directory {
        Some(directory) => directory,
        None => board_directory(&state, true)?.context("Board directory was not created")?,
    };
    let temporary = CString::new(format!(".board-{}.tmp", uuid::Uuid::new_v4()))?;
    let result = (|| -> Result<()> {
        let mut file = open_at(
            &directory,
            &temporary,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .context("Cannot stage board update")?;
        file.write_all(markdown.as_bytes())?;
        file.sync_all()?;
        let result = unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary.as_ptr(),
                directory.as_raw_fd(),
                DOCUMENT.as_ptr(),
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .context("Cannot replace board document atomically");
        }
        directory
            .sync_all()
            .context("Cannot persist board directory")?;
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0);
        }
    }
    result?;
    Ok(snapshot(state_dir, markdown, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    fn private_state() -> tempfile::TempDir {
        let state = tempfile::tempdir().unwrap();
        fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
        state
    }
    fn set(state: &Path, markdown: &str) -> Snapshot {
        let before = read(state).unwrap();
        update(
            state,
            &before.revision,
            &[Edit::Set {
                markdown: markdown.into(),
            }],
        )
        .unwrap()
    }

    #[test]
    fn absent_read_is_empty_and_does_not_create_files() {
        let state = private_state();
        let board = read(state.path()).unwrap();
        assert_eq!(board.name, "main");
        assert!(!board.exists);
        assert!(board.markdown.is_empty());
        assert_eq!(board.revision.len(), 64);
        assert!(!state.path().join("boards").exists());
    }

    #[test]
    fn incremental_unicode_updates_are_atomic_and_preserve_arbitrary_markdown() {
        let state = private_state();
        let original =
            "# 🦀 Team\n\n| Agent | Task |\n| --- | --- |\n| α | Research |\n| β | Test |\n";
        let before = set(state.path(), original);
        let after = update(
            state.path(),
            &before.revision,
            &[
                Edit::Replace {
                    old: "| α | Research |".into(),
                    new: "| α | Needs owner |".into(),
                },
                Edit::Prepend {
                    text: "<!-- user-defined board -->\n".into(),
                },
                Edit::Append {
                    text: "\n```text\n\u{1b}[31m literal terminal data\n```\n".into(),
                },
            ],
        )
        .unwrap();
        assert!(after.markdown.contains("| β | Test |"));
        assert!(after.markdown.contains("| α | Needs owner |"));
        assert!(after.markdown.contains('\u{1b}'));
        assert_eq!(fs::read_to_string(&after.path).unwrap(), after.markdown);
        assert_eq!(fs::metadata(&after.path).unwrap().mode() & 0o777, 0o600);
    }

    #[test]
    fn stale_revision_returns_current_document_without_overwriting_rows() {
        let state = private_state();
        let before = set(state.path(), "| A | old |\n| B | old |\n");
        let first = update(
            state.path(),
            &before.revision,
            &[Edit::Replace {
                old: "| A | old |".into(),
                new: "| A | done |".into(),
            }],
        )
        .unwrap();
        let failure = update(
            state.path(),
            &before.revision,
            &[Edit::Replace {
                old: "| B | old |".into(),
                new: "| B | done |".into(),
            }],
        )
        .unwrap_err();
        let conflict = failure.downcast_ref::<Conflict>().unwrap();
        assert_eq!(conflict.current.revision, first.revision);
        let final_board = update(
            state.path(),
            &conflict.current.revision,
            &[Edit::Replace {
                old: "| B | old |".into(),
                new: "| B | done |".into(),
            }],
        )
        .unwrap();
        assert_eq!(final_board.markdown, "| A | done |\n| B | done |\n");
    }

    #[test]
    fn invalid_or_ambiguous_batch_leaves_document_unchanged_and_no_staging_files() {
        let state = private_state();
        let before = set(state.path(), "same\nsame\nunique\n");
        for edits in [
            vec![
                Edit::Append {
                    text: "would change".into(),
                },
                Edit::Replace {
                    old: "missing".into(),
                    new: "x".into(),
                },
            ],
            vec![Edit::Replace {
                old: "same".into(),
                new: "x".into(),
            }],
            vec![Edit::Replace {
                old: String::new(),
                new: "x".into(),
            }],
        ] {
            assert!(update(state.path(), &before.revision, &edits).is_err());
            assert_eq!(read(state.path()).unwrap().markdown, before.markdown);
        }
        assert_eq!(
            fs::read_dir(state.path().join("boards")).unwrap().count(),
            1
        );
    }

    #[test]
    fn overlapping_replacement_matches_are_ambiguous() {
        let state = private_state();
        for (markdown, old) in [("aaa", "aa"), ("ééé", "éé")] {
            let before = set(state.path(), markdown);
            assert!(
                update(
                    state.path(),
                    &before.revision,
                    &[Edit::Replace {
                        old: old.into(),
                        new: "changed".into()
                    }]
                )
                .is_err()
            );
            assert_eq!(read(state.path()).unwrap().markdown, markdown);
        }
    }

    #[test]
    fn bounds_and_invalid_requests_never_create_or_truncate_a_board() {
        let state = private_state();
        let before = read(state.path()).unwrap();
        assert!(
            update(
                state.path(),
                "invalid",
                &[Edit::Append { text: "x".into() }]
            )
            .is_err()
        );
        assert!(update(state.path(), &before.revision, &[]).is_err());
        assert!(
            update(
                state.path(),
                &before.revision,
                &vec![
                    Edit::Append {
                        text: String::new()
                    };
                    MAX_EDITS + 1
                ]
            )
            .is_err()
        );
        assert!(
            update(
                state.path(),
                &before.revision,
                &[Edit::Set {
                    markdown: "é".repeat(MAX_BOARD_BYTES / 2 + 1)
                }]
            )
            .is_err()
        );
        assert!(!state.path().join("boards").exists());
        let full = set(state.path(), &"x".repeat(MAX_BOARD_BYTES));
        assert!(
            update(
                state.path(),
                &full.revision,
                &[Edit::Append { text: "x".into() }]
            )
            .is_err()
        );
        assert_eq!(read(state.path()).unwrap().markdown.len(), MAX_BOARD_BYTES);
    }

    #[test]
    fn unsafe_board_files_and_directory_aliases_are_rejected() {
        let state = private_state();
        let outside = private_state();
        symlink(outside.path(), state.path().join("boards")).unwrap();
        assert!(read(state.path()).is_err());
        fs::remove_file(state.path().join("boards")).unwrap();
        let before = set(state.path(), "private");
        let other = state.path().join("other");
        fs::rename(&before.path, &other).unwrap();
        symlink(&other, &before.path).unwrap();
        assert!(read(state.path()).is_err());
        fs::remove_file(&before.path).unwrap();
        fs::hard_link(&other, &before.path).unwrap();
        assert!(read(state.path()).is_err());
        fs::remove_file(&other).unwrap();
        fs::set_permissions(&before.path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(state.path()).is_err());
        fs::set_permissions(&before.path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read(state.path()).unwrap().markdown, "private");
        fs::remove_file(&before.path).unwrap();
        let fifo = CString::new(before.path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(read(state.path()).is_err());
    }

    #[test]
    fn oversized_and_invalid_utf8_existing_documents_are_rejected() {
        let state = private_state();
        let before = set(state.path(), "small");
        fs::write(&before.path, [0xff]).unwrap();
        assert!(read(state.path()).is_err());
        fs::write(&before.path, vec![b'x'; MAX_BOARD_BYTES + 1]).unwrap();
        assert!(read(state.path()).is_err());
    }
}
