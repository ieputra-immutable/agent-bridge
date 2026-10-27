//! Persistent bridge identity. Private key material never enters protocol responses.
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use libp2p_identity::{KeyType, Keypair};
use serde::Serialize;
use std::{
    ffi::{CStr, CString},
    fs::{DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::Path,
    sync::Mutex,
};
use zeroize::Zeroizing;

const KEY_FILE: &CStr = c"identity.key";
const LOCK_FILE: &CStr = c"identity.lock";
const MAX_KEY_BYTES: u64 = 1024;

// A process gate complements the cross-process advisory lock. Keep the entire
// descriptor/open/publish/load lifetime inside it: no concurrent caller in this
// process may observe the temporary two-link publication state or close another
// lock descriptor while an identity operation is still in progress. A single
// bounded gate also avoids a path-keyed registry and symlink/alias lock bypasses.
static IDENTITY_GATE: Mutex<()> = Mutex::new(());

/// The full canonical PeerId is also the fingerprint: it binds the public key.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct IdentityInfo {
    pub peer_id: String,
    pub fingerprint: String,
}

// Deliberately neither Debug nor Serialize: only IdentityInfo may be displayed.
pub struct Identity {
    keypair: Keypair,
}

impl Identity {
    pub fn load_or_create(state_dir: &Path) -> Result<Self> {
        let _process_guard = IDENTITY_GATE.lock().map_err(|_| {
            anyhow::anyhow!("Identity process lock is poisoned; refusing to change keys")
        })?;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(state_dir)
            .context("Could not create identity state directory")?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(state_dir)
            .context("Identity state directory must be a real directory")?;
        let metadata = directory
            .metadata()
            .context("Could not inspect opened identity state directory")?;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "Identity state directory belongs to another user"
        );
        ensure!(
            metadata.mode() & 0o7777 == 0o700,
            "Identity state directory must have mode 0700"
        );

        // Serialize readers too: publication briefly has two links before the
        // temporary link is removed, while permanent hard links are rejected.
        // Darwin can return spurious ENOENT when concurrent openat calls use
        // O_CREAT without O_EXCL. Create exclusively, or open the existing lock
        // without creation; keep the same descriptor-relative safety checks.
        // See entireio/cli commit fb597b386a1fa2b20adc90f4603c99ba7ccb2edf.
        let lock = match open_relative(
            &directory,
            LOCK_FILE,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        ) {
            Ok(file) => Ok(file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                open_relative(&directory, LOCK_FILE, libc::O_RDWR)
            }
            Err(error) => Err(error),
        }
        .context("Could not open identity lock file")?;
        validate_private_file(&lock).context("Invalid identity lock file")?;
        lock.lock_exclusive()
            .context("Could not lock identity file")?;
        match Self::load(&directory) {
            Ok(identity) => return Ok(identity),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
            Err(error) => {
                return Err(
                    error.context("Could not load identity; existing keys are never replaced")
                );
            }
        }

        let keypair = Keypair::generate_ed25519();
        let encoded = Zeroizing::new(
            keypair
                .to_protobuf_encoding()
                .context("Could not encode identity")?,
        );
        let temporary = CString::new(format!(".identity-{}.tmp", uuid::Uuid::new_v4()))?;
        let mut file = open_relative(
            &directory,
            &temporary,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        let publish = (|| -> Result<()> {
            file.write_all(&encoded)
                .context("Could not write identity")?;
            file.sync_all().context("Could not persist identity")?;
            let result = unsafe {
                libc::linkat(
                    directory.as_raw_fd(),
                    temporary.as_ptr(),
                    directory.as_raw_fd(),
                    KEY_FILE.as_ptr(),
                    0,
                )
            };
            if result != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("Could not publish identity without replacing existing key");
            }
            Ok(())
        })();
        let removed = unsafe { libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0) };
        if removed != 0 {
            return Err(std::io::Error::last_os_error())
                .context("Could not remove temporary identity link");
        }
        publish?;
        directory
            .sync_all()
            .context("Could not persist identity directory")?;
        Self::load(&directory).context("Could not reload published identity")
    }

    fn load(directory: &File) -> Result<Self> {
        let file = open_relative(directory, KEY_FILE, libc::O_RDONLY)
            .context("Could not open identity key file")?;
        validate_private_file(&file).context("Invalid identity key file")?;
        ensure!(
            file.metadata()
                .context("Could not inspect identity key length")?
                .len()
                <= MAX_KEY_BYTES,
            "Identity key file is too large"
        );
        let mut encoded = Zeroizing::new(Vec::new());
        file.take(MAX_KEY_BYTES + 1)
            .read_to_end(&mut encoded)
            .context("Could not read opened identity key")?;
        ensure!(
            encoded.len() as u64 <= MAX_KEY_BYTES,
            "Identity key file is too large"
        );
        let keypair =
            Keypair::from_protobuf_encoding(&encoded).context("Invalid identity key encoding")?;
        ensure!(
            keypair.key_type() == KeyType::Ed25519,
            "Identity key must use Ed25519"
        );
        let canonical = Zeroizing::new(keypair.to_protobuf_encoding()?);
        ensure!(
            *canonical == *encoded,
            "Identity key encoding is not canonical"
        );
        Ok(Self { keypair })
    }

    pub fn info(&self) -> IdentityInfo {
        let peer_id = self.keypair.public().to_peer_id().to_string();
        IdentityInfo {
            fingerprint: peer_id.clone(),
            peer_id,
        }
    }

    /// Transport receives the key in memory; it never enters an RPC response.
    pub(crate) fn keypair(&self) -> Keypair {
        self.keypair.clone()
    }
}

fn open_relative(directory: &File, name: &CStr, flags: libc::c_int) -> std::io::Result<File> {
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

fn validate_private_file(file: &File) -> Result<()> {
    let metadata = file
        .metadata()
        .context("Could not inspect opened private identity file")?;
    ensure!(metadata.is_file(), "Identity files must be regular files");
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() },
        "Identity file belongs to another user"
    );
    ensure!(
        metadata.mode() & 0o7777 == 0o600,
        "Identity files must have mode 0600"
    );
    ensure!(
        metadata.nlink() == 1,
        "Identity files must not have additional hard links"
    );
    Ok(())
}
