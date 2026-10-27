use agent_bridge::network::identity::Identity;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    sync::{Arc, Barrier},
};

fn private_temp() -> tempfile::TempDir {
    let state = tempfile::tempdir().unwrap();
    fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    state
}

#[test]
fn identity_persists_and_different_state_directories_have_distinct_keys() {
    let first = private_temp();
    let second = private_temp();
    let identity = Identity::load_or_create(first.path()).unwrap().info();
    assert_eq!(identity.peer_id, identity.fingerprint);
    assert_eq!(
        identity,
        Identity::load_or_create(first.path()).unwrap().info()
    );
    assert_ne!(
        identity,
        Identity::load_or_create(second.path()).unwrap().info()
    );
    let metadata = fs::metadata(first.path().join("identity.key")).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert!(identity.peer_id.parse::<libp2p_identity::PeerId>().is_ok());
}

#[test]
fn corrupt_and_oversized_existing_keys_are_never_replaced() {
    let state = private_temp();
    Identity::load_or_create(state.path()).unwrap();
    let key = state.path().join("identity.key");
    for contents in [vec![1, 2, 3], vec![0; 1025]] {
        fs::write(&key, &contents).unwrap();
        assert!(Identity::load_or_create(state.path()).is_err());
        assert_eq!(fs::read(&key).unwrap(), contents);
    }
}

#[test]
fn identity_rejects_symlinks_hard_links_and_insecure_modes() {
    let state = private_temp();
    Identity::load_or_create(state.path()).unwrap();
    let key = state.path().join("identity.key");
    let other = state.path().join("other.key");
    fs::rename(&key, &other).unwrap();
    symlink(&other, &key).unwrap();
    assert!(Identity::load_or_create(state.path()).is_err());
    fs::remove_file(&key).unwrap();
    fs::hard_link(&other, &key).unwrap();
    assert!(Identity::load_or_create(state.path()).is_err());
    fs::remove_file(&other).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Identity::load_or_create(state.path()).is_err());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    Identity::load_or_create(state.path()).unwrap();
    fs::set_permissions(state.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Identity::load_or_create(state.path()).is_err());
}

#[test]
fn state_directory_and_lock_symlinks_are_rejected() {
    let root = private_temp();
    let state = root.path().join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = root.path().join("alias");
    symlink(&state, &alias).unwrap();
    assert!(Identity::load_or_create(&alias).is_err());
    let target = root.path().join("target");
    fs::write(&target, b"unchanged").unwrap();
    symlink(&target, state.join("identity.lock")).unwrap();
    assert!(Identity::load_or_create(&state).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"unchanged");
}

#[test]
fn concurrent_first_loads_publish_one_identity() {
    for round in 0..32 {
        let state = private_temp();
        let barrier = Arc::new(Barrier::new(8));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let path = state.path().to_path_buf();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    Identity::load_or_create(&path).map(|identity| identity.info())
                })
            })
            .collect();
        // Join every worker before asserting anything or dropping TempDir. A
        // short-circuiting collect/unwrap can delete state beneath live workers
        // and replace the primary failure with misleading ENOENT errors.
        let outcomes: Vec<_> = workers.into_iter().map(|worker| worker.join()).collect();
        let mut identities = Vec::new();
        let mut errors = Vec::new();
        for (worker, outcome) in outcomes.into_iter().enumerate() {
            match outcome {
                Ok(Ok(identity)) => identities.push(identity),
                Ok(Err(error)) => errors.push(format!("worker {worker}: {error:#}")),
                Err(payload) => errors.push(format!(
                    "worker {worker} panicked: {}",
                    payload
                        .downcast_ref::<String>()
                        .map(String::as_str)
                        .or_else(|| payload.downcast_ref::<&str>().copied())
                        .unwrap_or("unknown panic")
                )),
            }
        }
        assert!(errors.is_empty(), "round {round}: {}", errors.join("; "));
        assert_eq!(identities.len(), 8);
        assert!(identities.iter().all(|identity| identity == &identities[0]));
        assert_eq!(
            fs::metadata(state.path().join("identity.key"))
                .unwrap()
                .nlink(),
            1
        );
        assert!(fs::read_dir(state.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }
}

// A subprocess helper tests real independent filesystem lock holders, rather
// than only the in-process gate. No environment or production state is changed.
#[test]
fn identity_process_child() -> anyhow::Result<()> {
    let Some(root) = std::env::var_os("AGENT_BRIDGE_IDENTITY_TEST_ROOT") else {
        return Ok(());
    };
    let root = std::path::PathBuf::from(root);
    let ready = root.join(format!("ready-{}", std::process::id()));
    fs::write(ready, b"ready")?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !root.join("start").exists() {
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "Child start barrier timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let info = Identity::load_or_create(&root.join("state"))?.info();
    println!("IDENTITY_TEST_PEER_ID={}", info.peer_id);
    Ok(())
}

#[test]
fn independent_processes_publish_one_identity() {
    let root = private_temp();
    let exe = std::env::current_exe().unwrap();
    let mut children: Vec<_> = (0..4)
        .map(|_| {
            std::process::Command::new(&exe)
                .args(["--exact", "identity_process_child", "--nocapture"])
                .env("AGENT_BRIDGE_IDENTITY_TEST_ROOT", root.path())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let ready = fs::read_dir(root.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("ready-"))
            .count();
        if ready == 4 || std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    // Release every started child even when readiness is incomplete, then collect
    // every output before any assertion can remove the shared temporary state.
    fs::write(root.path().join("start"), b"start").unwrap();
    let mut outputs = Vec::new();
    for child in &mut children {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        if child.try_wait().unwrap().is_none() {
            let _ = child.kill();
        }
    }
    for child in children {
        outputs.push(child.wait_with_output());
    }
    let outputs: Vec<_> = outputs.into_iter().map(|output| output.unwrap()).collect();
    let failures: Vec<_> = outputs
        .iter()
        .filter(|output| !output.status.success())
        .map(|output| {
            format!(
                "{}: {} {}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("; "));
    let identities: Vec<_> = outputs
        .iter()
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .find_map(|line| {
                    line.strip_prefix("IDENTITY_TEST_PEER_ID=")
                        .map(str::to_string)
                })
                .unwrap()
        })
        .collect();
    assert_eq!(identities.len(), 4);
    assert!(identities.iter().all(|identity| identity == &identities[0]));
    assert_eq!(
        fs::metadata(root.path().join("state/identity.key"))
            .unwrap()
            .nlink(),
        1
    );
}

#[test]
fn non_regular_key_does_not_block_loading() {
    let state = private_temp();
    let key = state.path().join("identity.key");
    let name = std::ffi::CString::new(key.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(Identity::load_or_create(state.path()).is_err());
}
