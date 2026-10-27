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
    let state = private_temp();
    let barrier = Arc::new(Barrier::new(8));
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let path = state.path().to_path_buf();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                Identity::load_or_create(&path).unwrap().info()
            })
        })
        .collect();
    let identities: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
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

#[test]
fn non_regular_key_does_not_block_loading() {
    let state = private_temp();
    let key = state.path().join("identity.key");
    let name = std::ffi::CString::new(key.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(Identity::load_or_create(state.path()).is_err());
}
