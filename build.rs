use std::{env, fs, path::PathBuf};

fn release_version(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
                && part.parse::<u64>().is_ok()
        })
}

fn main() {
    println!("cargo:rerun-if-env-changed=AGENT_BRIDGE_BUILD_VERSION");
    println!("cargo:rerun-if-changed=SOURCE_VERSION");
    let version = match env::var("AGENT_BRIDGE_BUILD_VERSION") {
        Ok(version) => version,
        Err(env::VarError::NotPresent) => {
            let path =
                PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("SOURCE_VERSION");
            match fs::read_to_string(path) {
                Ok(version) => version.trim_end_matches(['\r', '\n']).to_owned(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    env::var("CARGO_PKG_VERSION").unwrap()
                }
                Err(error) => panic!("Cannot read packaged source version: {error}"),
            }
        }
        Err(error) => panic!("Invalid build version environment: {error}"),
    };
    assert!(
        release_version(&version),
        "Expected a version in MAJOR.MINOR.PATCH form, without a v prefix or leading zeros"
    );
    println!("cargo:rustc-env=AGENT_BRIDGE_VERSION={version}");
}
