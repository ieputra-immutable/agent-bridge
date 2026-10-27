use agent_bridge::{
    broker::{self, Broker},
    network::identity::Identity,
};
use serde_json::{Value, json};
use std::path::Path;

async fn cli(state: &Path, args: &[&str]) -> std::process::Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_agent-bridge"))
        .arg("--state-dir")
        .arg(state)
        .args(args)
        .output()
        .await
        .unwrap()
}
async fn success(state: &Path, args: &[&str]) -> Value {
    let output = cli(state, args).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[tokio::test]
async fn cli_shares_and_removes_exact_sessions_and_reports_connection_scope() {
    let root = tempfile::Builder::new()
        .prefix("ab-sharing-cli-")
        .tempdir_in("/tmp")
        .unwrap();
    let state = root.path().join("local");
    let bound = Broker::bind(state.clone(), "/missing/codex".into()).unwrap();
    let server = tokio::spawn(broker::serve(bound));
    let remote = Identity::load_or_create(&root.path().join("remote"))
        .unwrap()
        .info();
    success(
        &state,
        &[
            "peers",
            "pair",
            &remote.peer_id,
            "--fingerprint",
            &remote.fingerprint,
            "--alias",
            "machine-b",
        ],
    )
    .await;
    assert_eq!(success(&state, &["peers", "shared"]).await, json!([]));
    assert!(
        !cli(&state, &["peers", "share", "unknown", "--agent", "user"])
            .await
            .status
            .success()
    );
    success(
        &state,
        &["register", "inbox", "worker", "--session", "original"],
    )
    .await;
    let shared = success(
        &state,
        &["peers", "share", "machine-b", "--agent", "worker"],
    )
    .await;
    assert_eq!(shared["grants"].as_array().unwrap().len(), 3);
    let rows = success(&state, &["peers", "shared"]).await;
    assert_eq!(rows[0]["shared"], true);
    assert_eq!(rows[0]["session"], "original");
    assert_eq!(
        rows[0]["permissions"],
        json!(["discover", "receive", "send"])
    );
    let connections = success(&state, &["peers", "connections"]).await;
    assert_eq!(connections[0]["state"], "network_disabled");
    assert_eq!(connections[0]["trusted"], true);
    assert_eq!(connections[0]["shared_sessions"][0]["session"], "original");
    assert!(!connections.to_string().contains("verification_code"));
    assert!(!connections.to_string().contains("endpoint"));
    success(
        &state,
        &["peers", "unshare", "machine-b", "--agent", "worker"],
    )
    .await;
    assert_eq!(success(&state, &["peers", "shared"]).await, json!([]));
    success(
        &state,
        &["peers", "share", "machine-b", "--agent", "worker"],
    )
    .await;
    success(
        &state,
        &[
            "register",
            "inbox",
            "worker",
            "--session",
            "replacement",
            "--replace",
        ],
    )
    .await;
    success(
        &state,
        &["peers", "share", "machine-b", "--agent", "worker"],
    )
    .await;
    assert_eq!(
        success(&state, &["peers", "shared"])
            .await
            .as_array()
            .unwrap()
            .len(),
        2
    );
    success(
        &state,
        &[
            "peers",
            "unshare",
            "machine-b",
            "--provider",
            "inbox",
            "--session",
            "original",
        ],
    )
    .await;
    let rows = success(&state, &["peers", "shared"]).await;
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["session"], "replacement");
    success(
        &state,
        &["unregister", "worker", "--session", "replacement"],
    )
    .await;
    assert!(
        !cli(
            &state,
            &["peers", "share", "machine-b", "--agent", "worker"]
        )
        .await
        .status
        .success()
    );
    success(
        &state,
        &["peers", "unshare", "machine-b", "--agent", "worker"],
    )
    .await;
    assert_eq!(success(&state, &["peers", "shared"]).await, json!([]));
    for args in [
        vec![
            "peers",
            "unshare",
            "machine-b",
            "--agent",
            "worker",
            "--provider",
            "inbox",
            "--session",
            "original",
        ],
        vec!["peers", "unshare", "machine-b", "--provider", "inbox"],
        vec!["peers", "unshare", "machine-b", "--session", "original"],
        vec!["peers", "unshare", "machine-b"],
    ] {
        assert!(
            !cli(&state, &args).await.status.success(),
            "invalid scope accepted: {args:?}"
        );
    }
    success(&state, &["peers", "revoke", "machine-b"]).await;
    assert_eq!(
        success(&state, &["peers", "connections"]).await[0]["state"],
        "revoked"
    );
    assert!(
        !cli(&state, &["peers", "share", "machine-b", "--agent", "user"])
            .await
            .status
            .success()
    );
    server.abort();
    let _ = server.await;
}
