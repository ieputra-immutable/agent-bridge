use agent_bridge::broker::{self, Broker};
use serde_json::Value;
use std::{path::Path, time::Duration};

async fn cli(state: &Path, args: &[&str]) -> std::process::Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_agent-bridge"))
        .arg("--state-dir")
        .arg(state)
        .args(args)
        .output()
        .await
        .unwrap()
}

async fn json(state: &Path, args: &[&str]) -> Value {
    let output = cli(state, args).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[tokio::test]
async fn cli_exchanges_invitations_without_grants_and_controls_lan_mode() {
    let root = tempfile::Builder::new()
        .prefix("ab-lan-cli-")
        .tempdir_in("/tmp")
        .unwrap();
    let a = root.path().join("a");
    let b = root.path().join("b");
    let alice = tokio::spawn(broker::serve(
        Broker::bind(a.clone(), "/missing/codex".into()).unwrap(),
    ));
    let bob = tokio::spawn(broker::serve(
        Broker::bind(b.clone(), "/missing/codex".into()).unwrap(),
    ));
    let invitation = json(&b, &["peers", "invite", "--seconds", "120"]).await;
    let token = invitation["invitation"].as_str().unwrap();
    let fingerprint = invitation["fingerprint"].as_str().unwrap();
    assert!(
        !cli(&a, &["peers", "accept", token, "--fingerprint", "wrong"])
            .await
            .status
            .success()
    );
    assert_eq!(json(&a, &["peers", "list"]).await, serde_json::json!([]));
    let peer = json(
        &a,
        &[
            "peers",
            "accept",
            token,
            "--fingerprint",
            fingerprint,
            "--alias",
            "bob",
        ],
    )
    .await;
    assert_eq!(peer["peer_id"], fingerprint);
    assert!(peer["grants"].as_array().unwrap().is_empty());
    json(&a, &["peers", "revoke", "bob"]).await;
    assert!(
        !cli(
            &a,
            &["peers", "accept", token, "--fingerprint", fingerprint]
        )
        .await
        .status
        .success()
    );
    assert_eq!(json(&a, &["peers", "list"]).await[0]["revoked"], true);
    assert!(
        !cli(&b, &["peers", "invite", "--seconds", "29"])
            .await
            .status
            .success()
    );
    assert_eq!(
        json(&a, &["peers", "discover"]).await,
        serde_json::json!([])
    );
    let config = json(
        &a,
        &[
            "network",
            "enable",
            "--lan",
            "--listen",
            "/ip4/127.0.0.1/udp/0/quic-v1",
        ],
    )
    .await;
    assert_eq!(config["lan"], true);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if json(&a, &["status"]).await["network"]["lan"] == true {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("LAN listener did not start");
    let config = json(
        &a,
        &[
            "network",
            "enable",
            "--listen",
            "/ip4/127.0.0.1/udp/0/quic-v1",
        ],
    )
    .await;
    assert_eq!(config["lan"], false);
    assert_eq!(
        json(&a, &["peers", "discover"]).await,
        serde_json::json!([])
    );
    json(&a, &["network", "disable"]).await;
    alice.abort();
    bob.abort();
    let _ = alice.await;
    let _ = bob.await;
}
