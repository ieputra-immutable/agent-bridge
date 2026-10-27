//! Black-box MCP stdio checks against the real broker. No native model, global
//! client configuration or existing bridge state is touched.
use agent_bridge::{
    broker::{self, Broker},
    protocol::{Agent, MAX_FRAME, Provider, Request},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap, os::unix::fs::PermissionsExt, path::Path, process::Stdio, time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixListener,
    process::{Child, ChildStdin, ChildStdout},
    time::timeout,
};

struct Running {
    broker: Broker,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}
impl Running {
    fn start(state: &Path) -> Self {
        let bound = Broker::bind(state.into(), "/missing/codex".into()).unwrap();
        Self {
            broker: bound.broker.clone(),
            task: tokio::spawn(broker::serve(bound)),
        }
    }
    fn request(&self, request: Request) -> Value {
        self.broker.request(request).unwrap()
    }
    fn inbox(&self, name: &str) {
        self.request(Request::Register {
            agent: Agent {
                name: name.into(),
                provider: Provider::Inbox,
                session: format!("inbox-{name}"),
                endpoint: String::new(),
                enabled: true,
            },
            replace: false,
        });
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Native {
    name: String,
    session: String,
    task: tokio::task::JoinHandle<()>,
}
impl Native {
    fn start(running: &Running, directory: &Path, name: &str) -> Self {
        std::fs::create_dir_all(directory).unwrap();
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.join("native.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let session = uuid::Uuid::new_v4().to_string();
        running.request(Request::Register {
            agent: Agent {
                name: name.into(),
                provider: Provider::Claude,
                session: session.clone(),
                endpoint: socket.to_string_lossy().into(),
                enabled: true,
            },
            replace: false,
        });
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let mut bytes = Vec::new();
                timeout(
                    Duration::from_secs(5),
                    stream.take(MAX_FRAME as u64).read_to_end(&mut bytes),
                )
                .await
                .unwrap()
                .unwrap();
                let frame: Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(frame["type"], "user");
            }
        });
        Self {
            name: name.into(),
            session,
            task,
        }
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Mcp {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    next_id: u64,
}
impl Mcp {
    fn start(state: &Path) -> Self {
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_agent-bridge"))
            .args(["--state-dir", state.to_str().unwrap(), "mcp"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        Self {
            input: child.stdin.take(),
            output: BufReader::new(child.stdout.take().unwrap()),
            child,
            next_id: 1,
        }
    }
    async fn write(&mut self, value: &Value) {
        let mut frame = serde_json::to_vec(value).unwrap();
        frame.push(b'\n');
        self.input
            .as_mut()
            .unwrap()
            .write_all(&frame)
            .await
            .unwrap();
    }
    async fn read(&mut self) -> Value {
        let mut line = String::new();
        let read = timeout(Duration::from_secs(10), self.output.read_line(&mut line))
            .await
            .expect("MCP response timed out")
            .unwrap();
        assert_ne!(read, 0, "MCP closed stdout before responding");
        let value: Value = serde_json::from_str(&line)
            .unwrap_or_else(|error| panic!("non-JSON protocol output: {error}: {line:?}"));
        assert_eq!(value["jsonrpc"], "2.0");
        value
    }
    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.write(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .await;
        loop {
            let response = self.read().await;
            if response["id"] == id {
                return response;
            }
            // SDK notifications and an uncorrelated parse error for a rejected
            // oversized frame still have to be valid JSON-RPC, never log text.
            assert!(response.get("id").is_none() || response["id"].is_null());
        }
    }
    async fn initialize(&mut self) {
        let response = self
            .request(
                "initialize",
                json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"agent-bridge-integration","version":"1"}}),
            )
            .await;
        assert!(response.get("error").is_none(), "{response}");
        assert_eq!(response["result"]["protocolVersion"], "2025-11-25");
        self.write(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
    }
    async fn call(&mut self, name: &str, arguments: Value) -> Value {
        self.request("tools/call", json!({"name":name,"arguments":arguments}))
            .await
    }
    async fn listening(&mut self) -> Value {
        timeout(Duration::from_secs(8), async {
            loop {
                let status = self.call("connection_status", json!({})).await;
                let status = &structured(&status)["result"]["status"];
                if status["network"]["listening"]
                    .as_array()
                    .is_some_and(|addresses| !addresses.is_empty())
                {
                    break status.clone();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap()
    }
    async fn pairing_state(&mut self, id: &str, phase: &str) -> Value {
        timeout(Duration::from_secs(12), async {
            loop {
                let status = self.call("pairing_status", json!({})).await;
                if let Some(view) = structured(&status)["result"]["requests"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|view| view["id"] == id && view["state"] == phase)
                {
                    break view.clone();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("pairing did not reach {phase}"))
    }
    async fn close(mut self) {
        drop(self.input.take());
        let status = timeout(Duration::from_secs(5), self.child.wait())
            .await
            .expect("MCP did not stop after stdin closed")
            .unwrap();
        assert!(status.success(), "MCP failed on clean EOF: {status}");
    }
}

fn failed(response: &Value) -> bool {
    response.get("error").is_some() || response["result"]["isError"] == true
}

fn structured(response: &Value) -> &Value {
    assert!(!failed(response), "{response}");
    &response["result"]["structuredContent"]
}

fn root() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("ab-mcp-")
        .tempdir_in("/tmp")
        .unwrap()
}

#[tokio::test]
async fn one_stdio_process_discovers_tools_and_routes_messages_with_safe_retries() {
    let root = root();
    let state = root.path().join("state");
    let running = Running::start(&state);
    running.inbox("alice");
    running.inbox("bob");
    let mut mcp = Mcp::start(&state);
    let pid = mcp.child.id();
    mcp.initialize().await;
    let tools = mcp.request("tools/list", json!({})).await;
    let tools = tools["result"]["tools"].as_array().unwrap();
    for name in [
        "connection_status",
        "send_message",
        "acknowledge_message",
        "connect_peer",
        "confirm_pairing",
        "share_session",
    ] {
        assert!(tools.iter().any(|tool| tool["name"] == name), "{name}");
    }
    assert!(!tools.iter().any(|tool| tool["name"] == "rpc"));
    assert_eq!(
        tools
            .iter()
            .find(|tool| tool["name"] == "connection_status")
            .unwrap()["annotations"]["readOnlyHint"],
        true
    );
    assert_ne!(
        tools
            .iter()
            .find(|tool| tool["name"] == "send_message")
            .unwrap()["annotations"]["readOnlyHint"],
        true
    );
    assert!(!failed(&mcp.call("connection_status", json!({})).await));
    let agents = mcp.call("list_agents", json!({})).await;
    assert!(
        structured(&agents)["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|agent| agent["name"] == "alice")
    );
    let body = "MCP test: quotes ' \" and newline\n$(this-is-data)";
    let sent = mcp
        .call(
            "send_message",
            json!({"from":"alice","to":"bob","body":body}),
        )
        .await;
    let id = structured(&sent)["id"].as_str().unwrap().to_owned();
    uuid::Uuid::parse_str(&id).unwrap();
    assert_eq!(structured(&sent)["result"]["id"], id);
    let repeated = mcp
        .call(
            "send_message",
            json!({"from":"alice","to":"bob","body":body,"id":id}),
        )
        .await;
    assert_eq!(structured(&repeated)["result"]["id"], id);
    let history = mcp
        .call("list_messages", json!({"agent":"bob","limit":10}))
        .await;
    let rows = structured(&history)["result"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["body"], body);
    timeout(Duration::from_secs(3), async {
        loop {
            let message = mcp.call("get_message", json!({"id":id})).await;
            if structured(&message)["result"]["state"] == "submitted" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let ack = mcp
        .call("acknowledge_message", json!({"id":id,"agent":"bob"}))
        .await;
    assert_eq!(structured(&ack)["result"]["state"], "acknowledged");
    assert_eq!(mcp.child.id(), pid);
    assert_eq!(running.request(Request::PeersList), json!([]));
    mcp.close().await;
}

#[tokio::test]
async fn strict_tools_reject_unknown_fields_and_cannot_supply_owner_approval() {
    let root = root();
    let state = root.path().join("state");
    let running = Running::start(&state);
    running.inbox("alice");
    let mut mcp = Mcp::start(&state);
    mcp.initialize().await;
    let bad = mcp
        .call("list_agents", json!({"remote":false,"op":"peer_pair"}))
        .await;
    assert!(failed(&bad), "{bad}");
    let unknown = mcp.request("agent_bridge/raw_rpc", json!({})).await;
    assert!(failed(&unknown), "{unknown}");
    let false_confirmation = mcp
        .call(
            "confirm_pairing",
            json!({"id":uuid::Uuid::new_v4().to_string(),"code":"1234-5678-9012","owner_confirmed":false}),
        )
        .await;
    assert!(failed(&false_confirmation), "{false_confirmation}");
    let absent_confirmation = mcp
        .call(
            "confirm_pairing",
            json!({"id":uuid::Uuid::new_v4().to_string(),"code":"1234-5678-9012"}),
        )
        .await;
    assert!(failed(&absent_confirmation), "{absent_confirmation}");
    running.request(Request::NetworkConfigure {
        enabled: true,
        listen: Some("/ip4/127.0.0.1/udp/0/quic-v1".into()),
    });
    let inbox_watch = mcp
        .call("open_pairing", json!({"agent":"alice","seconds":120}))
        .await;
    assert!(failed(&inbox_watch), "{inbox_watch}");
    assert_eq!(running.request(Request::LanPairingList)["open"], false);
    assert_eq!(running.request(Request::PeersList), json!([]));
    // A malformed tool call does not kill the persistent server.
    assert!(!failed(&mcp.call("connection_status", json!({})).await));
    mcp.close().await;
}

#[tokio::test]
async fn failed_send_returns_a_stable_retry_id_without_leaking_message_in_errors() {
    let root = root();
    let state = root.path().join("no-broker");
    let mut mcp = Mcp::start(&state);
    mcp.initialize().await;
    let body = "PRIVATE_MCP_ERROR_CANARY";
    let result = mcp
        .call(
            "send_message",
            json!({"from":"alice","to":"bob","body":body}),
        )
        .await;
    assert!(failed(&result));
    let id = result["result"]["structuredContent"]["id"]
        .as_str()
        .unwrap();
    uuid::Uuid::parse_str(id).unwrap();
    assert!(!result.to_string().contains(body));
    let retry = mcp
        .call(
            "send_message",
            json!({"from":"alice","to":"bob","body":body,"id":id}),
        )
        .await;
    assert_eq!(retry["result"]["structuredContent"]["id"], id);
    assert!(failed(&retry));
    mcp.close().await;
}

#[tokio::test]
async fn pipelined_calls_keep_request_ids_and_only_emit_json_rpc() {
    let root = root();
    let state = root.path().join("state");
    let _running = Running::start(&state);
    let mut mcp = Mcp::start(&state);
    mcp.initialize().await;
    for id in [101, 102] {
        mcp.write(&json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"connection_status","arguments":{}}}))
            .await;
    }
    let mut results = BTreeMap::new();
    for _ in 0..2 {
        let response = mcp.read().await;
        assert!(!failed(&response), "{response}");
        results.insert(response["id"].as_u64().unwrap(), response);
    }
    assert_eq!(results.keys().copied().collect::<Vec<_>>(), [101, 102]);
    mcp.close().await;
}

#[tokio::test]
async fn oversized_input_is_discarded_and_clean_eof_stops_the_server() {
    let root = root();
    let state = root.path().join("state");
    let _running = Running::start(&state);
    let mut mcp = Mcp::start(&state);
    mcp.initialize().await;
    // The SDK must reject the complete line before dispatch, then recover its
    // newline framing so the next bounded request still works.
    mcp.write(&json!({"jsonrpc":"2.0","id":999,"method":"tools/call","params":{"name":"send_message","arguments":{"from":"missing","to":"user","body":"x".repeat(MAX_FRAME + 1024)}}}))
        .await;
    assert!(!failed(&mcp.call("connection_status", json!({})).await));
    mcp.close().await;
}

#[tokio::test]
async fn modern_discovery_and_per_request_metadata_work_without_initialize() {
    let root = root();
    let state = root.path().join("state");
    let _running = Running::start(&state);
    let mut mcp = Mcp::start(&state);
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientInfo":{"name":"agent-bridge-modern-test","version":"1"},
        "io.modelcontextprotocol/clientCapabilities":{}
    });
    let discovered = mcp.request("server/discover", json!({"_meta":meta})).await;
    assert!(!failed(&discovered), "{discovered}");
    assert!(
        discovered["result"]["supportedVersions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|version| version == "2026-07-28")
    );
    let tools = mcp.request("tools/list", json!({"_meta":meta})).await;
    assert!(tools["result"]["tools"].as_array().is_some());
    let status = mcp
        .request(
            "tools/call",
            json!({"name":"connection_status","arguments":{},"_meta":meta}),
        )
        .await;
    assert!(!failed(&status), "{status}");
    mcp.close().await;
}

#[tokio::test]
async fn two_mcp_clients_pair_real_brokers_only_after_both_owners_approve_then_share_one_session() {
    let root = root();
    let a_state = root.path().join("a");
    let b_state = root.path().join("b");
    let a = Running::start(&a_state);
    let b = Running::start(&b_state);
    let a_native = Native::start(&a, &root.path().join("a-native"), "a-owner");
    let b_native = Native::start(&b, &root.path().join("b-native"), "b-owner");
    let mut a_mcp = Mcp::start(&a_state);
    let mut b_mcp = Mcp::start(&b_state);
    a_mcp.initialize().await;
    b_mcp.initialize().await;
    for client in [&mut a_mcp, &mut b_mcp] {
        let configured = client
            .call(
                "configure_network",
                json!({"enabled":true,"lan":false,"listen":"/ip4/127.0.0.1/udp/0/quic-v1"}),
            )
            .await;
        assert!(!failed(&configured), "{configured}");
    }
    a_mcp.listening().await;
    let b_status = b_mcp.listening().await;
    let b_peer = b_status["machine"]["peer_id"].as_str().unwrap().to_owned();
    let b_address = b_status["network"]["listening"][0].as_str().unwrap();
    let opened = b_mcp
        .call("open_pairing", json!({"agent":b_native.name,"seconds":120}))
        .await;
    assert!(!failed(&opened), "{opened}");
    let connected = a_mcp
        .call(
            "connect_peer",
            json!({"peer":b_peer,"address":b_address,"agent":a_native.name,"seconds":120}),
        )
        .await;
    let id = structured(&connected)["result"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let a_view = a_mcp.pairing_state(&id, "compare_code").await;
    let b_view = b_mcp.pairing_state(&id, "compare_code").await;
    assert_eq!(a_view["verification_code"], b_view["verification_code"]);
    let code = a_view["verification_code"].as_str().unwrap();
    let denied = a_mcp
        .call(
            "confirm_pairing",
            json!({"id":id,"code":code,"owner_confirmed":false}),
        )
        .await;
    assert!(failed(&denied), "{denied}");
    assert_eq!(a.request(Request::PeersList), json!([]));
    assert_eq!(b.request(Request::PeersList), json!([]));
    let a_confirmed = a_mcp
        .call(
            "confirm_pairing",
            json!({"id":id,"code":code,"owner_confirmed":true}),
        )
        .await;
    assert!(!failed(&a_confirmed), "{a_confirmed}");
    a_mcp.pairing_state(&id, "waiting_peer_confirmation").await;
    assert_eq!(a.request(Request::PeersList), json!([]));
    assert_eq!(b.request(Request::PeersList), json!([]));
    let b_confirmed = b_mcp
        .call(
            "confirm_pairing",
            json!({"id":id,"code":code,"owner_confirmed":true}),
        )
        .await;
    assert!(!failed(&b_confirmed), "{b_confirmed}");
    a_mcp.pairing_state(&id, "paired").await;
    b_mcp.pairing_state(&id, "paired").await;
    assert_eq!(a.request(Request::PeersList)[0]["grants"], json!([]));
    assert_eq!(b.request(Request::PeersList)[0]["grants"], json!([]));
    let shared = a_mcp
        .call(
            "share_session",
            json!({"peer":b_peer,"agent":a_native.name}),
        )
        .await;
    assert!(!failed(&shared), "{shared}");
    let a_peers = a.request(Request::PeersList);
    let grants = a_peers[0]["grants"].as_array().unwrap();
    assert_eq!(grants.len(), 3);
    assert!(
        grants
            .iter()
            .all(|grant| grant["session"] == a_native.session)
    );
    assert_eq!(b.request(Request::PeersList)[0]["grants"], json!([]));
    let unshared = a_mcp
        .call(
            "unshare_session",
            json!({"peer":b_peer,"agent":a_native.name}),
        )
        .await;
    assert!(!failed(&unshared), "{unshared}");
    assert_eq!(a.request(Request::PeersList)[0]["grants"], json!([]));
    a_mcp.close().await;
    b_mcp.close().await;
}
