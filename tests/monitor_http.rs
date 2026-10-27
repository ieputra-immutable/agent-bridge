use agent_bridge::{
    broker::{self, Broker},
    protocol::Request,
};
use serde_json::Value;
use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

struct Running {
    broker: Broker,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}
impl Running {
    fn start(path: &Path) -> Self {
        let bound = Broker::bind(path.into(), "/missing/codex".into()).unwrap();
        let broker = bound.broker.clone();
        let task = tokio::spawn(broker::serve(bound));
        Self { broker, task }
    }
    async fn enable(&self, port: u16) -> Value {
        self.broker
            .request_async(Request::MonitorEnable { port })
            .await
            .unwrap()
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn host(access: &Value) -> String {
    access["url"]
        .as_str()
        .unwrap()
        .strip_prefix("http://")
        .unwrap()
        .into()
}
fn key(access: &Value) -> &str {
    access["access_token"].as_str().unwrap()
}
async fn connect(access: &Value, path: &str, headers: &str) -> TcpStream {
    let target = host(access);
    let mut stream = TcpStream::connect(&target).await.unwrap();
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: {target}\r\n{headers}\r\n").as_bytes())
        .await
        .unwrap();
    stream
}
async fn get(access: &Value, path: &str, headers: &str) -> String {
    let mut stream = connect(access, path, headers).await;
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(3), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8(bytes).unwrap()
}
fn auth(access: &Value) -> String {
    format!("Authorization: Bearer {}\r\n", key(access))
}
async fn first_event(stream: &mut TcpStream) -> String {
    timeout(Duration::from_secs(3), async {
        let mut bytes = Vec::new();
        let mut buf = [0; 1024];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            assert_ne!(n, 0, "SSE closed before first event");
            bytes.extend_from_slice(&buf[..n]);
            if bytes
                .windows(b"event: revision".len())
                .any(|b| b == b"event: revision")
            {
                break;
            }
        }
        String::from_utf8(bytes).unwrap()
    })
    .await
    .unwrap()
}
#[tokio::test]
async fn monitor_requires_bearer_and_enforces_browser_boundaries_on_assets_and_api() {
    let root = tempfile::Builder::new()
        .prefix("ab-http-")
        .tempdir_in("/tmp")
        .unwrap();
    let running = Running::start(root.path());
    let status = running.broker.request(Request::MonitorStatus).unwrap();
    assert_eq!(status["enabled"], false);
    assert!(status.get("access_token").is_none());
    let access = running.enable(0).await;
    assert!(key(&access).len() >= 43);
    assert!(
        !running.broker.request(Request::Status).unwrap()["network"]["enabled"]
            .as_bool()
            .unwrap()
    );
    let page = get(&access, "/", "").await;
    assert!(page.starts_with("HTTP/1.1 200"));
    assert!(page.contains("content-security-policy:"));
    assert!(page.contains("cache-control: no-store"));
    assert!(!page.contains(key(&access)));
    assert!(
        get(&access, "/api/messages", "")
            .await
            .starts_with("HTTP/1.1 401")
    );
    assert!(
        get(&access, "/api/status", &auth(&access))
            .await
            .starts_with("HTTP/1.1 200")
    );
    for extra in [
        "Origin: https://evil.example\r\n",
        "Origin: null\r\n",
        "Sec-Fetch-Site: cross-site\r\n",
        "Sec-Fetch-Site: same-site\r\n",
    ] {
        for path in ["/", "/app.js", "/api/messages"] {
            let result = get(&access, path, &format!("{}{extra}", auth(&access))).await;
            assert!(result.starts_with("HTTP/1.1 403"), "{result}");
            assert!(result.contains("cache-control: no-store"));
        }
    }
    let mut socket = TcpStream::connect(host(&access)).await.unwrap();
    socket
        .write_all(
            format!(
                "GET /api/status HTTP/1.1\r\nHost: evil.example\r\n{}\r\n",
                auth(&access)
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    socket.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.starts_with(b"HTTP/1.1 403"));
    let same_origin = format!(
        "{}Origin: {}\r\nSec-Fetch-Site: same-origin\r\n",
        auth(&access),
        access["url"].as_str().unwrap()
    );
    assert!(
        get(&access, "/api/status", &same_origin)
            .await
            .starts_with("HTTP/1.1 200")
    );
    assert!(
        get(
            &access,
            "/api/status",
            &format!("{}{}", auth(&access), auth(&access))
        )
        .await
        .starts_with("HTTP/1.1 401")
    );
    for path in [
        "/api/messages?access_token=secret",
        "/api/messages?limit=100000",
        "/api/messages?limit=0",
        "/api/messages?machine=a&machine=b",
        "/api/status?token=secret",
    ] {
        assert!(
            get(&access, path, &auth(&access))
                .await
                .starts_with("HTTP/1.1 400"),
            "{path}"
        );
    }
    assert!(!root.path().join("identity.key").exists());
}
#[tokio::test]
async fn disabling_monitor_closes_live_streams_and_rotates_credentials_independently_of_networking()
{
    let root = tempfile::Builder::new()
        .prefix("ab-http-live-")
        .tempdir_in("/tmp")
        .unwrap();
    let running = Running::start(root.path());
    let access = running.enable(0).await;
    let mut stream = connect(&access, "/api/events", &auth(&access)).await;
    let first = first_event(&mut stream).await;
    assert!(first.starts_with("HTTP/1.1 200"));
    assert!(!first.contains(key(&access)));
    let same = running.enable(0).await;
    assert_eq!(same["url"], access["url"]);
    assert_eq!(same["access_token"], access["access_token"]);
    running.broker.request(Request::MonitorDisable).unwrap();
    let mut rest = Vec::new();
    timeout(Duration::from_secs(2), stream.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    let current = running.enable(0).await;
    assert_ne!(current["access_token"], access["access_token"]);
    assert!(
        get(&current, "/api/status", &auth(&access))
            .await
            .starts_with("HTTP/1.1 401")
    );
    assert!(
        get(&current, "/api/status", &auth(&current))
            .await
            .starts_with("HTTP/1.1 200")
    );
}
#[tokio::test]
async fn occupied_port_reports_failure_without_disrupting_the_broker() {
    let root = tempfile::Builder::new()
        .prefix("ab-http-busy-")
        .tempdir_in("/tmp")
        .unwrap();
    let running = Running::start(root.path());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    assert!(
        running
            .broker
            .request_async(Request::MonitorEnable { port })
            .await
            .is_err()
    );
    assert!(running.broker.request(Request::List { all: false }).is_ok());
    assert!(
        running
            .broker
            .request(Request::MonitorStatus)
            .unwrap()
            .get("access_token")
            .is_none()
    );
    running.broker.request(Request::MonitorDisable).unwrap();
    assert!(running.enable(0).await["url"].is_string());
}
