use agent_bridge::{broker::Broker, db::Db, discovery, protocol::Request};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::{
    net::UnixListener,
    time::{sleep, timeout},
};

fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[test]
fn native_aliases_follow_renames_but_messages_stay_pinned_and_duplicate_names_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = Db::open(&dir.path().join("db")).unwrap();
    let first = id();
    db.observe_codex(&first, Some("Native agent with spaces"), true)
        .unwrap();
    let mid = id();
    let sent = db
        .send(&mid, "user", "Native agent with spaces", "first", &None)
        .unwrap();
    assert_eq!(sent.recipient_session, first);
    db.observe_codex(&first, Some("Renamed agent"), true)
        .unwrap();
    assert!(db.resolve_agent("Native agent with spaces").is_err());
    assert_eq!(db.resolve_agent("Renamed agent").unwrap().session, first);
    assert_eq!(db.get(&mid).unwrap().recipient_session, first);
    let second = id();
    db.observe_codex(&second, Some("Renamed agent"), true)
        .unwrap();
    assert!(db.resolve_agent("Renamed agent").is_err());
    db.codex_offline(Some(&second)).unwrap();
    assert_eq!(db.resolve_agent("Renamed agent").unwrap().session, first);
    db.codex_offline(None).unwrap();
    assert!(db.resolve_agent("Renamed agent").is_err());
    assert_eq!(db.get(&mid).unwrap().state, "queued");
}

async fn wait_for(broker: &Broker, check: impl Fn(&Value) -> bool) {
    timeout(Duration::from_secs(3), async {
        loop {
            let agents = broker.request(Request::List { all: true }).unwrap();
            if check(&agents) {
                return;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn observer_discovers_loaded_sessions_and_follows_native_events_without_resuming_or_starting_them()
 {
    let dir = tempfile::Builder::new()
        .prefix("abd-")
        .tempdir_in("/tmp")
        .unwrap();
    let home = dir.path().join("codex-home");
    std::fs::create_dir(&home).unwrap();
    let socket = dir.path().join("native.sock");
    let native = UnixListener::bind(&socket).unwrap();
    let bound = Broker::bind(dir.path().join("state"), "/missing/codex".into()).unwrap();
    let broker = bound.broker.clone();
    let observer =
        tokio::spawn(async move { discovery::observe_connection(&broker, &socket, &home).await });
    let (stream, _) = native.accept().await.unwrap();
    let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
    async fn recv(ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::UnixStream>) -> Value {
        let m = timeout(Duration::from_secs(3), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        serde_json::from_str(m.to_text().unwrap()).unwrap()
    }
    async fn send(ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::UnixStream>, v: Value) {
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            v.to_string().into(),
        ))
        .await
        .unwrap();
    }
    let init = recv(&mut ws).await;
    assert_eq!(init["method"], "initialize");
    send(
        &mut ws,
        json!({"id":init["id"],"result":{"codexHome":dir.path().join("codex-home")}}),
    )
    .await;
    assert_eq!(recv(&mut ws).await["method"], "initialized");
    let list = recv(&mut ws).await;
    assert_eq!(list["method"], "thread/loaded/list");
    let session = id();
    send(
        &mut ws,
        json!({"id":list["id"],"result":{"data":[session],"nextCursor":null}}),
    )
    .await;
    let read = recv(&mut ws).await;
    assert_eq!(read["method"], "thread/read");
    assert_eq!(read["params"]["threadId"], session);
    send(&mut ws,json!({"id":read["id"],"result":{"thread":{"id":session,"name":"native-test","status":{"type":"idle"}}}})).await;
    wait_for(&bound.broker, |a| {
        a.as_array()
            .unwrap()
            .iter()
            .any(|x| x["display_name"] == "native-test")
    })
    .await;
    send(&mut ws,json!({"method":"thread/name/updated","params":{"threadId":session,"threadName":"renamed-test"}})).await;
    let read = recv(&mut ws).await;
    assert_eq!(read["method"], "thread/read");
    send(&mut ws,json!({"id":read["id"],"result":{"thread":{"id":session,"name":"renamed-test","status":{"type":"idle"}}}})).await;
    wait_for(&bound.broker, |a| {
        a.as_array()
            .unwrap()
            .iter()
            .any(|x| x["display_name"] == "renamed-test")
    })
    .await;
    let sent = bound
        .broker
        .request(Request::Send {
            id: id(),
            sender: "user".into(),
            recipient: "renamed-test".into(),
            body: "test".into(),
            parent: None,
        })
        .unwrap();
    assert_eq!(sent["recipient_session"], session);
    send(
        &mut ws,
        json!({"method":"thread/closed","params":{"threadId":session}}),
    )
    .await;
    wait_for(&bound.broker, |a| {
        a.as_array()
            .unwrap()
            .iter()
            .any(|x| x["session"] == session && x["enabled"] == false)
    })
    .await;
    observer.abort();
    let _ = observer.await;
}

#[tokio::test]
async fn default_list_hides_exited_sessions_and_all_preserves_history_and_restart_identity() {
    let dir = tempfile::Builder::new()
        .prefix("abl-")
        .tempdir_in("/tmp")
        .unwrap();
    let bound = Broker::bind(dir.path().join("state"), "/missing/codex".into()).unwrap();
    let session = id();
    let thread = json!({"id":session,"name":"returning-peer","status":{"type":"idle"}});
    bound.broker.observe_codex(&thread).unwrap();
    let mid = id();
    bound
        .broker
        .request(Request::Send {
            id: mid.clone(),
            sender: "user".into(),
            recipient: "returning-peer".into(),
            body: "retained".into(),
            parent: None,
        })
        .unwrap();
    bound.broker.codex_offline(Some(&session)).unwrap();
    // Existing clients omitting the new field also get the available-only default.
    let default: Request = serde_json::from_value(json!({"op":"list"})).unwrap();
    let listed = bound.broker.request(default).unwrap();
    assert!(
        !listed
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["session"] == session)
    );
    assert!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["enabled"] == true)
    );
    let all = bound.broker.request(Request::List { all: true }).unwrap();
    assert!(
        all.as_array()
            .unwrap()
            .iter()
            .any(|a| a["session"] == session && a["enabled"] == false)
    );
    let message = bound.broker.request(Request::Get { id: mid }).unwrap();
    assert_eq!(message["body"], "retained");
    assert_eq!(message["recipient_session"], session);
    bound.broker.observe_codex(&thread).unwrap();
    let listed = bound.broker.request(Request::List { all: false }).unwrap();
    assert!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["session"] == session && a["enabled"] == true)
    );
}
