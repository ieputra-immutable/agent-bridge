use agent_bridge::{
    broker::Broker,
    claude_discovery::{self, Titles},
    db::Db,
    protocol::{Agent, Provider, Request},
};
use serde_json::{Value, json};
use std::{io::Write, time::Duration};

fn agent(session: &str) -> Agent {
    Agent {
        name: format!("claude-{session}"),
        provider: Provider::Claude,
        session: session.into(),
        endpoint: String::new(),
        enabled: true,
    }
}

#[test]
fn provider_qualified_names_distinguish_cross_provider_collisions_and_manual_aliases() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = Db::open(&dir.path().join("db")).unwrap();
    let cc = uuid::Uuid::new_v4().to_string();
    let cx = uuid::Uuid::new_v4().to_string();
    db.register(&agent(&cc), false).unwrap();
    db.observe_claude_name(&cc, "same-name").unwrap();
    db.observe_codex(&cx, Some("same-name"), true).unwrap();
    assert!(db.resolve_agent("same-name").is_err());
    assert_eq!(db.resolve_agent("claude:same-name").unwrap().session, cc);
    assert_eq!(db.resolve_agent("codex:same-name").unwrap().session, cx);
    let mut alias = db.resolve_agent(&format!("codex-{cx}")).unwrap();
    alias.name = "same-name".into();
    db.register(&alias, false).unwrap();
    assert_eq!(db.resolve_agent("same-name").unwrap().session, cx);
    assert_eq!(db.resolve_agent("claude:same-name").unwrap().session, cc);
    db.observe_claude_name(&cc, "renamed").unwrap();
    assert!(db.resolve_agent("claude:same-name").is_err());
    assert_eq!(db.resolve_agent("claude:renamed").unwrap().session, cc);
    let other = uuid::Uuid::new_v4().to_string();
    db.register(&agent(&other), false).unwrap();
    db.observe_claude_name(&other, "renamed").unwrap();
    assert!(db.resolve_agent("claude:renamed").is_err());
}

fn append(path: &std::path::Path, value: Value) {
    writeln!(
        std::fs::OpenOptions::new().append(true).open(path).unwrap(),
        "{value}"
    )
    .unwrap();
}
async fn wait_title(broker: &Broker, title: &str) {
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            if broker
                .request(Request::List { all: false })
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .any(|a| {
                    a["display_name"] == title && a["qualified_name"] == format!("claude:{title}")
                })
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn claude_titles_follow_filesystem_events_and_recover_partial_writes_and_replaced_files() {
    let dir = tempfile::Builder::new()
        .prefix("abc-")
        .tempdir_in("/tmp")
        .unwrap();
    let projects = dir.path().join("projects");
    let project = projects.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let session = uuid::Uuid::new_v4().to_string();
    let path = project.join(format!("{session}.jsonl"));
    std::fs::write(&path, "").unwrap();
    append(
        &path,
        json!({"type":"custom-title","sessionId":session,"customTitle":"before-start"}),
    );
    append(
        &path,
        json!({"type":"agent-name","sessionId":"wrong-session","agentName":"ignore-me"}),
    );
    let bound = Broker::bind(dir.path().join("state"), "/missing/codex".into()).unwrap();
    let socket = dir.path().join("cc.sock");
    let _listener = tokio::net::UnixListener::bind(&socket).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut cc = agent(&session);
    cc.endpoint = socket.to_string_lossy().into();
    bound
        .broker
        .request(Request::Register {
            agent: cc,
            replace: false,
        })
        .unwrap();
    let broker = bound.broker.clone();
    let root = projects.clone();
    let task = tokio::spawn(async move { claude_discovery::observe(&broker, &root).await });
    wait_title(&bound.broker, "before-start").await;
    append(
        &path,
        json!({"type":"agent-name","sessionId":session,"agentName":"native-rename"}),
    );
    wait_title(&bound.broker, "native-rename").await;
    task.abort();
    let _ = task.await;

    let mut titles = Titles::default();
    titles.refresh(&bound.broker, &projects).unwrap();
    let partial = json!({"type":"custom-title","sessionId":session,"customTitle":"partial-write"})
        .to_string();
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    f.write_all(&partial.as_bytes()[..10]).unwrap();
    titles.refresh(&bound.broker, &projects).unwrap();
    wait_title(&bound.broker, "native-rename").await;
    writeln!(f, "{}", &partial[10..]).unwrap();
    titles.refresh(&bound.broker, &projects).unwrap();
    wait_title(&bound.broker, "partial-write").await;
    let replacement = project.join("replacement");
    std::fs::write(
        &replacement,
        format!(
            "{}\n",
            json!({"type":"custom-title","sessionId":session,"customTitle":"replacement"})
        ),
    )
    .unwrap();
    std::fs::rename(replacement, &path).unwrap();
    titles.refresh(&bound.broker, &projects).unwrap();
    wait_title(&bound.broker, "replacement").await;
}
