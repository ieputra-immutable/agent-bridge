use agent_bridge::{
    db::Db,
    protocol::{Agent, Provider},
};

fn register(db: &mut Db, provider: Provider, session: &str, name: Option<&str>) -> String {
    let route = format!("{}-{session}", provider.label());
    db.register(
        &Agent {
            name: route.clone(),
            provider: provider.clone(),
            session: session.into(),
            endpoint: String::new(),
            enabled: true,
        },
        false,
    )
    .unwrap();
    db.observe_session_name(&provider, session, name).unwrap();
    route
}

#[test]
fn metadata_is_separate_from_registration_and_names_preserve_identity() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = Db::open(&dir.path().join("db")).unwrap();
    let s1 = uuid::Uuid::new_v4().to_string();
    let s2 = uuid::Uuid::new_v4().to_string();
    db.observe_session_name(&Provider::Claude, &s1, Some("stale"))
        .unwrap();
    assert!(db.resolve_agent("stale").is_err());
    let claude = register(&mut db, Provider::Claude, &s1, Some("shared"));
    let codex = register(&mut db, Provider::Codex, &s1, Some("shared"));
    assert!(db.resolve_agent("shared").is_err());
    assert_eq!(db.resolve_agent("claude:shared").unwrap().name, claude);
    assert_eq!(db.resolve_agent("codex:shared").unwrap().name, codex);
    let duplicate = register(&mut db, Provider::Claude, &s2, Some("shared"));
    assert!(db.resolve_agent("claude:shared").is_err());
    db.unregister(&duplicate, &s2).unwrap();
    assert_eq!(db.resolve_agent("claude:shared").unwrap().name, claude);
    db.register(
        &Agent {
            name: "shared".into(),
            provider: Provider::Inbox,
            session: "manual".into(),
            endpoint: String::new(),
            enabled: true,
        },
        false,
    )
    .unwrap();
    assert_eq!(db.resolve_agent("shared").unwrap().session, "manual");
    db.observe_session_name(&Provider::Claude, &s1, Some("renamed"))
        .unwrap();
    assert_eq!(db.resolve_agent("renamed").unwrap().name, claude);
    assert!(db.resolve_agent("claude:shared").is_err());
    db.unregister(&claude, &s1).unwrap();
    assert!(db.resolve_agent("renamed").is_err());
    db.observe_session_name(&Provider::Claude, &s1, None)
        .unwrap();
    assert_eq!(db.display_name(&Provider::Claude, &s1).unwrap(), None);
    db.observe_session_name(&Provider::Claude, &s1, Some(""))
        .unwrap();
    assert_eq!(
        db.display_name(&Provider::Claude, &s1).unwrap().as_deref(),
        Some("")
    );
    assert!(db.resolve_agent("unknown:shared").is_err());
    assert!("unknown".parse::<Provider>().is_err());
    assert!(
        db.observe_session_name(&Provider::Claude, "invalid", Some("bad"))
            .is_err()
    );
    assert_eq!(db.resolve_agent("user").unwrap().provider, Provider::Inbox);
    assert!(
        db.observe_session_name(&Provider::Inbox, "user", Some("inbox title"))
            .is_err()
    );
    assert_eq!(db.display_name(&Provider::Inbox, "user").unwrap(), None);
    let untitled = register(&mut db, Provider::Codex, &s2, None);
    assert!(db.resolve_agent(&untitled).unwrap().enabled);
    db.observe_session_name(&Provider::Codex, &s2, Some(""))
        .unwrap();
    assert_eq!(db.resolve_agent("codex:").unwrap().name, untitled);
    db.codex_offline(Some(&s2)).unwrap();
    assert!(!db.agent(&untitled).unwrap().enabled);
}
