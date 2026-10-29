use agent_bridge::{
    db::Db,
    protocol::{Agent, Provider},
};

fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}
fn agent(name: &str) -> Agent {
    Agent {
        name: name.into(),
        provider: Provider::Inbox,
        session: id(),
        endpoint: String::new(),
        enabled: true,
    }
}

#[test]
fn duplicate_send_is_idempotent_but_conflicting_reuse_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let dbpath = temp.path().join("db");
    let mut db = Db::open(&dbpath).unwrap();
    db.register(&agent("worker"), false).unwrap();
    let mid = id();
    db.send(&mid, "user", "worker", "first", &None, None)
        .unwrap();
    assert_eq!(
        db.send(&mid, "user", "worker", "first", &None, None)
            .unwrap()
            .id,
        mid
    );
    assert!(
        db.send(&mid, "user", "worker", "different", &None, None)
            .is_err()
    );
    assert_eq!(db.history(&None, 50).unwrap().len(), 1);
}

#[test]
fn crash_preserves_queued_and_quarantines_in_flight() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("db");
    let mut db = Db::open(&path).unwrap();
    db.register(&agent("worker"), false).unwrap();
    let first = id();
    let second = id();
    db.send(&first, "user", "worker", "first", &None, None)
        .unwrap();
    db.send(&second, "user", "worker", "second", &None, None)
        .unwrap();
    assert_eq!(db.claim().unwrap().unwrap().0.id, first);
    drop(db);
    let db = Db::open(&path).unwrap();
    assert_eq!(db.get(&first).unwrap().state, "uncertain");
    assert_eq!(db.get(&second).unwrap().state, "queued");
    assert!(db.retry(&first, false).is_err());
    db.retry(&first, true).unwrap();
}

#[test]
fn recipient_replacement_never_redirects_pending_work() {
    let temp = tempfile::tempdir().unwrap();
    let mut db = Db::open(&temp.path().join("db")).unwrap();
    let old = agent("worker");
    db.register(&old, false).unwrap();
    let mid = id();
    db.send(&mid, "user", "worker", "for old session", &None, None)
        .unwrap();
    let new = agent("worker");
    assert!(db.register(&new, false).is_err());
    db.register(&new, true).unwrap();
    assert_eq!(db.get(&mid).unwrap().state, "failed");
    assert!(db.retry(&mid, false).is_err());
    assert!(db.claim().unwrap().is_none());
    // A delayed SessionEnd from the previous session cannot unregister its replacement.
    db.unregister("worker", &old.session).unwrap();
    assert!(db.agent("worker").unwrap().enabled);
}

#[test]
fn one_in_flight_per_recipient_preserves_fifo_without_blocking_other_agents() {
    let temp = tempfile::tempdir().unwrap();
    let mut db = Db::open(&temp.path().join("db")).unwrap();
    db.register(&agent("a"), false).unwrap();
    db.register(&agent("b"), false).unwrap();
    let a1 = id();
    let a2 = id();
    let b1 = id();
    db.send(&a1, "user", "a", "a1", &None, None).unwrap();
    db.send(&a2, "user", "a", "a2", &None, None).unwrap();
    db.send(&b1, "user", "b", "b1", &None, None).unwrap();
    assert_eq!(db.claim().unwrap().unwrap().0.id, a1);
    assert_eq!(db.claim().unwrap().unwrap().0.id, b1);
    assert!(db.claim().unwrap().is_none());
    db.finish(&a1, "submitted", "sent").unwrap();
    assert_eq!(db.claim().unwrap().unwrap().0.id, a2);
}

#[test]
fn fast_ack_cannot_be_overwritten_by_transport_completion() {
    let temp = tempfile::tempdir().unwrap();
    let mut db = Db::open(&temp.path().join("db")).unwrap();
    db.register(&agent("worker"), false).unwrap();
    let mid = id();
    db.send(&mid, "user", "worker", "message", &None, None)
        .unwrap();
    db.claim().unwrap();
    assert!(db.ack(&mid, "user").is_err());
    db.ack(&mid, "worker").unwrap();
    db.finish(&mid, "submitted", "transport finished later")
        .unwrap();
    assert_eq!(db.get(&mid).unwrap().state, "acknowledged");
    assert!(db.retry(&mid, true).is_err());
}

#[test]
fn pause_and_offline_registration_hold_work_until_resume() {
    let temp = tempfile::tempdir().unwrap();
    let mut db = Db::open(&temp.path().join("db")).unwrap();
    let worker = agent("worker");
    db.register(&worker, false).unwrap();
    db.send(&id(), "user", "worker", "wait", &None, None)
        .unwrap();
    db.pause(true).unwrap();
    assert!(db.claim().unwrap().is_none());
    db.pause(false).unwrap();
    db.unregister("worker", &worker.session).unwrap();
    assert!(db.claim().unwrap().is_none());
    db.register(&worker, false).unwrap();
    assert!(db.claim().unwrap().is_some());
}

#[test]
fn replies_are_correlated_and_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let mut db = Db::open(&temp.path().join("db")).unwrap();
    db.register(&agent("a"), false).unwrap();
    db.register(&agent("b"), false).unwrap();
    let mut parent = id();
    db.send(&parent, "a", "b", "start", &None, None).unwrap();
    assert!(
        db.send(
            &id(),
            "a",
            "b",
            "forged parent",
            &Some(parent.clone()),
            None
        )
        .is_err()
    );
    let (mut sender, mut recipient) = ("b", "a");
    for hop in 1..=8 {
        let next = id();
        assert_eq!(
            db.send(&next, sender, recipient, "reply", &Some(parent), None)
                .unwrap()
                .hops,
            hop
        );
        parent = next;
        std::mem::swap(&mut sender, &mut recipient);
    }
    assert!(
        db.send(&id(), sender, recipient, "loop", &Some(parent), None)
            .is_err()
    );
}

#[test]
fn submitted_requires_explicit_duplicate_override_and_queued_can_cancel() {
    let temp = tempfile::tempdir().unwrap();
    let mut db = Db::open(&temp.path().join("db")).unwrap();
    db.register(&agent("worker"), false).unwrap();
    let mid = id();
    db.send(&mid, "user", "worker", "message", &None, None)
        .unwrap();
    db.claim().unwrap();
    db.finish(&mid, "submitted", "sent").unwrap();
    assert!(db.retry(&mid, false).is_err());
    assert!(db.cancel(&mid).is_err());
    db.retry(&mid, true).unwrap();
    db.cancel(&mid).unwrap();
    assert!(db.claim().unwrap().is_none());
}

#[test]
fn reply_outcome_is_durable_and_part_of_idempotency() {
    use agent_bridge::protocol::TaskOutcome;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("db");
    let mut db = Db::open(&path).unwrap();
    db.register(&agent("worker"), false).unwrap();
    assert!(
        db.send(
            &id(),
            "worker",
            "user",
            "done",
            &None,
            Some(TaskOutcome::Succeeded)
        )
        .unwrap_err()
        .to_string()
        .contains("Outcome requires a reply parent")
    );
    let parent = id();
    db.send(&parent, "user", "worker", "task", &None, None)
        .unwrap();
    for outcome in [TaskOutcome::Succeeded, TaskOutcome::Failed] {
        let reply = id();
        let parent = Some(parent.clone());
        let sent = db
            .send(&reply, "worker", "user", "report", &parent, Some(outcome))
            .unwrap();
        assert_eq!(sent.outcome, Some(outcome));
        assert_eq!(
            db.send(&reply, "worker", "user", "report", &parent, Some(outcome))
                .unwrap()
                .id,
            reply
        );
        for conflicting in [
            None,
            Some(if outcome == TaskOutcome::Succeeded {
                TaskOutcome::Failed
            } else {
                TaskOutcome::Succeeded
            }),
        ] {
            assert!(
                db.send(&reply, "worker", "user", "report", &parent, conflicting)
                    .is_err()
            );
        }
        drop(db);
        db = Db::open(&path).unwrap();
        assert_eq!(db.get(&reply).unwrap().outcome, Some(outcome));
        assert_eq!(db.history(&None, 1).unwrap()[0].outcome, Some(outcome));
        assert_eq!(db.get(parent.as_ref().unwrap()).unwrap().outcome, None);
    }
}
