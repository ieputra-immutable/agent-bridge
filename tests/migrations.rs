use agent_bridge::{db::Db, migrations::SCHEMA_VERSION, protocol::Provider};
use rusqlite::Connection;

// This fixture is the unversioned schema shipped before migration support.
const LEGACY: &str = "
CREATE TABLE agents(name TEXT PRIMARY KEY,provider TEXT NOT NULL,session TEXT NOT NULL,endpoint TEXT NOT NULL,enabled INTEGER NOT NULL);
CREATE TABLE messages(id TEXT PRIMARY KEY,sender TEXT NOT NULL,recipient TEXT NOT NULL,recipient_session TEXT NOT NULL,body TEXT NOT NULL,parent TEXT,hops INTEGER NOT NULL,state TEXT NOT NULL,detail TEXT,created INTEGER NOT NULL,updated INTEGER NOT NULL);
CREATE INDEX messages_delivery ON messages(state,recipient,created);
CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE native_codex(session TEXT PRIMARY KEY,display_name TEXT);
CREATE TABLE native_claude(session TEXT PRIMARY KEY,display_name TEXT);
INSERT INTO settings VALUES('paused','true');
INSERT INTO agents VALUES('user','inbox','user','',1),('receiver','inbox','receiver-session','',1);
INSERT INTO native_codex VALUES('codex-session','A title');
INSERT INTO native_claude VALUES('claude-session','Another title');
INSERT INTO messages VALUES('queued-id','user','receiver','receiver-session','hello',NULL,0,'queued',NULL,10,10),('sending-id','user','receiver','receiver-session','in flight',NULL,0,'sending',NULL,11,11);
";

#[test]
fn legacy_database_migrates_without_losing_messages_or_registrations() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(LEGACY).unwrap();
    drop(conn);
    let db = Db::open(&path).unwrap();
    assert!(db.paused().unwrap());
    assert_eq!(db.agent("receiver").unwrap().session, "receiver-session");
    assert_eq!(db.get("queued-id").unwrap().state, "queued");
    assert_eq!(db.get("sending-id").unwrap().state, "uncertain");
    assert_eq!(
        db.display_name(&Provider::Codex, "codex-session")
            .unwrap()
            .as_deref(),
        Some("A title")
    );
    assert_eq!(
        db.display_name(&Provider::Claude, "claude-session")
            .unwrap()
            .as_deref(),
        Some("Another title")
    );
    assert!(db.peers().unwrap().is_empty());
    drop(db);
    let conn = Connection::open(&path).unwrap();
    assert_eq!(
        conn.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        SCHEMA_VERSION
    );
    drop(conn);
    let db = Db::open(&path).unwrap();
    assert_eq!(db.history(&None, 100).unwrap().len(), 2);
}

#[test]
fn future_schema_is_rejected_before_journal_or_data_changes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(LEGACY).unwrap();
    conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
        .unwrap();
    drop(conn);
    let before = std::fs::read(&path).unwrap();
    assert!(Db::open(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let conn = Connection::open(&path).unwrap();
    assert_eq!(
        conn.pragma_query_value::<String, _>(None, "journal_mode", |r| r.get(0))
            .unwrap(),
        "delete"
    );
    assert_eq!(
        conn.query_row::<String, _, _>(
            "SELECT state FROM messages WHERE id='sending-id'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        "sending"
    );
}

#[test]
fn migration_failure_rolls_back_schema_and_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TABLE peers(unexpected TEXT);")
        .unwrap();
    drop(conn);
    assert!(Db::open(&path).is_err());
    let conn = Connection::open(&path).unwrap();
    assert_eq!(
        conn.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        0
    );
    assert_eq!(
        conn.query_row::<i64, _, _>(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='agents'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn version_one_database_adds_trust_tables_without_reinitializing_settings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(LEGACY).unwrap();
    conn.pragma_update(None, "user_version", 1).unwrap();
    drop(conn);
    let db = Db::open(&path).unwrap();
    assert!(db.paused().unwrap());
    assert!(db.peers().unwrap().is_empty());
    assert_eq!(db.history(&None, 100).unwrap().len(), 2);
}
