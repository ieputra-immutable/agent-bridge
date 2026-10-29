-- Restore the title tables when reconstructing an older numbered fixture from
-- a current database. This is test setup, not a supported database downgrade.
CREATE TABLE native_claude(session TEXT PRIMARY KEY,display_name TEXT);
CREATE TABLE native_codex(session TEXT PRIMARY KEY,display_name TEXT);
INSERT INTO native_claude SELECT session,display_name FROM session_metadata WHERE provider='claude';
INSERT INTO native_codex SELECT session,display_name FROM session_metadata WHERE provider='codex';
DROP TABLE session_metadata;
