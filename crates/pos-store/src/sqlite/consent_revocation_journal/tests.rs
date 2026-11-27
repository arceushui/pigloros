//! ADR-137 I1: the journal table's row shapes, its single-`Pending` index, the
//! `events` lookup index, and the exact-shape validation of a writable open.

use rusqlite::{params, types::Value, Connection};

use crate::sqlite::SqliteStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TABLE: &str = "consent_revocation_journal";
const PENDING_INDEX: &str = "consent_revocation_single_pending";
const EVENTS_INDEX: &str = "idx_events_entity_type";

/// One journal row, field by field, so a test can break exactly one field.
#[derive(Clone)]
struct Row {
    seq: Value,
    operation: Value,
    generation: Value,
    timeline: Value,
    subject: Value,
    grantee: Value,
    grant_seq: Value,
    fence: Value,
    digest: Value,
    state: Value,
    abort: Value,
    event: Value,
}

impl Row {
    /// A well-formed `Pending` row; `tag` makes its sequence and operation unique.
    fn pending(tag: u8) -> Self {
        Self {
            seq: Value::Integer(i64::from(tag)),
            operation: Value::Blob(vec![tag; 16]),
            generation: Value::Integer(1),
            timeline: Value::Text("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned()),
            subject: Value::Text("subject".to_owned()),
            grantee: Value::Text("grantee".to_owned()),
            grant_seq: Value::Integer(1),
            fence: Value::Integer(2),
            digest: Value::Blob(vec![7; 32]),
            state: Value::Integer(1),
            abort: Value::Null,
            event: Value::Null,
        }
    }

    fn committed(tag: u8) -> Self {
        Self {
            state: Value::Integer(2),
            event: Value::Text("event".to_owned()),
            ..Self::pending(tag)
        }
    }

    fn aborted(tag: u8, reason: i64) -> Self {
        Self {
            state: Value::Integer(3),
            abort: Value::Integer(reason),
            ..Self::pending(tag)
        }
    }

    fn insert(&self, conn: &Connection) -> rusqlite::Result<usize> {
        conn.execute(
            "INSERT INTO consent_revocation_journal (journal_seq, operation_id, generation,
                timeline_id, subject_id, grantee_id, grant_seq, requested_fence, binding_digest,
                state, abort_reason, event_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                self.seq,
                self.operation,
                self.generation,
                self.timeline,
                self.subject,
                self.grantee,
                self.grant_seq,
                self.fence,
                self.digest,
                self.state,
                self.abort,
                self.event,
            ],
        )
    }
}

fn count(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT count(*) FROM consent_revocation_journal",
        [],
        |row| row.get(0),
    )
}

fn stored_sql(conn: &Connection, name: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT sql FROM sqlite_master WHERE name = ?1",
        params![name],
        |row| row.get(0),
    )
}

fn object_count(conn: &Connection, name: &str) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE name = ?1",
        params![name],
        |row| row.get(0),
    )
}

/// A store file with the objects created, closed again.
fn prepared(directory: &tempfile::TempDir) -> Result<String, Box<dyn std::error::Error>> {
    let path = directory.path().join("journal.sqlite3");
    let path = path.to_str().ok_or("non-UTF-8 path")?.to_owned();
    drop(SqliteStore::open(&path)?);
    Ok(path)
}

/// Run `repair` on the prepared file and return the writable open's refusal text.
fn refusal_after(repair: &str) -> Result<String, Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = prepared(&directory)?;
    Connection::open(&path)?.execute_batch(repair)?;
    let refusal = SqliteStore::open(&path)
        .err()
        .ok_or("open accepted the schema")?;
    Ok(refusal.to_string())
}

#[test]
fn a_writable_open_creates_the_objects_with_the_adr_text() -> TestResult {
    let store = SqliteStore::open_in_memory()?;
    for name in [TABLE, PENDING_INDEX, EVENTS_INDEX] {
        assert_eq!(object_count(&store.conn, name)?, 1, "{name}");
    }
    let table = stored_sql(&store.conn, TABLE)?.ok_or("no table sql")?;
    assert!(table.ends_with(") STRICT"));
    assert!(table.contains("journal_seq      INTEGER NOT NULL UNIQUE"));
    assert_eq!(
        stored_sql(&store.conn, PENDING_INDEX)?.ok_or("no index sql")?,
        "CREATE UNIQUE INDEX consent_revocation_single_pending
    ON consent_revocation_journal(state) WHERE state = 1"
    );
    assert_eq!(
        stored_sql(&store.conn, EVENTS_INDEX)?.ok_or("no index sql")?,
        "CREATE INDEX idx_events_entity_type
    ON events(timeline_id, entity_id, event_type, seq)"
    );
    Ok(())
}

#[test]
fn a_reopen_keeps_the_rows() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = prepared(&directory)?;
    {
        let store = SqliteStore::open(&path)?;
        Row::committed(1).insert(&store.conn)?;
    }
    let store = SqliteStore::open(&path)?;
    assert_eq!(count(&store.conn)?, 1);
    Ok(())
}

#[test]
fn a_read_only_open_creates_and_validates_nothing() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = prepared(&directory)?;
    Connection::open(&path)?.execute_batch(
        "DROP TABLE consent_revocation_journal;
         DROP INDEX idx_events_entity_type;",
    )?;
    let store = SqliteStore::open_read_only(&path)?;
    assert_eq!(object_count(&store.conn, TABLE)?, 0);
    assert_eq!(object_count(&store.conn, PENDING_INDEX)?, 0);
    assert_eq!(object_count(&store.conn, EVENTS_INDEX)?, 0);
    Ok(())
}

#[test]
fn a_writable_open_adds_missing_objects_to_an_existing_store() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = prepared(&directory)?;
    Connection::open(&path)?.execute_batch(
        "DROP TABLE consent_revocation_journal;
         DROP INDEX idx_events_entity_type;",
    )?;
    let store = SqliteStore::open(&path)?;
    for name in [TABLE, PENDING_INDEX, EVENTS_INDEX] {
        assert_eq!(object_count(&store.conn, name)?, 1, "{name}");
    }
    Ok(())
}

#[test]
fn every_state_shape_of_i1_is_accepted() -> TestResult {
    let store = SqliteStore::open_in_memory()?;
    Row::pending(1).insert(&store.conn)?;
    Row::committed(2).insert(&store.conn)?;
    Row::aborted(3, 1).insert(&store.conn)?;
    Row::aborted(4, 2).insert(&store.conn)?;
    assert_eq!(count(&store.conn)?, 4);
    Ok(())
}

#[test]
fn state_shapes_outside_i1_are_refused() -> TestResult {
    let store = SqliteStore::open_in_memory()?;
    let event = Value::Text("event".to_owned());
    let refused = [
        ("pending with a reason", {
            let mut row = Row::pending(1);
            row.abort = Value::Integer(1);
            row
        }),
        ("pending with an event", {
            let mut row = Row::pending(1);
            row.event = event.clone();
            row
        }),
        ("committed without an event", {
            let mut row = Row::committed(1);
            row.event = Value::Null;
            row
        }),
        ("committed with a reason", {
            let mut row = Row::committed(1);
            row.abort = Value::Integer(1);
            row
        }),
        ("aborted without a reason", {
            let mut row = Row::aborted(1, 1);
            row.abort = Value::Null;
            row
        }),
        ("aborted with an event", {
            let mut row = Row::aborted(1, 1);
            row.event = event;
            row
        }),
        ("state zero", {
            let mut row = Row::pending(1);
            row.state = Value::Integer(0);
            row
        }),
        ("state four", {
            let mut row = Row::pending(1);
            row.state = Value::Integer(4);
            row
        }),
        ("reason zero", Row::aborted(1, 0)),
        ("reason three", Row::aborted(1, 3)),
    ];
    for (label, row) in &refused {
        assert!(row.insert(&store.conn).is_err(), "{label}");
    }
    assert_eq!(count(&store.conn)?, 0);
    Ok(())
}

#[test]
fn field_bounds_of_i1_are_enforced() -> TestResult {
    let store = SqliteStore::open_in_memory()?;
    let refused = [
        ("sequence zero", {
            let mut row = Row::pending(1);
            row.seq = Value::Integer(0);
            row
        }),
        ("generation zero", {
            let mut row = Row::pending(1);
            row.generation = Value::Integer(0);
            row
        }),
        ("grant sequence zero", {
            let mut row = Row::pending(1);
            row.grant_seq = Value::Integer(0);
            row
        }),
        ("fence one", {
            let mut row = Row::pending(1);
            row.fence = Value::Integer(1);
            row
        }),
        ("short operation", {
            let mut row = Row::pending(1);
            row.operation = Value::Blob(vec![1; 15]);
            row
        }),
        ("long operation", {
            let mut row = Row::pending(1);
            row.operation = Value::Blob(vec![1; 17]);
            row
        }),
        ("text operation", {
            let mut row = Row::pending(1);
            row.operation = Value::Text("a".repeat(16));
            row
        }),
        ("short digest", {
            let mut row = Row::pending(1);
            row.digest = Value::Blob(vec![1; 31]);
            row
        }),
        ("long digest", {
            let mut row = Row::pending(1);
            row.digest = Value::Blob(vec![1; 33]);
            row
        }),
        ("blob timeline", {
            let mut row = Row::pending(1);
            row.timeline = Value::Blob(vec![1; 26]);
            row
        }),
        ("null timeline", {
            let mut row = Row::pending(1);
            row.timeline = Value::Null;
            row
        }),
        ("null subject", {
            let mut row = Row::pending(1);
            row.subject = Value::Null;
            row
        }),
        ("null grantee", {
            let mut row = Row::pending(1);
            row.grantee = Value::Null;
            row
        }),
        ("null generation", {
            let mut row = Row::pending(1);
            row.generation = Value::Null;
            row
        }),
        ("null digest", {
            let mut row = Row::pending(1);
            row.digest = Value::Null;
            row
        }),
        ("null state", {
            let mut row = Row::pending(1);
            row.state = Value::Null;
            row
        }),
    ];
    for (label, row) in &refused {
        assert!(row.insert(&store.conn).is_err(), "{label}");
    }

    let mut boundary = Row::pending(1);
    boundary.fence = Value::Integer(2);
    boundary.generation = Value::Integer(1);
    boundary.grant_seq = Value::Integer(1);
    boundary.insert(&store.conn)?;
    assert_eq!(count(&store.conn)?, 1);
    Ok(())
}

#[test]
fn sequence_and_operation_are_unique() -> TestResult {
    let store = SqliteStore::open_in_memory()?;
    Row::committed(1).insert(&store.conn)?;

    let mut same_sequence = Row::committed(2);
    same_sequence.seq = Value::Integer(1);
    assert!(same_sequence.insert(&store.conn).is_err());

    let mut same_operation = Row::committed(2);
    same_operation.operation = Value::Blob(vec![1; 16]);
    assert!(same_operation.insert(&store.conn).is_err());

    Row::committed(2).insert(&store.conn)?;
    Ok(())
}

#[test]
fn only_one_row_may_be_pending() -> TestResult {
    let store = SqliteStore::open_in_memory()?;
    Row::pending(1).insert(&store.conn)?;
    assert!(
        Row::pending(2).insert(&store.conn).is_err(),
        "a second Pending row is JournalBusy"
    );
    Row::committed(2).insert(&store.conn)?;
    Row::aborted(3, 1).insert(&store.conn)?;

    store.conn.execute(
        "UPDATE consent_revocation_journal SET state = 3, abort_reason = 2 WHERE state = 1",
        [],
    )?;
    Row::pending(4).insert(&store.conn)?;
    assert_eq!(count(&store.conn)?, 4);
    Ok(())
}

#[test]
fn the_events_index_serves_the_entity_type_lookup() -> TestResult {
    let store = SqliteStore::open_in_memory()?;
    let columns = store
        .conn
        .prepare("SELECT name FROM pragma_index_info('idx_events_entity_type') ORDER BY seqno")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    assert_eq!(columns, ["timeline_id", "entity_id", "event_type", "seq"]);
    let unique: i64 = store.conn.query_row(
        "SELECT \"unique\" FROM pragma_index_list('events') WHERE name = 'idx_events_entity_type'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(unique, 0);

    let plan: String = store.conn.query_row(
        "EXPLAIN QUERY PLAN SELECT seq FROM events INDEXED BY idx_events_entity_type
         WHERE timeline_id = ?1 AND entity_id = ?2 AND event_type = ?3
         ORDER BY seq DESC LIMIT 1",
        params!["timeline", "subject", "subject.data.v1"],
        |row| row.get(3),
    )?;
    assert!(plan.contains("idx_events_entity_type"), "{plan}");
    Ok(())
}

#[test]
fn a_different_table_text_refuses_a_writable_open() -> TestResult {
    let refusal = refusal_after(
        "DROP TABLE consent_revocation_journal;
         CREATE TABLE consent_revocation_journal (state INTEGER NOT NULL);",
    )?;
    assert!(refusal.contains(TABLE), "{refusal}");
    Ok(())
}

#[test]
fn a_looser_table_check_refuses_a_writable_open() -> TestResult {
    let refusal = refusal_after(
        "DROP TABLE consent_revocation_journal;
         CREATE TABLE consent_revocation_journal (
            journal_seq INTEGER NOT NULL UNIQUE CHECK (journal_seq >= 0),
            operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
            generation INTEGER NOT NULL CHECK (generation >= 1),
            timeline_id TEXT NOT NULL, subject_id TEXT NOT NULL, grantee_id TEXT NOT NULL,
            grant_seq INTEGER NOT NULL CHECK (grant_seq >= 1),
            requested_fence INTEGER NOT NULL CHECK (requested_fence >= 2),
            binding_digest BLOB NOT NULL CHECK (length(binding_digest) = 32),
            state INTEGER NOT NULL CHECK (state IN (1, 2, 3)),
            abort_reason INTEGER CHECK (abort_reason IS NULL OR abort_reason IN (1, 2)),
            event_id TEXT,
            CHECK ((state = 1 AND abort_reason IS NULL AND event_id IS NULL)
                OR (state = 2 AND abort_reason IS NULL AND event_id IS NOT NULL)
                OR (state = 3 AND abort_reason IS NOT NULL AND event_id IS NULL))
         ) STRICT;
         CREATE UNIQUE INDEX consent_revocation_single_pending
            ON consent_revocation_journal(state) WHERE state = 1;",
    )?;
    assert!(refusal.contains(TABLE), "{refusal}");
    Ok(())
}

#[test]
fn a_non_partial_pending_index_refuses_a_writable_open() -> TestResult {
    let refusal = refusal_after(
        "DROP INDEX consent_revocation_single_pending;
         CREATE UNIQUE INDEX consent_revocation_single_pending
            ON consent_revocation_journal(state);",
    )?;
    assert!(refusal.contains(PENDING_INDEX), "{refusal}");
    Ok(())
}

#[test]
fn a_different_events_index_refuses_a_writable_open() -> TestResult {
    let refusal = refusal_after(
        "DROP INDEX idx_events_entity_type;
         CREATE INDEX idx_events_entity_type ON events(timeline_id, entity_id, event_type);",
    )?;
    assert!(refusal.contains(EVENTS_INDEX), "{refusal}");
    Ok(())
}

#[test]
fn an_events_index_name_on_another_table_refuses_a_writable_open() -> TestResult {
    let refusal = refusal_after(
        "DROP INDEX idx_events_entity_type;
         CREATE INDEX idx_events_entity_type ON key_registry(singleton);",
    )?;
    assert!(refusal.contains(EVENTS_INDEX), "{refusal}");
    Ok(())
}

#[test]
fn a_view_in_place_of_the_table_refuses_a_writable_open() -> TestResult {
    let refusal = refusal_after(
        "DROP TABLE consent_revocation_journal;
         CREATE VIEW consent_revocation_journal AS SELECT 1 AS state;",
    )?;
    assert!(refusal.contains("view"), "{refusal}");
    Ok(())
}

#[test]
fn a_table_squatting_an_index_name_refuses_a_writable_open() -> TestResult {
    let refusal = refusal_after(
        "DROP INDEX idx_events_entity_type;
         CREATE TABLE idx_events_entity_type (value INTEGER);",
    )?;
    assert!(refusal.contains(EVENTS_INDEX), "{refusal}");
    Ok(())
}
