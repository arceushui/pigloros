//! ADR-097 B6 fence rows: the table shape, the rows it refuses, and the
//! owner's exact-Timeline check inside the caller's transaction.

use pos_core::ids::TimelineId;
use rusqlite::{params, types::Value, Connection};
use sha2::{Digest, Sha256};

use super::{require_no_erasure_fence_rows, ErasureFenceRefusalV1};
use crate::sqlite::SqliteStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A 32-byte erasure request reference derived from a label.
fn request(label: &str) -> Vec<u8> {
    let digest = Sha256::digest(label.as_bytes());
    let bytes: [u8; 32] = std::array::from_fn(|index| digest[index]);
    bytes.to_vec()
}

fn insert(
    conn: &Connection,
    timeline: &Value,
    request: &Value,
    lifecycle: &Value,
) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO erasure_fence_rows (timeline_id, erasure_request_id, lifecycle_code)
         VALUES (?1, ?2, ?3)",
        params![timeline, request, lifecycle],
    )
}

fn row(
    conn: &Connection,
    timeline: TimelineId,
    label: &str,
    lifecycle: i64,
) -> rusqlite::Result<usize> {
    insert(
        conn,
        &Value::Text(timeline.to_string()),
        &Value::Blob(request(label)),
        &Value::Integer(lifecycle),
    )
}

/// Run the check inside a `BEGIN IMMEDIATE` that is then rolled back.
fn check(
    conn: &Connection,
    timeline: TimelineId,
) -> Result<Result<(), ErasureFenceRefusalV1>, rusqlite::Error> {
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = require_no_erasure_fence_rows(conn, timeline);
    conn.execute_batch("ROLLBACK")?;
    Ok(result)
}

fn table_exists(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'erasure_fence_rows'",
        [],
        |row| row.get(0),
    )
}

#[test]
fn a_writable_open_creates_the_table_and_a_reopen_keeps_its_rows() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fence.sqlite3");
    let path = path.to_str().ok_or("non-UTF-8 path")?;
    let timeline = TimelineId::new();
    {
        let store = SqliteStore::open(path)?;
        assert!(table_exists(&store.conn)?);
        row(&store.conn, timeline, "kept", 2)?;
    }
    let store = SqliteStore::open(path)?;
    assert_eq!(
        check(&store.conn, timeline)?,
        Err(ErasureFenceRefusalV1::Fenced),
        "a reopen keeps the committed row"
    );
    Ok(())
}

#[test]
fn a_read_only_open_creates_nothing_and_a_missing_table_is_unreadable() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fence.sqlite3");
    let path = path.to_str().ok_or("non-UTF-8 path")?;
    drop(SqliteStore::open(path)?);
    Connection::open(path)?.execute_batch("DROP TABLE erasure_fence_rows")?;

    let store = SqliteStore::open_read_only(path)?;
    assert!(!table_exists(&store.conn)?);
    store.conn.execute_batch("BEGIN")?;
    assert_eq!(
        require_no_erasure_fence_rows(&store.conn, TimelineId::new()),
        Err(ErasureFenceRefusalV1::Unreadable)
    );
    store.conn.execute_batch("ROLLBACK")?;
    Ok(())
}

#[test]
fn an_incompatible_table_refuses_a_writable_open() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fence.sqlite3");
    let path = path.to_str().ok_or("non-UTF-8 path")?;
    drop(SqliteStore::open(path)?);
    Connection::open(path)?.execute_batch(
        "DROP TABLE erasure_fence_rows;
         CREATE TABLE erasure_fence_rows (timeline_id TEXT NOT NULL);",
    )?;

    let refusal = SqliteStore::open(path)
        .err()
        .ok_or("open accepted the table")?;
    assert!(refusal.to_string().contains("erasure_fence_rows"));
    Ok(())
}

#[test]
fn only_a_row_of_the_exact_timeline_fences_it() -> TestResult {
    let store = SqliteStore::open_in_memory()?;
    let target = TimelineId::new();
    let other = TimelineId::new();
    row(&store.conn, other, "other", 2)?;

    assert_eq!(check(&store.conn, target)?, Ok(()));
    assert_eq!(
        check(&store.conn, other)?,
        Err(ErasureFenceRefusalV1::Fenced)
    );
    Ok(())
}

#[test]
fn every_lifecycle_from_access_frozen_fences() -> TestResult {
    let store = SqliteStore::open_in_memory()?;
    for code in 2..=6 {
        let timeline = TimelineId::new();
        row(&store.conn, timeline, "frozen", code)?;
        assert_eq!(
            check(&store.conn, timeline)?,
            Err(ErasureFenceRefusalV1::Fenced),
            "lifecycle {code}"
        );
    }
    Ok(())
}

#[test]
fn the_table_refuses_rows_b6_never_writes() -> TestResult {
    let store = SqliteStore::open_in_memory()?;
    let timeline = TimelineId::new();
    let canonical = Value::Text(timeline.to_string());
    let reference = Value::Blob(request("refused"));
    let frozen = Value::Integer(2);
    for code in [0, 1, 7] {
        assert!(
            insert(&store.conn, &canonical, &reference, &Value::Integer(code)).is_err(),
            "lifecycle {code}"
        );
    }
    let malformed_timelines = [
        Value::Text(timeline.to_string().to_lowercase()),
        Value::Text(timeline.to_string()[1..].to_owned()),
        Value::Blob(timeline.to_string().into_bytes()),
    ];
    for bad in &malformed_timelines {
        assert!(insert(&store.conn, bad, &reference, &frozen).is_err());
    }
    let malformed_requests = [
        Value::Blob(request("short")[1..].to_vec()),
        Value::Text("r".repeat(32)),
    ];
    for bad in &malformed_requests {
        assert!(insert(&store.conn, &canonical, bad, &frozen).is_err());
    }

    insert(&store.conn, &canonical, &reference, &frozen)?;
    assert!(
        insert(&store.conn, &canonical, &reference, &Value::Integer(3)).is_err(),
        "the key is (timeline_id, erasure_request_id)"
    );
    insert(
        &store.conn,
        &canonical,
        &Value::Blob(request("second")),
        &frozen,
    )?;
    Ok(())
}

#[test]
fn a_malformed_row_fails_closed() -> TestResult {
    let store = SqliteStore::open_in_memory()?;
    store
        .conn
        .execute_batch("PRAGMA ignore_check_constraints = ON")?;
    let malformed = [
        (Value::Blob(request("never")), Value::Integer(0)),
        (Value::Blob(request("never")), Value::Integer(1)),
        (Value::Blob(request("rejected")), Value::Integer(7)),
        (
            Value::Blob(request("text")),
            Value::Text("frozen".to_owned()),
        ),
        (Value::Blob(request("real")), Value::Real(2.5)),
        (
            Value::Blob(request("short")[1..].to_vec()),
            Value::Integer(2),
        ),
        (Value::Text("r".repeat(32)), Value::Integer(2)),
    ];
    for (reference, lifecycle) in &malformed {
        let timeline = TimelineId::new();
        insert(
            &store.conn,
            &Value::Text(timeline.to_string()),
            reference,
            lifecycle,
        )?;
        assert_eq!(
            check(&store.conn, timeline)?,
            Err(ErasureFenceRefusalV1::Malformed),
            "{reference:?} {lifecycle:?}"
        );
    }
    Ok(())
}

#[test]
fn the_check_refuses_outside_a_transaction() -> TestResult {
    let store = SqliteStore::open_in_memory()?;
    assert_eq!(
        require_no_erasure_fence_rows(&store.conn, TimelineId::new()),
        Err(ErasureFenceRefusalV1::OutsideTransaction)
    );
    Ok(())
}

#[test]
fn the_check_reads_the_enclosing_transaction() -> TestResult {
    let store = SqliteStore::open_in_memory()?;
    let timeline = TimelineId::new();
    store.conn.execute_batch("BEGIN IMMEDIATE")?;
    assert_eq!(require_no_erasure_fence_rows(&store.conn, timeline), Ok(()));
    row(&store.conn, timeline, "same transaction", 2)?;
    assert_eq!(
        require_no_erasure_fence_rows(&store.conn, timeline),
        Err(ErasureFenceRefusalV1::Fenced)
    );
    store.conn.execute_batch("ROLLBACK")?;

    assert_eq!(check(&store.conn, timeline)?, Ok(()), "the row rolled back");
    Ok(())
}
