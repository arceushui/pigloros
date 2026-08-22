#![forbid(unsafe_code)]

use std::process::{Command, Output};

use rusqlite::{params, Connection};

fn run_pos(args: &[&str]) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(Command::new(env!("CARGO_BIN_EXE_pos"))
        .args(args)
        .output()?)
}

fn initialized_store() -> Result<(tempfile::TempDir, String), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("store.db");
    let path = path.to_str().ok_or("UTF-8 database path")?.to_owned();
    let output = run_pos(&["store", "init", &path])?;
    assert!(
        output.status.success(),
        "store init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok((directory, path))
}

fn store_timeline_id(connection: &Connection) -> Result<String, Box<dyn std::error::Error>> {
    Ok(connection.query_row("SELECT id FROM timelines LIMIT 1", [], |row| row.get(0))?)
}

#[test]
fn healthy_store_info_prints_exact_statistics() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, path) = initialized_store()?;

    let output = run_pos(&["store", "info", &path])?;

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)?,
        "Timelines: 1\nTotal events: 0\n"
    );
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn corrupt_timeline_listing_fails_without_partial_stdout() -> Result<(), Box<dyn std::error::Error>>
{
    let (_directory, path) = initialized_store()?;
    let connection = Connection::open(&path)?;
    connection.execute("UPDATE timelines SET name = X'0102'", [])?;

    let output = run_pos(&["store", "info", &path])?;
    let stderr = String::from_utf8(output.stderr)?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        stderr.contains("failed to list Timelines while calculating store information"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        stderr.contains("Invalid column type"),
        "missing root cause in stderr: {stderr}"
    );
    Ok(())
}

#[test]
fn corrupt_timeline_events_fail_without_partial_stdout() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, path) = initialized_store()?;
    let connection = Connection::open(&path)?;
    let timeline_id = store_timeline_id(&connection)?;
    connection.execute(
        "INSERT INTO events (
                timeline_id, seq, event_id, entity_id, event_type, payload,
                wall_time, causation_id, correlation_id, schema_version,
                payload_hash, signature
             ) VALUES (?1, 1, ?2, ?3, 'test.event', X'', 0, NULL, NULL, 1, X'01', NULL)",
        params![
            timeline_id,
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "01ARZ3NDEKTSV4RRFFQ69G5FAW"
        ],
    )?;
    connection.execute("UPDATE timelines SET head_seq = 1", [])?;

    let output = run_pos(&["store", "info", &path])?;
    let stderr = String::from_utf8(output.stderr)?;

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        stderr.contains(&format!("failed to read Timeline {timeline_id}")),
        "missing Timeline ID in stderr: {stderr}"
    );
    assert!(
        stderr.contains("serialization error: bad hash"),
        "missing root cause in stderr: {stderr}"
    );
    Ok(())
}
