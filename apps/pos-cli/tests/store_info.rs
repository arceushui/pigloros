#![forbid(unsafe_code)]

use std::process::{Command, Output};

use rusqlite::{params, Connection};

fn run_pos(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pos"))
        .args(args)
        .output()
        .expect("run pos binary")
}

fn initialized_store() -> (tempfile::TempDir, String) {
    let directory = tempfile::tempdir().expect("create temporary directory");
    let path = directory.path().join("store.db");
    let path = path.to_str().expect("UTF-8 database path").to_owned();
    let output = run_pos(&["store", "init", &path]);
    assert!(
        output.status.success(),
        "store init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (directory, path)
}

fn store_timeline_id(connection: &Connection) -> String {
    connection
        .query_row("SELECT id FROM timelines LIMIT 1", [], |row| row.get(0))
        .expect("read Timeline ID")
}

#[test]
fn healthy_store_info_prints_exact_statistics() {
    let (_directory, path) = initialized_store();

    let output = run_pos(&["store", "info", &path]);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("UTF-8 stdout"),
        "Timelines: 1\nTotal events: 0\n"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn corrupt_timeline_listing_fails_without_partial_stdout() {
    let (_directory, path) = initialized_store();
    let connection = Connection::open(&path).expect("open store for corruption");
    connection
        .execute("UPDATE timelines SET name = X'0102'", [])
        .expect("corrupt Timeline name");

    let output = run_pos(&["store", "info", &path]);
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");

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
}

#[test]
fn corrupt_timeline_events_fail_without_partial_stdout() {
    let (_directory, path) = initialized_store();
    let connection = Connection::open(&path).expect("open store for corruption");
    let timeline_id = store_timeline_id(&connection);
    connection
        .execute(
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
        )
        .expect("insert corrupt Event");

    let output = run_pos(&["store", "info", &path]);
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");

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
}
