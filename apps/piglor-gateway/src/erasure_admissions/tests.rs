//! `piglor-gateway erasure-admissions` (#1408): the audit lines, every
//! execution mode, and the stores and arguments it refuses.

use pos_core::{ErasureAdmissionsPortV1 as _, ErasureAdmissionsStateV1};
use pos_store::sqlite::SqliteStore;

use super::execute;
use crate::mode_profile::{bind_test_store, GatewayModeProfileIdV1, GatewayModeStoreLockV1};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn run(arguments: &[&str]) -> Result<String, super::ErasureAdmissionsCommandErrorV1> {
    execute(
        &arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect::<Vec<_>>(),
    )
}

/// A store at a fresh path in `directory`, bound to `mode` unless `None`.
fn store_in(
    directory: &tempfile::TempDir,
    mode: Option<GatewayModeProfileIdV1>,
) -> Result<String, Box<dyn std::error::Error>> {
    let path = directory
        .path()
        .join("gateway.sqlite3")
        .to_str()
        .ok_or("temporary database path is not UTF-8")?
        .to_owned();
    let mut store = SqliteStore::open(&path)?;
    if let Some(mode) = mode {
        bind_test_store(&mut store, mode).map_err(|error| format!("{error:?}"))?;
    }
    Ok(path)
}

/// `close` and `open` each print one audit line naming the previous and
/// the new state, `status` the persisted state, and the record is the
/// store's own: a fresh open of the store reads it.
#[test]
fn close_open_and_status_report_the_record() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = store_in(&directory, Some(GatewayModeProfileIdV1::Local))?;
    for (verb, output) in [
        ("status", "Erasure admissions: open"),
        ("close", "Erasure admissions closed (were open)"),
        ("status", "Erasure admissions: closed"),
        ("close", "Erasure admissions closed (were closed)"),
        ("open", "Erasure admissions opened (were closed)"),
        ("open", "Erasure admissions opened (were open)"),
        ("close", "Erasure admissions closed (were open)"),
    ] {
        assert_eq!(run(&[verb, path.as_str()])?, output, "{verb}");
    }
    assert_eq!(
        SqliteStore::open(&path)?.erasure_admissions()?,
        ErasureAdmissionsStateV1::Closed
    );
    Ok(())
}

/// Neither verb is refused in the Air-Gapped mode: closing only reduces
/// what the host admits, and reopening must stay possible there.
#[test]
fn an_air_gapped_store_closes_and_reopens() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = store_in(&directory, Some(GatewayModeProfileIdV1::AirGapped))?;
    assert_eq!(
        run(&["close", path.as_str()])?,
        "Erasure admissions closed (were open)"
    );
    assert_eq!(
        run(&["open", path.as_str()])?,
        "Erasure admissions opened (were closed)"
    );
    assert_eq!(run(&["status", path.as_str()])?, "Erasure admissions: open");
    Ok(())
}

/// Any other arguments are a usage error before the store is touched.
#[test]
fn other_arguments_are_a_usage_error() -> TestResult {
    for arguments in [
        &[][..],
        &["close"][..],
        &["reopen", "unused.sqlite3"][..],
        &["close", "unused.sqlite3", "extra"][..],
    ] {
        let usage = run(arguments).err().ok_or("expected a usage error")?;
        assert!(usage.to_string().starts_with("Usage:"), "{arguments:?}");
    }
    Ok(())
}

/// An offline writer refuses an unbound store and a store `migrate-mode`
/// holds; a store it cannot open, or whose record it cannot read, leaves
/// the record unavailable and unchanged.
#[test]
fn unbound_locked_and_unreadable_stores_are_refused() -> TestResult {
    let directory = tempfile::tempdir()?;
    let unbound = store_in(&directory, None)?;
    for verb in ["close", "open", "status"] {
        let refused = run(&[verb, unbound.as_str()])
            .err()
            .ok_or("an unbound store")?;
        assert!(
            refused.to_string().contains("not bound"),
            "{verb}: {refused}"
        );
    }

    let bound_directory = tempfile::tempdir()?;
    let bound = store_in(&bound_directory, Some(GatewayModeProfileIdV1::Local))?;
    let migrating = GatewayModeStoreLockV1::exclusive(&bound)?;
    for verb in ["close", "open", "status"] {
        let locked = run(&[verb, bound.as_str()]).err().ok_or("a locked store")?;
        assert!(locked.to_string().contains("lock"), "{verb}: {locked}");
    }
    drop(migrating);

    let garbage = directory.path().join("garbage.sqlite3");
    std::fs::write(&garbage, b"not a database")?;
    let garbage = garbage.to_str().ok_or("temporary path is not UTF-8")?;
    let unopenable = run(&["close", garbage]).err().ok_or("a garbage store")?;
    assert_eq!(
        unopenable.to_string(),
        "erasure admissions record is unavailable"
    );

    rusqlite::Connection::open(&bound)?.execute_batch(
        "PRAGMA ignore_check_constraints = ON;
         INSERT INTO erasure_admissions (singleton, closed) VALUES (1, 'unreadable');",
    )?;
    for verb in ["close", "open", "status"] {
        let unavailable = run(&[verb, bound.as_str()])
            .err()
            .ok_or("an unreadable record")?;
        assert_eq!(
            unavailable.to_string(),
            "erasure admissions record is unavailable",
            "{verb}"
        );
    }
    let stored: String = rusqlite::Connection::open(&bound)?.query_row(
        "SELECT closed FROM erasure_admissions WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(stored, "unreadable");
    Ok(())
}

/// A live `serve` holds the store's shared lock for its lifetime: `close`
/// and `open` refuse to commit beside it, since a foreign commit would make
/// the serving host fail closed, and leave the record unchanged, while
/// `status` still reads it.
#[test]
fn a_serving_store_refuses_changes_but_answers_status() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = store_in(&directory, Some(GatewayModeProfileIdV1::Local))?;
    let serving = GatewayModeStoreLockV1::shared(&path)?;
    for verb in ["close", "open"] {
        let refused = run(&[verb, path.as_str()]).err().ok_or("a served store")?;
        assert_eq!(
            refused.to_string(),
            "store execution-mode lock is unavailable",
            "{verb}"
        );
    }
    assert_eq!(run(&["status", path.as_str()])?, "Erasure admissions: open");
    drop(serving);
    assert_eq!(
        run(&["close", path.as_str()])?,
        "Erasure admissions closed (were open)"
    );
    Ok(())
}
