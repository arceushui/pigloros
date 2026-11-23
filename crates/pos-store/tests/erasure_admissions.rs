//! The operator's Local erasure admissions record (ADR-136 follow-up F3,
//! #1408) on `MemoryStore` and `SqliteStore`: a store without the record is
//! open, each change returns the state it replaced, a `SQLite` record
//! survives a reopen of its file, and a record that cannot be read fails
//! closed without being changed.
#![cfg(feature = "sqlite")]

use pos_core::{ErasureAdmissionsPortV1, ErasureAdmissionsStateV1};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};
use tempfile::tempdir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A store of each adapter.
type Stores = Vec<(&'static str, Box<dyn ErasureAdmissionsPortV1>)>;

fn stores() -> Result<Stores, Box<dyn std::error::Error>> {
    let memory: Box<dyn ErasureAdmissionsPortV1> = Box::new(MemoryStore::new());
    let sqlite: Box<dyn ErasureAdmissionsPortV1> = Box::new(SqliteStore::open_in_memory()?);
    Ok(vec![("memory", memory), ("sqlite", sqlite)])
}

#[test]
fn a_store_without_the_record_is_open() -> TestResult {
    for (adapter, store) in stores()? {
        assert_eq!(
            store.erasure_admissions()?,
            ErasureAdmissionsStateV1::Open,
            "{adapter}"
        );
    }
    Ok(())
}

#[test]
fn each_change_returns_the_state_it_replaced() -> TestResult {
    use ErasureAdmissionsStateV1::{Closed, Open};
    for (adapter, mut store) in stores()? {
        for (state, previous) in [
            (Closed, Open),
            (Closed, Closed),
            (Open, Closed),
            (Open, Open),
        ] {
            assert_eq!(
                store.set_erasure_admissions(state)?,
                previous,
                "{adapter}: {state:?}"
            );
            assert_eq!(store.erasure_admissions()?, state, "{adapter}: {state:?}");
        }
    }
    Ok(())
}

#[test]
fn a_closed_record_survives_a_reopen_and_open_restores() -> TestResult {
    let directory = tempdir()?;
    let path = directory
        .path()
        .join("admissions.sqlite3")
        .to_str()
        .ok_or("temporary database path is not UTF-8")?
        .to_owned();
    assert_eq!(
        SqliteStore::open(&path)?.set_erasure_admissions(ErasureAdmissionsStateV1::Closed)?,
        ErasureAdmissionsStateV1::Open
    );
    let mut reopened = SqliteStore::open(&path)?;
    assert_eq!(
        reopened.erasure_admissions()?,
        ErasureAdmissionsStateV1::Closed
    );
    assert_eq!(
        reopened.set_erasure_admissions(ErasureAdmissionsStateV1::Open)?,
        ErasureAdmissionsStateV1::Closed
    );
    drop(reopened);
    assert_eq!(
        SqliteStore::open(&path)?.erasure_admissions()?,
        ErasureAdmissionsStateV1::Open
    );
    Ok(())
}

/// A row the `CHECK` would refuse, written with the checks off, is a record
/// the adapter cannot read: the read fails rather than answer open, and a
/// change fails without touching it.
#[test]
fn an_unreadable_record_fails_and_is_left_unchanged() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("corrupt.sqlite3");
    let path = path
        .to_str()
        .ok_or("temporary database path is not UTF-8")?;
    drop(SqliteStore::open(path)?);
    let raw = rusqlite::Connection::open(path)?;
    raw.execute_batch(
        "PRAGMA ignore_check_constraints = ON;
         INSERT INTO erasure_admissions (singleton, closed) VALUES (1, 'unreadable');",
    )?;
    let mut store = SqliteStore::open(path)?;
    assert!(store.erasure_admissions().is_err());
    for state in [
        ErasureAdmissionsStateV1::Open,
        ErasureAdmissionsStateV1::Closed,
    ] {
        assert!(store.set_erasure_admissions(state).is_err(), "{state:?}");
    }
    drop(store);
    let stored: String = raw.query_row(
        "SELECT closed FROM erasure_admissions WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(stored, "unreadable");
    Ok(())
}

/// A store whose `erasure_admissions` table was reshaped is refused at open,
/// whether a `CHECK` constraint is missing or a column has another type, so
/// a record under a weaker schema is never trusted.
#[test]
fn a_reshaped_admissions_table_refuses_to_open() -> TestResult {
    for table in [
        "CREATE TABLE erasure_admissions (singleton INTEGER PRIMARY KEY, \
         closed INTEGER NOT NULL)",
        "CREATE TABLE erasure_admissions (singleton INTEGER PRIMARY KEY \
         CHECK (singleton = 1), closed TEXT NOT NULL CHECK (closed IN (0, 1)))",
    ] {
        let directory = tempdir()?;
        let path = directory.path().join("reshaped.sqlite3");
        let path = path
            .to_str()
            .ok_or("temporary database path is not UTF-8")?;
        drop(SqliteStore::open(path)?);
        rusqlite::Connection::open(path)?
            .execute_batch(&format!("DROP TABLE erasure_admissions; {table};"))?;
        let error = SqliteStore::open(path)
            .err()
            .ok_or("a reshaped table was opened")?
            .to_string();
        assert!(error.contains("erasure_admissions"), "{table}: {error}");
        assert!(error.contains("incompatible schema"), "{table}: {error}");
    }
    Ok(())
}
