//! The durability of an admissions change (#1408): the write runs under
//! `synchronous=FULL` and the store's `NORMAL` level is restored after a
//! committed change and after a refused one.

use pos_core::{ErasureAdmissionsPortV1 as _, ErasureAdmissionsStateV1};

use super::SqliteStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The value `PRAGMA synchronous` reads back for `NORMAL`.
const SYNCHRONOUS_NORMAL: i64 = 1;

fn level(store: &SqliteStore) -> Result<i64, Box<dyn std::error::Error>> {
    Ok(store
        .conn
        .query_row("PRAGMA synchronous", [], |row| row.get(0))?)
}

#[test]
fn a_change_restores_the_normal_level_after_a_commit_and_after_a_refusal() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("admissions.sqlite3");
    let mut store = SqliteStore::open(path.to_str().ok_or("non-UTF-8 path")?)?;
    assert_eq!(
        level(&store)?,
        SYNCHRONOUS_NORMAL,
        "a fresh store runs at NORMAL"
    );

    assert_eq!(
        store.set_erasure_admissions(ErasureAdmissionsStateV1::Closed)?,
        ErasureAdmissionsStateV1::Open
    );
    assert_eq!(
        level(&store)?,
        SYNCHRONOUS_NORMAL,
        "after a committed change"
    );

    store.conn.execute_batch(
        "PRAGMA ignore_check_constraints = ON;
         UPDATE erasure_admissions SET closed = 'unreadable' WHERE singleton = 1;
         PRAGMA ignore_check_constraints = OFF;",
    )?;
    assert!(store
        .set_erasure_admissions(ErasureAdmissionsStateV1::Open)
        .is_err());
    assert_eq!(level(&store)?, SYNCHRONOUS_NORMAL, "after a refused change");
    Ok(())
}
