//! `SQLite` adapter for the operator's Local erasure admissions record
//! (ADR-136 follow-up F3, Redmine #1408).
//!
//! One singleton row sits beside the Gateway mode binding. A store without
//! the row is open. A change is one `BEGIN IMMEDIATE` transaction committed
//! under `synchronous=FULL` that reads the previous state and writes the new
//! one, so an offline writer and a serving host never see a torn record.

use pos_core::{error::CoreError, ErasureAdmissionsPortV1, ErasureAdmissionsStateV1};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::{SqliteSchemaColumn, SqliteSchemaTable, SqliteStore};

/// The admissions table, created and validated exactly.
pub(super) const ERASURE_ADMISSIONS_SCHEMA_TABLES: &[SqliteSchemaTable] = &[SqliteSchemaTable {
    name: "erasure_admissions",
    columns_query: "PRAGMA table_info(erasure_admissions)",
    columns: &[
        SqliteSchemaColumn {
            name: "singleton",
            kind: "INTEGER",
            not_null: false,
            primary_key: true,
        },
        SqliteSchemaColumn {
            name: "closed",
            kind: "INTEGER",
            not_null: true,
            primary_key: false,
        },
    ],
    constraints: &["CHECK (singleton = 1)", "CHECK (closed IN (0, 1))"],
}];

/// The state of a persisted `closed` flag; no row is open.
fn admissions_of(closed: Option<bool>) -> ErasureAdmissionsStateV1 {
    if closed == Some(true) {
        ErasureAdmissionsStateV1::Closed
    } else {
        ErasureAdmissionsStateV1::Open
    }
}

fn read_admissions(conn: &Connection) -> rusqlite::Result<ErasureAdmissionsStateV1> {
    conn.query_row(
        "SELECT closed FROM erasure_admissions WHERE singleton = 1",
        [],
        |row| row.get::<_, bool>(0),
    )
    .optional()
    .map(admissions_of)
}

/// Replace the record with `state` and return the state it replaced.
fn write_admissions(
    conn: &Connection,
    state: ErasureAdmissionsStateV1,
) -> rusqlite::Result<ErasureAdmissionsStateV1> {
    read_admissions(conn).and_then(|previous| {
        conn.execute(
            "INSERT INTO erasure_admissions (singleton, closed) VALUES (1, ?1)
             ON CONFLICT(singleton) DO UPDATE SET closed = excluded.closed",
            params![state == ErasureAdmissionsStateV1::Closed],
        )
        .map(|_| previous)
    })
}

/// The value `PRAGMA synchronous` reads back for `FULL`.
const SYNCHRONOUS_FULL: i64 = 2;

/// Change the record in one `BEGIN IMMEDIATE` transaction under
/// `synchronous=FULL`, read back before the transaction begins; a failed
/// step drops the transaction, which rolls it back.
fn change_admissions(
    conn: &mut Connection,
    state: ErasureAdmissionsStateV1,
) -> rusqlite::Result<ErasureAdmissionsStateV1> {
    conn.execute_batch("PRAGMA synchronous=FULL")
        .and_then(|()| conn.query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0)))
        .and_then(|level| {
            (level == SYNCHRONOUS_FULL)
                .then_some(())
                .ok_or(rusqlite::Error::InvalidQuery)
        })
        .map(|()| conn)
        .and_then(|conn| conn.transaction_with_behavior(TransactionBehavior::Immediate))
        .and_then(|transaction| {
            write_admissions(&transaction, state)
                .and_then(|previous| transaction.commit().map(|()| previous))
        })
}

impl SqliteStore {
    pub(super) fn validate_erasure_admissions_schema(&self) -> Result<(), CoreError> {
        ERASURE_ADMISSIONS_SCHEMA_TABLES
            .iter()
            .try_for_each(|table| self.validate_sqlite_schema_table(table))
    }
}

impl ErasureAdmissionsPortV1 for SqliteStore {
    fn erasure_admissions(&self) -> Result<ErasureAdmissionsStateV1, CoreError> {
        read_admissions(&self.conn).map_err(Self::into_storage_error)
    }

    /// Change the record, then restore the store's `synchronous=NORMAL`.
    ///
    /// The restore's own result is not reported, as in the mode-binding
    /// adapter: once the transaction has committed the change is durable,
    /// and the level only governs later writes, so a failed restore must not
    /// turn a committed change into a reported failure.
    fn set_erasure_admissions(
        &mut self,
        state: ErasureAdmissionsStateV1,
    ) -> Result<ErasureAdmissionsStateV1, CoreError> {
        let changed = change_admissions(&mut self.conn, state);
        drop(self.conn.execute_batch("PRAGMA synchronous=NORMAL"));
        changed.map_err(Self::into_storage_error)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
