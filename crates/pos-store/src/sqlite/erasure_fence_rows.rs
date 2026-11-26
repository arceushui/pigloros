#![cfg(all(target_os = "linux", any(test, feature = "test-support")))]
//! ADR-097 B6 durable erasure fence rows and the owner's exact-Timeline check.
//!
//! The Gateway mirrors its ADR-060 erasure lifecycle into one row per subject
//! Timeline and erasure request, `(timeline_id, erasure_request_id,
//! lifecycle_code)`, from `AccessFrozen` onward. The owner process trusts only
//! these durable rows, never the Gateway's in-process containment gate. Every
//! owner write gate and every owner plaintext read calls
//! [`require_no_erasure_fence_rows`] inside its own `BEGIN IMMEDIATE`, and any
//! row for the exact Timeline refuses (ADR-097 B6, ADR-121 §3).
//!
//! This module owns the table and that read only. The Gateway writers and the
//! readiness reconciliation are a separate slice. Everything here stays
//! test-support gated until owner activation (#1438).
//!
//! Only a writable open creates and validates the table. A read-only open
//! neither creates nor validates it, so a store without the table answers
//! every check with [`ErasureFenceRefusalV1::Unreadable`]: it fails closed,
//! never open. Two obligations follow:
//!
//! - The qualified owner constructor (#1547 P-a1, ADR-123 §4 validate-only)
//!   must validate this table's exact shape itself, because it opens without
//!   creating anything.
//! - Ungating in #1438 must remove both `cfg` gates together, this module's
//!   and the writable-open call in `sqlite.rs`, and every deployed database
//!   must be opened writable by the ungated build before the ADR-121 §3a
//!   install. A store that never gains the table fails closed forever.

use pos_core::{error::CoreError, ids::TimelineId};
use rusqlite::{params, Connection, OptionalExtension, TransactionState, MAIN_DB};

use super::{sqlite_schema_ddl, SqliteSchemaColumn, SqliteSchemaTable, SqliteStore};

/// The B6 table, keyed by `(timeline_id, erasure_request_id)`.
///
/// `timeline_id` is the canonical ULID text that every Timeline column of the
/// store uses, `erasure_request_id` is the 32-byte ADR-060 request reference
/// (`ErasureReferenceV1`), and `lifecycle_code` is the ADR-060
/// `ErasureLifecycleV1` code. B6 writes rows only from `AccessFrozen` (2)
/// through `PartialFailure` (6): no row exists at `Submitted` (0) or
/// `Authorized` (1), and `Rejected` (7) deletes its row. The checks keep a
/// row the exact-Timeline read could not match from ever being written.
const ERASURE_FENCE_ROWS_SCHEMA_TABLES: &[SqliteSchemaTable] = &[SqliteSchemaTable {
    name: "erasure_fence_rows",
    columns_query: "PRAGMA table_info(erasure_fence_rows)",
    columns: &[
        SqliteSchemaColumn {
            name: "timeline_id",
            kind: "TEXT",
            not_null: true,
            primary_key: true,
        },
        SqliteSchemaColumn {
            name: "erasure_request_id",
            kind: "BLOB",
            not_null: true,
            primary_key: true,
        },
        SqliteSchemaColumn {
            name: "lifecycle_code",
            kind: "INTEGER",
            not_null: true,
            primary_key: false,
        },
    ],
    constraints: &[
        "CHECK (typeof(timeline_id) = 'text')",
        "CHECK (length(timeline_id) = 26)",
        "CHECK (timeline_id = upper(timeline_id))",
        "CHECK (typeof(erasure_request_id) = 'blob')",
        "CHECK (length(erasure_request_id) = 32)",
        "CHECK (lifecycle_code IN (2, 3, 4, 5, 6))",
    ],
}];

/// Reads at most one row of the exact Timeline and reports whether it parses.
///
/// One row is enough: any row refuses. The primary key's index bounds the
/// read, and the order makes the reported row deterministic.
const EXACT_TIMELINE_ROW_SQL: &str = "SELECT typeof(erasure_request_id) = 'blob'
            AND length(erasure_request_id) = 32
            AND typeof(lifecycle_code) = 'integer'
            AND lifecycle_code IN (2, 3, 4, 5, 6)
     FROM erasure_fence_rows
     WHERE timeline_id = ?1
     ORDER BY erasure_request_id
     LIMIT 1";

/// Why the exact-Timeline check refused. Every variant fails closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureFenceRefusalV1 {
    /// The connection held no write transaction on `main`.
    ///
    /// Autocommit has no transaction to cover the caller's later effect, and
    /// a deferred transaction that has not written may still read a snapshot
    /// older than the Gateway's committed fence row.
    NotWriteTransaction,
    /// A well-formed fence row exists for the Timeline.
    Fenced,
    /// The fence rows could not be read.
    Unreadable,
    /// A row exists for the Timeline, but it does not parse.
    Malformed,
}

/// Require that the exact `timeline` has no ADR-097 B6 erasure fence row.
///
/// Call it on the connection of the caller's own `BEGIN IMMEDIATE`, before
/// any crypto callback or protected effect, so the answer and the effect
/// commit or roll back together against the Gateway's fence transaction. It
/// reads only; it neither begins nor finishes the transaction. Only the exact
/// Timeline is read: no Fork ancestor or descendant is consulted.
///
/// The connection must hold a write transaction on `main`
/// (`sqlite3_txn_state` reports `SQLITE_TXN_WRITE`). `BEGIN IMMEDIATE`, and a
/// savepoint inside it, hold one from the start. A deferred `BEGIN` is
/// refused until it has written: before that it may read a stale WAL
/// snapshot, and once it holds the write lock its snapshot is current,
/// because a stale snapshot cannot take the WAL write lock.
///
/// The lookup matches the canonical upper-case 26-character ULID text
/// exactly, so the primary key's index serves it. A stored `timeline_id`
/// that is not canonical (lower case, a blob, or the wrong length) never
/// matches and is ignored. The table's `CHECK` constraints refuse such a row
/// from every normal writer; only `PRAGMA ignore_check_constraints` or file
/// corruption can store one. Normalizing the column in the lookup would
/// defeat the index, so the check relies on those constraints instead.
///
/// # Errors
/// Returns [`ErasureFenceRefusalV1::NotWriteTransaction`] when the connection
/// holds no write transaction on `main`,
/// [`ErasureFenceRefusalV1::Unreadable`] when the read fails (for example,
/// the table is missing), and [`ErasureFenceRefusalV1::Fenced`] or
/// [`ErasureFenceRefusalV1::Malformed`] when a row exists for the Timeline.
pub fn require_no_erasure_fence_rows(
    conn: &Connection,
    timeline: TimelineId,
) -> Result<(), ErasureFenceRefusalV1> {
    if !matches!(
        conn.transaction_state(Some(MAIN_DB)),
        Ok(TransactionState::Write)
    ) {
        return Err(ErasureFenceRefusalV1::NotWriteTransaction);
    }
    conn.query_row(
        EXACT_TIMELINE_ROW_SQL,
        params![timeline.to_string()],
        |row| row.get::<_, bool>(0),
    )
    .optional()
    .map_err(|_| ErasureFenceRefusalV1::Unreadable)
    .and_then(refusal_of)
}

/// Map the parsed first row of the Timeline, if any, to the check's answer.
const fn refusal_of(well_formed: Option<bool>) -> Result<(), ErasureFenceRefusalV1> {
    match well_formed {
        None => Ok(()),
        Some(true) => Err(ErasureFenceRefusalV1::Fenced),
        Some(false) => Err(ErasureFenceRefusalV1::Malformed),
    }
}

impl SqliteStore {
    /// Create the B6 table on a writable open, then validate its exact shape.
    pub(super) fn prepare_erasure_fence_rows_schema(&self) -> Result<(), CoreError> {
        self.conn
            .execute_batch(&sqlite_schema_ddl(ERASURE_FENCE_ROWS_SCHEMA_TABLES))
            .map_err(Self::into_storage_error)
            .and_then(|()| {
                ERASURE_FENCE_ROWS_SCHEMA_TABLES
                    .iter()
                    .try_for_each(|table| self.validate_sqlite_schema_table(table))
            })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
