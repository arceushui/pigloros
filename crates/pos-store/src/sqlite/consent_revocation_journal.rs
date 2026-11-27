#![cfg(all(target_os = "linux", any(test, feature = "test-support")))]
//! ADR-137 I1 consent revocation journal table and the `events` lookup index.
//!
//! The journal records the Gateway's durable intent for one `consent.revoked.v1`
//! append at a time (`Pending`), and the outcome of the newest finished
//! operations (`Committed` or `Aborted`). I6 bounds it to two rows, and the
//! partial unique index `consent_revocation_single_pending` allows at most one
//! `Pending` row. The row `CHECK`s admit only the three state shapes of I1.
//!
//! This module owns the DDL and its exact-shape validation only. The Gateway
//! writers (I2, I3, I5, I6), the closed error types (I8) and the ceiling-free
//! append (I9) are separate slices, and the owner composition has no API that
//! writes the journal (I7). Everything here stays test-support gated until
//! owner activation (#1438).
//!
//! The ADR-137 A3 lookup needs `idx_events_entity_type` on
//! `events(timeline_id, entity_id, event_type, seq)`, so the same writable
//! open creates it. Only a writable open creates and validates these objects;
//! a read-only open neither creates nor validates them. Ungating in #1438 must
//! remove both `cfg` gates together, this module's and the writable-open call
//! in `sqlite.rs`.

use pos_core::error::CoreError;
use rusqlite::{params, OptionalExtension};

use super::{normalize_schema_sql, SqliteStore};

/// One schema object this module creates and validates.
struct JournalSchemaObject {
    /// The `sqlite_schema.type` of the object.
    kind: &'static str,
    name: &'static str,
    /// The table the object belongs to.
    table: &'static str,
    /// The idempotent `CREATE` statement, without a trailing semicolon.
    create: &'static str,
}

/// The journal table, its single-`Pending` index and the `events` index.
const JOURNAL_SCHEMA_OBJECTS: [JournalSchemaObject; 3] = [
    JournalSchemaObject {
        kind: "table",
        name: "consent_revocation_journal",
        table: "consent_revocation_journal",
        create: "CREATE TABLE IF NOT EXISTS consent_revocation_journal (
    journal_seq      INTEGER NOT NULL UNIQUE CHECK (journal_seq >= 1),
    operation_id     BLOB    PRIMARY KEY CHECK (length(operation_id) = 16),
    generation       INTEGER NOT NULL CHECK (generation >= 1),
    timeline_id      TEXT    NOT NULL,
    subject_id       TEXT    NOT NULL,
    grantee_id       TEXT    NOT NULL,
    grant_seq        INTEGER NOT NULL CHECK (grant_seq >= 1),
    requested_fence  INTEGER NOT NULL CHECK (requested_fence >= 2),
    binding_digest   BLOB    NOT NULL CHECK (length(binding_digest) = 32),
    state            INTEGER NOT NULL CHECK (state IN (1, 2, 3)),
    abort_reason     INTEGER CHECK (abort_reason IS NULL OR abort_reason IN (1, 2)),
    event_id         TEXT,
    CHECK ((state = 1 AND abort_reason IS NULL AND event_id IS NULL)
        OR (state = 2 AND abort_reason IS NULL AND event_id IS NOT NULL)
        OR (state = 3 AND abort_reason IS NOT NULL AND event_id IS NULL))
) STRICT",
    },
    JournalSchemaObject {
        kind: "index",
        name: "consent_revocation_single_pending",
        table: "consent_revocation_journal",
        create: "CREATE UNIQUE INDEX IF NOT EXISTS consent_revocation_single_pending
    ON consent_revocation_journal(state) WHERE state = 1",
    },
    JournalSchemaObject {
        kind: "index",
        name: "idx_events_entity_type",
        table: "events",
        create: "CREATE INDEX IF NOT EXISTS idx_events_entity_type
    ON events(timeline_id, entity_id, event_type, seq)",
    },
];

/// The stored text of the object, which `SQLite` writes without `IF NOT EXISTS`.
fn expected_sql(object: &JournalSchemaObject) -> String {
    normalize_schema_sql(object.create).replacen("ifnotexists", "", 1)
}

/// The refusal for an object that is missing, of another type or table, or with other text.
fn incompatible(object: &JournalSchemaObject) -> CoreError {
    CoreError::Storage(format!(
        "SQLite {} {} is missing or has an incompatible schema",
        object.kind, object.name
    ))
}

impl SqliteStore {
    /// Refuse foreign objects, create the journal objects, then validate their text.
    pub(super) fn prepare_consent_revocation_journal_schema(&self) -> Result<(), CoreError> {
        JOURNAL_SCHEMA_OBJECTS
            .iter()
            .try_for_each(|object| self.refuse_foreign_journal_object(object))
            .and_then(|()| {
                self.conn
                    .execute_batch(
                        &JOURNAL_SCHEMA_OBJECTS
                            .iter()
                            .map(|object| object.create)
                            .collect::<Vec<_>>()
                            .join(";\n"),
                    )
                    .map_err(Self::into_storage_error)
            })
            .and_then(|()| {
                JOURNAL_SCHEMA_OBJECTS
                    .iter()
                    .try_for_each(|object| self.validate_consent_revocation_journal_object(object))
            })
    }

    /// Refuse an object of that name that has another type or belongs to another table.
    ///
    /// This runs before the `CREATE ... IF NOT EXISTS` statements, so the
    /// refusal is this module's fixed text and not `SQLite`'s own wording.
    fn refuse_foreign_journal_object(&self, object: &JournalSchemaObject) -> Result<(), CoreError> {
        self.conn
            .query_row(
                "SELECT type, tbl_name FROM main.sqlite_schema WHERE name = ?1",
                params![object.name],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(Self::into_storage_error)
            .and_then(|found| match found {
                Some(found) if found != (object.kind.to_owned(), object.table.to_owned()) => {
                    Err(incompatible(object))
                }
                _ => Ok(()),
            })
    }

    /// Refuse a created object whose stored text differs from the ADR text.
    fn validate_consent_revocation_journal_object(
        &self,
        object: &JournalSchemaObject,
    ) -> Result<(), CoreError> {
        self.conn
            .query_row(
                "SELECT sql FROM main.sqlite_schema WHERE name = ?1",
                params![object.name],
                |row| row.get::<_, String>(0),
            )
            .map_err(Self::into_storage_error)
            .and_then(|sql| {
                if normalize_schema_sql(&sql) == expected_sql(object) {
                    Ok(())
                } else {
                    Err(incompatible(object))
                }
            })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
