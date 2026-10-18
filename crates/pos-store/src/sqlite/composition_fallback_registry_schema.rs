//! Exact schema of the `SQLite` composition fallback registry (ADR-119 section 4.3).
//!
//! The four STRICT tables and the five append-only triggers are one reviewed set.
//! `provision_fallback_registry` creates the set when every table is absent; every operation
//! validates it before use. A partial table set, or a present object whose stored definition
//! differs from the reviewed one, is `CorruptState`, and nothing is silently recreated.
//!
//! The ledger's kind-specific columns carry no `CHECK` tying them to `kind`: a column that is
//! NULL where the kind needs it is `CorruptState` when the row is read. The ledger's `UNIQUE`
//! constraints are the port's uniqueness on `(scope, timeline, entry_key, closing tenure)` and
//! on the activation ordinal, and on one declaration per policy digest.

use rusqlite::{params_from_iter, Connection};

use super::composition_fallback_registry_rows::{query_many, storage_error, Columns};
use super::normalize_schema_sql;
use crate::composition_fallback_registry::logic::{require, FallbackResult};
use crate::composition_fallback_registry::CompositionFallbackRegistryErrorV1 as Error;

/// The retained DFP1 bytes, keyed by policy digest.
const POLICIES_TABLE: &str = "CREATE TABLE composition_fallback_policies (
    policy_digest BLOB NOT NULL PRIMARY KEY CHECK (length(policy_digest) = 32),
    policy_bytes  BLOB NOT NULL
) STRICT";

/// One `(scope, timeline)` row: the recorded entity and the folded scalar state.
const ROWS_TABLE: &str = "CREATE TABLE composition_fallback_rows (
    scope              TEXT    NOT NULL,
    timeline           TEXT    NOT NULL,
    entity             BLOB    NOT NULL CHECK (length(entity) = 16),
    state_revision     INTEGER NOT NULL,
    policy_digest      BLOB    CHECK (policy_digest IS NULL OR length(policy_digest) = 32),
    activation_ordinal INTEGER NOT NULL,
    PRIMARY KEY (scope, timeline)
) STRICT";

/// The per-entry state of one row.
const ENTRIES_TABLE: &str = "CREATE TABLE composition_fallback_entries (
    scope            TEXT    NOT NULL,
    timeline         TEXT    NOT NULL,
    entry_key        TEXT    NOT NULL,
    tenure_ordinal   INTEGER NOT NULL,
    effective_digest BLOB    NOT NULL CHECK (length(effective_digest) = 32),
    chain_position   INTEGER NOT NULL CHECK (chain_position BETWEEN 0 AND 2),
    PRIMARY KEY (scope, timeline, entry_key)
) STRICT";

/// The append-only ledger. `kind` is 1 `Declaration`, 2 `Activation`.
const LEDGER_TABLE: &str = "CREATE TABLE composition_fallback_ledger (
    scope                  TEXT    NOT NULL,
    timeline               TEXT    NOT NULL,
    row_seq                INTEGER NOT NULL CHECK (row_seq >= 1),
    kind                   INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 2),
    entity                 BLOB    NOT NULL CHECK (length(entity) = 16),
    state_revision         INTEGER NOT NULL,
    policy_digest          BLOB    NOT NULL CHECK (length(policy_digest) = 32),
    request_digest         BLOB    NOT NULL CHECK (length(request_digest) = 32),
    declared_digest        BLOB    CHECK (declared_digest IS NULL OR length(declared_digest) = 32),
    conformance_digest     BLOB    CHECK (
        conformance_digest IS NULL OR length(conformance_digest) = 32),
    entry_key              TEXT,
    closing_tenure_ordinal INTEGER,
    activation_ordinal     INTEGER,
    tick                   INTEGER,
    event_id               BLOB    NOT NULL CHECK (length(event_id) = 16),
    event_seq              INTEGER NOT NULL,
    event_payload_digest   BLOB    NOT NULL CHECK (length(event_payload_digest) = 32),
    PRIMARY KEY (scope, timeline, row_seq),
    UNIQUE (scope, timeline, declared_digest),
    UNIQUE (scope, timeline, entry_key, closing_tenure_ordinal),
    UNIQUE (scope, timeline, activation_ordinal)
) STRICT";

const LEDGER_NO_UPDATE: &str = "CREATE TRIGGER composition_fallback_ledger_no_update
    BEFORE UPDATE ON composition_fallback_ledger
BEGIN
    SELECT RAISE(ABORT, 'composition_fallback_ledger is append-only');
END";

const LEDGER_NO_DELETE: &str = "CREATE TRIGGER composition_fallback_ledger_no_delete
    BEFORE DELETE ON composition_fallback_ledger
BEGIN
    SELECT RAISE(ABORT, 'composition_fallback_ledger is append-only');
END";

const LEDGER_NO_REPLACE: &str = "CREATE TRIGGER composition_fallback_ledger_no_replace
    BEFORE INSERT ON composition_fallback_ledger
    WHEN EXISTS (
        SELECT 1 FROM composition_fallback_ledger
        WHERE scope = NEW.scope AND timeline = NEW.timeline AND row_seq = NEW.row_seq)
BEGIN
    SELECT RAISE(ABORT, 'composition_fallback_ledger is append-only');
END";

const POLICY_NO_UPDATE: &str = "CREATE TRIGGER composition_fallback_policies_no_update
    BEFORE UPDATE ON composition_fallback_policies
BEGIN
    SELECT RAISE(ABORT, 'composition_fallback_policies is append-only');
END";

const POLICY_NO_DELETE: &str = "CREATE TRIGGER composition_fallback_policies_no_delete
    BEFORE DELETE ON composition_fallback_policies
BEGIN
    SELECT RAISE(ABORT, 'composition_fallback_policies is append-only');
END";

/// Reads the stored definition of every reviewed object that exists.
const STORED_OBJECTS: &str = "SELECT type, name, sql FROM sqlite_master
    WHERE name IN (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";

/// One reviewed schema object: its `sqlite_master.type`, name, and definition.
struct ReviewedObject {
    object_type: &'static str,
    name: &'static str,
    sql: &'static str,
}

/// The reviewed set, tables before the triggers that guard them.
static REVIEWED: [ReviewedObject; 9] = [
    ReviewedObject {
        object_type: "table",
        name: "composition_fallback_policies",
        sql: POLICIES_TABLE,
    },
    ReviewedObject {
        object_type: "table",
        name: "composition_fallback_rows",
        sql: ROWS_TABLE,
    },
    ReviewedObject {
        object_type: "table",
        name: "composition_fallback_entries",
        sql: ENTRIES_TABLE,
    },
    ReviewedObject {
        object_type: "table",
        name: "composition_fallback_ledger",
        sql: LEDGER_TABLE,
    },
    ReviewedObject {
        object_type: "trigger",
        name: "composition_fallback_ledger_no_update",
        sql: LEDGER_NO_UPDATE,
    },
    ReviewedObject {
        object_type: "trigger",
        name: "composition_fallback_ledger_no_delete",
        sql: LEDGER_NO_DELETE,
    },
    ReviewedObject {
        object_type: "trigger",
        name: "composition_fallback_ledger_no_replace",
        sql: LEDGER_NO_REPLACE,
    },
    ReviewedObject {
        object_type: "trigger",
        name: "composition_fallback_policies_no_update",
        sql: POLICY_NO_UPDATE,
    },
    ReviewedObject {
        object_type: "trigger",
        name: "composition_fallback_policies_no_delete",
        sql: POLICY_NO_DELETE,
    },
];

/// One stored schema object found by name.
struct StoredObject {
    object_type: String,
    name: String,
    sql: Option<String>,
}

impl StoredObject {
    /// Whether this is the reviewed object: same name, type, and normalized definition.
    fn is(&self, reviewed: &ReviewedObject) -> bool {
        self.name == reviewed.name
            && self.object_type == reviewed.object_type
            && self
                .sql
                .as_deref()
                .is_some_and(|sql| normalize_schema_sql(sql) == normalize_schema_sql(reviewed.sql))
    }
}

fn stored_objects(connection: &Connection) -> FallbackResult<Vec<StoredObject>> {
    query_many(
        connection,
        STORED_OBJECTS,
        params_from_iter(REVIEWED.iter().map(|reviewed| reviewed.name)),
        |row| {
            let cols = Columns::new(row);
            cols.finish(StoredObject {
                object_type: cols.get("type"),
                name: cols.get("name"),
                sql: cols.get("sql"),
            })
        },
    )
}

/// `Ok(true)` for the exact reviewed set, `Ok(false)` for no object at all, else `CorruptState`.
fn classify(stored: &[StoredObject]) -> FallbackResult<bool> {
    let exact = REVIEWED
        .iter()
        .all(|reviewed| stored.iter().any(|found| found.is(reviewed)));
    require(exact || stored.is_empty(), Error::CorruptState).map(|()| exact)
}

/// Every operation except provisioning needs the complete schema.
///
/// # Errors
/// `MissingState` when no reviewed object exists; `CorruptState` for any other deviation.
pub(super) fn require_present(connection: &Connection) -> FallbackResult<()> {
    stored_objects(connection)
        .and_then(|stored| classify(&stored))
        .and_then(|present| present.then_some(()).ok_or(Error::MissingState))
}

/// Create the reviewed set when nothing exists, and report whether it was created.
///
/// # Errors
/// `CorruptState` for a partial or different set; a storage error when a statement fails.
pub(super) fn ensure_for_provision(connection: &Connection) -> FallbackResult<bool> {
    let present = stored_objects(connection).and_then(|stored| classify(&stored))?;
    REVIEWED
        .iter()
        .filter(|_| !present)
        .try_for_each(|reviewed| {
            connection
                .execute_batch(reviewed.sql)
                .map_err(|error| storage_error(&error))
        })
        .map(|()| !present)
}
