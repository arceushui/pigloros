//! Exact schema of the `SQLite` Plugin trust policy registry (ADR-103 revision 4, decision 8).
//!
//! The four STRICT tables and the three ledger triggers are one reviewed set. `provision`
//! creates the set when every table is absent; every operation validates it before use. A
//! partial table set, or a present object whose stored definition differs from the reviewed
//! one, is `CorruptState`, and nothing is silently recreated. `CREATE ... IF NOT EXISTS` is
//! never used, because it would keep a weaker object of the same name.
//!
//! `normalize_schema_sql` lowercases a statement and strips all of its whitespace, string
//! literals included, so a reviewed definition must not rely on a literal's case or spacing.
//! The only literals here are the triggers' fixed `RAISE` messages, which carry no semantics.

use rusqlite::{params_from_iter, Connection};

use super::normalize_schema_sql;
use super::plugin_trust_registry_rows::{storage_error, RegistryResult};
use crate::plugin_trust_registry::PluginTrustPolicyRegistryErrorV1;

/// One scope: the persisted anchor, the retained TPS1, both floors, and the highest UTC second.
///
/// The floor pairs carry no `CHECK`: a half-present pair is detected, as `CorruptState`, by the
/// adapter and by the shared floor classification.
const SCOPES_TABLE: &str = "CREATE TABLE plugin_trust_scopes (
    scope                      TEXT    NOT NULL PRIMARY KEY,
    anchor_ptr1_genesis_digest BLOB    NOT NULL CHECK (length(anchor_ptr1_genesis_digest) = 32),
    anchor_operator_key        BLOB    NOT NULL CHECK (length(anchor_operator_key) = 32),
    anchor_operator_role       TEXT    NOT NULL,
    anchor_genesis_tps1_digest BLOB    NOT NULL CHECK (length(anchor_genesis_tps1_digest) = 32),
    tps1_epoch                 INTEGER NOT NULL,
    tps1_digest                BLOB    NOT NULL CHECK (length(tps1_digest) = 32),
    tps1_effective_position    INTEGER NOT NULL,
    tps1_bytes                 BLOB    NOT NULL,
    ptr1_version               INTEGER,
    ptr1_digest                BLOB    CHECK (ptr1_digest IS NULL OR length(ptr1_digest) = 32),
    prv1_epoch                 INTEGER,
    prv1_digest                BLOB    CHECK (prv1_digest IS NULL OR length(prv1_digest) = 32),
    highest_trusted_utc        INTEGER
) STRICT";

/// One admitted release decision, keyed `(scope, PMF1 digest)`.
const DECISIONS_TABLE: &str = "CREATE TABLE plugin_trust_decisions (
    scope                    TEXT    NOT NULL,
    pmf1_digest              BLOB    NOT NULL CHECK (length(pmf1_digest) = 32),
    plugin_id                TEXT    NOT NULL,
    release_digest           BLOB    NOT NULL CHECK (length(release_digest) = 32),
    previous_release_digest  BLOB    CHECK (
        previous_release_digest IS NULL OR length(previous_release_digest) = 32),
    tps1_digest              BLOB    NOT NULL CHECK (length(tps1_digest) = 32),
    tps1_epoch               INTEGER NOT NULL,
    tps1_effective_position  INTEGER NOT NULL,
    ptr1_version             INTEGER NOT NULL,
    ptr1_digest              BLOB    NOT NULL CHECK (length(ptr1_digest) = 32),
    prv1_epoch               INTEGER NOT NULL,
    prv1_digest              BLOB    NOT NULL CHECK (length(prv1_digest) = 32),
    trusted_utc              INTEGER NOT NULL,
    tick                     INTEGER NOT NULL,
    event_timeline           TEXT    NOT NULL,
    event_id                 TEXT    NOT NULL,
    event_seq                INTEGER NOT NULL,
    event_type               TEXT    NOT NULL,
    event_schema_version     INTEGER NOT NULL CHECK (event_schema_version = 1),
    event_payload_digest     BLOB    NOT NULL CHECK (length(event_payload_digest) = 32),
    event_origin_logical_seq INTEGER,
    PRIMARY KEY (scope, pmf1_digest)
) STRICT";

/// The active pointer of one `(scope, exact Plugin ID)`.
const ACTIVE_TABLE: &str = "CREATE TABLE plugin_trust_active (
    scope                    TEXT    NOT NULL,
    plugin_id                TEXT    NOT NULL,
    pmf1_digest              BLOB    NOT NULL CHECK (length(pmf1_digest) = 32),
    release_digest           BLOB    NOT NULL CHECK (length(release_digest) = 32),
    event_timeline           TEXT    NOT NULL,
    event_id                 TEXT    NOT NULL,
    event_seq                INTEGER NOT NULL,
    event_type               TEXT    NOT NULL,
    event_schema_version     INTEGER NOT NULL CHECK (event_schema_version = 1),
    event_payload_digest     BLOB    NOT NULL CHECK (length(event_payload_digest) = 32),
    event_origin_logical_seq INTEGER,
    PRIMARY KEY (scope, plugin_id)
) STRICT";

/// The append-only ledger. `kind` is 1 `Provision`, 2 `Advance`, 3 `Admission`, 4 `Rollback`;
/// the columns a kind does not use stay NULL, and a kind-specific column that is NULL where the
/// kind needs it is `CorruptState` when the row is read.
const LEDGER_TABLE: &str = "CREATE TABLE plugin_trust_ledger (
    scope                       TEXT    NOT NULL,
    row_seq                     INTEGER NOT NULL CHECK (row_seq >= 1),
    kind                        INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 4),
    tps1_digest                 BLOB    NOT NULL CHECK (length(tps1_digest) = 32),
    tps1_epoch                  INTEGER NOT NULL,
    tps1_effective_position     INTEGER NOT NULL,
    ptr1_version                INTEGER,
    ptr1_digest                 BLOB    CHECK (ptr1_digest IS NULL OR length(ptr1_digest) = 32),
    prv1_epoch                  INTEGER,
    prv1_digest                 BLOB    CHECK (prv1_digest IS NULL OR length(prv1_digest) = 32),
    trusted_utc                 INTEGER,
    tick                        INTEGER,
    plugin_id                   TEXT,
    pmf1_digest                 BLOB    CHECK (pmf1_digest IS NULL OR length(pmf1_digest) = 32),
    release_digest              BLOB    CHECK (
        release_digest IS NULL OR length(release_digest) = 32),
    previous_release_digest     BLOB    CHECK (
        previous_release_digest IS NULL OR length(previous_release_digest) = 32),
    previous_active_pmf1_digest BLOB    CHECK (
        previous_active_pmf1_digest IS NULL OR length(previous_active_pmf1_digest) = 32),
    event_timeline              TEXT,
    event_id                    TEXT,
    event_seq                   INTEGER,
    event_type                  TEXT,
    event_schema_version        INTEGER CHECK (
        event_schema_version IS NULL OR event_schema_version = 1),
    event_payload_digest        BLOB    CHECK (
        event_payload_digest IS NULL OR length(event_payload_digest) = 32),
    event_origin_logical_seq    INTEGER,
    PRIMARY KEY (scope, row_seq)
) STRICT";

const LEDGER_NO_UPDATE: &str = "CREATE TRIGGER plugin_trust_ledger_no_update
    BEFORE UPDATE ON plugin_trust_ledger
BEGIN
    SELECT RAISE(ABORT, 'plugin_trust_ledger is append-only');
END";

const LEDGER_NO_DELETE: &str = "CREATE TRIGGER plugin_trust_ledger_no_delete
    BEFORE DELETE ON plugin_trust_ledger
BEGIN
    SELECT RAISE(ABORT, 'plugin_trust_ledger is append-only');
END";

const LEDGER_NO_REPLACE: &str = "CREATE TRIGGER plugin_trust_ledger_no_replace
    BEFORE INSERT ON plugin_trust_ledger
    WHEN EXISTS (
        SELECT 1 FROM plugin_trust_ledger WHERE scope = NEW.scope AND row_seq = NEW.row_seq)
BEGIN
    SELECT RAISE(ABORT, 'plugin_trust_ledger is append-only');
END";

/// Reads the stored definition of every reviewed object that exists.
const STORED_OBJECTS: &str = "SELECT type, name, sql FROM sqlite_master
    WHERE name IN (?1, ?2, ?3, ?4, ?5, ?6, ?7)";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectKind {
    Table,
    Trigger,
}

impl ObjectKind {
    /// The `sqlite_master.type` value.
    const fn sqlite_type(self) -> &'static str {
        match self {
            Self::Table => "table",
            Self::Trigger => "trigger",
        }
    }
}

/// One reviewed schema object.
struct ReviewedObject {
    kind: ObjectKind,
    name: &'static str,
    sql: &'static str,
}

/// The number of reviewed tables; all or none of them exist.
const TABLE_COUNT: usize = 4;

/// The reviewed set, tables before the triggers that guard them.
static REVIEWED: [ReviewedObject; 7] = [
    ReviewedObject {
        kind: ObjectKind::Table,
        name: "plugin_trust_scopes",
        sql: SCOPES_TABLE,
    },
    ReviewedObject {
        kind: ObjectKind::Table,
        name: "plugin_trust_decisions",
        sql: DECISIONS_TABLE,
    },
    ReviewedObject {
        kind: ObjectKind::Table,
        name: "plugin_trust_active",
        sql: ACTIVE_TABLE,
    },
    ReviewedObject {
        kind: ObjectKind::Table,
        name: "plugin_trust_ledger",
        sql: LEDGER_TABLE,
    },
    ReviewedObject {
        kind: ObjectKind::Trigger,
        name: "plugin_trust_ledger_no_update",
        sql: LEDGER_NO_UPDATE,
    },
    ReviewedObject {
        kind: ObjectKind::Trigger,
        name: "plugin_trust_ledger_no_delete",
        sql: LEDGER_NO_DELETE,
    },
    ReviewedObject {
        kind: ObjectKind::Trigger,
        name: "plugin_trust_ledger_no_replace",
        sql: LEDGER_NO_REPLACE,
    },
];

/// Whether the Plugin trust tables exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SchemaStateV1 {
    /// No Plugin trust table exists: the store is not provisioned.
    Absent,
    /// The complete reviewed set exists, byte for byte up to case and whitespace.
    Present,
}

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
            && self.object_type == reviewed.kind.sqlite_type()
            && self
                .sql
                .as_deref()
                .is_some_and(|sql| normalize_schema_sql(sql) == normalize_schema_sql(reviewed.sql))
    }
}

fn stored_objects(connection: &Connection) -> RegistryResult<Vec<StoredObject>> {
    let mut statement = connection
        .prepare(STORED_OBJECTS)
        .map_err(|error| storage_error(&error))?;
    let rows = statement
        .query_map(
            params_from_iter(REVIEWED.iter().map(|reviewed| reviewed.name)),
            |row| {
                Ok(StoredObject {
                    object_type: row.get(0)?,
                    name: row.get(1)?,
                    sql: row.get(2)?,
                })
            },
        )
        .map_err(|error| storage_error(&error))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| storage_error(&error))
}

/// Classify the stored schema: absent, the exact reviewed set, or `CorruptState`.
///
/// # Errors
/// `CorruptState` for a partial table set or a present object of a different shape; a storage
/// error when `sqlite_master` cannot be read.
pub(super) fn validate(connection: &Connection) -> RegistryResult<SchemaStateV1> {
    let stored = stored_objects(connection)?;
    let tables = REVIEWED
        .iter()
        .filter(|reviewed| reviewed.kind == ObjectKind::Table)
        .filter(|reviewed| stored.iter().any(|found| found.name == reviewed.name))
        .count();
    if tables == 0 {
        // A reviewed-name trigger or index without its table is not a clean, unprovisioned store.
        return if stored.is_empty() {
            Ok(SchemaStateV1::Absent)
        } else {
            Err(PluginTrustPolicyRegistryErrorV1::CorruptState)
        };
    }
    let exact = tables == TABLE_COUNT
        && REVIEWED
            .iter()
            .all(|reviewed| stored.iter().any(|found| found.is(reviewed)));
    if exact {
        Ok(SchemaStateV1::Present)
    } else {
        Err(PluginTrustPolicyRegistryErrorV1::CorruptState)
    }
}

/// Every operation except `provision` needs the complete schema.
///
/// # Errors
/// `MissingState` when every table is absent; `CorruptState` for any other deviation.
pub(super) fn require_present(connection: &Connection) -> RegistryResult<()> {
    match validate(connection)? {
        SchemaStateV1::Present => Ok(()),
        SchemaStateV1::Absent => Err(PluginTrustPolicyRegistryErrorV1::MissingState),
    }
}

/// `provision` creates the reviewed set when every table is absent and otherwise validates it.
///
/// # Errors
/// `CorruptState` for a partial or different set; a storage error when a statement fails.
pub(super) fn ensure_for_provision(connection: &Connection) -> RegistryResult<()> {
    match validate(connection)? {
        SchemaStateV1::Present => Ok(()),
        SchemaStateV1::Absent => REVIEWED.iter().try_for_each(|reviewed| {
            connection
                .execute_batch(reviewed.sql)
                .map_err(|error| storage_error(&error))
        }),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn the_reviewed_set_names_four_tables_then_three_triggers() {
        assert_eq!(REVIEWED.len(), 7);
        let tables = REVIEWED
            .iter()
            .filter(|reviewed| reviewed.kind == ObjectKind::Table)
            .count();
        assert_eq!(tables, TABLE_COUNT);
        assert!(REVIEWED[..TABLE_COUNT]
            .iter()
            .all(|reviewed| reviewed.kind == ObjectKind::Table));
        assert!(REVIEWED[TABLE_COUNT..]
            .iter()
            .all(|reviewed| reviewed.kind == ObjectKind::Trigger));
    }
}
