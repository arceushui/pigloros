//! Child-local provenance selection and open-time index qualification (ADR-120).

use pos_core::CoreError;
use rusqlite::{params, Connection};

type Result<T> = std::result::Result<T, CoreError>;

struct ProvenanceIndexV1 {
    name: &'static str,
    table: &'static str,
    create: &'static str,
}

const INDEXES: [ProvenanceIndexV1; 2] = [
    ProvenanceIndexV1 {
        name: "idx_fork_event_origins_child_v1",
        table: "fork_event_origins",
        create: "CREATE INDEX idx_fork_event_origins_child_v1
            ON fork_event_origins(substr(eor1_cbor, 9, 16))",
    },
    ProvenanceIndexV1 {
        name: "idx_fork_intervention_admissions_child_v1",
        table: "fork_intervention_admissions",
        create: "CREATE INDEX idx_fork_intervention_admissions_child_v1
            ON fork_intervention_admissions(substr(fia1_cbor, 43, 16))",
    },
];

pub(super) const ORPHANED_PROVENANCE: &str = "SELECT EXISTS(
    SELECT 1 FROM fork_event_origins INDEXED BY idx_fork_event_origins_child_v1
    LEFT JOIN events ON events.timeline_id = ?1
        AND events.event_id = fork_event_origins.event_id
    WHERE substr(eor1_cbor, 9, 16) = ?2 AND events.event_id IS NULL
) OR EXISTS(
    SELECT 1 FROM fork_intervention_admissions
        INDEXED BY idx_fork_intervention_admissions_child_v1
    LEFT JOIN events ON events.timeline_id = ?1
        AND events.event_id = fork_intervention_admissions.event_id
    WHERE substr(fia1_cbor, 43, 16) = ?2 AND events.event_id IS NULL
)";

fn incompatible(index: &ProvenanceIndexV1) -> CoreError {
    CoreError::Storage(format!(
        "SQLite {} is missing or incompatible; prepare once using read-write open",
        index.name
    ))
}

fn normalize(sql: &str) -> String {
    let whitespace = [' ', '\t', '\r', '\n', '\u{c}'];
    let trimmed = sql.trim_end_matches(whitespace);
    trimmed
        .strip_suffix(';')
        .unwrap_or(trimmed)
        .chars()
        .filter(|character| !whitespace.contains(character))
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn definition(conn: &Connection, index: &ProvenanceIndexV1) -> Result<Option<String>> {
    let mut statement = conn
        .prepare(
            "SELECT type, name, tbl_name, sql FROM main.sqlite_schema
             WHERE name = ?1 COLLATE NOCASE",
        )
        .map_err(super::SqliteStore::into_storage_error)?;
    let mut rows = statement
        .query_map([index.name], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(super::SqliteStore::into_storage_error)?;
    let first = rows
        .next()
        .transpose()
        .map_err(super::SqliteStore::into_storage_error)?;
    if rows
        .next()
        .transpose()
        .map_err(super::SqliteStore::into_storage_error)?
        .is_some()
    {
        return Err(incompatible(index));
    }
    first
        .map(|(kind, name, table, sql)| {
            if kind != "index" || name != index.name || table != index.table {
                return Err(incompatible(index));
            }
            sql.ok_or_else(|| incompatible(index))
        })
        .transpose()
}

fn validate_index(conn: &Connection, index: &ProvenanceIndexV1, sql: &str) -> Result<()> {
    if normalize(sql) != normalize(index.create) {
        return Err(incompatible(index));
    }
    let valid = conn
        .query_row(
            "SELECT
                (SELECT count(*) = 1 FROM pragma_index_list(?1)
                    WHERE name = ?2 AND \"unique\" = 0 AND origin = 'c' AND partial = 0)
                AND (SELECT count(*) = 2 FROM pragma_index_xinfo(?2))
                AND (SELECT count(*) = 1 FROM pragma_index_xinfo(?2)
                    WHERE seqno = 0 AND cid = -2 AND name IS NULL
                        AND \"desc\" = 0 AND coll = 'BINARY' AND key = 1)
                AND (SELECT count(*) = 1 FROM pragma_index_xinfo(?2)
                    WHERE seqno = 1 AND cid = -1 AND name IS NULL
                        AND \"desc\" = 0 AND coll = 'BINARY' AND key = 0)",
            params![index.table, index.name],
            |row| row.get::<_, bool>(0),
        )
        .map_err(super::SqliteStore::into_storage_error)?;
    if valid {
        Ok(())
    } else {
        Err(incompatible(index))
    }
}

pub(super) fn prepare(conn: &Connection) -> Result<()> {
    INDEXES.iter().try_for_each(|index| {
        let sql = match definition(conn, index)? {
            Some(sql) => sql,
            None => {
                conn.execute_batch(index.create)
                    .map_err(super::SqliteStore::into_storage_error)?;
                definition(conn, index)?.ok_or_else(|| incompatible(index))?
            }
        };
        validate_index(conn, index, &sql)
    })
}

pub(super) fn validate(conn: &Connection) -> Result<()> {
    INDEXES.iter().try_for_each(|index| {
        let sql = definition(conn, index)?.ok_or_else(|| incompatible(index))?;
        validate_index(conn, index, &sql)
    })
}

pub(super) fn require_autocommit(conn: &Connection) -> Result<()> {
    if conn.is_autocommit() {
        Ok(())
    } else {
        Err(CoreError::Storage(
            "SQLite fork schema preparation requires a settled transaction".to_owned(),
        ))
    }
}

/// Called only after this opener successfully acquired its own transaction.
pub(super) fn finish_owned_preparation(conn: &Connection, result: Result<()>) -> Result<()> {
    result
        .and_then(|()| require_autocommit(conn))
        .or_else(|error| {
            if conn.is_autocommit() {
                return Err(error);
            }
            conn.execute_batch("ROLLBACK").map_err(|rollback| {
                CoreError::Storage(format!(
                    "SQLite fork schema rollback is uncertain; discard connection: {rollback}"
                ))
            })?;
            require_autocommit(conn).and(Err(error))
        })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
