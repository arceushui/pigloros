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
    conn.prepare(
        "SELECT type, name, tbl_name, sql FROM main.sqlite_schema
         WHERE name = ?1 COLLATE NOCASE",
    )
    .and_then(|mut statement| {
        statement
            .query_map([index.name], |row| {
                row.get::<_, String>(0)
                    .and_then(|kind| row.get::<_, String>(1).map(|name| (kind, name)))
                    .and_then(|(kind, name)| {
                        row.get::<_, String>(2).map(|table| (kind, name, table))
                    })
                    .and_then(|(kind, name, table)| {
                        row.get::<_, Option<String>>(3)
                            .map(|sql| (kind, name, table, sql))
                    })
            })
            // Only two rows are needed to refuse a catalog-name collision.
            .and_then(|rows| rows.take(2).collect::<rusqlite::Result<Vec<_>>>())
    })
    .map_err(super::SqliteStore::into_storage_error)
    .and_then(|mut rows| {
        if rows.len() > 1 {
            return Err(incompatible(index));
        }
        rows.pop()
            .map(|(kind, name, table, sql)| {
                if kind != "index" || name != index.name || table != index.table {
                    return Err(incompatible(index));
                }
                sql.ok_or_else(|| incompatible(index))
            })
            .transpose()
    })
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
        let sql = if let Some(sql) = definition(conn, index)? {
            sql
        } else {
            conn.execute_batch(index.create)
                .map_err(super::SqliteStore::into_storage_error)?;
            // Native metadata is qualified below. The owned opener re-reads
            // both durable catalog definitions before its sole COMMIT.
            index.create.to_owned()
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
mod tests {
    //! Public-open witnesses plus private native fault injection for ADR-120.

    use super::super::SqliteStore;
    use super::*;
    use crate::fae1_fixture::Fallible;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };

    fn remove_indexes(conn: &Connection) -> rusqlite::Result<()> {
        conn.execute_batch(
            "DROP INDEX idx_fork_event_origins_child_v1;
             DROP INDEX idx_fork_intervention_admissions_child_v1",
        )
    }

    fn storage_error<T>(result: &Result<T>) {
        assert!(matches!(result, Err(CoreError::Storage(_))));
    }

    fn schema(conn: &Connection) -> rusqlite::Result<Vec<(String, String)>> {
        let mut statement =
            conn.prepare("SELECT name, coalesce(sql, '') FROM sqlite_schema ORDER BY name")?;
        let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect()
    }

    fn fresh_helper_store() -> Fallible<SqliteStore> {
        let store = SqliteStore::open(":memory:")?;
        for table in super::super::FORK_ADMISSION_SCHEMA_TABLES {
            store
                .conn
                .execute_batch(&format!("DROP TABLE {}", table.name))?;
        }
        store
            .conn
            .execute_batch("DROP TABLE fork_admission_authority")?;
        Ok(store)
    }

    #[test]
    fn fresh_helper_orders_retained_work_before_indexes_and_commits_once() -> Fallible<()> {
        let store = fresh_helper_store()?;
        let actions = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&actions);
        store
            .conn
            .authorizer(Some(move |context: AuthContext<'_>| {
                let Ok(mut actions) = observed.lock() else {
                    return Authorization::Deny;
                };
                actions.push(format!("{:?}", context.action));
                Authorization::Allow
            }))?;
        let commits = Arc::new(AtomicUsize::new(0));
        let committed = Arc::clone(&commits);
        store.conn.commit_hook(Some(move || {
            committed.fetch_add(1, Ordering::SeqCst);
            false
        }))?;
        store.prepare_fork_admission_authority_schema()?;
        store
            .conn
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
        store.conn.commit_hook::<fn() -> bool>(None)?;
        assert_eq!(commits.load(Ordering::SeqCst), 1);
        assert!(store.conn.is_autocommit());
        let actions = actions.lock().map_err(|_| "action capture")?;
        let position = |needle: &str| -> Fallible<usize> {
            actions
                .iter()
                .position(|line| line.contains(needle))
                .ok_or_else(|| needle.to_owned().into())
        };
        let eor = position("index_name: \"idx_fork_event_origins_child_v1\"")?;
        let fia = position("index_name: \"idx_fork_intervention_admissions_child_v1\"")?;
        assert!(position("CreateTable { table_name: \"fork_admission_authority\"")? < eor);
        for table in super::super::FORK_ADMISSION_SCHEMA_TABLES {
            assert!(position(&format!("CreateTable {{ table_name: \"{}\"", table.name))? < eor);
        }
        assert!(position("index_name: \"idx_imported_pob1_principal\"")? < eor);
        assert!(position("Insert { table_name: \"fork_delivery_fence_counter\"")? < eor);
        assert!(eor < fia);
        assert_eq!(
            store.conn.query_row(
                "SELECT last_fence FROM fork_delivery_fence_counter WHERE id=1",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
        validate(&store.conn)?;
        Ok(())
    }

    #[test]
    fn repeat_open_does_not_recreate_indexes_or_reset_a_nonzero_fence() -> Fallible<()> {
        let store = SqliteStore::open(":memory:")?;
        store.conn.execute(
            "UPDATE fork_delivery_fence_counter SET last_fence=73 WHERE id=1",
            [],
        )?;
        let before = schema(&store.conn)?;
        store.conn.authorizer(Some(|context: AuthContext<'_>| {
            if matches!(context.action, AuthAction::CreateIndex { index_name, .. } if INDEXES.iter().any(|index| index.name == index_name)) {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }))?;
        store.prepare_fork_admission_authority_schema()?;
        store
            .conn
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
        assert_eq!(schema(&store.conn)?, before);
        assert_eq!(
            store.conn.query_row(
                "SELECT last_fence FROM fork_delivery_fence_counter WHERE id=1",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            73
        );
        Ok(())
    }

    #[test]
    fn read_only_open_refuses_legacy_indexes_until_one_writable_preparation() -> Fallible<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("legacy.sqlite");
        let path = path.to_str().ok_or("UTF-8 path")?;
        let store = SqliteStore::open(path)?;
        store.conn.execute(
            "UPDATE fork_delivery_fence_counter SET last_fence=73 WHERE id=1",
            [],
        )?;
        remove_indexes(&store.conn)?;
        let before = schema(&store.conn)?;
        drop(store);
        match SqliteStore::open_read_only(path) {
            Err(CoreError::Storage(message)) => {
                assert!(message.contains("prepare once using read-write open"));
            }
            _ => return Err("read-only legacy open must refuse".into()),
        }
        let raw = Connection::open(path)?;
        assert_eq!(schema(&raw)?, before);
        drop(raw);
        let upgraded = SqliteStore::open(path)?;
        validate(&upgraded.conn)?;
        assert_eq!(
            upgraded.conn.query_row(
                "SELECT last_fence FROM fork_delivery_fence_counter WHERE id=1",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            73
        );
        drop(upgraded);
        let reopened = SqliteStore::open_read_only(path)?;
        validate(&reopened.conn)?;
        Ok(())
    }

    #[test]
    fn incompatible_definitions_are_rejected_not_repaired_by_public_open() -> Fallible<()> {
        for ddl in [
            "CREATE TABLE idx_fork_event_origins_child_v1 (value)",
            "CREATE VIEW idx_fork_event_origins_child_v1 AS SELECT 1",
            "CREATE INDEX idx_fork_event_origins_child_v1 ON fork_event_origins(substr(eor1_cbor,9,16));
             CREATE TRIGGER idx_fork_event_origins_child_v1 AFTER INSERT ON fork_event_origins BEGIN SELECT 1; END",
            "CREATE INDEX IDX_FORK_EVENT_ORIGINS_CHILD_V1 ON fork_event_origins(substr(eor1_cbor,9,16))",
            "CREATE INDEX idx_fork_event_origins_child_v1 ON fork_intervention_admissions(substr(fia1_cbor,9,16))",
            "CREATE INDEX idx_fork_event_origins_child_v1 ON fork_event_origins(substr(eor1_cbor,8,16))",
            "CREATE INDEX idx_fork_event_origins_child_v1 ON fork_event_origins(substr(eor1_cbor,9,15))",
            "CREATE INDEX idx_fork_event_origins_child_v1 ON fork_event_origins(substring(eor1_cbor,9,16))",
            "CREATE INDEX idx_fork_event_origins_child_v1 ON fork_event_origins(substr(CAST(eor1_cbor AS BLOB),9,16))",
            "CREATE INDEX idx_fork_event_origins_child_v1 ON fork_event_origins(substr(eor1_cbor,9,16) COLLATE NOCASE)",
            "CREATE INDEX idx_fork_event_origins_child_v1 ON fork_event_origins(substr(eor1_cbor,9,16) DESC)",
            "CREATE INDEX idx_fork_event_origins_child_v1 ON fork_event_origins(substr(eor1_cbor,9,16) ASC)",
            "CREATE INDEX idx_fork_event_origins_child_v1 ON fork_event_origins(substr(eor1_cbor,9,16)) WHERE event_id IS NOT NULL",
            "CREATE UNIQUE INDEX idx_fork_event_origins_child_v1 ON fork_event_origins(substr(eor1_cbor,9,16))",
            "CREATE INDEX idx_fork_event_origins_child_v1 ON fork_event_origins(substr(eor1_cbor,9,16),event_id)",
            "CREATE INDEX idx_fork_event_origins_child_v1 ON fork_event_origins(substr(/*comment*/eor1_cbor,9,16))",
            "CREATE INDEX idx_fork_event_origins_child_v1 ON fork_event_origins(substr(\"eor1_cbor\",9,16))",
        ] {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("incompatible.sqlite");
            let path = path.to_str().ok_or("UTF-8 path")?;
            let store = SqliteStore::open(path)?;
            store.conn.execute_batch("DROP INDEX idx_fork_event_origins_child_v1")?;
            store.conn.execute_batch(ddl)?;
            let before = schema(&store.conn)?;
            drop(store);
            storage_error(&SqliteStore::open_read_only(path));
            storage_error(&SqliteStore::open(path));
            let raw = Connection::open(path)?;
            assert_eq!(schema(&raw)?, before, "{ddl}");
        }
        Ok(())
    }

    #[test]
    fn canonical_sql_normalization_is_closed_and_ascii_only() {
        let canonical = INDEXES[0].create;
        assert_eq!(
            normalize(canonical),
            normalize(&format!("\t{} ;\r\n", canonical.to_ascii_lowercase()))
        );
        for changed in [
            format!("{canonical};;"),
            format!("{canonical} --comment"),
            canonical.replace("CREATE INDEX", "CREATE INDEX IF NOT EXISTS"),
            canonical.replace("CREATE INDEX", "CREATE\u{a0}INDEX"),
            canonical.replace("eor1_cbor", "\"eor1_cbor\""),
        ] {
            assert_ne!(normalize(canonical), normalize(&changed));
        }
    }

    #[test]
    fn every_retained_create_and_new_index_failure_rolls_back_the_entire_helper() -> Fallible<()> {
        let names = std::iter::once("fork_admission_authority")
            .chain(
                super::super::FORK_ADMISSION_SCHEMA_TABLES
                    .iter()
                    .map(|table| table.name),
            )
            .chain([
                "idx_imported_pob1_principal",
                INDEXES[0].name,
                INDEXES[1].name,
            ]);
        for name in names {
            let store = fresh_helper_store()?;
            let before = schema(&store.conn)?;
            let hit = Arc::new(AtomicUsize::new(0));
            let denied = Arc::clone(&hit);
            store
                .conn
                .authorizer(Some(move |context: AuthContext<'_>| {
                    let target = match context.action {
                        AuthAction::CreateTable { table_name } => table_name == name,
                        AuthAction::CreateIndex { index_name, .. } => index_name == name,
                        _ => false,
                    };
                    if target {
                        denied.fetch_add(1, Ordering::SeqCst);
                        Authorization::Deny
                    } else {
                        Authorization::Allow
                    }
                }))?;
            storage_error(&store.prepare_fork_admission_authority_schema());
            store
                .conn
                .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
            assert_eq!(hit.load(Ordering::SeqCst), 1, "{name}");
            assert!(store.conn.is_autocommit(), "{name}");
            assert_eq!(schema(&store.conn)?, before, "{name}");
        }
        Ok(())
    }

    #[test]
    fn seed_validation_commit_and_rollback_faults_fail_closed() -> Fallible<()> {
        for stage in [
            "seed",
            "table-validation",
            "index-validation",
            "commit",
            "rollback",
        ] {
            let store = fresh_helper_store()?;
            let before = schema(&store.conn)?;
            let hit = Arc::new(AtomicUsize::new(0));
            let denied = Arc::clone(&hit);
            store
                .conn
                .authorizer(Some(move |context: AuthContext<'_>| {
                    let target = match context.action {
                        AuthAction::Insert {
                            table_name: "fork_delivery_fence_counter",
                        } => stage == "seed",
                        AuthAction::Pragma {
                            pragma_name: "table_info",
                            ..
                        } => stage == "table-validation",
                        AuthAction::Read {
                            table_name: "pragma_index_list",
                            ..
                        } => stage == "index-validation",
                        AuthAction::Transaction {
                            // rusqlite 0.40.2 maps SQLite's COMMIT to Unknown.
                            operation: TransactionOperation::Unknown,
                        } => matches!(stage, "commit" | "rollback"),
                        AuthAction::Transaction {
                            operation: TransactionOperation::Rollback,
                        } => stage == "rollback",
                        _ => false,
                    };
                    if target {
                        denied.fetch_add(1, Ordering::SeqCst);
                        Authorization::Deny
                    } else {
                        Authorization::Allow
                    }
                }))?;
            let result = store.prepare_fork_admission_authority_schema();
            if stage == "rollback" {
                assert!(
                    matches!(&result, Err(CoreError::Storage(message)) if message.contains("rollback is uncertain"))
                );
                assert!(!store.conn.is_autocommit());
            }
            storage_error(&result);
            store
                .conn
                .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
            assert!(hit.load(Ordering::SeqCst) > 0, "{stage}");
            if stage == "rollback" {
                store.conn.execute_batch("ROLLBACK")?;
            }
            assert!(store.conn.is_autocommit(), "{stage}");
            assert_eq!(schema(&store.conn)?, before, "{stage}");
        }
        let store = fresh_helper_store()?;
        let before = schema(&store.conn)?;
        store.conn.commit_hook(Some(|| true))?;
        storage_error(&store.prepare_fork_admission_authority_schema());
        store.conn.commit_hook::<fn() -> bool>(None)?;
        assert!(store.conn.is_autocommit());
        assert_eq!(schema(&store.conn)?, before);
        Ok(())
    }

    #[test]
    fn helper_never_rolls_back_a_transaction_it_did_not_acquire() -> Fallible<()> {
        let store = SqliteStore::open(":memory:")?;
        store
            .conn
            .execute_batch("BEGIN; CREATE TABLE caller_owned (id)")?;
        storage_error(&store.prepare_fork_admission_authority_schema());
        assert!(!store.conn.is_autocommit());
        assert!(schema(&store.conn)?
            .iter()
            .any(|(name, _)| name == "caller_owned"));
        store.conn.execute_batch("ROLLBACK")?;
        store.conn.authorizer(Some(|context: AuthContext<'_>| {
            if matches!(context.action, AuthAction::Transaction { .. }) {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }))?;
        storage_error(&store.prepare_fork_admission_authority_schema());
        store
            .conn
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
        assert!(store.conn.is_autocommit());
        Ok(())
    }

    #[test]
    fn canonical_encoders_select_the_exact_binary_child_in_both_indexes() -> Fallible<()> {
        use pos_core::{
            EventId, EventOriginRecordInputV1, EventOriginRecordV1, ForkEventClassificationV1,
            ForkEventOriginKindV1, ForkInterventionAdmissionInputV1, ForkInterventionAdmissionV1, Hash,
            TimelineId,
        };

        for child_bytes in [
            [0_u8; 16],
            [255_u8; 16],
            [
                0, 128, 255, 0, 128, 255, 0, 128, 255, 0, 128, 255, 0, 128, 255, 0,
            ],
        ] {
            let child = TimelineId::from_ulid(ulid::Ulid::from_bytes(child_bytes));
            let event = EventId::new();
            let hash = Hash::from_bytes([1; 32]);
            let origin = EventOriginRecordV1::new(EventOriginRecordInputV1 {
                fork_timeline_id: child,
                logical_seq: 1,
                event_id: event,
                classification: ForkEventClassificationV1::new(
                    ForkEventOriginKindV1::ExternalInput,
                    true,
                )?,
                classifier_revision_digest: hash,
                fork_admission_digest: hash,
            })?
            .to_canonical_cbor();
            let intervention = ForkInterventionAdmissionV1::new(ForkInterventionAdmissionInputV1 {
                operation_id: hash,
                fork_timeline_id: child,
                logical_seq: 1,
                event_id: event,
                payload_hash: hash,
                room_revision_descriptor_hash: hash,
                classifier_revision_digest: hash,
                fork_admission_digest: hash,
            })?
            .to_canonical_cbor();
            assert_eq!(&origin[8..24], &child_bytes);
            assert_eq!(&intervention[42..58], &child_bytes);
            let store = SqliteStore::open(":memory:")?;
            for (index, column, offset, bytes) in [
                (&INDEXES[0], "eor1_cbor", 9, origin),
                (&INDEXES[1], "fia1_cbor", 43, intervention),
            ] {
                store.conn.execute(
                    &format!(
                        "INSERT INTO {} (event_id,{column}) VALUES (?1,?2)",
                        index.table
                    ),
                    params![event.to_string(), bytes],
                )?;
                let retained: (String, Vec<u8>) = store.conn.query_row(&format!("SELECT typeof(substr({column},{offset},16)), substr({column},{offset},16) FROM {} INDEXED BY {} WHERE substr({column},{offset},16)=?1", index.table,index.name), [child_bytes.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)))?;
                assert_eq!(retained, ("blob".to_owned(), child_bytes.to_vec()));
            }
        }
        Ok(())
    }

    #[test]
    fn private_function_override_is_unsupported_not_detected_as_physical_integrity() -> Fallible<()> {
        use rusqlite::functions::FunctionFlags;

        let store = SqliteStore::open(":memory:")?;
        let bytes = vec![7_u8; 24];
        store.conn.execute(
            "INSERT INTO fork_event_origins VALUES ('probe',?1)",
            [&bytes],
        )?;
        store
            .conn
            .create_scalar_function("substr", 3, FunctionFlags::SQLITE_DETERMINISTIC, |_| {
                Ok(vec![0_u8; 16])
            })?;
        // This deliberate private violation demonstrates the documented limitation:
        // structural qualification cannot prove unchanged native function semantics.
        validate(&store.conn)?;
        let direct: Vec<u8> = store
            .conn
            .query_row("SELECT substr(?1,9,16)", [&bytes], |row| row.get(0))?;
        assert_eq!(direct, vec![0; 16]);
        let stale: String = store.conn.query_row("SELECT event_id FROM fork_event_origins INDEXED BY idx_fork_event_origins_child_v1 WHERE substr(eor1_cbor,9,16)=?1", [vec![7_u8; 16]], |row| row.get(0))?;
        assert_eq!(stale, "probe");
        Ok(())
    }

    #[test]
    fn read_only_open_requires_the_second_index_too() -> Fallible<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("missing-fia.sqlite");
        let path = path.to_str().ok_or("UTF-8 path")?;
        let store = SqliteStore::open(path)?;
        store
            .conn
            .execute_batch("DROP INDEX idx_fork_intervention_admissions_child_v1")?;
        drop(store);
        storage_error(&SqliteStore::open_read_only(path));
        drop(SqliteStore::open(path)?);
        drop(SqliteStore::open_read_only(path)?);
        Ok(())
    }

    #[test]
    fn native_metadata_is_checked_even_if_the_catalog_sql_claims_the_canonical_ddl() -> Fallible<()> {
        for expression in [
            "substr(eor1_cbor,9,16) DESC",
            "substr(eor1_cbor,9,16) COLLATE NOCASE",
            "substr(eor1_cbor,9,16),event_id",
            "event_id",
        ] {
            let store = SqliteStore::open(":memory:")?;
            store.conn.execute_batch(&format!(
                "DROP INDEX idx_fork_event_origins_child_v1;
                 CREATE INDEX idx_fork_event_origins_child_v1 ON fork_event_origins({expression});
                 PRAGMA writable_schema=ON"
            ))?;
            // Impossible through the public opener: the native schema cache and
            // deliberately corrupted catalog now disagree. Do not reload the cache.
            store.conn.execute(
                "UPDATE sqlite_schema SET sql=?1 WHERE name='idx_fork_event_origins_child_v1'",
                [INDEXES[0].create],
            )?;
            assert_eq!(
                definition(&store.conn, &INDEXES[0])?,
                Some(INDEXES[0].create.to_owned())
            );
            storage_error(&validate(&store.conn));
        }
        for corruption in ["sql=NULL", "sql=x'ff'", "type=x'ff'", "tbl_name=x'ff'"] {
            let store = SqliteStore::open(":memory:")?;
            store.conn.execute_batch(&format!(
                "PRAGMA writable_schema=ON;
                 UPDATE sqlite_schema SET {corruption} WHERE name='idx_fork_event_origins_child_v1'"
            ))?;
            storage_error(&validate(&store.conn));
        }
        Ok(())
    }

    #[test]
    fn final_revalidation_failure_rolls_back_both_new_indexes() -> Fallible<()> {
        let store = fresh_helper_store()?;
        let before = schema(&store.conn)?;
        let reads = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&reads);
        store
            .conn
            .authorizer(Some(move |context: AuthContext<'_>| {
                if matches!(
                    context.action,
                    AuthAction::Read {
                        table_name: "pragma_index_list",
                        column_name: "name"
                    }
                ) && observed.fetch_add(1, Ordering::SeqCst) == 2
                {
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }))?;
        storage_error(&store.prepare_fork_admission_authority_schema());
        store
            .conn
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
        assert_eq!(reads.load(Ordering::SeqCst), 3);
        assert!(store.conn.is_autocommit());
        assert_eq!(schema(&store.conn)?, before);
        Ok(())
    }
}
