//! `SQLite` adapter for the persistent Gateway execution-mode binding
//! (ADR-134 §8).
//!
//! Three tables sit beside `authority_state` and `authority_denials`:
//! the singleton current binding, its immutable history (one row per epoch)
//! and the permanent commit-epoch evidence of every Event range committed on
//! a bound store. Each binding change is one `BEGIN IMMEDIATE` transaction
//! committed under `synchronous=FULL`.
//!
//! [`record_commit_epoch_in_transaction`] is the adapter's one append choke
//! point: every production `INSERT INTO events` path calls it inside the
//! transaction that inserts the Event rows, with the epoch attached to the
//! writing adapter instance.

use std::num::NonZeroU64;

use pos_core::{
    commit_epoch_for_append_v1, error::CoreError, GatewayModeBindPermitV1,
    GatewayModeBindingErrorV1, GatewayModeBindingHistoryEntryV1, GatewayModeBindingKindV1,
    GatewayModeBindingPortV1, GatewayModeBindingRecordV1, GatewayModeMigrationPermitV1,
    GatewayModeProfileRefV1, GatewayModeRotationPermitV1, Seq, TimelineId,
};
use rusqlite::{params, Connection, OptionalExtension};

use super::{SqliteSchemaColumn, SqliteSchemaTable, SqliteStore};

/// The three mode-binding tables, created and validated exactly.
pub(super) const GATEWAY_MODE_SCHEMA_TABLES: &[SqliteSchemaTable] = &[
    SqliteSchemaTable {
        name: "gateway_mode_binding",
        columns_query: "PRAGMA table_info(gateway_mode_binding)",
        columns: &[
            SqliteSchemaColumn {
                name: "singleton",
                kind: "INTEGER",
                not_null: false,
                primary_key: true,
            },
            SqliteSchemaColumn {
                name: "binding_epoch",
                kind: "INTEGER",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "profile_id",
                kind: "TEXT",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "profile_digest",
                kind: "BLOB",
                not_null: true,
                primary_key: false,
            },
        ],
        constraints: &[
            "CHECK (singleton = 1)",
            "CHECK (binding_epoch >= 1)",
            "CHECK (length(profile_digest) = 32)",
        ],
    },
    SqliteSchemaTable {
        name: "gateway_mode_binding_history",
        columns_query: "PRAGMA table_info(gateway_mode_binding_history)",
        columns: &[
            SqliteSchemaColumn {
                name: "binding_epoch",
                kind: "INTEGER",
                not_null: false,
                primary_key: true,
            },
            SqliteSchemaColumn {
                name: "profile_id",
                kind: "TEXT",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "profile_digest",
                kind: "BLOB",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "kind",
                kind: "INTEGER",
                not_null: true,
                primary_key: false,
            },
        ],
        constraints: &[
            "CHECK (length(profile_digest) = 32)",
            "CHECK (kind IN (1, 2, 3))",
        ],
    },
    SqliteSchemaTable {
        name: "gateway_mode_commit_epochs",
        columns_query: "PRAGMA table_info(gateway_mode_commit_epochs)",
        columns: &[
            SqliteSchemaColumn {
                name: "timeline_id",
                kind: "TEXT",
                not_null: true,
                primary_key: true,
            },
            SqliteSchemaColumn {
                name: "first_local_seq",
                kind: "INTEGER",
                not_null: true,
                primary_key: true,
            },
            SqliteSchemaColumn {
                name: "last_local_seq",
                kind: "INTEGER",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "binding_epoch",
                kind: "INTEGER",
                not_null: true,
                primary_key: false,
            },
        ],
        constraints: &[
            "CHECK (last_local_seq >= first_local_seq)",
            "CHECK (binding_epoch >= 1)",
        ],
    },
];

/// Records whose presence makes a store populated: Events and Timelines,
/// authority grants and denial evidence, the `OwnTracks` enrollment, and
/// Fork-admission authority, admissions and Principal-owner bindings. Tables
/// that a fresh open or erasure recovery fills (for example the Fork delivery
/// fence counter) are deliberately absent.
const POPULATED_STORE_SQL: &str = "SELECT EXISTS (SELECT 1 FROM timelines)
     OR EXISTS (SELECT 1 FROM authority_state)
     OR EXISTS (SELECT 1 FROM authority_denials)
     OR EXISTS (SELECT 1 FROM owntracks_enrollment)
     OR EXISTS (SELECT 1 FROM fork_admission_authority)
     OR EXISTS (SELECT 1 FROM fork_admissions)
     OR EXISTS (SELECT 1 FROM fork_principal_owner_bindings)";

/// One raw `gateway_mode_binding` or history row before identifier checks.
struct BindingRowV1 {
    epoch: NonZeroU64,
    profile_id: String,
    profile_digest: [u8; 32],
}

impl BindingRowV1 {
    fn record(self) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1> {
        GatewayModeProfileRefV1::try_new(&self.profile_id, self.profile_digest)
            .map(|profile| GatewayModeBindingRecordV1::new(profile, self.epoch))
    }
}

type BindingStep<T> = rusqlite::Result<Result<T, GatewayModeBindingErrorV1>>;

/// Collapse an adapter failure into the port's closed unavailable error.
fn settle<T>(step: BindingStep<T>) -> Result<T, GatewayModeBindingErrorV1> {
    step.map_err(|_| GatewayModeBindingErrorV1::Unavailable)
        .and_then(std::convert::identity)
}

fn read_binding_row(conn: &Connection) -> rusqlite::Result<Option<BindingRowV1>> {
    conn.query_row(
        "SELECT binding_epoch, profile_id, profile_digest FROM gateway_mode_binding
         WHERE singleton = 1",
        [],
        |row| {
            Ok(BindingRowV1 {
                epoch: row.get(0)?,
                profile_id: row.get(1)?,
                profile_digest: row.get(2)?,
            })
        },
    )
    .optional()
}

fn read_binding(conn: &Connection) -> BindingStep<Option<GatewayModeBindingRecordV1>> {
    read_binding_row(conn).map(|row| row.map(BindingRowV1::record).transpose())
}

fn store_is_populated(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(POPULATED_STORE_SQL, [], |row| row.get(0))
}

/// Replace the current binding and append its history row.
fn write_binding(
    conn: &Connection,
    profile: &GatewayModeProfileRefV1,
    epoch: NonZeroU64,
    kind: GatewayModeBindingKindV1,
) -> rusqlite::Result<GatewayModeBindingRecordV1> {
    let digest = profile.profile_digest();
    conn.execute(
        "INSERT INTO gateway_mode_binding (singleton, binding_epoch, profile_id, profile_digest)
         VALUES (1, ?1, ?2, ?3)
         ON CONFLICT(singleton) DO UPDATE SET
             binding_epoch = excluded.binding_epoch,
             profile_id = excluded.profile_id,
             profile_digest = excluded.profile_digest",
        params![epoch.get(), profile.profile_id(), digest],
    )
    .and_then(|_| {
        conn.execute(
            "INSERT INTO gateway_mode_binding_history
             (binding_epoch, profile_id, profile_digest, kind)
             VALUES (?1, ?2, ?3, ?4)",
            params![epoch.get(), profile.profile_id(), digest, kind.code()],
        )
    })
    .map(|_| GatewayModeBindingRecordV1::new(profile.clone(), epoch))
}

fn bind_in_transaction(
    conn: &Connection,
    to: &GatewayModeProfileRefV1,
) -> BindingStep<GatewayModeBindingRecordV1> {
    read_binding_row(conn)
        .and_then(|bound| store_is_populated(conn).map(|populated| (bound.is_some(), populated)))
        .and_then(|state| match state {
            (true, _) => Ok(Err(GatewayModeBindingErrorV1::AlreadyBound)),
            (false, true) => Ok(Err(GatewayModeBindingErrorV1::PopulatedUnbound)),
            (false, false) => {
                write_binding(conn, to, NonZeroU64::MIN, GatewayModeBindingKindV1::Bind).map(Ok)
            }
        })
}

fn change_in_transaction(
    conn: &Connection,
    from: &GatewayModeProfileRefV1,
    to: &GatewayModeProfileRefV1,
    kind: GatewayModeBindingKindV1,
) -> BindingStep<GatewayModeBindingRecordV1> {
    read_binding(conn).and_then(|current| {
        match current.and_then(|current| current.ok_or(GatewayModeBindingErrorV1::Unbound)) {
            Ok(current) if current.profile() == from => {
                write_binding(conn, to, current.binding_epoch().saturating_add(1), kind).map(Ok)
            }
            Ok(_) => Ok(Err(GatewayModeBindingErrorV1::Mismatch)),
            Err(error) => Ok(Err(error)),
        }
    })
}

/// Commit a successful step, roll back any other.
fn finish_binding_transaction<T>(conn: &Connection, step: BindingStep<T>) -> BindingStep<T> {
    let commit = step.as_ref().is_ok_and(Result::is_ok);
    conn.execute_batch(if commit { "COMMIT" } else { "ROLLBACK" })
        .and_then(|()| step)
}

/// Run one binding change as a `BEGIN IMMEDIATE` transaction under
/// `synchronous=FULL`, then restore the store's `synchronous=NORMAL`.
fn binding_transaction(
    conn: &Connection,
    body: impl FnOnce(&Connection) -> BindingStep<GatewayModeBindingRecordV1>,
) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1> {
    let step = conn
        .execute_batch("PRAGMA synchronous=FULL; BEGIN IMMEDIATE")
        .and_then(|()| finish_binding_transaction(conn, body(conn)));
    drop(conn.execute_batch("PRAGMA synchronous=NORMAL"));
    settle(step)
}

/// The epoch recorded for the commit that wrote segment-local `local_seq`.
pub(super) fn commit_epoch_at(
    conn: &Connection,
    timeline: TimelineId,
    local_seq: u64,
) -> Result<Option<NonZeroU64>, CoreError> {
    conn.query_row(
        "SELECT binding_epoch FROM (
             SELECT binding_epoch, last_local_seq FROM gateway_mode_commit_epochs
             WHERE timeline_id = ?1 AND first_local_seq <= ?2
             ORDER BY first_local_seq DESC LIMIT 1
         ) WHERE last_local_seq >= ?2",
        params![timeline.to_string(), local_seq],
        |row| row.get(0),
    )
    .optional()
    .map_err(|error| CoreError::Storage(error.to_string()))
}

/// The append choke point: compare the writer's attached epoch with the
/// persisted one and record the committed range under it, inside the
/// transaction that inserts the Event rows.
///
/// # Errors
/// Returns [`CoreError::ModeBindingStale`] when the store is bound and the
/// writer is unattached or attached to another epoch, or the writer is
/// attached and the store is unbound; the caller's transaction then commits
/// nothing. Returns a storage error when the evidence cannot be read or
/// written.
pub(super) fn record_commit_epoch_in_transaction(
    conn: &Connection,
    attached: Option<NonZeroU64>,
    timeline: TimelineId,
    first_local_seq: Seq,
    last_local_seq: Seq,
) -> Result<(), CoreError> {
    conn.query_row(
        "SELECT binding_epoch FROM gateway_mode_binding WHERE singleton = 1",
        [],
        |row| row.get(0),
    )
    .optional()
    .map_err(|error| CoreError::Storage(error.to_string()))
    .and_then(|persisted| commit_epoch_for_append_v1(persisted, attached))
    .and_then(|epoch| {
        epoch.map_or(Ok(()), |epoch| {
            conn.execute(
                "INSERT INTO gateway_mode_commit_epochs
                 (timeline_id, first_local_seq, last_local_seq, binding_epoch)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    timeline.to_string(),
                    first_local_seq.as_u64(),
                    last_local_seq.as_u64(),
                    epoch.get()
                ],
            )
            .map(drop)
            .map_err(|error| CoreError::Storage(error.to_string()))
        })
    })
}

impl SqliteStore {
    pub(super) fn validate_gateway_mode_schema(&self) -> Result<(), CoreError> {
        GATEWAY_MODE_SCHEMA_TABLES
            .iter()
            .try_for_each(|table| self.validate_sqlite_schema_table(table))
    }

    fn attach_record(
        &mut self,
        record: Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1>,
    ) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1> {
        record.inspect(|record| self.mode_binding_epoch = Some(record.binding_epoch()))
    }
}

impl GatewayModeBindingPortV1 for SqliteStore {
    fn bind_empty_store_mode(
        &mut self,
        permit: GatewayModeBindPermitV1,
    ) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1> {
        let bound = binding_transaction(&self.conn, |conn| bind_in_transaction(conn, permit.to()));
        self.attach_record(bound)
    }

    fn attach_mode_binding(
        &mut self,
    ) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1> {
        let current = settle(read_binding(&self.conn))
            .and_then(|current| current.ok_or(GatewayModeBindingErrorV1::Unbound));
        self.attach_record(current)
    }

    fn rotate_mode(
        &mut self,
        permit: GatewayModeRotationPermitV1,
    ) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1> {
        let rotated = binding_transaction(&self.conn, |conn| {
            change_in_transaction(
                conn,
                permit.from(),
                permit.to(),
                GatewayModeBindingKindV1::Rotate,
            )
        });
        self.attach_record(rotated)
    }

    fn migrate_mode(
        &mut self,
        permit: GatewayModeMigrationPermitV1,
    ) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1> {
        let migrated = binding_transaction(&self.conn, |conn| {
            change_in_transaction(
                conn,
                permit.from(),
                permit.to(),
                GatewayModeBindingKindV1::Migrate,
            )
        });
        self.attach_record(migrated)
    }

    fn load_mode_binding(
        &self,
    ) -> Result<Option<GatewayModeBindingRecordV1>, GatewayModeBindingErrorV1> {
        settle(read_binding(&self.conn))
    }

    fn load_mode_binding_history(
        &self,
    ) -> Result<Vec<GatewayModeBindingHistoryEntryV1>, GatewayModeBindingErrorV1> {
        let rows = self
            .conn
            .prepare(
                "SELECT binding_epoch, profile_id, profile_digest, kind
                 FROM gateway_mode_binding_history ORDER BY binding_epoch",
            )
            .and_then(|mut statement| {
                statement
                    .query_map([], |row| {
                        Ok((
                            BindingRowV1 {
                                epoch: row.get(0)?,
                                profile_id: row.get(1)?,
                                profile_digest: row.get(2)?,
                            },
                            row.get::<_, u8>(3)?,
                        ))
                    })
                    .and_then(Iterator::collect::<rusqlite::Result<Vec<_>>>)
            });
        settle(rows.map(|rows| {
            rows.into_iter()
                .map(|(row, kind)| {
                    GatewayModeBindingKindV1::from_code(kind).and_then(|kind| {
                        row.record()
                            .map(|record| GatewayModeBindingHistoryEntryV1::new(record, kind))
                    })
                })
                .collect()
        }))
    }

    fn load_commit_epoch(
        &self,
        timeline: TimelineId,
        local_seq: Seq,
    ) -> Result<Option<NonZeroU64>, GatewayModeBindingErrorV1> {
        commit_epoch_at(&self.conn, timeline, local_seq.as_u64())
            .map_err(|_| GatewayModeBindingErrorV1::Unavailable)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::sync::Arc;

    use pos_core::{
        CanonicalBytes, EntityId, ErasureContainmentGateV1, EventDraft, EventStore,
        GatewayModeBindingHostV1, Kind, SeqRange,
    };

    use super::*;

    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
        })
    }

    fn store() -> SqliteStore {
        let mut store = ok(SqliteStore::open_in_memory());
        ok(store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open())));
        store
    }

    fn bound_store() -> (SqliteStore, TimelineId) {
        let mut store = store();
        let profile = ok(GatewayModeProfileRefV1::try_new(
            "gateway-mode-local-v1",
            [1; 32],
        ));
        ok(store.bind_empty_store_mode(GatewayModeBindingHostV1::new().authorize_bind(profile)));
        let timeline = ok(store.create_timeline("bound")).id();
        (store, timeline)
    }

    fn append(store: &mut SqliteStore, timeline: TimelineId) -> Result<(), CoreError> {
        let draft = EventDraft::new(
            EntityId::new(),
            Kind::new("gateway.mode.test"),
            CanonicalBytes::from_vec(vec![1]),
        );
        store.append(timeline, &[draft]).map(drop)
    }

    fn event_count(store: &SqliteStore, timeline: TimelineId) -> usize {
        ok(store.read(timeline, SeqRange::all())).len()
    }

    #[test]
    fn a_writer_attached_to_another_epoch_commits_nothing() {
        let (mut store, timeline) = bound_store();
        for attached in [None, NonZeroU64::new(2)] {
            store.mode_binding_epoch = attached;
            assert!(matches!(
                append(&mut store, timeline),
                Err(CoreError::ModeBindingStale)
            ));
            assert_eq!(event_count(&store, timeline), 0);
        }
        store.mode_binding_epoch = NonZeroU64::new(1);
        ok(append(&mut store, timeline));
        assert_eq!(
            ok(store.load_commit_epoch(timeline, Seq::from_u64(1))),
            NonZeroU64::new(1)
        );
    }

    #[test]
    fn an_attached_writer_on_an_unbound_store_commits_nothing() {
        let mut store = store();
        let timeline = ok(store.create_timeline("unbound")).id();
        store.mode_binding_epoch = NonZeroU64::new(1);
        assert!(matches!(
            append(&mut store, timeline),
            Err(CoreError::ModeBindingStale)
        ));
        assert_eq!(event_count(&store, timeline), 0);
    }

    #[test]
    fn an_unreadable_binding_fails_the_append_closed() {
        let (mut store, timeline) = bound_store();
        ok(store.conn.execute_batch("DROP TABLE gateway_mode_binding"));
        assert!(matches!(
            append(&mut store, timeline),
            Err(CoreError::Storage(_))
        ));
        assert_eq!(event_count(&store, timeline), 0);
    }
}
