//! `SQLite` adapter and additive schema for the ADR-021 admitted-batch port.

use std::num::NonZeroUsize;

use pos_core::{
    clock::{Seq, WallTime},
    error::CoreError,
    ids::TimelineId,
    store::{checked_append_identity_expires_at, AppendDedupKey, PurgeOutcome},
    ErasureProtectedOperationV1, PipelineAdmissionBasisV1, PipelineAdmissionFenceV1,
    PipelineAdmissionPortV1, PipelineContractErrorV1, PipelineOutcomeV1,
};
use rusqlite::{params, Connection, OptionalExtension};

use super::{
    begin_immediate_scope, finish_immediate_scope, read_authority_state, sqlite_schema_ddl,
    SqliteSchemaColumn, SqliteSchemaTable, SqliteStore,
};

/// Additive pre-product tables owned by the admitted-batch port.
const PIPELINE_ADMISSION_SCHEMA_TABLES: &[SqliteSchemaTable] = &[
    SqliteSchemaTable {
        name: "pipeline_admission_fences",
        columns_query: "PRAGMA table_info(pipeline_admission_fences)",
        columns: &[
            SqliteSchemaColumn {
                name: "timeline_id",
                kind: "TEXT",
                not_null: true,
                primary_key: true,
            },
            SqliteSchemaColumn {
                name: "fence_bytes",
                kind: "BLOB",
                not_null: true,
                primary_key: false,
            },
        ],
        constraints: &["CHECK (length(fence_bytes) = 298)"],
    },
    SqliteSchemaTable {
        name: "pipeline_admission_receipts",
        columns_query: "PRAGMA table_info(pipeline_admission_receipts)",
        columns: &[
            SqliteSchemaColumn {
                name: "dedup_key",
                kind: "BLOB",
                not_null: true,
                primary_key: true,
            },
            SqliteSchemaColumn {
                name: "timeline_id",
                kind: "TEXT",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "basis_digest",
                kind: "BLOB",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "first_local_seq",
                kind: "INTEGER",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "event_count",
                kind: "INTEGER",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "expires_at",
                kind: "INTEGER",
                not_null: true,
                primary_key: false,
            },
        ],
        constraints: &[
            "CHECK (length(dedup_key) = 32)",
            "CHECK (length(basis_digest) = 32)",
            "CHECK (first_local_seq >= 1)",
            "CHECK (event_count >= 1)",
        ],
    },
];

/// Retained exact-retry row for one committed admitted batch.
struct RetainedPipelineReceiptV1 {
    timeline: String,
    basis_digest: Vec<u8>,
    first_local_seq: i64,
    event_count: i64,
    expires_at: i64,
}

impl SqliteStore {
    /// Create the additive admitted-batch tables, then validate their shape.
    pub(super) fn prepare_pipeline_admission_schema(&self) -> Result<(), CoreError> {
        self.conn
            .execute_batch(&format!(
                "BEGIN IMMEDIATE;
                 {}
                 CREATE INDEX IF NOT EXISTS idx_pipeline_admission_receipts_expiry
                 ON pipeline_admission_receipts(expires_at, dedup_key);
                 COMMIT;",
                sqlite_schema_ddl(PIPELINE_ADMISSION_SCHEMA_TABLES)
            ))
            .map_err(Self::into_storage_error)
            .and_then(|()| self.validate_pipeline_admission_schema())
    }

    /// Validate the admitted-batch tables without creating them.
    pub(super) fn validate_pipeline_admission_schema(&self) -> Result<(), CoreError> {
        PIPELINE_ADMISSION_SCHEMA_TABLES
            .iter()
            .try_for_each(|table| self.validate_sqlite_schema_table(table))
    }

    fn admit_visible_pipeline_batch(
        &self,
        timeline: TimelineId,
        basis: &PipelineAdmissionBasisV1,
        now: WallTime,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        begin_immediate_scope(&self.conn).and_then(|scope| {
            let result = self
                .validate_erasure_inventory_data_version()
                .and_then(|()| self.ensure_generic_fork_append_is_rejected(timeline))
                .and_then(|()| self.admit_locked_pipeline_batch(timeline, basis, now));
            finish_immediate_scope(&self.conn, scope, result)
        })
    }

    fn admit_locked_pipeline_batch(
        &self,
        timeline: TimelineId,
        basis: &PipelineAdmissionBasisV1,
        now: WallTime,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        let key = basis.attempt().idempotency().dedup_key;
        let now_micros = i64::try_from(now.as_micros()).unwrap_or(i64::MAX);
        Self::fork_chain_with_leaf_head_on(&self.conn, timeline).and_then(|(chain, owned_head)| {
            let prefix = chain.last().map_or(0, |(_, fork)| fork.as_u64());
            read_retained_receipt(&self.conn, key).and_then(|retained| match retained {
                Some(record) if record.expires_at > now_micros => {
                    self.recover_pipeline_receipt(timeline, basis, prefix, &record)
                }
                Some(_) => delete_receipt(&self.conn, key).and_then(|()| {
                    self.commit_pipeline_batch(timeline, basis, now, prefix, owned_head)
                }),
                None => self.commit_pipeline_batch(timeline, basis, now, prefix, owned_head),
            })
        })
    }

    fn recover_pipeline_receipt(
        &self,
        timeline: TimelineId,
        basis: &PipelineAdmissionBasisV1,
        prefix: u64,
        record: &RetainedPipelineReceiptV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        if record.timeline != timeline.to_string()
            || record.basis_digest.as_slice() != basis.digest().as_bytes()
        {
            return Ok(PipelineOutcomeV1::AdmissionConflict);
        }
        Self::read_own_events_limited_on(
            &self.conn,
            timeline,
            Seq::from_u64(u64::try_from(record.first_local_seq).unwrap_or(0)),
            None,
            Some(usize::try_from(record.event_count).unwrap_or(0)),
            None,
            u64::MAX,
        )
        .and_then(|events| {
            events
                .into_iter()
                .map(|event| Self::logical_event(prefix, event))
                .collect::<Result<Vec<_>, _>>()
        })
        .and_then(|events| crate::recovered_pipeline_receipt(basis, timeline, &events))
    }

    fn commit_pipeline_batch(
        &self,
        timeline: TimelineId,
        basis: &PipelineAdmissionBasisV1,
        now: WallTime,
        prefix: u64,
        owned_head: u64,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        crate::checked_logical_head(prefix, owned_head)
            .and_then(|logical_head| {
                read_fence(&self.conn, timeline).map(|fence| (Seq::from_u64(logical_head), fence))
            })
            .and_then(|(logical_head, fence)| {
                crate::evaluate_pipeline_admission(basis, fence.as_ref(), logical_head, |grant| {
                    read_authority_state(&self.conn).and_then(|state| state.resolve(grant))
                })
                .map_or_else(Ok, |next_fence| {
                    self.insert_pipeline_batch(
                        timeline,
                        basis,
                        now,
                        prefix,
                        owned_head,
                        &next_fence,
                    )
                })
            })
    }

    fn insert_pipeline_batch(
        &self,
        timeline: TimelineId,
        basis: &PipelineAdmissionBasisV1,
        now: WallTime,
        prefix: u64,
        owned_head: u64,
        next_fence: &PipelineAdmissionFenceV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        let drafts = basis.batch().drafts();
        drafts
            .iter()
            .map(|draft| {
                Self::append_one_in_transaction(
                    &self.conn,
                    self.hasher.as_ref(),
                    timeline,
                    draft.clone(),
                )
                .and_then(|event| Self::logical_event(prefix, event))
            })
            .collect::<Result<Vec<_>, _>>()
            .and_then(|events| crate::committed_pipeline_receipt(basis, timeline, &events))
            .and_then(|receipt| {
                checked_append_identity_expires_at(now).map(|expires_at| (receipt, expires_at))
            })
            .and_then(|(receipt, expires_at)| {
                write_fence(&self.conn, timeline, next_fence)
                    .and_then(|()| {
                        self.conn
                            .execute(
                                "INSERT INTO pipeline_admission_receipts
                                 (dedup_key, timeline_id, basis_digest, first_local_seq,
                                  event_count, expires_at)
                                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                                params![
                                    basis
                                        .attempt()
                                        .idempotency()
                                        .dedup_key
                                        .as_bytes()
                                        .as_slice(),
                                    timeline.to_string(),
                                    basis.digest().as_bytes().as_slice(),
                                    i64::try_from(owned_head.saturating_add(1)).unwrap_or(i64::MAX),
                                    i64::try_from(drafts.len()).unwrap_or(i64::MAX),
                                    i64::try_from(expires_at.as_micros()).unwrap_or(i64::MAX),
                                ],
                            )
                            .map_err(Self::into_storage_error)
                    })
                    .map(|_| PipelineOutcomeV1::Committed(receipt))
            })
    }
}

/// Remove admission rows owned by a Timeline inside its deletion transaction.
pub(super) fn delete_pipeline_admission_rows(
    conn: &Connection,
    timeline: &str,
) -> Result<(), CoreError> {
    conn.execute(
        "DELETE FROM pipeline_admission_receipts WHERE timeline_id = ?1",
        params![timeline],
    )
    .and_then(|_| {
        conn.execute(
            "DELETE FROM pipeline_admission_fences WHERE timeline_id = ?1",
            params![timeline],
        )
    })
    .map(|_| ())
    .map_err(SqliteStore::into_storage_error)
}

fn read_retained_receipt(
    conn: &Connection,
    key: AppendDedupKey,
) -> Result<Option<RetainedPipelineReceiptV1>, CoreError> {
    conn.query_row(
        "SELECT timeline_id, basis_digest, first_local_seq, event_count, expires_at
         FROM pipeline_admission_receipts WHERE dedup_key = ?1",
        params![key.as_bytes().as_slice()],
        |row| {
            row.get::<_, String>(0).and_then(|timeline| {
                row.get::<_, Vec<u8>>(1).and_then(|basis_digest| {
                    row.get::<_, i64>(2).and_then(|first_local_seq| {
                        row.get::<_, i64>(3).and_then(|event_count| {
                            row.get::<_, i64>(4)
                                .map(|expires_at| RetainedPipelineReceiptV1 {
                                    timeline,
                                    basis_digest,
                                    first_local_seq,
                                    event_count,
                                    expires_at,
                                })
                        })
                    })
                })
            })
        },
    )
    .optional()
    .map_err(SqliteStore::into_storage_error)
}

fn delete_receipt(conn: &Connection, key: AppendDedupKey) -> Result<(), CoreError> {
    conn.execute(
        "DELETE FROM pipeline_admission_receipts WHERE dedup_key = ?1",
        params![key.as_bytes().as_slice()],
    )
    .map(|_| ())
    .map_err(SqliteStore::into_storage_error)
}

fn read_fence(
    conn: &Connection,
    timeline: TimelineId,
) -> Result<Option<PipelineAdmissionFenceV1>, CoreError> {
    conn.query_row(
        "SELECT fence_bytes FROM pipeline_admission_fences WHERE timeline_id = ?1",
        params![timeline.to_string()],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .optional()
    .map_err(SqliteStore::into_storage_error)
    .and_then(|bytes| {
        bytes
            .map(|bytes| {
                PipelineAdmissionFenceV1::from_persistence_bytes(&bytes).map_err(fence_error)
            })
            .transpose()
    })
}

fn write_fence(
    conn: &Connection,
    timeline: TimelineId,
    fence: &PipelineAdmissionFenceV1,
) -> Result<(), CoreError> {
    conn.execute(
        "INSERT INTO pipeline_admission_fences (timeline_id, fence_bytes) VALUES (?1, ?2)
         ON CONFLICT(timeline_id) DO UPDATE SET fence_bytes = excluded.fence_bytes",
        params![
            timeline.to_string(),
            fence.to_persistence_bytes().as_slice()
        ],
    )
    .map(|_| ())
    .map_err(SqliteStore::into_storage_error)
}

fn fence_error(error: PipelineContractErrorV1) -> CoreError {
    CoreError::Storage(format!(
        "persisted pipeline admission fence is invalid: {error}"
    ))
}

impl PipelineAdmissionPortV1 for SqliteStore {
    fn set_pipeline_admission_fence(
        &mut self,
        timeline: TimelineId,
        fence: PipelineAdmissionFenceV1,
    ) -> Result<(), CoreError> {
        self.ensure_generic_timeline_visibility(timeline)
            .and_then(|()| Self::fork_chain_with_leaf_head_on(&self.conn, timeline))
            .and_then(|_| write_fence(&self.conn, timeline, &fence))
    }

    fn pipeline_admission_fence(
        &self,
        timeline: TimelineId,
    ) -> Result<Option<PipelineAdmissionFenceV1>, CoreError> {
        read_fence(&self.conn, timeline)
    }

    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        let timeline = basis.attempt().observation().timeline_id();
        self.clock.now().and_then(|now| {
            self.with_erasure_fence(timeline, ErasureProtectedOperationV1::Append, |store| {
                store
                    .ensure_generic_timeline_visibility(timeline)
                    .and_then(|()| store.admit_visible_pipeline_batch(timeline, basis, now))
            })
        })
    }

    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        self.clock.now().and_then(|now| {
            self.conn
                .execute(
                    "DELETE FROM pipeline_admission_receipts WHERE dedup_key IN (
                         SELECT dedup_key FROM pipeline_admission_receipts
                         WHERE expires_at <= ?1
                         ORDER BY expires_at, dedup_key
                         LIMIT ?2
                     )",
                    params![
                        i64::try_from(now.as_micros()).unwrap_or(i64::MAX),
                        i64::try_from(limit.get()).unwrap_or(i64::MAX),
                    ],
                )
                .map(|removed| PurgeOutcome {
                    removed,
                    more_may_remain: removed == limit.get(),
                })
                .map_err(Self::into_storage_error)
        })
    }
}
