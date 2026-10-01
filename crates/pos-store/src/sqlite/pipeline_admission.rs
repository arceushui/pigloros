//! `SQLite` adapter and additive schema for the ADR-021 admitted-batch port.

use std::num::{NonZeroUsize, TryFromIntError};

use pos_core::{
    clock::{Seq, WallTime},
    error::CoreError,
    ids::TimelineId,
    store::{checked_append_identity_expires_at, AppendDedupKey, AppendDedupScope, PurgeOutcome},
    ErasureProtectedOperationV1, Hash, PipelineAdmissionBasisV1, PipelineAdmissionFencePublisherV1,
    PipelineAdmissionFenceV1, PipelineAdmissionPortV1, PipelineAttemptIdV1,
    PipelineContractErrorV1, PipelineOutcomeV1, PipelineReceiptLookupV1,
};
use rusqlite::{params, Connection, OptionalExtension};

use super::{
    begin_immediate_scope, finish_immediate_scope, read_authority_state, sqlite_schema_ddl,
    SqliteSchemaColumn, SqliteSchemaTable, SqliteStore,
};
use crate::{
    committed_pipeline_receipt, evaluate_pipeline_admission, install_or_reject,
    recovered_pipeline_receipt, retained_pipeline_receipt, PipelinePersistedStateV1,
};

/// `SQLite` treats a negative `LIMIT` as having no upper bound.
const SQLITE_UNBOUNDED_LIMIT: i64 = -1;

/// Exact `CHECK` constraint for the fixed-width persisted fence record. A unit
/// test pins it to [`pos_core::PIPELINE_ADMISSION_FENCE_BYTES_V1`].
const FENCE_LENGTH_CONSTRAINT: &str = "CHECK (length(fence_bytes) = 298)";

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
        constraints: &[FENCE_LENGTH_CONSTRAINT],
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
                name: "scope_key",
                kind: "BLOB",
                not_null: true,
                primary_key: false,
            },
            SqliteSchemaColumn {
                name: "attempt_id",
                kind: "BLOB",
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
                name: "draft_batch_digest",
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
            "CHECK (length(scope_key) = 32)",
            "CHECK (length(attempt_id) = 16)",
            "CHECK (length(basis_digest) = 32)",
            "CHECK (length(draft_batch_digest) = 32)",
            "CHECK (first_local_seq >= 1)",
            "CHECK (event_count >= 1)",
        ],
    },
];

/// Retained exact-retry row for one committed admitted batch.
struct RetainedPipelineReceiptV1 {
    timeline: String,
    attempt_id: [u8; 16],
    basis_digest: Vec<u8>,
    draft_batch_digest: [u8; 32],
    first_local_seq: u64,
    event_count: usize,
    expires_at: WallTime,
}

/// Raw integer columns of one retained receipt row before range validation.
type RetainedPipelineReceiptRowV1 = (String, [u8; 16], Vec<u8>, [u8; 32], i64, i64, i64);

impl RetainedPipelineReceiptV1 {
    /// Validate a raw row; an out-of-range integer is a storage error rather
    /// than a clamped value.
    fn try_from_row(row: RetainedPipelineReceiptRowV1) -> Result<Self, CoreError> {
        let (
            timeline,
            attempt_id,
            basis_digest,
            draft_batch_digest,
            first_local_seq,
            event_count,
            expires_at,
        ) = row;
        u64::try_from(first_local_seq)
            .and_then(|first_local_seq| {
                usize::try_from(event_count).and_then(|event_count| {
                    u64::try_from(expires_at).map(|expires_at| Self {
                        timeline,
                        attempt_id,
                        basis_digest,
                        draft_batch_digest,
                        first_local_seq,
                        event_count,
                        expires_at: WallTime::from_micros(expires_at),
                    })
                })
            })
            .map_err(integer_out_of_range)
    }
}

/// Map an unrepresentable `SQLite` integer to a closed storage error.
fn integer_out_of_range(_error: TryFromIntError) -> CoreError {
    CoreError::Storage("admitted pipeline integer is outside its storage range".to_owned())
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
                 CREATE INDEX IF NOT EXISTS idx_pipeline_admission_receipts_scope
                 ON pipeline_admission_receipts(scope_key, expires_at, dedup_key);
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
        Self::fork_chain_with_leaf_head_on(&self.conn, timeline).and_then(|(chain, owned_head)| {
            let prefix = chain.last().map_or(0, |(_, fork)| fork.as_u64());
            // An expired receipt stays retained until the successful commit
            // replaces it, so every rejection leaves the receipts unchanged.
            read_retained_receipt(&self.conn, key).and_then(|retained| match retained {
                Some(record) if record.expires_at > now => {
                    self.recover_pipeline_receipt(timeline, basis, prefix, &record)
                }
                Some(_) | None => {
                    self.commit_pipeline_batch(timeline, basis, now, prefix, owned_head)
                }
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
        self.retained_pipeline_events(timeline, prefix, record)
            .and_then(|events| recovered_pipeline_receipt(basis, timeline, &events))
    }

    /// The committed logical Events a retained receipt row names.
    fn retained_pipeline_events(
        &self,
        timeline: TimelineId,
        prefix: u64,
        record: &RetainedPipelineReceiptV1,
    ) -> Result<Vec<pos_core::Event>, CoreError> {
        Self::read_own_events_limited_on(
            &self.conn,
            timeline,
            Seq::from_u64(record.first_local_seq),
            None,
            Some(record.event_count),
            None,
            u64::MAX,
        )
        .and_then(|events| {
            events
                .into_iter()
                .map(|event| Self::logical_event(prefix, event))
                .collect::<Result<Vec<_>, _>>()
        })
    }

    /// Resolve a basis-free receipt lookup inside one read transaction.
    fn lookup_visible_pipeline_receipt(
        &self,
        timeline: TimelineId,
        key: AppendDedupKey,
        attempt_id: PipelineAttemptIdV1,
        now: WallTime,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        begin_immediate_scope(&self.conn).and_then(|scope| {
            let result = self
                .validate_erasure_inventory_data_version()
                .and_then(|()| Self::fork_chain_with_leaf_head_on(&self.conn, timeline))
                .and_then(|(chain, _)| {
                    let prefix = chain.last().map_or(0, |(_, fork)| fork.as_u64());
                    read_retained_receipt(&self.conn, key).and_then(|retained| match retained {
                        Some(record) if record.expires_at > now => {
                            self.retained_lookup(timeline, prefix, attempt_id, &record)
                        }
                        Some(_) | None => Ok(PipelineReceiptLookupV1::Absent),
                    })
                });
            finish_immediate_scope(&self.conn, scope, result)
        })
    }

    /// Rebuild the receipt of an unexpired retained row, or report a conflict.
    fn retained_lookup(
        &self,
        timeline: TimelineId,
        prefix: u64,
        attempt_id: PipelineAttemptIdV1,
        record: &RetainedPipelineReceiptV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        if record.timeline != timeline.to_string() || record.attempt_id != attempt_id.as_bytes() {
            return Ok(PipelineReceiptLookupV1::Conflict);
        }
        self.retained_pipeline_events(timeline, prefix, record)
            .and_then(|events| {
                retained_pipeline_receipt(
                    attempt_id,
                    timeline,
                    Hash::from_bytes(record.draft_batch_digest),
                    &events,
                )
            })
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
                let persisted = PipelinePersistedStateV1 {
                    fence: fence.as_ref(),
                    logical_head,
                    erasure_inventory_generation: self.erasure_inventory_generation,
                };
                let evaluated = evaluate_pipeline_admission(basis, &persisted, |grant| {
                    read_authority_state(&self.conn).and_then(|state| state.resolve(grant))
                });
                install_or_reject(evaluated, |next_fence| {
                    self.insert_pipeline_batch(timeline, basis, now, prefix, owned_head, next_fence)
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
            .and_then(|events| committed_pipeline_receipt(basis, timeline, &events))
            .and_then(|receipt| {
                checked_append_identity_expires_at(now).map(|expires_at| (receipt, expires_at))
            })
            .and_then(|(receipt, expires_at)| {
                write_fence(&self.conn, timeline, next_fence)
                    .and_then(|()| {
                        write_receipt(
                            &self.conn,
                            basis,
                            timeline,
                            owned_head.saturating_add(1),
                            drafts.len(),
                            expires_at,
                        )
                    })
                    .map(|()| PipelineOutcomeV1::Committed(receipt))
            })
    }
}

/// Insert the receipt for a just-committed batch, replacing an expired
/// receipt for the same idempotency key inside the same transaction.
fn write_receipt(
    conn: &Connection,
    basis: &PipelineAdmissionBasisV1,
    timeline: TimelineId,
    first_local_seq: u64,
    event_count: usize,
    expires_at: WallTime,
) -> Result<(), CoreError> {
    i64::try_from(first_local_seq)
        .and_then(|first_local_seq| {
            i64::try_from(event_count).and_then(|event_count| {
                i64::try_from(expires_at.as_micros())
                    .map(|expires_at| (first_local_seq, event_count, expires_at))
            })
        })
        .map_err(integer_out_of_range)
        .and_then(|(first_local_seq, event_count, expires_at)| {
            conn.execute(
                "INSERT INTO pipeline_admission_receipts
                 (dedup_key, timeline_id, scope_key, attempt_id, basis_digest,
                  draft_batch_digest, first_local_seq, event_count, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(dedup_key) DO UPDATE SET
                     timeline_id = excluded.timeline_id,
                     scope_key = excluded.scope_key,
                     attempt_id = excluded.attempt_id,
                     basis_digest = excluded.basis_digest,
                     draft_batch_digest = excluded.draft_batch_digest,
                     first_local_seq = excluded.first_local_seq,
                     event_count = excluded.event_count,
                     expires_at = excluded.expires_at",
                params![
                    basis
                        .attempt()
                        .idempotency()
                        .dedup_key
                        .as_bytes()
                        .as_slice(),
                    timeline.to_string(),
                    basis.attempt().idempotency().scope.as_bytes().as_slice(),
                    basis.attempt().attempt_id().as_bytes().as_slice(),
                    basis.digest().as_bytes().as_slice(),
                    basis.batch().digest().as_bytes().as_slice(),
                    first_local_seq,
                    event_count,
                    expires_at,
                ],
            )
            .map(|_| ())
            .map_err(SqliteStore::into_storage_error)
        })
}

/// Remove one subject-scoped retry identity, whether an append identity or
/// an admitted-batch receipt, inside the caller's cleanup transaction.
pub(super) fn delete_scoped_identity(
    conn: &Connection,
    scope: AppendDedupScope,
    key: &[u8],
) -> Result<(), CoreError> {
    conn.execute(
        "DELETE FROM append_identities WHERE scope_key = ?1 AND dedup_key = ?2",
        params![scope.as_bytes().as_slice(), key],
    )
    .and_then(|_| {
        conn.execute(
            "DELETE FROM pipeline_admission_receipts WHERE scope_key = ?1 AND dedup_key = ?2",
            params![scope.as_bytes().as_slice(), key],
        )
    })
    .map(|_| ())
    .map_err(SqliteStore::into_storage_error)
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
        "SELECT timeline_id, attempt_id, basis_digest, draft_batch_digest,
                first_local_seq, event_count, expires_at
         FROM pipeline_admission_receipts WHERE dedup_key = ?1",
        params![key.as_bytes().as_slice()],
        |row| {
            row.get::<_, String>(0).and_then(|timeline| {
                row.get::<_, [u8; 16]>(1).and_then(|attempt_id| {
                    row.get::<_, Vec<u8>>(2).and_then(|basis_digest| {
                        row.get::<_, [u8; 32]>(3).and_then(|draft_batch_digest| {
                            row.get::<_, i64>(4).and_then(|first_local_seq| {
                                row.get::<_, i64>(5).and_then(|event_count| {
                                    row.get::<_, i64>(6).map(|expires_at| {
                                        (
                                            timeline,
                                            attempt_id,
                                            basis_digest,
                                            draft_batch_digest,
                                            first_local_seq,
                                            event_count,
                                            expires_at,
                                        )
                                    })
                                })
                            })
                        })
                    })
                })
            })
        },
    )
    .optional()
    .map_err(SqliteStore::into_storage_error)
    .and_then(|row| row.map(RetainedPipelineReceiptV1::try_from_row).transpose())
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

impl PipelineAdmissionFencePublisherV1 for SqliteStore {
    fn set_pipeline_admission_fence(
        &mut self,
        timeline: TimelineId,
        fence: PipelineAdmissionFenceV1,
    ) -> Result<(), CoreError> {
        self.with_erasure_fence(timeline, ErasureProtectedOperationV1::Append, |store| {
            store
                .ensure_generic_timeline_visibility(timeline)
                .and_then(|()| {
                    begin_immediate_scope(&store.conn).and_then(|scope| {
                        let result = store
                            .validate_erasure_inventory_data_version()
                            .and_then(|()| {
                                Self::fork_chain_with_leaf_head_on(&store.conn, timeline)
                            })
                            .and_then(|_| write_fence(&store.conn, timeline, &fence));
                        finish_immediate_scope(&store.conn, scope, result)
                    })
                })
        })
    }

    fn pipeline_admission_fence(
        &self,
        timeline: TimelineId,
    ) -> Result<Option<PipelineAdmissionFenceV1>, CoreError> {
        read_fence(&self.conn, timeline)
    }
}

impl PipelineAdmissionPortV1 for SqliteStore {
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

    fn lookup_pipeline_receipt(
        &mut self,
        timeline: TimelineId,
        key: AppendDedupKey,
        attempt_id: PipelineAttemptIdV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        self.clock.now().and_then(|now| {
            self.with_erasure_fence(timeline, ErasureProtectedOperationV1::Append, |store| {
                store
                    .ensure_generic_timeline_visibility(timeline)
                    .and_then(|()| {
                        store.lookup_visible_pipeline_receipt(timeline, key, attempt_id, now)
                    })
            })
        })
    }

    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        self.clock
            .now()
            .and_then(|now| i64::try_from(now.as_micros()).map_err(integer_out_of_range))
            .and_then(|now| {
                // A limit beyond `i64` cannot bound any table, so it is exactly
                // SQLite's unbounded LIMIT rather than a clamped value.
                let bound = i64::try_from(limit.get()).unwrap_or(SQLITE_UNBOUNDED_LIMIT);
                self.conn
                    .execute(
                        "DELETE FROM pipeline_admission_receipts WHERE dedup_key IN (
                             SELECT dedup_key FROM pipeline_admission_receipts
                             WHERE expires_at <= ?1
                             ORDER BY expires_at, dedup_key
                             LIMIT ?2
                         )",
                        params![now, bound],
                    )
                    .map(|removed| PurgeOutcome {
                        removed,
                        more_may_remain: removed == limit.get(),
                    })
                    .map_err(Self::into_storage_error)
            })
    }
}

#[cfg(test)]
mod tests {
    use pos_core::PIPELINE_ADMISSION_FENCE_BYTES_V1;

    use super::FENCE_LENGTH_CONSTRAINT;

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fence_length_constraint_matches_the_fixed_record_width() {
        assert_eq!(
            FENCE_LENGTH_CONSTRAINT,
            format!("CHECK (length(fence_bytes) = {PIPELINE_ADMISSION_FENCE_BYTES_V1})")
        );
    }
}
