//! `SQLite` adapter and additive schema for the ADR-021 admitted-batch port.
//!
//! # Schema evolution
//!
//! These tables are unreleased pre-product V1 state (they are not on `main`),
//! so their shape is replaced rather than migrated. Opening a file whose
//! `pipeline_admission_receipts` table predates the `scope_key`,
//! `attempt_id`, and `draft_batch_digest` columns fails closed with a storage
//! error: `CREATE TABLE IF NOT EXISTS` keeps the old table, so a writable
//! open cannot build the scope index on it and a read-only open fails the
//! exact column comparison. Both receipt indexes are validated on every
//! open, including a read-only one, so a missing or reshaped index is
//! rejected the same way.
//!
//! # Shared files
//!
//! The admission fence is one row per Timeline, last writer wins. Two hosts
//! sharing one file (for example a Gateway and a local experiment session)
//! that each republish a Timeline's fence are supported only in the
//! fail-closed sense: a connection that observes another connection's write
//! rejects with a storage error before comparing, and a basis built against a
//! replaced fence is [`PipelineOutcomeV1::AdmissionConflict`]. Neither host
//! commits against the other's fence, but they can starve each other, so a
//! deployment should give each Timeline one admitting host.

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
    begin_immediate_scope, finish_immediate_scope, normalize_schema_sql, read_authority_state,
    sqlite_schema_ddl, SqliteSchemaColumn, SqliteSchemaTable, SqliteStore,
};
use crate::{
    committed_pipeline_receipt, evaluate_pipeline_admission,
    factual_tick_plan::{FactualInstallV1, PlannedTickV1},
    install_or_reject, recovered_pipeline_receipt, retained_pipeline_receipt,
    PipelinePersistedStateV1,
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

/// Receipt indexes and their exact column lists: expiry purge order, and the
/// subject-scoped consent cleanup group.
const PIPELINE_ADMISSION_RECEIPT_INDEXES: &[(&str, &str)] = &[
    (
        "idx_pipeline_admission_receipts_expiry",
        "(expires_at, dedup_key)",
    ),
    (
        "idx_pipeline_admission_receipts_scope",
        "(scope_key, expires_at, dedup_key)",
    ),
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

/// Where an admitted batch lands in its Timeline.
#[derive(Clone, Copy)]
struct BatchPositionV1 {
    /// The length of the Timeline's inherited prefix: the logical offset of
    /// its own Events.
    prefix: u64,
    /// The Timeline's own head before the batch.
    owned_head: u64,
}

impl BatchPositionV1 {
    /// The logical `seq` the first Event of the batch takes.
    const fn first_seq(self) -> Seq {
        let logical_head = self.prefix.saturating_add(self.owned_head);
        Seq::from_u64(logical_head.saturating_add(1))
    }
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
        let indexes = PIPELINE_ADMISSION_RECEIPT_INDEXES
            .iter()
            .map(|(name, columns)| {
                format!(
                    "CREATE INDEX IF NOT EXISTS {name} ON pipeline_admission_receipts{columns};"
                )
            })
            .collect::<Vec<_>>()
            .concat();
        self.conn
            .execute_batch(&format!(
                "BEGIN IMMEDIATE;
                 {}
                 {indexes}
                 COMMIT;",
                sqlite_schema_ddl(PIPELINE_ADMISSION_SCHEMA_TABLES)
            ))
            .map_err(Self::into_storage_error)
            .and_then(|()| self.validate_pipeline_admission_schema())
    }

    /// Validate the admitted-batch tables and receipt indexes without
    /// creating them.
    pub(super) fn validate_pipeline_admission_schema(&self) -> Result<(), CoreError> {
        PIPELINE_ADMISSION_SCHEMA_TABLES
            .iter()
            .try_for_each(|table| self.validate_sqlite_schema_table(table))
            .and_then(|()| {
                PIPELINE_ADMISSION_RECEIPT_INDEXES
                    .iter()
                    .try_for_each(|(name, columns)| self.validate_receipt_index(name, columns))
            })
    }

    /// Require one receipt index on its exact column list.
    fn validate_receipt_index(&self, name: &str, columns: &str) -> Result<(), CoreError> {
        let expected = normalize_schema_sql(&format!("ON pipeline_admission_receipts{columns}"));
        self.conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?1",
                params![name],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(Self::into_storage_error)
            .and_then(|sql| {
                if sql.is_some_and(|sql| normalize_schema_sql(&sql).ends_with(&expected)) {
                    Ok(())
                } else {
                    Err(CoreError::Storage(format!(
                        "SQLite {name} index has an incompatible schema"
                    )))
                }
            })
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
                    let position = BatchPositionV1 { prefix, owned_head };
                    self.commit_pipeline_batch(timeline, basis, now, position, &chain)
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
        position: BatchPositionV1,
        chain: &[(TimelineId, Seq)],
    ) -> Result<PipelineOutcomeV1, CoreError> {
        crate::checked_logical_head(position.prefix, position.owned_head)
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
                    self.insert_pipeline_batch(timeline, basis, now, position, next_fence, chain)
                })
            })
    }

    /// Check the Tick declaration, then append the complete batch and record
    /// every effect together. A refused declaration is the commit's outcome;
    /// nothing is appended or recorded.
    fn insert_pipeline_batch(
        &self,
        timeline: TimelineId,
        basis: &PipelineAdmissionBasisV1,
        now: WallTime,
        position: BatchPositionV1,
        next_fence: &PipelineAdmissionFenceV1,
        chain: &[(TimelineId, Seq)],
    ) -> Result<PipelineOutcomeV1, CoreError> {
        let grant = next_fence.authority_grant();
        let first_seq = position.first_seq();
        let planned = self.plan_factual_tick(timeline, basis, grant, first_seq, chain);
        planned.and_then(|checked| match checked {
            PlannedTickV1::Install(install) => {
                self.append_planned_batch(timeline, basis, now, position, next_fence, &install)
            }
            PlannedTickV1::Refused(refusal) => Ok(refusal.outcome()),
        })
    }

    /// Append the batch, then write the Tick's dependency rows, the next
    /// fence and the receipt in the same transaction.
    fn append_planned_batch(
        &self,
        timeline: TimelineId,
        basis: &PipelineAdmissionBasisV1,
        now: WallTime,
        position: BatchPositionV1,
        next_fence: &PipelineAdmissionFenceV1,
        install: &FactualInstallV1,
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
                .and_then(|event| Self::logical_event(position.prefix, event))
            })
            .collect::<Result<Vec<_>, _>>()
            .and_then(|events| committed_pipeline_receipt(basis, timeline, &events))
            .and_then(|receipt| {
                checked_append_identity_expires_at(now).map(|expires_at| (receipt, expires_at))
            })
            .and_then(|(receipt, expires_at)| {
                let record = basis.dependencies().record();
                self.install_planned_factual_tick(timeline, record, install)
                    .and_then(|()| write_fence(&self.conn, timeline, next_fence))
                    .and_then(|()| {
                        write_receipt(
                            &self.conn,
                            basis,
                            timeline,
                            position.owned_head.saturating_add(1),
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
    use std::sync::Arc;

    use pos_core::output_policy::OutputAuthorityV1;
    use pos_core::{
        assemble_factual_tick, AppendIdentity, CanonicalBytes, DependencyNodeCoordinateV1,
        EntityId, ErasureContainmentGateV1, Event, EventDraft, EventStore, FactualDriverStepV1,
        FactualHeadV1, FactualIngressEventV1, FactualInputV1, FactualOutputV1, FactualOwnerIdV1,
        FactualPrefixReadPortV1, FactualPriorNodeV1, FactualScheduledTickV1, FactualTickContextV1,
        FactualTickShapeV1, Kind, PipelineAdmissionBasisDraftV1, PipelineAttemptDraftV1,
        PipelineAttemptV1, PipelineDraftBatchV1, PipelineEvidenceRefV1, PipelineIngressV1,
        PipelineObservationAnchorV1, PipelinePreconditionV1, PipelineSecurityRevisionsDraftV1,
        PipelineSecurityRevisionsV1, RecordedDependencyClassV1, RecordedSetCountsV1, SeqRange,
        TentativePipelineResultV1, PIPELINE_ADMISSION_FENCE_BYTES_V1, PIPELINE_CONTRACT_VERSION_V1,
    };
    use ulid::Ulid;

    use super::*;

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
        })
    }

    /// What the basis of a test declares besides its two Events.
    #[derive(Clone, Copy)]
    enum Declares {
        /// A human action: one node per Event.
        Plain,
        /// A scheduled Tick that records the ingress node of the first Event.
        Ingress,
        /// A scheduled Tick whose Driver consumes a node no Tick recorded.
        Prior,
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn scheduled_shape(
        drafts: &[EventDraft],
        ingress_events: Vec<FactualIngressEventV1>,
        extra: Vec<FactualInputV1>,
    ) -> FactualTickShapeV1 {
        let outputs = drafts
            .iter()
            .map(|draft| FactualOutputV1 {
                draft: draft.clone(),
                authority: OutputAuthorityV1::Authoritative,
                direct_inputs: Vec::new(),
            })
            .collect();
        let step_inputs = ingress_events
            .iter()
            .map(|event| FactualInputV1::IngressEvent(event.seq))
            .chain(extra)
            .collect();
        let driver = FactualDriverStepV1 {
            owner: FactualOwnerIdV1::new("plugin:test".to_owned()),
            policy_identity: Hash::from_bytes([8; 32]),
            step_inputs,
            outputs,
        };
        FactualTickShapeV1::Scheduled(FactualScheduledTickV1 {
            snapshot_digest: Hash::from_bytes([2; 32]),
            prefix_contents: Vec::new(),
            history_contents: Vec::new(),
            ingress_events,
            drivers: vec![driver],
        })
    }

    /// The shape a test declares over `drafts`, given the Events already
    /// stored.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn shape_of(declares: Declares, drafts: &[EventDraft], stored: &[Event]) -> FactualTickShapeV1 {
        match declares {
            Declares::Plain => FactualTickShapeV1::Human(drafts.to_vec()),
            Declares::Ingress => {
                let event = &stored[0];
                let ingress = FactualIngressEventV1 {
                    seq: event.seq,
                    event_type: event.event_type.as_str().to_owned(),
                    payload_hash: event.payload_hash,
                };
                scheduled_shape(drafts, vec![ingress], Vec::new())
            }
            Declares::Prior => {
                let ghost = ok(DependencyNodeCoordinateV1::try_new(
                    0,
                    1,
                    "plugin:ghost".to_owned(),
                    0,
                    7,
                    Hash::from_bytes([0xee; 32]),
                ));
                let class = RecordedDependencyClassV1::EndogenousRecomputed;
                let prior = FactualInputV1::Prior(FactualPriorNodeV1::new(ghost, class));
                scheduled_shape(drafts, Vec::new(), vec![prior])
            }
        }
    }

    /// The basis of a Tick 1 over two Events, observed through the stored
    /// Events.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn basis(
        timeline: TimelineId,
        declares: Declares,
        stored: &[Event],
    ) -> PipelineAdmissionBasisV1 {
        let observed = stored.last().map_or(Seq::ZERO, |event| event.seq);
        let observation =
            PipelineObservationAnchorV1::try_new(timeline, observed, Hash::from_bytes([2; 32]));
        let ingress = match declares {
            Declares::Plain => PipelineIngressV1::HumanProposedAction,
            Declares::Ingress | Declares::Prior => PipelineIngressV1::ScheduledAiDriver,
        };
        let attempt = ok(PipelineAttemptV1::try_from_draft(PipelineAttemptDraftV1 {
            contract_version: PIPELINE_CONTRACT_VERSION_V1,
            attempt_id: Some(ok(PipelineAttemptIdV1::try_new([1; 16]))),
            ingress: Some(ingress),
            observation: Some(ok(observation)),
            idempotency: Some(AppendIdentity::new(
                AppendDedupKey::from_keyed_hash([3; 32]),
                AppendDedupScope::from_keyed_hash([4; 32]),
            )),
        }));
        let drafts: Vec<EventDraft> = (0..2_u8)
            .map(|index| {
                EventDraft::new(
                    EntityId::from_ulid(Ulid::from(9_u128)),
                    Kind::new("world.action"),
                    CanonicalBytes::from_vec(vec![index]),
                )
            })
            .collect();
        let context = FactualTickContextV1 {
            timeline_id: timeline,
            tick: 1,
            attempt_id: ok(PipelineAttemptIdV1::try_new([1; 16])),
            evidence_digest: Hash::from_bytes([5; 32]),
            authority_grant: Hash::from_bytes([7; 32]),
        };
        let shape = shape_of(declares, &drafts, stored);
        let evidence = ok(PipelineEvidenceRefV1::try_new(Hash::from_bytes([5; 32])));
        let tentative_result = match declares {
            Declares::Plain => TentativePipelineResultV1::HumanDomainApproval(evidence),
            Declares::Ingress | Declares::Prior => {
                TentativePipelineResultV1::AiProviderValidation(evidence)
            }
        };
        let revision = Hash::from_bytes([6; 32]);
        ok(PipelineAdmissionBasisV1::try_from_draft(
            PipelineAdmissionBasisDraftV1 {
                contract_version: PIPELINE_CONTRACT_VERSION_V1,
                attempt: Some(attempt),
                tentative_result: Some(tentative_result),
                precondition: Some(PipelinePreconditionV1::ExpectedLogicalHead(observed)),
                security_revisions: Some(ok(PipelineSecurityRevisionsV1::try_from_draft(
                    PipelineSecurityRevisionsDraftV1 {
                        authority: revision,
                        consent: revision,
                        capability: revision,
                        delegation: revision,
                        policy: revision,
                        execution_profile: revision,
                        erasure: revision,
                    },
                ))),
                batch: Some(ok(PipelineDraftBatchV1::try_new(drafts))),
                dependencies: ok(assemble_factual_tick(&context, &shape)),
            },
        ))
    }

    /// The fence a commit of `basis` leaves behind, and the fence before it.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fences(basis: &PipelineAdmissionBasisV1) -> [PipelineAdmissionFenceV1; 2] {
        let fence = ok(PipelineAdmissionFenceV1::try_new(
            Hash::from_bytes([7; 32]),
            basis.security_revisions(),
            None,
            10,
        ));
        [fence, ok(fence.after_commit(2).ok_or("budget"))]
    }

    /// Commit the batch of `basis` inside one transaction, as the port does,
    /// after `stored` Events.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn commit_in_transaction(
        store: &SqliteStore,
        timeline: TimelineId,
        basis: &PipelineAdmissionBasisV1,
        stored: u64,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        let position = BatchPositionV1 {
            prefix: 0,
            owned_head: stored,
        };
        let [_, next_fence] = fences(basis);
        begin_immediate_scope(&store.conn).and_then(|scope| {
            let result = SqliteStore::fork_chain_on(&store.conn, timeline).and_then(|chain| {
                let now = WallTime::from_micros(1);
                store.insert_pipeline_batch(timeline, basis, now, position, &next_fence, &chain)
            });
            finish_immediate_scope(&store.conn, scope, result)
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_with_gate(path: &str) -> SqliteStore {
        let mut store = ok(SqliteStore::open(path));
        ok(store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open())));
        store
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn an_in_doubt_commit_records_nothing_and_the_retry_commits_after_reopen() {
        let directory = ok(tempfile::tempdir());
        let path = directory
            .path()
            .join("admission-in-doubt.db")
            .to_string_lossy()
            .into_owned();
        let mut store = open_with_gate(&path);
        let timeline = ok(store.create_timeline("admission-in-doubt")).id();
        let basis = basis(timeline, Declares::Plain, &[]);
        let [fence, _] = fences(&basis);
        ok(store.set_pipeline_admission_fence(timeline, fence));

        ok(store.conn.commit_hook(Some(|| true)));
        let in_doubt = commit_in_transaction(&store, timeline, &basis, 0);
        ok(store.conn.commit_hook::<fn() -> bool>(None));
        assert!(in_doubt.is_err());
        drop(store);

        let reopened = open_with_gate(&path);
        assert!(ok(reopened.read(timeline, SeqRange::all())).is_empty());
        assert_eq!(ok(reopened.pipeline_admission_fence(timeline)), Some(fence));
        let no_tick = FactualHeadV1 {
            tick: 0,
            last_seq: Seq::ZERO,
        };
        assert_eq!(ok(reopened.last_committed_factual_tick(timeline)), no_tick);
        let no_rows = RecordedSetCountsV1 {
            nodes: 0,
            edges: 0,
            inputs: 0,
        };
        assert_eq!(ok(reopened.factual_set_counts(timeline)), no_rows);

        let retried = ok(commit_in_transaction(&reopened, timeline, &basis, 0));
        let PipelineOutcomeV1::Committed(receipt) = retried else {
            std::panic::resume_unwind(Box::new(format!("expected a commit, got {retried:?}")));
        };
        assert_eq!(receipt.committed_events().len(), 2);
        let one_tick = FactualHeadV1 {
            tick: 1,
            last_seq: Seq::from_u64(2),
        };
        assert_eq!(ok(reopened.last_committed_factual_tick(timeline)), one_tick);
    }

    /// A failing read of the store while a Tick is planned is an error that
    /// leaves nothing behind, whichever read fails.
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn a_failing_planning_read_is_a_storage_error_that_commits_nothing() {
        let cases = [
            (Declares::Plain, "counterfactual_dependency_commit_ranges"),
            (Declares::Plain, "counterfactual_dependency_nodes"),
            (Declares::Plain, "counterfactual_dependency_records"),
            (Declares::Ingress, "events"),
            (Declares::Ingress, "counterfactual_dependency_event_nodes"),
            (Declares::Prior, "counterfactual_dependency_event_nodes"),
        ];
        for (declares, table) in cases {
            let mut store = open_with_gate(":memory:");
            let timeline = ok(store.create_timeline("admission-read-fault")).id();
            let seed = [EventDraft::new(
                EntityId::from_ulid(Ulid::from(9_u128)),
                Kind::new("world.action"),
                CanonicalBytes::from_vec(vec![9]),
            )];
            ok(store.append(timeline, &seed));
            let stored = ok(store.read(timeline, SeqRange::all()));
            let basis = basis(timeline, declares, &stored);
            ok(store
                .conn
                .execute_batch(&format!("PRAGMA foreign_keys = OFF; DROP TABLE {table};")));

            let outcome = commit_in_transaction(&store, timeline, &basis, 1);

            assert!(
                matches!(outcome, Err(CoreError::Storage(_))),
                "{table}: {outcome:?}"
            );
            assert!(store.conn.is_autocommit(), "{table}");
            let receipts = store.conn.query_row(
                "SELECT COUNT(*) FROM pipeline_admission_receipts",
                [],
                |row| row.get::<_, i64>(0),
            );
            assert_eq!(ok(receipts), 0, "{table}");
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fence_length_constraint_matches_the_fixed_record_width() {
        assert_eq!(
            FENCE_LENGTH_CONSTRAINT,
            format!("CHECK (length(fence_bytes) = {PIPELINE_ADMISSION_FENCE_BYTES_V1})")
        );
    }
}
