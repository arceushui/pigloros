//! `SQLite` adapter for the single-host erasure authority (ADR-136 §2.5 and
//! §4a): the authority snapshot, retained objects, owner effects, the
//! write-once erasure store identity, the startup sweep, the
//! recipient-export publication read and the recipient-export withdrawal
//! reads (ADR-138 §5).
//!
//! The authority snapshot reads the erasure inventory, every Timeline's owner
//! and Fork relation and the store identity in one read transaction. Every
//! write is one `BEGIN IMMEDIATE` transaction (or a savepoint inside an outer
//! one), so an error commits nothing.

use std::collections::BTreeSet;

use pos_core::{
    error::CoreError, local_erasure_export_recipient_v1, store::EventStore,
    ErasureAuthoritySnapshotV1, ErasureAuthorityTimelineRowV1, ErasureErrorV1,
    ErasureRecoveryLimitsV1, ErasureReferenceV1, ErasureRetainedObjectV1, Hash,
    KeyDestructionRequestV1, KeyTombstoneV1, OwnerIdV1, PreparedLocalOwnerEffectV1,
    RecipientExportPublicationRowV1, RecipientExportWithdrawalRowV1, Seq, TimelineId,
    ERASURE_MAX_OBLIGATIONS_PER_CATEGORY, REDACTION_GENERATION_MAX_V1,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::{
    begin_immediate_scope, finish_immediate_scope, load_sqlite_erasure_evidence,
    map_erasure_receipt_failure, parse_entity_id, parse_timeline_id, reference_from_sql,
    sqlite_erasure_inventory_snapshot, SqliteStore,
};

type TimelineSqlRowV1 = (String, Option<String>, Option<String>, Option<i64>);

/// The recipient-export withdrawal table (ADR-138 §3). It is created with
/// the recipient-export catalog, so a store that never published has neither.
pub(super) const RECIPIENT_EXPORT_WITHDRAWALS: &str = "recipient_export_withdrawals_v1";

impl SqliteStore {
    pub(super) fn local_erasure_authority_snapshot(
        &mut self,
        limits: ErasureRecoveryLimitsV1,
        export_targets: &[ErasureReferenceV1],
    ) -> Result<ErasureAuthoritySnapshotV1, ErasureErrorV1> {
        crate::export_targets_admitted(export_targets).and_then(|()| {
            self.conn
                .transaction_with_behavior(TransactionBehavior::Deferred)
                .map_err(map_erasure_receipt_failure)
                .and_then(|transaction| {
                    authority_snapshot_in(&transaction, limits, export_targets).and_then(
                        |snapshot| {
                            transaction
                                .commit()
                                .map(|()| snapshot)
                                .map_err(map_erasure_receipt_failure)
                        },
                    )
                })
        })
    }

    pub(super) fn local_erasure_retain(
        &self,
        canonical: &[u8],
        max_bytes: usize,
    ) -> Result<ErasureReferenceV1, ErasureErrorV1> {
        ErasureRetainedObjectV1::new(canonical, max_bytes).and_then(|object| {
            within_immediate(&self.conn, || insert_retained(&self.conn, &object))
        })
    }

    /// Commit one owner effect. A recipient-export withdrawal commits through
    /// its own durable T3 (ADR-138 §5); every other effect commits in one
    /// immediate transaction or savepoint.
    pub(super) fn local_erasure_commit_owner_effect(
        &self,
        prepared: &PreparedLocalOwnerEffectV1,
    ) -> Result<ErasureReferenceV1, ErasureErrorV1> {
        prepared.recipient_export_withdrawal().map_or_else(
            || self.commit_record_owner_effect(prepared),
            |binding| {
                #[cfg(target_os = "linux")]
                {
                    self.commit_recipient_export_withdrawal(prepared, &binding)
                }
                // ADR-138 T3 without Linux custody: no withdrawal row can
                // exist, so the `export_id` is unknown (ADR-138 §6).
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = binding;
                    Err(ErasureErrorV1::ProvenanceMissing)
                }
            },
        )
    }

    fn commit_record_owner_effect(
        &self,
        prepared: &PreparedLocalOwnerEffectV1,
    ) -> Result<ErasureReferenceV1, ErasureErrorV1> {
        within_immediate(&self.conn, || {
            prepared
                .key_tombstone()
                .map_or(Ok(()), |(request, deletion_receipt)| {
                    self.complete_tombstone(request, deletion_receipt)
                })
                .and_then(|()| {
                    prepared
                        .existing_tombstone()
                        .map_or(Ok(()), |tombstone| self.holds_tombstone(&tombstone))
                })
                // The generation is read before the effect is retained, so
                // the first ELCG1 is not yet in the store when its missing
                // row is checked.
                .and_then(|()| {
                    prepared
                        .raises_redaction_generation()
                        .then(|| read_redaction_generation(&self.conn))
                        .transpose()
                })
                .and_then(|current| {
                    prepared
                        .effect_object()
                        .map_or(Ok(false), |object| insert_new_retained(&self.conn, object))
                        .map(|inserted| current.filter(|_| inserted))
                })
                .and_then(|current| {
                    current.map_or(Ok(()), |generation| {
                        write_raised_redaction_generation(&self.conn, generation)
                    })
                })
                .and_then(|()| insert_retained(&self.conn, prepared.owner_result()))
        })
    }

    pub(super) fn local_erasure_redaction_generation(&self) -> Result<u64, ErasureErrorV1> {
        read_redaction_generation(&self.conn)
    }

    pub(super) fn local_erasure_store_identity(&self) -> Result<Option<Hash>, ErasureErrorV1> {
        read_store_identity(&self.conn)
    }

    pub(super) fn local_erasure_init_store_identity(
        &self,
        id: Hash,
    ) -> Result<Hash, ErasureErrorV1> {
        within_immediate(&self.conn, || {
            self.conn
                .execute(
                    "INSERT INTO erasure_store_identity (singleton, identity) VALUES (1, ?1)
                     ON CONFLICT (singleton) DO NOTHING",
                    params![id.as_bytes().as_slice()],
                )
                .map_err(map_erasure_receipt_failure)
                .and_then(|_| read_store_identity(&self.conn))
                .and_then(|recorded| {
                    (recorded == Some(id))
                        .then_some(id)
                        .ok_or(ErasureErrorV1::PolicyConflict)
                })
        })
    }

    pub(super) fn local_erasure_sweep(
        &self,
        tags: &[&str],
        keep: &[ErasureReferenceV1],
        max: usize,
    ) -> Result<usize, ErasureErrorV1> {
        within_immediate(&self.conn, || {
            sweep_candidates(&self.conn, tags, keep, max).and_then(|candidates| {
                candidates
                    .iter()
                    .try_for_each(|reference| delete_retained(&self.conn, *reference))
                    .map(|()| candidates.len())
            })
        })
    }

    /// The exact bytes of the retained objects of `tag`, in increasing
    /// address order, streamed so the read stops one row past `max`. No
    /// foreign key ties a retained row to its bytes, so a row whose
    /// `erasure_evidence` bytes are gone is
    /// [`ErasureErrorV1::ProvenanceMissing`], never silently dropped.
    pub(super) fn local_erasure_retained(
        &self,
        tag: &str,
        max: usize,
    ) -> Result<Vec<Vec<u8>>, ErasureErrorV1> {
        self.conn
            .prepare(
                "SELECT evidence.object_cbor FROM erasure_retained_objects AS retained
                 LEFT JOIN erasure_evidence AS evidence
                   ON evidence.reference_digest = retained.reference_digest
                 WHERE retained.tag = ?1 ORDER BY retained.reference_digest",
            )
            .map_err(map_erasure_receipt_failure)
            .and_then(|mut statement| {
                statement
                    .query_map(params![tag], |row| row.get::<_, Option<Vec<u8>>>(0))
                    .map_err(map_erasure_receipt_failure)
                    .and_then(|rows| {
                        rows.take(max.saturating_add(1))
                            .map(|row| {
                                row.map_err(map_erasure_receipt_failure).and_then(|bytes| {
                                    bytes.ok_or(ErasureErrorV1::ProvenanceMissing)
                                })
                            })
                            .collect::<Result<Vec<_>, _>>()
                    })
            })
            .and_then(|objects| {
                if objects.len() > max {
                    Err(ErasureErrorV1::ScopeInvalid)
                } else {
                    Ok(objects)
                }
            })
    }

    /// Every visible recipient-export publication of the named Timelines,
    /// sorted by `(timeline, export_id)`. Only `recipient_export_catalog_v1`
    /// holds visible publications; a pending one is never read. A store that
    /// never published has no catalog, which reads as empty.
    ///
    /// This read is not part of the authority's Timeline snapshot
    /// transaction, so it alone cannot exclude a publication racing it. That
    /// is safe because `publish_recipient_export` (`recipient_owner.rs`)
    /// publishes only while holding the erasure `Export` fence of its
    /// Timeline, which a Timeline under erasure refuses (pinned by
    /// `publication_holds_the_erasure_export_fence`): a pending publication
    /// left outside that fence can never become visible for such a Timeline.
    pub(super) fn local_erasure_recipient_export_publications(
        &self,
        timelines: &[TimelineId],
        max: usize,
    ) -> Result<Vec<RecipientExportPublicationRowV1>, ErasureErrorV1> {
        let selected: BTreeSet<TimelineId> = timelines.iter().copied().collect();
        table_present(&self.conn, "recipient_export_catalog_v1").and_then(|present| {
            if !present {
                return Ok(Vec::new());
            }
            selected
                .into_iter()
                .try_fold(Vec::new(), |mut publications, timeline| {
                    timeline_publications(&self.conn, timeline, max.saturating_add(1)).and_then(
                        |rows| {
                            publications.extend(rows);
                            if publications.len() > max {
                                Err(ErasureErrorV1::ScopeInvalid)
                            } else {
                                Ok(publications)
                            }
                        },
                    )
                })
        })
    }

    /// Resolve one `ELXR1` target (ADR-138 §5): the withdrawal row with that
    /// target first, else the first catalog row of `timelines` whose
    /// recomputed `ELXR1` equals it. Either is resolved only when its source
    /// Timeline is in `timelines`. A store without the withdrawal table never
    /// published, so it resolves nothing.
    pub(super) fn local_erasure_recipient_export_by_target(
        &self,
        target: ErasureReferenceV1,
        timelines: &[TimelineId],
    ) -> Result<Option<([u8; 16], OwnerIdV1)>, ErasureErrorV1> {
        table_present(&self.conn, RECIPIENT_EXPORT_WITHDRAWALS).and_then(|present| {
            if !present {
                return Ok(None);
            }
            withdrawal_by_target(&self.conn, target).and_then(|withdrawal| {
                withdrawal.map_or_else(
                    || catalog_by_target(&self.conn, target, timelines),
                    |row| {
                        Ok(timelines
                            .contains(&row.timeline)
                            .then_some((row.export_id, row.grantee_owner)))
                    },
                )
            })
        })
    }

    /// Whether the key registry holds exactly `tombstone`, read inside the
    /// caller's transaction.
    fn holds_tombstone(&self, tombstone: &KeyTombstoneV1) -> Result<(), ErasureErrorV1> {
        self.validate_erasure_inventory_data_version()
            .ok()
            .and_then(|()| self.load_key_registry().ok().flatten())
            .and_then(|registry| registry.tombstone(tombstone.identity))
            .filter(|held| held == tombstone)
            .map(drop)
            .ok_or(ErasureErrorV1::KeyDestructionFailed)
    }

    /// Complete one pending key destruction inside the caller's transaction,
    /// exactly as the key-registry tombstone command does.
    fn complete_tombstone(
        &self,
        request: KeyDestructionRequestV1,
        deletion_receipt: Hash,
    ) -> Result<(), ErasureErrorV1> {
        self.validate_erasure_inventory_data_version()
            .ok()
            .and_then(|()| self.load_key_registry().ok().flatten())
            .and_then(|mut registry| {
                registry
                    .complete_key_destruction(request, deletion_receipt)
                    .ok()
                    .map(|_| registry)
            })
            .and_then(|registry| self.save_key_registry_in_transaction(&registry).ok())
            .ok_or(ErasureErrorV1::KeyDestructionFailed)
    }
}

/// Read the inventory, every Timeline row, the store identity and the
/// withdrawal rows of `export_targets` inside one caller-owned read
/// transaction, so all four describe one store state.
fn authority_snapshot_in(
    transaction: &rusqlite::Transaction<'_>,
    limits: ErasureRecoveryLimitsV1,
    export_targets: &[ErasureReferenceV1],
) -> Result<ErasureAuthoritySnapshotV1, ErasureErrorV1> {
    sqlite_erasure_inventory_snapshot(transaction, limits).and_then(|inventory| {
        timeline_rows(transaction, limits).and_then(|timelines| {
            read_store_identity(transaction).and_then(|identity| {
                withdrawal_rows(transaction, export_targets).and_then(|withdrawals| {
                    ErasureAuthoritySnapshotV1::new(inventory, timelines, identity, withdrawals)
                })
            })
        })
    })
}

/// The withdrawal rows of the distinct `export_targets` that have one, in
/// increasing target order.
fn withdrawal_rows(
    connection: &Connection,
    export_targets: &[ErasureReferenceV1],
) -> Result<Vec<RecipientExportWithdrawalRowV1>, ErasureErrorV1> {
    let targets: BTreeSet<ErasureReferenceV1> = export_targets.iter().copied().collect();
    table_present(connection, RECIPIENT_EXPORT_WITHDRAWALS).and_then(|present| {
        targets
            .into_iter()
            .filter(|_| present)
            .filter_map(|target| withdrawal_by_target(connection, target).transpose())
            .map(|row| {
                row.map(|row| RecipientExportWithdrawalRowV1 {
                    target: row.target,
                    export_id: row.export_id,
                    disposition: row.disposition,
                    committed_elo1: row.committed_elo1,
                })
            })
            .collect()
    })
}

/// The target-indexed columns of one withdrawal row.
struct TargetedWithdrawalV1 {
    target: ErasureReferenceV1,
    export_id: [u8; 16],
    timeline: TimelineId,
    grantee_owner: OwnerIdV1,
    disposition: Option<ErasureReferenceV1>,
    committed_elo1: Option<ErasureReferenceV1>,
}

type TargetedWithdrawalSqlV1 = (Vec<u8>, String, String, Option<Vec<u8>>, Option<Vec<u8>>);

/// The withdrawal row whose `target` column is `target`; a malformed row is
/// [`ErasureErrorV1::ProvenanceMissing`].
fn withdrawal_by_target(
    connection: &Connection,
    target: ErasureReferenceV1,
) -> Result<Option<TargetedWithdrawalV1>, ErasureErrorV1> {
    connection
        .query_row(
            "SELECT export_id, timeline_id, owner_id, disposition, committed_elo1
             FROM recipient_export_withdrawals_v1 WHERE target = ?1",
            params![target.digest().as_slice()],
            |row| TargetedWithdrawalSqlV1::try_from(row),
        )
        .optional()
        .map_err(map_erasure_receipt_failure)
        .and_then(|row| {
            row.map(
                |(export_id, timeline, owner, disposition, committed_elo1)| {
                    <[u8; 16]>::try_from(export_id)
                        .ok()
                        .zip(parse_timeline_id(&timeline).ok())
                        .zip(OwnerIdV1::new(owner).ok())
                        .ok_or(ErasureErrorV1::ProvenanceMissing)
                        .and_then(|((export_id, timeline), grantee_owner)| {
                            disposition.map(reference_from_sql).transpose().and_then(
                                |disposition| {
                                    committed_elo1.map(reference_from_sql).transpose().map(
                                        |committed_elo1| TargetedWithdrawalV1 {
                                            target,
                                            export_id,
                                            timeline,
                                            grantee_owner,
                                            disposition,
                                            committed_elo1,
                                        },
                                    )
                                },
                            )
                        })
                },
            )
            .transpose()
        })
}

/// The first catalog row of `timelines`, in Timeline then `export_id` order,
/// whose recomputed `CA("ELXR1", [export_id, owner_id])` is `target`. The
/// scan reads at most one category of publications (ADR-138 §5): more is
/// [`ErasureErrorV1::ScopeInvalid`].
fn catalog_by_target(
    connection: &Connection,
    target: ErasureReferenceV1,
    timelines: &[TimelineId],
) -> Result<Option<([u8; 16], OwnerIdV1)>, ErasureErrorV1> {
    let selected: BTreeSet<TimelineId> = timelines.iter().copied().collect();
    let limit = ERASURE_MAX_OBLIGATIONS_PER_CATEGORY.saturating_add(1);
    selected
        .into_iter()
        .map(|timeline| timeline_publications(connection, timeline, limit))
        .collect::<Result<Vec<_>, _>>()
        .and_then(|publications| {
            if publications.iter().map(Vec::len).sum::<usize>()
                > ERASURE_MAX_OBLIGATIONS_PER_CATEGORY
            {
                Err(ErasureErrorV1::ScopeInvalid)
            } else {
                Ok(publications)
            }
        })
        .and_then(|publications| {
            publications
                .into_iter()
                .flatten()
                .map(|row| {
                    local_erasure_export_recipient_v1(row.export_id, &row.grantee_owner).map(
                        |candidate| {
                            (candidate == target).then_some((row.export_id, row.grantee_owner))
                        },
                    )
                })
                .find_map(Result::transpose)
                .transpose()
        })
}

/// Whether the store holds the named table.
pub(super) fn table_present(connection: &Connection, table: &str) -> Result<bool, ErasureErrorV1> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
            params![table],
            |row| row.get(0),
        )
        .map_err(map_erasure_receipt_failure)
}

/// Run one write in its own immediate transaction, or a savepoint inside an
/// outer one, keeping the write's closed error.
fn within_immediate<T>(
    connection: &Connection,
    work: impl FnOnce() -> Result<T, ErasureErrorV1>,
) -> Result<T, ErasureErrorV1> {
    let mut failure = ErasureErrorV1::ReceiptCommitFailed;
    begin_immediate_scope(connection)
        .and_then(|scope| {
            let result = work().map_err(|error| {
                failure = error;
                CoreError::Storage(String::new())
            });
            finish_immediate_scope(connection, scope, result)
        })
        .map_err(|_| failure)
}

fn timeline_rows(
    connection: &Connection,
    limits: ErasureRecoveryLimitsV1,
) -> Result<Vec<ErasureAuthorityTimelineRowV1>, ErasureErrorV1> {
    let limit = i64::try_from(limits.maximum_timelines().saturating_add(1)).unwrap_or(i64::MAX);
    connection
        .prepare(
            "SELECT t.id, o.owner_id, t.parent_id, t.fork_seq FROM timelines t
             LEFT JOIN timeline_owners o ON o.timeline_id = t.id
             ORDER BY t.id LIMIT ?1",
        )
        .map_err(map_erasure_receipt_failure)
        .and_then(|mut statement| {
            statement
                .query_map(params![limit], |row| TimelineSqlRowV1::try_from(row))
                .map_err(map_erasure_receipt_failure)
                .and_then(|rows| {
                    rows.map(|row| {
                        row.map_err(map_erasure_receipt_failure).and_then(|row| {
                            timeline_row(&row).ok_or(ErasureErrorV1::ProvenanceMissing)
                        })
                    })
                    .collect()
                })
        })
}

/// Decode one Timeline row; `None` when a stored identity is malformed.
fn timeline_row(row: &TimelineSqlRowV1) -> Option<ErasureAuthorityTimelineRowV1> {
    let (id, owner, parent, fork_seq) = row;
    let owner = owner
        .as_deref()
        .map_or(Some(None), |owner| parse_entity_id(owner).ok().map(Some));
    let fork_point = match (parent.as_deref(), fork_seq) {
        (Some(parent), Some(fork_seq)) => parse_timeline_id(parent)
            .ok()
            .zip(u64::try_from(*fork_seq).ok())
            .map(|(parent, fork_seq)| Some((parent, Seq::from_u64(fork_seq)))),
        _ => Some(None),
    };
    parse_timeline_id(id)
        .ok()
        .zip(owner)
        .zip(fork_point)
        .map(|((id, owner), fork_point)| ErasureAuthorityTimelineRowV1 {
            id,
            owner,
            fork_point,
        })
}

/// The first `limit` publications of one Timeline in `export_id` order.
fn timeline_publications(
    connection: &Connection,
    timeline: TimelineId,
    limit: usize,
) -> Result<Vec<RecipientExportPublicationRowV1>, ErasureErrorV1> {
    let timeline_text = timeline.to_string();
    connection
        .prepare(
            "SELECT export_id, owner_id FROM recipient_export_catalog_v1
             WHERE timeline_id = ?1 ORDER BY export_id",
        )
        .and_then(|mut statement| {
            statement
                .query_map(params![timeline_text], |row| {
                    row.get::<_, Vec<u8>>(0).and_then(|export_id| {
                        row.get::<_, String>(1).map(|owner| (export_id, owner))
                    })
                })
                .and_then(|rows| rows.take(limit).collect::<Result<Vec<_>, _>>())
        })
        .map_err(map_erasure_receipt_failure)
        .and_then(|rows| {
            rows.into_iter()
                .map(|(export_id, owner)| publication_row(timeline, export_id, owner))
                .collect()
        })
}

/// Decode one catalog row; a malformed export identity or owner is
/// [`ErasureErrorV1::ProvenanceMissing`].
fn publication_row(
    timeline: TimelineId,
    export_id: Vec<u8>,
    owner: String,
) -> Result<RecipientExportPublicationRowV1, ErasureErrorV1> {
    <[u8; 16]>::try_from(export_id)
        .ok()
        .zip(OwnerIdV1::new(owner).ok())
        .map(
            |(export_id, grantee_owner)| RecipientExportPublicationRowV1 {
                export_id,
                timeline,
                grantee_owner,
            },
        )
        .ok_or(ErasureErrorV1::ProvenanceMissing)
}

fn read_store_identity(connection: &Connection) -> Result<Option<Hash>, ErasureErrorV1> {
    connection
        .query_row(
            "SELECT identity FROM erasure_store_identity WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(map_erasure_receipt_failure)
        .and_then(|identity| {
            identity
                .map(|identity| {
                    reference_from_sql(identity).map(|identity| Hash::from_bytes(identity.digest()))
                })
                .transpose()
        })
}

/// Insert one object into the shared erasure object store. Only a newly
/// inserted object becomes a sweep candidate, so a coordinator object is
/// never marked; an existing address must hold exactly these bytes.
pub(super) fn insert_retained(
    connection: &Connection,
    object: &ErasureRetainedObjectV1,
) -> Result<ErasureReferenceV1, ErasureErrorV1> {
    insert_new_retained(connection, object).map(|_| object.reference())
}

/// [`insert_retained`], answering whether the object's bytes were newly
/// inserted rather than already held.
fn insert_new_retained(
    connection: &Connection,
    object: &ErasureRetainedObjectV1,
) -> Result<bool, ErasureErrorV1> {
    let reference = object.reference();
    connection
        .execute(
            "INSERT INTO erasure_evidence (reference_digest, object_cbor) VALUES (?1, ?2)
             ON CONFLICT (reference_digest) DO NOTHING",
            params![reference.digest().as_slice(), object.canonical_cbor()],
        )
        .map_err(map_erasure_receipt_failure)
        .and_then(|inserted| {
            connection
                .execute(
                    "INSERT INTO erasure_retained_objects (reference_digest, tag)
                     SELECT ?1, ?2 WHERE ?3",
                    params![reference.digest().as_slice(), object.tag(), inserted == 1],
                )
                .map_err(map_erasure_receipt_failure)
                .map(|_| inserted == 1)
        })
        .and_then(|inserted| {
            load_sqlite_erasure_evidence(connection, reference).and_then(|stored| {
                (stored.as_slice() == object.canonical_cbor())
                    .then_some(inserted)
                    .ok_or(ErasureErrorV1::ProvenanceMissing)
            })
        })
}

/// The redaction generation (#1407). A store without its row has committed
/// no ELCG1 and reads 0, unless it retains an ELCG1: then the row was lost,
/// and 0 would let the generation decrease. That, a stored value that is
/// negative or above [`REDACTION_GENERATION_MAX_V1`], and a row the adapter
/// cannot read are each a closed persistence error.
fn read_redaction_generation(connection: &Connection) -> Result<u64, ErasureErrorV1> {
    connection
        .query_row(
            "SELECT generation FROM erasure_redaction_generation WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(map_erasure_receipt_failure)
        .and_then(|stored| {
            stored.map_or_else(
                || holds_no_cache_generation(connection).map(|()| 0),
                |generation| {
                    u64::try_from(generation)
                        .ok()
                        .filter(|generation| *generation <= REDACTION_GENERATION_MAX_V1)
                        .ok_or(ErasureErrorV1::ReceiptCommitFailed)
                },
            )
        })
}

/// `Ok` when the store retains no ELCG1 cache generation, so a missing
/// redaction-generation row means none was committed;
/// [`ErasureErrorV1::ReceiptCommitFailed`] when it retains one.
fn holds_no_cache_generation(connection: &Connection) -> Result<(), ErasureErrorV1> {
    connection
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM erasure_retained_objects WHERE tag = 'ELCG1')",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(map_erasure_receipt_failure)
        .and_then(|holds| {
            (!holds)
                .then_some(())
                .ok_or(ErasureErrorV1::ReceiptCommitFailed)
        })
}

/// Write `generation` raised by one inside the caller's transaction. A
/// generation past [`REDACTION_GENERATION_MAX_V1`] is never written, so the
/// caller's transaction fails and rolls back. `generation` was read under
/// that bound, so the addition cannot overflow.
fn write_raised_redaction_generation(
    connection: &Connection,
    generation: u64,
) -> Result<(), ErasureErrorV1> {
    Some(generation + 1)
        .filter(|raised| *raised <= REDACTION_GENERATION_MAX_V1)
        .and_then(|raised| i64::try_from(raised).ok())
        .ok_or(ErasureErrorV1::ReceiptCommitFailed)
        .and_then(|raised| {
            connection
                .execute(
                    "INSERT INTO erasure_redaction_generation (singleton, generation)
                     VALUES (1, ?1)
                     ON CONFLICT (singleton) DO UPDATE SET generation = excluded.generation",
                    params![raised],
                )
                .map(drop)
                .map_err(map_erasure_receipt_failure)
        })
}

/// The first `max` retained objects of the named tags outside `keep`, in
/// increasing address order. Tags are filtered in SQL and rows are streamed,
/// so the scan stops at the `max`-th candidate.
fn sweep_candidates(
    connection: &Connection,
    tags: &[&str],
    keep: &[ErasureReferenceV1],
    max: usize,
) -> Result<Vec<ErasureReferenceV1>, ErasureErrorV1> {
    let placeholders = vec!["?"; tags.len()].join(", ");
    connection
        .prepare(&format!(
            "SELECT reference_digest FROM erasure_retained_objects
             WHERE tag IN ({placeholders}) ORDER BY reference_digest"
        ))
        .map_err(map_erasure_receipt_failure)
        .and_then(|mut statement| {
            statement
                .query_map(rusqlite::params_from_iter(tags), |row| {
                    row.get::<_, Vec<u8>>(0)
                })
                .map_err(map_erasure_receipt_failure)
                .and_then(|rows| {
                    rows.map(|row| {
                        row.map_err(map_erasure_receipt_failure)
                            .and_then(reference_from_sql)
                    })
                    .filter(|row| !row.as_ref().is_ok_and(|reference| keep.contains(reference)))
                    .take(max)
                    .collect()
                })
        })
}

fn delete_retained(
    connection: &Connection,
    reference: ErasureReferenceV1,
) -> Result<(), ErasureErrorV1> {
    connection
        .execute(
            "DELETE FROM erasure_retained_objects WHERE reference_digest = ?1",
            params![reference.digest().as_slice()],
        )
        .and_then(|_| {
            connection.execute(
                "DELETE FROM erasure_evidence WHERE reference_digest = ?1",
                params![reference.digest().as_slice()],
            )
        })
        .map(|_| ())
        .map_err(map_erasure_receipt_failure)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// An address the evidence path already holds is never marked as a
    /// sweep candidate when the same bytes are retained again, so a startup
    /// sweep cannot delete committed evidence. The coordinator CAS does key
    /// ERSEH1 and ERAH1 evidence by that address; the public guard is in
    /// `tests/erasure_persistence.rs`, and this seeded case is a cheap
    /// mutation guard for the adapter branch alone.
    #[test]
    fn retaining_bytes_the_evidence_path_wrote_first_never_marks_them(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("evidence-first.sqlite3");
        let path = path
            .to_str()
            .ok_or("temporary database path is not UTF-8")?;
        let store = SqliteStore::open(path)?;
        let bytes = [0x82, 0x64, b'E', b'R', b'C', b'1', 0x01];
        let reference = ErasureRetainedObjectV1::new(&bytes, 1_024)?.reference();
        store.conn.execute(
            "INSERT INTO erasure_evidence (reference_digest, object_cbor) VALUES (?1, ?2)",
            params![reference.digest().as_slice(), bytes.as_slice()],
        )?;
        assert_eq!(store.local_erasure_retain(&bytes, 1_024)?, reference);
        assert_eq!(store.local_erasure_sweep(&["ERC1"], &[], 16)?, 0);
        assert_eq!(
            load_sqlite_erasure_evidence(&store.conn, reference)?,
            bytes.to_vec()
        );
        Ok(())
    }

    /// #1407: a redaction-generation row lost beside a retained ELCG1 is a
    /// closed read and refuses the next ELCG1 commit, which retains nothing
    /// and leaves the row absent, rather than restart the generation at 0.
    /// Without any ELCG1 a missing row still reads 0.
    #[test]
    fn a_lost_generation_row_beside_an_elcg1_fails_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("lost-generation.sqlite3");
        let path = path
            .to_str()
            .ok_or("temporary database path is not UTF-8")?;
        let store = SqliteStore::open(path)?;
        assert_eq!(store.local_erasure_redaction_generation(), Ok(0));
        let elcg1 = |value: u8| {
            PreparedLocalOwnerEffectV1::new(
                pos_core::LocalOwnerEffectV1::CacheGeneration(vec![
                    0x83, 0x65, b'E', b'L', b'C', b'G', b'1', 0x01, value,
                ]),
                pos_core::LocalOwnerResultBindingV1 {
                    request: ErasureReferenceV1::from_digest([value; 32]),
                    attempt: ErasureReferenceV1::from_digest([2; 32]),
                    obligation: ErasureReferenceV1::from_digest([3; 32]),
                    command: ErasureReferenceV1::from_digest([4; 32]),
                    owner_ref: ErasureReferenceV1::from_digest([5; 32]),
                    error: None,
                },
            )
        };
        store.local_erasure_commit_owner_effect(&elcg1(1)?)?;
        assert_eq!(store.local_erasure_redaction_generation(), Ok(1));
        store
            .conn
            .execute("DELETE FROM erasure_redaction_generation", [])?;
        assert_eq!(
            store.local_erasure_redaction_generation(),
            Err(ErasureErrorV1::ReceiptCommitFailed)
        );
        assert_eq!(
            store.local_erasure_commit_owner_effect(&elcg1(2)?),
            Err(ErasureErrorV1::ReceiptCommitFailed)
        );
        let (rows, retained): (i64, i64) = store.conn.query_row(
            "SELECT (SELECT count(*) FROM erasure_redaction_generation),
                    (SELECT count(*) FROM erasure_retained_objects WHERE tag = 'ELCG1')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!((rows, retained), (0, 1));
        Ok(())
    }

    /// The production snapshot reads all its parts in the one transaction it
    /// is given: a Timeline another connection commits after that
    /// transaction's read snapshot began is in none of them.
    #[test]
    fn authority_snapshot_reads_share_one_read_transaction(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("isolation.sqlite3");
        let path = path
            .to_str()
            .ok_or("temporary database path is not UTF-8")?;
        let mut store = SqliteStore::open(path)?;
        store.create_timeline("before")?;
        let limits = ErasureRecoveryLimitsV1::from_maximum_requests(4)?;
        let transaction = store
            .conn
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let started: i64 =
            transaction.query_row("SELECT count(*) FROM timelines", [], |row| row.get(0))?;
        SqliteStore::open(path)?.create_timeline("during")?;
        let snapshot = authority_snapshot_in(&transaction, limits, &[])?;
        assert_eq!(started, 1);
        assert_eq!(snapshot.inventory().topology().len(), 1);
        assert_eq!(snapshot.timelines().len(), 1);
        drop(transaction);
        assert_eq!(
            store
                .local_erasure_authority_snapshot(limits, &[])?
                .timelines()
                .len(),
            2
        );
        Ok(())
    }
}
