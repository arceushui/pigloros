//! `SQLite` adapter for the single-host erasure authority (ADR-136 §2.5 and
//! §4a): the authority snapshot, retained objects, owner effects, the
//! write-once erasure store identity and the startup sweep.
//!
//! The authority snapshot reads the erasure inventory, every Timeline's owner
//! and Fork relation and the store identity in one read transaction. Every
//! write is one `BEGIN IMMEDIATE` transaction (or a savepoint inside an outer
//! one), so an error commits nothing.

use pos_core::{
    error::CoreError, store::EventStore, ErasureAuthoritySnapshotV1, ErasureAuthorityTimelineRowV1,
    ErasureErrorV1, ErasureRecoveryLimitsV1, ErasureReferenceV1, ErasureRetainedObjectV1, Hash,
    KeyDestructionRequestV1, LocalOwnerEffectV1, PreparedLocalOwnerEffectV1, Seq,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::{
    begin_immediate_scope, finish_immediate_scope, load_sqlite_erasure_evidence,
    map_erasure_receipt_failure, parse_entity_id, parse_timeline_id, reference_from_sql,
    sqlite_erasure_inventory_snapshot, SqliteStore,
};

type TimelineSqlRowV1 = (String, Option<String>, Option<String>, Option<i64>);

impl SqliteStore {
    pub(super) fn local_erasure_authority_snapshot(
        &mut self,
        limits: ErasureRecoveryLimitsV1,
    ) -> Result<ErasureAuthoritySnapshotV1, ErasureErrorV1> {
        self.conn
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(map_erasure_receipt_failure)
            .and_then(|transaction| {
                authority_snapshot_in(&transaction, limits).and_then(|snapshot| {
                    transaction
                        .commit()
                        .map(|()| snapshot)
                        .map_err(map_erasure_receipt_failure)
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

    pub(super) fn local_erasure_commit_owner_effect(
        &self,
        effect: LocalOwnerEffectV1,
        elo1: &[u8],
    ) -> Result<ErasureReferenceV1, ErasureErrorV1> {
        PreparedLocalOwnerEffectV1::new(effect, elo1).and_then(|prepared| {
            within_immediate(&self.conn, || {
                prepared
                    .key_tombstone()
                    .map_or(Ok(()), |(request, deletion_receipt)| {
                        self.complete_tombstone(request, deletion_receipt)
                    })
                    .and_then(|()| {
                        prepared.effect_object().map_or(Ok(()), |object| {
                            insert_retained(&self.conn, object).map(|_| ())
                        })
                    })
                    .and_then(|()| insert_retained(&self.conn, prepared.owner_result()))
            })
        })
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

/// Read the inventory, every Timeline row and the store identity inside one
/// caller-owned read transaction, so all three describe one store state.
fn authority_snapshot_in(
    transaction: &rusqlite::Transaction<'_>,
    limits: ErasureRecoveryLimitsV1,
) -> Result<ErasureAuthoritySnapshotV1, ErasureErrorV1> {
    sqlite_erasure_inventory_snapshot(transaction, limits).and_then(|inventory| {
        timeline_rows(transaction, limits).and_then(|timelines| {
            read_store_identity(transaction).and_then(|identity| {
                ErasureAuthoritySnapshotV1::new(inventory, timelines, identity)
            })
        })
    })
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
fn insert_retained(
    connection: &Connection,
    object: &ErasureRetainedObjectV1,
) -> Result<ErasureReferenceV1, ErasureErrorV1> {
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
        })
        .and_then(|_| load_sqlite_erasure_evidence(connection, reference))
        .and_then(|stored| {
            (stored.as_slice() == object.canonical_cbor())
                .then_some(reference)
                .ok_or(ErasureErrorV1::ProvenanceMissing)
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
        let snapshot = authority_snapshot_in(&transaction, limits)?;
        assert_eq!(started, 1);
        assert_eq!(snapshot.inventory().topology().len(), 1);
        assert_eq!(snapshot.timelines().len(), 1);
        drop(transaction);
        assert_eq!(
            store
                .local_erasure_authority_snapshot(limits)?
                .timelines()
                .len(),
            2
        );
        Ok(())
    }
}
