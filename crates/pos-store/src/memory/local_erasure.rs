//! `MemoryStore` adapter for the single-host erasure authority (ADR-136 §2.5
//! and §4a): the authority snapshot, retained objects, owner effects, the
//! write-once erasure store identity and the startup sweep.
//!
//! Every fallible check runs before the first mutation, so an error leaves
//! the store unchanged, matching the `SQLite` adapter's transactions.
//!
//! `MemoryStore` has no recipient-export publication path (ADR-138 §6): its
//! snapshot holds no withdrawal row and a withdrawal effect names an unknown
//! `export_id`.

use pos_core::{
    store::EventStore, ErasureAuthoritySnapshotV1, ErasureAuthorityTimelineRowV1, ErasureErrorV1,
    ErasureInventoryPersistencePortV1, ErasureRecoveryLimitsV1, ErasureReferenceV1,
    ErasureRetainedObjectV1, Hash, KeyTombstoneV1, PreparedLocalOwnerEffectV1,
    ERASURE_MAX_OBLIGATIONS_PER_CATEGORY,
};

use super::MemoryStore;

impl MemoryStore {
    pub(super) fn local_erasure_authority_snapshot(
        &mut self,
        limits: ErasureRecoveryLimitsV1,
        export_targets: &[ErasureReferenceV1],
    ) -> Result<ErasureAuthoritySnapshotV1, ErasureErrorV1> {
        if export_targets.len() > ERASURE_MAX_OBLIGATIONS_PER_CATEGORY {
            return Err(ErasureErrorV1::ScopeInvalid);
        }
        // The authority read never rebinds the installed inventory generation.
        let installed = self.erasure_inventory_generation;
        let inventory = self.complete_erasure_inventory_snapshot_with_limits(limits);
        self.erasure_inventory_generation = installed;
        inventory.and_then(|inventory| {
            let mut timelines = self
                .timelines
                .values()
                .map(|state| ErasureAuthorityTimelineRowV1 {
                    id: state.timeline.meta.id,
                    owner: state.timeline.meta.owner,
                    fork_point: state.timeline.meta.fork_point,
                })
                .collect::<Vec<_>>();
            timelines.sort_unstable_by_key(|row| row.id);
            ErasureAuthoritySnapshotV1::new(
                inventory,
                timelines,
                self.erasure_store_identity,
                Vec::new(),
            )
        })
    }

    pub(super) fn local_erasure_retain(
        &mut self,
        canonical: &[u8],
        max_bytes: usize,
    ) -> Result<ErasureReferenceV1, ErasureErrorV1> {
        ErasureRetainedObjectV1::new(canonical, max_bytes).and_then(|object| {
            self.retainable(&object)
                .map(|()| self.insert_retained(&object))
        })
    }

    pub(super) fn local_erasure_commit_owner_effect(
        &mut self,
        prepared: &PreparedLocalOwnerEffectV1,
    ) -> Result<ErasureReferenceV1, ErasureErrorV1> {
        prepared
            .recipient_export_withdrawal()
            .map_or(Ok(()), |_| Err(ErasureErrorV1::ProvenanceMissing))
            .and_then(|()| {
                prepared
                    .effect_object()
                    .map_or(Ok(()), |object| self.retainable(object))
            })
            .and_then(|()| self.retainable(prepared.owner_result()))
            .and_then(|()| {
                prepared
                    .key_tombstone()
                    .map_or(Ok(()), |(request, deletion_receipt)| {
                        self.complete_tombstone(request, deletion_receipt)
                    })
            })
            .and_then(|()| {
                prepared
                    .existing_tombstone()
                    .map_or(Ok(()), |tombstone| self.holds_tombstone(&tombstone))
            })
            .map(|()| {
                if let Some(object) = prepared.effect_object() {
                    self.insert_retained(object);
                }
                self.insert_retained(prepared.owner_result())
            })
    }

    pub(super) const fn local_erasure_store_identity(&self) -> Option<Hash> {
        self.erasure_store_identity
    }

    pub(super) fn local_erasure_init_store_identity(
        &mut self,
        id: Hash,
    ) -> Result<Hash, ErasureErrorV1> {
        let recorded = *self.erasure_store_identity.get_or_insert(id);
        if recorded == id {
            Ok(recorded)
        } else {
            Err(ErasureErrorV1::PolicyConflict)
        }
    }

    pub(super) fn local_erasure_sweep(
        &mut self,
        tags: &[&str],
        keep: &[ErasureReferenceV1],
        max: usize,
    ) -> usize {
        let candidates = self
            .erasure_retained_objects
            .iter()
            .filter(|(reference, tag)| tags.contains(&tag.as_str()) && !keep.contains(reference))
            .map(|(reference, _)| *reference)
            .take(max)
            .collect::<Vec<_>>();
        for reference in &candidates {
            self.erasure_retained_objects.remove(reference);
            self.erasure_evidence.remove(reference);
        }
        candidates.len()
    }

    /// Every retained object of `tag`, read from the object map itself, so
    /// each listed object has its bytes by construction: the retained index
    /// only selects which of those objects are candidates.
    pub(super) fn local_erasure_retained(
        &self,
        tag: &str,
        max: usize,
    ) -> Result<Vec<Vec<u8>>, ErasureErrorV1> {
        let objects = self
            .erasure_evidence
            .iter()
            .filter(|(reference, _)| {
                self.erasure_retained_objects
                    .get(*reference)
                    .is_some_and(|retained| retained == tag)
            })
            .map(|(_, bytes)| bytes.clone())
            .take(max.saturating_add(1))
            .collect::<Vec<_>>();
        if objects.len() > max {
            Err(ErasureErrorV1::ScopeInvalid)
        } else {
            Ok(objects)
        }
    }

    /// An address is retainable when it is free or already holds exactly
    /// these bytes.
    fn retainable(&self, object: &ErasureRetainedObjectV1) -> Result<(), ErasureErrorV1> {
        self.erasure_evidence
            .get(&object.reference())
            .is_none_or(|bytes| bytes.as_slice() == object.canonical_cbor())
            .then_some(())
            .ok_or(ErasureErrorV1::ProvenanceMissing)
    }

    /// Insert one checked object. Only a newly inserted object becomes a
    /// sweep candidate, so a coordinator object is never marked.
    fn insert_retained(&mut self, object: &ErasureRetainedObjectV1) -> ErasureReferenceV1 {
        let reference = object.reference();
        if let std::collections::btree_map::Entry::Vacant(entry) =
            self.erasure_evidence.entry(reference)
        {
            self.erasure_retained_objects
                .insert(reference, object.tag().to_owned());
            entry.insert(object.canonical_cbor().to_vec());
        }
        reference
    }

    /// Whether the key registry holds exactly `tombstone`.
    fn holds_tombstone(&self, tombstone: &KeyTombstoneV1) -> Result<(), ErasureErrorV1> {
        self.load_key_registry()
            .ok()
            .flatten()
            .and_then(|registry| registry.tombstone(tombstone.identity))
            .filter(|held| held == tombstone)
            .map(drop)
            .ok_or(ErasureErrorV1::KeyDestructionFailed)
    }

    fn complete_tombstone(
        &mut self,
        request: pos_core::KeyDestructionRequestV1,
        deletion_receipt: Hash,
    ) -> Result<(), ErasureErrorV1> {
        self.load_key_registry()
            .ok()
            .flatten()
            .and_then(|mut registry| {
                registry
                    .complete_key_destruction(request, deletion_receipt)
                    .ok()
                    .map(|_| registry)
            })
            .ok_or(ErasureErrorV1::KeyDestructionFailed)
            .and_then(|registry| {
                self.save_key_registry(&registry)
                    .ok()
                    .ok_or(ErasureErrorV1::KeyDestructionFailed)
            })
    }
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
    fn retaining_bytes_the_evidence_path_wrote_first_never_marks_them() -> Result<(), ErasureErrorV1>
    {
        let mut store = MemoryStore::new();
        let bytes = vec![0x82, 0x64, b'E', b'R', b'C', b'1', 0x01];
        let reference = ErasureRetainedObjectV1::new(&bytes, 1_024)?.reference();
        store.erasure_evidence.insert(reference, bytes.clone());
        assert_eq!(store.local_erasure_retain(&bytes, 1_024)?, reference);
        assert_eq!(store.local_erasure_sweep(&["ERC1"], &[], 16), 0);
        assert_eq!(store.erasure_evidence.get(&reference), Some(&bytes));
        Ok(())
    }

    /// An address that already holds other bytes is not retainable: the
    /// retain is refused and the held bytes stay as they were.
    #[test]
    fn retaining_over_an_address_holding_other_bytes_is_refused() -> Result<(), ErasureErrorV1> {
        let mut store = MemoryStore::new();
        let bytes = [0x82, 0x64, b'E', b'R', b'C', b'1', 0x01];
        let reference = ErasureRetainedObjectV1::new(&bytes, 1_024)?.reference();
        let held = vec![0x82, 0x64, b'E', b'R', b'C', b'1', 0x02];
        store.erasure_evidence.insert(reference, held.clone());
        assert_eq!(
            store.local_erasure_retain(&bytes, 1_024),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
        assert_eq!(store.erasure_evidence.get(&reference), Some(&held));
        assert!(store.erasure_retained_objects.is_empty());
        Ok(())
    }
}
