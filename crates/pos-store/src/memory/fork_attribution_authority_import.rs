//! `MemoryStore` adapter for the ADR-105 `FAE1` authority import.
//!
//! Records without an origin member (`EOR1`, `FIA1`, `FCT1`, `FCR1`, `FOP1`,
//! `FPB1`, `FPA1`) are installed in the same per-child maps as local rows.
//! The code-2 `POB1`, `FAR1`, and `FPO1` have no local projection that could
//! carry their origin, so they live in separate imported maps, as do the
//! imported `FCS1` custody store, the `IKR1`/`IKT1` evidence, and the `IFA1`
//! admission with its exact `FAE1` bytes. Every local trusted read
//! therefore stays closed to code 2 until #519.
//!
//! The adapter checks every occupancy key first and only then stages the
//! child Timeline. Staging is the one fallible mutation: a later failure
//! deletes the staged child, and every row insert is infallible.

use std::collections::HashSet;

use pos_core::{
    store::{EventStore, TimelineExport},
    EventId, EventOriginRecordV1, ForkAppendOperationV1, ForkClassifierRegistrationV1,
    ForkClassifierSourceV1, ForkClassifierTableV1, ForkInterventionAdmissionV1,
    ForkPublicationArtifactV1, ForkPublicationBindingV1, Hash, ImportedForkAdmissionRecordV1,
    ImportedForkPublicationOperationV1, ImportedKeyRecordV1, ImportedKeyTombstoneV1,
    ImportedPrincipalOwnerBindingV1, TimelineId,
};

use super::MemoryStore;
use crate::fork_attribution_authority_import::{
    run_import, ForkAttributionAuthorityImportErrorV1 as ImportError,
    ForkAttributionAuthorityImportPortV1, ForkAttributionAuthorityImportReceiptV1,
    ForkAttributionAuthorityImportRequestV1, ImportBackendV1, InstallPlanV1, InstalledRowsV1,
    StoredImportV1,
};

/// The committed admission row of one import.
pub(super) struct ImportedAttributionRowV1 {
    child: TimelineId,
    admission_bytes: Vec<u8>,
    envelope_bytes: Vec<u8>,
    envelope_digest: Hash,
}

/// The imported `IKR1` and optional `IKT1` of one import.
pub(super) struct ImportedKeyEvidenceV1 {
    record: ImportedKeyRecordV1,
    tombstone: Option<ImportedKeyTombstoneV1>,
}

impl ForkAttributionAuthorityImportPortV1 for MemoryStore {
    fn import_verified(
        &mut self,
        request: &ForkAttributionAuthorityImportRequestV1<'_>,
    ) -> Result<ForkAttributionAuthorityImportReceiptV1, ImportError> {
        run_import(self, request)
    }
}

impl MemoryStore {
    /// Whether any key naming the child Fork is held.
    fn import_child_held(&self, child: TimelineId) -> bool {
        self.timelines.contains_key(&child)
            || self.fork_admissions.contains_key(&child)
            || self.imported_fork_admissions.contains_key(&child)
            || self.fork_classifier_tables.contains_key(&child)
            || self.import_child_rows_held(child)
    }

    /// Whether a registration, append operation, or admission row names the
    /// child Fork.
    fn import_child_rows_held(&self, child: TimelineId) -> bool {
        self.fork_classifier_registrations
            .values()
            .any(|record| record.input().child_timeline_id == child)
            || self
                .fork_append_operations
                .values()
                .any(|record| record.input().child_timeline_id == child)
            || self
                .imported_fork_attributions
                .values()
                .any(|row| row.child == child)
    }

    /// Whether the `POB1` operation or Principal key is held.
    fn import_binding_held(&self, plan: &InstallPlanV1<'_>) -> bool {
        let binding = plan.closure().principal_owner_binding().input();
        self.imported_fork_principal_owner_bindings
            .contains_key(&binding.operation_id)
            || self
                .imported_fork_principal_owner_bindings
                .values()
                .any(|record| record.input().principal_digest == binding.principal_digest)
            || self
                .fork_principal_owner_bindings
                .contains_key(&binding.principal_digest)
            || self
                .fork_principal_owner_bindings
                .values()
                .any(|record| record.input().operation_id == binding.operation_id)
    }

    /// Whether an `FCR1` operation, or an Event's `FOP1`, `EOR1`, or `FIA1`,
    /// is held.
    fn import_event_rows_held(&self, plan: &InstallPlanV1<'_>) -> bool {
        let closure = plan.closure();
        let held_events = self
            .fork_append_operations
            .values()
            .map(|record| record.input().event_id)
            .collect::<HashSet<_>>();
        closure
            .classifier()
            .is_some_and(|graph| self.import_registration_held(&graph.registration))
            || closure
                .append_operations()
                .iter()
                .any(|record| self.import_operation_held(record))
            || plan
                .event_ids()
                .iter()
                .any(|event_id| self.import_event_held(*event_id, &held_events))
    }

    fn import_registration_held(&self, record: &ForkClassifierRegistrationV1) -> bool {
        let operation_id = record.input().operation_id;
        self.fork_classifier_registrations.contains_key(&operation_id)
    }

    fn import_operation_held(&self, record: &ForkAppendOperationV1) -> bool {
        let operation_id = record.input().operation_id;
        self.fork_append_operations.contains_key(&operation_id)
    }

    fn import_event_held(&self, event_id: EventId, held_events: &HashSet<EventId>) -> bool {
        self.event_ids.contains(&event_id)
            || held_events.contains(&event_id)
            || self.fork_event_origins.contains_key(&event_id)
            || self.fork_intervention_admissions.contains_key(&event_id)
    }

    /// Whether the publication Fork and head, operation, or record key is
    /// held by a local or imported row.
    fn import_publication_held(&self, plan: &InstallPlanV1<'_>) -> bool {
        let closure = plan.closure();
        let operation = closure.publication_operation().fields();
        let record_id = operation.signed_manifest_record_id;
        let operation_id = operation.operation_id;
        self.fork_publication_bindings
            .contains_key(&(plan.child(), plan.final_head()))
            || self
                .fork_publication_operations
                .contains_key(&operation_id)
            || self
                .imported_fork_publication_operations
                .contains_key(&operation_id)
            || self.fork_publication_artifacts.contains_key(&record_id)
            || self
                .fork_publication_operations
                .values()
                .any(|record| record.input().signed_manifest_record_id == record_id)
            || self
                .imported_fork_publication_operations
                .values()
                .any(|record| record.fields().signed_manifest_record_id == record_id)
            || self
                .fork_publication_bindings
                .values()
                .any(|record| record.input().operation_id == operation_id)
            || self
                .fork_publication_artifacts
                .values()
                .any(|record| record.input().operation_id == operation_id)
    }

    /// Require a referenced imported `FCS1` row to be exactly the imported
    /// bytes: an identical row is reused, and any other row under the same
    /// digest is corrupt.
    fn import_source_is_reusable(&self, plan: &InstallPlanV1<'_>) -> bool {
        plan.closure().classifier().is_none_or(|graph| {
            self.imported_fork_classifier_sources
                .get(&graph.source.digest())
                .is_none_or(|stored| *stored == graph.source)
        })
    }

    fn insert_imported_rows(&mut self, plan: &InstallPlanV1<'_>) {
        let closure = plan.closure();
        let child = plan.child();
        let binding = closure.principal_owner_binding();
        self.imported_fork_principal_owner_bindings
            .insert(binding.input().operation_id, binding.clone());
        self.imported_fork_admissions
            .insert(child, closure.fork_admission().clone());
        let operation = closure.publication_operation();
        self.imported_fork_publication_operations
            .insert(operation.fields().operation_id, operation.clone());
        self.imported_fork_key_evidence.insert(
            plan.import_operation_id(),
            ImportedKeyEvidenceV1 {
                record: plan.key_record(),
                tombstone: plan.key_tombstone(),
            },
        );
    }

    fn insert_event_rows(&mut self, plan: &InstallPlanV1<'_>) {
        let closure = plan.closure();
        for record in closure.event_origins() {
            self.fork_event_origins
                .insert(record.input().event_id, record.clone());
        }
        for record in closure.intervention_admissions() {
            self.fork_intervention_admissions
                .insert(record.input().event_id, record.clone());
        }
        for record in closure.append_operations() {
            self.fork_append_operations
                .insert(record.input().operation_id, record.clone());
        }
    }

    fn insert_classifier_rows(&mut self, plan: &InstallPlanV1<'_>) {
        if let Some(graph) = plan.closure().classifier() {
            self.imported_fork_classifier_sources
                .entry(graph.source.digest())
                .or_insert_with(|| graph.source.clone());
            self.fork_classifier_tables
                .insert(plan.child(), graph.table.clone());
            self.fork_classifier_registrations
                .insert(graph.registration.input().operation_id, graph.registration.clone());
        }
    }

    fn insert_publication_rows(&mut self, plan: &InstallPlanV1<'_>) {
        let closure = plan.closure();
        let artifact = closure.publication_artifact();
        self.fork_publication_bindings.insert(
            (plan.child(), plan.final_head()),
            closure.publication_binding().clone(),
        );
        self.fork_publication_artifacts
            .insert(artifact.input().signed_manifest_record_id, artifact.clone());
        self.imported_fork_attributions.insert(
            plan.import_operation_id(),
            ImportedAttributionRowV1 {
                child: plan.child(),
                admission_bytes: plan.admission.to_canonical_cbor(),
                envelope_bytes: plan.prepared.bytes.clone(),
                envelope_digest: plan.admission.input().full_envelope_digest,
            },
        );
    }
}

impl ImportBackendV1 for MemoryStore {
    fn read_stored_import(
        &self,
        import_operation_id: Hash,
    ) -> Result<Option<StoredImportV1>, ImportError> {
        Ok(self
            .imported_fork_attributions
            .get(&import_operation_id)
            .map(|row| StoredImportV1 {
                admission_bytes: row.admission_bytes.clone(),
                envelope_bytes: row.envelope_bytes.clone(),
                envelope_digest: row.envelope_digest,
            }))
    }

    fn has_key_evidence(&self, import_operation_id: Hash) -> Result<bool, ImportError> {
        Ok(self
            .imported_fork_key_evidence
            .contains_key(&import_operation_id))
    }

    fn read_installed(&self, plan: &InstallPlanV1<'_>) -> Result<InstalledRowsV1, ImportError> {
        let closure = plan.closure();
        let child = plan.child();
        let evidence = self
            .imported_fork_key_evidence
            .get(&plan.import_operation_id());
        let mut operations = self
            .fork_append_operations
            .values()
            .filter(|record| record.input().child_timeline_id == child)
            .collect::<Vec<_>>();
        operations.sort_by_key(|record| record.input().logical_seq);
        Ok(InstalledRowsV1 {
            binding: self
                .imported_fork_principal_owner_bindings
                .get(&closure.principal_owner_binding().input().operation_id)
                .map(ImportedPrincipalOwnerBindingV1::to_canonical_cbor),
            admission: self
                .imported_fork_admissions
                .get(&child)
                .map(ImportedForkAdmissionRecordV1::to_canonical_cbor),
            origins: plan
                .event_ids()
                .iter()
                .map(|event_id| {
                    self.fork_event_origins
                        .get(event_id)
                        .map(EventOriginRecordV1::to_canonical_cbor)
                })
                .collect(),
            interventions: plan
                .event_ids()
                .iter()
                .map(|event_id| {
                    self.fork_intervention_admissions
                        .get(event_id)
                        .map(ForkInterventionAdmissionV1::to_canonical_cbor)
                })
                .collect(),
            source: closure
                .classifier()
                .and_then(|graph| {
                    self.imported_fork_classifier_sources
                        .get(&graph.source.digest())
                })
                .map(ForkClassifierSourceV1::to_canonical_cbor),
            table: self
                .fork_classifier_tables
                .get(&child)
                .map(ForkClassifierTableV1::to_canonical_cbor),
            registration: self
                .fork_classifier_registrations
                .values()
                .find(|record| record.input().child_timeline_id == child)
                .map(ForkClassifierRegistrationV1::to_canonical_cbor),
            operations: operations
                .into_iter()
                .map(ForkAppendOperationV1::to_canonical_cbor)
                .collect(),
            publication_operation: self
                .imported_fork_publication_operations
                .get(&closure.publication_operation().fields().operation_id)
                .map(ImportedForkPublicationOperationV1::to_canonical_cbor),
            publication_binding: self
                .fork_publication_bindings
                .get(&(child, plan.final_head()))
                .map(ForkPublicationBindingV1::to_canonical_cbor),
            publication_artifact: self
                .fork_publication_artifacts
                .get(&closure.publication_artifact().input().signed_manifest_record_id)
                .map(ForkPublicationArtifactV1::to_canonical_cbor),
            key_record: evidence.map(|row| row.record.to_canonical_cbor()),
            key_tombstone: evidence
                .and_then(|row| row.tombstone.as_ref())
                .map(ImportedKeyTombstoneV1::to_canonical_cbor),
        })
    }

    fn occupied(&self, plan: &InstallPlanV1<'_>) -> Result<bool, ImportError> {
        if !self.import_source_is_reusable(plan) {
            return Err(ImportError::CorruptAuthority);
        }
        Ok(self.import_child_held(plan.child())
            || self.import_binding_held(plan)
            || self.import_event_rows_held(plan)
            || self.import_publication_held(plan))
    }

    fn stage_child(&mut self, export: &TimelineExport) -> Result<(), ImportError> {
        self.import_committed(export.timeline.meta.clone(), &export.events)?;
        Ok(())
    }

    fn install_rows(&mut self, plan: &InstallPlanV1<'_>) -> Result<(), ImportError> {
        self.insert_imported_rows(plan);
        self.insert_event_rows(plan);
        self.insert_classifier_rows(plan);
        self.insert_publication_rows(plan);
        Ok(())
    }

    fn atomically<T, F>(&mut self, child: TimelineId, body: F) -> Result<T, ImportError>
    where
        F: FnOnce(&mut Self) -> Result<T, ImportError>,
    {
        let existed = self.timelines.contains_key(&child);
        let result = body(self);
        if result.is_err()
            && !existed
            && self.timelines.contains_key(&child)
            && self.delete_timeline(child).is_err()
        {
            return Err(ImportError::StorageIndeterminate);
        }
        result
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "../../tests/support/fae1_fixture.rs"]
mod fae1_fixture;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use pos_core::{
        ForkAdmissionRecordV1, ForkAppendOperationInputV1, ForkAttributionImportClosureV1,
        ForkClassifierRegistrationInputV1, ForkClassifierSourceInputV1, ForkPublicationOperationV1,
        PrincipalOwnerBindingV1,
    };

    use super::fae1_fixture::{
        hash, pin_policy, request_for, Built, Fallible, Shape, Spec, World, PARENT_CUT,
    };
    use super::*;

    type Outcome = Result<ForkAttributionAuthorityImportReceiptV1, ImportError>;

    const CORRUPT: ImportError = ImportError::CorruptAuthority;

    /// The keys of one committed import.
    struct Keys {
        child: TimelineId,
        import_operation: Hash,
        binding_operation: Hash,
        principal: Hash,
        registration_operation: Hash,
        operation: Hash,
        event: EventId,
        publication_operation: Hash,
        record_id: Hash,
        head: u64,
        source_digest: Hash,
    }

    /// One import, committed in a `MemoryStore`.
    struct Imported {
        world: World,
        built: Built,
        store: MemoryStore,
        closure: ForkAttributionImportClosureV1,
        keys: Keys,
    }

    impl Imported {
        fn retry(&mut self) -> Outcome {
            self.store
                .import_verified(&request_for(&self.world, &self.built))
        }
    }

    fn first<T>(items: &[T]) -> Fallible<&T> {
        items.first().ok_or_else(|| "empty list".into())
    }

    fn keys(
        world: &World,
        built: &Built,
        closure: &ForkAttributionImportClosureV1,
    ) -> Fallible<Keys> {
        let binding = closure.principal_owner_binding().input();
        let graph = closure.classifier().ok_or("no classifier")?;
        let publication = closure.publication_operation().fields();
        Ok(Keys {
            child: world.child_at(0)?.id,
            import_operation: built.envelope.unsigned().input().import_operation_id,
            binding_operation: binding.operation_id,
            principal: binding.principal_digest,
            registration_operation: graph.registration.input().operation_id,
            operation: first(closure.append_operations())?.input().operation_id,
            event: first(closure.event_origins())?.input().event_id,
            publication_operation: publication.operation_id,
            record_id: publication.signed_manifest_record_id,
            head: PARENT_CUT + 4,
            source_digest: graph.source.digest(),
        })
    }

    fn prepared(world: &World, built: &Built) -> Fallible<MemoryStore> {
        let mut store = MemoryStore::new();
        world.seed_destination(&mut store)?;
        pin_policy(&mut store, &built.policy)?;
        Ok(store)
    }

    fn imported() -> Fallible<Imported> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        let mut store = prepared(&world, &built)?;
        store.import_verified(&request_for(&world, &built))?;
        let closure = ForkAttributionImportClosureV1::validate(&built.envelope)?;
        let keys = keys(&world, &built, &closure)?;
        Ok(Imported {
            world,
            built,
            store,
            closure,
            keys,
        })
    }

    /// Tamper a committed import, then retry it.
    fn tampered(tamper: impl FnOnce(&mut Imported) -> Fallible<()>) -> Fallible<Outcome> {
        let mut state = imported()?;
        tamper(&mut state)?;
        Ok(state.retry())
    }

    #[test]
    fn the_original_receipt_survives_every_retry() -> Fallible<()> {
        let mut state = imported()?;
        let original = state.retry()?;
        assert_eq!(
            original.admission.input().child_timeline_id,
            state.keys.child
        );
        assert_eq!(state.retry(), Ok(original));
        Ok(())
    }

    #[test]
    fn a_missing_installed_row_is_corrupt() -> Fallible<()> {
        let tampers: &[fn(&mut Imported) -> Fallible<()>] = &[
            |s| {
                s.store.fork_append_operations.remove(&s.keys.operation);
                Ok(())
            },
            |s| {
                s.store.fork_classifier_tables.remove(&s.keys.child);
                Ok(())
            },
            |s| {
                let operation = s.keys.registration_operation;
                s.store.fork_classifier_registrations.remove(&operation);
                Ok(())
            },
            |s| {
                s.store.fork_event_origins.remove(&s.keys.event);
                Ok(())
            },
            |s| {
                s.store.imported_fork_admissions.remove(&s.keys.child);
                Ok(())
            },
            |s| {
                let operation = s.keys.binding_operation;
                s.store
                    .imported_fork_principal_owner_bindings
                    .remove(&operation);
                Ok(())
            },
            |s| {
                let operation = s.keys.publication_operation;
                s.store
                    .imported_fork_publication_operations
                    .remove(&operation);
                Ok(())
            },
            |s| {
                let key = (s.keys.child, s.keys.head);
                s.store.fork_publication_bindings.remove(&key);
                Ok(())
            },
            |s| {
                s.store.fork_publication_artifacts.remove(&s.keys.record_id);
                Ok(())
            },
            |s| {
                s.store.imported_fork_classifier_sources.clear();
                Ok(())
            },
            |s| {
                let operation = s.keys.import_operation;
                s.store.imported_fork_key_evidence.remove(&operation);
                Ok(())
            },
            |s| {
                // An orphan: the key evidence outlives its admission row.
                let operation = s.keys.import_operation;
                s.store.imported_fork_attributions.remove(&operation);
                Ok(())
            },
        ];
        for tamper in tampers {
            assert_eq!(tampered(*tamper)?, Err(CORRUPT));
        }
        Ok(())
    }

    #[test]
    fn an_extra_row_or_a_missing_child_is_corrupt() -> Fallible<()> {
        let tampers: &[fn(&mut Imported) -> Fallible<()>] = &[
            |s| {
                // An extra `FIA1` where the first Event is host-internal.
                let record = first(s.closure.intervention_admissions())?.clone();
                s.store
                    .fork_intervention_admissions
                    .insert(s.keys.event, record);
                Ok(())
            },
            |s| {
                // An extra `FOP1` for the child under another operation.
                let operation = first(s.closure.append_operations())?;
                let extra = ForkAppendOperationV1::new(ForkAppendOperationInputV1 {
                    operation_id: hash(0xee),
                    ..operation.input().clone()
                })?;
                s.store.fork_append_operations.insert(hash(0xee), extra);
                Ok(())
            },
            |s| {
                s.store.timelines.remove(&s.keys.child);
                Ok(())
            },
            |s| {
                let state = s
                    .store
                    .timelines
                    .get_mut(&s.keys.child)
                    .ok_or("no child state")?;
                state.events.truncate(3);
                Ok(())
            },
        ];
        for tamper in tampers {
            assert_eq!(tampered(*tamper)?, Err(CORRUPT));
        }
        Ok(())
    }

    #[test]
    fn an_altered_stored_row_or_policy_is_corrupt() -> Fallible<()> {
        let alterations: &[fn(&mut Imported) -> Fallible<()>] = &[
            |s| {
                let operation = s.keys.import_operation;
                let row = s.store.imported_fork_attributions.get_mut(&operation);
                let row = row.ok_or("no row")?;
                row.envelope_bytes.truncate(8);
                Ok(())
            },
            |s| {
                let operation = s.keys.import_operation;
                let row = s.store.imported_fork_attributions.get_mut(&operation);
                let row = row.ok_or("no row")?;
                row.admission_bytes.truncate(8);
                Ok(())
            },
            |s| {
                let operation = s.keys.import_operation;
                let row = s.store.imported_fork_attributions.get_mut(&operation);
                let row = row.ok_or("no row")?;
                row.envelope_digest = hash(0x01);
                Ok(())
            },
            |s| {
                let graph = s.closure.classifier().ok_or("no classifier")?;
                let other = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
                    registrar_identifier: "registrar-b".to_owned(),
                    ..graph.source.input().clone()
                })?;
                let digest = s.keys.source_digest;
                s.store.imported_fork_classifier_sources.insert(digest, other);
                Ok(())
            },
            |s| {
                let entry = s
                    .store
                    .fork_attribution_issuer_policies
                    .first_mut()
                    .ok_or("no policy")?;
                entry.0 = hash(0x02);
                Ok(())
            },
        ];
        for alteration in alterations {
            assert_eq!(tampered(*alteration)?, Err(CORRUPT));
        }
        Ok(())
    }

    #[test]
    fn a_tampered_shared_source_blocks_a_second_import() -> Fallible<()> {
        let mut world = World::new(Shape::Mixed, false)?;
        world.add_child(Shape::Mixed)?;
        let first = world.build(&Spec::default())?;
        let second = world.build(&Spec::distinct(1))?;
        let mut store = prepared(&world, &first)?;
        store.import_verified(&request_for(&world, &first))?;
        let closure = ForkAttributionImportClosureV1::validate(&first.envelope)?;
        let graph = closure.classifier().ok_or("no classifier")?;
        let other = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
            registrar_identifier: "registrar-b".to_owned(),
            ..graph.source.input().clone()
        })?;
        store
            .imported_fork_classifier_sources
            .insert(graph.source.digest(), other);
        let outcome = store.import_verified(&request_for(&world, &second));
        assert_eq!(outcome, Err(CORRUPT));
        assert_eq!(store.get_timeline(world.child_at(1)?.id)?, None);
        Ok(())
    }

    #[test]
    fn local_classifier_custody_is_never_read_or_changed() -> Fallible<()> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        let mut store = prepared(&world, &built)?;
        let closure = ForkAttributionImportClosureV1::validate(&built.envelope)?;
        let graph = closure.classifier().ok_or("no classifier")?;
        let source = graph.source.input();
        let local = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
            routes: Vec::new(),
            ..source.clone()
        })?;
        let key = (
            source.room_revision_descriptor_hash,
            source.registrar_identifier.clone(),
        );
        store.fork_classifier_sources.insert(key.clone(), local.clone());
        store.import_verified(&request_for(&world, &built))?;
        assert_eq!(store.fork_classifier_sources.get(&key), Some(&local));
        assert_eq!(store.fork_classifier_sources.len(), 1);
        assert_eq!(store.imported_fork_classifier_sources.len(), 1);
        Ok(())
    }

    type Occupation = fn(&mut MemoryStore, &ForkAttributionImportClosureV1, &Keys) -> Fallible<()>;

    /// Occupy one key of the default import with a local or foreign row, then
    /// import it.
    fn occupy_then_import(occupy: Occupation) -> Fallible<()> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        let closure = ForkAttributionImportClosureV1::validate(&built.envelope)?;
        let keys = keys(&world, &built, &closure)?;
        let mut store = prepared(&world, &built)?;
        occupy(&mut store, &closure, &keys)?;
        let outcome = store.import_verified(&request_for(&world, &built));
        assert_eq!(outcome, Err(ImportError::Conflict));
        assert!(store.imported_fork_attributions.is_empty());
        assert!(store.imported_fork_key_evidence.is_empty());
        Ok(())
    }

    #[test]
    fn every_occupied_child_key_is_a_conflict() -> Fallible<()> {
        let occupations: &[Occupation] = &[
            |store, closure, keys| {
                let record = ForkAdmissionRecordV1::new(closure.fork_admission().fields().clone())?;
                store.fork_admissions.insert(keys.child, record);
                Ok(())
            },
            |store, closure, keys| {
                let graph = closure.classifier().ok_or("no classifier")?;
                store
                    .fork_classifier_tables
                    .insert(keys.child, graph.table.clone());
                Ok(())
            },
            |store, closure, keys| {
                let graph = closure.classifier().ok_or("no classifier")?;
                store
                    .fork_classifier_registrations
                    .insert(hash(0xee), graph.registration.clone());
                Ok(())
            },
            |store, closure, keys| {
                let operation = first(closure.append_operations())?;
                store
                    .fork_append_operations
                    .insert(hash(0xee), operation.clone());
                Ok(())
            },
            |store, closure, keys| {
                let graph = closure.classifier().ok_or("no classifier")?;
                let other = ForkClassifierRegistrationV1::new(ForkClassifierRegistrationInputV1 {
                    child_timeline_id: TimelineId::new(),
                    ..graph.registration.input().clone()
                })?;
                store
                    .fork_classifier_registrations
                    .insert(keys.registration_operation, other);
                Ok(())
            },
            |store, closure, keys| {
                let operation = first(closure.append_operations())?;
                let other = ForkAppendOperationV1::new(ForkAppendOperationInputV1 {
                    child_timeline_id: TimelineId::new(),
                    ..operation.input().clone()
                })?;
                store.fork_append_operations.insert(keys.operation, other);
                Ok(())
            },
            |store, closure, keys| {
                let operation = first(closure.append_operations())?;
                let other = ForkAppendOperationV1::new(ForkAppendOperationInputV1 {
                    child_timeline_id: TimelineId::new(),
                    operation_id: hash(0xee),
                    ..operation.input().clone()
                })?;
                store.fork_append_operations.insert(hash(0xee), other);
                Ok(())
            },
        ];
        for occupation in occupations {
            occupy_then_import(*occupation)?;
        }
        Ok(())
    }

    #[test]
    fn every_occupied_event_and_binding_key_is_a_conflict() -> Fallible<()> {
        let occupations: &[Occupation] = &[
            |store, closure, keys| {
                let record = first(closure.event_origins())?;
                store.fork_event_origins.insert(keys.event, record.clone());
                Ok(())
            },
            |store, closure, keys| {
                let record = first(closure.intervention_admissions())?;
                store
                    .fork_intervention_admissions
                    .insert(keys.event, record.clone());
                Ok(())
            },
            |store, closure, keys| {
                store.event_ids.insert(keys.event);
                Ok(())
            },
            |store, closure, keys| {
                let record = closure.principal_owner_binding();
                store
                    .imported_fork_principal_owner_bindings
                    .insert(hash(0xee), record.clone());
                Ok(())
            },
            |store, closure, keys| {
                let record = PrincipalOwnerBindingV1::new(
                    closure.principal_owner_binding().input().clone(),
                )?;
                store
                    .fork_principal_owner_bindings
                    .insert(keys.principal, record.clone());
                store
                    .fork_principal_owner_bindings
                    .insert(hash(0xee), record);
                Ok(())
            },
        ];
        for occupation in occupations {
            occupy_then_import(*occupation)?;
        }
        Ok(())
    }

    #[test]
    fn every_occupied_publication_key_is_a_conflict() -> Fallible<()> {
        let occupations: &[Occupation] = &[
            |store, closure, keys| {
                let key = (keys.child, keys.head);
                store
                    .fork_publication_bindings
                    .insert(key, closure.publication_binding().clone());
                Ok(())
            },
            |store, closure, keys| {
                let record = ForkPublicationOperationV1::new(
                    closure.publication_operation().fields().clone(),
                )?;
                store
                    .fork_publication_operations
                    .insert(keys.publication_operation, record.clone());
                store.fork_publication_operations.insert(hash(0xee), record);
                Ok(())
            },
            |store, closure, keys| {
                let record = closure.publication_operation();
                store
                    .imported_fork_publication_operations
                    .insert(keys.publication_operation, record.clone());
                store
                    .imported_fork_publication_operations
                    .insert(hash(0xee), record.clone());
                Ok(())
            },
            |store, closure, keys| {
                let record = closure.publication_artifact();
                store
                    .fork_publication_artifacts
                    .insert(keys.record_id, record.clone());
                store.fork_publication_artifacts.insert(hash(0xee), record.clone());
                Ok(())
            },
            |store, closure, keys| {
                let key = (TimelineId::new(), 1);
                store
                    .fork_publication_bindings
                    .insert(key, closure.publication_binding().clone());
                Ok(())
            },
        ];
        for occupation in occupations {
            occupy_then_import(*occupation)?;
        }
        Ok(())
    }

    #[test]
    fn a_failed_delete_after_a_range_failure_is_indeterminate() -> Fallible<()> {
        let world = World::new(Shape::Mixed, false)?;
        let wrong = world.build(&Spec {
            final_hash: Some(hash(0x99)),
            ..Spec::default()
        })?;
        let right = world.build(&Spec::default())?;
        let mut store = prepared(&world, &right)?;
        assert_eq!(
            store.import_verified(&request_for(&world, &wrong)),
            Err(ImportError::InvalidRangeEvidence)
        );
        assert_eq!(store.get_timeline(world.child_at(0)?.id)?, None);
        super::super::fail_next_visible_delete_for_test();
        assert_eq!(
            store.import_verified(&request_for(&world, &wrong)),
            Err(ImportError::StorageIndeterminate)
        );
        Ok(())
    }
}
