//! Allocation preflight for the existing `MemoryStore` validator-(b) read.

use std::collections::HashSet;

use pos_core::{Event, TimelineId};

use super::MemoryStore;
use crate::{
    fork_event_authority::AuthorityValidatorV1,
    fork_replay::{charge_registry, CanonicalSizeV1},
    ForkReplayAuthorityEvidenceV1, ForkReplayAuthorityReadErrorV1 as Error,
    ForkReplayAuthorityReadPortV1, ForkReplayReadBudgetV1, ForkReplayRequirementV1,
};

type ReadResult<T> = Result<T, Error>;

impl ForkReplayAuthorityReadPortV1 for MemoryStore {
    fn validate_fork_replay_authority(
        &self,
        requirement: &ForkReplayRequirementV1,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> ReadResult<ForkReplayAuthorityEvidenceV1> {
        self.preflight_replay_ancestry(requirement.child_timeline_id(), budget)?;
        self.preflight_replay_records(requirement, budget)?;
        let committed = self
            .read_committed_as(
                requirement.child_timeline_id(),
                requirement.publication_logical_head().as_u64(),
                AuthorityValidatorV1::CodeTwoAware,
            )
            .map_err(|_| Error::CorruptAuthority)?;
        budget.check_time()?;
        ForkReplayAuthorityEvidenceV1::from_committed(*requirement, &committed, budget)
    }
}

impl MemoryStore {
    /// Bound each chain and all Event payload copies before the existing reader
    /// constructs its chain/suffix collections. No metadata is cloned here.
    fn preflight_replay_ancestry(
        &self,
        child: TimelineId,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> ReadResult<()> {
        let mut visited = HashSet::new();
        let mut next = Some(child);
        let mut depth = 0;
        while let Some(timeline) = next {
            budget.charge_node(depth)?;
            if !visited.insert(timeline) {
                return Err(Error::CorruptAuthority);
            }
            let state = self.timelines.get(&timeline).ok_or(Error::Unavailable)?;
            for event in &state.events {
                budget.charge_rows(1)?;
                charge_event(event, budget)?;
            }
            next = state.timeline.meta.fork_point.map(|(parent, _)| parent);
            depth += 1;
        }
        Ok(())
    }

    /// Indexed records belong only to this selected publication. Broader scans
    /// are retained only where validator (b) genuinely checks orphans/duplicates.
    fn preflight_replay_records(&self, requirement: &ForkReplayRequirementV1, budget: &mut ForkReplayReadBudgetV1<'_>) -> ReadResult<()> {
        let child = requirement.child_timeline_id();
        let local = self.fork_admissions.get(&child);
        charge_records(local.into_iter(), budget)?;
        charge_records(self.imported_fork_admissions.get(&child).into_iter(), budget)?;
        if local.is_some() {
            for binding in self.fork_principal_owner_bindings.values() {
                budget.charge_rows(1)?;
                // The local validator searches this map by its FAR1 digest.
                budget.charge_bytes(binding.canonical_size())?;
            }
        }
        if let Some(table) = self.fork_classifier_tables.get(&child) {
            charge_records(std::iter::once(table), budget)?;
            charge_records(self.imported_fork_classifier_sources.get(&table.input().source_configuration_revision_digest).into_iter(), budget)?;
            let key = (table.input().room_revision_descriptor_hash, table.input().registrar_identifier.clone());
            charge_records(self.fork_classifier_sources.get(&key).into_iter(), budget)?;
        }
        for registration in self.fork_classifier_registrations.values() {
            budget.charge_rows(1)?;
            if registration.input().child_timeline_id == child {
                budget.charge_bytes(registration.canonical_size())?;
            }
        }
        charge_records(self.fork_append_operations.values(), budget)?;
        charge_records(self.fork_event_origins.values(), budget)?;
        charge_records(self.fork_intervention_admissions.values(), budget)?;
        if let Some(binding) = self.fork_publication_bindings.get(&(child, requirement.publication_logical_head().as_u64())) {
            charge_records(std::iter::once(binding), budget)?;
            let input = binding.input();
            charge_records(self.fork_publication_operations.get(&input.operation_id).into_iter(), budget)?;
            charge_records(self.imported_fork_publication_operations.get(&input.operation_id).into_iter(), budget)?;
            charge_records(self.fork_publication_artifacts.get(&input.signed_manifest_record_id).into_iter(), budget)?;
        }
        for row in self.imported_fork_attributions.values() {
            budget.charge_rows(1)?;
            if row.child == child {
                budget.charge_bytes(row.stored.admission_bytes.len())?;
                // The preflight's own canonical decoder is charged too.
                budget.charge_bytes(row.stored.admission_bytes.len())?;
                let admission = pos_core::ImportedForkAttributionAdmissionV1::from_canonical_cbor(&row.stored.admission_bytes).map_err(|_| Error::CorruptAuthority)?;
                if let Some(evidence) = self.imported_fork_key_evidence.get(&admission.input().import_operation_id) {
                    charge_records(std::iter::once(&evidence.record), budget)?;
                    charge_records(evidence.tombstone.iter(), budget)?;
                }
            }
        }
        if let Some(registry) = &self.key_registry {
            charge_registry(registry, budget)?;
        }
        budget.check_time()
    }
}

fn charge_records<'record, T: CanonicalSizeV1 + 'record>(
    records: impl Iterator<Item = &'record T>,
    budget: &mut ForkReplayReadBudgetV1<'_>,
) -> ReadResult<()> {
    for record in records {
        budget.charge_rows(1)?;
        budget.charge_bytes(record.canonical_size())?;
    }
    Ok(())
}

fn charge_event(event: &Event, budget: &mut ForkReplayReadBudgetV1<'_>) -> ReadResult<()> {
    budget.charge_bytes(event.payload.as_slice().len())?;
    budget.charge_bytes(event.event_type.as_str().len())
}
