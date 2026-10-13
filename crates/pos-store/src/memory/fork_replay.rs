//! Allocation preflight for the existing `MemoryStore` validator-(b) read.

use super::MemoryStore;
use crate::{
    fork_event_authority::AuthorityValidatorV1,
    fork_replay::{charge_registry, CanonicalSizeV1, NativeReadContextV1},
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
        self.preflight_replay_records(requirement, budget)?;
        let committed = self.read_committed_with_context(
            requirement.child_timeline_id(),
            requirement.publication_logical_head().as_u64(),
            AuthorityValidatorV1::CodeTwoAware,
            &mut NativeReadContextV1::protected(budget),
        );
        // Preserve the latched budget error over native error translation.
        budget.check_time()?;
        let committed = committed.map_err(|_| Error::CorruptAuthority)?;
        ForkReplayAuthorityEvidenceV1::from_committed(*requirement, &committed, budget)
    }
}

impl MemoryStore {
    /// Indexed records belong only to this selected publication. Broader scans
    /// are retained only where validator (b) genuinely checks orphans/duplicates.
    fn preflight_replay_records(
        &self,
        requirement: &ForkReplayRequirementV1,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> ReadResult<()> {
        let child = requirement.child_timeline_id();
        if let Some(binding) = self
            .fork_publication_bindings
            .get(&(child, requirement.publication_logical_head().as_u64()))
        {
            charge_records(std::iter::once(binding), budget)?;
            let input = binding.input();
            charge_records(
                self.fork_publication_operations
                    .get(&input.operation_id)
                    .into_iter(),
                budget,
            )?;
            charge_records(
                self.imported_fork_publication_operations
                    .get(&input.operation_id)
                    .into_iter(),
                budget,
            )?;
            // The Memory trusted read borrows FPA1, including its cached FSM1;
            // no artifact clone or FPA1 encoding is materialized here.
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
        budget.charge_canonical(record.canonical_size())?;
    }
    Ok(())
}
