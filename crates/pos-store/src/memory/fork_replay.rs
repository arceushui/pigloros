//! Bounded bridge into the existing `MemoryStore` validator-(b) implementation.

use super::MemoryStore;
use crate::{
    fork_event_authority::AuthorityValidatorV1, fork_replay::NativeReadContextV1,
    ForkReplayAuthorityEvidenceV1, ForkReplayAuthorityReadErrorV1 as Error,
    ForkReplayAuthorityReadPortV1, ForkReplayReadBudgetV1, ForkReplayRequirementV1,
};

type ReadResult<T> = Result<T, Error>;

impl ForkReplayAuthorityReadPortV1 for MemoryStore {
    fn read_fork_replay_lineage_node(
        &self,
        timeline_id: pos_core::TimelineId,
        depth: usize,
        effective_max_fork_depth: usize,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> Result<Option<crate::ForkReplayLineageNodeV1>, crate::ForkReplayLineageReadErrorV1>
    {
        let mut context = crate::fork_replay::lineage::LineageReadContextV1::new(
            budget,
            effective_max_fork_depth,
        )?;
        crate::fork_replay::lineage::read_visible_lineage(
            timeline_id,
            depth,
            &mut context,
            |member, visited, context| self.read_lineage_member(member, visited, context),
        )
    }

    fn validate_fork_replay_authority(
        &self,
        requirement: &ForkReplayRequirementV1,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> ReadResult<ForkReplayAuthorityEvidenceV1> {
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
