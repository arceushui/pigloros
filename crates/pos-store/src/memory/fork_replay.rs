//! Bounded bridge into the existing `MemoryStore` validator-(b) implementation.

use super::MemoryStore;
use crate::{
    fork_event_authority::AuthorityValidatorV1, fork_replay::NativeReadContextV1,
    ForkReplayAuthorityEvidenceV1, ForkReplayAuthorityReadErrorV1 as Error,
    ForkReplayAuthorityReadPortV1, ForkReplayReadBudgetV1, ForkReplayRequirementV1,
};

type ReadResult<T> = Result<T, Error>;

impl ForkReplayAuthorityReadPortV1 for MemoryStore {
    fn begin_fork_replay_read_interval(
        &self,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> Result<pos_core::ErasureProtectedEffectIntervalV1, crate::ForkReplayLineageReadErrorV1>
    {
        budget
            .check_time()
            .map_err(crate::ForkReplayLineageReadErrorV1::Read)?;
        // Exclusive host ownership already serializes MemoryStore; this
        // branch executes no native BEGIN, freshness row or interval cleanup.
        budget
            .check_time()
            .map_err(crate::ForkReplayLineageReadErrorV1::Read)
            .map(|()| pos_core::ErasureProtectedEffectIntervalV1::Unowned)
    }

    fn fork_replay_logical_head(
        &self,
        timeline_id: pos_core::TimelineId,
        effective_max_fork_depth: usize,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> Result<pos_core::Seq, crate::ForkReplayLineageReadErrorV1> {
        let mut context =
            crate::fork_replay::LineageReadContextV1::new(budget, effective_max_fork_depth)?;
        let history = crate::fork_replay::read_visible_history(
            timeline_id,
            &mut context,
            |member, visited, context| self.read_lineage_member(member, visited, context, false),
        )?;
        let head = crate::fork_replay::history_head(&history, &mut context)?;
        context.bytes(8).map(|()| pos_core::Seq::from_u64(head))
    }

    fn read_fork_replay_events(
        &self,
        timeline_id: pos_core::TimelineId,
        range: pos_core::SeqRange,
        bounds: pos_core::EventReadBounds,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> Result<Vec<pos_core::Event>, crate::ForkReplayLineageReadErrorV1> {
        let mut context = crate::fork_replay::LineageReadContextV1::for_events(budget, bounds)?;
        let history = crate::fork_replay::read_visible_history(
            timeline_id,
            &mut context,
            |member, visited, context| self.read_lineage_member(member, visited, context, true),
        )?;
        let head = crate::fork_replay::history_head(&history, &mut context)?;
        let (from, to) =
            crate::fork_replay::complete_event_range(head, range, bounds, &mut context)?;
        let mut carrier = Vec::new();
        let mut events = crate::fork_replay::ReplayEventStagingV1::new(&mut carrier);
        let mut total_bytes = 0_usize;
        for (index, (node, _)) in history.iter().enumerate() {
            let (prefix, length) =
                crate::fork_replay::history_segment(&history, index, &mut context)?;
            if length == 0 {
                continue;
            }
            // Validated segment arithmetic proves prefix+length fits and,
            // for a nonempty segment, so does prefix+1.
            let first = from.max(prefix + 1);
            let last = to.min(prefix + length);
            if first > last {
                continue;
            }
            let timeline = node.timeline_id();
            self.with_replay_read_fence(*timeline, &mut context, |context| {
                let state = self.state(*timeline);
                let raw_start = first - prefix;
                let start = usize::try_from(raw_start - 1).unwrap_or(usize::MAX);
                let take = usize::try_from(last - first + 1).unwrap_or(usize::MAX);
                for (offset, event) in state.events.iter().skip(start).take(take).enumerate() {
                    context.check()?;
                    context.row()?;
                    let expected = raw_start + u64::try_from(offset).unwrap_or(u64::MAX);
                    context.step(|_| {
                        let origin = pos_core::EventOriginV1 {
                            origin_timeline_id: *timeline,
                            origin_logical_seq: pos_core::Seq::from_u64(prefix + expected),
                        };
                        if event.seq.as_u64() != expected || event.origin != Some(origin) {
                            return crate::fork_replay::corrupt();
                        }
                        pos_core::store::validate_event_signature(event).map_err(|_| {
                            crate::ForkReplayLineageReadErrorV1::Read(Error::CorruptAuthority)
                        })
                    })?;
                    let payload = event.payload.as_slice().len();
                    let kind = event.event_type.as_str().len();
                    let bytes = payload.checked_add(kind);
                    let next_total = bytes.and_then(|bytes| total_bytes.checked_add(bytes));
                    context.require(
                        payload <= bounds.max_payload_bytes()
                            && kind <= bounds.max_event_type_bytes()
                            && next_total.is_some_and(|total| total <= bounds.max_total_bytes()),
                    )?;
                    context.bytes(8)?;
                    context.bytes(bytes.unwrap_or(usize::MAX))?;
                    // One funded owned clone: fixed fields are Copy, while
                    // P+T is copied once and remains scrubbable on refusal.
                    events.push(pos_core::Event {
                        event_type: event.event_type.clone(),
                        payload: pos_core::CanonicalBytes::from_vec(
                            event.payload.as_slice().to_vec(),
                        ),
                        seq: pos_core::Seq::from_u64(prefix + expected),
                        ..*event
                    });
                    total_bytes = next_total.unwrap_or(usize::MAX);
                    context.check()?;
                }
                Ok(())
            })?;
        }
        // The visibility walk checked each immutable segment's head/count.
        // Its disjoint selected slices push exactly once per Event; the sealed
        // fence cannot repeat a successful effect or change those slices.
        Ok(events.into_events())
    }

    fn read_fork_replay_lineage_node(
        &self,
        timeline_id: pos_core::TimelineId,
        depth: usize,
        effective_max_fork_depth: usize,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> Result<Option<crate::ForkReplayLineageNodeV1>, crate::ForkReplayLineageReadErrorV1> {
        let mut context =
            crate::fork_replay::LineageReadContextV1::new(budget, effective_max_fork_depth)?;
        crate::fork_replay::read_visible_lineage(
            timeline_id,
            depth,
            &mut context,
            |member, visited, context| self.read_lineage_member(member, visited, context, false),
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
