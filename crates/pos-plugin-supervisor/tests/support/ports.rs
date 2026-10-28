//! The admission-port wrappers of the pass vectors.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use pos_core::{
    AppendDedupKey, CoreError, FactualPrefixReadPortV1, PipelineAdmissionBasisV1,
    PipelineAdmissionPortV1, PipelineAttemptIdV1, PipelineOutcomeV1, PipelineReceiptLookupV1,
    PurgeOutcome, TimelineId,
};
use pos_runtime::ScheduledAdmissionStoreV1;

/// A port that commits through the real store and then loses the outcome.
pub struct LostPort<'a>(pub &'a mut dyn ScheduledAdmissionStoreV1);

impl PipelineAdmissionPortV1 for LostPort<'_> {
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        self.0.admit_pipeline_batch(basis).and_then(|_| {
            Err(CoreError::StorageOutcomeUnknown(
                "injected lost commit acknowledgement".to_owned(),
            ))
        })
    }

    fn lookup_pipeline_receipt(
        &mut self,
        timeline: TimelineId,
        key: AppendDedupKey,
        attempt_id: PipelineAttemptIdV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        self.0.lookup_pipeline_receipt(timeline, key, attempt_id)
    }

    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        self.0.purge_expired_pipeline_receipts_bounded(limit)
    }
}

impl FactualPrefixReadPortV1 for LostPort<'_> {
    fn last_committed_factual_tick(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<pos_core::FactualHeadV1, pos_core::CoreError> {
        self.0.last_committed_factual_tick(timeline)
    }

    fn cut_tick_at(
        &self,
        timeline: pos_core::TimelineId,
        seq: pos_core::Seq,
    ) -> Result<pos_core::FactualCutV1, pos_core::CoreError> {
        self.0.cut_tick_at(timeline, seq)
    }

    fn nodes_for_committed_events(
        &self,
        timeline: pos_core::TimelineId,
        seqs: &[pos_core::Seq],
    ) -> Result<Vec<Option<pos_core::DependencyNodeRecordV1>>, pos_core::CoreError> {
        self.0.nodes_for_committed_events(timeline, seqs)
    }

    fn nodes_by_digest(
        &self,
        timeline: pos_core::TimelineId,
        digests: &[pos_core::Hash],
    ) -> Result<Vec<Option<pos_core::factual_dependency::BoundFactualNodeV1>>, pos_core::CoreError>
    {
        self.0.nodes_by_digest(timeline, digests)
    }

    fn last_step_node(
        &self,
        timeline: pos_core::TimelineId,
        owner: &pos_core::FactualOwnerIdV1,
    ) -> Result<Option<pos_core::DependencyNodeRecordV1>, pos_core::CoreError> {
        self.0.last_step_node(timeline, owner)
    }

    fn factual_set_counts(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<pos_core::RecordedSetCountsV1, pos_core::CoreError> {
        self.0.factual_set_counts(timeline)
    }

    fn fold_cursor(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<Option<pos_core::FactualFoldCursorV1>, pos_core::CoreError> {
        self.0.fold_cursor(timeline)
    }

    fn fold_window(
        &self,
        timeline: pos_core::TimelineId,
        after: pos_core::Seq,
        through: pos_core::Seq,
    ) -> Result<pos_core::FactualFoldWindowV1, pos_core::CoreError> {
        self.0.fold_window(timeline, after, through)
    }
}

/// A port whose admission fails with a deterministic store error, not an unknown outcome.
pub struct FailingPort<'a>(pub &'a mut dyn ScheduledAdmissionStoreV1);

impl PipelineAdmissionPortV1 for FailingPort<'_> {
    fn admit_pipeline_batch(
        &mut self,
        _basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        Err(CoreError::ErasureAccessFrozen)
    }

    fn lookup_pipeline_receipt(
        &mut self,
        timeline: TimelineId,
        key: AppendDedupKey,
        attempt_id: PipelineAttemptIdV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        self.0.lookup_pipeline_receipt(timeline, key, attempt_id)
    }

    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        self.0.purge_expired_pipeline_receipts_bounded(limit)
    }
}

impl FactualPrefixReadPortV1 for FailingPort<'_> {
    fn last_committed_factual_tick(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<pos_core::FactualHeadV1, pos_core::CoreError> {
        self.0.last_committed_factual_tick(timeline)
    }

    fn cut_tick_at(
        &self,
        timeline: pos_core::TimelineId,
        seq: pos_core::Seq,
    ) -> Result<pos_core::FactualCutV1, pos_core::CoreError> {
        self.0.cut_tick_at(timeline, seq)
    }

    fn nodes_for_committed_events(
        &self,
        timeline: pos_core::TimelineId,
        seqs: &[pos_core::Seq],
    ) -> Result<Vec<Option<pos_core::DependencyNodeRecordV1>>, pos_core::CoreError> {
        self.0.nodes_for_committed_events(timeline, seqs)
    }

    fn nodes_by_digest(
        &self,
        timeline: pos_core::TimelineId,
        digests: &[pos_core::Hash],
    ) -> Result<Vec<Option<pos_core::factual_dependency::BoundFactualNodeV1>>, pos_core::CoreError>
    {
        self.0.nodes_by_digest(timeline, digests)
    }

    fn last_step_node(
        &self,
        timeline: pos_core::TimelineId,
        owner: &pos_core::FactualOwnerIdV1,
    ) -> Result<Option<pos_core::DependencyNodeRecordV1>, pos_core::CoreError> {
        self.0.last_step_node(timeline, owner)
    }

    fn factual_set_counts(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<pos_core::RecordedSetCountsV1, pos_core::CoreError> {
        self.0.factual_set_counts(timeline)
    }

    fn fold_cursor(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<Option<pos_core::FactualFoldCursorV1>, pos_core::CoreError> {
        self.0.fold_cursor(timeline)
    }

    fn fold_window(
        &self,
        timeline: pos_core::TimelineId,
        after: pos_core::Seq,
        through: pos_core::Seq,
    ) -> Result<pos_core::FactualFoldWindowV1, pos_core::CoreError> {
        self.0.fold_window(timeline, after, through)
    }
}

/// A port that stamps every admit call from a shared clock and then delegates.
///
/// The stamp is `fetch_add(1) + 1` of the clock, so it is ordered against every other recorder
/// that shares the clock (the spy registry of the signed-release world stamps its evaluations the
/// same way). It is a wrapper of an admission port, an implementation of a different trait than
/// the Plugin trust policy registry, and calls no registry.
pub struct StampedPort<'a> {
    db: &'a mut dyn ScheduledAdmissionStoreV1,
    clock: Arc<AtomicU64>,
    stamps: Vec<u64>,
}

impl<'a> StampedPort<'a> {
    /// A port over `db` that stamps from `clock`.
    #[must_use]
    pub const fn new(db: &'a mut dyn ScheduledAdmissionStoreV1, clock: Arc<AtomicU64>) -> Self {
        Self {
            db,
            clock,
            stamps: Vec::new(),
        }
    }

    /// The stamp of each admit call, in call order.
    #[must_use]
    pub fn stamps(&self) -> &[u64] {
        &self.stamps
    }
}

impl PipelineAdmissionPortV1 for StampedPort<'_> {
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        let stamp = self.clock.fetch_add(1, Ordering::SeqCst) + 1;
        self.stamps.push(stamp);
        self.db.admit_pipeline_batch(basis)
    }

    fn lookup_pipeline_receipt(
        &mut self,
        timeline: TimelineId,
        key: AppendDedupKey,
        attempt_id: PipelineAttemptIdV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        self.db.lookup_pipeline_receipt(timeline, key, attempt_id)
    }

    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        self.db.purge_expired_pipeline_receipts_bounded(limit)
    }
}

impl FactualPrefixReadPortV1 for StampedPort<'_> {
    fn last_committed_factual_tick(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<pos_core::FactualHeadV1, pos_core::CoreError> {
        self.db.last_committed_factual_tick(timeline)
    }

    fn cut_tick_at(
        &self,
        timeline: pos_core::TimelineId,
        seq: pos_core::Seq,
    ) -> Result<pos_core::FactualCutV1, pos_core::CoreError> {
        self.db.cut_tick_at(timeline, seq)
    }

    fn nodes_for_committed_events(
        &self,
        timeline: pos_core::TimelineId,
        seqs: &[pos_core::Seq],
    ) -> Result<Vec<Option<pos_core::DependencyNodeRecordV1>>, pos_core::CoreError> {
        self.db.nodes_for_committed_events(timeline, seqs)
    }

    fn nodes_by_digest(
        &self,
        timeline: pos_core::TimelineId,
        digests: &[pos_core::Hash],
    ) -> Result<Vec<Option<pos_core::factual_dependency::BoundFactualNodeV1>>, pos_core::CoreError>
    {
        self.db.nodes_by_digest(timeline, digests)
    }

    fn last_step_node(
        &self,
        timeline: pos_core::TimelineId,
        owner: &pos_core::FactualOwnerIdV1,
    ) -> Result<Option<pos_core::DependencyNodeRecordV1>, pos_core::CoreError> {
        self.db.last_step_node(timeline, owner)
    }

    fn factual_set_counts(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<pos_core::RecordedSetCountsV1, pos_core::CoreError> {
        self.db.factual_set_counts(timeline)
    }

    fn fold_cursor(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<Option<pos_core::FactualFoldCursorV1>, pos_core::CoreError> {
        self.db.fold_cursor(timeline)
    }

    fn fold_window(
        &self,
        timeline: pos_core::TimelineId,
        after: pos_core::Seq,
        through: pos_core::Seq,
    ) -> Result<pos_core::FactualFoldWindowV1, pos_core::CoreError> {
        self.db.fold_window(timeline, after, through)
    }
}

/// A port whose approval of the staged batch at the Tick-Boundary commit refuses it with a typed
/// outcome, as the store's own approval (the authority and policy check of
/// `admit_pipeline_batch`) does when the authority is revoked or expired or the policy cannot be
/// determined: the store commits nothing and the outcome is returned.
///
/// Every other call, the prefix reads that build the basis included, goes to the real store.
pub struct RefusingPort<'a> {
    db: &'a mut dyn ScheduledAdmissionStoreV1,
    outcome: PipelineOutcomeV1,
    calls: usize,
}

impl<'a> RefusingPort<'a> {
    /// A port over `db` whose approval refuses every batch with `outcome`.
    #[must_use]
    pub const fn new(
        db: &'a mut dyn ScheduledAdmissionStoreV1,
        outcome: PipelineOutcomeV1,
    ) -> Self {
        Self {
            db,
            outcome,
            calls: 0,
        }
    }

    /// How many batches reached the approval, which shows that the refusal was injected.
    #[must_use]
    pub const fn calls(&self) -> usize {
        self.calls
    }
}

impl PipelineAdmissionPortV1 for RefusingPort<'_> {
    fn admit_pipeline_batch(
        &mut self,
        _basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        self.calls += 1;
        Ok(self.outcome.clone())
    }

    fn lookup_pipeline_receipt(
        &mut self,
        timeline: TimelineId,
        key: AppendDedupKey,
        attempt_id: PipelineAttemptIdV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        self.db.lookup_pipeline_receipt(timeline, key, attempt_id)
    }

    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        self.db.purge_expired_pipeline_receipts_bounded(limit)
    }
}

impl FactualPrefixReadPortV1 for RefusingPort<'_> {
    fn last_committed_factual_tick(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<pos_core::FactualHeadV1, pos_core::CoreError> {
        self.db.last_committed_factual_tick(timeline)
    }

    fn cut_tick_at(
        &self,
        timeline: pos_core::TimelineId,
        seq: pos_core::Seq,
    ) -> Result<pos_core::FactualCutV1, pos_core::CoreError> {
        self.db.cut_tick_at(timeline, seq)
    }

    fn nodes_for_committed_events(
        &self,
        timeline: pos_core::TimelineId,
        seqs: &[pos_core::Seq],
    ) -> Result<Vec<Option<pos_core::DependencyNodeRecordV1>>, pos_core::CoreError> {
        self.db.nodes_for_committed_events(timeline, seqs)
    }

    fn nodes_by_digest(
        &self,
        timeline: pos_core::TimelineId,
        digests: &[pos_core::Hash],
    ) -> Result<Vec<Option<pos_core::factual_dependency::BoundFactualNodeV1>>, pos_core::CoreError>
    {
        self.db.nodes_by_digest(timeline, digests)
    }

    fn last_step_node(
        &self,
        timeline: pos_core::TimelineId,
        owner: &pos_core::FactualOwnerIdV1,
    ) -> Result<Option<pos_core::DependencyNodeRecordV1>, pos_core::CoreError> {
        self.db.last_step_node(timeline, owner)
    }

    fn factual_set_counts(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<pos_core::RecordedSetCountsV1, pos_core::CoreError> {
        self.db.factual_set_counts(timeline)
    }

    fn fold_cursor(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<Option<pos_core::FactualFoldCursorV1>, pos_core::CoreError> {
        self.db.fold_cursor(timeline)
    }

    fn fold_window(
        &self,
        timeline: pos_core::TimelineId,
        after: pos_core::Seq,
        through: pos_core::Seq,
    ) -> Result<pos_core::FactualFoldWindowV1, pos_core::CoreError> {
        self.db.fold_window(timeline, after, through)
    }
}
