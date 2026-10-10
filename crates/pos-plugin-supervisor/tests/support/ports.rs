//! The admission-port wrappers of the pass vectors.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use pos_core::{
    AppendDedupKey, CoreError, PipelineAdmissionBasisV1, PipelineAdmissionPortV1,
    PipelineAttemptIdV1, PipelineOutcomeV1, PipelineReceiptLookupV1, PurgeOutcome, TimelineId,
};
use pos_store::memory::MemoryStore;

/// A port that commits through the real store and then loses the outcome.
pub struct LostPort<'a>(pub &'a mut MemoryStore);

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

/// A port whose admission fails with a deterministic store error, not an unknown outcome.
pub struct FailingPort<'a>(pub &'a mut MemoryStore);

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

/// A port that stamps every admit call from a shared clock and then delegates.
///
/// The stamp is `fetch_add(1) + 1` of the clock, so it is ordered against every other recorder
/// that shares the clock (the spy registry of the signed-release world stamps its evaluations the
/// same way). It is a wrapper of an admission port, an implementation of a different trait than
/// the Plugin trust policy registry, and calls no registry.
pub struct StampedPort<'a> {
    db: &'a mut MemoryStore,
    clock: Arc<AtomicU64>,
    stamps: Vec<u64>,
}

impl<'a> StampedPort<'a> {
    /// A port over `db` that stamps from `clock`.
    #[must_use]
    pub const fn new(db: &'a mut MemoryStore, clock: Arc<AtomicU64>) -> Self {
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
