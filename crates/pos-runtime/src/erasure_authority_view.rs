//! The erasure authority's read-only snapshot view (ADR-136 companion §2.6).

use pos_core::{
    ErasureAuthoritySnapshotV1, ErasureAuthorityTimelineRowV1, ErasureReferenceV1, Hash, TimelineId,
};

/// Read-only, snapshot-bound evidence an execution host passes into every
/// [`crate::ErasureCoordinatorAuthorityV1`] method.
///
/// The view supplies store-held facts only. Every trust root, authorization
/// rule and policy comes from the authority's own pinned configuration, and a
/// store-held trust artefact is compared against that pinned copy, never
/// trusted on its own (ADR-136 companion §2.2). The view has no write, commit
/// or index-repair method, so an authority cannot change any durable record
/// through it.
pub trait ErasureAuthorityReadViewV1 {
    /// The generation of the complete erasure inventory in this snapshot.
    fn snapshot_generation(&self) -> ErasureReferenceV1;

    /// Every Timeline and Fork ID in this snapshot, in increasing order.
    fn topology(&self) -> &[TimelineId];

    /// The owner and Fork relation of one Timeline in this snapshot.
    fn timeline_meta(&self, timeline: TimelineId) -> Option<&ErasureAuthorityTimelineRowV1>;

    /// How many durable erasure request heads this snapshot holds.
    fn request_count(&self) -> usize;

    /// The write-once erasure store identity, when it has been written.
    fn store_identity(&self) -> Option<Hash>;
}

/// The view over one adapter [`ErasureAuthoritySnapshotV1`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErasureAuthoritySnapshotViewV1 {
    snapshot: ErasureAuthoritySnapshotV1,
}

impl ErasureAuthoritySnapshotViewV1 {
    /// Wrap one adapter snapshot.
    #[must_use]
    pub const fn new(snapshot: ErasureAuthoritySnapshotV1) -> Self {
        Self { snapshot }
    }
}

impl ErasureAuthorityReadViewV1 for ErasureAuthoritySnapshotViewV1 {
    fn snapshot_generation(&self) -> ErasureReferenceV1 {
        self.snapshot.inventory().generation()
    }

    fn topology(&self) -> &[TimelineId] {
        self.snapshot.inventory().topology()
    }

    fn timeline_meta(&self, timeline: TimelineId) -> Option<&ErasureAuthorityTimelineRowV1> {
        self.snapshot.timeline(timeline)
    }

    fn request_count(&self) -> usize {
        self.snapshot.inventory().request_heads().len()
    }

    fn store_identity(&self) -> Option<Hash> {
        self.snapshot.store_identity()
    }
}
