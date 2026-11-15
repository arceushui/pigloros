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
///
/// The trait is sealed and its one implementation is private: only the
/// execution host builds a view, from its own adapter snapshot, so no caller
/// can hand an authority fabricated evidence.
pub trait ErasureAuthorityReadViewV1: view_sealed::Sealed {
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

mod view_sealed {
    /// Keeps the view closed: only the execution host's snapshot view
    /// implements it.
    pub trait Sealed {}
}

/// The view over one adapter [`ErasureAuthoritySnapshotV1`], built only by
/// the execution host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ErasureAuthoritySnapshotViewV1 {
    snapshot: ErasureAuthoritySnapshotV1,
}

impl ErasureAuthoritySnapshotViewV1 {
    /// Wrap one adapter snapshot.
    pub(crate) const fn new(snapshot: ErasureAuthoritySnapshotV1) -> Self {
        Self { snapshot }
    }
}

impl view_sealed::Sealed for ErasureAuthoritySnapshotViewV1 {}

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
