//! The erasure authority's read-only snapshot view (ADR-136 companion §2.6).

use std::{rc::Rc, sync::Arc};

use pos_core::{
    ErasureAuthoritySnapshotV1, ErasureAuthorityTimelineRowV1, ErasureReferenceV1,
    ErasureVerifiedInventoryV1, ErasureVerifiedStateV1, Hash, PersistedAuthorityV1, TimelineId,
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

    /// The host's request-head ceiling for this store.
    fn maximum_requests(&self) -> usize;

    /// Every request of the host's installed verified inventory, a bounded
    /// scan of at most the request-head ceiling; empty while the host
    /// recovers.
    fn verified_requests(&self) -> Vec<&ErasureVerifiedStateV1>;

    /// One request of the host's installed verified inventory.
    fn verified_request(&self, request: ErasureReferenceV1) -> Option<&ErasureVerifiedStateV1>;

    /// The exact bytes of one object in the shared erasure object store,
    /// read inside the host command that built this view.
    fn retained_object(&self, reference: ErasureReferenceV1) -> Option<Vec<u8>>;

    /// The recorded delegation chain whose leaf grant is `grant`, read
    /// inside the host command that built this view.
    fn local_principal_authority(&self, grant: Hash) -> Option<PersistedAuthorityV1>;
}

mod view_sealed {
    /// Keeps the view closed: only the execution host's view implements it.
    pub trait Sealed {}
}

/// The store reads a host view resolves while its host command runs.
pub(crate) trait ErasureAuthorityStoreReadsV1 {
    /// The exact bytes of one erasure object.
    fn retained_object(&self, reference: ErasureReferenceV1) -> Option<Vec<u8>>;

    /// The recorded delegation chain whose leaf grant is `grant`.
    fn local_principal_authority(&self, grant: Hash) -> Option<PersistedAuthorityV1>;
}

/// The reads of a view handed out of its host command: none.
struct DetachedStoreReadsV1;

impl ErasureAuthorityStoreReadsV1 for DetachedStoreReadsV1 {
    fn retained_object(&self, _reference: ErasureReferenceV1) -> Option<Vec<u8>> {
        None
    }

    fn local_principal_authority(&self, _grant: Hash) -> Option<PersistedAuthorityV1> {
        None
    }
}

static DETACHED: DetachedStoreReadsV1 = DetachedStoreReadsV1;

/// The snapshot facts of one view: one adapter [`ErasureAuthoritySnapshotV1`],
/// the host's request-head ceiling and its installed verified inventory.
pub(crate) struct ErasureAuthoritySnapshotViewV1 {
    snapshot: ErasureAuthoritySnapshotV1,
    maximum_requests: usize,
    inventory: Option<Arc<ErasureVerifiedInventoryV1>>,
}

impl ErasureAuthoritySnapshotViewV1 {
    /// Wrap one adapter snapshot.
    pub(crate) const fn new(
        snapshot: ErasureAuthoritySnapshotV1,
        maximum_requests: usize,
        inventory: Option<Arc<ErasureVerifiedInventoryV1>>,
    ) -> Self {
        Self {
            snapshot,
            maximum_requests,
            inventory,
        }
    }
}

/// The one view implementation: snapshot facts plus the reads of the host
/// command that built it.
pub(crate) struct HostAuthorityViewV1<'reads> {
    snapshot: Rc<ErasureAuthoritySnapshotViewV1>,
    reads: &'reads dyn ErasureAuthorityStoreReadsV1,
}

impl<'reads> HostAuthorityViewV1<'reads> {
    /// A view whose store reads run inside the current host command.
    pub(crate) const fn attached(
        snapshot: Rc<ErasureAuthoritySnapshotViewV1>,
        reads: &'reads dyn ErasureAuthorityStoreReadsV1,
    ) -> Self {
        Self { snapshot, reads }
    }
}

impl HostAuthorityViewV1<'static> {
    /// A view handed out of its host command, which reads no object.
    pub(crate) fn detached(snapshot: ErasureAuthoritySnapshotViewV1) -> Self {
        Self {
            snapshot: Rc::new(snapshot),
            reads: &DETACHED,
        }
    }
}

impl view_sealed::Sealed for HostAuthorityViewV1<'_> {}

impl ErasureAuthorityReadViewV1 for HostAuthorityViewV1<'_> {
    fn snapshot_generation(&self) -> ErasureReferenceV1 {
        self.snapshot.snapshot.inventory().generation()
    }

    fn topology(&self) -> &[TimelineId] {
        self.snapshot.snapshot.inventory().topology()
    }

    fn timeline_meta(&self, timeline: TimelineId) -> Option<&ErasureAuthorityTimelineRowV1> {
        self.snapshot.snapshot.timeline(timeline)
    }

    fn request_count(&self) -> usize {
        self.snapshot.snapshot.inventory().request_heads().len()
    }

    fn store_identity(&self) -> Option<Hash> {
        self.snapshot.snapshot.store_identity()
    }

    fn maximum_requests(&self) -> usize {
        self.snapshot.maximum_requests
    }

    fn verified_requests(&self) -> Vec<&ErasureVerifiedStateV1> {
        self.snapshot
            .inventory
            .iter()
            .flat_map(|inventory| inventory.states())
            .collect()
    }

    fn verified_request(&self, request: ErasureReferenceV1) -> Option<&ErasureVerifiedStateV1> {
        self.snapshot
            .inventory
            .iter()
            .flat_map(|inventory| inventory.states())
            .find(|state| state.request().reference() == request)
    }

    fn retained_object(&self, reference: ErasureReferenceV1) -> Option<Vec<u8>> {
        self.reads.retained_object(reference)
    }

    fn local_principal_authority(&self, grant: Hash) -> Option<PersistedAuthorityV1> {
        self.reads.local_principal_authority(grant)
    }
}
