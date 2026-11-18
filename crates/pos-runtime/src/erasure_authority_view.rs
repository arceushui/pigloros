//! The erasure authority's read-only snapshot view (ADR-136 companion §2.6).

use std::{cell::OnceCell, rc::Rc, sync::Arc};

use pos_core::{
    ArtifactRegistrationCatalogRowV1, ErasureAuthoritySnapshotV1, ErasureAuthorityTimelineRowV1,
    ErasureErrorV1, ErasureReferenceV1, ErasureRetryAdmissionV1, ErasureScopeCommitmentV1,
    ErasureScopeExtensionV1, ErasureVerifiedInventoryV1, ErasureVerifiedStateV1, Hash,
    KeyIdentityV1, KeyRegistryStateV1, OwnerIdV1, PersistedAuthorityV1,
    RecipientExportPublicationRowV1, TimelineId,
};

/// The committed ERSC1 of one request and its ERSE1 chain in ordinal order.
pub type ErasureRecordedScopeV1 = (ErasureScopeCommitmentV1, Vec<ErasureScopeExtensionV1>);

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

    /// The committed ERSC1 and ERSE1 chain of one request, read inside the
    /// host command that built this view (companion §2.6
    /// `scope_commitment` and `scope_extensions`). `Ok(None)` when the
    /// request has no committed scope; core recovery checks every
    /// observation built from it.
    ///
    /// # Errors
    /// [`ErasureErrorV1::ProvenanceMissing`] outside a host command, or the
    /// closed read error of a recorded scope.
    fn recorded_scope(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<ErasureRecordedScopeV1>, ErasureErrorV1>;

    /// The admission of one request's active attempt, `Ok(None)` when it
    /// has none.
    ///
    /// It is read inside the host command that built this view, and carries
    /// the trust revision the attempt pins (ADR-136 §5).
    ///
    /// # Errors
    /// [`ErasureErrorV1::ProvenanceMissing`] outside a host command, or the
    /// closed read error of a recorded attempt.
    fn active_attempt(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<ErasureRetryAdmissionV1>, ErasureErrorV1>;

    /// The trust revision one request's frozen obligation set pins,
    /// `Ok(None)` before freeze.
    ///
    /// It is read inside the host command that built this view. Core
    /// recovery requires every attempt of the request to pin it.
    ///
    /// # Errors
    /// [`ErasureErrorV1::ProvenanceMissing`] outside a host command, or the
    /// closed read error of a recorded obligation set.
    fn frozen_trust(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1>;

    /// Every ARD1 registration bound to `timeline`, in registration-address
    /// order (companion §2.6 `artifact_registrations`).
    ///
    /// # Errors
    /// [`ErasureViewListErrorV1::OverBound`] above the per-category closure
    /// bound of 4,096 rows, otherwise a read failure.
    fn artifact_registrations(
        &self,
        timeline: TimelineId,
    ) -> Result<Vec<ArtifactRegistrationCatalogRowV1>, ErasureViewListErrorV1>;

    /// Every visible recipient-export publication of `timelines`, sorted by
    /// `(timeline, export_id)`.
    ///
    /// # Errors
    /// [`ErasureViewListErrorV1::OverBound`] above 4,096 publications,
    /// otherwise a read failure.
    fn recipient_export_publications(
        &self,
        timelines: &[TimelineId],
    ) -> Result<Vec<RecipientExportPublicationRowV1>, ErasureViewListErrorV1>;

    /// Every key-registry identity of `owner`, in every role and epoch,
    /// including destroyed ones (companion §2.6 `key_identities`).
    ///
    /// # Errors
    /// [`ErasureViewListErrorV1::OverBound`] above 4,096 identities,
    /// otherwise a read failure.
    fn key_identities(
        &self,
        owner: &OwnerIdV1,
    ) -> Result<Vec<KeyIdentityV1>, ErasureViewListErrorV1>;
}

/// The most rows one bounded view list returns: the ADR-060 V1
/// per-category obligation bound.
pub(crate) const VIEW_LIST_MAX: usize = pos_core::ERASURE_MAX_OBLIGATIONS_PER_CATEGORY;

/// The view error of a failed ARD1 Timeline read: the read's bound
/// overflow is [`ErasureViewListErrorV1::OverBound`], any other failure an
/// unreadable store.
pub(crate) fn registration_read_error(
    error: pos_core::ArtifactRegistrationPersistenceErrorV1,
) -> ErasureViewListErrorV1 {
    if error == pos_core::ArtifactRegistrationPersistenceErrorV1::FieldOutOfBounds {
        ErasureViewListErrorV1::OverBound
    } else {
        ErasureViewListErrorV1::Read(ErasureErrorV1::ProvenanceMissing)
    }
}

/// The view error of a failed recipient-export read: the adapter documents
/// `ScopeInvalid` as its only over-`max` answer, mapped here once.
pub(crate) fn export_read_error(error: ErasureErrorV1) -> ErasureViewListErrorV1 {
    if error == ErasureErrorV1::ScopeInvalid {
        ErasureViewListErrorV1::OverBound
    } else {
        ErasureViewListErrorV1::Read(error)
    }
}

/// Why a bounded view list was not returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErasureViewListErrorV1 {
    /// More rows than the list's bound of 4,096.
    OverBound,
    /// The rows could not be read.
    Read(ErasureErrorV1),
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

    /// The committed ERSC1 and ERSE1 chain of one request.
    fn recorded_scope(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<ErasureRecordedScopeV1>, ErasureErrorV1>;

    /// The admission of one request's active attempt.
    fn active_attempt(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<ErasureRetryAdmissionV1>, ErasureErrorV1>;

    /// The trust of one request's frozen obligation set.
    fn frozen_trust(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1>;

    /// The ARD1 rows bound to one Timeline, at most [`VIEW_LIST_MAX`].
    fn artifact_registrations(
        &self,
        timeline: TimelineId,
    ) -> Result<Vec<ArtifactRegistrationCatalogRowV1>, ErasureViewListErrorV1>;

    /// The recipient-export publications of `timelines`, at most
    /// [`VIEW_LIST_MAX`].
    fn recipient_export_publications(
        &self,
        timelines: &[TimelineId],
    ) -> Result<Vec<RecipientExportPublicationRowV1>, ErasureViewListErrorV1>;

    /// The whole key registry, read once per view.
    fn key_registry(&self) -> Result<Option<KeyRegistryStateV1>, ErasureErrorV1>;
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

    fn recorded_scope(
        &self,
        _request: ErasureReferenceV1,
    ) -> Result<Option<ErasureRecordedScopeV1>, ErasureErrorV1> {
        Err(ErasureErrorV1::ProvenanceMissing)
    }

    fn active_attempt(
        &self,
        _request: ErasureReferenceV1,
    ) -> Result<Option<ErasureRetryAdmissionV1>, ErasureErrorV1> {
        Err(ErasureErrorV1::ProvenanceMissing)
    }

    fn frozen_trust(
        &self,
        _request: ErasureReferenceV1,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
        Err(ErasureErrorV1::ProvenanceMissing)
    }

    fn artifact_registrations(
        &self,
        _timeline: TimelineId,
    ) -> Result<Vec<ArtifactRegistrationCatalogRowV1>, ErasureViewListErrorV1> {
        Err(ErasureViewListErrorV1::Read(
            ErasureErrorV1::ProvenanceMissing,
        ))
    }

    fn recipient_export_publications(
        &self,
        _timelines: &[TimelineId],
    ) -> Result<Vec<RecipientExportPublicationRowV1>, ErasureViewListErrorV1> {
        Err(ErasureViewListErrorV1::Read(
            ErasureErrorV1::ProvenanceMissing,
        ))
    }

    fn key_registry(&self) -> Result<Option<KeyRegistryStateV1>, ErasureErrorV1> {
        Err(ErasureErrorV1::ProvenanceMissing)
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
    /// The key registry, read at most once by this view.
    key_registry: OnceCell<Result<Option<KeyRegistryStateV1>, ErasureErrorV1>>,
}

impl<'reads> HostAuthorityViewV1<'reads> {
    /// A view whose store reads run inside the current host command.
    pub(crate) const fn attached(
        snapshot: Rc<ErasureAuthoritySnapshotViewV1>,
        reads: &'reads dyn ErasureAuthorityStoreReadsV1,
    ) -> Self {
        Self {
            snapshot,
            reads,
            key_registry: OnceCell::new(),
        }
    }
}

impl HostAuthorityViewV1<'static> {
    /// A view handed out of its host command, which reads no object.
    pub(crate) fn detached(snapshot: ErasureAuthoritySnapshotViewV1) -> Self {
        Self {
            snapshot: Rc::new(snapshot),
            reads: &DETACHED,
            key_registry: OnceCell::new(),
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

    fn recorded_scope(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<ErasureRecordedScopeV1>, ErasureErrorV1> {
        self.reads.recorded_scope(request)
    }

    fn active_attempt(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<ErasureRetryAdmissionV1>, ErasureErrorV1> {
        self.reads.active_attempt(request)
    }

    fn frozen_trust(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<ErasureReferenceV1>, ErasureErrorV1> {
        self.reads.frozen_trust(request)
    }

    fn artifact_registrations(
        &self,
        timeline: TimelineId,
    ) -> Result<Vec<ArtifactRegistrationCatalogRowV1>, ErasureViewListErrorV1> {
        self.reads.artifact_registrations(timeline)
    }

    fn recipient_export_publications(
        &self,
        timelines: &[TimelineId],
    ) -> Result<Vec<RecipientExportPublicationRowV1>, ErasureViewListErrorV1> {
        self.reads.recipient_export_publications(timelines)
    }

    fn key_identities(
        &self,
        owner: &OwnerIdV1,
    ) -> Result<Vec<KeyIdentityV1>, ErasureViewListErrorV1> {
        self.key_registry
            .get_or_init(|| self.reads.key_registry())
            .as_ref()
            .map_err(|error| ErasureViewListErrorV1::Read(*error))
            .map(|registry| {
                registry
                    .iter()
                    .flat_map(KeyRegistryStateV1::key_records)
                    .map(|record| record.identity)
                    .filter(|identity| identity.owner_id == *owner)
                    .collect::<Vec<_>>()
            })
            .and_then(|identities| {
                (identities.len() <= VIEW_LIST_MAX)
                    .then_some(identities)
                    .ok_or(ErasureViewListErrorV1::OverBound)
            })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_core::ArtifactRegistrationPersistenceErrorV1;

    #[test]
    fn only_an_over_bound_list_read_is_over_bound() {
        assert_eq!(
            registration_read_error(ArtifactRegistrationPersistenceErrorV1::FieldOutOfBounds),
            ErasureViewListErrorV1::OverBound
        );
        for error in [
            ArtifactRegistrationPersistenceErrorV1::StorageFailure,
            ArtifactRegistrationPersistenceErrorV1::CorruptCatalog,
        ] {
            assert_eq!(
                registration_read_error(error),
                ErasureViewListErrorV1::Read(ErasureErrorV1::ProvenanceMissing)
            );
        }
        assert_eq!(
            export_read_error(ErasureErrorV1::ScopeInvalid),
            ErasureViewListErrorV1::OverBound
        );
        assert_eq!(
            export_read_error(ErasureErrorV1::ProvenanceMissing),
            ErasureViewListErrorV1::Read(ErasureErrorV1::ProvenanceMissing)
        );
    }
}
