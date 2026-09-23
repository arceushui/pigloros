//! Runtime-owned World Replay verification capabilities.
//!
//! [`pos_core::WorldReplayClosureV1`] is deliberately structural.  It can be
//! decoded and checked for immutable shape, but it cannot mint a Replay claim.
//! The runtime owns the installed verifier boundary and the opaque verified
//! result used by protected Replay, Snapshot, and comparison operations.

use pos_core::{
    store::{EventReadBounds, SeqRange},
    ErasureProtectedOperationV1, ErasureReferenceV1, ErasureReplayClaimV1, Hash, TimelineId,
    WorldReplayClosureV1,
};

#[cfg(any(test, feature = "test-support"))]
const TEST_WORLD_REPLAY_READ_BOUNDS: EventReadBounds =
    EventReadBounds::new_with_total_bytes_and_elapsed(
        65_536, 128, 8, 65_536, 67_108_864, 30_000_000,
    );

/// Closed reasons why an installed World Replay verifier could not issue a
/// protected-use capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorldReplayVerificationErrorV1 {
    /// The requested operation is not covered by the structural closure.
    #[error("World Replay request is not covered by the closure")]
    RequestMismatch,
    /// No host-installed verifier was configured for this composition.
    #[error("World Replay verifier is not installed")]
    MissingVerifier,
    /// The verifier rejected the structural closure or its native evidence.
    #[error("World Replay closure evidence is unavailable")]
    EvidenceUnavailable,
    /// The verifier observed a different host inventory generation.
    #[error("World Replay verifier observed a stale inventory generation")]
    StaleGeneration,
    /// The verified evidence does not support authoritative use.
    #[error("World Replay evidence does not support authoritative use")]
    ClaimUnavailable,
}

/// Exact protected use presented to the installed World Replay verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldReplayUseV1 {
    timeline_id: TimelineId,
    operation: ErasureProtectedOperationV1,
    range: SeqRange,
    consumer_ids: Vec<String>,
    requested_optional_view_roots: Vec<Hash>,
}

impl WorldReplayUseV1 {
    /// Construct a bounded request with a canonical consumer selection.
    ///
    /// # Errors
    /// Returns [`WorldReplayVerificationErrorV1::RequestMismatch`] for an
    /// empty, duplicate, oversized, or malformed consumer selection.
    pub fn new(
        timeline_id: TimelineId,
        operation: ErasureProtectedOperationV1,
        range: SeqRange,
        consumer_ids: Vec<String>,
    ) -> Result<Self, WorldReplayVerificationErrorV1> {
        Self::new_with_optional_views(timeline_id, operation, range, consumer_ids, Vec::new())
    }

    /// Construct a bounded request that names every optional view it will expose.
    ///
    /// # Errors
    /// Returns [`WorldReplayVerificationErrorV1::RequestMismatch`] for an
    /// invalid consumer selection or optional-view root set.
    pub fn new_with_optional_views(
        timeline_id: TimelineId,
        operation: ErasureProtectedOperationV1,
        range: SeqRange,
        mut consumer_ids: Vec<String>,
        mut requested_optional_view_roots: Vec<Hash>,
    ) -> Result<Self, WorldReplayVerificationErrorV1> {
        consumer_ids.sort_unstable();
        requested_optional_view_roots.sort_unstable_by_key(|root| *root.as_bytes());
        let invalid = range.to.is_some_and(|to| to < range.from)
            || consumer_ids.is_empty()
            || consumer_ids.len() > pos_core::world_consumer_set::WORLD_CONSUMER_SET_MAX_CONSUMERS
            || requested_optional_view_roots.len()
                > pos_core::world_consumer_set::WORLD_CONSUMER_SET_MAX_PRODUCERS_OR_VIEWS
            || requested_optional_view_roots
                .iter()
                .any(|root| *root == Hash::zero())
            || requested_optional_view_roots
                .windows(2)
                .any(|pair| pair[0] == pair[1])
            || consumer_ids.iter().any(|id| {
                id.is_empty()
                    || id.len()
                        > pos_core::world_consumer_set::WORLD_CONSUMER_SET_MAX_CONSUMER_ID_BYTES
            })
            || consumer_ids.windows(2).any(|pair| pair[0] == pair[1]);
        if invalid {
            return Err(WorldReplayVerificationErrorV1::RequestMismatch);
        }
        Ok(Self {
            timeline_id,
            operation,
            range,
            consumer_ids,
            requested_optional_view_roots,
        })
    }

    /// Return the requested Timeline.
    #[must_use]
    pub const fn timeline_id(&self) -> TimelineId {
        self.timeline_id
    }

    /// Return the requested protected operation.
    #[must_use]
    pub const fn operation(&self) -> ErasureProtectedOperationV1 {
        self.operation
    }

    /// Return the exact requested source range.
    #[must_use]
    pub const fn range(&self) -> SeqRange {
        self.range
    }

    /// Return the canonical requested consumer identifiers.
    #[must_use]
    pub fn consumer_ids(&self) -> &[String] {
        &self.consumer_ids
    }

    /// Return the exact optional-view roots requested for this use.
    #[must_use]
    pub fn requested_optional_view_roots(&self) -> &[Hash] {
        &self.requested_optional_view_roots
    }

    pub(crate) fn is_covered_by(&self, closure: &WorldReplayClosureV1) -> bool {
        self.timeline_id == closure.timeline_id()
            && self.consumer_ids.iter().all(|requested| {
                closure
                    .consumer_set()
                    .consumers()
                    .iter()
                    .any(|recorded| recorded.consumer_id() == requested)
            })
            && self.requested_optional_view_roots.iter().all(|requested| {
                closure
                    .consumer_set()
                    .optional_view_roots()
                    .contains(requested)
            })
    }
}

/// An opaque host-issued World Replay result.
///
/// The fields are private and there is no public constructor.  A caller may
/// submit an untrusted structural closure to the installed verifier, but it
/// cannot fabricate the result consumed by protected read paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedWorldReplayV1 {
    closure_digest: Hash,
    timeline_id: TimelineId,
    source_head: Hash,
    inventory_generation: ErasureReferenceV1,
    replay_claim: ErasureReplayClaimV1,
    requested_use: WorldReplayUseV1,
    authorized_optional_view_roots: Vec<Hash>,
    read_bounds: EventReadBounds,
}

impl VerifiedWorldReplayV1 {
    /// Return the exact closure identity verified by the host.
    #[must_use]
    pub const fn closure_digest(&self) -> Hash {
        self.closure_digest
    }

    /// Return the Timeline covered by this result.
    #[must_use]
    pub const fn timeline_id(&self) -> TimelineId {
        self.timeline_id
    }

    /// Return the source head bound by the verified closure.
    #[must_use]
    pub const fn source_head(&self) -> Hash {
        self.source_head
    }

    /// Return the host inventory generation at verification time.
    #[must_use]
    pub const fn inventory_generation(&self) -> ErasureReferenceV1 {
        self.inventory_generation
    }

    /// Return the finite owner-verified bounds for materializing this use.
    #[must_use]
    pub const fn read_bounds(&self) -> EventReadBounds {
        self.read_bounds
    }

    pub(crate) const fn has_finite_read_bounds(&self) -> bool {
        let bounds = self.read_bounds;
        finite_usize(bounds.max_payload_bytes())
            && finite_usize(bounds.max_event_type_bytes())
            && finite_usize(bounds.max_fork_depth())
            && finite_usize(bounds.max_events())
            && finite_usize(bounds.max_total_bytes())
            && bounds.max_elapsed_micros() != 0
            && bounds.max_elapsed_micros() != u64::MAX
    }

    /// Require an Exact claim before protected materialization.
    ///
    /// # Errors
    /// Returns [`WorldReplayVerificationErrorV1::ClaimUnavailable`] when the
    /// installed owner reports an expired, erased, structurally limited, or
    /// otherwise non-authoritative result. Optional-view redaction remains an
    /// authoritative claim under ADR-060.
    pub fn require_authoritative_use(&self) -> Result<(), WorldReplayVerificationErrorV1> {
        if matches!(
            self.replay_claim,
            ErasureReplayClaimV1::Exact | ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews
        ) && self
            .requested_use
            .requested_optional_view_roots()
            .iter()
            .all(|root| self.authorized_optional_view_roots.contains(root))
        {
            Ok(())
        } else {
            Err(WorldReplayVerificationErrorV1::ClaimUnavailable)
        }
    }

    pub(crate) const fn requested_use(&self) -> &WorldReplayUseV1 {
        &self.requested_use
    }
}

const fn finite_usize(value: usize) -> bool {
    value != 0 && value != usize::MAX
}

/// Construct a verified result for an explicitly enabled downstream seam
/// test.
///
/// This helper is unavailable from the normal dependency graph. Production
/// code receives [`VerifiedWorldReplayV1`] only from an installed verifier.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn test_verified_world_replay(
    closure: &WorldReplayClosureV1,
    requested_use: &WorldReplayUseV1,
    inventory_generation: ErasureReferenceV1,
    replay_claim: ErasureReplayClaimV1,
) -> VerifiedWorldReplayV1 {
    test_verified_world_replay_with_fields_and_bounds(
        closure.digest(),
        closure.timeline_id(),
        closure.source_head(),
        requested_use.clone(),
        inventory_generation,
        replay_claim,
        TEST_WORLD_REPLAY_READ_BOUNDS,
    )
}

/// Construct a verifier result with explicit fields for runtime seam tests.
///
/// The function is available only to the crate's tests or to a dependency
/// that explicitly enables the `test-support` feature.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub const fn test_verified_world_replay_with_fields(
    closure_digest: Hash,
    timeline_id: TimelineId,
    source_head: Hash,
    requested_use: WorldReplayUseV1,
    inventory_generation: ErasureReferenceV1,
    replay_claim: ErasureReplayClaimV1,
) -> VerifiedWorldReplayV1 {
    test_verified_world_replay_with_fields_and_bounds(
        closure_digest,
        timeline_id,
        source_head,
        requested_use,
        inventory_generation,
        replay_claim,
        TEST_WORLD_REPLAY_READ_BOUNDS,
    )
}

/// Construct a verifier result with explicit bindings and read bounds for
/// downstream seam tests.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub const fn test_verified_world_replay_with_fields_and_bounds(
    closure_digest: Hash,
    timeline_id: TimelineId,
    source_head: Hash,
    requested_use: WorldReplayUseV1,
    inventory_generation: ErasureReferenceV1,
    replay_claim: ErasureReplayClaimV1,
    read_bounds: EventReadBounds,
) -> VerifiedWorldReplayV1 {
    VerifiedWorldReplayV1 {
        closure_digest,
        timeline_id,
        source_head,
        inventory_generation,
        replay_claim,
        requested_use,
        authorized_optional_view_roots: Vec::new(),
        read_bounds,
    }
}

/// Attach explicit per-view authorization to a downstream seam-test result.
/// The actual owner must verify each root's current claim before minting this result.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn test_verified_world_replay_with_authorized_views(
    mut verified: VerifiedWorldReplayV1,
    authorized_optional_view_roots: Vec<Hash>,
) -> VerifiedWorldReplayV1 {
    verified.authorized_optional_view_roots = authorized_optional_view_roots;
    verified
}

/// Installed native World Replay verifier.
///
/// The trait is a composition-root seam, not a caller-side claim API.  The
/// returned capability has a private constructor, so third-party code cannot
/// implement a verifier that returns a fabricated successful result.  Until a
/// deployment installs the approved native owners, the closed composition
/// rejects the request.
pub trait WorldReplayVerifierV1: Send + Sync {
    /// Verify the complete native closure against the installed generation.
    ///
    /// # Errors
    /// Returns a closed provenance, dependency, source, lease, or generation
    /// error when exact evidence is unavailable.
    fn verify(
        &self,
        closure: &WorldReplayClosureV1,
        requested_use: &WorldReplayUseV1,
        inventory_generation: ErasureReferenceV1,
    ) -> Result<VerifiedWorldReplayV1, WorldReplayVerificationErrorV1>;
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected World Replay fixture error: {error:?}"
                )))
            })
        }
    }

    #[test]
    fn verified_result_exposes_bindings_and_requires_an_exact_claim() {
        let closure = WorldReplayClosureV1::test_fixture().test_ok();
        let generation = ErasureReferenceV1::from_digest([63; 32]);
        let requested_use = WorldReplayUseV1::new(
            closure.timeline_id(),
            ErasureProtectedOperationV1::Read,
            SeqRange::all(),
            vec!["count".to_owned()],
        )
        .test_ok();
        let exact = test_verified_world_replay(
            &closure,
            &requested_use,
            generation,
            ErasureReplayClaimV1::Exact,
        );
        assert_eq!(exact.closure_digest(), closure.digest());
        assert_eq!(exact.timeline_id(), closure.timeline_id());
        assert_eq!(exact.source_head(), closure.source_head());
        assert_eq!(exact.inventory_generation(), generation);
        assert_eq!(exact.requested_use(), &requested_use);
        assert_eq!(exact.read_bounds(), TEST_WORLD_REPLAY_READ_BOUNDS);
        assert!(exact.has_finite_read_bounds());
        assert_eq!(exact.require_authoritative_use(), Ok(()));

        let redacted = test_verified_world_replay(
            &closure,
            &requested_use,
            generation,
            ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
        );
        assert_eq!(redacted.require_authoritative_use(), Ok(()));

        let structural = test_verified_world_replay_with_fields(
            closure.digest(),
            closure.timeline_id(),
            closure.source_head(),
            requested_use,
            generation,
            ErasureReplayClaimV1::StructuralOnly,
        );
        assert_eq!(
            structural.require_authoritative_use(),
            Err(WorldReplayVerificationErrorV1::ClaimUnavailable)
        );
    }

    #[test]
    fn requested_use_rejects_invalid_consumer_selections() {
        let timeline = TimelineId::new();
        for consumers in [
            Vec::new(),
            vec!["count".to_owned(), "count".to_owned()],
            vec!["x".repeat(
                pos_core::world_consumer_set::WORLD_CONSUMER_SET_MAX_CONSUMER_ID_BYTES + 1,
            )],
        ] {
            assert_eq!(
                WorldReplayUseV1::new(
                    timeline,
                    ErasureProtectedOperationV1::Read,
                    SeqRange::all(),
                    consumers,
                ),
                Err(WorldReplayVerificationErrorV1::RequestMismatch)
            );
        }
        assert_eq!(
            WorldReplayUseV1::new(
                timeline,
                ErasureProtectedOperationV1::Read,
                SeqRange::bounded(pos_core::Seq::from_u64(2), pos_core::Seq::from_u64(1)),
                vec!["count".to_owned()],
            ),
            Err(WorldReplayVerificationErrorV1::RequestMismatch)
        );
    }

    #[test]
    fn optional_view_use_requires_exact_per_root_authorization() {
        let closure = WorldReplayClosureV1::test_fixture().test_ok();
        let generation = ErasureReferenceV1::from_digest([63; 32]);
        let root = Hash::from_bytes([53; 32]);
        let request = WorldReplayUseV1::new_with_optional_views(
            closure.timeline_id(),
            ErasureProtectedOperationV1::Read,
            SeqRange::all(),
            vec!["count".to_owned()],
            vec![root],
        )
        .test_ok();
        assert_eq!(request.requested_optional_view_roots(), &[root]);
        assert!(request.is_covered_by(&closure));
        let unverified =
            test_verified_world_replay(&closure, &request, generation, ErasureReplayClaimV1::Exact);
        assert_eq!(
            unverified.require_authoritative_use(),
            Err(WorldReplayVerificationErrorV1::ClaimUnavailable)
        );
        let authorized = test_verified_world_replay_with_authorized_views(
            test_verified_world_replay(
                &closure,
                &request,
                generation,
                ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
            ),
            vec![root],
        );
        assert_eq!(authorized.require_authoritative_use(), Ok(()));
        let unavailable = test_verified_world_replay_with_authorized_views(
            test_verified_world_replay(
                &closure,
                &request,
                generation,
                ErasureReplayClaimV1::StructuralOnly,
            ),
            vec![root],
        );
        assert_eq!(
            unavailable.require_authoritative_use(),
            Err(WorldReplayVerificationErrorV1::ClaimUnavailable)
        );

        for roots in [vec![Hash::zero()], vec![root, root]] {
            assert_eq!(
                WorldReplayUseV1::new_with_optional_views(
                    closure.timeline_id(),
                    ErasureProtectedOperationV1::Read,
                    SeqRange::all(),
                    vec!["count".to_owned()],
                    roots,
                ),
                Err(WorldReplayVerificationErrorV1::RequestMismatch)
            );
        }
        let unknown = WorldReplayUseV1::new_with_optional_views(
            closure.timeline_id(),
            ErasureProtectedOperationV1::Read,
            SeqRange::all(),
            vec!["count".to_owned()],
            vec![Hash::from_bytes([54; 32])],
        )
        .test_ok();
        assert!(!unknown.is_covered_by(&closure));
    }
}
