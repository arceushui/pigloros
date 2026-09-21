//! Runtime-owned World Replay verification capabilities.
//!
//! [`pos_core::WorldReplayClosureV1`] is deliberately structural.  It can be
//! decoded and checked for immutable shape, but it cannot mint a Replay claim.
//! The runtime owns the installed verifier boundary and the opaque verified
//! result used by protected Replay, Snapshot, and comparison operations.

use pos_core::{ErasureReferenceV1, ErasureReplayClaimV1, Hash, TimelineId, WorldReplayClosureV1};

/// Closed reasons why an installed World Replay verifier could not issue a
/// protected-use capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorldReplayVerificationErrorV1 {
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

    /// Require an Exact claim before protected materialization.
    ///
    /// # Errors
    /// Returns [`WorldReplayVerificationErrorV1::ClaimUnavailable`] when the
    /// installed owner reports an expired, erased, redacted, or otherwise
    /// non-authoritative result.
    pub const fn require_authoritative_use(&self) -> Result<(), WorldReplayVerificationErrorV1> {
        if matches!(self.replay_claim, ErasureReplayClaimV1::Exact) {
            Ok(())
        } else {
            Err(WorldReplayVerificationErrorV1::ClaimUnavailable)
        }
    }
}

/// Construct a verified result for an explicitly enabled downstream seam
/// test.
///
/// This helper is unavailable from the normal dependency graph. Production
/// code receives [`VerifiedWorldReplayV1`] only from an installed verifier.
#[cfg(any(test, feature = "test-support"))]
pub fn test_verified_world_replay(
    closure: &WorldReplayClosureV1,
    inventory_generation: ErasureReferenceV1,
    replay_claim: ErasureReplayClaimV1,
) -> VerifiedWorldReplayV1 {
    test_verified_world_replay_with_fields(
        closure.digest(),
        closure.timeline_id(),
        closure.source_head(),
        inventory_generation,
        replay_claim,
    )
}

/// Construct a verifier result with explicit fields for runtime seam tests.
///
/// The function is available only to the crate's tests or to a dependency
/// that explicitly enables the `test-support` feature.
#[cfg(any(test, feature = "test-support"))]
pub fn test_verified_world_replay_with_fields(
    closure_digest: Hash,
    timeline_id: TimelineId,
    source_head: Hash,
    inventory_generation: ErasureReferenceV1,
    replay_claim: ErasureReplayClaimV1,
) -> VerifiedWorldReplayV1 {
    VerifiedWorldReplayV1 {
        closure_digest,
        timeline_id,
        source_head,
        inventory_generation,
        replay_claim,
    }
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
        let exact = test_verified_world_replay(&closure, generation, ErasureReplayClaimV1::Exact);
        assert_eq!(exact.closure_digest(), closure.digest());
        assert_eq!(exact.timeline_id(), closure.timeline_id());
        assert_eq!(exact.source_head(), closure.source_head());
        assert_eq!(exact.inventory_generation(), generation);
        assert_eq!(exact.require_authoritative_use(), Ok(()));

        let structural = test_verified_world_replay_with_fields(
            closure.digest(),
            closure.timeline_id(),
            closure.source_head(),
            generation,
            ErasureReplayClaimV1::StructuralOnly,
        );
        assert_eq!(
            structural.require_authoritative_use(),
            Err(WorldReplayVerificationErrorV1::ClaimUnavailable)
        );
    }
}
