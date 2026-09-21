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
