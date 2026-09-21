//! Host-owned admission for retained World Replay claims.
//!
//! The structural WAL1, WCS1, RTP1, and RLS1 records describe a possible
//! closure, but none of those records grant read authority on their own. This
//! module joins those records at one small seam and requires a host-owned
//! authority to report the current clock and every artifact state before a
//! Replay claim can be used.

use crate::retention::{WorldRetentionLeaseV1, WorldRetentionPolicyV1};
use crate::{
    ArtifactClaimInputV1, ArtifactStateV1, ErasureArtifactClassV1, ErasureErrorV1,
    ErasureReferenceV1, ErasureReplayClaimV1, Hash, ReplayClaimEvaluationV1,
    ReplayClaimEvaluatorV1, TimelineId, WallTime, WorldArtifactKindV1, WorldArtifactLeafV1,
    WorldConsumerSetV1,
};

/// Maximum number of native artifact leaves in one retained World closure.
pub const MAX_WORLD_REPLAY_ARTIFACTS_V1: usize = 4096;

const REQUIRED_KINDS: [WorldArtifactKindV1; 13] = [
    WorldArtifactKindV1::OutputPolicy,
    WorldArtifactKindV1::ExecutableBudgetPolicy,
    WorldArtifactKindV1::RetentionPolicy,
    WorldArtifactKindV1::RetentionLease,
    WorldArtifactKindV1::BaseConfiguration,
    WorldArtifactKindV1::ExecutionProfile,
    WorldArtifactKindV1::AudiencePolicy,
    WorldArtifactKindV1::Schema,
    WorldArtifactKindV1::ReducerImplementation,
    WorldArtifactKindV1::RuntimeIdentity,
    WorldArtifactKindV1::PluginImplementationIdentity,
    WorldArtifactKindV1::KeyDependencyEvidence,
    WorldArtifactKindV1::TimelinePayload,
];

const CLOSURE_DOMAIN: &[u8] = b"pigloros.world-replay-closure.v1\0";

/// Fail-closed errors at the retained World Replay seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorldReplayClosureErrorV1 {
    /// The closure contained no leaves or exceeded its fixed bound.
    #[error("World Replay closure artifact count is out of bounds")]
    ArtifactCountOutOfBounds,
    /// The lease belongs to a different Timeline.
    #[error("World Replay lease belongs to a different Timeline")]
    LeaseTimelineMismatch,
    /// The lease does not bind the supplied retention policy.
    #[error("World Replay lease and policy identities do not match")]
    PolicyMismatch,
    /// A leaf is outside the closure's consumer-set scope.
    #[error("World Replay artifact is outside the consumer-set scope")]
    ScopeMismatch,
    /// A required structural kind was not recorded.
    #[error("World Replay closure is missing a required artifact kind")]
    MissingRequiredArtifact,
    /// A kind/digest identity was listed more than once.
    #[error("World Replay closure contains a duplicate artifact identity")]
    DuplicateArtifact,
    /// A leaf has no host owner or native bytes.
    #[error("World Replay artifact has no host owner or native bytes")]
    UnownedArtifact,
    /// A consumer or producer points at an absent native leaf.
    #[error("World Replay consumer or producer points at a missing artifact")]
    MissingConsumerArtifact,
    /// The retention clock or artifact authority could not be read.
    #[error("World Replay artifact authority is unavailable")]
    AuthorityUnavailable,
    /// The current artifact closure cannot support an authoritative claim.
    #[error("World Replay claim is not authoritative")]
    ClaimUnavailable,
    /// The core evaluator rejected the assembled closure.
    #[error("World Replay closure could not be evaluated")]
    EvaluationRejected,
}

/// Untrusted closure input assembled by a recorder or persistence adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldReplayClosureInputV1 {
    /// Timeline whose retained history is being claimed.
    pub timeline_id: TimelineId,
    /// Exact RTP1 record bound to the lease.
    pub retention_policy: WorldRetentionPolicyV1,
    /// Exact RLS1 record that fixes the finite retention horizon.
    pub retention_lease: WorldRetentionLeaseV1,
    /// Exact WCS1 producer/consumer selector for this closure.
    pub consumer_set: WorldConsumerSetV1,
    /// WAL1 leaves required to reconstruct the recorded World history.
    pub artifacts: Vec<WorldArtifactLeafV1>,
}

/// One validated, immutable retained World closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldReplayClosureV1 {
    timeline_id: TimelineId,
    retention_policy: WorldRetentionPolicyV1,
    retention_lease: WorldRetentionLeaseV1,
    consumer_set: WorldConsumerSetV1,
    artifacts: Vec<WorldArtifactLeafV1>,
}

impl WorldReplayClosureV1 {
    /// Validate identities, scope, required kinds, and consumer references.
    ///
    /// This method only validates immutable structure. Current availability and
    /// authorization are deliberately deferred to [`Self::admit`].
    ///
    /// # Errors
    /// Returns a closed error when the closure is empty or oversized, its
    /// retention identities disagree, a leaf is out of scope or unowned, a
    /// required kind is absent, or a consumer-set reference is missing.
    pub fn new(input: WorldReplayClosureInputV1) -> Result<Self, WorldReplayClosureErrorV1> {
        if input.artifacts.is_empty() || input.artifacts.len() > MAX_WORLD_REPLAY_ARTIFACTS_V1 {
            return Err(WorldReplayClosureErrorV1::ArtifactCountOutOfBounds);
        }
        let lease_input = input.retention_lease.as_input();
        if lease_input.timeline_id != input.timeline_id {
            return Err(WorldReplayClosureErrorV1::LeaseTimelineMismatch);
        }
        if lease_input.policy_hash != input.retention_policy.digest() {
            return Err(WorldReplayClosureErrorV1::PolicyMismatch);
        }
        let lease_digest = input.retention_lease.digest();
        let scope = input.consumer_set.scope();
        let mut artifacts = input.artifacts;
        artifacts.sort_unstable_by_key(|leaf| {
            (leaf.as_input().kind.code(), leaf.as_input().native_digest)
        });
        if artifacts.windows(2).any(|pair| {
            pair[0].as_input().kind == pair[1].as_input().kind
                && pair[0].as_input().native_digest == pair[1].as_input().native_digest
        }) {
            return Err(WorldReplayClosureErrorV1::DuplicateArtifact);
        }
        if artifacts.iter().any(|leaf| {
            let input = leaf.as_input();
            input.scope != scope || input.source_lease_hash != lease_digest
        }) {
            return Err(WorldReplayClosureErrorV1::ScopeMismatch);
        }
        if artifacts.iter().any(|leaf| {
            let input = leaf.as_input();
            input.owner == [0; 32] || input.native_byte_length == 0
        }) {
            return Err(WorldReplayClosureErrorV1::UnownedArtifact);
        }
        if REQUIRED_KINDS
            .iter()
            .any(|kind| !artifacts.iter().any(|leaf| leaf.as_input().kind == *kind))
        {
            return Err(WorldReplayClosureErrorV1::MissingRequiredArtifact);
        }
        if !has_identity(
            &artifacts,
            WorldArtifactKindV1::RetentionPolicy,
            input.retention_policy.digest(),
        ) || !has_identity(
            &artifacts,
            WorldArtifactKindV1::RetentionLease,
            input.retention_lease.digest(),
        ) {
            return Err(WorldReplayClosureErrorV1::PolicyMismatch);
        }
        if input.consumer_set.consumers().iter().any(|consumer| {
            !has_identity(
                &artifacts,
                WorldArtifactKindV1::ReducerImplementation,
                consumer.reducer_hash(),
            ) || !has_identity(
                &artifacts,
                WorldArtifactKindV1::Schema,
                consumer.schema_hash(),
            ) || !has_identity(
                &artifacts,
                WorldArtifactKindV1::RuntimeIdentity,
                consumer.runtime_hash(),
            )
        }) || input.consumer_set.producers().iter().any(|producer| {
            !has_identity(
                &artifacts,
                WorldArtifactKindV1::OutputPolicy,
                producer.output_policy_hash(),
            )
        }) || input
            .consumer_set
            .optional_view_roots()
            .iter()
            .any(|root| !has_identity(&artifacts, WorldArtifactKindV1::OptionalView, *root))
        {
            return Err(WorldReplayClosureErrorV1::MissingConsumerArtifact);
        }
        Ok(Self {
            timeline_id: input.timeline_id,
            retention_policy: input.retention_policy,
            retention_lease: input.retention_lease,
            consumer_set: input.consumer_set,
            artifacts,
        })
    }

    /// Return the Timeline bound to this closure.
    #[must_use]
    pub const fn timeline_id(&self) -> TimelineId {
        self.timeline_id
    }

    /// Return the canonical closure identity used in Replay receipts.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CLOSURE_DOMAIN);
        hasher.update(&self.timeline_id.inner().to_bytes());
        hasher.update(&self.retention_policy.to_canonical_cbor());
        hasher.update(&self.retention_lease.to_canonical_cbor());
        hasher.update(self.consumer_set.encode().as_slice());
        for leaf in &self.artifacts {
            hasher.update(leaf.digest().as_bytes());
        }
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Return the validated immutable leaves in canonical identity order.
    #[must_use]
    pub fn artifacts(&self) -> &[WorldArtifactLeafV1] {
        &self.artifacts
    }

    /// Admit the closure against a host-owned clock and artifact authority.
    ///
    /// The authority is the only source of current time and artifact state.
    /// Callers cannot turn structural WAL1 metadata into an Exact claim by
    /// supplying a hand-written state snapshot.
    ///
    /// # Errors
    /// Returns a closed error when the authority cannot provide trusted time
    /// or artifact state, or when the evaluated closure is not admissible.
    pub fn admit(
        &self,
        authority: &mut dyn WorldReplayClosureAuthorityV1,
    ) -> Result<WorldReplayAdmissionV1, WorldReplayClosureErrorV1> {
        let now = authority
            .now()
            .map_err(|_| WorldReplayClosureErrorV1::AuthorityUnavailable)?;
        let expired = now.as_micros() >= self.retention_lease.as_input().retention_deadline_micros;
        let mut claims = Vec::with_capacity(self.artifacts.len());
        for leaf in &self.artifacts {
            let state = if expired {
                ArtifactStateV1::MissingParentCut
            } else {
                authority
                    .artifact_state(leaf)
                    .map_err(|_| WorldReplayClosureErrorV1::AuthorityUnavailable)?
            };
            claims.push(ArtifactClaimInputV1 {
                registration: crate::RegisteredArtifactV1::new(
                    ErasureArtifactClassV1::TimelineReplay,
                    ErasureReferenceV1::from_digest(*leaf.as_input().native_digest.as_bytes()),
                    leaf.as_input().data_class,
                    None,
                    ErasureReferenceV1::from_digest(leaf.as_input().owner),
                    leaf.as_input().optionality,
                    leaf.as_input().transition,
                ),
                current_claim: ErasureReplayClaimV1::Exact,
                state,
            });
        }
        let evaluation = ReplayClaimEvaluatorV1::evaluate(ErasureReplayClaimV1::Exact, &claims)
            .map_err(|_| WorldReplayClosureErrorV1::EvaluationRejected)?;
        Ok(WorldReplayAdmissionV1 {
            closure_digest: self.digest(),
            evaluation,
        })
    }
}

fn has_identity(
    artifacts: &[WorldArtifactLeafV1],
    kind: WorldArtifactKindV1,
    digest: Hash,
) -> bool {
    artifacts
        .iter()
        .any(|leaf| leaf.as_input().kind == kind && leaf.as_input().native_digest == digest)
}

/// Host-owned source of current time and artifact availability.
pub trait WorldReplayClosureAuthorityV1 {
    /// Return the current trusted clock value.
    ///
    /// # Errors
    /// Returns a payload-free authority or provenance error when the host
    /// cannot establish the current trusted time.
    fn now(&mut self) -> Result<WallTime, ErasureErrorV1>;

    /// Return the current state of one registered native artifact.
    ///
    /// # Errors
    /// Returns a payload-free authority or provenance error when the host
    /// cannot verify the artifact's current disposition.
    fn artifact_state(
        &mut self,
        artifact: &WorldArtifactLeafV1,
    ) -> Result<ArtifactStateV1, ErasureErrorV1>;
}

/// An admitted closure and its monotonic Replay claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldReplayAdmissionV1 {
    closure_digest: Hash,
    evaluation: ReplayClaimEvaluationV1,
}

impl WorldReplayAdmissionV1 {
    /// Return the exact closure identity used for this admission.
    #[must_use]
    pub const fn closure_digest(&self) -> Hash {
        self.closure_digest
    }

    /// Return the evaluated claim and per-artifact transitions.
    #[must_use]
    pub const fn evaluation(&self) -> &ReplayClaimEvaluationV1 {
        &self.evaluation
    }

    /// Require the admitted closure to support authoritative Replay.
    ///
    /// # Errors
    /// Returns [`WorldReplayClosureErrorV1::ClaimUnavailable`] when expiry,
    /// erasure, or another required artifact state weakened the claim.
    pub const fn require_authoritative_use(&self) -> Result<(), WorldReplayClosureErrorV1> {
        if matches!(
            self.evaluation.replay_claim(),
            ErasureReplayClaimV1::Exact | ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews
        ) {
            Ok(())
        } else {
            Err(WorldReplayClosureErrorV1::ClaimUnavailable)
        }
    }
}
