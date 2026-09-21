//! Host-owned admission for retained World Replay claims.
//!
//! The structural WAL1, WCS1, RTP1, and RLS1 records describe a possible
//! closure, but none of those records grant read authority on their own. This
//! module joins those records at one small seam and requires a host-owned
//! authority to report the current clock and every artifact state before a
//! Replay claim can be used.

use crate::retention::{WorldRetentionLeaseV1, WorldRetentionPolicyV1};
use crate::{Hash, TimelineId, WorldArtifactKindV1, WorldArtifactLeafV1, WorldConsumerSetV1};

#[cfg(feature = "test-support")]
use crate::{
    ArtifactClaimInputV1, ArtifactStateV1, ErasureArtifactClassV1, ErasureErrorV1,
    ErasureReferenceV1, ErasureReplayClaimV1, PluginId, ReplayClaimEvaluationV1,
    ReplayClaimEvaluatorV1, WallTime,
};
#[cfg(feature = "test-support")]
use ulid::Ulid;

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
    /// The closure is missing an operation, source-head, or inventory identity.
    #[error("World Replay closure is missing a binding identity")]
    BindingIdentityMissing,
    /// The trusted native verifier returned a different content identity.
    #[error("World Replay native artifact identity does not match its recorded digest")]
    NativeDigestMismatch,
    /// The trusted native verifier could not establish an artifact identity.
    #[error("World Replay native artifact verification is unavailable")]
    NativeVerificationUnavailable,
    /// The finite retention lease has expired.
    #[error("World Replay retention lease has expired")]
    RetentionExpired,
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
    /// Stable operation identity assigned by the recording owner.
    pub operation_identity: Hash,
    /// Exact source/head identity covered by this closure.
    pub source_head: Hash,
    /// Installed host inventory generation used to verify this closure.
    pub inventory_generation: Hash,
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
    operation_identity: Hash,
    source_head: Hash,
    inventory_generation: Hash,
    retention_policy: WorldRetentionPolicyV1,
    retention_lease: WorldRetentionLeaseV1,
    consumer_set: WorldConsumerSetV1,
    artifacts: Vec<WorldArtifactLeafV1>,
}

impl WorldReplayClosureV1 {
    /// Validate identities, scope, required kinds, and consumer references.
    ///
    /// This method only validates immutable structure. Production availability
    /// and authorization are owned by the runtime verifier; the old
    /// test-support admission helper is intentionally unavailable to a normal
    /// production dependency graph.
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
        if input.operation_identity == Hash::zero()
            || input.source_head == Hash::zero()
            || input.inventory_generation == Hash::zero()
        {
            return Err(WorldReplayClosureErrorV1::BindingIdentityMissing);
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
            operation_identity: input.operation_identity,
            source_head: input.source_head,
            inventory_generation: input.inventory_generation,
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

    /// Return the recording operation identity bound to this closure.
    #[must_use]
    pub const fn operation_identity(&self) -> Hash {
        self.operation_identity
    }

    /// Return the exact source/head identity covered by this closure.
    #[must_use]
    pub const fn source_head(&self) -> Hash {
        self.source_head
    }

    /// Return the installed inventory generation used by this closure.
    #[must_use]
    pub const fn inventory_generation(&self) -> Hash {
        self.inventory_generation
    }

    /// Return the canonical closure identity used in Replay receipts.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CLOSURE_DOMAIN);
        hasher.update(&self.timeline_id.inner().to_bytes());
        hasher.update(self.operation_identity.as_bytes());
        hasher.update(self.source_head.as_bytes());
        hasher.update(self.inventory_generation.as_bytes());
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

    /// Build a deterministic complete closure for downstream seam tests.
    ///
    /// This helper is available only with the explicit `test-support` feature;
    /// production callers must obtain a closure from their recording owner.
    #[cfg(feature = "test-support")]
    pub fn test_fixture() -> Result<Self, WorldReplayClosureErrorV1> {
        const DAY_MICROS: u64 = 86_400_000_000;
        let timeline_id = TimelineId::from_ulid(Ulid::from(1_u128));
        let retention_policy = crate::retention::WorldRetentionPolicyV1::new(
            crate::retention::WorldRetentionPolicyInputV1 {
                policy_revision: 1,
                purpose: "world-replay".to_owned(),
                audience_policy_hash: Hash::from_bytes([10; 32]),
                minimum_post_admission_days: 90,
                maximum_active_days: 30,
                maximum_total_days: 120,
            },
        )
        .map_err(|_| WorldReplayClosureErrorV1::EvaluationRejected)?;
        let retention_lease = crate::retention::WorldRetentionLeaseV1::new(
            &retention_policy,
            crate::retention::WorldRetentionLeaseInputV1 {
                timeline_id,
                policy_hash: retention_policy.digest(),
                started_at_micros: 0,
                admission_closes_at_micros: 30 * DAY_MICROS,
                retention_deadline_micros: 120 * DAY_MICROS,
            },
        )
        .map_err(|_| WorldReplayClosureErrorV1::EvaluationRejected)?;
        let scope = Hash::from_bytes([9; 32]);
        let consumer_set =
            WorldConsumerSetV1::new(crate::world_consumer_set::WorldConsumerSetInputV1 {
                scope,
                consumers: vec![crate::world_consumer_set::WorldConsumerV1::new(
                    "entity-state".to_owned(),
                    Hash::from_bytes([40; 32]),
                    Hash::from_bytes([41; 32]),
                    Hash::from_bytes([42; 32]),
                )
                .map_err(|_| WorldReplayClosureErrorV1::EvaluationRejected)?],
                producers: vec![crate::world_consumer_set::WorldProducerV1::new(
                    PluginId::from_ulid(Ulid::from(1_u128)),
                    Hash::from_bytes([43; 32]),
                )
                .map_err(|_| WorldReplayClosureErrorV1::EvaluationRejected)?],
                optional_view_roots: vec![Hash::from_bytes([53; 32])],
            })
            .map_err(|_| WorldReplayClosureErrorV1::EvaluationRejected)?;
        let kinds = [
            (
                WorldArtifactKindV1::OutputPolicy,
                Hash::from_bytes([43; 32]),
            ),
            (
                WorldArtifactKindV1::ExecutableBudgetPolicy,
                Hash::from_bytes([44; 32]),
            ),
            (
                WorldArtifactKindV1::RetentionPolicy,
                retention_policy.digest(),
            ),
            (
                WorldArtifactKindV1::RetentionLease,
                retention_lease.digest(),
            ),
            (
                WorldArtifactKindV1::BaseConfiguration,
                Hash::from_bytes([45; 32]),
            ),
            (
                WorldArtifactKindV1::ExecutionProfile,
                Hash::from_bytes([46; 32]),
            ),
            (
                WorldArtifactKindV1::AudiencePolicy,
                Hash::from_bytes([47; 32]),
            ),
            (WorldArtifactKindV1::Schema, Hash::from_bytes([41; 32])),
            (
                WorldArtifactKindV1::ReducerImplementation,
                Hash::from_bytes([40; 32]),
            ),
            (
                WorldArtifactKindV1::RuntimeIdentity,
                Hash::from_bytes([42; 32]),
            ),
            (
                WorldArtifactKindV1::PluginImplementationIdentity,
                Hash::from_bytes([48; 32]),
            ),
            (
                WorldArtifactKindV1::KeyDependencyEvidence,
                Hash::from_bytes([49; 32]),
            ),
            (
                WorldArtifactKindV1::TimelinePayload,
                Hash::from_bytes([50; 32]),
            ),
            (
                WorldArtifactKindV1::OptionalView,
                Hash::from_bytes([53; 32]),
            ),
        ];
        let artifacts = kinds
            .into_iter()
            .enumerate()
            .map(|(index, (kind, native_digest))| {
                let owner_offset = u8::try_from(index)
                    .map_err(|_| WorldReplayClosureErrorV1::ArtifactCountOutOfBounds)?;
                WorldArtifactLeafV1::new(crate::world_artifact::WorldArtifactLeafInputV1 {
                    scope,
                    kind,
                    native_digest,
                    native_byte_length: 1,
                    owner: [100 + owner_offset; 32],
                    data_class: crate::ArtifactDataClassV1::StructuralAuditMetadata,
                    optionality: if kind == WorldArtifactKindV1::OptionalView {
                        crate::ArtifactOptionalityV1::Optional
                    } else {
                        crate::ArtifactOptionalityV1::Required
                    },
                    transition: if kind == WorldArtifactKindV1::OptionalView {
                        crate::ArtifactTransitionRuleV1::RedactViews
                    } else {
                        crate::ArtifactTransitionRuleV1::PreserveExact
                    },
                    source_lease_hash: retention_lease.digest(),
                    key_dependencies: Vec::new(),
                    child_node_hashes: Vec::new(),
                })
                .map_err(|_| WorldReplayClosureErrorV1::EvaluationRejected)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(WorldReplayClosureInputV1 {
            timeline_id,
            operation_identity: Hash::from_bytes([60; 32]),
            source_head: Hash::from_bytes([61; 32]),
            inventory_generation: Hash::from_bytes([62; 32]),
            retention_policy,
            retention_lease,
            consumer_set,
            artifacts,
        })
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
    #[cfg(feature = "test-support")]
    pub fn admit(
        &self,
        authority: &mut dyn WorldReplayClosureAuthorityV1,
    ) -> Result<WorldReplayAdmissionV1, WorldReplayClosureErrorV1> {
        let now = authority
            .now()
            .map_err(|_| WorldReplayClosureErrorV1::AuthorityUnavailable)?;
        if now.as_micros() >= self.retention_lease.as_input().retention_deadline_micros {
            return Err(WorldReplayClosureErrorV1::RetentionExpired);
        }
        let mut claims = Vec::with_capacity(self.artifacts.len());
        for leaf in &self.artifacts {
            let verified_digest = authority
                .verify_native_artifact(leaf)
                .map_err(|_| WorldReplayClosureErrorV1::NativeVerificationUnavailable)?;
            if verified_digest != leaf.as_input().native_digest {
                return Err(WorldReplayClosureErrorV1::NativeDigestMismatch);
            }
            let state = authority
                .artifact_state(leaf)
                .map_err(|_| WorldReplayClosureErrorV1::AuthorityUnavailable)?;
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
            optional_view_roots: self.consumer_set.optional_view_roots().to_vec(),
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
#[cfg(feature = "test-support")]
pub trait WorldReplayClosureAuthorityV1 {
    /// Return the current trusted clock value.
    ///
    /// # Errors
    /// Returns a payload-free authority or provenance error when the host
    /// cannot establish the current trusted time.
    fn now(&mut self) -> Result<WallTime, ErasureErrorV1>;

    /// Verify the native bytes and dependency identity for one leaf.
    ///
    /// # Errors
    /// Returns a payload-free authority or provenance error when the installed
    /// native owner cannot verify the recorded identity.
    fn verify_native_artifact(
        &mut self,
        artifact: &WorldArtifactLeafV1,
    ) -> Result<Hash, ErasureErrorV1>;

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
#[cfg(feature = "test-support")]
pub struct WorldReplayAdmissionV1 {
    closure_digest: Hash,
    evaluation: ReplayClaimEvaluationV1,
    optional_view_roots: Vec<Hash>,
}

#[cfg(feature = "test-support")]
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
        if matches!(self.evaluation.replay_claim(), ErasureReplayClaimV1::Exact) {
            Ok(())
        } else {
            Err(WorldReplayClosureErrorV1::ClaimUnavailable)
        }
    }

    /// Require authoritative Replay for explicitly requested optional views.
    ///
    /// # Errors
    /// Returns [`WorldReplayClosureErrorV1::ClaimUnavailable`] when the
    /// enclosing claim or any requested view is not currently authorized.
    pub fn require_authoritative_use_for(
        &self,
        requested_view_roots: &[Hash],
    ) -> Result<(), WorldReplayClosureErrorV1> {
        self.require_authoritative_use()?;
        let required_members_authorized = self
            .evaluation
            .artifacts()
            .iter()
            .filter(|artifact| artifact.optionality() == crate::ArtifactOptionalityV1::Required)
            .all(crate::EvaluatedArtifactClaimV1::authoritative_use_permitted);
        if required_members_authorized
            && requested_view_roots.iter().all(|root| {
                self.optional_view_roots.contains(root)
                    && self.evaluation.artifacts().iter().any(|artifact| {
                        Hash::from_bytes(artifact.artifact_digest().digest()) == *root
                            && artifact.to() == ErasureReplayClaimV1::Exact
                            && artifact.authoritative_use_permitted()
                    })
            })
        {
            Ok(())
        } else {
            Err(WorldReplayClosureErrorV1::ClaimUnavailable)
        }
    }
}
