//! Host-owned admission for retained World Replay claims.
//!
//! The structural WAL1, WCS1, RTP1, and RLS1 records describe a possible
//! closure, but none of those records grant read authority on their own. This
//! module joins those records at one small seam and requires a host-owned
//! authority to report the current clock and every artifact state before a
//! Replay claim can be used.
//!
//! [`WorldReplayClosureV1::evaluate`] is the production degradation policy: it
//! maps one closure, one trusted evaluation time, and one host observation per
//! leaf to a monotonic Replay claim. Obtaining those observations from native
//! owners remains the installed verifier's responsibility.

use crate::retention::{WorldRetentionLeaseV1, WorldRetentionPolicyV1};
use crate::world_artifact::WorldArtifactLeafInputV1;
use crate::{
    ArtifactClaimInputV1, ArtifactStateV1, ErasureArtifactClassV1, ErasureReferenceV1,
    ErasureReplayClaimV1, Hash, ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1, TimelineId,
    WallTime, WorldArtifactKindV1, WorldArtifactLeafV1, WorldConsumerSetV1,
};

#[cfg(feature = "test-support")]
use crate::{ErasureErrorV1, PluginId};
#[cfg(feature = "test-support")]
use ulid::Ulid;

/// Maximum number of native artifact leaves in one retained World closure.
pub const MAX_WORLD_REPLAY_ARTIFACTS_V1: usize = 4096;

const REQUIRED_KINDS: [WorldArtifactKindV1; 12] = [
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
    WorldArtifactKindV1::TimelinePayload,
];

const CLOSURE_DOMAIN: &[u8] = b"pigloros.world-replay-closure.v1\0";

/// Deterministic identities used only by the `test-support` seam fixtures.
#[cfg(feature = "test-support")]
mod fixture_identity {
    use crate::Hash;

    pub(super) const REDUCER_IMPLEMENTATION: Hash = Hash::from_bytes([40; 32]);
    pub(super) const SCHEMA: Hash = Hash::from_bytes([41; 32]);
    pub(super) const RUNTIME_IDENTITY: Hash = Hash::from_bytes([42; 32]);
    pub(super) const OUTPUT_POLICY: Hash = Hash::from_bytes([43; 32]);
    pub(super) const EXECUTABLE_BUDGET_POLICY: Hash = Hash::from_bytes([44; 32]);
    pub(super) const BASE_CONFIGURATION: Hash = Hash::from_bytes([45; 32]);
    pub(super) const EXECUTION_PROFILE: Hash = Hash::from_bytes([46; 32]);
    pub(super) const AUDIENCE_POLICY: Hash = Hash::from_bytes([47; 32]);
    pub(super) const PLUGIN_IMPLEMENTATION: Hash = Hash::from_bytes([48; 32]);
    pub(super) const KEY_DEPENDENCY_EVIDENCE: Hash = Hash::from_bytes([49; 32]);
    pub(super) const TIMELINE_PAYLOAD: Hash = Hash::from_bytes([50; 32]);
    pub(super) const OPTIONAL_VIEW: Hash = Hash::from_bytes([53; 32]);
    pub(super) const OPERATION: Hash = Hash::from_bytes([60; 32]);
    pub(super) const SOURCE_HEAD: Hash = Hash::from_bytes([61; 32]);
    pub(super) const INVENTORY_GENERATION: Hash = Hash::from_bytes([62; 32]);
    pub(super) const RETENTION_AUDIENCE_POLICY: Hash = Hash::from_bytes([10; 32]);
    /// First byte of the per-leaf host owner; each leaf adds its offset.
    pub(super) const OWNER_BASE: u8 = 100;
}

#[cfg(feature = "test-support")]
fn test_fixture_artifacts(
    scope: Hash,
    retention_policy: &WorldRetentionPolicyV1,
    retention_lease: &WorldRetentionLeaseV1,
) -> Result<Vec<WorldArtifactLeafV1>, WorldReplayClosureErrorV1> {
    use fixture_identity as id;
    let fixtures = [
        (WorldArtifactKindV1::OutputPolicy, id::OUTPUT_POLICY),
        (
            WorldArtifactKindV1::ExecutableBudgetPolicy,
            id::EXECUTABLE_BUDGET_POLICY,
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
            id::BASE_CONFIGURATION,
        ),
        (WorldArtifactKindV1::ExecutionProfile, id::EXECUTION_PROFILE),
        (WorldArtifactKindV1::AudiencePolicy, id::AUDIENCE_POLICY),
        (WorldArtifactKindV1::Schema, id::SCHEMA),
        (
            WorldArtifactKindV1::ReducerImplementation,
            id::REDUCER_IMPLEMENTATION,
        ),
        (WorldArtifactKindV1::RuntimeIdentity, id::RUNTIME_IDENTITY),
        (
            WorldArtifactKindV1::PluginImplementationIdentity,
            id::PLUGIN_IMPLEMENTATION,
        ),
        (
            WorldArtifactKindV1::KeyDependencyEvidence,
            id::KEY_DEPENDENCY_EVIDENCE,
        ),
        (WorldArtifactKindV1::TimelinePayload, id::TIMELINE_PAYLOAD),
        (WorldArtifactKindV1::OptionalView, id::OPTIONAL_VIEW),
    ];
    (id::OWNER_BASE..)
        .zip(fixtures)
        .map(|(owner, (kind, native_digest))| {
            WorldArtifactLeafV1::new(WorldArtifactLeafInputV1 {
                scope,
                kind,
                native_digest,
                native_byte_length: 1,
                owner: [owner; 32],
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
        .collect()
}

#[cfg(feature = "test-support")]
fn test_fixture_digest(
    artifacts: &[WorldArtifactLeafV1],
    kind: WorldArtifactKindV1,
) -> Result<Hash, WorldReplayClosureErrorV1> {
    artifacts
        .iter()
        .find(|leaf| leaf.as_input().kind == kind)
        .map(WorldArtifactLeafV1::digest)
        .ok_or(WorldReplayClosureErrorV1::EvaluationRejected)
}

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
    /// An optional view is not selected by the immutable WCS1 root set.
    #[error("World Replay closure contains an unselected optional view")]
    UnselectedOptionalView,
    /// The retention clock or artifact authority could not be read.
    #[error("World Replay artifact authority is unavailable")]
    AuthorityUnavailable,
    /// The host did not report exactly one observation for every leaf.
    #[error("World Replay observations do not cover the closure")]
    ObservationMismatch,
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
        // A zero source head is the valid genesis hash for an empty Timeline.
        // The native owner must verify the recorded head against the source.
        if input.operation_identity == Hash::zero() || input.inventory_generation == Hash::zero() {
            return Err(WorldReplayClosureErrorV1::BindingIdentityMissing);
        }
        let lease_digest = input.retention_lease.digest();
        let scope = Self::artifact_scope(input.timeline_id, lease_digest);
        if input.consumer_set.scope() != scope {
            return Err(WorldReplayClosureErrorV1::ScopeMismatch);
        }
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
        validate_leaf_rules(&artifacts, scope, lease_digest)?;
        if REQUIRED_KINDS
            .iter()
            .any(|kind| !has_leaf(&artifacts, *kind, |_| true))
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
        validate_consumer_set_references(&artifacts, &input.consumer_set)?;
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

    /// Return the provisional source/head label carried by this flat closure.
    /// This is not a WCB1 cut coordinate or stitched Timeline head.
    #[must_use]
    pub const fn source_head(&self) -> Hash {
        self.source_head
    }

    /// Return the installed inventory generation used by this closure.
    #[must_use]
    pub const fn inventory_generation(&self) -> Hash {
        self.inventory_generation
    }

    /// Return the immutable consumer and producer selection bound to this closure.
    #[must_use]
    pub const fn consumer_set(&self) -> &WorldConsumerSetV1 {
        &self.consumer_set
    }

    /// Derive the lease-scoped WAL1/WCS1 identity fixed by ADR-081.
    #[must_use]
    pub fn artifact_scope(timeline_id: TimelineId, native_lease_hash: Hash) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pigloros.world-evidence.scope.v1\0");
        hasher.update(&timeline_id.inner().to_bytes());
        hasher.update(native_lease_hash.as_bytes());
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Return this flat closure's provisional digest.
    /// This is not the canonical WCB1 binding or an owner-authenticated receipt.
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
    ///
    /// # Errors
    /// Returns a closed fixture-construction error if the deterministic test
    /// records fail their own public validation.
    #[cfg(feature = "test-support")]
    pub fn test_fixture() -> Result<Self, WorldReplayClosureErrorV1> {
        Self::test_fixture_with_inventory_generation(fixture_identity::INVENTORY_GENERATION)
    }

    /// Build the deterministic seam fixture against one caller-supplied
    /// inventory generation.
    ///
    /// A host generation changes when a Timeline is admitted, so downstream
    /// tests use this helper after creating their test topology. Production
    /// callers must obtain the generation from their recovered host instead.
    ///
    /// # Errors
    /// Returns a closed fixture-construction error if the deterministic test
    /// records fail their own public validation.
    #[cfg(feature = "test-support")]
    pub fn test_fixture_with_inventory_generation(
        inventory_generation: Hash,
    ) -> Result<Self, WorldReplayClosureErrorV1> {
        Self::test_fixture_for_timeline_with_inventory_generation(
            TimelineId::from_ulid(Ulid::from(1_u128)),
            inventory_generation,
        )
    }

    /// Build the deterministic seam fixture for one Timeline and inventory generation.
    ///
    /// # Errors
    /// Returns a closed fixture-construction error if the deterministic test
    /// records fail their own public validation.
    #[cfg(feature = "test-support")]
    pub fn test_fixture_for_timeline_with_inventory_generation(
        timeline_id: TimelineId,
        inventory_generation: Hash,
    ) -> Result<Self, WorldReplayClosureErrorV1> {
        Self::test_fixture_for_timeline_consumer(timeline_id, inventory_generation, "count")
    }

    /// Build a deterministic seam fixture recording one named reducer consumer.
    ///
    /// # Errors
    /// Returns a closed fixture-construction error when the consumer identifier
    /// or any structural record fails validation.
    #[cfg(feature = "test-support")]
    pub fn test_fixture_for_timeline_consumer(
        timeline_id: TimelineId,
        inventory_generation: Hash,
        consumer_id: &str,
    ) -> Result<Self, WorldReplayClosureErrorV1> {
        const DAY_MICROS: u64 = 86_400_000_000;
        let retention_policy = crate::retention::WorldRetentionPolicyV1::new(
            crate::retention::WorldRetentionPolicyInputV1 {
                policy_revision: 1,
                purpose: "world-replay".to_owned(),
                audience_policy_hash: fixture_identity::RETENTION_AUDIENCE_POLICY,
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
        let scope = Self::artifact_scope(timeline_id, retention_lease.digest());
        let artifacts = test_fixture_artifacts(scope, &retention_policy, &retention_lease)?;
        let consumer = crate::world_consumer_set::WorldConsumerV1::new(
            consumer_id.to_owned(),
            test_fixture_digest(&artifacts, WorldArtifactKindV1::ReducerImplementation)?,
            test_fixture_digest(&artifacts, WorldArtifactKindV1::Schema)?,
            test_fixture_digest(&artifacts, WorldArtifactKindV1::RuntimeIdentity)?,
        )
        .map_err(|_| WorldReplayClosureErrorV1::EvaluationRejected)?;
        let producer = crate::world_consumer_set::WorldProducerV1::new(
            PluginId::from_ulid(Ulid::from(1_u128)),
            test_fixture_digest(&artifacts, WorldArtifactKindV1::OutputPolicy)?,
        )
        .map_err(|_| WorldReplayClosureErrorV1::EvaluationRejected)?;
        let consumer_set =
            WorldConsumerSetV1::new(crate::world_consumer_set::WorldConsumerSetInputV1 {
                scope,
                consumers: vec![consumer],
                producers: vec![producer],
                optional_view_roots: vec![test_fixture_digest(
                    &artifacts,
                    WorldArtifactKindV1::OptionalView,
                )?],
            })
            .map_err(|_| WorldReplayClosureErrorV1::EvaluationRejected)?;
        Self::new(WorldReplayClosureInputV1 {
            timeline_id,
            operation_identity: fixture_identity::OPERATION,
            source_head: fixture_identity::SOURCE_HEAD,
            inventory_generation,
            retention_policy,
            retention_lease,
            consumer_set,
            artifacts,
        })
    }

    /// Evaluate this closure's Replay claim from host-observed evidence.
    ///
    /// This is the production degradation policy that every installed
    /// verifier must apply after it has read trusted inputs from the native
    /// owners: `now` is the trusted evaluation time, and `observations` holds
    /// exactly one host observation per leaf, in [`Self::artifacts`] order.
    /// Expiry fails closed, a native digest that differs from the recorded
    /// leaf fails closed, and each current artifact state weakens the claim
    /// monotonically. The result also records which WCS1 optional-view roots
    /// may be authorized for the requested use.
    ///
    /// # Errors
    /// Returns [`WorldReplayClosureErrorV1::RetentionExpired`] at or after the
    /// lease deadline, [`WorldReplayClosureErrorV1::ObservationMismatch`] when
    /// the observations do not cover every leaf exactly once,
    /// [`WorldReplayClosureErrorV1::NativeDigestMismatch`] when a native owner
    /// verified different content, or
    /// [`WorldReplayClosureErrorV1::EvaluationRejected`] when the core claim
    /// evaluator rejects the assembled artifact set.
    pub fn evaluate(
        &self,
        now: WallTime,
        observations: &[WorldReplayArtifactObservationV1],
    ) -> Result<WorldReplayAdmissionV1, WorldReplayClosureErrorV1> {
        self.ensure_retained(now)?;
        if observations.len() != self.artifacts.len() {
            return Err(WorldReplayClosureErrorV1::ObservationMismatch);
        }
        let claims = self
            .artifacts
            .iter()
            .zip(observations)
            .map(|(leaf, observation)| artifact_claim(leaf, *observation))
            .collect::<Result<Vec<_>, _>>()?;
        let evaluation = ReplayClaimEvaluatorV1::evaluate(ErasureReplayClaimV1::Exact, &claims)
            .map_err(|_| WorldReplayClosureErrorV1::EvaluationRejected)?;
        Ok(WorldReplayAdmissionV1 {
            closure_digest: self.digest(),
            evaluation,
            optional_views: self
                .artifacts
                .iter()
                .filter(|leaf| {
                    self.consumer_set
                        .optional_view_roots()
                        .contains(&leaf.digest())
                })
                .map(|leaf| (leaf.digest(), leaf.as_input().native_digest))
                .collect(),
        })
    }

    fn ensure_retained(&self, now: WallTime) -> Result<(), WorldReplayClosureErrorV1> {
        if now.as_micros() >= self.retention_lease.as_input().retention_deadline_micros {
            Err(WorldReplayClosureErrorV1::RetentionExpired)
        } else {
            Ok(())
        }
    }

    /// Admit the closure against a host-owned clock and artifact authority.
    ///
    /// The authority is the only source of current time and artifact state.
    /// Callers cannot turn structural WAL1 metadata into an Exact claim by
    /// supplying a hand-written state snapshot. The collected observations
    /// are evaluated by [`Self::evaluate`].
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
        self.ensure_retained(now)?;
        let mut observations = Vec::with_capacity(self.artifacts.len());
        for leaf in &self.artifacts {
            let verified_native_digest = authority
                .verify_native_artifact(leaf)
                .map_err(|_| WorldReplayClosureErrorV1::NativeVerificationUnavailable)?;
            let state = authority
                .artifact_state(leaf)
                .map_err(|_| WorldReplayClosureErrorV1::AuthorityUnavailable)?;
            observations.push(WorldReplayArtifactObservationV1 {
                verified_native_digest,
                state,
            });
        }
        self.evaluate(now, &observations)
    }
}

/// One host observation of a closure leaf, reported by its native owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorldReplayArtifactObservationV1 {
    /// Content identity the native owner verified for the leaf's bytes.
    pub verified_native_digest: Hash,
    /// Current retained, transitioned, or missing state of the leaf.
    pub state: ArtifactStateV1,
}

fn artifact_claim(
    leaf: &WorldArtifactLeafV1,
    observation: WorldReplayArtifactObservationV1,
) -> Result<ArtifactClaimInputV1, WorldReplayClosureErrorV1> {
    let input = leaf.as_input();
    if observation.verified_native_digest != input.native_digest {
        return Err(WorldReplayClosureErrorV1::NativeDigestMismatch);
    }
    Ok(ArtifactClaimInputV1 {
        registration: crate::RegisteredArtifactV1::new(
            ErasureArtifactClassV1::TimelineReplay,
            ErasureReferenceV1::from_digest(*input.native_digest.as_bytes()),
            input.data_class,
            None,
            ErasureReferenceV1::from_digest(input.owner),
            input.optionality,
            input.transition,
        ),
        current_claim: ErasureReplayClaimV1::Exact,
        state: observation.state,
    })
}

/// Per-leaf structural rules, checked in this order across every leaf.
fn validate_leaf_rules(
    artifacts: &[WorldArtifactLeafV1],
    scope: Hash,
    lease_digest: Hash,
) -> Result<(), WorldReplayClosureErrorV1> {
    let out_of_scope = |leaf: &WorldArtifactLeafInputV1| {
        leaf.scope != scope || leaf.source_lease_hash != lease_digest
    };
    let unowned =
        |leaf: &WorldArtifactLeafInputV1| leaf.owner == [0; 32] || leaf.native_byte_length == 0;
    let optional_mandatory = |leaf: &WorldArtifactLeafInputV1| {
        leaf.kind != WorldArtifactKindV1::OptionalView
            && leaf.optionality != crate::ArtifactOptionalityV1::Required
    };
    let rules: [(
        &dyn Fn(&WorldArtifactLeafInputV1) -> bool,
        WorldReplayClosureErrorV1,
    ); 3] = [
        (&out_of_scope, WorldReplayClosureErrorV1::ScopeMismatch),
        (&unowned, WorldReplayClosureErrorV1::UnownedArtifact),
        (
            &optional_mandatory,
            WorldReplayClosureErrorV1::MissingRequiredArtifact,
        ),
    ];
    match rules
        .iter()
        .find(|(violates, _)| artifacts.iter().any(|leaf| violates(leaf.as_input())))
    {
        Some((_, error)) => Err(*error),
        None => Ok(()),
    }
}

/// Return whether any leaf of `kind` satisfies `predicate`.
fn has_leaf(
    artifacts: &[WorldArtifactLeafV1],
    kind: WorldArtifactKindV1,
    predicate: impl Fn(&WorldArtifactLeafV1) -> bool,
) -> bool {
    artifacts
        .iter()
        .any(|leaf| leaf.as_input().kind == kind && predicate(leaf))
}

fn has_identity(
    artifacts: &[WorldArtifactLeafV1],
    kind: WorldArtifactKindV1,
    digest: Hash,
) -> bool {
    has_leaf(artifacts, kind, |leaf| {
        leaf.as_input().native_digest == digest
    })
}

fn has_leaf_address(
    artifacts: &[WorldArtifactLeafV1],
    kind: WorldArtifactKindV1,
    address: Hash,
) -> bool {
    has_leaf(artifacts, kind, |leaf| leaf.digest() == address)
}

fn validate_consumer_set_references(
    artifacts: &[WorldArtifactLeafV1],
    consumer_set: &WorldConsumerSetV1,
) -> Result<(), WorldReplayClosureErrorV1> {
    if consumer_set.consumers().iter().any(|consumer| {
        !has_leaf_address(
            artifacts,
            WorldArtifactKindV1::ReducerImplementation,
            consumer.reducer_hash(),
        ) || !has_leaf_address(
            artifacts,
            WorldArtifactKindV1::Schema,
            consumer.schema_hash(),
        ) || !has_leaf_address(
            artifacts,
            WorldArtifactKindV1::RuntimeIdentity,
            consumer.runtime_hash(),
        )
    }) || consumer_set.producers().iter().any(|producer| {
        !has_leaf_address(
            artifacts,
            WorldArtifactKindV1::OutputPolicy,
            producer.output_policy_hash(),
        )
    }) || consumer_set.optional_view_roots().iter().any(|root| {
        !has_leaf(artifacts, WorldArtifactKindV1::OptionalView, |leaf| {
            leaf.digest() == *root
                && leaf.as_input().optionality == crate::ArtifactOptionalityV1::Optional
        })
    }) {
        return Err(WorldReplayClosureErrorV1::MissingConsumerArtifact);
    }
    if has_leaf(artifacts, WorldArtifactKindV1::OptionalView, |leaf| {
        !consumer_set.optional_view_roots().contains(&leaf.digest())
    }) {
        return Err(WorldReplayClosureErrorV1::UnselectedOptionalView);
    }
    Ok(())
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

/// An evaluated closure and its monotonic Replay claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldReplayAdmissionV1 {
    closure_digest: Hash,
    evaluation: ReplayClaimEvaluationV1,
    optional_views: Vec<(Hash, Hash)>,
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
                self.optional_views.iter().any(|(node, native)| {
                    node == root
                        && self.evaluation.artifacts().iter().any(|artifact| {
                            Hash::from_bytes(artifact.artifact_digest().digest()) == *native
                                && artifact.to() == ErasureReplayClaimV1::Exact
                                && artifact.authoritative_use_permitted()
                        })
                })
            })
        {
            Ok(())
        } else {
            Err(WorldReplayClosureErrorV1::ClaimUnavailable)
        }
    }
}

#[cfg(test)]
#[cfg(feature = "test-support")]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn public_test_fixture_rejects_missing_inventory_generation() {
        assert_eq!(
            WorldReplayClosureV1::test_fixture_with_inventory_generation(Hash::zero()),
            Err(WorldReplayClosureErrorV1::BindingIdentityMissing)
        );
    }

    #[test]
    fn public_test_fixture_rejects_invalid_consumer_identity() {
        assert_eq!(
            WorldReplayClosureV1::test_fixture_for_timeline_consumer(
                TimelineId::new(),
                Hash::from_bytes([1; 32]),
                "",
            ),
            Err(WorldReplayClosureErrorV1::EvaluationRejected)
        );
    }
}
