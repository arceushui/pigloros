#![cfg(feature = "test-support")]

use pos_core::retention::{
    WorldRetentionLeaseInputV1, WorldRetentionLeaseV1, WorldRetentionPolicyInputV1,
    WorldRetentionPolicyV1,
};
use pos_core::{
    ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1, ArtifactTransitionRuleV1,
    ErasureErrorV1, ErasureReplayClaimV1, Hash, PluginId, TimelineId, WallTime,
    WorldArtifactKindV1, WorldArtifactLeafInputV1, WorldArtifactLeafV1, WorldConsumerSetInputV1,
    WorldConsumerSetV1, WorldConsumerV1, WorldProducerV1, WorldReplayClosureAuthorityV1,
    WorldReplayClosureErrorV1, WorldReplayClosureInputV1, WorldReplayClosureV1,
};
use std::fmt::Debug;
use ulid::Ulid;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DAY_MICROS: u64 = 86_400_000_000;

fn test_ok<T, E: Debug>(value: Result<T, E>) -> T {
    value.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!(
            "unexpected world replay fixture error: {error:?}"
        )))
    })
}

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn timeline(value: u128) -> TimelineId {
    TimelineId::from_ulid(Ulid::from(value))
}

fn scope() -> Hash {
    let policy = policy();
    let lease = lease(timeline(1), &policy);
    WorldReplayClosureV1::artifact_scope(timeline(1), lease.digest())
}

fn policy() -> WorldRetentionPolicyV1 {
    test_ok(WorldRetentionPolicyV1::new(WorldRetentionPolicyInputV1 {
        policy_revision: 1,
        purpose: "world-replay".to_owned(),
        audience_policy_hash: hash(10),
        minimum_post_admission_days: 90,
        maximum_active_days: 30,
        maximum_total_days: 120,
    }))
}

fn lease(timeline_id: TimelineId, policy: &WorldRetentionPolicyV1) -> WorldRetentionLeaseV1 {
    test_ok(WorldRetentionLeaseV1::new(
        policy,
        WorldRetentionLeaseInputV1 {
            timeline_id,
            policy_hash: policy.digest(),
            started_at_micros: 0,
            admission_closes_at_micros: 30 * DAY_MICROS,
            retention_deadline_micros: 120 * DAY_MICROS,
        },
    ))
}

fn consumer_set(
    artifacts: &[WorldArtifactLeafV1],
    reducer: Hash,
    output_policy: Hash,
) -> WorldConsumerSetV1 {
    test_ok(WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope: scope(),
        consumers: vec![test_ok(WorldConsumerV1::new(
            "entity-state".to_owned(),
            reducer,
            artifacts[7].digest(),
            artifacts[9].digest(),
        ))],
        producers: vec![test_ok(WorldProducerV1::new(
            PluginId::from_ulid(Ulid::from(1_u128)),
            output_policy,
        ))],
        optional_view_roots: vec![artifacts[13].digest()],
    }))
}

fn leaf(
    scope: Hash,
    lease_hash: Hash,
    kind: WorldArtifactKindV1,
    native_digest: Hash,
    owner: [u8; 32],
    optionality: ArtifactOptionalityV1,
    transition: ArtifactTransitionRuleV1,
) -> WorldArtifactLeafV1 {
    test_ok(WorldArtifactLeafV1::new(WorldArtifactLeafInputV1 {
        scope,
        kind,
        native_digest,
        native_byte_length: 1,
        owner,
        data_class: ArtifactDataClassV1::StructuralAuditMetadata,
        optionality,
        transition,
        source_lease_hash: lease_hash,
        key_dependencies: Vec::new(),
        child_node_hashes: Vec::new(),
    }))
}

const fn artifact_specs(
    policy_digest: Hash,
    lease_digest: Hash,
) -> [(
    WorldArtifactKindV1,
    Hash,
    ArtifactOptionalityV1,
    ArtifactTransitionRuleV1,
); 14] {
    [
        (
            WorldArtifactKindV1::OutputPolicy,
            hash(43),
            ArtifactOptionalityV1::Required,
            ArtifactTransitionRuleV1::PreserveExact,
        ),
        (
            WorldArtifactKindV1::ExecutableBudgetPolicy,
            hash(44),
            ArtifactOptionalityV1::Required,
            ArtifactTransitionRuleV1::PreserveExact,
        ),
        (
            WorldArtifactKindV1::RetentionPolicy,
            policy_digest,
            ArtifactOptionalityV1::Required,
            ArtifactTransitionRuleV1::PreserveExact,
        ),
        (
            WorldArtifactKindV1::RetentionLease,
            lease_digest,
            ArtifactOptionalityV1::Required,
            ArtifactTransitionRuleV1::PreserveExact,
        ),
        (
            WorldArtifactKindV1::BaseConfiguration,
            hash(45),
            ArtifactOptionalityV1::Required,
            ArtifactTransitionRuleV1::PreserveExact,
        ),
        (
            WorldArtifactKindV1::ExecutionProfile,
            hash(46),
            ArtifactOptionalityV1::Required,
            ArtifactTransitionRuleV1::PreserveExact,
        ),
        (
            WorldArtifactKindV1::AudiencePolicy,
            hash(47),
            ArtifactOptionalityV1::Required,
            ArtifactTransitionRuleV1::PreserveExact,
        ),
        (
            WorldArtifactKindV1::Schema,
            hash(41),
            ArtifactOptionalityV1::Required,
            ArtifactTransitionRuleV1::PreserveExact,
        ),
        (
            WorldArtifactKindV1::ReducerImplementation,
            hash(40),
            ArtifactOptionalityV1::Required,
            ArtifactTransitionRuleV1::PreserveExact,
        ),
        (
            WorldArtifactKindV1::RuntimeIdentity,
            hash(42),
            ArtifactOptionalityV1::Required,
            ArtifactTransitionRuleV1::PreserveExact,
        ),
        (
            WorldArtifactKindV1::PluginImplementationIdentity,
            hash(48),
            ArtifactOptionalityV1::Required,
            ArtifactTransitionRuleV1::PreserveExact,
        ),
        (
            WorldArtifactKindV1::KeyDependencyEvidence,
            hash(49),
            ArtifactOptionalityV1::Required,
            ArtifactTransitionRuleV1::PreserveExact,
        ),
        (
            WorldArtifactKindV1::TimelinePayload,
            hash(50),
            ArtifactOptionalityV1::Required,
            ArtifactTransitionRuleV1::PreserveExact,
        ),
        (
            WorldArtifactKindV1::OptionalView,
            hash(53),
            ArtifactOptionalityV1::Optional,
            ArtifactTransitionRuleV1::RedactViews,
        ),
    ]
}

fn artifacts(
    policy: &WorldRetentionPolicyV1,
    retention_lease: &WorldRetentionLeaseV1,
    scope: Hash,
) -> Vec<WorldArtifactLeafV1> {
    let lease_hash = retention_lease.digest();
    artifact_specs(policy.digest(), retention_lease.digest())
        .into_iter()
        .enumerate()
        .map(|(index, (kind, digest, optionality, transition))| {
            leaf(
                scope,
                lease_hash,
                kind,
                digest,
                [100 + test_ok(u8::try_from(index)); 32],
                optionality,
                transition,
            )
        })
        .collect()
}

fn closure_input() -> WorldReplayClosureInputV1 {
    let timeline_id = timeline(1);
    let retention_policy = policy();
    let retention_lease = lease(timeline_id, &retention_policy);
    let scope = scope();
    let artifacts = artifacts(&retention_policy, &retention_lease, scope);
    let consumers = consumer_set(&artifacts, artifacts[8].digest(), artifacts[0].digest());
    WorldReplayClosureInputV1 {
        timeline_id,
        operation_identity: hash(60),
        source_head: hash(61),
        inventory_generation: hash(62),
        retention_policy,
        retention_lease,
        consumer_set: consumers,
        artifacts,
    }
}

#[derive(Clone, Copy)]
enum AuthorityMode {
    Normal,
    FailNow,
    FailArtifact,
    FailNativeVerification,
    WrongNativeDigest,
    TransitionOptionalView,
}

struct Authority {
    now: WallTime,
    missing: Option<WorldArtifactKindV1>,
    mode: AuthorityMode,
}

impl Authority {
    const fn new(now: WallTime) -> Self {
        Self {
            now,
            missing: None,
            mode: AuthorityMode::Normal,
        }
    }

    const fn with_missing(mut self, kind: WorldArtifactKindV1) -> Self {
        self.missing = Some(kind);
        self
    }

    const fn with_mode(mut self, mode: AuthorityMode) -> Self {
        self.mode = mode;
        self
    }
}

impl WorldReplayClosureAuthorityV1 for Authority {
    fn now(&mut self) -> Result<WallTime, ErasureErrorV1> {
        if matches!(self.mode, AuthorityMode::FailNow) {
            Err(ErasureErrorV1::ProvenanceMissing)
        } else {
            Ok(self.now)
        }
    }

    fn verify_native_artifact(
        &mut self,
        artifact: &WorldArtifactLeafV1,
    ) -> Result<Hash, ErasureErrorV1> {
        if matches!(self.mode, AuthorityMode::FailNativeVerification) {
            Err(ErasureErrorV1::ProvenanceMissing)
        } else if matches!(self.mode, AuthorityMode::WrongNativeDigest) {
            Ok(hash(254))
        } else {
            Ok(artifact.as_input().native_digest)
        }
    }

    fn artifact_state(
        &mut self,
        artifact: &WorldArtifactLeafV1,
    ) -> Result<ArtifactStateV1, ErasureErrorV1> {
        if matches!(self.mode, AuthorityMode::FailArtifact) {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        if self.missing == Some(artifact.as_input().kind) {
            return Ok(ArtifactStateV1::MissingRequiredOutput);
        }
        if matches!(self.mode, AuthorityMode::TransitionOptionalView)
            && artifact.as_input().kind == WorldArtifactKindV1::OptionalView
        {
            Ok(ArtifactStateV1::TransitionApplied)
        } else {
            Ok(ArtifactStateV1::Retained)
        }
    }
}

fn admitted(
    authority: &mut Authority,
) -> Result<pos_core::WorldReplayAdmissionV1, WorldReplayClosureErrorV1> {
    WorldReplayClosureV1::new(closure_input())?.admit(authority)
}

#[test]
fn retained_closure_admits_exact_authoritative_replay() -> TestResult {
    let mut authority = Authority::new(WallTime::from_micros(1));
    let closure = WorldReplayClosureV1::new(closure_input())?;
    let digest = closure.digest();
    let admission = closure.admit(&mut authority)?;
    assert_eq!(admission.closure_digest(), digest);
    assert_eq!(
        admission.evaluation().replay_claim(),
        ErasureReplayClaimV1::Exact
    );
    admission.require_authoritative_use()?;
    assert_eq!(closure.timeline_id(), timeline(1));
    assert_eq!(closure.operation_identity(), hash(60));
    assert_eq!(closure.source_head(), hash(61));
    assert_eq!(closure.inventory_generation(), hash(62));
    assert_eq!(closure.artifacts().len(), 14);
    Ok(())
}

#[test]
fn expiry_denies_use_and_missing_required_artifacts_degrade_the_claim() -> TestResult {
    let mut expired = Authority::new(WallTime::from_micros(120 * DAY_MICROS));
    assert_eq!(
        admitted(&mut expired),
        Err(WorldReplayClosureErrorV1::RetentionExpired)
    );

    let mut missing =
        Authority::new(WallTime::from_micros(1)).with_missing(WorldArtifactKindV1::Schema);
    let missing_admission = admitted(&mut missing)?;
    assert_eq!(
        missing_admission.evaluation().replay_claim(),
        ErasureReplayClaimV1::UnverifiableArtifactsMissing
    );
    assert_eq!(
        missing_admission.require_authoritative_use(),
        Err(WorldReplayClosureErrorV1::ClaimUnavailable)
    );
    assert_eq!(
        missing_admission.require_authoritative_use_for(&[]),
        Err(WorldReplayClosureErrorV1::ClaimUnavailable)
    );
    Ok(())
}

#[test]
fn optional_view_redaction_preserves_authoritative_replay() -> TestResult {
    let optional_view_root = closure_input().consumer_set.optional_view_roots()[0];
    let mut retained = Authority::new(WallTime::from_micros(1));
    let retained_admission = admitted(&mut retained)?;
    assert_eq!(
        retained_admission.require_authoritative_use_for(&[optional_view_root]),
        Ok(())
    );

    let mut authority =
        Authority::new(WallTime::from_micros(1)).with_mode(AuthorityMode::TransitionOptionalView);
    let admission = admitted(&mut authority)?;
    assert_eq!(
        admission.evaluation().replay_claim(),
        ErasureReplayClaimV1::Exact
    );
    admission.require_authoritative_use()?;
    assert_eq!(
        admission.require_authoritative_use_for(&[optional_view_root]),
        Err(WorldReplayClosureErrorV1::ClaimUnavailable)
    );
    Ok(())
}

#[test]
fn structural_validation_rejects_unbound_or_incomplete_closures() {
    let base = closure_input();

    let mut caller_chosen_scope = base.clone();
    let arbitrary_scope = hash(9);
    caller_chosen_scope.consumer_set = test_ok(WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope: arbitrary_scope,
        consumers: caller_chosen_scope.consumer_set.consumers().to_vec(),
        producers: caller_chosen_scope.consumer_set.producers().to_vec(),
        optional_view_roots: caller_chosen_scope
            .consumer_set
            .optional_view_roots()
            .to_vec(),
    }));
    caller_chosen_scope.artifacts = caller_chosen_scope
        .artifacts
        .iter()
        .map(|artifact| {
            let mut input = artifact.as_input().clone();
            input.scope = arbitrary_scope;
            test_ok(WorldArtifactLeafV1::new(input))
        })
        .collect();
    assert_eq!(
        WorldReplayClosureV1::new(caller_chosen_scope),
        Err(WorldReplayClosureErrorV1::ScopeMismatch)
    );

    assert_eq!(
        WorldReplayClosureV1::new(WorldReplayClosureInputV1 {
            artifacts: Vec::new(),
            ..base.clone()
        }),
        Err(WorldReplayClosureErrorV1::ArtifactCountOutOfBounds)
    );

    assert_eq!(
        WorldReplayClosureV1::new(WorldReplayClosureInputV1 {
            operation_identity: Hash::zero(),
            ..base.clone()
        }),
        Err(WorldReplayClosureErrorV1::BindingIdentityMissing)
    );

    let mut missing = base.clone();
    missing
        .artifacts
        .retain(|leaf| leaf.as_input().kind != WorldArtifactKindV1::Schema);
    assert_eq!(
        WorldReplayClosureV1::new(missing),
        Err(WorldReplayClosureErrorV1::MissingRequiredArtifact)
    );

    let mut wrong_scope = base.clone();
    wrong_scope.artifacts[0] = leaf(
        hash(8),
        wrong_scope.retention_lease.digest(),
        WorldArtifactKindV1::OutputPolicy,
        hash(43),
        [100; 32],
        ArtifactOptionalityV1::Required,
        ArtifactTransitionRuleV1::PreserveExact,
    );
    assert_eq!(
        WorldReplayClosureV1::new(wrong_scope),
        Err(WorldReplayClosureErrorV1::ScopeMismatch)
    );

    let mut unowned = base;
    unowned.artifacts[0] = leaf(
        scope(),
        unowned.retention_lease.digest(),
        WorldArtifactKindV1::OutputPolicy,
        hash(43),
        [0; 32],
        ArtifactOptionalityV1::Required,
        ArtifactTransitionRuleV1::PreserveExact,
    );
    assert_eq!(
        WorldReplayClosureV1::new(unowned),
        Err(WorldReplayClosureErrorV1::UnownedArtifact)
    );
}

#[test]
fn structural_validation_allows_no_key_dependencies() {
    let mut keyless = closure_input();
    keyless
        .artifacts
        .retain(|leaf| leaf.as_input().kind != WorldArtifactKindV1::KeyDependencyEvidence);
    assert!(WorldReplayClosureV1::new(keyless).is_ok());
}

#[test]
fn structural_validation_rejects_duplicate_digest_and_zero_length() {
    let base = closure_input();
    let mut duplicate = base.clone();
    duplicate.artifacts.push(duplicate.artifacts[0].clone());
    assert_eq!(
        WorldReplayClosureV1::new(duplicate),
        Err(WorldReplayClosureErrorV1::DuplicateArtifact)
    );

    let mut duplicate_digest = base.clone();
    duplicate_digest.artifacts[1] = leaf(
        scope(),
        duplicate_digest.retention_lease.digest(),
        WorldArtifactKindV1::ExecutableBudgetPolicy,
        hash(43),
        [101; 32],
        ArtifactOptionalityV1::Required,
        ArtifactTransitionRuleV1::PreserveExact,
    );
    let duplicate_digest_closure = test_ok(WorldReplayClosureV1::new(duplicate_digest));
    let mut authority = Authority::new(WallTime::from_micros(1));
    assert_eq!(
        duplicate_digest_closure.admit(&mut authority),
        Err(WorldReplayClosureErrorV1::EvaluationRejected)
    );

    let mut zero_length = base;
    let zero_length_lease_hash = zero_length.retention_lease.digest();
    zero_length.artifacts[0] = test_ok(WorldArtifactLeafV1::new(WorldArtifactLeafInputV1 {
        scope: scope(),
        kind: WorldArtifactKindV1::OutputPolicy,
        native_digest: hash(43),
        native_byte_length: 0,
        owner: [100; 32],
        data_class: ArtifactDataClassV1::StructuralAuditMetadata,
        optionality: ArtifactOptionalityV1::Required,
        transition: ArtifactTransitionRuleV1::PreserveExact,
        source_lease_hash: zero_length_lease_hash,
        key_dependencies: Vec::new(),
        child_node_hashes: Vec::new(),
    }));
    assert_eq!(
        WorldReplayClosureV1::new(zero_length),
        Err(WorldReplayClosureErrorV1::UnownedArtifact)
    );
}

#[test]
fn structural_validation_rejects_native_wal_references() {
    let base = closure_input();

    let mut native_address_reference = base.clone();
    native_address_reference.consumer_set = consumer_set(
        &native_address_reference.artifacts,
        hash(40),
        native_address_reference.artifacts[0].digest(),
    );
    assert_eq!(
        WorldReplayClosureV1::new(native_address_reference),
        Err(WorldReplayClosureErrorV1::MissingConsumerArtifact)
    );
    let mut native_view_reference = base.clone();
    native_view_reference.consumer_set =
        test_ok(WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
            scope: scope(),
            consumers: base.consumer_set.consumers().to_vec(),
            producers: base.consumer_set.producers().to_vec(),
            optional_view_roots: vec![hash(53)],
        }));
    assert_eq!(
        WorldReplayClosureV1::new(native_view_reference),
        Err(WorldReplayClosureErrorV1::MissingConsumerArtifact)
    );
}

#[test]
fn structural_validation_rejects_bad_bindings_and_consumer_references() {
    let base = closure_input();
    let policy = policy();
    let other_lease = lease(timeline(2), &policy);
    let mut wrong_timeline = base.clone();
    wrong_timeline.retention_lease = other_lease;
    assert_eq!(
        WorldReplayClosureV1::new(wrong_timeline),
        Err(WorldReplayClosureErrorV1::LeaseTimelineMismatch)
    );

    let mut wrong_lease_source = base.clone();
    wrong_lease_source.artifacts[0] = leaf(
        scope(),
        hash(99),
        WorldArtifactKindV1::OutputPolicy,
        hash(43),
        [100; 32],
        ArtifactOptionalityV1::Required,
        ArtifactTransitionRuleV1::PreserveExact,
    );
    assert_eq!(
        WorldReplayClosureV1::new(wrong_lease_source),
        Err(WorldReplayClosureErrorV1::ScopeMismatch)
    );

    let mut wrong_policy = base.clone();
    wrong_policy.retention_policy =
        test_ok(WorldRetentionPolicyV1::new(WorldRetentionPolicyInputV1 {
            policy_revision: 1,
            purpose: "different-purpose".to_owned(),
            audience_policy_hash: hash(10),
            minimum_post_admission_days: 90,
            maximum_active_days: 30,
            maximum_total_days: 120,
        }));
    assert_eq!(
        WorldReplayClosureV1::new(wrong_policy),
        Err(WorldReplayClosureErrorV1::PolicyMismatch)
    );

    let mut wrong_policy_leaf = base.clone();
    wrong_policy_leaf.artifacts[2] = leaf(
        scope(),
        wrong_policy_leaf.retention_lease.digest(),
        WorldArtifactKindV1::RetentionPolicy,
        hash(98),
        [102; 32],
        ArtifactOptionalityV1::Required,
        ArtifactTransitionRuleV1::PreserveExact,
    );
    assert_eq!(
        WorldReplayClosureV1::new(wrong_policy_leaf),
        Err(WorldReplayClosureErrorV1::PolicyMismatch)
    );

    let mut wrong_lease_leaf = base.clone();
    wrong_lease_leaf.artifacts[3] = leaf(
        scope(),
        wrong_lease_leaf.retention_lease.digest(),
        WorldArtifactKindV1::RetentionLease,
        hash(97),
        [103; 32],
        ArtifactOptionalityV1::Required,
        ArtifactTransitionRuleV1::PreserveExact,
    );
    assert_eq!(
        WorldReplayClosureV1::new(wrong_lease_leaf),
        Err(WorldReplayClosureErrorV1::PolicyMismatch)
    );

    let mut missing_consumer_leaf = base;
    missing_consumer_leaf.consumer_set = consumer_set(
        &missing_consumer_leaf.artifacts,
        hash(98),
        missing_consumer_leaf.artifacts[0].digest(),
    );
    assert_eq!(
        WorldReplayClosureV1::new(missing_consumer_leaf),
        Err(WorldReplayClosureErrorV1::MissingConsumerArtifact)
    );

    let mut missing_producer_leaf = closure_input();
    missing_producer_leaf.consumer_set = consumer_set(
        &missing_producer_leaf.artifacts,
        missing_producer_leaf.artifacts[8].digest(),
        hash(98),
    );
    assert_eq!(
        WorldReplayClosureV1::new(missing_producer_leaf),
        Err(WorldReplayClosureErrorV1::MissingConsumerArtifact)
    );

    let mut missing_optional_view = closure_input();
    missing_optional_view
        .artifacts
        .retain(|leaf| leaf.as_input().kind != WorldArtifactKindV1::OptionalView);
    assert_eq!(
        WorldReplayClosureV1::new(missing_optional_view),
        Err(WorldReplayClosureErrorV1::MissingConsumerArtifact)
    );
}

#[test]
fn structural_validation_rejects_misclassified_optional_view() {
    let mut required_view = closure_input();
    let mut view_input = required_view.artifacts[13].as_input().clone();
    view_input.optionality = ArtifactOptionalityV1::Required;
    required_view.artifacts[13] = test_ok(WorldArtifactLeafV1::new(view_input));
    required_view.consumer_set = test_ok(WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope: scope(),
        consumers: required_view.consumer_set.consumers().to_vec(),
        producers: required_view.consumer_set.producers().to_vec(),
        optional_view_roots: vec![required_view.artifacts[13].digest()],
    }));
    assert_eq!(
        WorldReplayClosureV1::new(required_view),
        Err(WorldReplayClosureErrorV1::MissingConsumerArtifact)
    );
}

#[test]
fn unselected_optional_view_cannot_enter_the_admitted_closure() {
    let mut extra = closure_input();
    extra.artifacts.push(leaf(
        scope(),
        extra.retention_lease.digest(),
        WorldArtifactKindV1::OptionalView,
        hash(54),
        [115; 32],
        ArtifactOptionalityV1::Optional,
        ArtifactTransitionRuleV1::RedactViews,
    ));
    assert_eq!(
        WorldReplayClosureV1::new(extra),
        Err(WorldReplayClosureErrorV1::UnselectedOptionalView)
    );
}

#[test]
fn authority_failures_are_not_treated_as_replay_evidence() {
    let mut clock_failure =
        Authority::new(WallTime::from_micros(1)).with_mode(AuthorityMode::FailNow);
    assert_eq!(
        admitted(&mut clock_failure),
        Err(WorldReplayClosureErrorV1::AuthorityUnavailable)
    );

    let mut artifact_failure =
        Authority::new(WallTime::from_micros(1)).with_mode(AuthorityMode::FailArtifact);
    assert_eq!(
        admitted(&mut artifact_failure),
        Err(WorldReplayClosureErrorV1::AuthorityUnavailable)
    );

    let mut native_failure =
        Authority::new(WallTime::from_micros(1)).with_mode(AuthorityMode::FailNativeVerification);
    assert_eq!(
        admitted(&mut native_failure),
        Err(WorldReplayClosureErrorV1::NativeVerificationUnavailable)
    );

    let mut wrong_native =
        Authority::new(WallTime::from_micros(1)).with_mode(AuthorityMode::WrongNativeDigest);
    assert_eq!(
        admitted(&mut wrong_native),
        Err(WorldReplayClosureErrorV1::NativeDigestMismatch)
    );
}
