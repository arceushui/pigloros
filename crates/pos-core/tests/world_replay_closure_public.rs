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
use ulid::Ulid;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DAY_MICROS: u64 = 86_400_000_000;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn timeline(value: u128) -> TimelineId {
    TimelineId::from_ulid(Ulid::from(value))
}

fn policy() -> WorldRetentionPolicyV1 {
    WorldRetentionPolicyV1::new(WorldRetentionPolicyInputV1 {
        policy_revision: 1,
        purpose: "world-replay".to_owned(),
        audience_policy_hash: hash(10),
        minimum_post_admission_days: 90,
        maximum_active_days: 30,
        maximum_total_days: 120,
    })
    .expect("valid retention policy fixture")
}

fn lease(timeline_id: TimelineId, policy: &WorldRetentionPolicyV1) -> WorldRetentionLeaseV1 {
    WorldRetentionLeaseV1::new(
        policy,
        WorldRetentionLeaseInputV1 {
            timeline_id,
            policy_hash: policy.digest(),
            started_at_micros: 0,
            admission_closes_at_micros: 30 * DAY_MICROS,
            retention_deadline_micros: 120 * DAY_MICROS,
        },
    )
    .expect("valid retention lease fixture")
}

fn consumer_set(reducer: Hash, output_policy: Hash) -> WorldConsumerSetV1 {
    WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
        scope: hash(9),
        consumers: vec![WorldConsumerV1::new(
            "entity-state".to_owned(),
            reducer,
            hash(41),
            hash(42),
        )
        .expect("valid consumer fixture")],
        producers: vec![WorldProducerV1::new(
            PluginId::from_ulid(Ulid::from(1_u128)),
            output_policy,
        )
        .expect("valid producer fixture")],
        optional_view_roots: vec![hash(53)],
    })
    .expect("valid consumer-set fixture")
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
    WorldArtifactLeafV1::new(WorldArtifactLeafInputV1 {
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
    })
    .expect("valid artifact leaf fixture")
}

fn artifacts(
    policy: &WorldRetentionPolicyV1,
    retention_lease: &WorldRetentionLeaseV1,
    scope: Hash,
) -> Vec<WorldArtifactLeafV1> {
    let lease_hash = retention_lease.digest();
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
            policy.digest(),
            ArtifactOptionalityV1::Required,
            ArtifactTransitionRuleV1::PreserveExact,
        ),
        (
            WorldArtifactKindV1::RetentionLease,
            retention_lease.digest(),
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
    .into_iter()
    .enumerate()
    .map(|(index, (kind, digest, optionality, transition))| {
        leaf(
            scope,
            lease_hash,
            kind,
            digest,
            [100 + u8::try_from(index).expect("fixture index fits in a byte"); 32],
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
    let scope = hash(9);
    WorldReplayClosureInputV1 {
        timeline_id,
        retention_policy: retention_policy.clone(),
        retention_lease: retention_lease.clone(),
        consumer_set: consumer_set(hash(40), hash(43)),
        artifacts: artifacts(&retention_policy, &retention_lease, scope),
    }
}

struct Authority {
    now: WallTime,
    missing: Option<WorldArtifactKindV1>,
    fail_now: bool,
    fail_artifact: bool,
    transition_optional_view: bool,
}

impl WorldReplayClosureAuthorityV1 for Authority {
    fn now(&mut self) -> Result<WallTime, ErasureErrorV1> {
        if self.fail_now {
            Err(ErasureErrorV1::ProvenanceMissing)
        } else {
            Ok(self.now)
        }
    }

    fn artifact_state(
        &mut self,
        artifact: &WorldArtifactLeafV1,
    ) -> Result<ArtifactStateV1, ErasureErrorV1> {
        if self.fail_artifact {
            return Err(ErasureErrorV1::ProvenanceMissing);
        }
        if self.missing == Some(artifact.as_input().kind) {
            return Ok(ArtifactStateV1::MissingRequiredOutput);
        }
        if self.transition_optional_view
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
    let mut authority = Authority {
        now: WallTime::from_micros(1),
        missing: None,
        fail_now: false,
        fail_artifact: false,
        transition_optional_view: false,
    };
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
    assert_eq!(closure.artifacts().len(), 14);
    Ok(())
}

#[test]
fn expiry_and_missing_required_artifacts_degrade_the_claim() -> TestResult {
    let mut expired = Authority {
        now: WallTime::from_micros(120 * DAY_MICROS),
        missing: None,
        fail_now: false,
        fail_artifact: false,
        transition_optional_view: false,
    };
    let expired_admission = admitted(&mut expired)?;
    assert_eq!(
        expired_admission.evaluation().replay_claim(),
        ErasureReplayClaimV1::UnverifiableArtifactsMissing
    );
    assert_eq!(
        expired_admission.require_authoritative_use(),
        Err(WorldReplayClosureErrorV1::ClaimUnavailable)
    );

    let mut missing = Authority {
        now: WallTime::from_micros(1),
        missing: Some(WorldArtifactKindV1::Schema),
        fail_now: false,
        fail_artifact: false,
        transition_optional_view: false,
    };
    let missing_admission = admitted(&mut missing)?;
    assert_eq!(
        missing_admission.evaluation().replay_claim(),
        ErasureReplayClaimV1::UnverifiableArtifactsMissing
    );
    Ok(())
}

#[test]
fn optional_view_redaction_preserves_authoritative_replay() -> TestResult {
    let mut authority = Authority {
        now: WallTime::from_micros(1),
        missing: None,
        fail_now: false,
        fail_artifact: false,
        transition_optional_view: true,
    };
    let admission = admitted(&mut authority)?;
    assert_eq!(
        admission.evaluation().replay_claim(),
        ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews
    );
    admission.require_authoritative_use()?;
    Ok(())
}

#[test]
fn structural_validation_rejects_unbound_or_incomplete_closures() {
    let base = closure_input();

    assert_eq!(
        WorldReplayClosureV1::new(WorldReplayClosureInputV1 {
            artifacts: Vec::new(),
            ..base.clone()
        }),
        Err(WorldReplayClosureErrorV1::ArtifactCountOutOfBounds)
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

    let mut unowned = base.clone();
    unowned.artifacts[0] = leaf(
        hash(9),
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

    let mut duplicate = base.clone();
    duplicate.artifacts.push(duplicate.artifacts[0].clone());
    assert_eq!(
        WorldReplayClosureV1::new(duplicate),
        Err(WorldReplayClosureErrorV1::DuplicateArtifact)
    );

    let mut duplicate_digest = base.clone();
    duplicate_digest.artifacts[1] = leaf(
        hash(9),
        duplicate_digest.retention_lease.digest(),
        WorldArtifactKindV1::ExecutableBudgetPolicy,
        hash(43),
        [101; 32],
        ArtifactOptionalityV1::Required,
        ArtifactTransitionRuleV1::PreserveExact,
    );
    assert_eq!(
        WorldReplayClosureV1::new(duplicate_digest),
        Err(WorldReplayClosureErrorV1::DuplicateArtifact)
    );

    let mut zero_length = base.clone();
    let zero_length_lease_hash = zero_length.retention_lease.digest();
    zero_length.artifacts[0] = WorldArtifactLeafV1::new(WorldArtifactLeafInputV1 {
        scope: hash(9),
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
    })
    .expect("zero-length fixture remains structurally valid");
    assert_eq!(
        WorldReplayClosureV1::new(zero_length),
        Err(WorldReplayClosureErrorV1::UnownedArtifact)
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
        hash(9),
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
    wrong_policy.retention_policy = WorldRetentionPolicyV1::new(WorldRetentionPolicyInputV1 {
        policy_revision: 1,
        purpose: "different-purpose".to_owned(),
        audience_policy_hash: hash(10),
        minimum_post_admission_days: 90,
        maximum_active_days: 30,
        maximum_total_days: 120,
    })
    .expect("valid alternate retention policy fixture");
    assert_eq!(
        WorldReplayClosureV1::new(wrong_policy),
        Err(WorldReplayClosureErrorV1::PolicyMismatch)
    );

    let mut wrong_policy_leaf = base.clone();
    wrong_policy_leaf.artifacts[2] = leaf(
        hash(9),
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
        hash(9),
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
    missing_consumer_leaf.consumer_set = consumer_set(hash(98), hash(43));
    assert_eq!(
        WorldReplayClosureV1::new(missing_consumer_leaf),
        Err(WorldReplayClosureErrorV1::MissingConsumerArtifact)
    );

    let mut missing_producer_leaf = closure_input();
    missing_producer_leaf.consumer_set = consumer_set(hash(40), hash(98));
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
fn authority_failures_are_not_treated_as_replay_evidence() -> TestResult {
    let mut clock_failure = Authority {
        now: WallTime::from_micros(1),
        missing: None,
        fail_now: true,
        fail_artifact: false,
        transition_optional_view: false,
    };
    assert_eq!(
        admitted(&mut clock_failure),
        Err(WorldReplayClosureErrorV1::AuthorityUnavailable)
    );

    let mut artifact_failure = Authority {
        now: WallTime::from_micros(1),
        missing: None,
        fail_now: false,
        fail_artifact: true,
        transition_optional_view: false,
    };
    assert_eq!(
        admitted(&mut artifact_failure),
        Err(WorldReplayClosureErrorV1::AuthorityUnavailable)
    );
    Ok(())
}
