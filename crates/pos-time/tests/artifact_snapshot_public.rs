use pos_core::{
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, ErasureArtifactClassV1, ErasureKeyRoleV1, ErasureReferenceV1,
    ErasureReplayClaimV1, Event, Hash, KeyDestructionArtifactEvidenceV1, KeyDestructionRequestV1,
    KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1, Reducer, RegisteredArtifactV1,
    ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1, SignatureEvidenceV1, State, TimelineId,
};
use pos_runtime::ErasureExecutionHostV1;
use pos_state::ProjectionRegistry;
use pos_store::StoreConfig;
use pos_time::{snapshot, verify_snapshot_consistency};
use std::sync::Arc;

trait TestValueExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "unexpected artifact snapshot fixture error: {error:?}"
            )))
        })
    }
}

struct NoopReducer;

impl Reducer for NoopReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, _: &mut State, _: &Event) {}
}

const SNAPSHOT_DIGEST: ErasureReferenceV1 = ErasureReferenceV1::from_digest([51; 32]);
const REPLAY_DIGEST: ErasureReferenceV1 = ErasureReferenceV1::from_digest([53; 32]);

fn evaluation(state: ArtifactStateV1) -> ReplayClaimEvaluationV1 {
    ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::Exact,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::ForkOrSnapshot,
                SNAPSHOT_DIGEST,
                ArtifactDataClassV1::PrivateSubjectData,
                Some(ErasureKeyRoleV1::DataEncryption),
                ErasureReferenceV1::from_digest([52; 32]),
                ArtifactOptionalityV1::Required,
                ArtifactTransitionRuleV1::Remove,
            ),
            current_claim: ErasureReplayClaimV1::Exact,
            state,
        }],
    )
    .test_ok()
}

fn registry(gate: &Arc<pos_core::ErasureContainmentGateV1>) -> ProjectionRegistry {
    let mut registry = ProjectionRegistry::new().with_erasure_gate(Arc::clone(gate));
    registry.register("noop", Box::new(NoopReducer));
    registry
}

#[test]
fn replay_rejects_a_required_key_destroyed_in_the_registry() {
    let mut host = ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Memory,
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    )
    .test_ok();
    let gate = host.containment_gate();
    let timeline = host
        .command_sender()
        .test_ok()
        .create_timeline("destroyed-key-replay")
        .test_ok();
    let identity = KeyIdentityV1::new("replay-owner", KeyRoleV1::SubjectDataEncryption, 1);
    let material_digest = Hash::from_bytes([54; 32]);
    let mut key_registry = KeyRegistryStateV1::new();
    key_registry
        .register_key(KeyRegistrationV1::new(identity, material_digest, None))
        .test_ok();
    let request =
        KeyDestructionRequestV1::new(identity, material_digest, Hash::from_bytes([55; 32]));
    key_registry.begin_key_destruction(request).test_ok();
    key_registry
        .complete_key_destruction(request, pos_core::deletion_receipt(&request))
        .test_ok();
    assert!(key_registry.tombstone(identity).is_some());
    let artifact = ArtifactClaimInputV1 {
        registration: RegisteredArtifactV1::new(
            ErasureArtifactClassV1::TimelineReplay,
            REPLAY_DIGEST,
            ArtifactDataClassV1::PrivateSubjectData,
            Some(ErasureKeyRoleV1::DataEncryption),
            ErasureReferenceV1::from_digest([56; 32]),
            ArtifactOptionalityV1::Required,
            ArtifactTransitionRuleV1::PreserveExact,
        ),
        current_claim: ErasureReplayClaimV1::Exact,
        state: ArtifactStateV1::Retained,
    }
    .with_destruction_evidence(
        &key_registry,
        KeyDestructionArtifactEvidenceV1 {
            identity,
            material_digest,
            private_material_required: true,
            signature: SignatureEvidenceV1::NotRequired,
            required_artifacts_present: true,
        },
    )
    .test_ok();
    let evaluation =
        ReplayClaimEvaluatorV1::evaluate(ErasureReplayClaimV1::Exact, &[artifact]).test_ok();
    let mut reads = host.read_sender().test_ok();
    let mut projections = registry(&gate);
    assert!(matches!(
        pos_time::replay(
            &mut reads,
            timeline.id(),
            &mut projections,
            REPLAY_DIGEST,
            &evaluation,
        ),
        Err(pos_core::CoreError::ArtifactUnavailable)
    ));
}

#[test]
fn snapshot_verification_requires_authoritative_artifact_evidence() {
    let mut host = ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Memory,
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    )
    .test_ok();
    let gate = host.containment_gate();
    let timeline = host
        .command_sender()
        .test_ok()
        .create_timeline("artifact-snapshot")
        .test_ok();
    let mut reads = host.read_sender().test_ok();
    for state in [ArtifactStateV1::Erased, ArtifactStateV1::Invalidated] {
        let mut rejected_registry = registry(&gate);
        let result = snapshot(
            &mut reads,
            timeline.id(),
            &mut rejected_registry,
            SNAPSHOT_DIGEST,
            &evaluation(state),
        );
        match result {
            Err(pos_core::CoreError::ArtifactUnavailable) => {}
            other => std::panic::resume_unwind(Box::new(format!(
                "expected unavailable snapshot, got {other:?}"
            ))),
        }
    }
    let mut capture_registry = registry(&gate);
    let snapshot = snapshot(
        &mut reads,
        timeline.id(),
        &mut capture_registry,
        SNAPSHOT_DIGEST,
        &evaluation(ArtifactStateV1::Retained),
    )
    .test_ok();

    let mut retained_registry = registry(&gate);
    verify_snapshot_consistency(
        &mut reads,
        &snapshot,
        &mut retained_registry,
        SNAPSHOT_DIGEST,
        &evaluation(ArtifactStateV1::Retained),
    )
    .test_ok();

    for state in [ArtifactStateV1::Erased, ArtifactStateV1::Invalidated] {
        let mut rejected_registry = registry(&gate);
        let result = verify_snapshot_consistency(
            &mut reads,
            &snapshot,
            &mut rejected_registry,
            SNAPSHOT_DIGEST,
            &evaluation(state),
        );
        match result {
            Err(pos_time::SnapshotError::ArtifactUnavailable) => {}
            other => std::panic::resume_unwind(Box::new(format!(
                "expected unavailable snapshot verification, got {other:?}"
            ))),
        }
    }
}

#[test]
fn snapshot_and_verification_map_unknown_timeline_fence_errors() {
    let mut host = ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Memory,
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    )
    .test_ok();
    let gate = host.containment_gate();
    let unknown_timeline = TimelineId::new();
    let mut reads = host.read_sender().test_ok();

    let mut snapshot_registry = registry(&gate);
    assert!(snapshot(
        &mut reads,
        unknown_timeline,
        &mut snapshot_registry,
        SNAPSHOT_DIGEST,
        &evaluation(ArtifactStateV1::Retained),
    )
    .is_err());

    let mut verification_registry = registry(&gate);
    let unknown_snapshot = pos_time::Snapshot {
        timeline: unknown_timeline,
        at_seq: pos_core::clock::Seq::ZERO,
        registry: std::collections::HashMap::new(),
    };
    assert!(verify_snapshot_consistency(
        &mut reads,
        &unknown_snapshot,
        &mut verification_registry,
        SNAPSHOT_DIGEST,
        &evaluation(ArtifactStateV1::Retained),
    )
    .is_err());
}
