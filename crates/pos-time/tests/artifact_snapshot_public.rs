use pos_core::{
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, ErasureArtifactClassV1, ErasureKeyRoleV1, ErasureReferenceV1,
    ErasureReplayClaimV1, Event, Reducer, RegisteredArtifactV1, ReplayClaimEvaluationV1,
    ReplayClaimEvaluatorV1, State,
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

fn registry(gate: &Arc<dyn pos_core::ErasureGate>) -> ProjectionRegistry {
    let mut registry = ProjectionRegistry::new().with_erasure_gate(Arc::clone(gate));
    registry.register("noop", Box::new(NoopReducer));
    registry
}

#[test]
fn snapshot_verification_requires_authoritative_artifact_evidence() {
    let mut host = ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Memory,
        pos_core::ERASURE_MAX_INVENTORY_REQUESTS,
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
