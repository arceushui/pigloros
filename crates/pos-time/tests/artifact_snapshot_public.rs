use pos_core::{
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, ErasureArtifactClassV1, ErasureKeyRoleV1, ErasureReferenceV1,
    ErasureReplayClaimV1, Event, Reducer, RegisteredArtifactV1, ReplayClaimEvaluationV1,
    ReplayClaimEvaluatorV1, State,
};
use pos_state::ProjectionRegistry;
use pos_store::{open_store, StoreConfig};
use pos_time::{snapshot, verify_snapshot_consistency, SnapshotError};

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
    .expect("a unique snapshot artifact should evaluate")
}

fn registry() -> ProjectionRegistry {
    let mut registry = ProjectionRegistry::new();
    registry.register("noop", Box::new(NoopReducer));
    registry
}

#[test]
fn snapshot_verification_requires_authoritative_artifact_evidence() {
    let mut store = open_store(StoreConfig::Memory).expect("memory store should open");
    let timeline = store
        .create_timeline("artifact-snapshot")
        .expect("timeline should be created");
    let mut capture_registry = registry();
    let snapshot = snapshot(store.as_ref(), timeline.id(), &mut capture_registry)
        .expect("snapshot should be captured");

    let mut retained_registry = registry();
    verify_snapshot_consistency(
        store.as_ref(),
        &snapshot,
        &mut retained_registry,
        SNAPSHOT_DIGEST,
        &evaluation(ArtifactStateV1::Retained),
    )
    .expect("retained snapshot should remain authoritative");

    for state in [ArtifactStateV1::Erased, ArtifactStateV1::Invalidated] {
        let mut rejected_registry = registry();
        assert!(matches!(
            verify_snapshot_consistency(
                store.as_ref(),
                &snapshot,
                &mut rejected_registry,
                SNAPSHOT_DIGEST,
                &evaluation(state),
            ),
            Err(SnapshotError::ArtifactUnavailable)
        ));
    }
}
