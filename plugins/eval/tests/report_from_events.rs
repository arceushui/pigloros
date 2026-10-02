use std::sync::Arc;

use pos_core::{
    ids::EntityId, ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1,
    ArtifactStateV1, ArtifactTransitionRuleV1, ErasureArtifactClassV1, ErasureContainmentGateV1,
    ErasureKeyRoleV1, ErasureReferenceV1, ErasureReplayClaimV1, RegisteredArtifactV1,
    ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1,
};
use pos_plugin_eval::{
    compute_report, compute_report_from_events, draft_outcome, draft_prediction, EvalError,
};
use pos_store::{open_store, SeqRange, StoreConfig};

trait TestValueExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected eval error: {error:?}")))
        })
    }
}

const REPORT: ErasureReferenceV1 = ErasureReferenceV1::from_digest([1; 32]);

fn claim(rule: ArtifactTransitionRuleV1, state: ArtifactStateV1) -> ReplayClaimEvaluationV1 {
    ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::Exact,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::CalibrationReport,
                REPORT,
                ArtifactDataClassV1::AggregateData,
                Some(ErasureKeyRoleV1::DataEncryption),
                ErasureReferenceV1::from_digest([2; 32]),
                ArtifactOptionalityV1::Required,
                rule,
            ),
            current_claim: ErasureReplayClaimV1::Exact,
            state,
        }],
    )
    .test_ok()
}

#[test]
fn events_read_by_the_host_produce_the_store_report() {
    let mut store = open_store(StoreConfig::Memory).test_ok();
    store
        .bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
        .test_ok();
    let timeline = store.create_timeline("report-from-events").test_ok();
    let entity = EntityId::new();
    store
        .append(
            timeline.id(),
            &[
                draft_prediction(entity, "subject", 0.8, "p1"),
                draft_outcome(entity, "p1", true),
                draft_prediction(entity, "subject", 0.3, "p2"),
                draft_outcome(entity, "p2", false),
            ],
        )
        .test_ok();
    let events = store.read(timeline.id(), SeqRange::all()).test_ok();
    let exact = claim(
        ArtifactTransitionRuleV1::PreserveExact,
        ArtifactStateV1::Retained,
    );

    let from_store = compute_report(store.as_ref(), timeline.id(), REPORT, &exact).test_ok();
    let from_events = compute_report_from_events(&events, REPORT, &exact).test_ok();
    assert_eq!(from_events.n_predictions, 2);
    assert_eq!(from_events.n_resolved, 2);
    assert!((from_events.brier_score - from_store.brier_score).abs() < f64::EPSILON);
    assert!((from_events.brier_score - 0.065).abs() < 1e-12);
    assert_eq!(from_events.reliability_bins, from_store.reliability_bins);

    let structural = claim(
        ArtifactTransitionRuleV1::RetainStructure,
        ArtifactStateV1::TransitionApplied,
    );
    assert!(matches!(
        compute_report_from_events(&events, REPORT, &structural),
        Err(EvalError::ArtifactUnavailable)
    ));
    assert!(matches!(
        compute_report_from_events(&events, ErasureReferenceV1::from_digest([3; 32]), &exact),
        Err(EvalError::ArtifactUnavailable)
    ));
}
