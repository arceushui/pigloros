//! ADR-062 Revision 7 section 4.4 through plugins/eval's public API: committed `eval.*`
//! Events map to `MTI1`, and the Calibration Report carries the `MTR1` micro-unit values.
//! Every expected value is exact; none is compared with a floating-point tolerance.

use std::sync::Arc;

use pos_core::{
    event::{CanonicalBytes, Event, EventDraft, Kind},
    ids::EntityId,
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactRedactionStateV1,
    ArtifactStateV1, ArtifactTransitionRuleV1, ErasureArtifactClassV1, ErasureContainmentGateV1,
    ErasureKeyRoleV1, ErasureReferenceV1, ErasureReplayClaimV1, RegisteredArtifactV1,
    ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1,
};
use pos_plugin_eval::{
    compute_report_from_events, draft_outcome, draft_prediction, map_events_to_metric_input,
    CalibrationReport, EvalError, EvalEvidenceV1, MetricErrorV1, MetricFailureV1, MetricInputV1,
    MetricOutcomeV1, MetricRecordStateV1, MetricRedactionStateV1, MetricValuesV1,
    OutcomeEvidenceV1, OutcomePayload, ReliabilityBin, EVENT_TYPE_OUTCOME, EVENT_TYPE_PREDICTION,
};
use pos_store::{open_store, EventStore, SeqRange, StoreConfig};

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

fn rejected<T: std::fmt::Debug>(result: Result<T, EvalError>) -> EvalError {
    match result {
        Ok(value) => std::panic::resume_unwind(Box::new(format!("unexpected success: {value:?}"))),
        Err(error) => error,
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

fn exact() -> ReplayClaimEvaluationV1 {
    claim(
        ArtifactTransitionRuleV1::PreserveExact,
        ArtifactStateV1::Retained,
    )
}

fn structural() -> ReplayClaimEvaluationV1 {
    claim(
        ArtifactTransitionRuleV1::RetainStructure,
        ArtifactStateV1::TransitionApplied,
    )
}

fn store() -> Box<dyn EventStore> {
    let mut store = open_store(StoreConfig::Memory).test_ok();
    store
        .bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
        .test_ok();
    store
}

/// Commit `drafts` to a fresh memory Timeline and read them back.
fn committed(drafts: &[EventDraft]) -> Vec<Event> {
    let mut store = store();
    let timeline = store.create_timeline("eval-report").test_ok();
    if !drafts.is_empty() {
        store.append(timeline.id(), drafts).test_ok();
    }
    store.read(timeline.id(), SeqRange::all()).test_ok()
}

fn report_of(drafts: &[EventDraft]) -> CalibrationReport {
    compute_report_from_events(&committed(drafts), &available, 1, REPORT, &exact()).test_ok()
}

const fn available(_: &Event) -> EvalEvidenceV1 {
    EvalEvidenceV1::Available
}

fn prediction(probability: f64, id: &str) -> EventDraft {
    draft_prediction(EntityId::new(), "e", probability, id)
}

fn outcome(id: &str, value: bool) -> EventDraft {
    draft_outcome(EntityId::new(), id, value)
}

fn pairs(pairs: &[(&str, f64, bool)]) -> Vec<EventDraft> {
    pairs
        .iter()
        .flat_map(|(id, probability, value)| [prediction(*probability, id), outcome(id, *value)])
        .collect()
}

fn values(report: &CalibrationReport) -> (MetricValuesV1, [ReliabilityBin; 10]) {
    match &report.result.outcome {
        MetricOutcomeV1::Computed { values, bins } => (*values, **bins),
        MetricOutcomeV1::InsufficientSamples => {
            std::panic::resume_unwind(Box::new("expected computed metrics"))
        }
    }
}

fn values_of(report: &CalibrationReport) -> MetricValuesV1 {
    values(report).0
}

const fn all_metrics(values: MetricValuesV1) -> [i64; 9] {
    [
        values.brier,
        values.crps,
        values.ece,
        values.population_avg_brier,
        values.lift_vs_population_avg,
        values.persistence_brier,
        values.lift_vs_persistence,
        values.personal_base_rate_brier,
        values.lift_vs_personal_base_rate,
    ]
}

const fn metric_failure(error: &EvalError) -> Option<(MetricErrorV1, &str)> {
    match error {
        EvalError::Metric(MetricFailureV1 { error, coordinate }) => {
            Some((*error, coordinate.as_str()))
        }
        _ => None,
    }
}

#[test]
fn committed_events_produce_the_report_in_micros_only_under_an_authoritative_claim() {
    let entity = EntityId::new();
    let events = committed(&[
        draft_prediction(entity, "subject", 0.8, "p1"),
        draft_outcome(entity, "p1", true),
        draft_prediction(entity, "subject", 0.3, "p2"),
        draft_outcome(entity, "p2", false),
    ]);
    let report = compute_report_from_events(&events, &available, 1, REPORT, &exact()).test_ok();
    assert_eq!(report.result.counts.record_count, 2);
    assert_eq!(report.result.counts.scored, 2);
    assert_eq!(
        all_metrics(values_of(&report)),
        [65_000, 65_000, 250_000, 252_500, 187_500, 250_000, 185_000, 1_000_000, 935_000]
    );
    assert_eq!(report.replay_claim, ErasureReplayClaimV1::Exact);
    assert_eq!(report.redaction_state, ArtifactRedactionStateV1::None);
    assert_eq!(report.orphan_outcomes, 0);

    assert!(matches!(
        compute_report_from_events(&events, &available, 1, REPORT, &structural()),
        Err(EvalError::ArtifactUnavailable)
    ));
    let unregistered = ErasureReferenceV1::from_digest([3; 32]);
    assert!(matches!(
        compute_report_from_events(&events, &available, 1, unregistered, &exact()),
        Err(EvalError::ArtifactUnavailable)
    ));
}

#[test]
fn the_report_consumes_the_host_claim_and_never_strengthens() {
    let mut report = report_of(&[]);
    report.apply_artifact_evaluation(&structural());
    assert_eq!(report.replay_claim, ErasureReplayClaimV1::StructuralOnly);
    assert_eq!(
        report.redaction_state,
        ArtifactRedactionStateV1::StructuralOnly
    );
    report.apply_artifact_evaluation(&exact());
    assert_eq!(report.replay_claim, ErasureReplayClaimV1::StructuralOnly);
    assert_eq!(
        report.redaction_state,
        ArtifactRedactionStateV1::StructuralOnly
    );
}

#[test]
fn no_scored_record_is_insufficient_samples_never_zeros() {
    let empty = report_of(&[]);
    assert_eq!(empty.result.outcome, MetricOutcomeV1::InsufficientSamples);
    assert_eq!(empty.result.counts.record_count, 0);
    let pending = report_of(&[prediction(0.8, "p1"), prediction(0.3, "p2")]);
    assert_eq!(pending.result.outcome, MetricOutcomeV1::InsufficientSamples);
    assert_eq!(pending.result.counts.record_count, 2);
    assert_eq!(pending.result.counts.pending, 2);
    assert_eq!(pending.result.counts.scored, 0);

    // A caller-declared minimum above the scored count is also InsufficientSamples.
    let events = committed(&pairs(&[("p1", 0.8, true), ("p2", 0.3, false)]));
    let below = compute_report_from_events(&events, &available, 3, REPORT, &exact()).test_ok();
    assert_eq!(below.result.outcome, MetricOutcomeV1::InsufficientSamples);
    assert_eq!(below.result.minimum_scored_records, 3);
    let at = compute_report_from_events(&events, &available, 2, REPORT, &exact()).test_ok();
    assert_eq!(values_of(&at).brier, 65_000);
    let zero = rejected(compute_report_from_events(
        &events,
        &available,
        0,
        REPORT,
        &exact(),
    ));
    assert_eq!(
        metric_failure(&zero),
        Some((MetricErrorV1::InvalidMinimum, "minimum_scored_records"))
    );
    assert!(matches!(
        compute_report_from_events(&events, &available, 2, REPORT, &structural()),
        Err(EvalError::ArtifactUnavailable)
    ));
}

#[test]
fn perfect_and_worst_predictors_are_exact() {
    let perfect = report_of(&pairs(&[("p1", 1.0, true), ("p2", 0.0, false)]));
    let (values, bins) = values(&perfect);
    assert_eq!(values.brier, 0);
    assert_eq!(values.ece, 0);
    assert_eq!(bins[0].count, 1);
    assert_eq!(bins[9].count, 1);
    let worst = report_of(&pairs(&[("p1", 1.0, false), ("p2", 0.0, true)]));
    assert_eq!(values_of(&worst).brier, 1_000_000);
    assert_eq!(values_of(&worst).crps, 1_000_000);
}

#[test]
fn brier_lifts_and_ece_are_restated_in_micros() {
    let brier = report_of(&pairs(&[
        ("p1", 0.9, true),
        ("p2", 0.2, false),
        ("p3", 0.7, true),
        ("p4", 0.4, false),
    ]));
    assert_eq!(
        all_metrics(values_of(&brier)),
        [75_000, 75_000, 250_000, 252_500, 177_500, 250_000, 175_000, 444_444, 369_444]
    );
    // A single pair: the model is the population-average predictor.
    let single = report_of(&pairs(&[("p1", 0.9, true)]));
    assert_eq!(
        all_metrics(values_of(&single)),
        [10_000, 10_000, 100_000, 10_000, 0, 0, -10_000, 1_000_000, 990_000]
    );
    let persistence = report_of(&pairs(&[("p1", 0.9, true), ("p2", 0.1, false)]));
    assert_eq!(values_of(&persistence).lift_vs_persistence, 240_000);
    // One record per bin: ECE is the mean |p - o|.
    let probabilities = [0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95];
    let ids: Vec<String> = (0..10).map(|index| format!("p{index}")).collect();
    let calibration: Vec<(&str, f64, bool)> = ids
        .iter()
        .zip(probabilities)
        .map(|(id, probability)| (id.as_str(), probability, probability > 0.5))
        .collect();
    let ece = report_of(&pairs(&calibration));
    let (values, bins) = values(&ece);
    assert_eq!(
        all_metrics(values),
        [82_500, 82_500, 250_000, 250_000, 167_500, 250_000, 167_500, 308_642, 226_142]
    );
    assert!(bins.iter().all(|bin| bin.count == 1));
    assert_eq!(
        bins[7],
        ReliabilityBin {
            count: 1,
            probability_sum_micros: 750_000,
            positives: 1,
        }
    );
}

#[test]
fn the_personal_base_rate_is_leave_one_out_with_a_zero_singleton_baseline() {
    let report = report_of(&[
        draft_prediction(EntityId::new(), "a", 1.0, "p1"),
        outcome("p1", true),
        draft_prediction(EntityId::new(), "a", 0.0, "p2"),
        outcome("p2", false),
        draft_prediction(EntityId::new(), "b", 0.5, "p3"),
        outcome("p3", false),
    ]);
    assert_eq!(report.result.counts.scored_entities, 2);
    assert_eq!(
        all_metrics(values_of(&report)),
        [83_333, 83_333, 166_667, 250_000, 166_667, 222_222, 138_889, 666_667, 583_333]
    );
    let shared_bin = report_of(&[
        prediction(0.31, "p1"),
        outcome("p1", true),
        prediction(0.39, "p2"),
        outcome("p2", false),
    ]);
    assert_eq!(
        values(&shared_bin).1[3],
        ReliabilityBin {
            count: 2,
            probability_sum_micros: 700_000,
            positives: 1,
        }
    );
}

#[test]
fn each_prediction_maps_to_one_record_in_canonical_order() {
    let events = committed(&[
        draft_prediction(EntityId::new(), "subject-b", 0.25, "p2"),
        draft_prediction(EntityId::new(), "subject-a", 0.75, "p1"),
        EventDraft::new(
            EntityId::new(),
            Kind::new("some.unrelated.event"),
            CanonicalBytes::from_vec(vec![]),
        ),
        outcome("p1", true),
    ]);
    let mapping = map_events_to_metric_input(&events, &available, 1).test_ok();
    assert_eq!(mapping.orphan_outcomes, 0);
    assert_eq!(mapping.input.minimum_scored_records(), 1);
    let records: Vec<_> = mapping
        .input
        .records()
        .iter()
        .map(|record| {
            (
                record.prediction_id.as_str(),
                record.entity_id.as_str(),
                record.probability_micros,
                record.state,
            )
        })
        .collect();
    assert_eq!(
        records,
        [
            (
                "p1",
                "subject-a",
                750_000,
                MetricRecordStateV1::Observed {
                    outcome: true,
                    predictor_supplied: false,
                }
            ),
            ("p2", "subject-b", 250_000, MetricRecordStateV1::Pending),
        ]
    );
    assert_eq!(
        MetricInputV1::decode(mapping.input.as_bytes()).test_ok(),
        mapping.input
    );
}

#[test]
fn duplicates_are_refused_and_never_resolved_first_wins() {
    let duplicate_prediction = rejected(compute_report_from_events(
        &committed(&[prediction(0.4, "p1"), prediction(0.6, "p1")]),
        &available,
        1,
        REPORT,
        &exact(),
    ));
    assert_eq!(
        metric_failure(&duplicate_prediction),
        Some((MetricErrorV1::DuplicatePrediction, "events/1"))
    );
    assert_eq!(
        duplicate_prediction.to_string(),
        "metric input rejected: DuplicatePrediction at events/1"
    );
    let duplicate_outcome = rejected(compute_report_from_events(
        &committed(&[
            prediction(0.4, "p1"),
            outcome("p1", true),
            outcome("p1", false),
        ]),
        &available,
        1,
        REPORT,
        &exact(),
    ));
    assert_eq!(metric_failure(&duplicate_outcome), None);
    assert_eq!(
        duplicate_outcome.to_string(),
        "duplicate outcome at events/2"
    );
}

#[test]
fn orphan_outcomes_are_a_diagnostic_count_not_records() {
    let report = report_of(&[
        outcome("p999", true),
        prediction(0.7, "p1"),
        outcome("p1", true),
        outcome("p998", false),
    ]);
    assert_eq!(report.orphan_outcomes, 2);
    assert_eq!(report.result.counts.record_count, 1);
    assert_eq!(report.result.counts.scored, 1);
    // An outcome committed before its prediction still resolves it.
    let reversed = report_of(&[outcome("p1", false), prediction(0.25, "p1")]);
    assert_eq!(reversed.orphan_outcomes, 0);
    assert_eq!(values_of(&reversed).brier, 62_500);
}

#[test]
fn withheld_events_are_redacted_or_unavailable_and_never_scored() {
    let events = committed(&[
        prediction(0.8, "p1"),
        outcome("p1", true),
        prediction(0.3, "p2"),
        outcome("p2", false),
        prediction(0.6, "p3"),
        outcome("p3", true),
        prediction(0.1, "p4"),
    ]);
    let (redacted_outcome, unavailable_prediction, redacted_pending) =
        (events[3].id, events[4].id, events[6].id);
    let evidence = move |event: &Event| {
        if event.id == unavailable_prediction {
            EvalEvidenceV1::Unavailable
        } else if event.id == redacted_outcome || event.id == redacted_pending {
            EvalEvidenceV1::Redacted
        } else {
            EvalEvidenceV1::Available
        }
    };
    let mapping = map_events_to_metric_input(&events, &evidence, 1).test_ok();
    let states: Vec<_> = mapping
        .input
        .records()
        .iter()
        .map(|record| record.state)
        .collect();
    assert_eq!(
        states,
        [
            MetricRecordStateV1::Observed {
                outcome: true,
                predictor_supplied: false,
            },
            MetricRecordStateV1::Redacted,
            MetricRecordStateV1::Unavailable,
            MetricRecordStateV1::Redacted,
        ]
    );
    let report = compute_report_from_events(&events, &evidence, 1, REPORT, &exact()).test_ok();
    assert_eq!(
        report.result.redaction_state,
        MetricRedactionStateV1::EvidenceMissing
    );
    assert_eq!(
        report.redaction_state,
        ArtifactRedactionStateV1::EvidenceMissing
    );
    assert_eq!(report.result.counts.scored, 1);
    assert_eq!(report.result.counts.redacted, 2);
    assert_eq!(report.result.counts.unavailable, 1);

    let redacted_only = move |event: &Event| {
        if event.id == redacted_outcome {
            EvalEvidenceV1::Redacted
        } else {
            EvalEvidenceV1::Available
        }
    };
    let report = compute_report_from_events(&events, &redacted_only, 1, REPORT, &exact()).test_ok();
    assert_eq!(
        report.redaction_state,
        ArtifactRedactionStateV1::RedactedViews
    );
}

#[test]
fn identifiers_outside_one_to_sixty_four_bytes_are_invalid() {
    let long = "x".repeat(65);
    for (entity, id, coordinate) in [("e", "", "events/0"), (long.as_str(), "p1", "events/0")] {
        let error = rejected(compute_report_from_events(
            &committed(&[draft_prediction(EntityId::new(), entity, 0.5, id)]),
            &available,
            1,
            REPORT,
            &exact(),
        ));
        assert_eq!(
            metric_failure(&error),
            Some((MetricErrorV1::InvalidIdentifier, coordinate))
        );
    }
}

#[test]
fn probabilities_are_quantized_from_their_bits_and_never_clamped() {
    for probability in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        -0.5,
        1.5,
        1.000_001,
    ] {
        let error = rejected(compute_report_from_events(
            &committed(&[outcome("p0", true), prediction(probability, "p1")]),
            &available,
            1,
            REPORT,
            &exact(),
        ));
        assert_eq!(
            metric_failure(&error),
            Some((MetricErrorV1::InvalidProbability, "events/1")),
            "{probability}"
        );
    }
    // -0.0 reaches the mapping with its sign bit set and quantizes to 0.
    let events = committed(&[prediction(-0.0, "p1"), outcome("p1", false)]);
    let payload: pos_plugin_eval::PredictionPayload =
        ciborium::from_reader(events[0].payload.as_slice()).test_ok();
    assert_eq!(payload.predicted_prob.to_bits(), 0x8000_0000_0000_0000);
    let mapping = map_events_to_metric_input(&events, &available, 1).test_ok();
    assert_eq!(mapping.input.records()[0].probability_micros, 0);
    let report = compute_report_from_events(&events, &available, 1, REPORT, &exact()).test_ok();
    assert_eq!(values(&report).1[0].count, 1);
    assert_eq!(values_of(&report).brier, 0);
}

#[test]
fn predictor_supplied_outcomes_are_counted_without_changing_values() {
    let mut buf = Vec::new();
    ciborium::into_writer(
        &OutcomePayload {
            prediction_id: "p1".to_owned(),
            outcome: true,
            evidence: Some(OutcomeEvidenceV1::PredictorSupplied),
        },
        &mut buf,
    )
    .test_ok();
    let supplied = EventDraft::new(
        EntityId::new(),
        Kind::new(EVENT_TYPE_OUTCOME),
        CanonicalBytes::from_vec(buf),
    );
    let labelled = report_of(&[prediction(0.75, "p1"), supplied]);
    let plain = report_of(&[prediction(0.75, "p1"), outcome("p1", true)]);
    assert_eq!(labelled.result.counts.predictor_supplied, 1);
    assert_eq!(plain.result.counts.predictor_supplied, 0);
    assert_eq!(values_of(&labelled), values_of(&plain));
}

#[test]
fn undecodable_payloads_are_decode_errors() {
    for event_type in [EVENT_TYPE_PREDICTION, EVENT_TYPE_OUTCOME] {
        let bad = EventDraft::new(
            EntityId::new(),
            Kind::new(event_type),
            CanonicalBytes::from_vec(vec![0xff, 0x00]),
        );
        let error = rejected(compute_report_from_events(
            &committed(&[bad]),
            &available,
            1,
            REPORT,
            &exact(),
        ));
        assert!(
            error.to_string().contains("payload decode error"),
            "{error}"
        );
    }
}

fn mapping_failure(drafts: &[EventDraft]) -> Option<(MetricErrorV1, String)> {
    map_events_to_metric_input(&committed(drafts), &available, 1)
        .err()
        .as_ref()
        .and_then(metric_failure)
        .map(|(error, coordinate)| (error, coordinate.to_owned()))
}

/// ADR-062 R7 Event mapping note §1: Events in Timeline Order, and the fields of one Event
/// in `MTI1` record field-index order.
#[test]
fn mapping_failures_follow_timeline_order_then_field_index_order() {
    let failure = |error, coordinate: &str| Some((error, coordinate.to_owned()));
    let identifier = MetricErrorV1::InvalidIdentifier;
    let long = "x".repeat(65);
    // One Event with an invalid prediction_id and an invalid probability.
    assert_eq!(
        mapping_failure(&[prediction(f64::NAN, "")]),
        failure(identifier, "events/0")
    );
    // entity_id (field 1) before the probability (field 2).
    assert_eq!(
        mapping_failure(&[draft_prediction(EntityId::new(), &long, 1.5, "p1")]),
        failure(identifier, "events/0")
    );
    // A duplicate prediction_id is checked with field 0, before the probability.
    assert_eq!(
        mapping_failure(&[prediction(0.5, "p1"), prediction(f64::INFINITY, "p1")]),
        failure(MetricErrorV1::DuplicatePrediction, "events/1")
    );
    // An earlier Event's probability failure wins over a later Event's identifier.
    assert_eq!(
        mapping_failure(&[prediction(-0.5, "p1"), prediction(0.5, "")]),
        failure(MetricErrorV1::InvalidProbability, "events/0")
    );
}

/// ADR-062 R7 Event mapping note §2: a withheld prediction is never quantized.
#[test]
fn withheld_predictions_are_never_quantized() {
    let events = committed(&[
        prediction(f64::NAN, "p1"),
        prediction(1.5, "p2"),
        outcome("p2", true),
    ]);
    let (redacted, unavailable) = (events[0].id, events[1].id);
    let evidence = move |event: &Event| {
        if event.id == redacted {
            EvalEvidenceV1::Redacted
        } else if event.id == unavailable {
            EvalEvidenceV1::Unavailable
        } else {
            EvalEvidenceV1::Available
        }
    };
    let mapping = map_events_to_metric_input(&events, &evidence, 1).test_ok();
    let records: Vec<_> = mapping
        .input
        .records()
        .iter()
        .map(|record| (record.probability_micros, record.state))
        .collect();
    assert_eq!(
        records,
        [
            (0, MetricRecordStateV1::Redacted),
            (0, MetricRecordStateV1::Unavailable),
        ]
    );
    let report = compute_report_from_events(&events, &evidence, 1, REPORT, &exact()).test_ok();
    assert_eq!(report.result.outcome, MetricOutcomeV1::InsufficientSamples);
    assert_eq!(
        report.redaction_state,
        ArtifactRedactionStateV1::EvidenceMissing
    );
}
