//! ADR-062 Revision 7 section 4.4: the deterministic mapping from a committed, authorized
//! `eval.*` Event sequence to `MTI1`, and the [`CalibrationReport`] built from its `MTR1`.

use std::collections::BTreeMap;

use pos_core::{
    event::Event, ArtifactRedactionStateV1, ErasureArtifactClassV1, ErasureReferenceV1,
    ErasureReplayClaimV1, ReplayClaimEvaluationV1,
};

use crate::metric_profile::{
    quantize_probability, MetricErrorV1, MetricFailureV1, MetricInputV1, MetricRecordStateV1,
    MetricRecordV1, MetricRedactionStateV1, MetricResultV1, MAX_METRIC_IDENTIFIER_BYTES,
};
use crate::{
    EvalError, OutcomeEvidenceV1, OutcomePayload, PredictionPayload, EVENT_TYPE_OUTCOME,
    EVENT_TYPE_PREDICTION,
};

/// The host's ADR-060 classification of one committed `eval.*` Event.
///
/// A withheld Event still names its prediction, so its record exists; nothing withheld is
/// scored or reconstructed.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EvalEvidenceV1 {
    /// The Event may be used as authoritative evaluator input.
    Available,
    /// The Event's protected view is redacted.
    Redacted,
    /// The Event's evidence is missing.
    Unavailable,
}

/// The `MTI1` input mapped from an Event sequence, with its mapping diagnostic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalMetricMappingV1 {
    /// One record per `eval.prediction`, in canonical order.
    pub input: MetricInputV1,
    /// Outcomes that name no prediction. They are not part of the input.
    pub orphan_outcomes: u64,
}

/// Calibration report built from one `MTR1` result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalibrationReport {
    /// Replay evidence retained for the report and its required inputs.
    pub replay_claim: ErasureReplayClaimV1,
    /// Redaction state: the `MTR1` state, weakened by the host's artifact evaluation.
    pub redaction_state: ArtifactRedactionStateV1,
    /// The authoritative metric result in micro-units, or `InsufficientSamples`.
    pub result: MetricResultV1,
    /// Outcomes that named no prediction (a mapping diagnostic, not a metric).
    pub orphan_outcomes: u64,
}

impl CalibrationReport {
    /// Consume the host-owned artifact evaluation without strengthening this report.
    pub const fn apply_artifact_evaluation(&mut self, evaluation: &ReplayClaimEvaluationV1) {
        self.replay_claim = self.replay_claim.weakened_to(evaluation.replay_claim());
        self.redaction_state = self
            .redaction_state
            .weakened_to(evaluation.redaction_state());
    }

    fn from_mapping(mapping: &EvalMetricMappingV1) -> Self {
        let result = mapping.input.compute();
        let redaction_state = match result.redaction_state {
            MetricRedactionStateV1::None => ArtifactRedactionStateV1::None,
            MetricRedactionStateV1::RedactedViews => ArtifactRedactionStateV1::RedactedViews,
            MetricRedactionStateV1::EvidenceMissing => ArtifactRedactionStateV1::EvidenceMissing,
        };
        Self {
            replay_claim: ErasureReplayClaimV1::Exact,
            redaction_state,
            result,
            orphan_outcomes: mapping.orphan_outcomes,
        }
    }
}

/// One decoded outcome awaiting its prediction.
#[derive(Clone, Copy)]
struct ResolvedOutcome {
    outcome: bool,
    predictor_supplied: bool,
    evidence: EvalEvidenceV1,
}

/// Map a committed `eval.*` Event sequence to `MTI1` (section 4.4).
///
/// Each `eval.prediction` becomes one record. A prediction without outcome is Pending; one
/// whose prediction or outcome Event `evidence` classifies as withheld is Redacted, or
/// Unavailable when either is Unavailable. A withheld prediction yields its record from its
/// identifiers only: its probability is never read, and its record carries 0. An available
/// prediction's `predicted_prob` is quantized from its binary64 bit pattern with no clamping.
///
/// The Events are walked in Timeline Order, and the fields of one Event in `MTI1` record
/// field-index order (section 4.2): `prediction_id` and its uniqueness, then `entity_id`,
/// then the probability. The first failure wins.
///
/// # Errors
/// Returns [`EvalError::Decode`] for an undecodable payload; [`EvalError::Metric`] at
/// `events/<i>` with `InvalidIdentifier` for an identifier outside 1..=64 bytes,
/// `DuplicatePrediction` for a second prediction with the same id, or `InvalidProbability`
/// for an available probability outside `[0, 1]`; [`EvalError::DuplicateOutcome`] at
/// `events/<i>` for a second outcome of one prediction; and [`EvalError::Metric`] for an
/// input the profile rejects as a whole (`InvalidMinimum`, `ResourceLimit`).
pub fn map_events_to_metric_input(
    events: &[Event],
    evidence: &dyn Fn(&Event) -> EvalEvidenceV1,
    minimum_scored_records: u32,
) -> Result<EvalMetricMappingV1, EvalError> {
    let mut predictions: BTreeMap<String, (MetricRecordV1, EvalEvidenceV1)> = BTreeMap::new();
    let mut outcomes: BTreeMap<String, ResolvedOutcome> = BTreeMap::new();
    for (index, event) in events.iter().enumerate() {
        match event.event_type.as_str() {
            EVENT_TYPE_PREDICTION => {
                add_prediction(&mut predictions, event, index, evidence(event))?;
            }
            EVENT_TYPE_OUTCOME => add_outcome(&mut outcomes, event, index, evidence(event))?,
            _ => {}
        }
    }
    // The map is keyed by `prediction_id`, so the records are in canonical order.
    let records: Vec<MetricRecordV1> = predictions
        .into_values()
        .map(|(mut record, withheld)| {
            record.state = state(withheld, outcomes.remove(&record.prediction_id));
            record
        })
        .collect();
    let input = MetricInputV1::from_records(minimum_scored_records, &records)?;
    Ok(EvalMetricMappingV1 {
        input,
        orphan_outcomes: u64::try_from(outcomes.len()).unwrap_or(u64::MAX),
    })
}

fn decode<T: serde::de::DeserializeOwned>(event: &Event) -> Result<T, EvalError> {
    ciborium::from_reader::<T, _>(event.payload.as_slice())
        .map_err(|error| EvalError::Decode(error.to_string()))
}

fn event_failure(error: MetricErrorV1, index: usize) -> EvalError {
    EvalError::Metric(MetricFailureV1 {
        error,
        coordinate: format!("events/{index}"),
    })
}

const fn check(valid: bool, error: MetricErrorV1) -> Result<(), MetricErrorV1> {
    if valid {
        Ok(())
    } else {
        Err(error)
    }
}

fn valid_identifier(identifier: &str) -> bool {
    (1..=MAX_METRIC_IDENTIFIER_BYTES).contains(&identifier.len())
}

fn add_prediction(
    predictions: &mut BTreeMap<String, (MetricRecordV1, EvalEvidenceV1)>,
    event: &Event,
    index: usize,
    evidence: EvalEvidenceV1,
) -> Result<(), EvalError> {
    let payload: PredictionPayload = decode(event)?;
    // MTI1 record field-index order: prediction_id and its uniqueness, entity_id, then the
    // probability, which is read only for an available prediction.
    let probability = check(
        valid_identifier(&payload.prediction_id),
        MetricErrorV1::InvalidIdentifier,
    )
    .and_then(|()| {
        check(
            !predictions.contains_key(&payload.prediction_id),
            MetricErrorV1::DuplicatePrediction,
        )
    })
    .and_then(|()| {
        check(
            valid_identifier(&payload.entity_id),
            MetricErrorV1::InvalidIdentifier,
        )
    })
    .and_then(|()| {
        if evidence == EvalEvidenceV1::Available {
            quantize_probability(payload.predicted_prob.to_bits())
        } else {
            Ok(0)
        }
    });
    let probability_micros = probability.map_err(|error| event_failure(error, index))?;
    predictions.insert(
        payload.prediction_id.clone(),
        (
            MetricRecordV1 {
                prediction_id: payload.prediction_id,
                entity_id: payload.entity_id,
                probability_micros,
                state: MetricRecordStateV1::Pending,
            },
            evidence,
        ),
    );
    Ok(())
}

fn add_outcome(
    outcomes: &mut BTreeMap<String, ResolvedOutcome>,
    event: &Event,
    index: usize,
    evidence: EvalEvidenceV1,
) -> Result<(), EvalError> {
    let payload: OutcomePayload = decode(event)?;
    let outcome = ResolvedOutcome {
        outcome: payload.outcome,
        predictor_supplied: payload.evidence == Some(OutcomeEvidenceV1::PredictorSupplied),
        evidence,
    };
    if outcomes.insert(payload.prediction_id, outcome).is_some() {
        Err(EvalError::DuplicateOutcome {
            coordinate: format!("events/{index}"),
        })
    } else {
        Ok(())
    }
}

/// The record state of a prediction withheld as `prediction` and its outcome, if any.
fn state(prediction: EvalEvidenceV1, outcome: Option<ResolvedOutcome>) -> MetricRecordStateV1 {
    let withheld = outcome.map_or(prediction, |outcome| prediction.max(outcome.evidence));
    match (withheld, outcome) {
        (EvalEvidenceV1::Unavailable, _) => MetricRecordStateV1::Unavailable,
        (EvalEvidenceV1::Redacted, _) => MetricRecordStateV1::Redacted,
        (EvalEvidenceV1::Available, Some(outcome)) => MetricRecordStateV1::Observed {
            outcome: outcome.outcome,
            predictor_supplied: outcome.predictor_supplied,
        },
        (EvalEvidenceV1::Available, None) => MetricRecordStateV1::Pending,
    }
}

/// Compute a [`CalibrationReport`] from an authorized, committed Event sequence, for
/// example the source prefix folded through one Projection cut.
///
/// The ADR-060 authoritative-use check of the report artifact runs before any Event is
/// decoded. `evidence` is the host's ADR-060 classification of each Event, and
/// `minimum_scored_records` is the caller's declared minimum: fewer scored records is
/// `InsufficientSamples`.
///
/// # Errors
/// Returns [`EvalError::ArtifactUnavailable`] when the report closure is not
/// authoritative, or a mapping error of [`map_events_to_metric_input`].
pub fn compute_report_from_events(
    events: &[Event],
    evidence: &dyn Fn(&Event) -> EvalEvidenceV1,
    minimum_scored_records: u32,
    artifact_digest: ErasureReferenceV1,
    evaluation: &ReplayClaimEvaluationV1,
) -> Result<CalibrationReport, EvalError> {
    evaluation
        .require_authoritative_use(ErasureArtifactClassV1::CalibrationReport, artifact_digest)
        .map_err(|_| EvalError::ArtifactUnavailable)
        .and_then(|()| map_events_to_metric_input(events, evidence, minimum_scored_records))
        .map(|mapping| CalibrationReport::from_mapping(&mapping))
}
