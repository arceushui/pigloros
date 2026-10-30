//! ADR-062 Revision 7 section 4.4: the deterministic mapping from a committed, authorized
//! `eval.*` Event sequence to `MTI1`, and the [`CalibrationReport`] built from its `MTR1`.

use std::collections::BTreeMap;

use pos_core::{
    event::Event, ids::TimelineId, store::EventStore, store::SeqRange, ArtifactRedactionStateV1,
    ErasureArtifactClassV1, ErasureReferenceV1, ErasureReplayClaimV1, ReplayClaimEvaluationV1,
};

use crate::metric_profile::{
    quantize_probability, MetricFailureV1, MetricInputV1, MetricRecordStateV1, MetricRecordV1,
    MetricRedactionStateV1, MetricResultV1,
};
use crate::{
    EvalError, OutcomeEvidenceV1, OutcomePayload, PredictionPayload, EVENT_TYPE_OUTCOME,
    EVENT_TYPE_PREDICTION,
};

/// The minimum number of scored records [`compute_report`] and
/// [`compute_report_from_events`] declare: a report with no scored record is
/// `InsufficientSamples`, never zeros.
pub const DEFAULT_MINIMUM_SCORED_RECORDS: u32 = 1;

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
/// Each `eval.prediction` becomes one record. Its `predicted_prob` is quantized from its
/// binary64 bit pattern with no clamping. A prediction without outcome is Pending; one whose
/// prediction or outcome Event `evidence` classifies as withheld is Redacted, or Unavailable
/// when either is Unavailable. Failures are reported in Event order, then in `MTI1` decode
/// order.
///
/// # Errors
/// Returns [`EvalError::Decode`] for an undecodable payload,
/// [`EvalError::Metric`] with `InvalidProbability` at `events/<i>` for a probability that is
/// not in `[0, 1]`, [`EvalError::DuplicateOutcome`] at `events/<i>` for a second outcome of
/// one prediction, and [`EvalError::Metric`] for an input the profile rejects, such as
/// `InvalidIdentifier`, `DuplicatePrediction`, `InvalidMinimum` or `ResourceLimit`.
pub fn map_events_to_metric_input(
    events: &[Event],
    evidence: &dyn Fn(&Event) -> EvalEvidenceV1,
    minimum_scored_records: u32,
) -> Result<EvalMetricMappingV1, EvalError> {
    let mut predictions = Vec::new();
    let mut outcomes: BTreeMap<String, ResolvedOutcome> = BTreeMap::new();
    for (index, event) in events.iter().enumerate() {
        match event.event_type.as_str() {
            EVENT_TYPE_PREDICTION => predictions.push(prediction(event, index, evidence(event))?),
            EVENT_TYPE_OUTCOME => add_outcome(&mut outcomes, event, index, evidence(event))?,
            _ => {}
        }
    }
    let mut records: Vec<MetricRecordV1> = predictions
        .into_iter()
        .map(|(mut record, withheld)| {
            record.state = state(withheld, outcomes.remove(&record.prediction_id));
            record
        })
        .collect();
    records.sort_by(|left, right| left.prediction_id.cmp(&right.prediction_id));
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

fn event_coordinate(index: usize) -> String {
    format!("events/{index}")
}

fn prediction(
    event: &Event,
    index: usize,
    evidence: EvalEvidenceV1,
) -> Result<(MetricRecordV1, EvalEvidenceV1), EvalError> {
    let payload: PredictionPayload = decode(event)?;
    let probability_micros =
        quantize_probability(payload.predicted_prob.to_bits()).map_err(|error| {
            EvalError::Metric(MetricFailureV1 {
                error,
                coordinate: event_coordinate(index),
            })
        })?;
    Ok((
        MetricRecordV1 {
            prediction_id: payload.prediction_id,
            entity_id: payload.entity_id,
            probability_micros,
            state: MetricRecordStateV1::Pending,
        },
        evidence,
    ))
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
            coordinate: event_coordinate(index),
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

/// Read all events from the given timeline and compute a [`CalibrationReport`].
///
/// # Errors
/// Returns [`EvalError::ArtifactUnavailable`] when the report closure is not
/// authoritative, [`EvalError::Store`] if the store cannot be read, or a mapping error of
/// [`map_events_to_metric_input`].
pub fn compute_report(
    store: &dyn EventStore,
    timeline_id: TimelineId,
    artifact_digest: ErasureReferenceV1,
    evaluation: &ReplayClaimEvaluationV1,
) -> Result<CalibrationReport, EvalError> {
    authorize(artifact_digest, evaluation)
        .and_then(|()| {
            store
                .read(timeline_id, SeqRange::all())
                .map_err(EvalError::Store)
        })
        .and_then(|events| report(&events, &available, DEFAULT_MINIMUM_SCORED_RECORDS))
}

/// Compute a [`CalibrationReport`] from an already authorized Event sequence.
///
/// This is [`compute_report`] for a host that reads the Events itself, for
/// example the source prefix folded through one Projection cut. The same
/// ADR-060 authoritative-use check runs before any Event is decoded. Every Event is
/// [`EvalEvidenceV1::Available`].
///
/// # Errors
/// Returns [`EvalError::ArtifactUnavailable`] when the report closure is not
/// authoritative, or a mapping error of [`map_events_to_metric_input`].
pub fn compute_report_from_events(
    events: &[Event],
    artifact_digest: ErasureReferenceV1,
    evaluation: &ReplayClaimEvaluationV1,
) -> Result<CalibrationReport, EvalError> {
    compute_report_from_evaluated_events(
        events,
        &available,
        DEFAULT_MINIMUM_SCORED_RECORDS,
        artifact_digest,
        evaluation,
    )
}

/// Compute a [`CalibrationReport`] from an authorized Event sequence whose Events the host
/// classified under ADR-060, with a caller-declared minimum number of scored records.
///
/// # Errors
/// Returns [`EvalError::ArtifactUnavailable`] when the report closure is not
/// authoritative, or a mapping error of [`map_events_to_metric_input`].
pub fn compute_report_from_evaluated_events(
    events: &[Event],
    evidence: &dyn Fn(&Event) -> EvalEvidenceV1,
    minimum_scored_records: u32,
    artifact_digest: ErasureReferenceV1,
    evaluation: &ReplayClaimEvaluationV1,
) -> Result<CalibrationReport, EvalError> {
    authorize(artifact_digest, evaluation)
        .and_then(|()| report(events, evidence, minimum_scored_records))
}

fn authorize(
    artifact_digest: ErasureReferenceV1,
    evaluation: &ReplayClaimEvaluationV1,
) -> Result<(), EvalError> {
    evaluation
        .require_authoritative_use(ErasureArtifactClassV1::CalibrationReport, artifact_digest)
        .map_err(|_| EvalError::ArtifactUnavailable)
}

const fn available(_: &Event) -> EvalEvidenceV1 {
    EvalEvidenceV1::Available
}

fn report(
    events: &[Event],
    evidence: &dyn Fn(&Event) -> EvalEvidenceV1,
    minimum_scored_records: u32,
) -> Result<CalibrationReport, EvalError> {
    map_events_to_metric_input(events, evidence, minimum_scored_records)
        .map(|mapping| CalibrationReport::from_mapping(&mapping))
}
