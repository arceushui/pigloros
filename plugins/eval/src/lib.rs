#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-plugin-eval` — Wave 5 calibration harness.
//!
//! Owns event types `"eval.prediction"` and `"eval.outcome"`.
//! Tracks predictions and outcomes in State, and provides
//! [`compute_report`] to produce a [`CalibrationReport`] from a timeline.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use pos_core::{
    event::{Event, Kind},
    ids::PluginId,
    ids::TimelineId,
    plugin::{Capability, Plugin},
    state::{Reducer, State},
    store::EventStore,
    store::SeqRange,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Event type for predictions.
pub const EVENT_TYPE_PREDICTION: &str = "eval.prediction";
/// Event type for outcomes.
pub const EVENT_TYPE_OUTCOME: &str = "eval.outcome";
/// Entity kind for eval targets.
pub const ENTITY_KIND: &str = "eval-target";

const NUM_BINS: usize = 10;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the eval plugin.
#[derive(Debug, thiserror::Error)]
pub enum EvalError {
    /// Store read failed.
    #[error("store error: {0}")]
    Store(#[from] pos_core::CoreError),
    /// CBOR payload could not be decoded.
    #[error("payload decode error: {0}")]
    Decode(String),
}

// ---------------------------------------------------------------------------
// Payload types (CBOR-serialized)
// ---------------------------------------------------------------------------

/// Payload for an `eval.prediction` event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PredictionPayload {
    /// Entity the prediction is about (string form for CBOR stability).
    pub entity_id: String,
    /// Predicted probability in `[0.0, 1.0]`.
    pub predicted_prob: f64,
    /// Stable id used to join with a later [`OutcomePayload`].
    pub prediction_id: String,
}

/// Payload for an `eval.outcome` event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutcomePayload {
    /// Must match a prior [`PredictionPayload::prediction_id`].
    pub prediction_id: String,
    /// Observed binary outcome.
    pub outcome: bool,
}

/// Build an `eval.prediction` [`pos_core::EventDraft`].
///
/// # Panics
/// Never panics; CBOR encoding of [`PredictionPayload`] is infallible.
#[must_use]
pub fn draft_prediction(
    entity: pos_core::ids::EntityId,
    entity_id: &str,
    predicted_prob: f64,
    prediction_id: &str,
) -> pos_core::event::EventDraft {
    use pos_core::event::{CanonicalBytes, EventDraft, Kind};

    let payload = PredictionPayload {
        entity_id: entity_id.to_owned(),
        predicted_prob,
        prediction_id: prediction_id.to_owned(),
    };
    let mut buf = Vec::new();
    assert!(ciborium::into_writer(&payload, &mut buf).is_ok());
    EventDraft::new(
        entity,
        Kind::new(EVENT_TYPE_PREDICTION),
        CanonicalBytes::from_vec(buf),
    )
}

/// Build an `eval.outcome` [`pos_core::EventDraft`].
///
/// # Panics
/// Never panics; CBOR encoding of [`OutcomePayload`] is infallible.
#[must_use]
pub fn draft_outcome(
    entity: pos_core::ids::EntityId,
    prediction_id: &str,
    outcome: bool,
) -> pos_core::event::EventDraft {
    use pos_core::event::{CanonicalBytes, EventDraft, Kind};

    let payload = OutcomePayload {
        prediction_id: prediction_id.to_owned(),
        outcome,
    };
    let mut buf = Vec::new();
    assert!(ciborium::into_writer(&payload, &mut buf).is_ok());
    EventDraft::new(
        entity,
        Kind::new(EVENT_TYPE_OUTCOME),
        CanonicalBytes::from_vec(buf),
    )
}

// ---------------------------------------------------------------------------
// Public report types
// ---------------------------------------------------------------------------

/// One reliability bin in the calibration diagram.
#[derive(Clone, Debug, PartialEq)]
pub struct ReliabilityBin {
    /// Lower bound (inclusive) of the probability bin.
    pub bin_lower: f64,
    /// Upper bound (exclusive, except the last bin which is inclusive) of the probability bin.
    pub bin_upper: f64,
    /// Mean predicted probability within this bin.
    pub mean_predicted: f64,
    /// Fraction of outcomes that were positive within this bin.
    pub fraction_positive: f64,
    /// Number of predictions in this bin.
    pub n: u64,
}

/// Calibration report produced by [`compute_report`].
#[derive(Clone, Debug)]
pub struct CalibrationReport {
    /// Brier score: mean squared error of probabilistic predictions.
    pub brier_score: f64,
    pub crps: f64,
    pub lift_vs_personal_base_rate: f64,
    /// Expected calibration error (10 equal-width bins).
    pub ece: f64,
    /// Brier improvement of model vs a constant predictor at population mean probability.
    ///
    /// Positive means model is better than the population-average baseline.
    pub lift_vs_population_avg: f64,
    /// Brier improvement of model vs a constant predictor at the fraction-positive rate.
    ///
    /// Positive means model is better than the persistence (base-rate) baseline.
    pub lift_vs_persistence: f64,
    /// Total number of prediction events seen.
    pub n_predictions: u64,
    /// Number of predictions for which a matching outcome was found.
    pub n_resolved: u64,
    /// The 10 reliability bins used to compute ECE.
    pub reliability_bins: Vec<ReliabilityBin>,
}

// ---------------------------------------------------------------------------
// EvalPlugin descriptor
// ---------------------------------------------------------------------------

/// Calibration harness plugin.
pub struct EvalPlugin {
    id: PluginId,
}

impl Default for EvalPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl EvalPlugin {
    /// Create a new `EvalPlugin`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: PluginId::new(),
        }
    }
}

impl Plugin for EvalPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "eval"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![
                Kind::new(EVENT_TYPE_PREDICTION),
                Kind::new(EVENT_TYPE_OUTCOME),
            ],
            owned_entity_kinds: vec![ENTITY_KIND.to_owned()],
            has_driver: false,
            has_reducer: true,
        }
    }
}

// ---------------------------------------------------------------------------
// EvalReducer
// ---------------------------------------------------------------------------

/// Tracks prediction and outcome events in [`State`].
pub struct EvalReducer;

impl Reducer for EvalReducer {
    fn initial(&self) -> State {
        let mut s = State::new();
        s.set("n_predictions", serde_json::json!(0_u64));
        s.set("n_outcomes", serde_json::json!(0_u64));
        s.set("predictions", serde_json::json!([]));
        s.set("outcomes", serde_json::json!([]));
        s
    }

    fn apply(&self, state: &mut State, event: &Event) {
        match event.event_type.as_str() {
            EVENT_TYPE_PREDICTION => {
                let n = state
                    .get("n_predictions")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                state.set("n_predictions", serde_json::json!(n + 1));

                // Decode CBOR payload; skip silently on decode error.
                if let Ok(p) =
                    ciborium::from_reader::<PredictionPayload, _>(event.payload.as_slice())
                {
                    let mut arr = state
                        .get("predictions")
                        .and_then(serde_json::Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    arr.push(serde_json::json!({
                        "prediction_id": p.prediction_id,
                        "predicted_prob": p.predicted_prob,
                    }));
                    state.set("predictions", serde_json::Value::Array(arr));
                }
            }
            EVENT_TYPE_OUTCOME => {
                let n = state
                    .get("n_outcomes")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                state.set("n_outcomes", serde_json::json!(n + 1));

                // Decode CBOR payload; skip silently on decode error.
                if let Ok(o) = ciborium::from_reader::<OutcomePayload, _>(event.payload.as_slice())
                {
                    let mut arr = state
                        .get("outcomes")
                        .and_then(serde_json::Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    arr.push(serde_json::json!({
                        "prediction_id": o.prediction_id,
                        "outcome": o.outcome,
                    }));
                    state.set("outcomes", serde_json::Value::Array(arr));
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// compute_report
// ---------------------------------------------------------------------------

/// A resolved (prediction, outcome) pair.
struct ResolvedPair {
    entity_id: String,
    predicted_prob: f64,
    outcome: f64,
}

/// Compute the Brier score for a constant predictor `p` over the given outcomes.
fn brier_constant(p: f64, outcomes: &[f64]) -> f64 {
    if outcomes.is_empty() {
        return 0.0;
    }
    let sum: f64 = outcomes.iter().map(|&o| (p - o) * (p - o)).sum();
    sum / f64::from(u32::try_from(outcomes.len()).unwrap_or(u32::MAX))
}

/// Build the 10 equal-width reliability bins from resolved pairs.
fn build_bins(pairs: &[ResolvedPair]) -> Vec<ReliabilityBin> {
    let mut bins: Vec<ReliabilityBin> = (0..NUM_BINS)
        .map(|i| {
            let lower = f64::from(u32::try_from(i).unwrap_or(u32::MAX)) / 10.0;
            let upper = f64::from(u32::try_from(i + 1).unwrap_or(u32::MAX)) / 10.0;
            ReliabilityBin {
                bin_lower: lower,
                bin_upper: upper,
                mean_predicted: 0.0,
                fraction_positive: 0.0,
                n: 0,
            }
        })
        .collect();

    let mut bin_prob_sums: Vec<f64> = vec![0.0; NUM_BINS];
    let mut bin_outcome_sums: Vec<f64> = vec![0.0; NUM_BINS];

    for pair in pairs {
        // Bin index: find the highest bin whose lower bound is <= predicted_prob.
        // This avoids any f64→integer cast (which triggers clippy::cast_sign_loss /
        // cast_possible_truncation under pedantic mode).
        let idx = (0..NUM_BINS)
            .rev()
            .find(|&i| {
                let lower = f64::from(u32::try_from(i).unwrap_or(0)) / 10.0;
                pair.predicted_prob >= lower
            })
            .unwrap_or(0);
        bins[idx].n += 1;
        bin_prob_sums[idx] += pair.predicted_prob;
        bin_outcome_sums[idx] += pair.outcome;
    }

    for (i, bin) in bins.iter_mut().enumerate() {
        if bin.n > 0 {
            let n_f = f64::from(u32::try_from(bin.n).unwrap_or(u32::MAX));
            bin.mean_predicted = bin_prob_sums[i] / n_f;
            bin.fraction_positive = bin_outcome_sums[i] / n_f;
        }
    }

    bins
}

/// Compute the Expected Calibration Error over the reliability bins.
fn compute_ece(bins: &[ReliabilityBin], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let total_f = f64::from(u32::try_from(total).unwrap_or(u32::MAX));
    bins.iter()
        .filter(|b| b.n > 0)
        .map(|b| {
            let n_f = f64::from(u32::try_from(b.n).unwrap_or(u32::MAX));
            let weight = n_f / total_f;
            weight * (b.mean_predicted - b.fraction_positive).abs()
        })
        .sum()
}

/// Read all events from the given timeline and compute a [`CalibrationReport`].
///
/// # Errors
/// Returns [`EvalError::Store`] if the store cannot be read, or
/// [`EvalError::Decode`] if a payload cannot be decoded.
pub fn compute_report(
    store: &dyn EventStore,
    timeline_id: TimelineId,
) -> Result<CalibrationReport, EvalError> {
    let events = store.read(timeline_id, SeqRange::all())?;

    // Collect raw data.
    let mut raw_predictions: Vec<PredictionPayload> = Vec::new();
    let mut raw_outcomes: Vec<OutcomePayload> = Vec::new();

    for event in &events {
        match event.event_type.as_str() {
            EVENT_TYPE_PREDICTION => {
                let p = ciborium::from_reader::<PredictionPayload, _>(event.payload.as_slice())
                    .map_err(|e| EvalError::Decode(e.to_string()))?;
                raw_predictions.push(p);
            }
            EVENT_TYPE_OUTCOME => {
                let o = ciborium::from_reader::<OutcomePayload, _>(event.payload.as_slice())
                    .map_err(|e| EvalError::Decode(e.to_string()))?;
                raw_outcomes.push(o);
            }
            _ => {}
        }
    }

    let n_predictions = u64::try_from(raw_predictions.len()).unwrap_or(u64::MAX);

    // Match predictions to outcomes by prediction_id.
    let mut resolved: Vec<ResolvedPair> = Vec::new();
    for pred in &raw_predictions {
        if let Some(outcome) = raw_outcomes
            .iter()
            .find(|o| o.prediction_id == pred.prediction_id)
        {
            resolved.push(ResolvedPair {
                entity_id: pred.entity_id.clone(),
                predicted_prob: pred.predicted_prob,
                outcome: if outcome.outcome { 1.0 } else { 0.0 },
            });
        }
    }

    let n_resolved = u64::try_from(resolved.len()).unwrap_or(u64::MAX);

    // Empty case: return a zero-filled report.
    if resolved.is_empty() {
        let empty_bins = build_bins(&[]);
        return Ok(CalibrationReport {
            brier_score: 0.0,
            crps: 0.0,
            lift_vs_personal_base_rate: 0.0,
            ece: 0.0,
            lift_vs_population_avg: 0.0,
            lift_vs_persistence: 0.0,
            n_predictions,
            n_resolved: 0,
            reliability_bins: empty_bins,
        });
    }

    let n_resolved_f = f64::from(u32::try_from(resolved.len()).unwrap_or(u32::MAX));

    // Brier score.
    let brier_score: f64 = resolved
        .iter()
        .map(|p| (p.predicted_prob - p.outcome) * (p.predicted_prob - p.outcome))
        .sum::<f64>()
        / n_resolved_f;

    // Population average predicted probability.
    let population_avg: f64 = resolved.iter().map(|p| p.predicted_prob).sum::<f64>() / n_resolved_f;

    // Fraction positive (persistence baseline).
    let fraction_positive: f64 = resolved.iter().map(|p| p.outcome).sum::<f64>() / n_resolved_f;

    let outcomes_vec: Vec<f64> = resolved.iter().map(|p| p.outcome).collect();

    let lift_vs_population_avg = brier_constant(population_avg, &outcomes_vec) - brier_score;
    let lift_vs_persistence = brier_constant(fraction_positive, &outcomes_vec) - brier_score;

    // CRPS — for binary outcomes, CRPS equals Brier score analytically.
    let crps = brier_score;

    // Lift vs personal base rate: per-entity historical outcome rate as baseline.
    // Uses leave-one-out: each prediction is scored against the entity's other outcomes.
    let mut entity_outcomes: std::collections::HashMap<String, Vec<f64>> =
        std::collections::HashMap::new();
    for r in &resolved {
        entity_outcomes
            .entry(r.entity_id.clone())
            .or_default()
            .push(r.outcome);
    }
    let personal_base_brier: f64 = resolved
        .iter()
        .map(|r| {
            let outcomes = &entity_outcomes[&r.entity_id];
            #[allow(clippy::cast_precision_loss)]
            let n = outcomes.len() as f64;
            let base_rate = if n > 1.0 {
                (outcomes.iter().sum::<f64>() - r.outcome) / (n - 1.0)
            } else {
                0.0
            };
            (base_rate - r.outcome) * (base_rate - r.outcome)
        })
        .sum::<f64>()
        / n_resolved_f;
    let lift_vs_personal_base_rate = personal_base_brier - brier_score;

    let reliability_bins = build_bins(&resolved);
    let ece = compute_ece(&reliability_bins, n_resolved);

    Ok(CalibrationReport {
        brier_score,
        crps,
        lift_vs_personal_base_rate,
        ece,
        lift_vs_population_avg,
        lift_vs_persistence,
        n_predictions,
        n_resolved,
        reliability_bins,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {

    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected eval fixture error: {error:?}"
                )))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing fixture value")))
        }
    }

    trait TestErrorExt<T, E> {
        fn test_err(self) -> E;
    }

    impl<T: std::fmt::Debug, E> TestErrorExt<T, E> for Result<T, E> {
        fn test_err(self) -> E {
            match self {
                Ok(value) => std::panic::resume_unwind(Box::new(format!(
                    "unexpected successful eval fixture value: {value:?}"
                ))),
                Err(error) => error,
            }
        }
    }
    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, EventDraft, Kind, SchemaVersion},
        ids::{EntityId, EventId, TimelineId},
    };
    use pos_store::{open_store, StoreConfig};

    // ── helpers ──────────────────────────────────────────────────────────────

    fn encode_prediction(entity_id: &str, predicted_prob: f64, prediction_id: &str) -> Vec<u8> {
        let p = PredictionPayload {
            entity_id: entity_id.to_owned(),
            predicted_prob,
            prediction_id: prediction_id.to_owned(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&p, &mut buf).test_ok();
        buf
    }

    fn encode_outcome(prediction_id: &str, outcome: bool) -> Vec<u8> {
        let o = OutcomePayload {
            prediction_id: prediction_id.to_owned(),
            outcome,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&o, &mut buf).test_ok();
        buf
    }

    fn make_event(entity: EntityId, kind: &str, payload: Vec<u8>, seq: u64) -> Event {
        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(kind),
            payload: CanonicalBytes::from_vec(payload),
            wall_time: WallTime::from_micros(seq),
            seq: Seq::from_u64(seq),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
    }

    fn append_prediction(
        store: &mut dyn EventStore,
        timeline_id: pos_core::ids::TimelineId,
        entity: EntityId,
        entity_id: &str,
        prob: f64,
        prediction_id: &str,
    ) {
        let payload = encode_prediction(entity_id, prob, prediction_id);
        let draft = EventDraft::new(
            entity,
            Kind::new(EVENT_TYPE_PREDICTION),
            CanonicalBytes::from_vec(payload),
        );
        store.append(timeline_id, &[draft]).test_ok();
    }

    fn append_outcome(
        store: &mut dyn EventStore,
        timeline_id: pos_core::ids::TimelineId,
        entity: EntityId,
        prediction_id: &str,
        outcome: bool,
    ) {
        let payload = encode_outcome(prediction_id, outcome);
        let draft = EventDraft::new(
            entity,
            Kind::new(EVENT_TYPE_OUTCOME),
            CanonicalBytes::from_vec(payload),
        );
        store.append(timeline_id, &[draft]).test_ok();
    }

    // ── EvalPlugin tests ─────────────────────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_new_and_default_have_same_name() {
        let p1 = EvalPlugin::new();
        let p2 = EvalPlugin::default();
        assert_eq!(p1.name(), p2.name());
        assert_eq!(p1.name(), "eval");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_id_is_unique() {
        let p1 = EvalPlugin::new();
        let p2 = EvalPlugin::new();
        assert_ne!(p1.id(), p2.id());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_capability() {
        let plugin = EvalPlugin::new();
        let cap = plugin.capability();
        assert_eq!(cap.owned_event_types.len(), 2);
        assert!(cap
            .owned_event_types
            .iter()
            .any(|k| k.as_str() == EVENT_TYPE_PREDICTION));
        assert!(cap
            .owned_event_types
            .iter()
            .any(|k| k.as_str() == EVENT_TYPE_OUTCOME));
        assert_eq!(cap.owned_entity_kinds, vec![ENTITY_KIND.to_owned()]);
        assert!(!cap.has_driver);
        assert!(cap.has_reducer);
    }

    // ── EvalReducer tests ─────────────────────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_initial_state() {
        let reducer = EvalReducer;
        let state = reducer.initial();
        assert_eq!(
            state
                .get("n_predictions")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
        assert_eq!(
            state.get("n_outcomes").and_then(serde_json::Value::as_u64),
            Some(0)
        );
        assert_eq!(
            state
                .get("predictions")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(0)
        );
        assert_eq!(
            state
                .get("outcomes")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(0)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_applies_prediction_events() {
        let reducer = EvalReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let event = make_event(
            entity,
            EVENT_TYPE_PREDICTION,
            encode_prediction("e1", 0.7, "p1"),
            1,
        );
        reducer.apply(&mut state, &event);

        assert_eq!(
            state
                .get("n_predictions")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        let preds = state
            .get("predictions")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert_eq!(preds.len(), 1);
        assert_eq!(preds[0]["prediction_id"].as_str(), Some("p1"));
        assert!((preds[0]["predicted_prob"].as_f64().unwrap_or(0.0) - 0.7).abs() < 1e-10);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_applies_outcome_events() {
        let reducer = EvalReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let event = make_event(entity, EVENT_TYPE_OUTCOME, encode_outcome("p1", true), 1);
        reducer.apply(&mut state, &event);

        assert_eq!(
            state.get("n_outcomes").and_then(serde_json::Value::as_u64),
            Some(1)
        );
        let outcomes = state
            .get("outcomes")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0]["prediction_id"].as_str(), Some("p1"));
        assert_eq!(outcomes[0]["outcome"].as_bool(), Some(true));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_ignores_other_event_types() {
        let reducer = EvalReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let event = make_event(entity, "some.other.event", vec![], 1);
        reducer.apply(&mut state, &event);

        assert_eq!(
            state
                .get("n_predictions")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
        assert_eq!(
            state.get("n_outcomes").and_then(serde_json::Value::as_u64),
            Some(0)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_skips_bad_cbor_payload_silently() {
        let reducer = EvalReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        // Bad CBOR payload — reducer should not panic, and count increments.
        let event = make_event(entity, EVENT_TYPE_PREDICTION, vec![0xFF, 0x00], 1);
        reducer.apply(&mut state, &event);

        // n_predictions incremented even though payload was invalid.
        assert_eq!(
            state
                .get("n_predictions")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        // But no prediction was appended to the array.
        let preds = state
            .get("predictions")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert_eq!(preds.len(), 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_skips_bad_cbor_outcome_payload_silently() {
        let reducer = EvalReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let event = make_event(entity, EVENT_TYPE_OUTCOME, vec![0xFF, 0x00], 1);
        reducer.apply(&mut state, &event);

        assert_eq!(
            state.get("n_outcomes").and_then(serde_json::Value::as_u64),
            Some(1)
        );
        let outcomes = state
            .get("outcomes")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert_eq!(outcomes.len(), 0);
    }

    // ── compute_report tests ──────────────────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_report_zero_predictions() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-zero").test_ok();

        let report = compute_report(store.as_ref(), tl.id()).test_ok();
        assert_eq!(report.n_predictions, 0);
        assert_eq!(report.n_resolved, 0);
        assert!((report.brier_score).abs() < f64::EPSILON);
        assert!((report.ece).abs() < f64::EPSILON);
        assert!((report.lift_vs_population_avg).abs() < f64::EPSILON);
        assert!((report.lift_vs_persistence).abs() < f64::EPSILON);
        assert!((report.crps).abs() < f64::EPSILON);
        assert!((report.lift_vs_personal_base_rate).abs() < f64::EPSILON);
        assert_eq!(report.reliability_bins.len(), NUM_BINS);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_report_predictions_without_outcomes() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-no-outcomes").test_ok();
        let entity = EntityId::new();

        append_prediction(store.as_mut(), tl.id(), entity, "e1", 0.8, "p1");
        append_prediction(store.as_mut(), tl.id(), entity, "e1", 0.3, "p2");

        let report = compute_report(store.as_ref(), tl.id()).test_ok();
        assert_eq!(report.n_predictions, 2);
        assert_eq!(report.n_resolved, 0);
        assert!((report.brier_score).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_report_perfect_predictor() {
        // A perfect predictor: all probs=1.0 for positive outcomes, 0.0 for negative.
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-perfect").test_ok();
        let entity = EntityId::new();

        append_prediction(store.as_mut(), tl.id(), entity, "e1", 1.0, "p1");
        append_prediction(store.as_mut(), tl.id(), entity, "e1", 0.0, "p2");
        append_outcome(store.as_mut(), tl.id(), entity, "p1", true);
        append_outcome(store.as_mut(), tl.id(), entity, "p2", false);

        let report = compute_report(store.as_ref(), tl.id()).test_ok();
        assert_eq!(report.n_predictions, 2);
        assert_eq!(report.n_resolved, 2);
        // Perfect predictor → Brier score = 0.
        assert!(report.brier_score.abs() < f64::EPSILON);
        // ECE should also be 0 for a perfect predictor.
        assert!(report.ece.abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_report_worst_predictor() {
        // Worst predictor: probs=1.0 for negative, 0.0 for positive.
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-worst").test_ok();
        let entity = EntityId::new();

        append_prediction(store.as_mut(), tl.id(), entity, "e1", 1.0, "p1");
        append_prediction(store.as_mut(), tl.id(), entity, "e1", 0.0, "p2");
        append_outcome(store.as_mut(), tl.id(), entity, "p1", false);
        append_outcome(store.as_mut(), tl.id(), entity, "p2", true);

        let report = compute_report(store.as_ref(), tl.id()).test_ok();
        // Brier score = mean((1-0)^2, (0-1)^2) = 1.0.
        assert!((report.brier_score - 1.0).abs() < 1e-10);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_report_brier_score_calculation() {
        // 4 resolved pairs with known Brier score.
        // Pairs: (0.9, true), (0.2, false), (0.7, true), (0.4, false)
        // Squared errors: (0.9-1)^2=0.01, (0.2-0)^2=0.04, (0.7-1)^2=0.09, (0.4-0)^2=0.16
        // Mean = (0.01+0.04+0.09+0.16)/4 = 0.075
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-brier").test_ok();
        let entity = EntityId::new();

        append_prediction(store.as_mut(), tl.id(), entity, "e", 0.9, "p1");
        append_prediction(store.as_mut(), tl.id(), entity, "e", 0.2, "p2");
        append_prediction(store.as_mut(), tl.id(), entity, "e", 0.7, "p3");
        append_prediction(store.as_mut(), tl.id(), entity, "e", 0.4, "p4");
        append_outcome(store.as_mut(), tl.id(), entity, "p1", true);
        append_outcome(store.as_mut(), tl.id(), entity, "p2", false);
        append_outcome(store.as_mut(), tl.id(), entity, "p3", true);
        append_outcome(store.as_mut(), tl.id(), entity, "p4", false);

        let report = compute_report(store.as_ref(), tl.id()).test_ok();
        assert_eq!(report.n_resolved, 4);
        let expected_brier = 0.075;
        assert!(
            (report.brier_score - expected_brier).abs() < 1e-10,
            "brier={}, expected={}",
            report.brier_score,
            expected_brier
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_report_lift_vs_population_avg() {
        // Single prediction/outcome pair with known lift.
        // pred=0.9, outcome=true.
        // brier_score = (0.9-1)^2 = 0.01
        // population_avg = 0.9
        // brier_constant(0.9) = (0.9-1)^2 = 0.01
        // lift_vs_population_avg = 0.01 - 0.01 = 0.0
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-lift-pop").test_ok();
        let entity = EntityId::new();

        append_prediction(store.as_mut(), tl.id(), entity, "e", 0.9, "p1");
        append_outcome(store.as_mut(), tl.id(), entity, "p1", true);

        let report = compute_report(store.as_ref(), tl.id()).test_ok();
        // lift_vs_population_avg = 0 because the model IS the population avg predictor.
        assert!(
            report.lift_vs_population_avg.abs() < 1e-10,
            "lift_vs_population_avg={}",
            report.lift_vs_population_avg
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_report_lift_vs_persistence_positive() {
        // Model that beats base rate.
        // predictions: (0.9, true), (0.1, false) — perfectly calibrated.
        // fraction_positive = 0.5
        // brier_constant(0.5) = mean((0.5-1)^2, (0.5-0)^2) = mean(0.25, 0.25) = 0.25
        // model brier = mean((0.9-1)^2, (0.1-0)^2) = mean(0.01, 0.01) = 0.01
        // lift = 0.25 - 0.01 = 0.24
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-lift-pers").test_ok();
        let entity = EntityId::new();

        append_prediction(store.as_mut(), tl.id(), entity, "e", 0.9, "p1");
        append_prediction(store.as_mut(), tl.id(), entity, "e", 0.1, "p2");
        append_outcome(store.as_mut(), tl.id(), entity, "p1", true);
        append_outcome(store.as_mut(), tl.id(), entity, "p2", false);

        let report = compute_report(store.as_ref(), tl.id()).test_ok();
        let expected_lift = 0.25 - 0.01;
        assert!(
            (report.lift_vs_persistence - expected_lift).abs() < 1e-10,
            "lift_vs_persistence={}, expected={}",
            report.lift_vs_persistence,
            expected_lift
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_report_ece_calculation() {
        // 10 predictions each in a different bin, all well-calibrated.
        // pred=0.05 (bin 0), outcome=false; pred=0.15 (bin 1), outcome=false; etc.
        // For a well-calibrated predictor ECE is non-zero but small.
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-ece").test_ok();
        let entity = EntityId::new();

        let probs = [0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95];
        for (i, &prob) in probs.iter().enumerate() {
            let pid = format!("p{i}");
            append_prediction(store.as_mut(), tl.id(), entity, "e", prob, &pid);
            // outcome matches if prob > 0.5
            append_outcome(store.as_mut(), tl.id(), entity, &pid, prob > 0.5);
        }

        let report = compute_report(store.as_ref(), tl.id()).test_ok();
        assert_eq!(report.n_resolved, 10);
        // ECE should be > 0 (predictions do not perfectly match outcomes).
        // Specifically for bins 0-4: mean_predicted ~ prob, fraction_positive=0.0 → |prob-0|
        // bins 5-9: mean_predicted ~ prob, fraction_positive=1.0 → |prob-1|
        assert!(report.ece > 0.0, "ECE should be > 0, got {}", report.ece);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_report_reliability_bins_populated() {
        // Put one prediction in each bin and verify bin fields.
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-bins").test_ok();
        let entity = EntityId::new();

        // prob=0.75 → bin 7
        append_prediction(store.as_mut(), tl.id(), entity, "e", 0.75, "p1");
        append_outcome(store.as_mut(), tl.id(), entity, "p1", true);

        let report = compute_report(store.as_ref(), tl.id()).test_ok();
        let bin7 = &report.reliability_bins[7];
        assert_eq!(bin7.n, 1);
        assert!((bin7.mean_predicted - 0.75).abs() < 1e-10);
        assert!((bin7.fraction_positive - 1.0).abs() < 1e-10);
        assert!((bin7.bin_lower - 0.7).abs() < 1e-10);
        assert!((bin7.bin_upper - 0.8).abs() < 1e-10);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_report_bin_boundary_exact_1_goes_to_last_bin() {
        // predicted_prob=1.0 exactly should go to bin 9 (the last bin).
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-bin-boundary").test_ok();
        let entity = EntityId::new();

        append_prediction(store.as_mut(), tl.id(), entity, "e", 1.0, "p1");
        append_outcome(store.as_mut(), tl.id(), entity, "p1", true);

        let report = compute_report(store.as_ref(), tl.id()).test_ok();
        let last_bin = &report.reliability_bins[9];
        assert_eq!(last_bin.n, 1, "prob=1.0 should land in bin 9");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_report_bin_boundary_exactly_zero() {
        // predicted_prob=0.0 should go to bin 0.
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-bin-zero").test_ok();
        let entity = EntityId::new();

        append_prediction(store.as_mut(), tl.id(), entity, "e", 0.0, "p1");
        append_outcome(store.as_mut(), tl.id(), entity, "p1", false);

        let report = compute_report(store.as_ref(), tl.id()).test_ok();
        let bin0 = &report.reliability_bins[0];
        assert_eq!(bin0.n, 1, "prob=0.0 should land in bin 0");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_report_all_bins_populated() {
        // Add one prediction per bin to verify all 10 bins have n>0.
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-all-bins").test_ok();
        let entity = EntityId::new();

        // Centers of each bin: 0.05, 0.15, ..., 0.95
        for i in 0..10_usize {
            let prob = (f64::from(u32::try_from(i).test_ok()) + 0.5) / 10.0;
            let pid = format!("pred{i}");
            append_prediction(store.as_mut(), tl.id(), entity, "e", prob, &pid);
            append_outcome(store.as_mut(), tl.id(), entity, &pid, i >= 5);
        }

        let report = compute_report(store.as_ref(), tl.id()).test_ok();
        assert_eq!(report.reliability_bins.len(), 10);
        for (i, bin) in report.reliability_bins.iter().enumerate() {
            assert_eq!(bin.n, 1, "bin {i} should have 1 prediction");
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_report_non_matching_prediction_ids() {
        // Outcomes don't match any prediction_id → n_resolved=0.
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-no-match").test_ok();
        let entity = EntityId::new();

        append_prediction(store.as_mut(), tl.id(), entity, "e", 0.7, "p1");
        append_outcome(store.as_mut(), tl.id(), entity, "p999", true); // no match

        let report = compute_report(store.as_ref(), tl.id()).test_ok();
        assert_eq!(report.n_predictions, 1);
        assert_eq!(report.n_resolved, 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_report_unrelated_events_ignored() {
        // Events with other type should not affect the report.
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-other-events").test_ok();
        let entity = EntityId::new();

        // Some random other event
        let draft = EventDraft::new(
            entity,
            Kind::new("some.unrelated.event"),
            CanonicalBytes::from_vec(vec![]),
        );
        store.append(tl.id(), &[draft]).test_ok();

        append_prediction(store.as_mut(), tl.id(), entity, "e", 0.6, "p1");
        append_outcome(store.as_mut(), tl.id(), entity, "p1", true);

        let report = compute_report(store.as_ref(), tl.id()).test_ok();
        assert_eq!(report.n_predictions, 1);
        assert_eq!(report.n_resolved, 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reliability_bin_all_fields_populated() {
        // Verify all ReliabilityBin fields are correctly populated.
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-bin-fields").test_ok();
        let entity = EntityId::new();

        // Two predictions in bin 3 (0.3-0.4): probs 0.31 and 0.39, outcomes true/false.
        append_prediction(store.as_mut(), tl.id(), entity, "e", 0.31, "p1");
        append_prediction(store.as_mut(), tl.id(), entity, "e", 0.39, "p2");
        append_outcome(store.as_mut(), tl.id(), entity, "p1", true);
        append_outcome(store.as_mut(), tl.id(), entity, "p2", false);

        let report = compute_report(store.as_ref(), tl.id()).test_ok();
        let bin3 = &report.reliability_bins[3];

        assert_eq!(bin3.n, 2);
        assert!((bin3.bin_lower - 0.3).abs() < 1e-10);
        assert!((bin3.bin_upper - 0.4).abs() < 1e-10);
        // mean_predicted = (0.31 + 0.39) / 2 = 0.35
        assert!((bin3.mean_predicted - 0.35).abs() < 1e-10);
        // fraction_positive = 1/2 = 0.5
        assert!((bin3.fraction_positive - 0.5).abs() < 1e-10);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_report_multiple_predictions_one_entity() {
        // 5 predictions + 5 outcomes → n_resolved=5, correct metrics.
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-multi").test_ok();
        let entity = EntityId::new();

        let probs = [0.1, 0.3, 0.5, 0.7, 0.9];
        let outcomes = [false, false, true, true, true];
        for (i, (&prob, &outcome)) in probs.iter().zip(outcomes.iter()).enumerate() {
            let pid = format!("p{i}");
            append_prediction(store.as_mut(), tl.id(), entity, "e", prob, &pid);
            append_outcome(store.as_mut(), tl.id(), entity, &pid, outcome);
        }

        let report = compute_report(store.as_ref(), tl.id()).test_ok();
        assert_eq!(report.n_predictions, 5);
        assert_eq!(report.n_resolved, 5);
        assert!(report.brier_score >= 0.0);
        assert!(report.ece >= 0.0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn brier_constant_empty_returns_zero() {
        assert!(brier_constant(0.5, &[]).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn brier_constant_known_value() {
        // brier_constant(0.5, [0.0, 1.0]) = mean(0.25, 0.25) = 0.25
        let result = brier_constant(0.5, &[0.0, 1.0]);
        assert!((result - 0.25).abs() < 1e-10);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn build_bins_empty() {
        let bins = build_bins(&[]);
        assert_eq!(bins.len(), NUM_BINS);
        for bin in &bins {
            assert_eq!(bin.n, 0);
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_ece_empty_bins() {
        let bins = build_bins(&[]);
        let ece = compute_ece(&bins, 0);
        assert!(ece.abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn eval_error_store_variant() {
        let core_err = pos_core::CoreError::Storage("test error".to_owned());
        let eval_err: EvalError = core_err.into();
        let s = eval_err.to_string();
        assert!(s.contains("store error"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn eval_error_decode_variant() {
        let eval_err = EvalError::Decode("bad payload".to_owned());
        let s = eval_err.to_string();
        assert!(s.contains("payload decode error"));
        assert!(s.contains("bad payload"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn draft_prediction_and_outcome_round_trip() {
        let entity = EntityId::new();
        let pred = draft_prediction(entity, "e1", 0.75, "p1");
        assert_eq!(pred.event_type.as_str(), EVENT_TYPE_PREDICTION);
        let decoded: PredictionPayload = ciborium::from_reader(pred.payload.as_slice()).test_ok();
        assert_eq!(decoded.entity_id, "e1");
        assert!((decoded.predicted_prob - 0.75).abs() < 1e-10);
        assert_eq!(decoded.prediction_id, "p1");

        let out = draft_outcome(entity, "p1", true);
        assert_eq!(out.event_type.as_str(), EVENT_TYPE_OUTCOME);
        let decoded_o: OutcomePayload = ciborium::from_reader(out.payload.as_slice()).test_ok();
        assert_eq!(decoded_o.prediction_id, "p1");
        assert!(decoded_o.outcome);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_report_store_error_on_unknown_timeline() {
        let store = open_store(StoreConfig::Memory).test_ok();
        let missing = TimelineId::new();
        let err = compute_report(store.as_ref(), missing).test_err();
        assert!(matches!(err, EvalError::Store(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_report_decode_error_on_bad_prediction_payload() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-bad-pred").test_ok();
        let entity = EntityId::new();
        let draft = EventDraft::new(
            entity,
            Kind::new(EVENT_TYPE_PREDICTION),
            CanonicalBytes::from_vec(vec![0xFF, 0x00]),
        );
        store.append(tl.id(), &[draft]).test_ok();
        let err = compute_report(store.as_ref(), tl.id()).test_err();
        assert!(matches!(err, EvalError::Decode(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn compute_report_decode_error_on_bad_outcome_payload() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-bad-out").test_ok();
        let entity = EntityId::new();
        let draft = EventDraft::new(
            entity,
            Kind::new(EVENT_TYPE_OUTCOME),
            CanonicalBytes::from_vec(vec![0xFF, 0x00]),
        );
        store.append(tl.id(), &[draft]).test_ok();
        let err = compute_report(store.as_ref(), tl.id()).test_err();
        assert!(matches!(err, EvalError::Decode(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn crps_equals_brier_for_binary_outcomes() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-crps").test_ok();
        let entity = EntityId::new();
        append_prediction(store.as_mut(), tl.id(), entity, "e1", 0.8, "p1");
        append_prediction(store.as_mut(), tl.id(), entity, "e1", 0.3, "p2");
        append_outcome(store.as_mut(), tl.id(), entity, "p1", true);
        append_outcome(store.as_mut(), tl.id(), entity, "p2", false);
        let report = compute_report(store.as_ref(), tl.id()).test_ok();
        assert!((report.crps - report.brier_score).abs() < 1e-10);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn lift_vs_personal_base_rate_with_multiple_entities() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("eval-personal").test_ok();
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        append_prediction(store.as_mut(), tl.id(), e1, "a", 1.0, "p1");
        append_outcome(store.as_mut(), tl.id(), e1, "p1", true);
        append_prediction(store.as_mut(), tl.id(), e1, "a", 0.0, "p2");
        append_outcome(store.as_mut(), tl.id(), e1, "p2", false);
        append_prediction(store.as_mut(), tl.id(), e2, "b", 0.5, "p3");
        append_outcome(store.as_mut(), tl.id(), e2, "p3", false);
        let report = compute_report(store.as_ref(), tl.id()).test_ok();
        assert_eq!(report.n_resolved, 3);
        assert!((report.crps - report.brier_score).abs() < 1e-10);
        // personal base rate with leave-one-out: entity e1 (2 preds) gives
        // base rates excluding self; entity e2 (1 pred) gives base_rate=0
        assert!(report.lift_vs_personal_base_rate.is_finite());
    }
}
