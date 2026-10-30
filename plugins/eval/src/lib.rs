#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-plugin-eval` — Wave 5 calibration harness.
//!
//! Owns event types `"eval.prediction"` and `"eval.outcome"` exclusively
//! (ADR-024 Revision 1). Tracks predictions and outcomes in State, provides
//! [`compute_report`] to produce a [`CalibrationReport`] from a timeline, and
//! supplies [`EvalDerivationDriver`], the only appender of `eval.*`, which
//! derives them from committed Persona prediction source Events.
//!
//! Every metric is computed by the ADR-062 Revision 7 integer micro-unit profile
//! (`pigloros.metric.binary-calibration` major 1): committed `eval.*` Events map to an
//! `MTI1` input ([`map_events_to_metric_input`]), which computes an `MTR1` result
//! ([`MetricInputV1::compute`]). No metric uses floating-point arithmetic.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

mod derivation;
mod event_mapping;
mod metric_profile;

pub use derivation::{
    derive_eval_units, EvalDerivationConfigV1, EvalDerivationDriver, EvalDerivationV1,
    EvalDiagnosticsV1, EvalIntegrityFindingKindV1, EvalIntegrityFindingV1,
    DERIVED_PREDICTION_ID_PREFIX, MIN_DRAFTS_PER_PASS,
};
pub use event_mapping::{
    compute_report, compute_report_from_evaluated_events, compute_report_from_events,
    map_events_to_metric_input, CalibrationReport, EvalEvidenceV1, EvalMetricMappingV1,
    DEFAULT_MINIMUM_SCORED_RECORDS,
};
pub use metric_profile::{
    decode_quantization_input_v1, encode_quantization_result_v1, quantize_probability,
    MetricCountsV1, MetricErrorV1, MetricFailureV1, MetricInputV1, MetricOutcomeV1,
    MetricRecordStateV1, MetricRecordV1, MetricRedactionStateV1, MetricResultV1, MetricValuesV1,
    ReliabilityBin, MAX_METRIC_IDENTIFIER_BYTES, MAX_METRIC_RECORDS, MAX_NESTING_DEPTH,
    MAX_QUANTIZATION_PATTERNS, METRIC_ALGORITHM_ID, METRIC_ALGORITHM_MAJOR, MICROS_PER_UNIT,
};

use pos_core::{
    event::Kind,
    ids::PluginId,
    plugin::{Capability, Plugin},
};
use pos_runtime::{InstalledPluginFactoryV1, InstalledPluginProductV1, NoActionApproverV1};
use serde::{Deserialize, Serialize};

mod reducer;

pub use reducer::EvalReducer;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Event type for predictions.
pub const EVENT_TYPE_PREDICTION: &str = "eval.prediction";
/// Event type for outcomes.
pub const EVENT_TYPE_OUTCOME: &str = "eval.outcome";
/// Entity kind for eval targets.
pub const ENTITY_KIND: &str = "eval-target";

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
    /// ADR-060 forbids this artifact from authoritative evaluator input.
    #[error("calibration artifact is unavailable for authoritative use")]
    ArtifactUnavailable,
    /// The derivation configuration cannot admit one whole unit per pass.
    #[error("derivation budget must admit at least one whole prediction unit")]
    InvalidConfiguration,
    /// The metric profile rejected the mapped input (ADR-062 Revision 7).
    #[error("metric input rejected: {0}")]
    Metric(#[from] MetricFailureV1),
    /// A second `eval.outcome` names an already resolved prediction (section 4.4 item 3).
    #[error("duplicate outcome at {coordinate}")]
    DuplicateOutcome {
        /// The `events/<i>` coordinate of the second outcome.
        coordinate: String,
    },
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

/// Provenance label of an `eval.outcome`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutcomeEvidenceV1 {
    /// The ground truth came from the predicting Plugin's own source Event,
    /// not from an independent observer. It is not independent outcome
    /// evidence; independence is owned by ADR-062.
    PredictorSupplied,
}

/// Payload for an `eval.outcome` event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutcomePayload {
    /// Must match a prior [`PredictionPayload::prediction_id`].
    pub prediction_id: String,
    /// Observed binary outcome.
    pub outcome: bool,
    /// Provenance label. Derived outcomes are labelled predictor-supplied;
    /// legacy outcomes carry no label and keep their exact encoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<OutcomeEvidenceV1>,
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
        evidence: None,
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

    /// Version 0.2.0 added the derivation Driver; version 0.3.0 quarantines
    /// bad eligible sources (ADR-024 Revision 2), so its pinned identity
    /// never matches an earlier Eval pin.
    fn version(&self) -> &'static str {
        "0.3.0"
    }

    /// Eval owns exactly `eval.prediction` and `eval.outcome` and supplies
    /// [`EvalDerivationDriver`] and [`EvalReducer`].
    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![
                Kind::new(EVENT_TYPE_PREDICTION),
                Kind::new(EVENT_TYPE_OUTCOME),
            ],
            owned_entity_kinds: vec![ENTITY_KIND.to_owned()],
            has_driver: true,
            has_reducer: true,
        }
    }
}

// Reviewed staged Reducer catalogue factory (ADR-113 §1): every protected
// candidate builds a fresh `EvalReducer` here and keeps only the reducer.
impl InstalledPluginFactoryV1 for EvalPlugin {
    type Configuration = ();
    type Plugin = Self;
    type Approver = NoActionApproverV1;

    fn configuration_details(_configuration: &()) -> Vec<u8> {
        pos_runtime::EMPTY_CONFIGURATION_DETAILS_V1.to_vec()
    }

    fn build(_configuration: &()) -> InstalledPluginProductV1<Self, NoActionApproverV1> {
        InstalledPluginProductV1 {
            plugin: Self::new(),
            reducer: Some(Box::new(EvalReducer)),
            approver: NoActionApproverV1,
        }
    }
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

    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, Event, Kind, SchemaVersion},
        ids::{EntityId, EventId},
        state::Reducer,
    };

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
            evidence: None,
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
            signature_identity: None,
            origin: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
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
        assert!(cap.has_driver);
        assert!(cap.has_reducer);
        assert_eq!(plugin.version(), "0.3.0");
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
    fn reducer_appends_in_place_and_replaces_absent_or_non_array_records() {
        let reducer = EvalReducer;
        let entity = EntityId::new();
        let prediction = make_event(
            entity,
            EVENT_TYPE_PREDICTION,
            encode_prediction("e1", 0.25, "p1"),
            1,
        );
        let outcome = make_event(entity, EVENT_TYPE_OUTCOME, encode_outcome("p1", true), 2);

        let mut absent = pos_core::state::State::new();
        reducer.apply(&mut absent, &prediction);
        reducer.apply(&mut absent, &outcome);
        let mut non_array = pos_core::state::State::new();
        non_array.set("predictions", serde_json::json!("not an array"));
        non_array.set("outcomes", serde_json::json!({ "stale": true }));
        reducer.apply(&mut non_array, &prediction);
        reducer.apply(&mut non_array, &outcome);

        for state in [&absent, &non_array] {
            assert_eq!(
                state.get("predictions"),
                Some(&serde_json::json!([{ "prediction_id": "p1", "predicted_prob": 0.25 }]))
            );
            assert_eq!(
                state.get("outcomes"),
                Some(&serde_json::json!([{ "prediction_id": "p1", "outcome": true }]))
            );
            assert_eq!(state.get("n_predictions"), Some(&serde_json::json!(1)));
            assert_eq!(state.get("n_outcomes"), Some(&serde_json::json!(1)));
        }

        let mut grown = reducer.initial();
        for _ in 0..3 {
            reducer.apply(&mut grown, &prediction);
        }
        assert_eq!(
            grown
                .get("predictions")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(3)
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
        assert_eq!(
            preds[0]["predicted_prob"].as_f64().map(f64::to_bits),
            Some(0.7_f64.to_bits())
        );
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
        assert_eq!(decoded.predicted_prob.to_bits(), 0.75_f64.to_bits());
        assert_eq!(decoded.prediction_id, "p1");

        let out = draft_outcome(entity, "p1", true);
        assert_eq!(out.event_type.as_str(), EVENT_TYPE_OUTCOME);
        let decoded_o: OutcomePayload = ciborium::from_reader(out.payload.as_slice()).test_ok();
        assert_eq!(decoded_o.prediction_id, "p1");
        assert!(decoded_o.outcome);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn staged_factory_builds_a_fresh_reducer_per_candidate() {
        use pos_runtime::{
            fold_detached_candidate_v1, HostProjectionProviderV1, InitialStateV1,
            ProtectedProjectionProviderV1, StagedReducerAdmissionErrorV1,
        };

        let mut provider = HostProjectionProviderV1::default();
        assert_eq!(
            EvalPlugin::configuration_details(&()),
            pos_runtime::EMPTY_CONFIGURATION_DETAILS_V1
        );
        assert_eq!(
            provider.admit::<EvalPlugin>(std::sync::Arc::new(())),
            Err(StagedReducerAdmissionErrorV1::ConformanceEvidenceMissing)
        );
        let consumer = provider
            .admit_fixture::<EvalPlugin>(std::sync::Arc::new(()))
            .test_ok();
        let source =
            pos_core::staged_install::ProjectionSourceV1::bound(pos_core::TimelineId::new(), None);
        let open = || provider.open_candidate(&[consumer], InitialStateV1::Empty, source);
        let mut folded = open().test_ok();
        let fresh = open().test_ok();
        let entity = EntityId::new();
        let event = make_event(
            entity,
            EVENT_TYPE_PREDICTION,
            encode_prediction("e1", 0.5, "p1"),
            1,
        );
        fold_detached_candidate_v1(&mut folded, std::slice::from_ref(&event));

        let mut expected = EvalReducer.initial();
        EvalReducer.apply(&mut expected, &event);
        assert_eq!(
            folded.state_for(consumer.plugin_id(), &entity),
            Some(&expected)
        );
        assert!(fresh.state_for(consumer.plugin_id(), &entity).is_none());
    }
}
