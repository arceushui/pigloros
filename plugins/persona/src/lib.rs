#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-plugin-persona` — calibrated digital twin plugin.
//!
//! This plugin represents a calibrated personal preference model as a simulation entity.
//! It owns event types `"persona.preference"`, `"persona.decision"` and the
//! versioned prediction source `"persona.prediction"`, and entity kind
//! `"persona"`. Under exclusive Event-type ownership (ADR-024 Revision 1)
//! Persona never emits `eval.*`; Eval derives its records from the committed
//! prediction source.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use pos_core::{
    event::{CanonicalBytes, Event, EventDraft, Kind},
    ids::{EntityId, PluginId, TimelineId},
    plugin::{Capability, Plugin},
    state::{Reducer, State},
};
use pos_runtime::{Driver, ObservationView, RuntimeError, StepOutput};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Event type for preference updates.
pub const EVENT_TYPE_PREFERENCE: &str = "persona.preference";
/// Event type for decisions.
pub const EVENT_TYPE_DECISION: &str = "persona.decision";
/// Event type for a Persona-owned prediction source (ADR-024 Revision 1
/// Decision 5). Eval's Driver derives `eval.prediction` / `eval.outcome`
/// from committed Events of this type.
pub const EVENT_TYPE_PREDICTION_SOURCE: &str = "persona.prediction";
/// The only prediction source payload version this crate defines.
pub const PREDICTION_SOURCE_VERSION_V1: u32 = 1;
/// Entity kind for personas.
pub const ENTITY_KIND: &str = "persona";

// ---------------------------------------------------------------------------
// Payload types (CBOR-serialized)
// ---------------------------------------------------------------------------

/// Payload for a `persona.preference` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreferencePayload {
    /// Preference dimension (e.g., "spicy", "sweet").
    pub dimension: String,
    /// Score in [-1.0, 1.0] range (negative = dislike, positive = like).
    pub score: f64,
    /// Confidence in this preference [0.0, 1.0].
    pub confidence: f64,
}

/// Payload for a `persona.decision` event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionPayload {
    /// First option presented.
    pub option_a: String,
    /// Second option presented.
    pub option_b: String,
    /// The chosen option.
    pub chosen: String,
    /// Probability of regret [0.0, 0.5].
    pub regret_prob: f64,
}

/// Whether a prediction source carries its outcome. The field is required in
/// every payload, so an outcome is either explicitly present or explicitly
/// absent; it is never silently missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PredictionOutcomeV1 {
    /// The source carries no outcome.
    Absent,
    /// The source carries the observed binary outcome.
    Observed(bool),
}

/// Payload for a `persona.prediction` source Event, version 1.
///
/// The ground truth, when present, is supplied by the predicting Persona
/// itself, so evaluation built from it is predictor-supplied evidence.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PredictionSourceV1 {
    /// Payload version; [`PREDICTION_SOURCE_VERSION_V1`] for this schema.
    pub version: u32,
    /// Predicted probability in `[0.0, 1.0]`.
    pub predicted_prob: f64,
    /// The explicit outcome field.
    pub outcome: PredictionOutcomeV1,
}

/// Build a version 1 `persona.prediction` source [`EventDraft`].
#[must_use]
pub fn draft_prediction_source(
    entity: EntityId,
    predicted_prob: f64,
    outcome: PredictionOutcomeV1,
) -> EventDraft {
    let payload = PredictionSourceV1 {
        version: PREDICTION_SOURCE_VERSION_V1,
        predicted_prob,
        outcome,
    };
    let mut buf = Vec::new();
    // `Vec<u8>` is an infallible CBOR sink.
    drop(ciborium::into_writer(&payload, &mut buf));
    EventDraft::new(
        entity,
        Kind::new(EVENT_TYPE_PREDICTION_SOURCE),
        CanonicalBytes::from_vec(buf),
    )
}

// ---------------------------------------------------------------------------
// PersonaPlugin descriptor
// ---------------------------------------------------------------------------

/// Persona plugin.
pub struct PersonaPlugin {
    id: PluginId,
}

impl Default for PersonaPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl PersonaPlugin {
    /// Create a new `PersonaPlugin`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: PluginId::new(),
        }
    }
}

impl Plugin for PersonaPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "persona"
    }

    /// Version 0.2.0 drops `eval.*` ownership for the prediction source, so
    /// its pinned identity never matches an earlier Persona pin.
    fn version(&self) -> &'static str {
        "0.2.0"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![
                Kind::new(EVENT_TYPE_PREFERENCE),
                Kind::new(EVENT_TYPE_DECISION),
                Kind::new(EVENT_TYPE_PREDICTION_SOURCE),
            ],
            owned_entity_kinds: vec![ENTITY_KIND.to_owned()],
            has_driver: true,
            has_reducer: true,
        }
    }
}

// ---------------------------------------------------------------------------
// PersonaReducer
// ---------------------------------------------------------------------------

/// Tracks persona preference and decision events in [`State`].
pub struct PersonaReducer;

impl Reducer for PersonaReducer {
    fn initial(&self) -> State {
        let mut s = State::new();
        s.set("preference_count", serde_json::json!(0_u64));
        s.set("decision_count", serde_json::json!(0_u64));
        s.set("last_regret_prob", serde_json::json!(0.0_f64));
        s
    }

    fn apply(&self, state: &mut State, event: &Event) {
        match event.event_type.as_str() {
            EVENT_TYPE_PREFERENCE => {
                let n = state
                    .get("preference_count")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                state.set("preference_count", serde_json::json!(n + 1));
            }
            EVENT_TYPE_DECISION => {
                let n = state
                    .get("decision_count")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                state.set("decision_count", serde_json::json!(n + 1));

                // Decode and store last regret_prob.
                if let Ok(payload) =
                    ciborium::from_reader::<DecisionPayload, _>(event.payload.as_slice())
                {
                    state.set("last_regret_prob", serde_json::json!(payload.regret_prob));
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// PersonaModel
// ---------------------------------------------------------------------------

/// A simple preference model (stub for Wave 5).
///
/// Stores a list of (dimension, score) pairs and scores options by matching
/// dimension names in the option strings.
#[derive(Debug, Clone)]
pub struct PersonaModel {
    preferences: Vec<(String, f64)>,
}

impl PersonaModel {
    /// Create a new `PersonaModel` from a list of (dimension, score) tuples.
    #[must_use]
    pub const fn new(preferences: Vec<(String, f64)>) -> Self {
        Self { preferences }
    }

    /// Score an option by summing preference scores where the dimension name
    /// appears in the option string.
    ///
    /// Returns a normalized score in [0.0, 1.0]. Returns 0.5 if no matches found.
    #[must_use]
    pub fn score_option(&self, option: &str) -> f64 {
        let mut total = 0.0;
        let mut count = 0;

        for (dimension, score) in &self.preferences {
            if option.contains(dimension) {
                total += score;
                count += 1;
            }
        }

        if count == 0 {
            return 0.5;
        }

        // Normalize: scores are in [-1, 1], map to [0, 1].
        let avg = total / f64::from(u32::try_from(count).unwrap_or(u32::MAX));
        f64::midpoint(avg, 1.0)
    }

    /// Generate a `persona.decision` event draft by comparing two options.
    ///
    /// Chooses the option with the higher score and computes a regret probability
    /// based on score difference (closer scores = higher regret).
    ///
    #[must_use]
    pub fn to_draft(&self, entity: EntityId, option_a: &str, option_b: &str) -> EventDraft {
        let score_a = self.score_option(option_a);
        let score_b = self.score_option(option_b);

        let (chosen, diff) = if score_a >= score_b {
            (option_a.to_owned(), score_a - score_b)
        } else {
            (option_b.to_owned(), score_b - score_a)
        };

        // regret_prob: map diff (0.0 to 1.0) to regret (0.5 to 0.0).
        // Closer scores (diff near 0) → higher regret (near 0.5).
        // Large diff (near 1.0) → low regret (near 0.0).
        let regret_prob = (1.0 - diff) * 0.5;

        let payload = DecisionPayload {
            option_a: option_a.to_owned(),
            option_b: option_b.to_owned(),
            chosen,
            regret_prob,
        };

        let mut buf = Vec::new();
        // `Vec<u8>` is an infallible CBOR sink.
        drop(ciborium::into_writer(&payload, &mut buf));

        EventDraft::new(
            entity,
            Kind::new(EVENT_TYPE_DECISION),
            CanonicalBytes::from_vec(buf),
        )
    }
}

// ---------------------------------------------------------------------------
// PersonaEvalDriver — closes the eval loop
// ---------------------------------------------------------------------------

/// One binary preference question used by [`PersonaEvalDriver`].
#[derive(Debug, Clone)]
pub struct PreferencePair {
    /// Option A description (matched against preference dimensions).
    pub option_a: String,
    /// Option B description.
    pub option_b: String,
    /// Ground-truth: whether the user actually prefers A over B.
    pub prefers_a: bool,
}

/// Driver that emits `persona.decision` plus a Persona-owned prediction source
/// each tick. Eval's own Driver closes the calibration loop in a later pass.
///
/// On tick `i` (cycling through `pairs`):
/// 1. `persona.decision` from [`PersonaModel::to_draft`]
/// 2. `persona.prediction` with `predicted_prob = score(option_a)`
///    (P(prefer A)) and the pair's ground-truth `prefers_a` as its outcome
pub struct PersonaEvalDriver {
    entity: EntityId,
    model: PersonaModel,
    pairs: Vec<PreferencePair>,
    tick: u64,
}

impl PersonaEvalDriver {
    /// Create a driver over the given preference pairs.
    ///
    #[must_use]
    pub const fn new(entity: EntityId, model: PersonaModel, pairs: Vec<PreferencePair>) -> Self {
        Self {
            entity,
            model,
            pairs,
            tick: 0,
        }
    }
}

impl Driver for PersonaEvalDriver {
    fn name(&self) -> &'static str {
        "persona-eval"
    }

    fn step(
        &mut self,
        _timeline: TimelineId,
        _observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        if self.pairs.is_empty() {
            return Err(RuntimeError::InvalidPayload {
                event_type: EVENT_TYPE_DECISION.to_owned(),
                reason: "persona evaluation pair catalogue is empty".to_owned(),
            });
        }
        let idx =
            usize::try_from(self.tick % u64::try_from(self.pairs.len()).unwrap_or(1)).unwrap_or(0);
        let pair = &self.pairs[idx];

        let predicted_prob = self.model.score_option(&pair.option_a);
        let decision = self
            .model
            .to_draft(self.entity, &pair.option_a, &pair.option_b);
        let source = draft_prediction_source(
            self.entity,
            predicted_prob,
            PredictionOutcomeV1::Observed(pair.prefers_a),
        );

        self.tick += 1;
        Ok(StepOutput::new(vec![decision, source]))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::SchemaVersion,
        ids::EventId,
    };

    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected persona fixture error: {error:?}"
                )))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("missing persona fixture value"))
            })
        }
    }

    fn quiet_workspace_pair() -> PreferencePair {
        PreferencePair {
            option_a: "quiet workspace".to_owned(),
            option_b: "busy workspace".to_owned(),
            prefers_a: true,
        }
    }

    // ── PersonaPlugin tests ──────────────────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_new_and_default_have_same_name() {
        let p1 = PersonaPlugin::new();
        let p2 = PersonaPlugin::default();
        assert_eq!(p1.name(), p2.name());
        assert_eq!(p1.name(), "persona");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_id_is_unique() {
        let p1 = PersonaPlugin::new();
        let p2 = PersonaPlugin::new();
        assert_ne!(p1.id(), p2.id());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_capability() {
        let plugin = PersonaPlugin::new();
        let cap = plugin.capability();
        let owned: Vec<&str> = cap.owned_event_types.iter().map(Kind::as_str).collect();
        assert_eq!(
            owned,
            vec![
                EVENT_TYPE_PREFERENCE,
                EVENT_TYPE_DECISION,
                EVENT_TYPE_PREDICTION_SOURCE
            ]
        );
        assert!(owned
            .iter()
            .all(|event_type| !event_type.starts_with("eval.")));
        assert_eq!(cap.owned_entity_kinds, vec![ENTITY_KIND.to_owned()]);
        assert!(cap.has_driver);
        assert!(cap.has_reducer);
        assert_eq!(plugin.version(), "0.2.0");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn empty_preference_pairs_fail_closed() {
        let mut driver =
            PersonaEvalDriver::new(EntityId::new(), PersonaModel::new(Vec::new()), Vec::new());
        let result = driver.step(TimelineId::new(), ObservationView::empty());
        assert!(matches!(
            result,
            Err(RuntimeError::InvalidPayload { event_type, .. })
                if event_type == EVENT_TYPE_DECISION
        ));
    }

    // ── PersonaReducer tests ──────────────────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_initial_state() {
        let reducer = PersonaReducer;
        let state = reducer.initial();
        assert_eq!(
            state
                .get("preference_count")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
        assert_eq!(
            state
                .get("decision_count")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
        assert_eq!(
            state
                .get("last_regret_prob")
                .and_then(serde_json::Value::as_f64),
            Some(0.0)
        );
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

    fn encode_preference(dimension: &str, score: f64, confidence: f64) -> Vec<u8> {
        let p = PreferencePayload {
            dimension: dimension.to_owned(),
            score,
            confidence,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&p, &mut buf).test_ok();
        buf
    }

    fn encode_decision(option_a: &str, option_b: &str, chosen: &str, regret_prob: f64) -> Vec<u8> {
        let d = DecisionPayload {
            option_a: option_a.to_owned(),
            option_b: option_b.to_owned(),
            chosen: chosen.to_owned(),
            regret_prob,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&d, &mut buf).test_ok();
        buf
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_applies_preference_events() {
        let reducer = PersonaReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let event = make_event(
            entity,
            EVENT_TYPE_PREFERENCE,
            encode_preference("spicy", 0.8, 0.9),
            1,
        );
        reducer.apply(&mut state, &event);

        assert_eq!(
            state
                .get("preference_count")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_applies_decision_events() {
        let reducer = PersonaReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let event = make_event(
            entity,
            EVENT_TYPE_DECISION,
            encode_decision("pizza", "sushi", "pizza", 0.15),
            1,
        );
        reducer.apply(&mut state, &event);

        assert_eq!(
            state
                .get("decision_count")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert!(
            (state
                .get("last_regret_prob")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0)
                - 0.15)
                .abs()
                < 1e-10
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_ignores_other_event_types() {
        let reducer = PersonaReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let event = make_event(entity, "some.other.event", vec![], 1);
        reducer.apply(&mut state, &event);

        assert_eq!(
            state
                .get("preference_count")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
        assert_eq!(
            state
                .get("decision_count")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_tracks_multiple_preferences() {
        let reducer = PersonaReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        for i in 0..5 {
            let event = make_event(
                entity,
                EVENT_TYPE_PREFERENCE,
                encode_preference("test", 0.5, 0.8),
                i,
            );
            reducer.apply(&mut state, &event);
        }

        assert_eq!(
            state
                .get("preference_count")
                .and_then(serde_json::Value::as_u64),
            Some(5)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_tracks_multiple_decisions() {
        let reducer = PersonaReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        for i in 0..3 {
            let event = make_event(
                entity,
                EVENT_TYPE_DECISION,
                encode_decision("a", "b", "a", 0.2),
                i,
            );
            reducer.apply(&mut state, &event);
        }

        assert_eq!(
            state
                .get("decision_count")
                .and_then(serde_json::Value::as_u64),
            Some(3)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_updates_last_regret_prob_from_latest_decision() {
        let reducer = PersonaReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let event1 = make_event(
            entity,
            EVENT_TYPE_DECISION,
            encode_decision("a", "b", "a", 0.1),
            1,
        );
        reducer.apply(&mut state, &event1);
        assert!(
            (state
                .get("last_regret_prob")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0)
                - 0.1)
                .abs()
                < 1e-10
        );

        let event2 = make_event(
            entity,
            EVENT_TYPE_DECISION,
            encode_decision("c", "d", "d", 0.3),
            2,
        );
        reducer.apply(&mut state, &event2);
        assert!(
            (state
                .get("last_regret_prob")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0)
                - 0.3)
                .abs()
                < 1e-10
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_handles_bad_cbor_payload_gracefully() {
        let reducer = PersonaReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        // Bad CBOR payload — decision_count increments, but last_regret_prob stays 0.0.
        let event = make_event(entity, EVENT_TYPE_DECISION, vec![0xFF, 0x00], 1);
        reducer.apply(&mut state, &event);

        assert_eq!(
            state
                .get("decision_count")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert_eq!(
            state
                .get("last_regret_prob")
                .and_then(serde_json::Value::as_f64),
            Some(0.0)
        );
    }

    // ── PersonaModel tests ────────────────────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn model_score_option_with_match() {
        let model = PersonaModel::new(vec![("spicy".to_owned(), 1.0)]);
        let score = model.score_option("spicy pizza");
        // score = 1.0, normalized to [0, 1]: (1.0 + 1.0) / 2.0 = 1.0
        assert!((score - 1.0).abs() < 1e-10);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn model_score_option_no_match() {
        let model = PersonaModel::new(vec![("spicy".to_owned(), 1.0)]);
        let score = model.score_option("bland soup");
        assert!((score - 0.5).abs() < 1e-10); // default score
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn model_score_option_multiple_matches() {
        let model = PersonaModel::new(vec![("spicy".to_owned(), 1.0), ("sweet".to_owned(), -1.0)]);
        let score = model.score_option("spicy and sweet dessert");
        // avg = (1.0 + (-1.0)) / 2 = 0.0, normalized: (0.0 + 1.0) / 2.0 = 0.5
        assert!((score - 0.5).abs() < 1e-10);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn model_score_option_negative_preference() {
        let model = PersonaModel::new(vec![("bitter".to_owned(), -0.5)]);
        let score = model.score_option("bitter coffee");
        // score = -0.5, normalized: (-0.5 + 1.0) / 2.0 = 0.25
        assert!((score - 0.25).abs() < 1e-10);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn model_to_draft_chooses_higher_score() {
        let model = PersonaModel::new(vec![("spicy".to_owned(), 1.0)]);
        let entity = EntityId::new();
        let draft = model.to_draft(entity, "spicy pizza", "bland soup");

        assert_eq!(draft.event_type.as_str(), EVENT_TYPE_DECISION);
        assert_eq!(draft.entity, entity);

        // Decode payload
        let payload: DecisionPayload = ciborium::from_reader(draft.payload.as_slice()).test_ok();
        assert_eq!(payload.chosen, "spicy pizza");
        assert_eq!(payload.option_a, "spicy pizza");
        assert_eq!(payload.option_b, "bland soup");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn model_to_draft_regret_prob_in_valid_range() {
        let model = PersonaModel::new(vec![("spicy".to_owned(), 1.0)]);
        let entity = EntityId::new();
        let draft = model.to_draft(entity, "spicy pizza", "bland soup");

        let payload: DecisionPayload = ciborium::from_reader(draft.payload.as_slice()).test_ok();
        assert!(payload.regret_prob >= 0.0);
        assert!(payload.regret_prob <= 0.5);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn model_to_draft_close_scores_high_regret() {
        let model = PersonaModel::new(vec![]);
        let entity = EntityId::new();
        let draft = model.to_draft(entity, "a", "b");

        // Both options score 0.5 (no match) → diff=0.0 → regret=0.5
        let payload: DecisionPayload = ciborium::from_reader(draft.payload.as_slice()).test_ok();
        assert!((payload.regret_prob - 0.5).abs() < 1e-10);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn model_to_draft_large_diff_low_regret() {
        let model = PersonaModel::new(vec![("best".to_owned(), 1.0)]);
        let entity = EntityId::new();
        let draft = model.to_draft(entity, "best option", "worst option");

        // score_a = 1.0, score_b = 0.5, diff = 0.5 → regret = (1.0 - 0.5) * 0.5 = 0.25
        let payload: DecisionPayload = ciborium::from_reader(draft.payload.as_slice()).test_ok();
        assert!((payload.regret_prob - 0.25).abs() < 1e-10);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn model_to_draft_tie_chooses_a() {
        let model = PersonaModel::new(vec![]);
        let entity = EntityId::new();
        let draft = model.to_draft(entity, "option a", "option b");

        // Both score 0.5 → tie, chooses option_a due to `>=` in comparison
        let payload: DecisionPayload = ciborium::from_reader(draft.payload.as_slice()).test_ok();
        assert_eq!(payload.chosen, "option a");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn model_score_option_empty_preferences() {
        let model = PersonaModel::new(vec![]);
        let score = model.score_option("anything");
        assert!((score - 0.5).abs() < 1e-10);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn model_to_draft_produces_valid_cbor() {
        let model = PersonaModel::new(vec![("good".to_owned(), 0.5)]);
        let entity = EntityId::new();
        let draft = model.to_draft(entity, "good choice", "bad choice");

        // Verify CBOR round-trip
        let payload: DecisionPayload = ciborium::from_reader(draft.payload.as_slice()).test_ok();
        let mut buf2 = Vec::new();
        ciborium::into_writer(&payload, &mut buf2).test_ok();
        let payload2: DecisionPayload = ciborium::from_reader(buf2.as_slice()).test_ok();
        assert_eq!(payload.chosen, payload2.chosen);
        assert_eq!(payload.option_a, payload2.option_a);
        assert_eq!(payload.option_b, payload2.option_b);
        assert!((payload.regret_prob - payload2.regret_prob).abs() < 1e-10);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn payload_preference_cbor_round_trip() {
        let p = PreferencePayload {
            dimension: "spicy".to_owned(),
            score: 0.75,
            confidence: 0.9,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&p, &mut buf).test_ok();
        let p2: PreferencePayload = ciborium::from_reader(buf.as_slice()).test_ok();
        assert_eq!(p.dimension, p2.dimension);
        assert!((p.score - p2.score).abs() < 1e-10);
        assert!((p.confidence - p2.confidence).abs() < 1e-10);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn payload_decision_cbor_round_trip() {
        let d = DecisionPayload {
            option_a: "a".to_owned(),
            option_b: "b".to_owned(),
            chosen: "a".to_owned(),
            regret_prob: 0.2,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&d, &mut buf).test_ok();
        let d2: DecisionPayload = ciborium::from_reader(buf.as_slice()).test_ok();
        assert_eq!(d.option_a, d2.option_a);
        assert_eq!(d.option_b, d2.option_b);
        assert_eq!(d.chosen, d2.chosen);
        assert!((d.regret_prob - d2.regret_prob).abs() < 1e-10);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn model_multiple_preferences_averaging() {
        let model = PersonaModel::new(vec![("spicy".to_owned(), 1.0), ("hot".to_owned(), 0.8)]);
        let score = model.score_option("spicy hot wings");
        // avg = (1.0 + 0.8) / 2 = 0.9, normalized: (0.9 + 1.0) / 2.0 = 0.95
        assert!((score - 0.95).abs() < 1e-10);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn model_to_draft_option_b_wins() {
        let model = PersonaModel::new(vec![("best".to_owned(), 1.0)]);
        let entity = EntityId::new();
        let draft = model.to_draft(entity, "worst", "best option");

        let payload: DecisionPayload = ciborium::from_reader(draft.payload.as_slice()).test_ok();
        assert_eq!(payload.chosen, "best option");
    }

    // ── PersonaEvalDriver tests ───────────────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn persona_eval_driver_emits_decision_and_prediction_source() {
        let model = PersonaModel::new(vec![("quiet".to_owned(), 0.8)]);
        let entity = EntityId::new();
        let mut driver = PersonaEvalDriver::new(entity, model, vec![quiet_workspace_pair()]);
        assert_eq!(driver.name(), "persona-eval");

        let out = driver
            .step(TimelineId::new(), ObservationView::empty())
            .test_ok();

        assert_eq!(out.drafts.len(), 2);
        assert_eq!(out.drafts[0].event_type.as_str(), EVENT_TYPE_DECISION);
        assert_eq!(
            out.drafts[1].event_type.as_str(),
            EVENT_TYPE_PREDICTION_SOURCE
        );
        assert_eq!(out.drafts[1].entity, entity);
        let source: PredictionSourceV1 =
            ciborium::from_reader(out.drafts[1].payload.as_slice()).test_ok();
        assert_eq!(source.version, PREDICTION_SOURCE_VERSION_V1);
        assert!((source.predicted_prob - 0.9).abs() < 1e-10);
        assert_eq!(source.outcome, PredictionOutcomeV1::Observed(true));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn prediction_source_records_an_explicitly_absent_outcome() {
        let draft = draft_prediction_source(EntityId::new(), 0.25, PredictionOutcomeV1::Absent);
        let source: PredictionSourceV1 = ciborium::from_reader(draft.payload.as_slice()).test_ok();
        assert_eq!(source.outcome, PredictionOutcomeV1::Absent);
        assert_eq!(source.version, PREDICTION_SOURCE_VERSION_V1);
    }
}
