//! Fixtures shared by Eval's derivation tests: Persona prediction source
//! drafts, good or deliberately bad, and the `eval.*` drafts an earlier pass
//! would have committed for a source.

use pos_core::{
    event::{CanonicalBytes, EventDraft, Kind},
    ids::{EntityId, EventId},
};
use pos_plugin_eval::{EvalIntegrityFindingKindV1, EvalIntegrityFindingV1};
use pos_plugin_persona::{PredictionOutcomeV1, PredictionSourceV1, EVENT_TYPE_PREDICTION_SOURCE};

pub trait TestValueExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected eval error: {error:?}")))
        })
    }
}

pub trait TestOptionExt<T> {
    fn test_ok_option(self) -> T;
}

impl<T> TestOptionExt<T> for Option<T> {
    fn test_ok_option(self) -> T {
        self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing fixture value")))
    }
}

#[must_use]
pub fn encoded<T: serde::Serialize>(payload: &T) -> CanonicalBytes {
    let mut buf = Vec::new();
    ciborium::into_writer(payload, &mut buf).test_ok();
    CanonicalBytes::from_vec(buf)
}

fn source_draft(entity: EntityId, payload: CanonicalBytes) -> EventDraft {
    EventDraft::new(entity, Kind::new(EVENT_TYPE_PREDICTION_SOURCE), payload)
}

/// A source with an explicit version, probability and outcome.
#[must_use]
pub fn raw_source(
    entity: EntityId,
    version: u32,
    predicted_prob: f64,
    outcome: PredictionOutcomeV1,
) -> EventDraft {
    source_draft(
        entity,
        encoded(&PredictionSourceV1 {
            version,
            predicted_prob,
            outcome,
        }),
    )
}

/// A source with a readable envelope and version but no prediction fields.
#[must_use]
pub fn envelope_only(entity: EntityId, version: u32) -> EventDraft {
    #[derive(serde::Serialize)]
    struct Envelope {
        version: u32,
    }
    source_draft(entity, encoded(&Envelope { version }))
}

/// A source whose payload is not CBOR at all.
#[must_use]
pub fn unreadable(entity: EntityId) -> EventDraft {
    source_draft(entity, CanonicalBytes::from_vec(vec![0xff]))
}

/// The `eval.prediction` and/or `eval.outcome` drafts naming `source`, as an
/// earlier pass would have committed them.
#[must_use]
pub fn naming_drafts(source: EventId, prediction: bool, outcome: bool) -> Vec<EventDraft> {
    let prediction_id = format!("eval:src:{source}");
    let entity = EntityId::new();
    let prediction = prediction
        .then(|| pos_plugin_eval::draft_prediction(entity, "injected", 0.5, &prediction_id));
    let outcome = outcome.then(|| pos_plugin_eval::draft_outcome(entity, &prediction_id, true));
    prediction
        .into_iter()
        .chain(outcome)
        .map(|mut draft| {
            draft.causation_id = Some(source);
            draft
        })
        .collect()
}

#[must_use]
pub const fn finding(source: EventId, kind: EvalIntegrityFindingKindV1) -> EvalIntegrityFindingV1 {
    EvalIntegrityFindingV1 { source, kind }
}
