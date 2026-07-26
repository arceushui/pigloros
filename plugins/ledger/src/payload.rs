//! CBOR event payloads for the ledger event types (`schema_version` 1).

use pos_core::{
    event::{CanonicalBytes, EventDraft, Kind},
    ids::EntityId,
};
use serde::{Deserialize, Serialize};

use crate::store::LedgerError;

/// Event type for a pre-registered prediction.
pub const EVENT_TYPE_PREDICTION: &str = "ledger.prediction";
/// Event type for a resolution of a prior prediction.
pub const EVENT_TYPE_OUTCOME: &str = "ledger.outcome";
/// Entity kind for ledger entries.
pub const ENTITY_KIND: &str = "ledger-entry";

/// Payload for a `ledger.prediction` event (also the TOML file form).
///
/// Dates are RFC-3339 strings: `made_at` is a UTC datetime
/// (`YYYY-MM-DDTHH:MM:SSZ`), `resolve_by` is a date (`YYYY-MM-DD`).
/// Strings keep the payload CBOR-stable and lexicographically sortable —
/// no date crate is pulled in (ADR-017).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LedgerPrediction {
    /// Stable id (ULID string) used to join with a later [`LedgerOutcome`].
    pub prediction_id: String,
    /// Short human-readable title.
    pub title: String,
    /// The falsifiable prediction statement.
    pub statement: String,
    /// The outcome label being predicted (binary domain: one side wins).
    pub predicted_outcome: String,
    /// Confidence in `[0.0, 1.0]` that `predicted_outcome` occurs.
    pub confidence: f64,
    /// Optional domain Scenario this prediction belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scenario: Option<String>,
    /// Registration time (RFC-3339 UTC datetime).
    pub made_at: String,
    /// Deadline for resolution (RFC-3339 date).
    pub resolve_by: String,
    /// OSF pre-registration URL/DOI. Required for display (ADR-017 Decision 8).
    pub osf_link: String,
}

/// Payload for a `ledger.outcome` event (also the TOML resolution file form).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LedgerOutcome {
    /// Must match a prior [`LedgerPrediction::prediction_id`].
    pub prediction_id: String,
    /// Observed binary outcome: `true` = the predicted outcome occurred.
    pub outcome: bool,
    /// Resolution time (RFC-3339 UTC datetime).
    pub resolved_at: String,
}

impl LedgerOutcome {
    /// Validate and construct a new [`LedgerOutcome`].
    ///
    /// # Errors
    /// Returns [`LedgerError::InvalidResolution`] if the `prediction_id` is
    /// not a ULID or `resolved_at` is not an RFC-3339 UTC datetime.
    pub fn new(
        prediction_id: String,
        outcome: bool,
        resolved_at: String,
    ) -> Result<Self, LedgerError> {
        let this = Self {
            prediction_id,
            outcome,
            resolved_at,
        };
        match crate::store::validate_outcome(&this) {
            Err(e) => Err(e),
            Ok(()) => Ok(this),
        }
    }
}

/// Build a `ledger.prediction` [`EventDraft`].
///
/// # Panics
/// Never panics; CBOR encoding of [`LedgerPrediction`] is infallible.
#[must_use]
pub fn draft_prediction(entity: EntityId, prediction: &LedgerPrediction) -> EventDraft {
    let mut buf = Vec::new();
    ciborium::into_writer(prediction, &mut buf).expect("ciborium write to Vec<u8> is infallible");
    EventDraft::new(
        entity,
        Kind::new(EVENT_TYPE_PREDICTION),
        CanonicalBytes::from_vec(buf),
    )
}

/// Build a `ledger.outcome` [`EventDraft`].
///
/// # Panics
/// Never panics; CBOR encoding of [`LedgerOutcome`] is infallible.
#[must_use]
pub fn draft_outcome(entity: EntityId, outcome: &LedgerOutcome) -> EventDraft {
    let mut buf = Vec::new();
    ciborium::into_writer(outcome, &mut buf).expect("ciborium write to Vec<u8> is infallible");
    EventDraft::new(
        entity,
        Kind::new(EVENT_TYPE_OUTCOME),
        CanonicalBytes::from_vec(buf),
    )
}

/// Decode a `ledger.prediction` payload.
///
/// # Errors
/// Returns [`LedgerError::Decode`] if the bytes are not a valid [`LedgerPrediction`].
pub fn decode_prediction(payload: &[u8]) -> Result<LedgerPrediction, LedgerError> {
    ciborium::from_reader(payload).map_err(|e| LedgerError::Decode(e.to_string()))
}

/// Decode a `ledger.outcome` payload.
///
/// # Errors
/// Returns [`LedgerError::Decode`] if the bytes are not a valid [`LedgerOutcome`].
pub fn decode_outcome(payload: &[u8]) -> Result<LedgerOutcome, LedgerError> {
    ciborium::from_reader(payload).map_err(|e| LedgerError::Decode(e.to_string()))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn sample_prediction(id: &str) -> LedgerPrediction {
        LedgerPrediction {
            prediction_id: id.to_owned(),
            title: "Kyoto vs Osaka".to_owned(),
            statement: "Kyoto will be chosen for the weekend trip".to_owned(),
            predicted_outcome: "Kyoto".to_owned(),
            confidence: 0.8,
            scenario: Some("places".to_owned()),
            made_at: "2026-07-25T12:00:00Z".to_owned(),
            resolve_by: "2026-08-01".to_owned(),
            osf_link: "https://osf.io/example".to_owned(),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn prediction_draft_decode_roundtrip() {
        let prediction = sample_prediction("01J3B0Y5ZK2J6MGK8D7QW3N0P4");
        let draft = draft_prediction(EntityId::new(), &prediction);
        assert_eq!(draft.event_type.as_str(), EVENT_TYPE_PREDICTION);
        let back = decode_prediction(draft.payload.as_slice()).unwrap();
        assert_eq!(back, prediction);
        // Scenario is optional and omitted from the encoding when absent.
        let mut no_scenario = prediction.clone();
        no_scenario.scenario = None;
        let draft = draft_prediction(EntityId::new(), &no_scenario);
        assert_eq!(
            decode_prediction(draft.payload.as_slice()).unwrap(),
            no_scenario
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn outcome_draft_decode_roundtrip() {
        let outcome = LedgerOutcome {
            prediction_id: "01J3B0Y5ZK2J6MGK8D7QW3N0P4".to_owned(),
            outcome: true,
            resolved_at: "2026-07-30T09:00:00Z".to_owned(),
        };
        let draft = draft_outcome(EntityId::new(), &outcome);
        assert_eq!(draft.event_type.as_str(), EVENT_TYPE_OUTCOME);
        assert_eq!(decode_outcome(draft.payload.as_slice()).unwrap(), outcome);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn decode_rejects_bad_bytes() {
        assert!(decode_prediction(&[0xff]).is_err());
        assert!(decode_outcome(&[0xff]).is_err());
    }
}
