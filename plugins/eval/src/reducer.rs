//! Admitted staged Reducer of the Eval Plugin (ADR-113 §7).
//!
//! This module is the effect-free boundary checked by this crate's
//! `clippy.toml`: the `forbid` header below re-raises the disallowed
//! method, type and macro lists and the print, debug and exit lints, so no
//! item in this module can allow or expect any of them. Crate helpers it
//! calls from outside this module are covered by review, not by this
//! `forbid` boundary (ADR-113 §7).
#![forbid(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::exit
)]

use pos_core::{
    event::Event,
    state::{Reducer, State},
};

use crate::{OutcomePayload, PredictionPayload, EVENT_TYPE_OUTCOME, EVENT_TYPE_PREDICTION};

/// Tracks prediction and outcome events in [`State`].
///
/// Each decoded record is appended in place to its array, so the work and
/// State growth of one `apply` are linear in the Event payload (ADR-113 §8).
pub struct EvalReducer;

const _: () = assert!(core::mem::size_of::<EvalReducer>() == 0);

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
                increment(state, "n_predictions");
                // Decode CBOR payload; skip silently on decode error.
                if let Ok(p) =
                    ciborium::from_reader::<PredictionPayload, _>(event.payload.as_slice())
                {
                    let record = serde_json::json!({
                        "prediction_id": p.prediction_id,
                        "predicted_prob": p.predicted_prob,
                    });
                    append(state, "predictions", record);
                }
            }
            EVENT_TYPE_OUTCOME => {
                increment(state, "n_outcomes");
                // Decode CBOR payload; skip silently on decode error.
                if let Ok(o) = ciborium::from_reader::<OutcomePayload, _>(event.payload.as_slice())
                {
                    let record = serde_json::json!({
                        "prediction_id": o.prediction_id,
                        "outcome": o.outcome,
                    });
                    append(state, "outcomes", record);
                }
            }
            _ => {}
        }
    }
}

/// Add one to a counter field, treating an absent or non-integer field as 0.
fn increment(state: &mut State, key: &str) {
    let n = state
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    state.set(key, serde_json::json!(n + 1));
}

/// Append one record to an array field in place, without cloning the array.
///
/// An absent or non-array field becomes a one-record array, exactly as the
/// earlier clone-and-reset fold produced.
fn append(state: &mut State, key: &str, record: serde_json::Value) {
    if let Some(serde_json::Value::Array(records)) = state.fields.get_mut(key) {
        records.push(record);
    } else {
        state.set(key, serde_json::Value::Array(vec![record]));
    }
}
