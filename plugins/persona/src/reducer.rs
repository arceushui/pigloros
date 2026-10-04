//! Admitted staged Reducer of the Persona Plugin (ADR-113 §7).
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

use crate::{DecisionPayload, EVENT_TYPE_DECISION, EVENT_TYPE_PREFERENCE};

/// Tracks persona preference and decision events in [`State`].
pub struct PersonaReducer;

const _: () = assert!(core::mem::size_of::<PersonaReducer>() == 0);

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
