//! Admitted staged Reducer of the Synthetic Observation Plugin (ADR-113 §7).
//!
//! This module is the effect-free boundary checked by this crate's
//! `clippy.toml`: the `forbid` header below re-raises the disallowed
//! method, type and macro lists and the print, debug and exit lints, so no
//! item in this module can allow or expect any of them.
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

use crate::{ObsPayload, EVENT_TYPE};

/// Tracks observation count and last observed value in State.
pub struct SyntheticReducer;

const _: () = assert!(core::mem::size_of::<SyntheticReducer>() == 0);

impl Reducer for SyntheticReducer {
    fn initial(&self) -> State {
        let mut s = State::new();
        s.set("observations", serde_json::Value::Number(0.into()));
        // 0.0 is always a finite f64, so from_f64 cannot fail here.
        s.set("last_value", serde_json::json!(0.0));
        s
    }

    fn apply(&self, state: &mut State, event: &Event) {
        if event.event_type.as_str() != EVENT_TYPE {
            return;
        }

        let observations = state
            .get("observations")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        state.set(
            "observations",
            serde_json::Value::Number((observations + 1).into()),
        );

        // Decode the CBOR payload to extract last_value
        if let Ok(payload) = ciborium::from_reader::<ObsPayload, _>(event.payload.as_slice()) {
            if let Some(n) = serde_json::Number::from_f64(payload.value) {
                state.set("last_value", serde_json::Value::Number(n));
            }
        }
    }
}
