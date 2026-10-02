//! Admitted staged Reducer of the Bridge Plugin (ADR-113 §7).
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

use crate::{BridgeObservation, EVENT_TYPE};

/// Tracks observation count and last value per entity.
pub struct BridgeReducer;

const _: () = assert!(core::mem::size_of::<BridgeReducer>() == 0);

impl Reducer for BridgeReducer {
    fn initial(&self) -> State {
        let mut s = State::new();
        s.set("observations", serde_json::Value::Number(0.into()));
        s.set("last_source", serde_json::Value::Null);
        s.set("last_value", serde_json::Value::Null);
        s.set("last_timestamp_micros", serde_json::Value::Number(0.into()));
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

        // Decode the CBOR payload and update last_* fields.
        if let Ok(observation) =
            ciborium::from_reader::<BridgeObservation, _>(event.payload.as_slice())
        {
            state.set("last_source", serde_json::Value::String(observation.source));
            state.set("last_value", observation.value);
            state.set(
                "last_timestamp_micros",
                serde_json::Value::Number(observation.timestamp_micros.into()),
            );
        }
    }
}
