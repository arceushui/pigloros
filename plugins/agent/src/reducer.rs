//! Admitted staged Reducer of the Agent Plugin (ADR-113 §7).
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

use crate::{protocol, ActionPayload, EVENT_TYPE_ACTION};

/// Tracks per-agent action count and last action in State.
pub struct AgentReducer;

const _: () = assert!(core::mem::size_of::<AgentReducer>() == 0);

impl Reducer for AgentReducer {
    fn initial(&self) -> State {
        let mut s = State::new();
        s.set("action_count", serde_json::Value::Number(0.into()));
        s.set("last_action", serde_json::Value::String(String::new()));
        s
    }

    fn apply(&self, state: &mut State, event: &Event) {
        if event.event_type.as_str() == EVENT_TYPE_ACTION {
            let action_count = state
                .get("action_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            state.set(
                "action_count",
                serde_json::Value::Number((action_count + 1).into()),
            );

            let action = if protocol::is_agent_action_wire(event.payload.as_slice()) {
                protocol::AgentActionV1::decode(event.payload.as_slice())
                    .ok()
                    .map(|payload| payload.action_id().to_owned())
            } else {
                ciborium::from_reader::<ActionPayload, _>(event.payload.as_slice())
                    .ok()
                    .map(|payload| payload.action)
            };
            if let Some(action) = action {
                state.set("last_action", serde_json::Value::String(action));
            }
        }
    }
}
