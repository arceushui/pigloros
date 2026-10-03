//! Admitted staged Reducer of the Rule Agent Plugin (ADR-113 §7).
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

use crate::EVENT_TYPE_DECISION;

/// Tracks per-agent decision count in State.
pub struct RuleAgentReducer;

const _: () = assert!(core::mem::size_of::<RuleAgentReducer>() == 0);

impl Reducer for RuleAgentReducer {
    fn initial(&self) -> State {
        let mut s = State::new();
        s.set("decisions", serde_json::Value::Number(0.into()));
        s
    }

    fn apply(&self, state: &mut State, event: &Event) {
        if event.event_type.as_str() == EVENT_TYPE_DECISION {
            let decisions = state
                .get("decisions")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            state.set(
                "decisions",
                serde_json::Value::Number((decisions + 1).into()),
            );
        }
    }
}
