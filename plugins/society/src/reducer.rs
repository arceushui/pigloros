//! Admitted staged Reducer of the Society Plugin (ADR-113 §7).
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

use crate::{SocietyDimension, SocietySignal, EVENT_TYPE_SIGNAL};

/// Tracks per-dimension count, sum, mean, and last value.
pub struct SocietyReducer;

const _: () = assert!(core::mem::size_of::<SocietyReducer>() == 0);

impl SocietyReducer {
    fn dim_key(prefix: &str, dim: SocietyDimension) -> String {
        format!("{prefix}.{}", dim.as_str())
    }
}

impl Reducer for SocietyReducer {
    fn initial(&self) -> State {
        let mut s = State::new();
        let zero = serde_json::json!(0.0);
        for dim in SocietyDimension::all() {
            s.set(
                Self::dim_key("count", dim),
                serde_json::Value::Number(0.into()),
            );
            s.set(Self::dim_key("sum", dim), zero.clone());
            s.set(Self::dim_key("mean", dim), zero.clone());
            s.set(Self::dim_key("last", dim), serde_json::Value::Null);
        }
        s.set("signals", serde_json::Value::Number(0.into()));
        s
    }

    fn apply(&self, state: &mut State, event: &Event) {
        if event.event_type.as_str() != EVENT_TYPE_SIGNAL {
            return;
        }

        let Ok(signal) = ciborium::from_reader::<SocietySignal, _>(event.payload.as_slice()) else {
            return;
        };

        // Bad CBOR / non-finite samples do not bump `signals` or dimension stats.
        if !signal.value.is_finite() {
            return;
        }

        let signals = state
            .get("signals")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        state.set("signals", serde_json::Value::Number((signals + 1).into()));

        // Scaffold contract: samples are clamped to `[0.0, 1.0]`.
        let value = signal.value.clamp(0.0, 1.0);

        let dim = signal.dimension;
        let count = state
            .get(&Self::dim_key("count", dim))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            + 1;
        let sum = state
            .get(&Self::dim_key("sum", dim))
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0)
            + value;
        #[expect(
            clippy::cast_precision_loss,
            reason = "a sample count above 2^53 loses only mean precision, as on main"
        )]
        let mean = sum / (count as f64);

        state.set(
            Self::dim_key("count", dim),
            serde_json::Value::Number(count.into()),
        );
        // `value`/`sum`/`mean` are finite here, so `json!(f64)` always yields a Number.
        state.set(Self::dim_key("sum", dim), serde_json::json!(sum));
        state.set(Self::dim_key("mean", dim), serde_json::json!(mean));
        state.set(Self::dim_key("last", dim), serde_json::json!(value));
    }
}
