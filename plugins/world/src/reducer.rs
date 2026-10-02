//! Admitted staged Reducer of the World Plugin (ADR-113 §7).
//!
//! This module is the effect-free boundary checked by this crate's
//! `clippy.toml`: the `forbid` header below re-raises the disallowed
//! method, type and macro lists and the print, debug and exit lints, so no
//! item in this module can allow or expect any of them. The WOB1 decoder it
//! calls lives outside this module and is covered by review (ADR-113 §7).
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

use crate::{WorldObservationV1, EVENT_TYPE_OBSERVATION_V1};

/// Projects the latest accepted WOB1 body observation without a physics backend.
pub struct WorldReducer;

const _: () = assert!(core::mem::size_of::<WorldReducer>() == 0);

impl WorldReducer {
    fn accepted_observation(event: &Event) -> Option<WorldObservationV1> {
        if event.event_type.as_str() != EVENT_TYPE_OBSERVATION_V1 {
            return None;
        }
        let observation = WorldObservationV1::decode(&event.payload).ok()?;
        (observation.body_entity_id == event.entity).then_some(observation)
    }
}

impl Reducer for WorldReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn projects_event(&self, event: &Event) -> bool {
        Self::accepted_observation(event).is_some()
    }

    fn apply(&self, state: &mut State, event: &Event) {
        let Some(observation) = Self::accepted_observation(event) else {
            return;
        };
        let mut projected = State::new();
        projected.set(
            "body_entity_id",
            serde_json::json!(observation.body_entity_id.to_string()),
        );
        projected.set("tick", serde_json::json!(observation.tick));
        projected.set("step_index", serde_json::json!(observation.step_index));
        projected.set("pos_x", serde_json::json!(observation.pos_x));
        projected.set("pos_y", serde_json::json!(observation.pos_y));
        projected.set("pos_z", serde_json::json!(observation.pos_z));
        projected.set("orient_w", serde_json::json!(observation.orient_w));
        projected.set("orient_x", serde_json::json!(observation.orient_x));
        projected.set("orient_y", serde_json::json!(observation.orient_y));
        projected.set("orient_z", serde_json::json!(observation.orient_z));
        projected.set("vel_lin_x", serde_json::json!(observation.vel_lin_x));
        projected.set("vel_lin_y", serde_json::json!(observation.vel_lin_y));
        projected.set("vel_lin_z", serde_json::json!(observation.vel_lin_z));
        projected.set("vel_ang_x", serde_json::json!(observation.vel_ang_x));
        projected.set("vel_ang_y", serde_json::json!(observation.vel_ang_y));
        projected.set("vel_ang_z", serde_json::json!(observation.vel_ang_z));
        projected.set("sensor_kind", serde_json::json!(observation.sensor_kind));
        projected.set("sensor_value", serde_json::json!(observation.sensor_value));
        projected.set("observation_id", serde_json::json!(event.id.to_string()));
        projected.set("observation_seq", serde_json::json!(event.seq.as_u64()));
        projected.set(
            "causation_id",
            serde_json::json!(event.causation_id.as_ref().map(ToString::to_string)),
        );
        *state = projected;
    }
}
