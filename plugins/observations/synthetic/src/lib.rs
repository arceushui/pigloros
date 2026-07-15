#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-plugin-synthetic-obs` — deterministic synthetic observation source plugin.
//!
//! Owns event type `"obs.synthetic"` and entity kind `"synthetic-source"`.
//! On each driver step it produces one observation event with a sinusoidal
//! value derived purely from the tick counter — no external entropy.

use pos_core::{
    event::{CanonicalBytes, Event, Kind},
    ids::{EntityId, PluginId, TimelineId},
    plugin::{Capability, Plugin},
    state::{Reducer, State},
    store::EventStore,
};
use pos_runtime::{Driver, RuntimeError, StepOutput};
use serde::{Deserialize, Serialize};

/// The entity kind string for synthetic observation sources.
pub const ENTITY_KIND: &str = "synthetic-source";

/// The event type for synthetic observations.
pub const EVENT_TYPE: &str = "obs.synthetic";

// ---------------------------------------------------------------------------
// Payload types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ObsPayload {
    value: f64,
    tick: u64,
}

// ---------------------------------------------------------------------------
// Plugin descriptor
// ---------------------------------------------------------------------------

/// A deterministic synthetic observation source plugin.
pub struct SyntheticObsPlugin {
    id: PluginId,
}

impl Default for SyntheticObsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl SyntheticObsPlugin {
    /// Create a new synthetic observation plugin.
    #[must_use]
    pub fn new() -> Self {
        Self { id: PluginId::new() }
    }
}

impl Plugin for SyntheticObsPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "synthetic-obs"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(EVENT_TYPE)],
            owned_entity_kinds: vec![ENTITY_KIND.to_owned()],
            has_driver: true,
            has_reducer: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// Produces one `obs.synthetic` event per step.
///
/// Value formula: `sin(tick * 0.1) * amplitude`.
/// Fully deterministic given the same starting tick.
pub struct SyntheticDriver {
    entity: EntityId,
    tick: u64,
    amplitude: f64,
}

impl SyntheticDriver {
    /// Create a new driver for the given entity with default amplitude 1.0.
    #[must_use]
    pub fn new(entity: EntityId) -> Self {
        Self { entity, tick: 0, amplitude: 1.0 }
    }

    /// Create a new driver with a custom amplitude.
    #[must_use]
    pub fn with_amplitude(entity: EntityId, amplitude: f64) -> Self {
        Self { entity, tick: 0, amplitude }
    }
}

impl Driver for SyntheticDriver {
    fn name(&self) -> &'static str {
        "synthetic-driver"
    }

    fn step(
        &mut self,
        _store: &dyn EventStore,
        _timeline: TimelineId,
    ) -> Result<StepOutput, RuntimeError> {
        #[allow(clippy::cast_precision_loss)]
        let value = (self.tick as f64 * 0.1_f64).sin() * self.amplitude;
        let payload = ObsPayload { value, tick: self.tick };

        let mut buf = Vec::new();
        // Writing to Vec<u8> is infallible with ciborium.
        ciborium::into_writer(&payload, &mut buf)
            .expect("ciborium write to Vec<u8> is infallible");

        let draft = pos_core::event::EventDraft::new(
            self.entity,
            Kind::new(EVENT_TYPE),
            CanonicalBytes::from_vec(buf),
        );

        self.tick += 1;
        Ok(StepOutput::new(vec![draft]))
    }
}

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------

/// Tracks observation count and last observed value in State.
pub struct SyntheticReducer;

impl Reducer for SyntheticReducer {
    fn initial(&self) -> State {
        let mut s = State::new();
        s.set("observations", serde_json::Value::Number(0.into()));
        s.set(
            "last_value",
            serde_json::Value::Number(
                serde_json::Number::from_f64(0.0)
                    .unwrap_or_else(|| serde_json::Number::from(0)),
            ),
        );
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
        state.set("observations", serde_json::Value::Number((observations + 1).into()));

        // Decode the CBOR payload to extract last_value
        if let Ok(payload) = ciborium::from_reader::<ObsPayload, _>(event.payload.as_slice()) {
            if let Some(n) = serde_json::Number::from_f64(payload.value) {
                state.set("last_value", serde_json::Value::Number(n));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, SchemaVersion},
        ids::{EntityId, EventId},
    };
    use pos_store::{open_store, StoreConfig};

    fn make_obs_event(entity: EntityId, value: f64, tick: u64) -> Event {
        let payload = ObsPayload { value, tick };
        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).unwrap();

        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(EVENT_TYPE),
            payload: CanonicalBytes::from_vec(buf),
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
    }

    #[test]
    fn plugin_capability_is_correct() {
        let plugin = SyntheticObsPlugin::new();
        let cap = plugin.capability();

        assert_eq!(cap.owned_event_types.len(), 1);
        assert_eq!(cap.owned_event_types[0].as_str(), EVENT_TYPE);
        assert_eq!(cap.owned_entity_kinds.len(), 1);
        assert_eq!(cap.owned_entity_kinds[0], ENTITY_KIND);
        assert!(cap.has_driver);
        assert!(cap.has_reducer);
    }

    #[test]
    fn default_creates_plugin() {
        let plugin = SyntheticObsPlugin::default();
        let cap = plugin.capability();
        assert_eq!(cap.owned_event_types.len(), 1);
    }

    #[test]
    fn plugin_id_name_capability() {
        let plugin = SyntheticObsPlugin::new();
        let _id = plugin.id(); // covers Plugin::id()
        assert_eq!(plugin.name(), "synthetic-obs");
        let cap = plugin.capability();
        assert_eq!(cap.owned_event_types[0].as_str(), EVENT_TYPE);
        assert_eq!(cap.owned_entity_kinds[0], ENTITY_KIND);
        assert!(cap.has_driver);
        assert!(cap.has_reducer);
    }

    #[test]
    fn driver_name_is_correct() {
        let entity = EntityId::new();
        let driver = SyntheticDriver::new(entity);
        assert_eq!(driver.name(), "synthetic-driver");
    }

    #[test]
    fn with_amplitude_driver_scales_values() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test-amp").unwrap();
        let entity = EntityId::new();
        let mut driver = SyntheticDriver::with_amplitude(entity, 2.0);
        let out = driver.step(store.as_ref(), tl.id()).unwrap();
        let payload: ObsPayload = ciborium::from_reader(out.drafts[0].payload.as_slice()).unwrap();
        // tick=0 → sin(0) * 2.0 = 0.0
        assert!((payload.value - 0.0_f64).abs() < f64::EPSILON);
    }

    #[test]
    fn driver_produces_deterministic_values() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let tl = store.create_timeline("test").unwrap();
        let entity = EntityId::new();

        // Compute expected values from the formula
        let expected: Vec<f64> = (0..3_u64)
            .map(|tick| {
                #[allow(clippy::cast_precision_loss)]
                let v = (tick as f64 * 0.1_f64).sin();
                v
            })
            .collect();

        // Run the driver twice from tick=0 — same seed → same values
        for _ in 0..2 {
            let mut driver = SyntheticDriver::new(entity);
            for &expected_val in &expected {
                let out = driver.step(store.as_ref(), tl.id()).unwrap();
                assert_eq!(out.drafts.len(), 1);

                let payload: ObsPayload =
                    ciborium::from_reader(out.drafts[0].payload.as_slice()).unwrap();
                assert!(
                    (payload.value - expected_val).abs() < f64::EPSILON,
                    "value mismatch: got {}, expected {}",
                    payload.value,
                    expected_val,
                );
            }
        }
    }

    #[test]
    fn reducer_tracks_observation_count() {
        let reducer = SyntheticReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        assert_eq!(state.get("observations").and_then(serde_json::Value::as_u64), Some(0));

        for i in 0..3_u64 {
            #[allow(clippy::cast_precision_loss)]
            let value = (i as f64 * 0.1_f64).sin();
            let event = make_obs_event(entity, value, i);
            reducer.apply(&mut state, &event);
        }

        assert_eq!(state.get("observations").and_then(serde_json::Value::as_u64), Some(3));
    }

    #[test]
    fn reducer_skips_invalid_cbor_payload() {
        // Covers the outer `if let Ok(payload)` else branch (line 175):
        // when the CBOR can't be decoded, the block is skipped silently.
        use pos_core::{
            clock::{Seq, WallTime},
            crypto::Hash,
            event::{CanonicalBytes, SchemaVersion},
            ids::{EntityId, EventId},
        };
        let reducer = SyntheticReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let bad_event = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(EVENT_TYPE),
            payload: CanonicalBytes::from_vec(vec![0xFF, 0xFE, 0xFD]), // invalid CBOR
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };
        reducer.apply(&mut state, &bad_event);
        // observations is incremented even though payload decode failed
        assert_eq!(state.get("observations").and_then(serde_json::Value::as_u64), Some(1));
    }

    #[test]
    fn reducer_ignores_non_matching_event_type() {
        // Covers the early `return;` in reducer.apply when event_type != EVENT_TYPE
        use pos_core::{
            clock::{Seq, WallTime},
            crypto::Hash,
            event::{CanonicalBytes, SchemaVersion},
            ids::{EntityId, EventId},
        };
        let reducer = SyntheticReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let non_matching_event = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("other.event"),
            payload: CanonicalBytes::from_vec(vec![]),
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };
        reducer.apply(&mut state, &non_matching_event);
        // observations should still be 0 since the event was ignored
        assert_eq!(state.get("observations").and_then(serde_json::Value::as_u64), Some(0));
    }

    #[test]
    fn reducer_handles_nan_value_gracefully() {
        // Covers the `if let Some(n)` path in reducer.apply — when from_f64(NaN) returns None
        // We create an event with a valid payload but a NaN value to hit that branch.
        // NaN: serde_json::Number::from_f64(f64::NAN) returns None, so the state.set is skipped.
        let reducer = SyntheticReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        // We build an event with NaN encoded in the CBOR payload.
        // ciborium encodes NaN as an f64 normally.
        let payload = ObsPayload { value: f64::NAN, tick: 0 };
        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).unwrap();

        let event = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(EVENT_TYPE),
            payload: CanonicalBytes::from_vec(buf),
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };
        reducer.apply(&mut state, &event);
        // observations incremented even though NaN value was skipped
        assert_eq!(state.get("observations").and_then(serde_json::Value::as_u64), Some(1));
    }
}
