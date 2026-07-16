#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-plugin-bridges` — digital-twin bridge plugin.
//!
//! Bridges real-world data (e.g., `OwnTracks` HTTP observations) into the
//! observation event stream. Owns event type `"bridge.observation"` and
//! entity kind `"bridge-source"`.
//!
//! # Architecture
//!
//! - [`BridgePlugin`]: Plugin descriptor, has reducer, no driver.
//! - [`BridgeIngestor`]: Standalone struct that produces [`EventDraft`]s
//!   from external data sources (no I/O, just event production).
//! - [`BridgeReducer`]: Tracks observation count and last value per entity.
//!
//! # Usage
//!
//! ```ignore
//! // In the experiment host:
//! let ingestor = BridgeIngestor::new(entity_id);
//! let draft = ingestor.ingest("owntracks", json_value, timestamp_micros);
//! store.append(timeline_id, &[draft])?;
//! ```

use pos_core::{
    event::{CanonicalBytes, Event, EventDraft, Kind},
    ids::{EntityId, PluginId},
    plugin::{Capability, Plugin},
    state::{Reducer, State},
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Entity kind string for bridge sources.
pub const ENTITY_KIND: &str = "bridge-source";

/// Event type for bridge observations.
pub const EVENT_TYPE: &str = "bridge.observation";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the bridges plugin.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    /// Store read failed.
    #[error("store error: {0}")]
    Store(#[from] pos_core::CoreError),
}

// ---------------------------------------------------------------------------
// Payload type (CBOR-serialized)
// ---------------------------------------------------------------------------

/// Payload for a bridge observation event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeObservation {
    /// Source identifier (e.g., "owntracks", "sensor-42").
    pub source: String,
    /// Opaque JSON value from the external source.
    pub value: serde_json::Value,
    /// Timestamp in microseconds since Unix epoch.
    pub timestamp_micros: u64,
}

// ---------------------------------------------------------------------------
// BridgePlugin descriptor
// ---------------------------------------------------------------------------

/// Digital-twin bridge plugin.
pub struct BridgePlugin {
    id: PluginId,
}

impl Default for BridgePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl BridgePlugin {
    /// Create a new `BridgePlugin`.
    #[must_use]
    pub fn new() -> Self {
        Self { id: PluginId::new() }
    }
}

impl Plugin for BridgePlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "bridges"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(EVENT_TYPE)],
            owned_entity_kinds: vec![ENTITY_KIND.to_owned()],
            has_driver: false,
            has_reducer: true,
        }
    }
}

// ---------------------------------------------------------------------------
// BridgeIngestor
// ---------------------------------------------------------------------------

/// Produces [`EventDraft`]s from external data sources.
///
/// This is NOT a Driver — it has no store/timeline dependencies.
/// Callers (e.g., experiment hosts) provide the data and append the drafts.
pub struct BridgeIngestor {
    entity: EntityId,
}

impl BridgeIngestor {
    /// Create a new ingestor for the given entity.
    #[must_use]
    pub fn new(entity: EntityId) -> Self {
        Self { entity }
    }

    /// Ingest external data and produce an [`EventDraft`].
    ///
    /// # Panics
    /// Panics if CBOR serialization fails. In practice this never happens when
    /// writing to a `Vec<u8>` with valid `BridgeObservation` data.
    #[must_use]
    pub fn ingest(
        &self,
        source: &str,
        value: serde_json::Value,
        timestamp_micros: u64,
    ) -> EventDraft {
        let observation = BridgeObservation {
            source: source.to_owned(),
            value,
            timestamp_micros,
        };

        let mut buf = Vec::new();
        // Writing to Vec<u8> is infallible with ciborium.
        ciborium::into_writer(&observation, &mut buf)
            .expect("ciborium write to Vec<u8> is infallible");

        EventDraft::new(
            self.entity,
            Kind::new(EVENT_TYPE),
            CanonicalBytes::from_vec(buf),
        )
    }
}

// ---------------------------------------------------------------------------
// BridgeReducer
// ---------------------------------------------------------------------------

/// Tracks observation count and last value per entity.
pub struct BridgeReducer;

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
        state.set("observations", serde_json::Value::Number((observations + 1).into()));

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::SchemaVersion,
        ids::EventId,
    };

    // ── BridgePlugin tests ────────────────────────────────────────────────

    #[test]
    fn plugin_new_and_default_have_same_name() {
        let p1 = BridgePlugin::new();
        let p2 = BridgePlugin::default();
        assert_eq!(p1.name(), p2.name());
        assert_eq!(p1.name(), "bridges");
    }

    #[test]
    fn plugin_id_is_unique() {
        let p1 = BridgePlugin::new();
        let p2 = BridgePlugin::new();
        assert_ne!(p1.id(), p2.id());
    }

    #[test]
    fn plugin_capability() {
        let plugin = BridgePlugin::new();
        let cap = plugin.capability();
        assert_eq!(cap.owned_event_types.len(), 1);
        assert_eq!(cap.owned_event_types[0].as_str(), EVENT_TYPE);
        assert_eq!(cap.owned_entity_kinds, vec![ENTITY_KIND.to_owned()]);
        assert!(!cap.has_driver);
        assert!(cap.has_reducer);
    }

    // ── BridgeIngestor tests ──────────────────────────────────────────────

    #[test]
    fn ingestor_produces_event_draft() {
        let entity = EntityId::new();
        let ingestor = BridgeIngestor::new(entity);

        let value = serde_json::json!({"lat": 37.7749, "lon": -122.4194});
        let draft = ingestor.ingest("owntracks", value.clone(), 1_000_000);

        assert_eq!(draft.entity, entity);
        assert_eq!(draft.event_type.as_str(), EVENT_TYPE);

        // Decode the payload to verify it roundtrips.
        let observation: BridgeObservation =
            ciborium::from_reader(draft.payload.as_slice()).unwrap();
        assert_eq!(observation.source, "owntracks");
        assert_eq!(observation.value, value);
        assert_eq!(observation.timestamp_micros, 1_000_000);
    }

    #[test]
    fn ingestor_handles_various_json_values() {
        let entity = EntityId::new();
        let ingestor = BridgeIngestor::new(entity);

        let test_values = vec![
            serde_json::json!(null),
            serde_json::json!(42),
            serde_json::json!(23.7),
            serde_json::json!("hello"),
            serde_json::json!(true),
            serde_json::json!({"nested": {"key": "value"}}),
            serde_json::json!([1, 2, 3]),
        ];

        for value in test_values {
            let draft = ingestor.ingest("test-source", value.clone(), 0);
            let observation: BridgeObservation =
                ciborium::from_reader(draft.payload.as_slice()).unwrap();
            assert_eq!(observation.value, value);
        }
    }

    // ── BridgeReducer tests ───────────────────────────────────────────────

    fn make_bridge_event(entity: EntityId, source: &str, value: serde_json::Value, timestamp_micros: u64) -> Event {
        let observation = BridgeObservation {
            source: source.to_owned(),
            value,
            timestamp_micros,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&observation, &mut buf).unwrap();

        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(EVENT_TYPE),
            payload: CanonicalBytes::from_vec(buf),
            wall_time: WallTime::from_micros(timestamp_micros),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
    }

    #[test]
    fn reducer_initial_state() {
        let reducer = BridgeReducer;
        let state = reducer.initial();
        assert_eq!(
            state.get("observations").and_then(serde_json::Value::as_u64),
            Some(0)
        );
        assert_eq!(
            state.get("last_source"),
            Some(&serde_json::Value::Null)
        );
        assert_eq!(
            state.get("last_value"),
            Some(&serde_json::Value::Null)
        );
        assert_eq!(
            state.get("last_timestamp_micros").and_then(serde_json::Value::as_u64),
            Some(0)
        );
    }

    #[test]
    fn reducer_tracks_observation_count() {
        let reducer = BridgeReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        assert_eq!(
            state.get("observations").and_then(serde_json::Value::as_u64),
            Some(0)
        );

        for i in 0_u64..5 {
            let event = make_bridge_event(
                entity,
                "test",
                serde_json::json!(i),
                i,
            );
            reducer.apply(&mut state, &event);
        }

        assert_eq!(
            state.get("observations").and_then(serde_json::Value::as_u64),
            Some(5)
        );
    }

    #[test]
    fn reducer_updates_last_value() {
        let reducer = BridgeReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let value1 = serde_json::json!({"reading": 42});
        let event1 = make_bridge_event(entity, "sensor-1", value1.clone(), 1_000);
        reducer.apply(&mut state, &event1);

        assert_eq!(state.get("last_source").and_then(serde_json::Value::as_str), Some("sensor-1"));
        assert_eq!(state.get("last_value"), Some(&value1));
        assert_eq!(
            state.get("last_timestamp_micros").and_then(serde_json::Value::as_u64),
            Some(1_000)
        );

        let value2 = serde_json::json!({"reading": 99});
        let event2 = make_bridge_event(entity, "sensor-2", value2.clone(), 2_000);
        reducer.apply(&mut state, &event2);

        assert_eq!(state.get("last_source").and_then(serde_json::Value::as_str), Some("sensor-2"));
        assert_eq!(state.get("last_value"), Some(&value2));
        assert_eq!(
            state.get("last_timestamp_micros").and_then(serde_json::Value::as_u64),
            Some(2_000)
        );
    }

    #[test]
    fn reducer_ignores_non_bridge_events() {
        let reducer = BridgeReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let other_event = Event {
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

        reducer.apply(&mut state, &other_event);

        assert_eq!(
            state.get("observations").and_then(serde_json::Value::as_u64),
            Some(0)
        );
    }

    #[test]
    fn reducer_handles_invalid_cbor_gracefully() {
        let reducer = BridgeReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let bad_event = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(EVENT_TYPE),
            payload: CanonicalBytes::from_vec(vec![0xFF, 0xFE, 0xFD]),
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };

        reducer.apply(&mut state, &bad_event);

        // Observation count incremented even though payload decode failed.
        assert_eq!(
            state.get("observations").and_then(serde_json::Value::as_u64),
            Some(1)
        );
        // last_* fields remain at initial values.
        assert_eq!(
            state.get("last_source"),
            Some(&serde_json::Value::Null)
        );
    }

    // ── Roundtrip tests ───────────────────────────────────────────────────

    #[test]
    fn roundtrip_ingest_to_reducer() {
        let entity = EntityId::new();
        let ingestor = BridgeIngestor::new(entity);
        let reducer = BridgeReducer;
        let mut state = reducer.initial();

        let value = serde_json::json!({"temperature": 23.5});
        let draft = ingestor.ingest("thermo-1", value.clone(), 5_000_000);

        // Convert draft to a full Event (normally the store does this).
        let event = Event {
            id: EventId::new(),
            entity: draft.entity,
            event_type: draft.event_type,
            payload: draft.payload,
            wall_time: WallTime::from_micros(5_000_000),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };

        reducer.apply(&mut state, &event);

        assert_eq!(
            state.get("observations").and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert_eq!(state.get("last_source").and_then(serde_json::Value::as_str), Some("thermo-1"));
        assert_eq!(state.get("last_value"), Some(&value));
        assert_eq!(
            state.get("last_timestamp_micros").and_then(serde_json::Value::as_u64),
            Some(5_000_000)
        );
    }

    #[test]
    fn bridge_observation_cbor_roundtrip() {
        let obs = BridgeObservation {
            source: "test-source".to_owned(),
            value: serde_json::json!({"key": "value"}),
            timestamp_micros: 123_456_789,
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&obs, &mut buf).unwrap();
        let decoded: BridgeObservation = ciborium::from_reader(buf.as_slice()).unwrap();

        assert_eq!(decoded.source, obs.source);
        assert_eq!(decoded.value, obs.value);
        assert_eq!(decoded.timestamp_micros, obs.timestamp_micros);
    }

    #[test]
    fn bridge_error_from_core_error() {
        let core_err = pos_core::CoreError::Storage("test error".to_owned());
        let bridge_err: BridgeError = core_err.into();
        let s = bridge_err.to_string();
        assert!(s.contains("store error"));
    }
}
