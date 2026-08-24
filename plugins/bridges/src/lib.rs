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
//! ```text
//! // In the experiment host:
//! let ingestor = BridgeIngestor::new(entity_id);
//! let draft = ingestor.ingest("owntracks", json_value, timestamp_micros);
//! store.append(timeline_id, &[draft])?;
//! ```
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use pos_core::{
    event::{CanonicalBytes, Event, EventDraft, Kind},
    ids::{EntityId, PluginId},
    plugin::{Capability, Plugin},
    state::{Reducer, State},
};
use pos_plugin_geo::{
    CompactLocationMetadata, CompactLocationObservation, GeoError, SourceTimeBucket,
    V1SpatialCloaker, Wgs84Point,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Entity kind string for bridge sources.
pub const ENTITY_KIND: &str = "bridge-source";

/// Event type for bridge observations.
pub const EVENT_TYPE: &str = "bridge.observation";

/// The stable schema version of a minimized `OwnTracks` location observation.
pub const OWNTRACKS_LOCATION_SCHEMA_VERSION: u8 = 1;

/// The consent/minimization policy version implemented by this decoder.
pub const OWNTRACKS_LOCATION_POLICY_VERSION: u8 = 1;

/// The V1 coarse spatial resolution in decimal degrees.
pub const OWNTRACKS_LOCATION_RESOLUTION_DEGREES: f64 = 0.1;

/// The V1 source-time bucket size in seconds.
pub const OWNTRACKS_SOURCE_TIME_BUCKET_SECONDS: i64 = 15 * 60;

/// The largest `OwnTracks` JSON body accepted by this pure decoder.
pub const MAX_OWNTRACKS_BODY_BYTES: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the bridges plugin.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    /// Store read failed.
    #[error("store error: {0}")]
    Store(#[from] pos_core::CoreError),
    /// Canonical observation encoding failed before a draft could be emitted.
    #[error("bridge observation encoding failed: {0}")]
    Encoding(String),
}

/// Errors returned while decoding a transient `OwnTracks` V1 location body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OwnTracksDecodeError {
    /// The body exceeds the bounded V1 decoder input.
    #[error("OwnTracks body exceeds the V1 size limit")]
    BodyTooLarge,
    /// The body is not valid JSON.
    #[error("OwnTracks body must be valid JSON")]
    MalformedJson,
    /// The JSON value is not one object.
    #[error("OwnTracks body must contain one JSON object")]
    ExpectedObject,
    /// The message is not an accepted V1 location message.
    #[error("OwnTracks V1 accepts only _type location")]
    UnsupportedMessageType,
    /// A location message has no numeric latitude.
    #[error("OwnTracks location requires a numeric lat")]
    MissingLatitude,
    /// A location message has no numeric longitude.
    #[error("OwnTracks location requires a numeric lon")]
    MissingLongitude,
    /// A location message has no signed integer timestamp.
    #[error("OwnTracks location requires a signed integer tst")]
    MissingTimestamp,
    /// The supplied WGS84 coordinate cannot be minimized safely.
    #[error("OwnTracks location has an invalid WGS84 coordinate: {0}")]
    InvalidCoordinate(GeoError),
}

/// Result of decoding one bounded `OwnTracks` request body.
#[derive(Debug, Clone, PartialEq)]
pub enum OwnTracksDecoded {
    /// A permitted zero-length `OwnTracks` no-op.
    Noop,
    /// A compact observation that contains no exact coordinate or raw telemetry.
    Location(CompactLocationObservation),
}

/// Decode and immediately minimize one `OwnTracks` V1 request body.
///
/// This pure boundary accepts only a zero-length no-op or one JSON object whose
/// `_type` is `location`. It retains no raw JSON, exact coordinate, timestamp,
/// or unallowlisted telemetry in its result.
///
/// # Errors
///
/// Returns [`OwnTracksDecodeError`] for an oversized, malformed, unsupported,
/// incomplete, or invalid location body.
///
/// # Panics
///
/// Never panics in practice: the fixed V1 degree-grid resolution is
/// WGS84-aligned by construction.
pub fn decode_owntracks_location(body: &[u8]) -> Result<OwnTracksDecoded, OwnTracksDecodeError> {
    if body.is_empty() {
        return Ok(OwnTracksDecoded::Noop);
    }
    if body.len() > MAX_OWNTRACKS_BODY_BYTES {
        return Err(OwnTracksDecodeError::BodyTooLarge);
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Err(OwnTracksDecodeError::MalformedJson);
    };
    let Some(object) = value.as_object() else {
        return Err(OwnTracksDecodeError::ExpectedObject);
    };
    if object.get("_type").and_then(serde_json::Value::as_str) != Some("location") {
        return Err(OwnTracksDecodeError::UnsupportedMessageType);
    }
    let Some(latitude) = object.get("lat").and_then(serde_json::Value::as_f64) else {
        return Err(OwnTracksDecodeError::MissingLatitude);
    };
    let Some(longitude) = object.get("lon").and_then(serde_json::Value::as_f64) else {
        return Err(OwnTracksDecodeError::MissingLongitude);
    };
    let Some(source_time) = object.get("tst").and_then(serde_json::Value::as_i64) else {
        return Err(OwnTracksDecodeError::MissingTimestamp);
    };
    let point = match Wgs84Point::new(latitude, longitude) {
        Ok(point) => point,
        Err(error) => return Err(OwnTracksDecodeError::InvalidCoordinate(error)),
    };
    let cloaker = V1SpatialCloaker::new();
    let cell = cloaker.cloak(point);
    let metadata = CompactLocationMetadata::v1(SourceTimeBucket::new(
        source_time.div_euclid(OWNTRACKS_SOURCE_TIME_BUCKET_SECONDS),
    ));
    let compact = CompactLocationObservation::new(cell, metadata);
    Ok(OwnTracksDecoded::Location(compact))
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
        Self {
            id: PluginId::new(),
        }
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
    pub const fn new(entity: EntityId) -> Self {
        Self { entity }
    }

    /// Ingest external data and produce an [`EventDraft`].
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::Encoding`] when the observation cannot be encoded.
    pub fn ingest(
        &self,
        source: &str,
        value: serde_json::Value,
        timestamp_micros: u64,
    ) -> Result<EventDraft, BridgeError> {
        let observation = BridgeObservation {
            source: source.to_owned(),
            value,
            timestamp_micros,
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&observation, &mut buf)
            .map_err(|error| BridgeError::Encoding(error.to_string()))?;

        Ok(EventDraft::new(
            self.entity,
            Kind::new(EVENT_TYPE),
            CanonicalBytes::from_vec(buf),
        ))
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test value")))
        }
    }

    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::SchemaVersion,
        ids::EventId,
    };

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn owntracks_empty_body_is_a_permitted_noop() {
        assert_eq!(decode_owntracks_location(b""), Ok(OwnTracksDecoded::Noop));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn owntracks_location_is_minimized_before_it_is_returned() {
        let decoded = decode_owntracks_location(
            br#"{"_type":"location","lat":37.7749,"lon":-122.4194,"tst":1800,"acc":3,"batt":91,"ssid":"private","tid":"x"}"#,
        );

        let Ok(OwnTracksDecoded::Location(location)) = decoded else {
            std::panic::resume_unwind(Box::new("valid OwnTracks location must minimize"));
        };
        assert!((location.cell_latitude() - 37.8).abs() < 1e-9);
        assert!((location.cell_longitude() - (-122.4)).abs() < 1e-9);
        assert_eq!(location.source_time_bucket().value(), 2);
        assert_eq!(
            location.schema_version().value(),
            OWNTRACKS_LOCATION_SCHEMA_VERSION
        );
        assert_eq!(
            location.policy_version().value(),
            OWNTRACKS_LOCATION_POLICY_VERSION
        );
        assert_eq!(location.quality_flags().bits(), 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn owntracks_platform_fixtures_are_minimized_and_discard_telemetry() {
        let android = decode_owntracks_location(include_bytes!(
            "../tests/fixtures/owntracks-android-location.json"
        ));
        let ios = decode_owntracks_location(include_bytes!(
            "../tests/fixtures/owntracks-ios-location.json"
        ));

        let Ok(OwnTracksDecoded::Location(android)) = android else {
            std::panic::resume_unwind(Box::new("Android fixture must minimize"));
        };
        let Ok(OwnTracksDecoded::Location(ios)) = ios else {
            std::panic::resume_unwind(Box::new("iOS fixture must minimize"));
        };
        assert!((android.cell_latitude() - 1.4).abs() < 1e-9);
        assert!((android.cell_longitude() - 103.8).abs() < 1e-9);
        assert_eq!(android.source_time_bucket().value(), 2);
        assert!((ios.cell_latitude() - 48.9).abs() < 1e-9);
        assert!((ios.cell_longitude() - 2.4).abs() < 1e-9);
        assert_eq!(ios.source_time_bucket().value(), 3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn owntracks_durable_payload_has_only_the_allowed_fields() {
        let decoded = decode_owntracks_location(include_bytes!(
            "../tests/fixtures/owntracks-android-location.json"
        ));
        let Ok(OwnTracksDecoded::Location(location)) = decoded else {
            std::panic::resume_unwind(Box::new("Android fixture must minimize"));
        };
        let decoded: ciborium::value::Value =
            ciborium::from_reader(location.canonical_bytes().test_ok().as_slice()).test_ok();
        let ciborium::value::Value::Map(entries) = decoded else {
            std::panic::resume_unwind(Box::new("compact location must encode as a CBOR map"));
        };
        let fields: Vec<&str> = entries
            .iter()
            .filter_map(|(key, _)| match key {
                ciborium::value::Value::Text(name) => Some(name.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            fields,
            vec![
                "cell_latitude",
                "quality_flags",
                "cell_longitude",
                "policy_version",
                "schema_version",
                "source_time_bucket",
            ]
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn owntracks_precise_points_in_one_cell_and_bucket_have_identical_bytes() {
        let first = decode_owntracks_location(
            br#"{"_type":"location","lat":37.76,"lon":-122.42,"tst":1800,"batt":1}"#,
        );
        let second = decode_owntracks_location(
            br#"{"_type":"location","lat":37.79,"lon":-122.44,"tst":2699,"batt":99,"wifi":"discarded"}"#,
        );

        let Ok(OwnTracksDecoded::Location(first)) = first else {
            std::panic::resume_unwind(Box::new("first location must minimize"));
        };
        let Ok(OwnTracksDecoded::Location(second)) = second else {
            std::panic::resume_unwind(Box::new("second location must minimize"));
        };
        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn owntracks_decoder_rejects_invalid_envelopes() {
        let oversized = vec![b'x'; MAX_OWNTRACKS_BODY_BYTES + 1];
        assert_eq!(
            decode_owntracks_location(&oversized),
            Err(OwnTracksDecodeError::BodyTooLarge)
        );
        assert_eq!(
            decode_owntracks_location(b"{"),
            Err(OwnTracksDecodeError::MalformedJson)
        );
        assert_eq!(
            decode_owntracks_location(b"[]"),
            Err(OwnTracksDecodeError::ExpectedObject)
        );
        assert_eq!(
            decode_owntracks_location(br#"{"_type":"encrypted"}"#),
            Err(OwnTracksDecodeError::UnsupportedMessageType)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn owntracks_decoder_requires_each_location_field() {
        assert_eq!(
            decode_owntracks_location(br#"{"_type":"location","lon":1,"tst":1}"#),
            Err(OwnTracksDecodeError::MissingLatitude)
        );
        assert_eq!(
            decode_owntracks_location(br#"{"_type":"location","lat":1,"tst":1}"#),
            Err(OwnTracksDecodeError::MissingLongitude)
        );
        assert_eq!(
            decode_owntracks_location(br#"{"_type":"location","lat":1,"lon":1,"tst":1.5}"#),
            Err(OwnTracksDecodeError::MissingTimestamp)
        );
        assert_eq!(
            decode_owntracks_location(
                br#"{"_type":"location","lat":1,"lon":1,"tst":18446744073709551615}"#
            ),
            Err(OwnTracksDecodeError::MissingTimestamp)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn owntracks_signed_timestamps_use_euclidean_15_minute_buckets() {
        for (timestamp, bucket) in [(-1, -1), (-900, -1), (-901, -2), (0, 0), (899, 0)] {
            let body = format!(r#"{{"_type":"location","lat":0,"lon":0,"tst":{timestamp}}}"#);
            let decoded = decode_owntracks_location(body.as_bytes());
            let Ok(OwnTracksDecoded::Location(location)) = decoded else {
                std::panic::resume_unwind(Box::new("signed integer tst must minimize"));
            };
            assert_eq!(location.source_time_bucket().value(), bucket);
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn owntracks_decoder_rejects_coordinates_outside_wgs84() {
        assert_eq!(
            decode_owntracks_location(br#"{"_type":"location","lat":91,"lon":0,"tst":1}"#),
            Err(OwnTracksDecodeError::InvalidCoordinate(
                GeoError::LatitudeOutOfRange
            ))
        );
        assert_eq!(
            decode_owntracks_location(br#"{"_type":"location","lat":0,"lon":181,"tst":1}"#),
            Err(OwnTracksDecodeError::InvalidCoordinate(
                GeoError::LongitudeOutOfRange
            ))
        );
    }

    // ── BridgePlugin tests ────────────────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_new_and_default_have_same_name() {
        let p1 = BridgePlugin::new();
        let p2 = BridgePlugin::default();
        assert_eq!(p1.name(), p2.name());
        assert_eq!(p1.name(), "bridges");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_id_is_unique() {
        let p1 = BridgePlugin::new();
        let p2 = BridgePlugin::new();
        assert_ne!(p1.id(), p2.id());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
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
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ingestor_produces_event_draft() {
        let entity = EntityId::new();
        let ingestor = BridgeIngestor::new(entity);

        let value = serde_json::json!({"lat": 37.7749, "lon": -122.4194});
        let draft = ingestor
            .ingest("owntracks", value.clone(), 1_000_000)
            .test_ok();

        assert_eq!(draft.entity, entity);
        assert_eq!(draft.event_type.as_str(), EVENT_TYPE);

        // Decode the payload to verify it roundtrips.
        let observation: BridgeObservation =
            ciborium::from_reader(draft.payload.as_slice()).test_ok();
        assert_eq!(observation.source, "owntracks");
        assert_eq!(observation.value, value);
        assert_eq!(observation.timestamp_micros, 1_000_000);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
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
            let draft = ingestor.ingest("test-source", value.clone(), 0).test_ok();
            let observation: BridgeObservation =
                ciborium::from_reader(draft.payload.as_slice()).test_ok();
            assert_eq!(observation.value, value);
        }
    }

    // ── BridgeReducer tests ───────────────────────────────────────────────

    fn make_bridge_event(
        entity: EntityId,
        source: &str,
        value: serde_json::Value,
        timestamp_micros: u64,
    ) -> Event {
        let observation = BridgeObservation {
            source: source.to_owned(),
            value,
            timestamp_micros,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&observation, &mut buf).test_ok();

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
            signature_identity: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_initial_state() {
        let reducer = BridgeReducer;
        let state = reducer.initial();
        assert_eq!(
            state
                .get("observations")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
        assert_eq!(state.get("last_source"), Some(&serde_json::Value::Null));
        assert_eq!(state.get("last_value"), Some(&serde_json::Value::Null));
        assert_eq!(
            state
                .get("last_timestamp_micros")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_tracks_observation_count() {
        let reducer = BridgeReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        assert_eq!(
            state
                .get("observations")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );

        for i in 0_u64..5 {
            let event = make_bridge_event(entity, "test", serde_json::json!(i), i);
            reducer.apply(&mut state, &event);
        }

        assert_eq!(
            state
                .get("observations")
                .and_then(serde_json::Value::as_u64),
            Some(5)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_updates_last_value() {
        let reducer = BridgeReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let value1 = serde_json::json!({"reading": 42});
        let event1 = make_bridge_event(entity, "sensor-1", value1.clone(), 1_000);
        reducer.apply(&mut state, &event1);

        assert_eq!(
            state.get("last_source").and_then(serde_json::Value::as_str),
            Some("sensor-1")
        );
        assert_eq!(state.get("last_value"), Some(&value1));
        assert_eq!(
            state
                .get("last_timestamp_micros")
                .and_then(serde_json::Value::as_u64),
            Some(1_000)
        );

        let value2 = serde_json::json!({"reading": 99});
        let event2 = make_bridge_event(entity, "sensor-2", value2.clone(), 2_000);
        reducer.apply(&mut state, &event2);

        assert_eq!(
            state.get("last_source").and_then(serde_json::Value::as_str),
            Some("sensor-2")
        );
        assert_eq!(state.get("last_value"), Some(&value2));
        assert_eq!(
            state
                .get("last_timestamp_micros")
                .and_then(serde_json::Value::as_u64),
            Some(2_000)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
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
            signature_identity: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };

        reducer.apply(&mut state, &other_event);

        assert_eq!(
            state
                .get("observations")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
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
            signature_identity: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };

        reducer.apply(&mut state, &bad_event);

        // Observation count incremented even though payload decode failed.
        assert_eq!(
            state
                .get("observations")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        // last_* fields remain at initial values.
        assert_eq!(state.get("last_source"), Some(&serde_json::Value::Null));
    }

    // ── Roundtrip tests ───────────────────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn roundtrip_ingest_to_reducer() {
        let entity = EntityId::new();
        let ingestor = BridgeIngestor::new(entity);
        let reducer = BridgeReducer;
        let mut state = reducer.initial();

        let value = serde_json::json!({"temperature": 23.5});
        let draft = ingestor
            .ingest("thermo-1", value.clone(), 5_000_000)
            .test_ok();

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
            signature_identity: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };

        reducer.apply(&mut state, &event);

        assert_eq!(
            state
                .get("observations")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert_eq!(
            state.get("last_source").and_then(serde_json::Value::as_str),
            Some("thermo-1")
        );
        assert_eq!(state.get("last_value"), Some(&value));
        assert_eq!(
            state
                .get("last_timestamp_micros")
                .and_then(serde_json::Value::as_u64),
            Some(5_000_000)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bridge_observation_cbor_roundtrip() {
        let obs = BridgeObservation {
            source: "test-source".to_owned(),
            value: serde_json::json!({"key": "value"}),
            timestamp_micros: 123_456_789,
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&obs, &mut buf).test_ok();
        let decoded: BridgeObservation = ciborium::from_reader(buf.as_slice()).test_ok();

        assert_eq!(decoded.source, obs.source);
        assert_eq!(decoded.value, obs.value);
        assert_eq!(decoded.timestamp_micros, obs.timestamp_micros);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bridge_error_from_core_error() {
        let core_err = pos_core::CoreError::Storage("test error".to_owned());
        let bridge_err: BridgeError = core_err.into();
        let s = bridge_err.to_string();
        assert!(s.contains("store error"));
    }
}
