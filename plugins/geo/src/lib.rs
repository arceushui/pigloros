#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-plugin-geo` — degree-grid spatial cloaking plugin.
//!
//! Owns event type `"geo.location"` and entity kind `"geo-entity"`.
//! Provides spatial cloaking: exact lat/lng → discretized grid cell.
//!
//! Wave 5 uses a pure-Rust degree-grid snap ([`SpatialCloaker`]); H3/S2 are deferred.
//! Privacy property: exact coordinates are snapped to a configurable grid resolution
//! (e.g., 0.1 degree cells), preventing exact location tracking.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use pos_core::{
    event::{CanonicalBytes, Event, Kind},
    ids::{EntityId, PluginId},
    plugin::{Capability, Plugin},
    state::{Reducer, State},
};
use serde::{Deserialize, Serialize};

/// Errors returned when a spatial-cloaking input is not a valid WGS84 value.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
pub enum GeoError {
    /// The degree-grid cell size is zero, negative, or non-finite.
    #[error("spatial-cloaking resolution must be finite and greater than zero")]
    InvalidResolution,
    /// A coordinate is not a finite floating-point number.
    #[error("WGS84 coordinate must be finite")]
    NonFiniteCoordinate,
    /// A latitude is outside the WGS84 range `[-90, 90]`.
    #[error("WGS84 latitude must be in [-90, 90]")]
    LatitudeOutOfRange,
    /// A longitude is outside the WGS84 range `[-180, 180]`.
    #[error("WGS84 longitude must be in [-180, 180]")]
    LongitudeOutOfRange,
}

/// A validated WGS84 latitude/longitude pair in degrees.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Wgs84Point {
    latitude: f64,
    longitude: f64,
}

impl Wgs84Point {
    /// Construct a WGS84 point after validating finite latitude and longitude bounds.
    ///
    /// # Errors
    ///
    /// Returns [`GeoError`] when either coordinate is non-finite or outside its
    /// WGS84 latitude/longitude range.
    pub fn new(latitude: f64, longitude: f64) -> Result<Self, GeoError> {
        if !latitude.is_finite() || !longitude.is_finite() {
            return Err(GeoError::NonFiniteCoordinate);
        }
        if !(-90.0..=90.0).contains(&latitude) {
            return Err(GeoError::LatitudeOutOfRange);
        }
        if !(-180.0..=180.0).contains(&longitude) {
            return Err(GeoError::LongitudeOutOfRange);
        }
        Ok(Self {
            latitude,
            longitude,
        })
    }

    /// Return the latitude in decimal degrees.
    #[must_use]
    pub fn latitude(self) -> f64 {
        self.latitude
    }

    /// Return the longitude in decimal degrees.
    #[must_use]
    pub fn longitude(self) -> f64 {
        self.longitude
    }
}

/// The entity kind string for geo entities.
pub const ENTITY_KIND: &str = "geo-entity";

/// The event type for location updates.
pub const EVENT_TYPE_LOCATION: &str = "geo.location";

// ---------------------------------------------------------------------------
// Payload types
// ---------------------------------------------------------------------------

/// CBOR payload for geo.location events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoLocationPayload {
    /// Cloaked latitude (snapped to grid).
    pub cell_lat: f64,
    /// Cloaked longitude (snapped to grid).
    pub cell_lng: f64,
    /// Grid resolution in degrees.
    pub resolution: f64,
}

// ---------------------------------------------------------------------------
// Spatial cloaking
// ---------------------------------------------------------------------------

/// Spatial cloaker that discretizes lat/lng to a grid.
#[derive(Debug, Clone, Copy)]
pub struct SpatialCloaker {
    /// Grid resolution in degrees (e.g., 0.1).
    resolution: f64,
}

impl SpatialCloaker {
    /// Create a new spatial cloaker with the given resolution.
    ///
    /// # Errors
    ///
    /// Returns [`GeoError::InvalidResolution`] when the degree-grid resolution
    /// is zero, negative, or non-finite.
    pub fn new(resolution: f64) -> Result<Self, GeoError> {
        if !resolution.is_finite() || resolution <= 0.0 {
            return Err(GeoError::InvalidResolution);
        }
        Ok(Self { resolution })
    }

    /// Return the validated degree-grid resolution.
    #[must_use]
    pub fn resolution(self) -> f64 {
        self.resolution
    }

    /// Cloak exact coordinates to the nearest grid point.
    ///
    /// Snaps to `(lat / resolution).round() * resolution`.
    /// This ensures that all points within `resolution/2` map to the same cell.
    #[must_use]
    pub fn cloak(&self, point: Wgs84Point) -> (f64, f64) {
        let cell_lat = (point.latitude / self.resolution).round() * self.resolution;
        let cell_lng = (point.longitude / self.resolution).round() * self.resolution;
        (cell_lat, cell_lng)
    }

    /// Convert exact coordinates to a geo.location `EventDraft`.
    ///
    /// # Panics
    ///
    /// Never panics in practice — CBOR serialization to `Vec<u8>` is infallible.
    #[must_use]
    pub fn to_draft(&self, entity: EntityId, point: Wgs84Point) -> pos_core::EventDraft {
        let (cell_lat, cell_lng) = self.cloak(point);
        let payload = GeoLocationPayload {
            cell_lat,
            cell_lng,
            resolution: self.resolution,
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).expect("ciborium write to Vec<u8> is infallible");

        pos_core::EventDraft::new(
            entity,
            Kind::new(EVENT_TYPE_LOCATION),
            CanonicalBytes::from_vec(buf),
        )
    }
}

// ---------------------------------------------------------------------------
// Plugin descriptor
// ---------------------------------------------------------------------------

/// Geo plugin for spatial cloaking.
pub struct GeoPlugin {
    id: PluginId,
}

impl Default for GeoPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoPlugin {
    /// Create a new geo plugin.
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: PluginId::new(),
        }
    }
}

impl Plugin for GeoPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "geo"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(EVENT_TYPE_LOCATION)],
            owned_entity_kinds: vec![ENTITY_KIND.to_owned()],
            has_driver: false,
            has_reducer: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------

/// Tracks per-entity location count and last cell coordinates.
pub struct GeoReducer;

impl Reducer for GeoReducer {
    fn initial(&self) -> State {
        let mut s = State::new();
        s.set("location_count", serde_json::Value::Number(0.into()));
        s.set(
            "last_cell_lat",
            serde_json::Value::Number(serde_json::Number::from_f64(0.0).unwrap_or(0.into())),
        );
        s.set(
            "last_cell_lng",
            serde_json::Value::Number(serde_json::Number::from_f64(0.0).unwrap_or(0.into())),
        );
        s
    }

    fn apply(&self, state: &mut State, event: &Event) {
        if event.event_type.as_str() == EVENT_TYPE_LOCATION {
            let location_count = state
                .get("location_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            state.set(
                "location_count",
                serde_json::Value::Number((location_count + 1).into()),
            );

            // Decode payload to extract last cell coordinates.
            if let Ok(payload) =
                ciborium::from_reader::<GeoLocationPayload, _>(event.payload.as_slice())
            {
                let lat_num = serde_json::Number::from_f64(payload.cell_lat).unwrap_or(0.into());
                let lng_num = serde_json::Number::from_f64(payload.cell_lng).unwrap_or(0.into());
                state.set("last_cell_lat", serde_json::Value::Number(lat_num));
                state.set("last_cell_lng", serde_json::Value::Number(lng_num));
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
        event::SchemaVersion,
        ids::{EntityId, EventId},
    };

    fn point(lat: f64, lng: f64) -> Wgs84Point {
        Wgs84Point::new(lat, lng).unwrap()
    }

    fn make_geo_event(entity: EntityId, cell_lat: f64, cell_lng: f64, resolution: f64) -> Event {
        let payload = GeoLocationPayload {
            cell_lat,
            cell_lng,
            resolution,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).unwrap();

        Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(EVENT_TYPE_LOCATION),
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

    fn make_other_event(entity: EntityId) -> Event {
        Event {
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
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_new_and_default() {
        let p1 = GeoPlugin::new();
        let p2 = GeoPlugin::default();
        assert_eq!(p1.name(), "geo");
        assert_eq!(p2.name(), "geo");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_name_is_geo() {
        let plugin = GeoPlugin::new();
        assert_eq!(plugin.name(), "geo");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_id_is_returned() {
        let plugin = GeoPlugin::new();
        let _id = plugin.id();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_capability_is_correct() {
        let plugin = GeoPlugin::new();
        let cap = plugin.capability();

        assert_eq!(cap.owned_event_types.len(), 1);
        assert_eq!(cap.owned_event_types[0].as_str(), EVENT_TYPE_LOCATION);
        assert_eq!(cap.owned_entity_kinds.len(), 1);
        assert_eq!(cap.owned_entity_kinds[0], ENTITY_KIND);
        assert!(!cap.has_driver);
        assert!(cap.has_reducer);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn spatial_cloaker_snaps_to_grid() {
        const TOLERANCE: f64 = 1e-10;
        let cloaker = SpatialCloaker::new(0.1).unwrap();

        // Test exact grid point
        let (lat, lng) = cloaker.cloak(point(37.0, -122.0));
        assert!((lat - 37.0).abs() < TOLERANCE);
        assert!((lng - (-122.0)).abs() < TOLERANCE);

        // Test rounding down
        let (lat, lng) = cloaker.cloak(point(37.03, -122.02));
        assert!((lat - 37.0).abs() < TOLERANCE);
        assert!((lng - (-122.0)).abs() < TOLERANCE);

        // Test rounding up
        let (lat, lng) = cloaker.cloak(point(37.07, -122.08));
        assert!((lat - 37.1).abs() < TOLERANCE);
        assert!((lng - (-122.1)).abs() < TOLERANCE);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn spatial_cloaker_resolution_half_degree() {
        let cloaker = SpatialCloaker::new(0.5).unwrap();

        assert!((cloaker.resolution() - 0.5).abs() < f64::EPSILON);

        let (lat, lng) = cloaker.cloak(point(37.2, -122.3));
        assert!((lat - 37.0).abs() < f64::EPSILON);
        assert!((lng - (-122.5)).abs() < f64::EPSILON);

        let (lat, lng) = cloaker.cloak(point(37.3, -122.6));
        assert!((lat - 37.5).abs() < f64::EPSILON);
        assert!((lng - (-122.5)).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn spatial_cloaker_rejects_invalid_resolutions() {
        for resolution in [0.0, -0.1, f64::INFINITY, f64::NAN] {
            assert_eq!(
                SpatialCloaker::new(resolution).unwrap_err(),
                GeoError::InvalidResolution
            );
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn wgs84_point_accepts_boundary_coordinates() {
        let point = Wgs84Point::new(-90.0, 180.0).unwrap();
        assert!((point.latitude() - (-90.0)).abs() < f64::EPSILON);
        assert!((point.longitude() - 180.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn wgs84_point_rejects_invalid_coordinates() {
        assert_eq!(
            Wgs84Point::new(f64::NAN, 0.0),
            Err(GeoError::NonFiniteCoordinate)
        );
        assert_eq!(
            Wgs84Point::new(90.1, 0.0),
            Err(GeoError::LatitudeOutOfRange)
        );
        assert_eq!(
            Wgs84Point::new(0.0, -180.1),
            Err(GeoError::LongitudeOutOfRange)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn spatial_cloaker_privacy_property() {
        let cloaker = SpatialCloaker::new(0.1).unwrap();

        // Two points within resolution/2 should map to same cell
        let (lat1, lng1) = cloaker.cloak(point(37.0, -122.0));
        let (lat2, lng2) = cloaker.cloak(point(37.04, -122.03));

        assert!((lat1 - lat2).abs() < f64::EPSILON);
        assert!((lng1 - lng2).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn spatial_cloaker_to_draft_produces_correct_event_type() {
        let cloaker = SpatialCloaker::new(0.1).unwrap();
        let entity = EntityId::new();
        let draft = cloaker.to_draft(entity, point(37.0, -122.0));

        assert_eq!(draft.event_type.as_str(), EVENT_TYPE_LOCATION);
        assert_eq!(draft.entity, entity);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn spatial_cloaker_to_draft_has_decodable_payload() {
        let cloaker = SpatialCloaker::new(0.1).unwrap();
        let entity = EntityId::new();
        let draft = cloaker.to_draft(entity, point(37.07, -122.03));

        let payload: GeoLocationPayload = ciborium::from_reader(draft.payload.as_slice()).unwrap();

        assert!((payload.cell_lat - 37.1).abs() < f64::EPSILON);
        assert!((payload.cell_lng - (-122.0)).abs() < f64::EPSILON);
        assert!((payload.resolution - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_tracks_location_count() {
        let reducer = GeoReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        assert_eq!(
            state
                .get("location_count")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );

        for _ in 0..3 {
            let event = make_geo_event(entity, 37.0, -122.0, 0.1);
            reducer.apply(&mut state, &event);
        }

        assert_eq!(
            state
                .get("location_count")
                .and_then(serde_json::Value::as_u64),
            Some(3)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_tracks_last_cell_coordinates() {
        let reducer = GeoReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let event1 = make_geo_event(entity, 37.1, -122.1, 0.1);
        reducer.apply(&mut state, &event1);

        assert!(
            (state
                .get("last_cell_lat")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0)
                - 37.1)
                .abs()
                < f64::EPSILON
        );
        assert!(
            (state
                .get("last_cell_lng")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0)
                - (-122.1))
                .abs()
                < f64::EPSILON
        );

        let event2 = make_geo_event(entity, 38.0, -123.0, 0.1);
        reducer.apply(&mut state, &event2);

        assert!(
            (state
                .get("last_cell_lat")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0)
                - 38.0)
                .abs()
                < f64::EPSILON
        );
        assert!(
            (state
                .get("last_cell_lng")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0)
                - (-123.0))
                .abs()
                < f64::EPSILON
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_ignores_other_event_types() {
        let reducer = GeoReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let other = make_other_event(entity);
        reducer.apply(&mut state, &other);

        assert_eq!(
            state
                .get("location_count")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
        assert!(
            (state
                .get("last_cell_lat")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0)
                - 0.0)
                .abs()
                < f64::EPSILON
        );
        assert!(
            (state
                .get("last_cell_lng")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0)
                - 0.0)
                .abs()
                < f64::EPSILON
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_initial_state_has_correct_fields() {
        let reducer = GeoReducer;
        let state = reducer.initial();
        assert!(state.get("location_count").is_some());
        assert!(state.get("last_cell_lat").is_some());
        assert!(state.get("last_cell_lng").is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_handles_malformed_payload() {
        let reducer = GeoReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let event = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(EVENT_TYPE_LOCATION),
            payload: CanonicalBytes::from_vec(vec![0xFF, 0xFF]),
            wall_time: WallTime::from_micros(0),
            seq: Seq::ZERO,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };

        reducer.apply(&mut state, &event);

        assert_eq!(
            state
                .get("location_count")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert!(
            (state
                .get("last_cell_lat")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0)
                - 0.0)
                .abs()
                < f64::EPSILON
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn geo_location_payload_serializes_correctly() {
        let payload = GeoLocationPayload {
            cell_lat: 37.0,
            cell_lng: -122.0,
            resolution: 0.1,
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).unwrap();
        let back: GeoLocationPayload = ciborium::from_reader(buf.as_slice()).unwrap();

        assert_eq!(payload, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn spatial_cloaker_negative_coordinates() {
        let cloaker = SpatialCloaker::new(0.1).unwrap();

        let (lat, lng) = cloaker.cloak(point(-37.07, 122.03));
        assert!((lat - (-37.1)).abs() < f64::EPSILON);
        assert!((lng - 122.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn spatial_cloaker_zero_coordinates() {
        let cloaker = SpatialCloaker::new(0.1).unwrap();

        let (lat, lng) = cloaker.cloak(point(0.0, 0.0));
        assert!((lat - 0.0).abs() < f64::EPSILON);
        assert!((lng - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn spatial_cloaker_clone() {
        let cloaker1 = SpatialCloaker::new(0.1).unwrap();
        let cloaker2 = cloaker1;

        let (lat1, lng1) = cloaker1.cloak(point(37.0, -122.0));
        let (lat2, lng2) = cloaker2.cloak(point(37.0, -122.0));

        assert!((lat1 - lat2).abs() < f64::EPSILON);
        assert!((lng1 - lng2).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn geo_location_payload_partial_eq() {
        let p1 = GeoLocationPayload {
            cell_lat: 37.0,
            cell_lng: -122.0,
            resolution: 0.1,
        };
        let p2 = GeoLocationPayload {
            cell_lat: 37.0,
            cell_lng: -122.0,
            resolution: 0.1,
        };
        let p3 = GeoLocationPayload {
            cell_lat: 38.0,
            cell_lng: -122.0,
            resolution: 0.1,
        };

        assert_eq!(p1, p2);
        assert_ne!(p1, p3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn reducer_count_increments_correctly() {
        let reducer = GeoReducer;
        let entity = EntityId::new();
        let mut state = reducer.initial();

        let event1 = make_geo_event(entity, 37.0, -122.0, 0.1);
        reducer.apply(&mut state, &event1);
        assert_eq!(
            state
                .get("location_count")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );

        let event2 = make_geo_event(entity, 38.0, -123.0, 0.1);
        reducer.apply(&mut state, &event2);
        assert_eq!(
            state
                .get("location_count")
                .and_then(serde_json::Value::as_u64),
            Some(2)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn spatial_cloaker_extreme_coordinates() {
        let cloaker = SpatialCloaker::new(0.1).unwrap();

        let (lat, lng) = cloaker.cloak(point(89.99, -179.99));
        assert!((lat - 90.0).abs() < f64::EPSILON);
        assert!((lng - (-180.0)).abs() < f64::EPSILON);
    }
}
