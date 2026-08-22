#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-plugin-geo` — degree-grid spatial cloaking utilities.
//!
//! Provides spatial cloaking: exact lat/lng → discretized grid cell. Geographic
//! evidence is core-owned under ADR-034: this crate neither admits nor owns
//! `geo.location` or `geo.cell` at runtime. Its legacy [`GeoPlugin`] descriptor
//! is retained only for compatibility with stored V1 payload tooling;
//! `PluginRegistry` rejects its reserved capability.
//!
//! Wave 5 uses a pure-Rust degree-grid snap ([`SpatialCloaker`]); H3/S2 are deferred.
//! Privacy property: exact coordinates are snapped to a configurable grid resolution
//! (e.g., 0.1 degree cells), preventing exact location tracking.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

#[cfg(feature = "h3")]
pub mod geo_cell;

#[cfg(test)]
use pos_core::{
    event::Event,
    state::{Reducer, State},
};
use pos_core::{
    event::{CanonicalBytes, Kind},
    ids::PluginId,
    plugin::{Capability, Plugin},
};
use pos_crypto::canonical;
use serde::{Deserialize, Serialize};

/// Errors returned when a spatial-cloaking input is not a valid WGS84 value.
#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
pub enum GeoError {
    /// The degree-grid cell size is zero, negative, or non-finite.
    #[error("spatial-cloaking resolution must be finite and greater than zero")]
    InvalidResolution,
    /// The grid resolution does not preserve the WGS84 coordinate bounds.
    #[error("spatial-cloaking resolution must partition the 90-degree WGS84 latitude half-span")]
    ResolutionDoesNotPartitionWgs84,
    /// A compact V1 observation requires a 0.1-degree cloaked cell.
    #[error("compact location V1 requires a 0.1-degree cloaked cell")]
    CompactLocationV1Resolution,
    /// A coordinate is not a finite floating-point number.
    #[error("WGS84 coordinate must be finite")]
    NonFiniteCoordinate,
    /// A latitude is outside the WGS84 range `[-90, 90]`.
    #[error("WGS84 latitude must be in [-90, 90]")]
    LatitudeOutOfRange,
    /// A longitude is outside the WGS84 range `[-180, 180]`.
    #[error("WGS84 longitude must be in [-180, 180]")]
    LongitudeOutOfRange,
    /// Canonical serialization failed for a validated compact observation.
    #[error("canonical compact location serialization failed")]
    CanonicalEncoding,
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
    pub const fn latitude(self) -> f64 {
        self.latitude
    }

    /// Return the longitude in decimal degrees.
    #[must_use]
    pub const fn longitude(self) -> f64 {
        self.longitude
    }
}

/// A WGS84-aligned grid point produced by [`SpatialCloaker`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CloakedPoint {
    latitude: f64,
    longitude: f64,
    resolution: f64,
}

/// A cloaked cell known to use the ADR-026 V1 0.1-degree grid.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct V1CloakedPoint(CloakedPoint);

impl TryFrom<CloakedPoint> for V1CloakedPoint {
    type Error = GeoError;

    fn try_from(cell: CloakedPoint) -> Result<Self, Self::Error> {
        if cell.resolution != COMPACT_LOCATION_V1_RESOLUTION_DEGREES {
            return Err(GeoError::CompactLocationV1Resolution);
        }
        Ok(Self(cell))
    }
}

/// A durable, minimized coarse location observation.
///
/// This generic representation intentionally contains neither an exact point
/// nor source-specific telemetry. Its payload is encoded with the workspace's
/// RFC 8949 deterministic CBOR encoder.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompactLocationObservation {
    cell_latitude: f64,
    cell_longitude: f64,
    source_time_bucket: SourceTimeBucket,
    schema_version: CompactLocationSchemaVersion,
    policy_version: CompactLocationPolicyVersion,
    quality_flags: CompactLocationQualityFlags,
}

/// The floor-rounded index of a source-time bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SourceTimeBucket(i64);

impl SourceTimeBucket {
    /// Create a source-time bucket index.
    #[must_use]
    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    /// Return the numeric bucket index.
    #[must_use]
    pub const fn value(self) -> i64 {
        self.0
    }
}

/// The immutable compact-observation schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CompactLocationSchemaVersion(u8);

impl CompactLocationSchemaVersion {
    /// The schema used by the ADR-026 V1 compact location payload.
    pub const V1: Self = Self(1);

    /// Return the encoded schema version.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

/// The consent/minimization policy version recorded with an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CompactLocationPolicyVersion(u8);

impl CompactLocationPolicyVersion {
    /// The ADR-026 V1 policy: 0.1-degree cells and 15-minute source-time buckets.
    pub const V1: Self = Self(1);

    /// Return the encoded policy version.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

/// Bounded flags that qualify how to interpret a compact observation.
///
/// ADR-026 V1 permits only [`Self::NONE`], encoded as zero, meaning that no
/// additional condition qualifies the minimized observation. Nonzero values
/// and telemetry-derived flags are not part of V1; later versions must add a
/// specifically documented flag before they can be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CompactLocationQualityFlags(u8);

impl CompactLocationQualityFlags {
    /// The sole valid V1 value: no quality conditions are recorded.
    pub const NONE: Self = Self(0);

    /// Return the encoded flags value.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }
}

/// Versioned metadata for a compact location observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactLocationMetadata {
    source_time_bucket: SourceTimeBucket,
    schema_version: CompactLocationSchemaVersion,
    policy_version: CompactLocationPolicyVersion,
    quality_flags: CompactLocationQualityFlags,
}

impl CompactLocationMetadata {
    /// Create metadata from explicit, non-interchangeable compact value types.
    #[must_use]
    pub const fn new(
        source_time_bucket: SourceTimeBucket,
        schema_version: CompactLocationSchemaVersion,
        policy_version: CompactLocationPolicyVersion,
        quality_flags: CompactLocationQualityFlags,
    ) -> Self {
        Self {
            source_time_bucket,
            schema_version,
            policy_version,
            quality_flags,
        }
    }

    /// Create ADR-026 V1 metadata for one 15-minute source-time bucket.
    #[must_use]
    pub const fn v1(source_time_bucket: SourceTimeBucket) -> Self {
        Self::new(
            source_time_bucket,
            CompactLocationSchemaVersion::V1,
            CompactLocationPolicyVersion::V1,
            CompactLocationQualityFlags::NONE,
        )
    }
}

impl CompactLocationObservation {
    /// Construct a V1 compact observation from a typed V1 cell and metadata.
    ///
    /// The API accepts only a [`V1CloakedPoint`], so callers cannot construct a
    /// V1 observation from a differently resolved cell or retain an exact
    /// coordinate.
    #[must_use]
    pub const fn new(cell: V1CloakedPoint, metadata: CompactLocationMetadata) -> Self {
        Self {
            cell_latitude: cell.0.latitude(),
            cell_longitude: cell.0.longitude(),
            source_time_bucket: metadata.source_time_bucket,
            schema_version: metadata.schema_version,
            policy_version: metadata.policy_version,
            quality_flags: metadata.quality_flags,
        }
    }

    /// Return the coarse cell latitude in decimal degrees.
    #[must_use]
    pub const fn cell_latitude(&self) -> f64 {
        self.cell_latitude
    }

    /// Return the coarse cell longitude in decimal degrees.
    #[must_use]
    pub const fn cell_longitude(&self) -> f64 {
        self.cell_longitude
    }

    /// Return the floor-rounded source-time bucket index.
    #[must_use]
    pub const fn source_time_bucket(&self) -> SourceTimeBucket {
        self.source_time_bucket
    }

    /// Return the immutable compact-observation schema version.
    #[must_use]
    pub const fn schema_version(&self) -> CompactLocationSchemaVersion {
        self.schema_version
    }

    /// Return the consent/minimization policy version used for this observation.
    #[must_use]
    pub const fn policy_version(&self) -> CompactLocationPolicyVersion {
        self.policy_version
    }

    /// Return bounded interpretation flags.
    #[must_use]
    pub const fn quality_flags(&self) -> CompactLocationQualityFlags {
        self.quality_flags
    }

    /// Encode this compact observation as RFC 8949 deterministic CBOR bytes.
    ///
    /// # Errors
    ///
    /// Returns [`GeoError::CanonicalEncoding`] if the shared deterministic
    /// encoder rejects the validated scalar envelope.
    #[must_use = "the canonical observation bytes are required by the event boundary"]
    pub fn canonical_bytes(&self) -> Result<CanonicalBytes, GeoError> {
        canonical::encode(self).map_err(|_| GeoError::CanonicalEncoding)
    }
}

impl CloakedPoint {
    /// Return the cloaked latitude in decimal degrees.
    #[must_use]
    pub const fn latitude(self) -> f64 {
        self.latitude
    }

    /// Return the cloaked longitude in decimal degrees.
    #[must_use]
    pub const fn longitude(self) -> f64 {
        self.longitude
    }
}

/// The fixed ADR-026 V1 0.1-degree spatial cloaker.
#[derive(Debug, Clone, Copy, Default)]
pub struct V1SpatialCloaker;

impl V1SpatialCloaker {
    /// Construct the fixed V1 spatial cloaker.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Cloak a valid WGS84 point to the fixed V1 grid.
    #[must_use]
    pub fn cloak(self, point: Wgs84Point) -> V1CloakedPoint {
        V1CloakedPoint(SpatialCloaker::cloak_at(
            point,
            COMPACT_LOCATION_V1_RESOLUTION_DEGREES,
        ))
    }
}

/// The entity kind string for geo entities.
pub const ENTITY_KIND: &str = "geo-entity";

/// Legacy V1 payload type name. Core-owned admission is required to persist it.
pub const EVENT_TYPE_LOCATION: &str = "geo.location";

const WGS84_LATITUDE_HALF_SPAN_DEGREES: f64 = 90.0;
const GRID_ALIGNMENT_TOLERANCE: f64 = 1e-9;
const COMPACT_LOCATION_V1_RESOLUTION_DEGREES: f64 = 0.1;

// ---------------------------------------------------------------------------
// Payload types
// ---------------------------------------------------------------------------

/// CBOR payload shape for legacy `geo.location` evidence.
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
    /// is zero, negative, or non-finite. Returns
    /// [`GeoError::ResolutionDoesNotPartitionWgs84`] unless the resolution
    /// divides the 90-degree WGS84 latitude half-span into whole cells.
    pub fn new(resolution: f64) -> Result<Self, GeoError> {
        if !resolution.is_finite() || resolution <= 0.0 {
            return Err(GeoError::InvalidResolution);
        }
        let cells_per_latitude_half_span = WGS84_LATITUDE_HALF_SPAN_DEGREES / resolution;
        if (cells_per_latitude_half_span - cells_per_latitude_half_span.round()).abs()
            > GRID_ALIGNMENT_TOLERANCE
        {
            return Err(GeoError::ResolutionDoesNotPartitionWgs84);
        }
        Ok(Self { resolution })
    }

    /// Return the validated degree-grid resolution.
    #[must_use]
    pub const fn resolution(self) -> f64 {
        self.resolution
    }

    /// Cloak exact coordinates to the nearest grid point.
    ///
    /// Snaps to `(lat / resolution).round() * resolution`.
    /// This ensures that all points within `resolution/2` map to the same cell.
    #[must_use]
    pub fn cloak(&self, point: Wgs84Point) -> CloakedPoint {
        Self::cloak_at(point, self.resolution)
    }

    fn cloak_at(point: Wgs84Point, resolution: f64) -> CloakedPoint {
        CloakedPoint {
            latitude: (point.latitude / resolution).round() * resolution,
            longitude: (point.longitude / resolution).round() * resolution,
            resolution,
        }
    }
}

// ---------------------------------------------------------------------------
// Plugin descriptor
// ---------------------------------------------------------------------------

/// Legacy descriptor for V1 geographic payload tooling.
///
/// It cannot be registered: `geo.location` is reserved to the core-owned
/// geographic boundary.
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

#[cfg(test)]
struct GeoReducer;

#[cfg(test)]
impl Reducer for GeoReducer {
    fn initial(&self) -> State {
        let mut s = State::new();
        s.set("location_count", serde_json::Value::Number(0.into()));
        s.set(
            "last_cell_lat",
            serde_json::Value::Number(
                serde_json::Number::from_f64(0.0).unwrap_or_else(|| 0.into()),
            ),
        );
        s.set(
            "last_cell_lng",
            serde_json::Value::Number(
                serde_json::Number::from_f64(0.0).unwrap_or_else(|| 0.into()),
            ),
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
                let lat_num =
                    serde_json::Number::from_f64(payload.cell_lat).unwrap_or_else(|| 0.into());
                let lng_num =
                    serde_json::Number::from_f64(payload.cell_lng).unwrap_or_else(|| 0.into());
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
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::SchemaVersion,
        ids::{EntityId, EventId},
    };

    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected geo fixture error: {error:?}"
                )))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing geo fixture value")))
        }
    }

    trait TestErrorExt<T, E> {
        fn test_err(self) -> E;
    }

    impl<T: std::fmt::Debug, E> TestErrorExt<T, E> for Result<T, E> {
        fn test_err(self) -> E {
            match self {
                Ok(value) => std::panic::resume_unwind(Box::new(format!(
                    "unexpected successful geo fixture value: {value:?}"
                ))),
                Err(error) => error,
            }
        }
    }

    fn wgs84_point(lat: f64, lng: f64) -> Wgs84Point {
        Wgs84Point::new(lat, lng).test_ok()
    }

    fn make_geo_event(entity: EntityId, cell_lat: f64, cell_lng: f64, resolution: f64) -> Event {
        let payload = GeoLocationPayload {
            cell_lat,
            cell_lng,
            resolution,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).test_ok();

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
        let cloaker = SpatialCloaker::new(0.1).test_ok();

        // Test exact grid point
        let point = cloaker.cloak(wgs84_point(37.0, -122.0));
        let (lat, lng) = (point.latitude(), point.longitude());
        assert!((lat - 37.0).abs() < TOLERANCE);
        assert!((lng - (-122.0)).abs() < TOLERANCE);

        // Test rounding down
        let point = cloaker.cloak(wgs84_point(37.03, -122.02));
        let (lat, lng) = (point.latitude(), point.longitude());
        assert!((lat - 37.0).abs() < TOLERANCE);
        assert!((lng - (-122.0)).abs() < TOLERANCE);

        // Test rounding up
        let point = cloaker.cloak(wgs84_point(37.07, -122.08));
        let (lat, lng) = (point.latitude(), point.longitude());
        assert!((lat - 37.1).abs() < TOLERANCE);
        assert!((lng - (-122.1)).abs() < TOLERANCE);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn spatial_cloaker_resolution_half_degree() {
        let cloaker = SpatialCloaker::new(0.5).test_ok();

        assert!((cloaker.resolution() - 0.5).abs() < f64::EPSILON);

        let point = cloaker.cloak(wgs84_point(37.2, -122.3));
        let (lat, lng) = (point.latitude(), point.longitude());
        assert!((lat - 37.0).abs() < f64::EPSILON);
        assert!((lng - (-122.5)).abs() < f64::EPSILON);

        let point = cloaker.cloak(wgs84_point(37.3, -122.6));
        let (lat, lng) = (point.latitude(), point.longitude());
        assert!((lat - 37.5).abs() < f64::EPSILON);
        assert!((lng - (-122.5)).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn spatial_cloaker_rejects_invalid_resolutions() {
        for resolution in [0.0, -0.1, f64::INFINITY, f64::NAN] {
            assert_eq!(
                SpatialCloaker::new(resolution).test_err(),
                GeoError::InvalidResolution
            );
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn spatial_cloaker_rejects_resolutions_that_do_not_align_to_wgs84() {
        for resolution in [100.0, 7.0] {
            assert_eq!(
                SpatialCloaker::new(resolution).test_err(),
                GeoError::ResolutionDoesNotPartitionWgs84
            );
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn wgs84_point_accepts_boundary_coordinates() {
        let point = Wgs84Point::new(-90.0, 180.0).test_ok();
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
    fn compact_location_uses_cloaked_cell_and_typed_v1_metadata() {
        let cloaker = V1SpatialCloaker::new();
        let cell = cloaker.cloak(wgs84_point(0.0, 0.0));
        let metadata = CompactLocationMetadata::v1(SourceTimeBucket::new(2));
        let location = CompactLocationObservation::new(cell, metadata);
        assert!((location.cell_latitude() - 0.0).abs() < f64::EPSILON);
        assert!((location.cell_longitude() - 0.0).abs() < f64::EPSILON);
        assert_eq!(location.source_time_bucket().value(), 2);
        assert_eq!(location.schema_version(), CompactLocationSchemaVersion::V1);
        assert_eq!(location.schema_version().value(), 1);
        assert_eq!(location.policy_version(), CompactLocationPolicyVersion::V1);
        assert_eq!(location.policy_version().value(), 1);
        assert_eq!(location.quality_flags(), CompactLocationQualityFlags::NONE);
        assert_eq!(location.quality_flags().bits(), 0);
        assert_eq!(
            location.canonical_bytes().test_ok().as_slice(),
            [
                0xa6, 0x6d, b'c', b'e', b'l', b'l', b'_', b'l', b'a', b't', b'i', b't', b'u', b'd',
                b'e', 0xf9, 0, 0, 0x6d, b'q', b'u', b'a', b'l', b'i', b't', b'y', b'_', b'f', b'l',
                b'a', b'g', b's', 0, 0x6e, b'c', b'e', b'l', b'l', b'_', b'l', b'o', b'n', b'g',
                b'i', b't', b'u', b'd', b'e', 0xf9, 0, 0, 0x6e, b'p', b'o', b'l', b'i', b'c', b'y',
                b'_', b'v', b'e', b'r', b's', b'i', b'o', b'n', 1, 0x6e, b's', b'c', b'h', b'e',
                b'm', b'a', b'_', b'v', b'e', b'r', b's', b'i', b'o', b'n', 1, 0x72, b's', b'o',
                b'u', b'r', b'c', b'e', b'_', b't', b'i', b'm', b'e', b'_', b'b', b'u', b'c', b'k',
                b'e', b't', 2,
            ]
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn v1_compact_cells_require_the_fixed_v1_resolution() {
        let point = wgs84_point(0.0, 0.0);
        let valid = SpatialCloaker::new(0.1).test_ok().cloak(point);
        assert!(V1CloakedPoint::try_from(valid).is_ok());

        let invalid = SpatialCloaker::new(1.0).test_ok().cloak(point);
        assert_eq!(
            V1CloakedPoint::try_from(invalid),
            Err(GeoError::CompactLocationV1Resolution)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn spatial_cloaker_privacy_property() {
        let cloaker = SpatialCloaker::new(0.1).test_ok();

        // Two points within resolution/2 should map to same cell
        let point1 = cloaker.cloak(wgs84_point(37.0, -122.0));
        let point2 = cloaker.cloak(wgs84_point(37.04, -122.03));
        let (lat1, lng1) = (point1.latitude(), point1.longitude());
        let (lat2, lng2) = (point2.latitude(), point2.longitude());

        assert!((lat1 - lat2).abs() < f64::EPSILON);
        assert!((lng1 - lng2).abs() < f64::EPSILON);
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
        ciborium::into_writer(&payload, &mut buf).test_ok();
        let back: GeoLocationPayload = ciborium::from_reader(buf.as_slice()).test_ok();

        assert_eq!(payload, back);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn spatial_cloaker_negative_coordinates() {
        let cloaker = SpatialCloaker::new(0.1).test_ok();

        let point = cloaker.cloak(wgs84_point(-37.07, 122.03));
        let (lat, lng) = (point.latitude(), point.longitude());
        assert!((lat - (-37.1)).abs() < f64::EPSILON);
        assert!((lng - 122.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn spatial_cloaker_zero_coordinates() {
        let cloaker = SpatialCloaker::new(0.1).test_ok();

        let point = cloaker.cloak(wgs84_point(0.0, 0.0));
        let (lat, lng) = (point.latitude(), point.longitude());
        assert!((lat - 0.0).abs() < f64::EPSILON);
        assert!((lng - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn spatial_cloaker_clone() {
        let cloaker1 = SpatialCloaker::new(0.1).test_ok();
        let cloaker2 = cloaker1;

        let point1 = cloaker1.cloak(wgs84_point(37.0, -122.0));
        let point2 = cloaker2.cloak(wgs84_point(37.0, -122.0));
        let (lat1, lng1) = (point1.latitude(), point1.longitude());
        let (lat2, lng2) = (point2.latitude(), point2.longitude());

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
        let cloaker = SpatialCloaker::new(0.1).test_ok();

        let point = cloaker.cloak(wgs84_point(89.99, -179.99));
        let (lat, lng) = (point.latitude(), point.longitude());
        assert!((lat - 90.0).abs() < f64::EPSILON);
        assert!((lng - (-180.0)).abs() < f64::EPSILON);
    }
}
