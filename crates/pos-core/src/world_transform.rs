use std::collections::BTreeMap;

use thiserror::Error;

const SEMI_MAJOR_AXIS_METRES: f64 = 6_378_137.0;
const INVERSE_FLATTENING: f64 = 298.257_223_563;
const FLATTENING: f64 = 1.0 / INVERSE_FLATTENING;
const FIRST_ECCENTRICITY_SQUARED: f64 = FLATTENING * (2.0 - FLATTENING);
const PI: f64 = std::f64::consts::PI;
const MAX_V1_RADIUS_METRES: f64 = 10_000.0;
const INVERSE_ITERATIONS: usize = 16;
const INVERSE_LATITUDE_TOLERANCE_RADIANS: f64 = 1.0 / 281_474_976_710_656.0;
const FORWARD_ABSOLUTE_TOLERANCE_METRES: f64 = 1e-6;
const FORWARD_RELATIVE_TOLERANCE: f64 = 1e-12;
const DIGEST_DOMAIN: &[u8] = b"pigloros/adr-032/world-origin-v1\0";

/// Errors returned by the core-owned deterministic WGS 84 transform seam.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum WorldTransformError {
    /// A supplied coordinate or intermediate value is not finite.
    #[error("world transform coordinate is not finite")]
    NonFiniteCoordinate,
    /// Latitude is outside the supported open interval.
    #[error("world transform latitude is outside (-90, 90) degrees")]
    LatitudeOutOfRange,
    /// Exact poles or an inverse point on the polar axis are unsupported.
    #[error("world transform does not support exact poles")]
    PoleUnsupported,
    /// The local transform radius is invalid.
    #[error("world transform radius must be finite, positive, and at most 10000 metres")]
    InvalidRadius,
    /// The transformed point is outside the configured local frame.
    #[error("world coordinate is outside the configured local radius")]
    OutOfRadius,
    /// The inverse did not satisfy its fixed convergence or residual contract.
    #[error("world transform inverse did not converge")]
    NonConvergent,
    /// The immutable origin definition does not match its digest.
    #[error("world origin definition digest mismatch")]
    InvalidOriginDigest,
    /// A registry key is already present.
    #[error("world origin is already registered")]
    DuplicateOrigin,
    /// A world/origin revision would move backwards.
    #[error("world origin revision conflicts with the immutable registry")]
    OriginRevisionConflict,
    /// A registry reference has no matching origin.
    #[error("world origin is unavailable")]
    OriginUnavailable,
    /// A registered origin cannot admit new evidence.
    #[error("world origin revision is retired")]
    OriginRetired,
}

/// An opaque capability held by the trusted core composition root.
///
/// Geographic evidence values are intentionally not generic serializable or
/// displayable application values. Downstream adapters receive derived named
/// coordinates rather than this capability.
pub struct WorldGeographicEvidenceCapabilityV1 {
    private: bool,
}

impl WorldGeographicEvidenceCapabilityV1 {
    /// Mint the capability at the trusted core composition root.
    #[must_use]
    pub const fn for_trusted_core() -> Self {
        Self { private: true }
    }
}

/// A validated WGS 84 geographic 3D position.
///
/// The value is transient geographic evidence. It intentionally does not
/// implement generic formatting or serialization traits.
#[derive(Clone, Copy, PartialEq)]
pub struct Wgs84PositionV1 {
    latitude_degrees: f64,
    longitude_degrees: f64,
    ellipsoidal_height_metres: f64,
}

impl Wgs84PositionV1 {
    /// Validate a position and canonicalize longitude to [-180, 180).
    ///
    /// # Errors
    ///
    /// Returns a typed error for non-finite values, exact poles, or an
    /// out-of-range latitude.
    pub fn new(
        latitude_degrees: f64,
        longitude_degrees: f64,
        ellipsoidal_height_metres: f64,
    ) -> Result<Self, WorldTransformError> {
        if !latitude_degrees.is_finite()
            || !longitude_degrees.is_finite()
            || !ellipsoidal_height_metres.is_finite()
        {
            return Err(WorldTransformError::NonFiniteCoordinate);
        }
        if latitude_degrees.to_bits() == (-90.0f64).to_bits()
            || latitude_degrees.to_bits() == 90.0f64.to_bits()
        {
            return Err(WorldTransformError::PoleUnsupported);
        }
        if !(-90.0..90.0).contains(&latitude_degrees) {
            return Err(WorldTransformError::LatitudeOutOfRange);
        }
        Ok(Self {
            latitude_degrees,
            longitude_degrees: normalize_longitude_degrees(longitude_degrees),
            ellipsoidal_height_metres,
        })
    }

    /// Return latitude in decimal degrees.
    #[must_use]
    pub const fn latitude_degrees(self) -> f64 {
        self.latitude_degrees
    }

    /// Return canonical longitude in decimal degrees.
    #[must_use]
    pub const fn longitude_degrees(self) -> f64 {
        self.longitude_degrees
    }

    /// Return WGS 84 ellipsoidal height in metres.
    #[must_use]
    pub const fn ellipsoidal_height_metres(self) -> f64 {
        self.ellipsoidal_height_metres
    }
}

/// A named local East/North/Up metric coordinate.
///
/// This value is transient geographic evidence and intentionally has no
/// generic serialization, display, or debug representation.
#[derive(Clone, Copy, PartialEq)]
pub struct WorldCoordinateV1 {
    east: f64,
    north: f64,
    up: f64,
}

impl WorldCoordinateV1 {
    /// Return East in metres.
    #[must_use]
    pub const fn east_metres(self) -> f64 {
        self.east
    }

    /// Return North in metres.
    #[must_use]
    pub const fn north_metres(self) -> f64 {
        self.north
    }

    /// Return Up in metres.
    #[must_use]
    pub const fn up_metres(self) -> f64 {
        self.up
    }

    /// Translate a coordinate by named metric offsets.
    ///
    /// # Errors
    ///
    /// Returns [`WorldTransformError::NonFiniteCoordinate`] if an offset or
    /// translated component is not finite.
    pub fn translated_by(
        self,
        east_metres: f64,
        north_metres: f64,
        up_metres: f64,
    ) -> Result<Self, WorldTransformError> {
        let translated = [
            self.east + east_metres,
            self.north + north_metres,
            self.up + up_metres,
        ];
        if translated.iter().all(|value| value.is_finite()) {
            Ok(Self {
                east: translated[0],
                north: translated[1],
                up: translated[2],
            })
        } else {
            Err(WorldTransformError::NonFiniteCoordinate)
        }
    }

    fn from_components(
        east_metres: f64,
        north_metres: f64,
        up_metres: f64,
    ) -> Result<Self, WorldTransformError> {
        if !east_metres.is_finite() || !north_metres.is_finite() || !up_metres.is_finite() {
            return Err(WorldTransformError::NonFiniteCoordinate);
        }
        Ok(Self {
            east: east_metres,
            north: north_metres,
            up: up_metres,
        })
    }
}

/// An opaque immutable registry reference.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WorldOriginReferenceV1 {
    world_id: [u8; 16],
    origin_id: [u8; 16],
    origin_revision: u64,
    origin_definition_digest: [u8; 32],
}

impl WorldOriginReferenceV1 {
    /// Construct a reference from opaque identity material.
    #[must_use]
    pub const fn new(
        world_id: [u8; 16],
        origin_id: [u8; 16],
        origin_revision: u64,
        origin_definition_digest: [u8; 32],
    ) -> Self {
        Self {
            world_id,
            origin_id,
            origin_revision,
            origin_definition_digest,
        }
    }

    /// Return the opaque world identifier.
    #[must_use]
    pub const fn world_id(self) -> [u8; 16] {
        self.world_id
    }

    /// Return the opaque origin identifier.
    #[must_use]
    pub const fn origin_id(self) -> [u8; 16] {
        self.origin_id
    }

    /// Return the immutable origin revision.
    #[must_use]
    pub const fn origin_revision(self) -> u64 {
        self.origin_revision
    }

    /// Return the origin-definition digest.
    #[must_use]
    pub const fn origin_definition_digest(self) -> [u8; 32] {
        self.origin_definition_digest
    }
}

/// An immutable world-scoped transform origin.
///
/// The geographic position is retained only inside the core-owned transform
/// seam and is never exposed by generic formatting or serialization.
#[derive(Clone, Copy, PartialEq)]
pub struct WorldOriginV1 {
    world_id: [u8; 16],
    origin_id: [u8; 16],
    origin_revision: u64,
    position: Wgs84PositionV1,
    provenance: [u8; 32],
    max_radius_metres: f64,
    origin_definition_digest: [u8; 32],
    origin_ecef: [f64; 3],
    retired: bool,
}

impl WorldOriginV1 {
    /// Create an immutable origin definition and its normative digest.
    ///
    /// # Errors
    ///
    /// Returns a typed error if the radius is invalid or the origin's ECEF
    /// intermediate cannot be represented as finite values.
    pub fn new(
        capability: &WorldGeographicEvidenceCapabilityV1,
        world_id: [u8; 16],
        origin_id: [u8; 16],
        origin_revision: u64,
        position: Wgs84PositionV1,
        provenance: [u8; 32],
        max_radius_metres: f64,
    ) -> Result<Self, WorldTransformError> {
        validate_capability(capability);
        validate_radius(max_radius_metres)?;
        let origin_ecef = geodetic_to_ecef(position)?;
        let origin_definition_digest = definition_digest(
            world_id,
            origin_id,
            origin_revision,
            position,
            max_radius_metres,
        );
        Ok(Self {
            world_id,
            origin_id,
            origin_revision,
            position,
            provenance,
            max_radius_metres,
            origin_definition_digest,
            origin_ecef,
            retired: false,
        })
    }

    /// Return the opaque reference needed to resolve this origin.
    #[must_use]
    pub const fn reference(self) -> WorldOriginReferenceV1 {
        WorldOriginReferenceV1::new(
            self.world_id,
            self.origin_id,
            self.origin_revision,
            self.origin_definition_digest,
        )
    }

    /// Return the opaque world identifier.
    #[must_use]
    pub const fn world_id(self) -> [u8; 16] {
        self.world_id
    }

    /// Return the opaque origin identifier.
    #[must_use]
    pub const fn origin_id(self) -> [u8; 16] {
        self.origin_id
    }

    /// Return the immutable revision.
    #[must_use]
    pub const fn origin_revision(self) -> u64 {
        self.origin_revision
    }

    /// Return the configured local radius in metres.
    #[must_use]
    pub const fn max_radius_metres(self) -> f64 {
        self.max_radius_metres
    }

    /// Return the normative origin-definition digest.
    #[must_use]
    pub const fn origin_definition_digest(self) -> [u8; 32] {
        self.origin_definition_digest
    }

    /// Return opaque provenance metadata without exposing geographic values.
    #[must_use]
    pub const fn provenance(self) -> [u8; 32] {
        self.provenance
    }

    fn verify_digest(self) -> Result<(), WorldTransformError> {
        let expected = definition_digest(
            self.world_id,
            self.origin_id,
            self.origin_revision,
            self.position,
            self.max_radius_metres,
        );
        if expected == self.origin_definition_digest {
            Ok(())
        } else {
            Err(WorldTransformError::InvalidOriginDigest)
        }
    }
}

/// A pure deterministic WGS 84 -> ECEF -> local ENU transform.
pub struct WorldTransformV1 {
    origin: WorldOriginV1,
    origin_sin_latitude: f64,
    origin_cos_latitude: f64,
    origin_sin_longitude: f64,
    origin_cos_longitude: f64,
}

impl WorldTransformV1 {
    /// Construct a transform from an immutable origin.
    ///
    /// # Errors
    ///
    /// Returns [`WorldTransformError::InvalidOriginDigest`] for a mismatched
    /// immutable origin artifact.
    pub fn new(
        capability: &WorldGeographicEvidenceCapabilityV1,
        origin: WorldOriginV1,
    ) -> Result<Self, WorldTransformError> {
        validate_capability(capability);
        origin.verify_digest()?;
        let (latitude, longitude) = radians(origin.position);
        Ok(Self {
            origin,
            origin_sin_latitude: latitude.sin(),
            origin_cos_latitude: latitude.cos(),
            origin_sin_longitude: longitude.sin(),
            origin_cos_longitude: longitude.cos(),
        })
    }

    /// Convert a validated WGS 84 position into local ENU metres.
    ///
    /// # Errors
    ///
    /// Returns a typed error for non-finite intermediates or a point outside
    /// the configured local radius.
    pub fn forward(
        &self,
        capability: &WorldGeographicEvidenceCapabilityV1,
        position: Wgs84PositionV1,
    ) -> Result<WorldCoordinateV1, WorldTransformError> {
        validate_capability(capability);
        let [x, y, z] = geodetic_to_ecef(position)?;
        let dx = x - self.origin.origin_ecef[0];
        let dy = y - self.origin.origin_ecef[1];
        let dz = z - self.origin.origin_ecef[2];
        let east = -self.origin_sin_longitude * dx + self.origin_cos_longitude * dy;
        let north = -self.origin_sin_latitude * self.origin_cos_longitude * dx
            - self.origin_sin_latitude * self.origin_sin_longitude * dy
            + self.origin_cos_latitude * dz;
        let up = self.origin_cos_latitude * self.origin_cos_longitude * dx
            + self.origin_cos_latitude * self.origin_sin_longitude * dy
            + self.origin_sin_latitude * dz;
        let coordinate = WorldCoordinateV1::from_components(east, north, up)?;
        let radius = (east * east + north * north + up * up).sqrt();
        if !radius.is_finite() {
            return Err(WorldTransformError::NonFiniteCoordinate);
        }
        if radius > self.origin.max_radius_metres {
            return Err(WorldTransformError::OutOfRadius);
        }
        Ok(coordinate)
    }

    /// Convert a local ENU coordinate back to WGS 84 for core replay/conformance.
    ///
    /// # Errors
    ///
    /// Returns a typed error if the coordinate is non-finite, polar, or fails
    /// the fixed inverse convergence and residual contract.
    pub fn inverse(
        &self,
        capability: &WorldGeographicEvidenceCapabilityV1,
        coordinate: WorldCoordinateV1,
    ) -> Result<Wgs84PositionV1, WorldTransformError> {
        validate_capability(capability);
        let east = coordinate.east;
        let north = coordinate.north;
        let up = coordinate.up;
        let radius = (east * east + north * north + up * up).sqrt();
        if !radius.is_finite() {
            return Err(WorldTransformError::NonFiniteCoordinate);
        }
        if radius > self.origin.max_radius_metres {
            return Err(WorldTransformError::OutOfRadius);
        }
        let dx = -self.origin_sin_longitude * east
            - self.origin_sin_latitude * self.origin_cos_longitude * north
            + self.origin_cos_latitude * self.origin_cos_longitude * up;
        let dy = self.origin_cos_longitude * east
            - self.origin_sin_latitude * self.origin_sin_longitude * north
            + self.origin_cos_latitude * self.origin_sin_longitude * up;
        let dz = self.origin_cos_latitude * north + self.origin_sin_latitude * up;
        let ecef_x = self.origin.origin_ecef[0] + dx;
        let ecef_y = self.origin.origin_ecef[1] + dy;
        let ecef_z = self.origin.origin_ecef[2] + dz;
        if !ecef_x.is_finite() || !ecef_y.is_finite() || !ecef_z.is_finite() {
            return Err(WorldTransformError::NonFiniteCoordinate);
        }
        let horizontal_distance = ecef_x.hypot(ecef_y);
        if horizontal_distance.to_bits() == 0 || !horizontal_distance.is_finite() {
            return Err(WorldTransformError::PoleUnsupported);
        }
        let longitude = ecef_y.atan2(ecef_x);
        let mut latitude = ecef_z.atan2(horizontal_distance * (1.0 - FIRST_ECCENTRICITY_SQUARED));
        let mut last_delta = f64::INFINITY;
        for _ in 0..INVERSE_ITERATIONS {
            let prime_radius = prime_vertical_radius(latitude);
            let cosine = latitude.cos();
            if !prime_radius.is_finite() {
                return Err(WorldTransformError::NonConvergent);
            }
            let height = horizontal_distance / cosine - prime_radius;
            let denominator = prime_radius + height;
            if !denominator.is_finite() || denominator.to_bits() == 0 {
                return Err(WorldTransformError::NonConvergent);
            }
            let next = ecef_z.atan2(
                horizontal_distance
                    * (1.0 - FIRST_ECCENTRICITY_SQUARED * prime_radius / denominator),
            );
            last_delta = (next - latitude).abs();
            latitude = next;
        }
        if last_delta > INVERSE_LATITUDE_TOLERANCE_RADIANS {
            return Err(WorldTransformError::NonConvergent);
        }
        let cosine = latitude.cos();
        let prime_radius = prime_vertical_radius(latitude);
        let height = horizontal_distance / cosine - prime_radius;
        if !height.is_finite() {
            return Err(WorldTransformError::NonConvergent);
        }
        let position = Wgs84PositionV1::new(
            latitude * 180.0 / PI,
            normalize_longitude_degrees(longitude * 180.0 / PI),
            height,
        )?;
        let recovered = geodetic_to_ecef(position)?;
        if [
            (recovered[0], ecef_x),
            (recovered[1], ecef_y),
            (recovered[2], ecef_z),
        ]
        .iter()
        .any(|(actual, expected)| !within_residual(*actual, *expected))
        {
            return Err(WorldTransformError::NonConvergent);
        }
        Ok(position)
    }
}

/// An in-memory immutable origin registry for authorized replay/conformance.
pub struct WorldOriginRegistryV1 {
    origins: BTreeMap<OriginKey, WorldOriginV1>,
}

impl WorldOriginRegistryV1 {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origins: BTreeMap::new(),
        }
    }

    /// Register one verified immutable origin.
    ///
    /// # Errors
    ///
    /// Returns a typed error for a digest mismatch, duplicate identity, or
    /// revision rollback.
    pub fn register(
        &mut self,
        capability: &WorldGeographicEvidenceCapabilityV1,
        origin: WorldOriginV1,
    ) -> Result<(), WorldTransformError> {
        validate_capability(capability);
        origin.verify_digest()?;
        let key = OriginKey::from_origin(origin);
        if self.origins.contains_key(&key) {
            return Err(WorldTransformError::DuplicateOrigin);
        }
        if self
            .origins
            .keys()
            .any(|existing| existing.same_origin(key) && existing.revision >= key.revision)
        {
            return Err(WorldTransformError::OriginRevisionConflict);
        }
        self.origins.insert(key, origin);
        Ok(())
    }

    /// Resolve an exact, non-retired origin reference.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the reference is missing, mismatched, or
    /// retired.
    pub fn resolve(
        &self,
        capability: &WorldGeographicEvidenceCapabilityV1,
        reference: &WorldOriginReferenceV1,
    ) -> Result<WorldTransformV1, WorldTransformError> {
        validate_capability(capability);
        let Some(origin) = self.origins.get(&OriginKey::from_reference(*reference)) else {
            return Err(WorldTransformError::OriginUnavailable);
        };
        if origin.origin_definition_digest != reference.origin_definition_digest {
            return Err(WorldTransformError::InvalidOriginDigest);
        }
        if origin.retired {
            return Err(WorldTransformError::OriginRetired);
        }
        WorldTransformV1::new(capability, *origin)
    }

    /// Retire one origin revision without deleting it from replay storage.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the reference is missing or its digest does
    /// not match the immutable registry entry.
    pub fn retire(
        &mut self,
        capability: &WorldGeographicEvidenceCapabilityV1,
        reference: &WorldOriginReferenceV1,
    ) -> Result<(), WorldTransformError> {
        validate_capability(capability);
        let Some(origin) = self.origins.get_mut(&OriginKey::from_reference(*reference)) else {
            return Err(WorldTransformError::OriginUnavailable);
        };
        if origin.origin_definition_digest != reference.origin_definition_digest {
            return Err(WorldTransformError::InvalidOriginDigest);
        }
        origin.retired = true;
        Ok(())
    }

    /// Atomically validate and replace the registry contents.
    ///
    /// # Errors
    ///
    /// Returns a typed error if any candidate entry is invalid, duplicated, or
    /// has a conflicting revision; the existing registry remains unchanged.
    pub fn restore(
        &mut self,
        capability: &WorldGeographicEvidenceCapabilityV1,
        origins: Vec<WorldOriginV1>,
    ) -> Result<(), WorldTransformError> {
        validate_capability(capability);
        let mut candidate: BTreeMap<OriginKey, WorldOriginV1> = BTreeMap::new();
        for origin in origins {
            origin.verify_digest()?;
            let key = OriginKey::from_origin(origin);
            if candidate.contains_key(&key) {
                return Err(WorldTransformError::DuplicateOrigin);
            }
            if candidate
                .keys()
                .any(|existing| existing.same_origin(key) && existing.revision >= key.revision)
            {
                return Err(WorldTransformError::OriginRevisionConflict);
            }
            candidate.insert(key, origin);
        }
        self.origins = candidate;
        Ok(())
    }
}

impl Default for WorldOriginRegistryV1 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct OriginKey {
    world_id: [u8; 16],
    origin_id: [u8; 16],
    revision: u64,
}

impl OriginKey {
    const fn from_origin(origin: WorldOriginV1) -> Self {
        Self {
            world_id: origin.world_id,
            origin_id: origin.origin_id,
            revision: origin.origin_revision,
        }
    }

    const fn from_reference(reference: WorldOriginReferenceV1) -> Self {
        Self {
            world_id: reference.world_id,
            origin_id: reference.origin_id,
            revision: reference.origin_revision,
        }
    }

    fn same_origin(self, other: Self) -> bool {
        self.world_id == other.world_id && self.origin_id == other.origin_id
    }
}

fn validate_radius(max_radius_metres: f64) -> Result<(), WorldTransformError> {
    if !max_radius_metres.is_finite()
        || max_radius_metres <= 0.0
        || max_radius_metres > MAX_V1_RADIUS_METRES
    {
        return Err(WorldTransformError::InvalidRadius);
    }
    Ok(())
}

fn validate_capability(capability: &WorldGeographicEvidenceCapabilityV1) {
    std::hint::black_box(capability.private);
}

fn normalize_longitude_degrees(longitude_degrees: f64) -> f64 {
    let normalized = (longitude_degrees + 180.0).rem_euclid(360.0) - 180.0;
    if normalized == 0.0 {
        0.0
    } else {
        normalized
    }
}

fn radians(position: Wgs84PositionV1) -> (f64, f64) {
    (
        position.latitude_degrees * PI / 180.0,
        position.longitude_degrees * PI / 180.0,
    )
}

fn prime_vertical_radius(latitude: f64) -> f64 {
    SEMI_MAJOR_AXIS_METRES / (1.0 - FIRST_ECCENTRICITY_SQUARED * latitude.sin().powi(2)).sqrt()
}

fn geodetic_to_ecef(position: Wgs84PositionV1) -> Result<[f64; 3], WorldTransformError> {
    let (latitude, longitude) = radians(position);
    let sine_latitude = latitude.sin();
    let cosine_latitude = latitude.cos();
    let sine_longitude = longitude.sin();
    let cosine_longitude = longitude.cos();
    let n = prime_vertical_radius(latitude);
    let height = position.ellipsoidal_height_metres;
    let x = (n + height) * cosine_latitude * cosine_longitude;
    let y = (n + height) * cosine_latitude * sine_longitude;
    let z = (n * (1.0 - FIRST_ECCENTRICITY_SQUARED) + height) * sine_latitude;
    if x.is_finite() && y.is_finite() && z.is_finite() {
        Ok([x, y, z])
    } else {
        Err(WorldTransformError::NonFiniteCoordinate)
    }
}

fn within_residual(actual: f64, expected: f64) -> bool {
    (actual - expected).abs()
        <= FORWARD_ABSOLUTE_TOLERANCE_METRES + FORWARD_RELATIVE_TOLERANCE * expected.abs()
}

fn canonical_zero(value: f64) -> f64 {
    if value == 0.0 {
        0.0
    } else {
        value
    }
}

fn definition_digest(
    world_id: [u8; 16],
    origin_id: [u8; 16],
    origin_revision: u64,
    position: Wgs84PositionV1,
    max_radius_metres: f64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(&[1]);
    hasher.update(&world_id);
    hasher.update(&origin_id);
    hasher.update(&origin_revision.to_be_bytes());
    for value in [
        position.latitude_degrees,
        position.longitude_degrees,
        position.ellipsoidal_height_metres,
        max_radius_metres,
    ] {
        hasher.update(&canonical_zero(value).to_bits().to_be_bytes());
    }
    hasher.update(b"6378137");
    hasher.update(b"298.257223563");
    hasher.update(b"WorldTransformV1");
    hasher.update(b"ENU");
    hasher.update(b"metre");
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability() -> WorldGeographicEvidenceCapabilityV1 {
        WorldGeographicEvidenceCapabilityV1::for_trusted_core()
    }

    fn origin(
        capability: &WorldGeographicEvidenceCapabilityV1,
        max_radius_metres: f64,
    ) -> WorldOriginV1 {
        WorldOriginV1::new(
            capability,
            [1; 16],
            [2; 16],
            1,
            Wgs84PositionV1::new(35.0, -120.0, 100.0).expect("fixture origin is valid"),
            [3; 32],
            max_radius_metres,
        )
        .expect("fixture origin is valid")
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn position_normalizes_longitude_and_rejects_poles() {
        let position =
            Wgs84PositionV1::new(10.0, 540.0, -20.0).expect("finite longitude normalizes");
        assert_eq!(position.latitude_degrees().to_bits(), 10.0f64.to_bits());
        assert_eq!(
            position.longitude_degrees().to_bits(),
            (-180.0f64).to_bits()
        );
        assert_eq!(
            position.ellipsoidal_height_metres().to_bits(),
            (-20.0f64).to_bits()
        );
        assert!(matches!(
            Wgs84PositionV1::new(90.0, 0.0, 0.0),
            Err(WorldTransformError::PoleUnsupported)
        ));
        assert!(matches!(
            Wgs84PositionV1::new(f64::NAN, 0.0, 0.0),
            Err(WorldTransformError::NonFiniteCoordinate)
        ));
        assert!(matches!(
            Wgs84PositionV1::new(91.0, 0.0, 0.0),
            Err(WorldTransformError::LatitudeOutOfRange)
        ));
        assert!(matches!(
            Wgs84PositionV1::new(0.0, f64::INFINITY, 0.0),
            Err(WorldTransformError::NonFiniteCoordinate)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn origin_definition_digest_fixture_is_stable() {
        let capability = capability();
        let origin = origin(&capability, 10_000.0);
        assert_eq!(
            origin.origin_definition_digest(),
            [
                0xea, 0x16, 0xee, 0xa9, 0xe2, 0xe0, 0x94, 0x2c, 0xdb, 0x74, 0x27, 0x61, 0xf6, 0x84,
                0xbb, 0x1a, 0x1d, 0xb5, 0x35, 0x79, 0x7f, 0x2b, 0xdd, 0x7c, 0x08, 0x82, 0xb7, 0x30,
                0x69, 0xef, 0x89, 0xeb,
            ]
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn forward_origin_is_zero_and_repeated_forward_is_deterministic() {
        let capability = capability();
        let origin = origin(&capability, 10_000.0);
        let transform =
            WorldTransformV1::new(&capability, origin).expect("origin is transformable");
        let coordinate = transform
            .forward(
                &capability,
                Wgs84PositionV1::new(35.0, -120.0, 100.0).expect("same origin is valid"),
            )
            .expect("origin maps to local zero");
        assert_eq!(coordinate.east_metres().to_bits(), 0.0f64.to_bits());
        assert_eq!(coordinate.north_metres().to_bits(), 0.0f64.to_bits());
        assert_eq!(coordinate.up_metres().to_bits(), 0.0f64.to_bits());
        assert!(
            coordinate
                == transform
                    .forward(
                        &capability,
                        Wgs84PositionV1::new(35.0, -120.0, 100.0).expect("same origin is valid"),
                    )
                    .expect("same input is deterministic")
        );
        assert_eq!(origin.max_radius_metres().to_bits(), 10_000.0f64.to_bits());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn forward_covers_hemispheres_height_antimeridian_and_radius() {
        let capability = capability();
        let equator = WorldOriginV1::new(
            &capability,
            [4; 16],
            [5; 16],
            1,
            Wgs84PositionV1::new(0.0, 179.999, 0.0).expect("valid antimeridian origin"),
            [6; 32],
            10_000.0,
        )
        .expect("origin is valid");
        let transform =
            WorldTransformV1::new(&capability, equator).expect("origin is transformable");
        let east = transform
            .forward(
                &capability,
                Wgs84PositionV1::new(0.0, -179.999, 25.0).expect("valid antimeridian neighbor"),
            )
            .expect("ECEF handles longitude wrap");
        assert!(east.east_metres().is_finite());
        assert!(east.north_metres().is_finite());
        assert!(east.up_metres().is_finite());

        let southern = transform
            .forward(
                &capability,
                Wgs84PositionV1::new(-0.01, 179.999, -25.0).expect("valid southern point"),
            )
            .expect("southern point is in range");
        assert!(southern.north_metres() < 0.0);
        assert!(southern.up_metres() < 0.0);

        let one_metre = WorldOriginV1::new(
            &capability,
            [7; 16],
            [8; 16],
            1,
            Wgs84PositionV1::new(0.0, 0.0, 0.0).expect("valid equator origin"),
            [9; 32],
            1.0,
        )
        .expect("one metre radius is valid");
        let one_metre_transform =
            WorldTransformV1::new(&capability, one_metre).expect("origin is transformable");
        assert!(one_metre_transform
            .forward(
                &capability,
                Wgs84PositionV1::new(0.0, 0.0, 1.0).expect("boundary height is valid"),
            )
            .is_ok());
        assert!(matches!(
            one_metre_transform.forward(
                &capability,
                Wgs84PositionV1::new(0.0, 0.0, 1.1).expect("out-of-radius height is valid"),
            ),
            Err(WorldTransformError::OutOfRadius)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn inverse_round_trip_and_near_pole_policy_are_deterministic() {
        let capability = capability();
        let transform = WorldTransformV1::new(&capability, origin(&capability, 10_000.0))
            .expect("origin is transformable");
        let source =
            Wgs84PositionV1::new(35.001, -119.999, 120.0).expect("round-trip source is valid");
        let coordinate = transform
            .forward(&capability, source)
            .expect("source is in local radius");
        let recovered = transform
            .inverse(&capability, coordinate)
            .expect("forward result is invertible");
        assert!((recovered.latitude_degrees() - source.latitude_degrees()).abs() < 1e-10);
        assert!((recovered.longitude_degrees() - source.longitude_degrees()).abs() < 1e-10);
        assert!(
            (recovered.ellipsoidal_height_metres() - source.ellipsoidal_height_metres()).abs()
                < 1e-4
        );
        assert!(Wgs84PositionV1::new(89.999, -120.0, 0.0).is_ok());
        let too_far = WorldCoordinateV1::from_components(10_000.1, 0.0, 0.0)
            .expect("finite coordinate is valid");
        assert!(matches!(
            transform.inverse(&capability, too_far),
            Err(WorldTransformError::OutOfRadius)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn invalid_radius_digest_and_translation_are_rejected() {
        let capability = capability();
        let position = Wgs84PositionV1::new(35.0, -120.0, 100.0).expect("fixture is valid");
        for radius in [f64::NAN, 0.0, -1.0, 10_000.1] {
            assert!(matches!(
                WorldOriginV1::new(
                    &capability,
                    [31; 16],
                    [32; 16],
                    1,
                    position,
                    [33; 32],
                    radius,
                ),
                Err(WorldTransformError::InvalidRadius)
            ));
        }

        let origin = origin(&capability, 10_000.0);
        let mut invalid_digest = origin;
        invalid_digest.origin_definition_digest[0] ^= 1;
        assert!(matches!(
            WorldTransformV1::new(&capability, invalid_digest),
            Err(WorldTransformError::InvalidOriginDigest)
        ));

        let coordinate =
            WorldCoordinateV1::from_components(1.0, 2.0, 3.0).expect("finite coordinate is valid");
        assert!(matches!(
            coordinate.translated_by(f64::INFINITY, 0.0, 0.0),
            Err(WorldTransformError::NonFiniteCoordinate)
        ));
        assert!(matches!(
            WorldCoordinateV1::from_components(f64::NAN, 0.0, 0.0),
            Err(WorldTransformError::NonFiniteCoordinate)
        ));

        let transform = WorldTransformV1::new(&capability, origin).expect("origin is valid");
        let huge_position =
            Wgs84PositionV1::new(0.0, 0.0, f64::MAX).expect("finite height is accepted");
        assert!(matches!(
            transform.forward(&capability, huge_position),
            Err(WorldTransformError::NonFiniteCoordinate)
        ));
        let huge_coordinate = WorldCoordinateV1::from_components(f64::MAX, 0.0, 0.0)
            .expect("finite coordinate is valid");
        assert!(matches!(
            transform.inverse(&capability, huge_coordinate),
            Err(WorldTransformError::NonFiniteCoordinate)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_identity_accessors_and_registry_fail_closed() {
        let capability = capability();
        let origin = origin(&capability, 10_000.0);
        let reference = origin.reference();
        assert_eq!(origin.world_id(), [1; 16]);
        assert_eq!(origin.origin_id(), [2; 16]);
        assert_eq!(origin.origin_revision(), 1);
        assert_eq!(origin.provenance(), [3; 32]);
        assert_eq!(reference.world_id(), [1; 16]);
        assert_eq!(reference.origin_id(), [2; 16]);
        assert_eq!(reference.origin_revision(), 1);
        assert_eq!(
            reference.origin_definition_digest(),
            origin.origin_definition_digest()
        );

        let mut registry = WorldOriginRegistryV1::default();
        registry
            .register(&capability, origin)
            .expect("origin registers");
        let unavailable = WorldOriginReferenceV1::new([90; 16], [91; 16], 1, [92; 32]);
        assert!(matches!(
            registry.resolve(&capability, &unavailable),
            Err(WorldTransformError::OriginUnavailable)
        ));
        assert!(matches!(
            registry.retire(&capability, &unavailable),
            Err(WorldTransformError::OriginUnavailable)
        ));

        let invalid_digest = WorldOriginReferenceV1::new(
            reference.world_id(),
            reference.origin_id(),
            reference.origin_revision(),
            [93; 32],
        );
        assert!(matches!(
            registry.resolve(&capability, &invalid_digest),
            Err(WorldTransformError::InvalidOriginDigest)
        ));
        assert!(matches!(
            registry.retire(&capability, &invalid_digest),
            Err(WorldTransformError::InvalidOriginDigest)
        ));

        let revision_two = WorldOriginV1::new(
            &capability,
            [94; 16],
            [95; 16],
            2,
            Wgs84PositionV1::new(10.0, 20.0, 0.0).expect("revision two is valid"),
            [96; 32],
            100.0,
        )
        .expect("revision two is valid");
        let revision_one = WorldOriginV1::new(
            &capability,
            [94; 16],
            [95; 16],
            1,
            Wgs84PositionV1::new(10.0, 20.0, 0.0).expect("revision one is valid"),
            [97; 32],
            100.0,
        )
        .expect("revision one is valid");
        assert!(matches!(
            WorldOriginRegistryV1::default().restore(&capability, vec![revision_two, revision_one]),
            Err(WorldTransformError::OriginRevisionConflict)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn inverse_rejects_exact_polar_axis() {
        let capability = capability();
        let polar_origin = WorldOriginV1::new(
            &capability,
            [98; 16],
            [99; 16],
            1,
            Wgs84PositionV1::new(89.999_999, 0.0, 0.0).expect("near-pole origin is valid"),
            [100; 32],
            10_000.0,
        )
        .expect("near-pole origin is valid");
        let transform =
            WorldTransformV1::new(&capability, polar_origin).expect("near-pole transform is valid");
        let dx = -polar_origin.origin_ecef[0];
        let dy = -polar_origin.origin_ecef[1];
        let dz = SEMI_MAJOR_AXIS_METRES * (1.0 - FLATTENING) - polar_origin.origin_ecef[2];
        let (latitude, longitude) = radians(polar_origin.position);
        let polar_coordinate = WorldCoordinateV1::from_components(
            -longitude.sin() * dx + longitude.cos() * dy,
            -latitude.sin() * longitude.cos() * dx - latitude.sin() * longitude.sin() * dy
                + latitude.cos() * dz,
            latitude.cos() * longitude.cos() * dx
                + latitude.cos() * longitude.sin() * dy
                + latitude.sin() * dz,
        )
        .expect("polar coordinate is finite");
        let result = transform.inverse(&capability, polar_coordinate);
        assert!(matches!(result, Err(WorldTransformError::PoleUnsupported)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn defensive_numeric_paths_are_fail_closed() {
        let capability = capability();
        let origin = origin(&capability, 10_000.0);
        let translated = WorldCoordinateV1::from_components(1.0, 2.0, 3.0)
            .expect("finite coordinate is valid")
            .translated_by(4.0, 5.0, 6.0)
            .expect("finite translation is valid");
        assert_eq!(translated.east_metres().to_bits(), 5.0f64.to_bits());
        assert_eq!(translated.north_metres().to_bits(), 7.0f64.to_bits());
        assert_eq!(translated.up_metres().to_bits(), 9.0f64.to_bits());

        let mut overflow_transform =
            WorldTransformV1::new(&capability, origin).expect("fixture transform is valid");
        overflow_transform.origin.origin_ecef = [0.0, 0.0, 0.0];
        overflow_transform.origin_sin_latitude = 0.0;
        overflow_transform.origin_cos_latitude = 1.0;
        overflow_transform.origin_sin_longitude = 0.0;
        overflow_transform.origin_cos_longitude = f64::MAX;
        let boundary_coordinate =
            WorldCoordinateV1::from_components(0.0, 0.0, 10_000.0).expect("coordinate is valid");
        assert!(matches!(
            overflow_transform.inverse(&capability, boundary_coordinate),
            Err(WorldTransformError::NonFiniteCoordinate)
        ));

        let mut infinite_horizontal_transform =
            WorldTransformV1::new(&capability, origin).expect("fixture transform is valid");
        infinite_horizontal_transform.origin.origin_ecef = [f64::MAX, f64::MAX, 0.0];
        let zero_coordinate =
            WorldCoordinateV1::from_components(0.0, 0.0, 0.0).expect("coordinate is valid");
        assert!(matches!(
            infinite_horizontal_transform.inverse(&capability, zero_coordinate),
            Err(WorldTransformError::PoleUnsupported)
        ));

        let mut non_convergent_transform =
            WorldTransformV1::new(&capability, origin).expect("fixture transform is valid");
        non_convergent_transform.origin.origin_ecef = [1.0, 0.0, 1.0];
        assert!(matches!(
            non_convergent_transform.inverse(&capability, zero_coordinate),
            Err(WorldTransformError::NonConvergent)
        ));

        let invalid_position = Wgs84PositionV1 {
            latitude_degrees: f64::NAN,
            longitude_degrees: 0.0,
            ellipsoidal_height_metres: 0.0,
        };
        assert!(matches!(
            geodetic_to_ecef(invalid_position),
            Err(WorldTransformError::NonFiniteCoordinate)
        ));

        let mut overflowing_inverse =
            WorldTransformV1::new(&capability, origin).expect("fixture transform is valid");
        overflowing_inverse.origin.origin_ecef = [f64::MAX, 0.0, f64::MAX];
        assert!(matches!(
            overflowing_inverse.inverse(&capability, zero_coordinate),
            Err(WorldTransformError::NonConvergent)
        ));
        let mut polar_inverse =
            WorldTransformV1::new(&capability, origin).expect("fixture transform is valid");
        polar_inverse.origin.origin_ecef = [1.0, 0.0, f64::MAX];
        assert!(matches!(
            polar_inverse.inverse(&capability, zero_coordinate),
            Err(WorldTransformError::PoleUnsupported)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn origin_registry_rejects_duplicates_and_restores_atomically() {
        let capability = capability();
        let first = origin(&capability, 10_000.0);
        let reference = first.reference();
        let mut registry = WorldOriginRegistryV1::new();
        registry
            .register(&capability, first)
            .expect("first origin registers");
        assert!(registry.resolve(&capability, &reference).is_ok());
        assert!(matches!(
            registry.register(&capability, first),
            Err(WorldTransformError::DuplicateOrigin)
        ));
        let older = WorldOriginV1::new(
            &capability,
            [1; 16],
            [2; 16],
            0,
            Wgs84PositionV1::new(35.0, -120.0, 100.0).expect("older origin is valid"),
            [3; 32],
            10_000.0,
        )
        .expect("older origin is valid");
        assert!(matches!(
            registry.register(&capability, older),
            Err(WorldTransformError::OriginRevisionConflict)
        ));
        registry
            .retire(&capability, &reference)
            .expect("retirement is authorized");
        assert!(matches!(
            registry.resolve(&capability, &reference),
            Err(WorldTransformError::OriginRetired)
        ));

        let second = WorldOriginV1::new(
            &capability,
            [10; 16],
            [11; 16],
            1,
            Wgs84PositionV1::new(-20.0, 30.0, 0.0).expect("second origin is valid"),
            [12; 32],
            500.0,
        )
        .expect("second origin is valid");
        assert!(matches!(
            registry.restore(&capability, vec![second, second]),
            Err(WorldTransformError::DuplicateOrigin)
        ));
        assert!(matches!(
            registry.resolve(&capability, &reference),
            Err(WorldTransformError::OriginRetired)
        ));
        registry
            .restore(&capability, vec![second])
            .expect("valid restore replaces the registry");
        assert!(registry.resolve(&capability, &second.reference()).is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn south_pole_and_non_finite_height_are_rejected() {
        // Negative pole: first || branch of the PoleUnsupported check.
        assert!(matches!(
            Wgs84PositionV1::new(-90.0, 0.0, 0.0),
            Err(WorldTransformError::PoleUnsupported)
        ));
        // Non-finite height: third || branch of the NonFiniteCoordinate check.
        assert!(matches!(
            Wgs84PositionV1::new(0.0, 0.0, f64::NAN),
            Err(WorldTransformError::NonFiniteCoordinate)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn coordinate_from_non_finite_north_or_up_is_rejected() {
        // Second || branch of the NonFiniteCoordinate check in from_components.
        assert!(matches!(
            WorldCoordinateV1::from_components(0.0, f64::NAN, 0.0),
            Err(WorldTransformError::NonFiniteCoordinate)
        ));
        // Third || branch.
        assert!(matches!(
            WorldCoordinateV1::from_components(0.0, 0.0, f64::NAN),
            Err(WorldTransformError::NonFiniteCoordinate)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn translation_rejects_non_finite_north_or_up_offset() {
        let coord = WorldCoordinateV1::from_components(0.0, 0.0, 0.0).expect("origin is finite");
        assert!(matches!(
            coord.translated_by(0.0, f64::NAN, 0.0),
            Err(WorldTransformError::NonFiniteCoordinate)
        ));
        assert!(matches!(
            coord.translated_by(0.0, 0.0, f64::NAN),
            Err(WorldTransformError::NonFiniteCoordinate)
        ));
    }
}
