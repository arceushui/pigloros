# WGS84-to-World ENU Implementation Design

Redmine: #143
Authority: Accepted ADR-032, version 10
Status: Implementation design authorized

## Goal

Implement the accepted V1 coordinate seam: validated static, epochless WGS 84
positions become named local East/North/Up metre coordinates through the fixed
WGS 84 ellipsoid -> ECEF -> origin-relative ENU operation. The inverse exists
for core-owned conformance and replay. SimpleKinematicBackend consumes the named
coordinate value without knowing geodesy.

## Chosen module boundary

The deep module lives in crates/pos-core/src/world_transform.rs. Its small
interface owns validation, fixed numerical ordering, the 10 km inclusive radius
policy, digest computation, and the in-memory immutable origin registry. The
world plugin receives WorldCoordinateV1 values and performs only coordinate
arithmetic; it does not import ellipsoid constants or implement a projection.

The module exposes named accessors but deliberately does not implement generic
Debug, Display, Serialize, or Deserialize for geographic evidence, origins,
coordinates, or inverse results. Error messages expose only bounded typed
classifications. The core-owned capability token is required by origin
registration and transform operations; the trusted composition root is the only
intended minting site.

## Interface

- Wgs84PositionV1: finite latitude in (-90, 90) degrees, finite ellipsoidal
  height in metres, and longitude canonicalized to [-180, 180).
- WorldOriginV1: opaque world/origin IDs, immutable revision, validated origin,
  opaque provenance, finite positive radius no greater than 10,000 metres, and
  the normative BLAKE3 definition digest.
- WorldCoordinateV1: named east/north/up metre values with finite checked
  translation for the kinematic adapter.
- WorldTransformV1::forward and ::inverse: capability-gated deterministic
  conversion with typed failures for non-finite values, unsupported poles,
  out-of-radius values, and inverse non-convergence.
- WorldOriginRegistryV1: in-memory registration, exact reference resolution,
  retirement, and atomic restore; no database or generic persistence is added.
- WorldCoordinateBody and SimpleKinematicBackend::step_coordinates: the
  world-plugin seam consumes named coordinates and velocity components without
  embedding WGS 84 or ECEF/ENU logic.

## Numerical and policy invariants

The implementation follows ADR-032's exact constants, operation order, fixed
binary64 pi literal, longitude normalization, strict pole rejection, inclusive
Euclidean radius, exactly 16 inverse updates, residual checks, digest byte
layout, and stated forward/round-trip tolerances. Existing two-dimensional
Body/WorldObservation APIs remain intact for the Wave 5 compatibility path; the
coordinate-aware adapter is additive.

## Alternatives rejected

1. Putting the transform in plugins/world would let another consumer repeat
   geodesy and would make the core-owned geographic-evidence seam shallow.
2. Using Web Mercator or direct degree axes would not provide the accepted local
   metric 3D physics contract.
3. Adding SQLite or Timeline persistence now would violate ADR-032's V1
   transient-evidence and no-migration decision.

## Verification boundary

RED tests will cover origin, both hemispheres, height, antimeridian neighbors,
near-pole policy, invalid inputs, deterministic output and digest, radius
boundaries, inverse round trips, registry atomicity/retirement, and the
coordinate-aware backend. The final gate is the capability-dropped repository
CI plus focused core/world tests, formatting, pedantic Clippy, and CTO review.
