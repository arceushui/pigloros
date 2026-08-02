# WGS84-to-World ENU Implementation Plan

> For agentic workers: REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

Goal: Implement the Accepted ADR-032 static epochless WGS 84 -> ECEF -> local ENU port, its immutable in-memory origin registry, and the additive coordinate-aware SimpleKinematic adapter for #143.

Architecture: Put the deep numerical and authority module in pos-core; keep geographic evidence opaque and capability-gated, with no generic serialization or persistence. Let pos-plugin-world consume WorldCoordinateV1 through a small additive adapter so geodesy remains behind the core seam.

Tech Stack: Rust 1.97, pos-core, pos-plugin-world, BLAKE3, fixed f64 arithmetic, existing workspace tests/Clippy/LLVM coverage.

## Global Constraints

- Use ADR-032 v10's fixed WGS 84 ellipsoid constants a = 6378137 and inverse flattening 298.257223563.
- Use strict latitude (-90, 90), normalized longitude [-180, 180), ellipsoidal height metres, East/North/Up metre axes, and exact-pole rejection.
- Accept the inclusive Euclidean local radius boundary and require finite positive max_radius_metres <= 10_000.
- Perform exactly 16 inverse Newton-style updates and enforce ADR-032's convergence/residual tolerances.
- Do not add a database migration, Timeline payload, generic serializer/exporter, public inverse route, network/GIS dependency, H3/S2 selection, dynamic datum/epoch, or raw-coordinate logging.
- Run the complete capability-dropped repository gates after every implementation change.

---

### Task 1: Commit the accepted implementation design

Files:
- Create: docs/superpowers/specs/2026-08-02-wgs84-world-enu-implementation-design.md
- Create: docs/superpowers/plans/2026-08-02-wgs84-world-enu-implementation.md

- [x] Step 1: Record the accepted seam and scope

The design file records the core module seam, opaque evidence policy, additive
world adapter, rejected alternatives, and verification matrix. This plan is the
task-by-task execution contract.

- [x] Step 2: Commit the design and plan

    git add docs/superpowers/specs/2026-08-02-wgs84-world-enu-implementation-design.md docs/superpowers/plans/2026-08-02-wgs84-world-enu-implementation.md
    git commit -m "docs: plan WGS84 world ENU transform"

### Task 2: Add RED core transform contracts

Files:
- Create: crates/pos-core/src/world_transform.rs
- Modify: crates/pos-core/src/lib.rs
- Modify: crates/pos-core/Cargo.toml

Interfaces:
- Wgs84PositionV1::new(latitude_degrees, longitude_degrees, ellipsoidal_height_metres) and named getters.
- WorldGeographicEvidenceCapabilityV1::for_trusted_core().
- WorldOriginV1::new(capability, world_id, origin_id, revision, position, provenance, max_radius_metres).
- WorldTransformV1::new(capability, origin) plus forward and inverse.
- WorldTransformError typed classifications.

- [ ] Step 1: Write the failing tests

Add tests that call the intended public interface for: equatorial origin,
hemisphere/height fixtures, antimeridian neighbors, exact and near poles,
non-finite/out-of-range values, radius == and > boundaries, deterministic
repeated forward results, fixed digest bytes, and forward/inverse round trips.

- [ ] Step 2: Run the focused tests to verify RED

    cargo test -p pos-core world_transform --lib

Expected: compilation/test failure because the transform module and its public
types do not yet exist.

- [ ] Step 3: Add the module declaration and BLAKE3 dependency

Add pub mod world_transform and re-export the named transform, origin, registry,
capability, coordinate, and error types from pos-core. Add blake3 = { workspace
= true } to crates/pos-core/Cargo.toml.

### Task 3: Implement the core transform and registry

Files:
- Modify: crates/pos-core/src/world_transform.rs

- [ ] Step 1: Implement validation and opaque named values

Keep coordinate-bearing fields private; validate finite values and strict pole
policy at construction; normalize longitude to the half-open interval and expose
only named scalar accessors and non-disclosing identity/digest accessors.

- [ ] Step 2: Implement fixed forward ECEF -> ENU conversion

Use the ADR-032 constants and operation order, subtract the precomputed origin
ECEF point, compute East/North/Up, reject non-finite intermediates, and enforce
the inclusive Euclidean radius.

- [ ] Step 3: Implement fixed 16-step inverse conversion

Use the transposed ENU rotation, atan2, exactly 16 Newton-style updates, latitude
convergence and ECEF residual checks, then return a validated Wgs84PositionV1 or
a typed non-convergence/pole error.

- [ ] Step 4: Implement digest and registry authority

Hash the exact ADR-032 domain separator, version byte, IDs, revision, canonical
binary64 values, constants, algorithm tag, axes, and units. Make registration,
reference resolution, retirement, and restore fail closed; restore validates a
candidate set before replacing the current map.

- [ ] Step 5: Run focused core tests

    cargo fmt --all -- --check
    cargo test -p pos-core world_transform --lib
    cargo clippy -p pos-core --all-targets --all-features -- -D warnings -W clippy::pedantic

Expected: all transform, digest, registry, and error-path tests pass.

### Task 4: Add the coordinate-aware world adapter

Files:
- Modify: plugins/world/src/lib.rs

Interfaces:
- WorldCoordinateBody::new(entity_id, position, east_velocity_mps, north_velocity_mps, up_velocity_mps).
- WorldCoordinateObservation named position accessors.
- SimpleKinematicBackend::step_coordinates(&[WorldCoordinateBody]).

- [ ] Step 1: Write the failing adapter test

Construct a coordinate body from a core transform result and assert the simple
backend advances East/North/Up using only named coordinate arithmetic, while the
existing two-dimensional backend tests remain unchanged.

- [ ] Step 2: Run the adapter test to verify RED

    cargo test -p pos-plugin-world coordinate --lib

Expected: compilation failure because the additive coordinate adapter does not
yet exist.

- [ ] Step 3: Implement the additive coordinate adapter

Use WorldCoordinateV1::translated_by; do not duplicate ellipsoid constants,
latitude/longitude handling, ECEF conversion, or radius policy in the plugin.

- [ ] Step 4: Run focused adapter checks

    cargo fmt --all -- --check
    cargo test -p pos-plugin-world --lib
    cargo clippy -p pos-plugin-world --all-targets --all-features -- -D warnings -W clippy::pedantic

### Task 5: Final verification and integration review

Files:
- Modify only files needed for verified implementation or factual documentation.

- [ ] Step 1: Run the exact capability-dropped repository gates

    capsh --drop=cap_dac_override,cap_dac_read_search -- -c './scripts/ci.sh'

Expected: policy, pinned dependencies, format, full tests including ignored
tests/doctests, Clippy, LLVM coverage, and the repository's final gate pass.

- [ ] Step 2: Record each implementation/test checkpoint in Redmine #143 and the Notion work journal

Include commit IDs, focused test results, final CI coverage, and any remaining
review state. Tag the user in Notion only if the goal becomes genuinely blocked.

- [ ] Step 3: Request CTO review and address findings

Review the complete diff against ADR-032 and the acceptance criteria. Do not
publish until the CTO returns APPROVE and all quality gates are green.

- [ ] Step 4: Rebase, publish, merge, and verify origin/main

Rebase ticket-143-wgs84 onto the latest origin/main, rerun the required gates,
publish through the GitHub workflow, merge only after remote checks pass, then
verify the merged SHA and update Redmine/Notion.
