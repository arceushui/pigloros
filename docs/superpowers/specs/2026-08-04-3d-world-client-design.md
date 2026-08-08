# ADR-018 Bevy World Client — Approved Thin-Slice Design

**Redmine:** #115

**Canonical decision:** ADR-018 version 7, Accepted

**CTO gate:** fresh `gpt-5.6-sol` review, APPROVE

## Goal

Add the smallest walkable, game-like 3D client that proves PiglorOS can render a deterministic projection of the same Rust event/reducer model used by the server.

## Hard boundaries

- Pin Bevy to `=0.19.0` with `3d` and `webgl2` features. Do not enable `webgpu`.
- Use complete, fixed `pos_core::TimelineExport`/`Event` values as the first-slice fixture. Do not consume the gateway JSON `EventView`, because it omits fields required to reconstruct `pos_core::Event`.
- Keep fold/projection logic pure Rust and shared with the existing `pos-core`/`pos-state`/plugin reducer boundary. The browser must not open `pos-store` or any database.
- Do not add browser HTTP, a public spectator-router route, a new Event type, Timeline schema, migration, backfill, dual-write, gateway write route, authentication capability, physics backend, or presence protocol.
- Gateway read integration is a separate future protocol/auth decision.

## Architecture

The new app is split into a testable library and a thin Bevy platform shell:

```text
fixed TimelineExport fixture
        |
        v
pure fixture adapter -> shared reducer registry -> ProjectionDigest
        |                         |
        |                         +--> native/headless test
        +------------------------+--> wasm-bindgen browser test
        |
        +--> Bevy ECS shell -> WebGL2 WASM canvas/native window
```

The fixture adapter owns construction/validation of the complete Event values and provides a deterministic sequence to the reducer registry. The projection maps one selected domain signal to a stable landmark/geometry value. The Bevy shell consumes the projection and owns only camera, movement, pointer lock, input, scene setup, and rendering. No platform API is used by the reducer or projection modules.

The browser test and native test call the same pure projection function with the same fixture bytes and assert one stable digest. This proves cross-target domain/projection parity; it does not claim that gateway transport is implemented.

## Initial user-visible slice

- Native and WASM app entry points.
- First-person camera.
- WASD movement and pointer-lock input.
- One bounded scene with a landmark whose geometry/value is derived from the deterministic projection.
- A small loading/error state for invalid fixture data or unavailable render setup.
- No human action submission.

## Testing and gates

The implementation is test-first. Each pure fixture/reducer/projection behavior gets a failing native test before production code. The browser parity test uses `wasm_bindgen_test_configure!(run_in_browser)` and runs through Chrome rather than Node.

Required commands:

```text
cargo test -p piglor-world-client --locked
cargo run -p piglor-world-client --release --locked
cargo check -p piglor-world-client --target wasm32-unknown-unknown --locked --no-default-features
wasm-pack build apps/piglor-world-client --target web --release -- --locked
wasm-pack test --headless --chrome apps/piglor-world-client --locked --no-default-features --test wasm_parity
scripts/ci.sh
```

The repository remains at least 99% line and region coverage, with no production coverage exemptions. Existing workspace `--all-features` CI remains authoritative; the client dependency does not expose a WebGPU feature, so `--all-features` cannot select it.

## Rollback

Remove/disable the standalone client app and artifact. No persisted data or existing gateway route changes, so rollback requires no migration or backfill.
