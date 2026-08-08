# ADR-018 Bevy World Client — Approved Thin-Slice Design

**Redmine:** #115

**Canonical decision:** ADR-018 version 27, Accepted

**CTO gate:** fresh `gpt-5.6-sol` review, APPROVE

## Goal

Add the smallest walkable, game-like 3D client that proves PiglorOS can render a deterministic projection of the same Rust event/reducer model used by the server.

## Hard boundaries

- Pin Bevy to `=0.19.0` with the `3d` feature's rendering/app composition expressed explicitly, plus `webgl2` and the X11 native smoke backend. Do not enable `webgpu` or the unsupported Wayland backend.
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

The convenience `3d` feature is not selected directly because Bevy 0.19 couples it to `default_platform`, which enables both X11 and Wayland. The product target is WebGL2 and the native verification target is X11; retaining Wayland would add an unmaintained `ttf-parser` chain (`RUSTSEC-2026-0192`) and require native Wayland development packages in every Rust CI job. The manifest therefore selects `3d_bevy_render`, `default_app`, `scene`, `picking`, the required runtime facilities, `bevy_winit`, `x11`, and `webgl2` explicitly. This changes neither the 3D shell nor the accepted browser scope. The dependency policy permits the SPDX `MIT-0` license used by Bevy's `encase` crates; advisory enforcement remains unchanged and no advisory is ignored.

Remote CI runs the optimized full-shell package and the real-Chrome parity test as independent required jobs. The first combined run showed the package succeeding before the browser session failed, so a fresh browser-parity runner isolates that lightweight test from the full Bevy optimizer. Follow-up logs on the fresh runner identified the remaining cause: setup-chrome installs a binary whose name is not stable, while wasm-bindgen reported that `webdriver.json` was absent and ChromeDriver returned HTTP 404. CI therefore passes setup-chrome's `chrome-path` output to wasm-bindgen as `goog:chromeOptions.binary` through `WASM_BINDGEN_TEST_WEBDRIVER_JSON`. The local script's default `all` mode continues to run both stages sequentially; neither required gate is waived.

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

Native unit and coverage jobs execute the public builder and runner without
requiring hosted-runner GPU hardware. Under `cfg(test)`, the client retains
Bevy `DefaultPlugins` but uses Bevy's documented no-renderer configuration
(`WgpuSettings { backends: None }`), disables Winit, and installs a terminating
test runner. No test is ignored and no production line is excluded from
coverage. The optimized WASM package compiles the full production renderer;
the separate browser-parity job exercises the client contract in real Chrome.

The full-workspace ASan job keeps its complete `--all-features --workspace
--tests` scope and address-sanitizer instrumentation. Because ASan with
`build-std` creates unusually large native links, Cargo build/link concurrency
is fixed at one on hosted runners. This mitigates the observed concurrent lld
`SIGBUS` by reducing peak link pressure; a fresh remote ASan run must prove the
checkpoint. It is a throughput control, not a test waiver. A parsed-YAML policy
check and adversarial fixtures verify serialization, unconditional failure
semantics, exact effective environment and command structure, sanitizer
instrumentation, unchanged test scope, and the exact pinned setup-step/job
graph. The final test step accepts only its exact `name`, `env`, and `run`
fields, so no prerequisite, environment-writing step, custom working directory,
or nested Cargo configuration can bypass execution.

Serialization alone did not resolve the failure: the floating 2026-08-07
nightly (`rustc 1.99.0-nightly`) crashed one isolated lld link with the same
`SIGBUS`. The ASan gate therefore pins `nightly-2026-07-01` (Rust 1.98 nightly)
and uses a toolchain-specific cache key. This makes the unstable sanitizer
toolchain reproducible and avoids silently adopting the observed crashing
linker. The full command, scope, sanitizer flags, and serial execution remain
unchanged apart from the dated toolchain selector, and fresh remote success is
required.

The dated candidate exposed the definitive hosted-runner cause: its check
annotation reported `No space left on device`. The ASan step therefore disables
incremental artifacts and selects `line-tables-only` for the Cargo test profile.
The pinned toolchain action already exported `CARGO_INCREMENTAL=0` in the failed
run; declaring it in the step only policy-locks that existing behavior. The new
storage-reduction candidate is `line-tables-only`, which preserves filename/line
backtraces while removing full type/variable debug metadata. Sanitizer flags,
debug assertions, packages, features, test targets, and execution scope remain
unchanged; fresh remote success is required.

## Rollback

Remove/disable the standalone client app and artifact. No persisted data or existing gateway route changes, so rollback requires no migration or backfill.
