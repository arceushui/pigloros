# Bevy World Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the accepted ADR-018 fixture-backed walkable Bevy client with shared Rust reducer projection, WebGL2 WASM/native shells, and native/browser parity tests.

**Architecture:** Add `apps/piglor-world-client` as a Bevy `=0.19.0` app with a pure library boundary. The library decodes a fixed `TimelineExport`, folds complete `Event` values through `pos-state::ProjectionRegistry` with the existing society reducer, and returns a stable `ProjectionDigest`; the Bevy shell renders one landmark and owns camera/input/window behavior. The first slice makes no HTTP request and does not depend on `pos-store`.

**Tech Stack:** Rust workspace, Bevy `=0.19.0` (explicit `3d` rendering/app composition + `x11` + `webgl2`, no Wayland or `webgpu`), `pos-core`, `pos-state`, `pos-plugin-society`, `ciborium`, `blake3`, `wasm-bindgen`, `wasm-bindgen-test`, `wasm-pack`, headless Chrome.

## Global Constraints

- Work only in `/root/pigloros-ticket-115-3d-world-client` on `ticket-115-3d-world-client`; preserve the separate #169 worktree.
- Do not add `pos-store`, SQLite, browser HTTP, EventView protocol changes, Gateway routes, Event schemas, migrations, backfills, dual-writes, auth capabilities, physics, or presence.
- Pin Bevy `=0.19.0`; compose the accepted 3D app explicitly with X11/WebGL2 so the broad `3d` convenience feature cannot pull unsupported Wayland. Do not select `webgpu` or ignore dependency advisories.
- Every production behavior starts with a failing test; run the focused test after each red/green cycle.
- Do not use production `coverage(off)`; all new production branches need tests and the workspace floor remains at least 99% lines and regions.
- Use shared `CARGO_TARGET_DIR=/root/pigloros/target` to avoid duplicate Rust artifacts and disk exhaustion.
- Stage only changed files; never use `git add -A`.

---

### Task 1: Add the deterministic fixture boundary

**Files:** Modify `Cargo.toml`. Create `apps/piglor-world-client/Cargo.toml`, `src/lib.rs`, and `src/fixture.rs`. Test fixture behavior in `src/fixture.rs`.

**Interfaces:** `fixture_bytes() -> Vec<u8>` encodes a root `TimelineExport` with fixed ULIDs, head sequence 2, and two complete `society.signal` Events for one fixed entity, with values `0.5` and `1.0`. `decode_fixture(&[u8]) -> Result<TimelineExport, ClientError>` decodes and validates the timeline identity, root mode, complete Event fields, entity, event type, contiguous sequences, and payload hashes.

- [ ] Write failing tests for byte determinism, complete Event field preservation, round-trip identity, malformed CBOR, wrong identity, wrong event type, and non-contiguous sequences.
- [ ] Run `CARGO_TARGET_DIR=/root/pigloros/target cargo test -p piglor-world-client fixture --locked`; verify it fails because the package/API is absent.
- [ ] Add the package and minimal fixture implementation. Use `Ulid::from(1u128)`, `Ulid::from(2u128)`, and `Ulid::from(3u128)` for stable IDs, BLAKE3 payload hashes, and CBOR `TimelineExport` encoding.
- [ ] Rerun the focused fixture tests and verify they pass.
- [ ] Commit with `git add Cargo.toml apps/piglor-world-client/Cargo.toml apps/piglor-world-client/src/lib.rs apps/piglor-world-client/src/fixture.rs && git commit -m "feat: add deterministic world client fixture"`.

### Task 2: Fold through shared reducers and define the digest

**Files:** Create `apps/piglor-world-client/src/projection.rs` and `tests/wasm_parity.rs`. Modify `src/lib.rs`.

**Interfaces:** Define `ProjectionDigest { signals: u64, trust_mean_bits: u64, landmark_x_bits: u64 }`, `project_fixture(&TimelineExport) -> Result<ProjectionDigest, ClientError>`, `ProjectionDigest::landmark_x() -> f32`, and `ProjectionDigest::digest_bytes() -> [u8; 32]`. Register `SocietyReducer` in `ProjectionRegistry`, fold Events in sequence order, read `signals` and `mean.trust` for the fixed entity, and project `landmark_x = trust_mean * 4.0 - 2.0`.

- [ ] Write a failing test expecting two signals, `0.75f64.to_bits()`, `1.0f64.to_bits()`, and a fixed digest byte array.
- [ ] Run `CARGO_TARGET_DIR=/root/pigloros/target cargo test -p piglor-world-client projection --locked`; verify the missing API failure.
- [ ] Implement the reducer projection, finite/range checks, deterministic digest byte layout, and typed errors with the smallest production surface.
- [ ] Rerun focused tests and add native/browser parity tests using the same `fixture_bytes()` → `decode_fixture()` → `project_fixture()` path. Under WASM, call `wasm_bindgen_test_configure!(run_in_browser)` and use `#[wasm_bindgen_test]`; native uses `#[test]`.
- [ ] Run `CARGO_TARGET_DIR=/root/pigloros/target cargo test -p piglor-world-client --locked` and commit `feat: project world fixture through shared reducers`.

### Task 3: Add the thin Bevy shell

**Files:** Create `src/shell.rs`, `src/main.rs`, and `index.html`. Modify `src/lib.rs`.

**Interfaces:** `build_app(ProjectionDigest) -> bevy::app::App`, `run_native() -> Result<(), ClientError>`, and a WASM `#[wasm_bindgen(start)]` entry that uses the same fixture/project path. Use Bevy 0.19 `DefaultPlugins`, `Window { fit_canvas_to_parent: true }`, `CursorOptions`, `CursorGrabMode::Locked`, `AccumulatedMouseMotion`, `ButtonInput<KeyCode>`, `Camera3d`, `Mesh3d`, `MeshMaterial3d`, `Cuboid`, and `DirectionalLight`.

- [ ] Write failing pure helper tests for movement vectors, zero input, pitch clamp, mouse delta, left-click cursor grab, and Escape cursor release.
- [ ] Run the focused shell test; verify the expected missing-helper failure.
- [ ] Implement pure helpers and systems for camera setup, floor/light/landmark setup, WASD movement, mouse look, and cursor grab/release. Keep platform/window code in the shell only and derive landmark position solely from `ProjectionDigest`.
- [ ] Run `CARGO_TARGET_DIR=/root/pigloros/target cargo test -p piglor-world-client --locked` and `cargo check -p piglor-world-client --locked`.
- [ ] Add `index.html` with a `#piglor-world` canvas and `wasm-pack --target web` module loader; commit `feat: add walkable Bevy world shell`.

### Task 4: Add WASM packaging and CI checks

**Files:** Create `scripts/check-world-client-wasm.sh`. Modify `.github/workflows/ci.yml` and `README.md`.

**Interfaces:** The script must run `cargo check -p piglor-world-client --target wasm32-unknown-unknown --locked --no-default-features`, `wasm-pack build apps/piglor-world-client --target web --release -- --locked`, and `wasm-pack test --headless --chrome apps/piglor-world-client --locked --no-default-features --test wasm_parity`. The browser flags precede the crate path because `wasm-pack` 0.15 treats the path and all following tokens as Cargo arguments. The focused browser command runs only the reducer parity integration target without the optional Bevy runtime; the preceding optimized web build separately compiles the complete Bevy/WebGL2 shell. The script defaults to `all` locally and exposes `package` and `browser` modes so required CI jobs `world-client-wasm` and `world-client-browser-parity` run on independent fresh runners. Both use Rust 1.97.1 and install the WASM target/tool; the browser job additionally installs pinned Chrome/ChromeDriver.

- [ ] Write a failing shell-contract test checking the WASM target, WebGL2 package path, and Chrome headless invocation.
- [ ] Run it and verify the script/job are absent.
- [ ] Add the script, pinned-action CI job, and README native/WASM instructions. Keep the job additive and do not add Gateway integration.
- [ ] Run the script locally; install the pinned tool only if unavailable, then rerun it.
- [ ] Commit `ci: verify world client wasm browser build`.

### Task 5: Verify, review, publish, and close

- [ ] Run focused tests, `cargo run -p piglor-world-client --release --locked`, the WASM script, and capability-dropped `scripts/ci.sh`; record test count and 99% line/region coverage.
- [ ] Run `git diff --check` and confirm no `pos-store`, Gateway route, Event schema, migration, or `webgpu` selection entered the branch.
- [ ] Run the `code-review` skill against the branch diff; address findings in a separate test/commit cycle.
- [ ] Request final fresh `gpt-5.6-sol` code review and require APPROVE.
- [ ] Rebase onto current `origin/main`, rerun all gates, push `ticket-115-3d-world-client`, open a draft PR, and wait for every required remote check.
- [ ] Merge only after all checks pass; verify `origin/main`, journal the evidence, set #115 Resolved/100% only when the accepted slice is integrated, and remove only this clean merged worktree.
