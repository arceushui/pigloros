# PiglorOS

A simulation world you join to preview your decisions.

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/arceushui/pigloros)

> **Current stage:** Pre-product. The product MVP is not shipped yet. Wave 9 is the acceptance target: an independently built third-party client — with the first reference acceptance client being a real 3D client — must operate PiglorOS through documented Gateway contracts, using its own preferences/options and Timeline/Scenario Room inputs, receiving a decision preview, submitting actions, reading committed Events, and exercising Replay/Fork. The current Gateway is only a local-first foundation; its default process has create/poll routes but no authenticated action principal, and the public decision-preview, Replay/Fork, and live 3D contracts remain planned. The old hard-coded `pos-mvp` decision demo was removed and is not counted as an MVP. **Prediction Ledger** is already delivered (#58: public page, TOML curated tier + EventStore live tier, CLI, gateway write route, Docker/CI/CD).

## Getting started

```bash
set -euo pipefail

# Start the local Gateway foundation
cargo run -p piglor-gateway --locked -- serve 127.0.0.1:8080

# Current foundation smoke test: create and poll
timeline_id="$(curl -sS -X POST http://127.0.0.1:8080/v1/timelines \
  -H 'content-type: application/json' \
  -d '{"name":"client-owned-room"}' | jq -r '.id')"
test -n "$timeline_id" && test "$timeline_id" != "null"
curl -sS "http://127.0.0.1:8080/v1/timelines/$timeline_id/events?from_seq=0&limit=100"

# The action route requires an authenticated principal and capability; the
# default local process intentionally fails closed. This smoke test is not the product client.

# Optional: durable store + experiment via the CLI (`pos` binary)
cargo run -p pos-cli --locked -- store init --path /tmp/piglor.db
cargo run -p pos-cli --locked -- --help

# Prediction Ledger CLI (ADR-017 / #58) — create and verify predictions
mkdir -m 700 .secrets
cargo run -p piglor-ledger --locked -- keygen --out ./.secrets/ledger.key
ledger_source="$(mktemp -d)"
cargo run -p piglor-ledger --locked -- predict --source "toml:$ledger_source" \
  --title "My prediction" --statement "..." --predicted-outcome Yes \
  --confidence 0.7 --made-at "2026-07-28T12:00:00Z" --resolve-by 2026-12-31 \
  --osf https://osf.io/xxxxx

# Docker deployment (gateway; no predictions are bundled)
docker compose up -d
curl http://localhost:8080/health
curl http://localhost:8080/v1/ledger

# Engineering-only fixture shell (not the product MVP; it is not Gateway-backed)
CARGO_TARGET_DIR=/root/pigloros/target cargo run -p piglor-world-client --release --locked

# Engineering-only fixture shell (WASM build + headless Chrome test)
CARGO_TARGET_DIR=/root/pigloros/target bash scripts/check-world-client-wasm.sh
```

`piglor-ledger keygen` is supported on Unix platforms, where it creates a
new owner-only key file and durably synchronizes both the file and containing
directory. It refuses existing outputs, symlinks, unsafe directory permissions,
and non-Unix platforms instead of weakening protection. Create the containing
directory with private permissions first (for example, `mkdir -m 700 .secrets`).
The command warns that the output must remain outside version control; verify
the chosen path explicitly with `git check-ignore -- .secrets/ledger.key`.

Ancestor checks and path-based file creation cannot be one atomic operation
using safe standard-library APIs. Keep the key in a stable private directory;
the final filename itself is protected atomically with create-new semantics.

Requires the pinned toolchain in `rust-toolchain.toml` (Rust **1.97.1**).

```bash
# One-time per clone — enable the versioned pre-commit hook
# (fmt, rust-test-policy, lockfile generation, and targeted Clippy):
git config core.hooksPath .githooks
```

## Repository Layout

```
pigloros/
  Cargo.toml              # workspace root
  crates/
    pos-core/             # Wave 1 ✅ — five kernel primitives (no I/O, no async)
    pos-crypto/           # Wave 1 ✅ — BLAKE3 + Ed25519 + canonical CBOR
    pos-store/            # Wave 1 ✅ — EventStore trait + SQLite WAL + in-memory
    pos-state/            # Wave 2 ✅ — ProjectionRegistry, fold layer
    pos-time/             # Wave 2 ✅ — replay, snapshot, fork compare, merge
    pos-query/            # Wave 2 ✅ — EventQuery builder, traversal
    pos-runtime/          # Wave 3 ✅ — plugin host: SchemaRegistry, Driver, Recorder
  apps/
    pos-experiment/       # Wave 4 ✅ — experiment host: tick loop, StopCondition, Fork, library backtest
    pos-cli/              # Wave 4/5 ✅ — pos binary: store, timeline, experiment, merge
    piglor-gateway/       # Wave 6 ✅ — local-first HTTP gateway (ADR-014 / #69)
    piglor-ledger/         # Wave 4 ✅ — Prediction Ledger CLI + static renderer (ADR-017 / #58)
    piglor-world-client/  # Engineering-only 3D fixture shell; not Gateway-backed MVP evidence
  plugins/
    entities/rule-agent/  # Wave 4 ✅ — deterministic rule-based agent plugin
    observations/synthetic/ # Wave 4 ✅ — synthetic sin-wave observation plugin
    persona/              # Wave 5 ✅ — PersonaModel + PersonaEvalDriver (closes eval loop)
    world/                # Wave 5 ✅ — WorldBackend + SimpleKinematic (rapier deferred)
    agent/                # Wave 5 ✅ — AgentPolicy + RoundRobin/RandomSeed (no LLM yet)
    geo/                  # Wave 5 ✅ — SpatialCloaker degree-grid cloaking (not H3)
    bridges/              # Wave 6+ ✅ — BridgeIngestor + minimized OwnTracks observations (ADR-026 / #60); gateway owns opt-in loopback HTTP ingress; MQTT/public ingress deferred
    eval/                 # Wave 5 ✅ — compute_report → CalibrationReport (Brier/ECE/lift)
    society/              # Wave 6 ✅ — SocietySignal + SocietyReducer (trust/opinion/… metrics)
    ledger/               # Wave 4 ✅ — Prediction Ledger domain, port, adapters (ADR-017 / #58)
```

Wave 6 will add `bindings/piglor-py` (PyO3); that directory is not in-tree yet.

## Wave Roadmap

| Wave | Description | Status |
|---|---|---|
| Wave 0 | Tracer Bullet — validate prediction baseline | Deferred |
| Wave 1 | Kernel Primitives (pos-core, pos-crypto, pos-store) | ✅ Complete |
| Wave 2 | Temporal Engine (replay, fork, merge) | ✅ Complete |
| Wave 3 | Plugin Runtime (pos-runtime) | ✅ Complete |
| Wave 4 | Experiment Framework + CLI (pos-experiment, pos-cli) | ✅ Complete |
| Wave 5 | Moat Plugins + Validation Foundation | ✅ Complete — plugin seams and calibration infrastructure; no product MVP claim |
| Wave 6 | Shared World & Social Foundation | ✅ Foundation done — #87 #71 #69; Prediction Ledger delivered (#58); auth/WS/PyO3/client/#72–74 deferred |
| Wave 7 | Hard-coded Contextual Decision Demo | Retired — `pos-mvp` was removed and never counted as the MVP |
| Wave 8 | Simulation Engine & Consent Foundation | 🔄 Current foundation gate — ADR-057 / #171 follow-up |
| Wave 9 | External-Client MVP & First Real Users | Planned — independent client operates PiglorOS through the Gateway API |
| Wave 10 | Shared World at Scale & Public Launch | Planned |

## Product MVP acceptance

The MVP is a product boundary, not a demo. It is accepted only when an independently built third-party client can:

- create or select a user-owned Timeline/Scenario Room through documented public contracts;
- supply preferences and options through the public decision-preview contract and receive a recommendation with explicit uncertainty;
- submit an action and observe the committed Event/state;
- replay or Fork through public contracts; and
- operate without importing PiglorOS private Rust modules or relying on bundled scenario data.

The Wave 9 acceptance run must use the real 3D reference client connected to live Gateway data; `piglor-world-client`'s fixture shell and the curl smoke test above are engineering validation only. The current repository does not yet satisfy this acceptance bar: Wave 9 still must connect the real 3D client to the Gateway and provide the missing public contracts.

This is a product-level acceptance target, not a claim that the accepted ADR-018 engineering slice already includes these contracts. ADR-018 remains the design boundary for the fixture-backed 3D shell: fixed `TimelineExport` inputs, pure projection parity, WebGL2/native entry points, and no human action submission or Gateway read integration in that shell. Any Wave 9 Gateway action, authentication, live-read, decision-preview, or Replay/Fork contract must be designed and accepted separately before implementation; this reset records the target and keeps the current fixture shell explicitly out of the MVP claim.

## Development

Toolchain is pinned in `rust-toolchain.toml` (**1.97.1** + clippy / rustfmt / llvm-tools).

For agent-based development, see **[AGENTS.md](AGENTS.md)** and **[CONTEXT.md](CONTEXT.md)**.

```bash
# Full local CI parity (same gates as GitHub Actions — Redmine #100 + Trunk):
./scripts/ci.sh

# Or individually:
trunk check --all          # rustfmt + rust-test-policy + actionlint + …
cargo deny --locked check  # dependency bans/licenses/advisories/sources
cargo shear --deny-warnings # unused/misplaced dependencies and unlinked Rust files
cargo fmt --all -- --check
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo test --workspace --locked -- --include-ignored
cargo clippy --workspace --all-targets --locked -- -D warnings -W clippy::pedantic
# `#[coverage(off)]` is ONLY ever applied to #[test] functions / #[cfg(test)] modules —
# it is never used to exempt production code. Needs bootstrap for the unstable attribute:
RUSTC_BOOTSTRAP=1 cargo llvm-cov --workspace --locked --summary-only \
  --fail-under-lines 99 --fail-under-regions 99 -- --include-ignored
```

CI (GitHub Actions): **Trunk Check** (`rust-test-policy`), **cargo-deny** (all features), **cargo-shear**, **cargo-crap** (no existing-score regressions; new functions at most 30), **fmt**, **rustdoc** (`-D warnings`), **test** (`--include-ignored`), **clippy pedantic**, **llvm-cov** (99% lines and 99% regions, with bounded hosted-runner parallelism), **docker-build** (image + smoke test), **deploy** (workflow_dispatch: build → smoke → push to ghcr.io), plus pull-request diff mutation testing, scheduled fuzzing, ThreadSanitizer, and CodeQL workflows. See `.github/workflows/`. The repository-wide LLVM gate is intentionally executed in the hosted `coverage` job with bounded parallelism; its completed LCOV artifact feeds a separate visible `cargo-crap` check without a second instrumented build. Green `main` runs publish per-commit baseline artifacts, and the protected `ci-gate` requires cargo-crap success. When local instrumentation exceeds available memory, run the other local gates and use that Actions job for the coverage execution without lowering either threshold.

Quality floor: **800+ tests · 0 failures · at least 99% line and 99% region coverage · no CRAP regressions · new-function CRAP ≤30 · clippy pedantic clean**

### Test & coverage policy

See **[docs/test-policy.md](docs/test-policy.md)** for the full policy.

| Gate | Tool | What it bans / enforces |
|---|---|---|
| `coverage(off)` + doctest ` ```ignore ` | Trunk **`rust-test-policy`** | `coverage(off)` test-only; no rustdoc ignore fences |
| Local git hook | Versioned `.githooks/pre-commit` + Trunk **`rust-test-policy`** | Blocks a commit if the staged Rust policy fails |
| Runtime `#[ignore]` | `cargo test -- --include-ignored` + `scripts/assert-no-ignored-in-test-summary.sh` | Summary must report `0 ignored` |
| Change risk | pinned **cargo-crap** + `scripts/check_cargo_crap_report.py` | Existing scores cannot regress; new functions must score ≤30 |
| Dependencies | **cargo-deny** (`deny.toml`) | Crates / licenses / advisories / sources |

#### Git hooks (local)

Git does not activate repository hooks automatically on clone. Enable the
versioned pre-commit hook once:

```bash
git config core.hooksPath .githooks
```

The hook fails closed if Trunk is unavailable, then runs `rust-test-policy` on
the staged files before its Cargo checks:

- **pre-commit:** `cargo fmt`, Trunk `rust-test-policy`, `Cargo.lock`
  regeneration/staging after manifest changes, and targeted Clippy.

`#[cfg_attr(coverage_nightly, coverage(off))]` is applied **only** to `#[test]` functions
and code inside `#[cfg(test)]` modules. CI requires **at least 99% lines and 99% regions**.
The 1% tolerance is only for LLVM coverage regions that cannot be mapped to a
source line or segment after a fresh non-root run; it does not exempt tests or
production code.
Unnecessary or unhittable branches are deleted or simplified rather than suppressed.
Run `RUSTC_BOOTSTRAP=1 cargo llvm-cov --workspace --locked --summary-only --fail-under-lines 99 --fail-under-regions 99 -- --include-ignored` to reproduce.
