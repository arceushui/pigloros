# PiglorOS

A simulation world you join to preview your decisions.

> **Current stage:** Pre-product. Wave 6 **foundation** delivered (#87 identity, #71 society, #69 gateway HTTP MVP) — auth/WS/client/PyO3/agents/distributed store still deferred. Wave 7 **thin MVP** delivered on `main` (ADR-015, #76 plain language, #75 local `--fork-compare`, #79 AI Influence Index); science tickets #77/#78 remain open. **Prediction Ledger** delivered on `main` (#58: public page, TOML curated tier + EventStore live tier, CLI, gateway write route, Docker/CI/CD).

## Getting started

```bash
# Decision preview demo (example scenario: places)
cargo run -p pos-mvp --locked

# Same loop, different domain (work structure)
cargo run -p pos-mvp --locked -- --scenario work --prefer autonomy=1.0 --prefer collaboration=0.2

# Flip a recommendation by changing prefs
cargo run -p pos-mvp --locked -- --scenario places --prefer food=1.0 --prefer nature=0.2

# Optional: durable store + experiment via the CLI (`pos` binary)
cargo run -p pos-cli --locked -- store init --path /tmp/piglor.db
cargo run -p pos-cli --locked -- --help

# Wave 6: local HTTP gateway (ADR-014 / #69) — Memory store on loopback
cargo run -p piglor-gateway --locked -- serve 127.0.0.1:8080

# Prediction Ledger CLI (ADR-017 / #58) — create and verify predictions
cargo run -p piglor-ledger --locked -- predict --source toml:./seed/predictions \
  --title "My prediction" --statement "..." --predicted-outcome Yes \
  --confidence 0.7 --made-at "2026-07-28T12:00:00Z" --resolve-by 2026-12-31 \
  --osf https://osf.io/xxxxx

# Docker deployment (gateway + seed predictions)
docker compose up -d
curl http://localhost:8080/health
curl http://localhost:8080/v1/ledger
```

Requires the pinned toolchain in `rust-toolchain.toml` (Rust **1.97.1**).

```bash
# One-time per clone — enable git hooks (fmt + clippy on commit):
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
    pos-experiment/       # Wave 4 ✅ — experiment host: tick loop, StopCondition, branch, backtest
    pos-cli/              # Wave 4/5 ✅ — pos binary: store, timeline, experiment, merge
    pos-mvp/              # Wave 5/7 — decision preview (+ optional gateway context, ADR-015)
    piglor-gateway/       # Wave 6 ✅ — local-first HTTP gateway (ADR-014 / #69)
    piglor-ledger/         # Wave 4 ✅ — Prediction Ledger CLI + static renderer (ADR-017 / #58)
  plugins/
    entities/rule-agent/  # Wave 4 ✅ — deterministic rule-based agent plugin
    observations/synthetic/ # Wave 4 ✅ — synthetic sin-wave observation plugin
    persona/              # Wave 5 ✅ — PersonaModel + PersonaEvalDriver (closes eval loop)
    world/                # Wave 5 ✅ — WorldBackend + SimpleKinematic (rapier deferred)
    agent/                # Wave 5 ✅ — AgentPolicy + RoundRobin/RandomSeed (no LLM yet)
    geo/                  # Wave 5 ✅ — SpatialCloaker degree-grid cloaking (not H3)
    bridges/              # Wave 5 ✅ — BridgeIngestor draft API (no HTTP/Claude yet)
    eval/                 # Wave 5 ✅ — compute_report → CalibrationReport (Brier/ECE/lift)
    society/              # Wave 6 ✅ — SocietySignal + SocietyReducer (trust/opinion/… metrics)
    ledger/               # Wave 4 ✅ — Prediction Ledger domain, port, adapters (ADR-017 / #58)
```

Wave 6 will add `bindings/piglor-py` (PyO3); that directory is not in-tree yet.

## Wave Roadmap

| Wave | Description | Status |
|---|---|---|
| Wave 0 | Tracer Bullet — validate prediction baseline | Deferred (folded into Wave 5 MVP loop) |
| Wave 1 | Kernel Primitives (pos-core, pos-crypto, pos-store) | ✅ Complete |
| Wave 2 | Temporal Engine (replay, fork, merge) | ✅ Complete |
| Wave 3 | Plugin Runtime (pos-runtime) | ✅ Complete |
| Wave 4 | Experiment Framework + CLI (pos-experiment, pos-cli) | ✅ Complete |
| Wave 5 | Moat Plugins + Single-User MVP | ✅ Complete |
| Wave 6 | Shared World & Social Layer (+ PyO3 bindings) | ✅ Foundation done — #87 #71 #69; Prediction Ledger delivered (#58); WS/auth/PyO3/client/#72–74 deferred |
| Wave 7 | Contextual Decision Preview | ✅ Thin MVP done — ADR-015/#76/#75 thin/#79; #77/#78 science open |

## Development

Toolchain is pinned in `rust-toolchain.toml` (**1.97.1** + clippy / rustfmt / llvm-tools).

For agent-based development, see **[AGENTS.md](AGENTS.md)** and **[CONTEXT.md](CONTEXT.md)**.

```bash
# Full local CI parity (same gates as GitHub Actions — Redmine #100 + Trunk):
./scripts/ci.sh

# Or individually:
trunk check --all          # rustfmt + rust-test-policy + actionlint + …
cargo deny --locked check  # dependency bans/licenses/advisories/sources
cargo fmt --all -- --check
cargo test --workspace --locked -- --include-ignored
cargo clippy --workspace --all-targets --locked -- -D warnings -W clippy::pedantic
# `#[coverage(off)]` is ONLY ever applied to #[test] functions / #[cfg(test)] modules —
# it is never used to exempt production code. Needs bootstrap for the unstable attribute:
RUSTC_BOOTSTRAP=1 cargo llvm-cov --workspace --locked --summary-only \
  --fail-under-lines 100 --fail-under-regions 100 -- --include-ignored
```

CI (GitHub Actions): **Trunk Check** (`rust-test-policy`), **cargo-deny**, **fmt**, **test** (`--include-ignored`), **clippy pedantic**, **llvm-cov**, **docker-build** (image + smoke test), **deploy** (workflow_dispatch: build → smoke → push to ghcr.io). See `.github/workflows/`.

Current stats: **800+ tests · 0 failures · 100% line coverage · 100% region coverage · clippy pedantic clean**

### Test & coverage policy

See **[docs/test-policy.md](docs/test-policy.md)** for the full policy (also mirrored in Cursor user rules).

| Gate | Tool | What it bans / enforces |
|---|---|---|
| `coverage(off)` + doctest ` ```ignore ` | Trunk **`rust-test-policy`** | `coverage(off)` test-only; no rustdoc ignore fences |
| Local git hooks | Trunk **`trunk-check-pre-commit`** + **`trunk-check-pre-push`** | Blocks commit/push if `rust-test-policy` fails (`trunk git-hooks sync`) |
| Runtime `#[ignore]` | `cargo test -- --include-ignored` + `scripts/assert-no-ignored-in-test-summary.sh` | Summary must report `0 ignored` |
| Dependencies | **cargo-deny** (`deny.toml`) | Crates / licenses / advisories / sources |

#### Git hooks (local)

Trunk manages hooks via `core.hooksPath` (not files under `.git/hooks/`):

```bash
trunk git-hooks sync   # once per clone / after enabling actions
```

Enabled actions (see `.trunk/trunk.yaml`):

- **pre-commit:** `trunk-fmt-pre-commit` + `trunk-check-pre-commit` (runs `rust-test-policy`)
- **pre-push:** `trunk-check-pre-push`

`#[cfg_attr(coverage_nightly, coverage(off))]` is applied **only** to `#[test]` functions
and code inside `#[cfg(test)]` modules. CI requires **100% lines and ≥100% regions**.
Unnecessary or unhittable branches are deleted or simplified rather than suppressed.
Run `RUSTC_BOOTSTRAP=1 cargo llvm-cov --workspace --locked --summary-only --fail-under-lines 100 --fail-under-regions 100 -- --include-ignored` to reproduce.
