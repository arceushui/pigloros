# PiglorOS

A simulation world you join to preview your decisions.

> **Current stage:** Pre-product. Wave 5 moat plugin crates + closed eval loop in `pos-mvp` / CLI backtest. LLM bridges, H3, and shared world remain deferred.

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
    pos-mvp/              # Wave 5 ✅ — Kyoto vs Osaka trip preview + CalibrationReport
  plugins/
    entities/rule-agent/  # Wave 4 ✅ — deterministic rule-based agent plugin
    observations/synthetic/ # Wave 4 ✅ — synthetic sin-wave observation plugin
    persona/              # Wave 5 ✅ — PersonaModel + PersonaEvalDriver (closes eval loop)
    world/                # Wave 5 ✅ — WorldBackend + SimpleKinematic (rapier deferred)
    agent/                # Wave 5 ✅ — AgentPolicy + RoundRobin/RandomSeed (no LLM yet)
    geo/                  # Wave 5 ✅ — SpatialCloaker degree-grid cloaking (not H3)
    bridges/              # Wave 5 ✅ — BridgeIngestor draft API (no HTTP/Claude yet)
    eval/                 # Wave 5 ✅ — compute_report → CalibrationReport (Brier/ECE/lift)
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
| Wave 6 | Shared World & Social Layer (+ PyO3 bindings) | Planned |
| Wave 7 | Contextual Decision Preview | Planned |

## Development

Toolchain is pinned in `rust-toolchain.toml` (**1.94.1** + clippy / rustfmt / llvm-tools).

```bash
# Full local CI parity (same gates as GitHub Actions — Redmine #100):
./scripts/ci.sh

# Or individually:
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings -W clippy::pedantic
# Region coverage: tests use #[coverage(off)] under cfg(coverage_nightly); needs bootstrap:
RUSTC_BOOTSTRAP=1 cargo llvm-cov --workspace --summary-only \
  --fail-under-lines 100 --fail-under-regions 100
```

CI (GitHub Actions): every PR and `main` run **fmt**, **test**, **clippy pedantic**, and **llvm-cov** with hard 100% line + region fail-under. See `.github/workflows/ci.yml`.

Wave 1 stats: **193 tests · 0 failures · 100% line coverage · clippy clean**

Wave 2 stats: **233 tests · 0 failures · 100% line coverage · clippy pedantic clean**

Wave 3 stats: **272 tests · 0 failures · 100% production line coverage · clippy pedantic clean**

Wave 4 stats: **359 tests · 0 failures · 100% line coverage · clippy pedantic clean**

Wave 5 stats: **718 tests · 0 failures · 100% line + region coverage · clippy pedantic clean**
