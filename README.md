# PiglorOS

A simulation world you join to preview your decisions.

> **Current stage:** Pre-product. Wave 1 (kernel primitives) complete.

## Repository Layout

```
pigloros/
  Cargo.toml              # workspace root
  crates/
    pos-core/             # Wave 1 ✅ — five kernel primitives (no I/O, no async)
    pos-crypto/           # Wave 1 ✅ — BLAKE3 + Ed25519 + canonical CBOR
    pos-store/            # Wave 1 ✅ — EventStore trait + SQLite WAL + in-memory
  apps/                   # Wave 4 — experiment framework + CLI
  plugins/                # Wave 5 — persona, eval, bridges, agents
  bindings/               # Wave 5 — PyO3 Python bindings
```

## Wave Roadmap

| Wave | Description | Status |
|---|---|---|
| Wave 0 | Tracer Bullet — validate prediction baseline | Pending |
| Wave 1 | Kernel Primitives (pos-core, pos-crypto, pos-store) | ✅ Complete |
| Wave 2 | Temporal Engine (replay, fork, merge) | Planned |
| Wave 3 | Plugin Runtime | Planned |
| Wave 4 | Experiment Framework + CLI | Planned |
| Wave 5 | Moat Plugins + Single-User MVP | Planned |
| Wave 6 | Shared World & Social Layer | Planned |
| Wave 7 | Contextual Decision Preview | Planned |

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings -W clippy::pedantic
cargo llvm-cov --workspace --summary-only
```

Wave 1 stats: **176 tests · 0 failures · 100% line coverage · clippy clean**
