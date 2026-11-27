# PiglorOS

PiglorOS is a Rust workspace for event-sourced simulations. It provides Timeline storage,
simulation and plugin runtimes, a local HTTP Gateway, and prediction evaluation.

## Applications

- [`piglor-gateway`](apps/piglor-gateway/README.md) serves the HTTP API for Timelines,
  Scenario Rooms, Preferences, OptionSpecs, decision previews, consent, erasure, and the
  Prediction Ledger. Protected operations use a provisioned Local Principal. Decision previews
  also require an installed execution profile.
- `pos-cli` provides command-line access to stores, Timelines, and experiment operations.
- [`pos-experiment`](apps/pos-experiment/README.md) runs simulations and provides the checked-in
  conformance subject adapters.
- `piglor-ledger` provides the Prediction Ledger command line and public read view.
- [`pos-sandboxd`](apps/pos-sandboxd/README.md) implements the Linux systemd sandbox provider,
  including attempt execution, launch barriers, and recovery.

The public HTTP contract is in [`contracts/gateway/v1`](contracts/gateway/v1/README.md).
Conformance inputs and expected records are in [`fixtures/conformance`](fixtures/conformance/README.md).

## Run the Gateway

Use the toolchain pinned in `rust-toolchain.toml`.

```bash
cargo run -p piglor-gateway --locked -- serve --profile gateway-mode-local-v1
curl http://127.0.0.1:8080/health
```

This command starts the in-memory store. Protected operations return `401 unauthenticated` until
you provision a Local Principal. Follow the [Gateway guide](apps/piglor-gateway/README.md) for
store setup, authorization, execution modes, and other service operations.

## Repository layout

- `apps/` contains the Gateway, command-line tools, experiment host, sandbox provider, and
  conformance adapters.
- `crates/` contains shared domain, storage, runtime, protocol, and evidence libraries.
- `plugins/` contains simulation and evaluation plugins.
- `contracts/` contains language-neutral public API contracts.
- `fixtures/` contains conformance inputs, expected outputs, and evidence records.
- `docs/` contains repository policy, implementation notes, and evidence reports.

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) for the worktree workflow, quality gates, and pull
request process. [`AGENTS.md`](AGENTS.md) records repository-specific agent instructions.
[`CONTEXT.md`](CONTEXT.md) defines domain terms. [`docs/test-policy.md`](docs/test-policy.md)
describes test and coverage requirements.
