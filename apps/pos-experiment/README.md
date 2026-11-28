# pos-experiment

`pos-experiment` provides the multi-rate simulation demo and the checked-in replay and
non-interference conformance subjects. Its executable targets require the `test-support` feature.

## Run the multi-rate demo

The demo appends to an existing Timeline in an explicit SQLite file. Do not use a database that a
Gateway has served. The Gateway binds its store to an execution mode and refuses writes from other
processes.

```bash
cargo run -p pos-experiment --features test-support --locked -- \
  multi-rate-demo /tmp/piglor.db <timeline-id> \
  --ticks 20 --quantum-ms 100 --pace-ms 100
```

The defaults are 20 Tick Boundaries, a 100 ms simulation quantum, and 100 ms wall-clock pacing.
`--ticks`, `--quantum-ms`, and `--pace-ms` override them. Ticks and the quantum must be non-zero.
Set `--pace-ms 0` to run without sleeping. Pacing changes terminal output speed; Driver cadence
uses the printed monotonic simulation time.

To submit simulated human actions, use the Gateway's `world.action.v1` contract and its
`world.action.v1.submit` capability. An authorized request still fails closed when the release
composition has no matching execution profile installed.

The command prints each `TickOutcome` and the final fast and slow action counts. On an error,
stop the process and start a fresh one. The new process rebuilds projections from committed
history. It starts a new cadence clock, so use a fresh Timeline or equivalent Fork to reproduce a
run. Re-running on the original Timeline appends another batch.

## Replay conformance subject

With `test-support`, the `pos-experiment` binary reads one EAI1 attempt from standard input and
writes one EAO1 observation to standard output. A wire fault exits with code 2. An unsupported
schema member or missing `RCS1` composite exits with code 3 without output. A write failure exits
with code 4.

The subject runs fixture cases through Recorded Replay and profile recomputation. It checks the
`VRR1` result of each leg against the expected records. The host enforces the execution mode,
network gate, Event budget, and execution-step budget from the named profile. It does not provide
process or network isolation. Results are Local-relaxation engineering evidence, not hosted
conformance.

The source is `src/replay_conformance.rs`. The fixtures, oracles, and status records are under
[`fixtures/conformance`](../../fixtures/conformance/README.md), in the `replay-conformance` layer.

## Non-interference harness

The harness executes a control and canary pair, normalizes the captures, compares them, and signs
an `NIA1` artifact. A non-executed case has no artifact and makes no claim. The harness builds an
`NIR1` report only from exactly 192 trusted `NIA1` artifacts.

- **Local** starts a fresh subject process for each run under a host timeout.
- **Replay** rebuilds projection state from recorded Events.
- **Fork** runs the subject in a Fork cut at a Tick Boundary.
- **Air-Gapped** currently returns `Unavailable`; it produces no execution artifact.

The checked-in capture adapters cover the G-PUB, G-ARCHIVE, G-PLUG, G-OPS, and G-FORK cases. The
G-OPS and G-FORK modules are Linux-only. The `NI-STATE-003` migration-only canary returns
`Unsupported`.

`NI-FORK-008` uses a records-form Fork. The host builds a provisional dependency graph for each
recomputation Tick and stages one draft per Driver. Local runs it in a fresh subject process,
Replay rebuilds its export from the recorded Event Store, and Fork runs it in-process. The capture
contains nine byte-exact artifact surfaces. Snapshot and ReproManifest surfaces are empty because
this records-form run creates neither.

The implementation is in `src/non_interference_harness/` and `src/fork_artifacts/`. The
content-addressed execution records are under
[`fixtures/conformance/non-interference`](../../fixtures/conformance/README.md).
