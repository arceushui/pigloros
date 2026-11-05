# pos-experiment

`pos-experiment` is a simulation host for a durable PiglorOS Timeline. Its
`multi-rate-demo` command proves deterministic 100 ms / 200 ms agent cadence.
Run standalone Gateway and experiment processes sequentially against the same
SQLite file; live concurrent commands must share one erasure host.
Human action submission additionally requires a host-bound Gateway authority adapter
and World body catalogue.

## Replay-conformance subject adapter

The `pos-experiment` binary is the replay-conformance subject adapter of ADR-062
Revision 8 slice R4 (#1222). It reads one EAI1 attempt from standard input and
writes one EAO1 observation to standard output (the `pos-reference` codec), or
writes nothing and exits with code 2 (wire fault), 3 (not executed: a schema
member other than provider contract 2.0.0, or no `RCS1` composite) or 4 (the
output could not be written). The logic is `pos_experiment::replay_conformance`.
It runs each sub-case of the payload through the `RecordedReplay` and
`ProfileRecomputation` / `CrossProfileConformance` execution steps and compares
the `VRR1` of every leg with the sub-case's expected legs.

The Experiment host binary is the replay subject adapter (ADR-062 Revision 8
section 3.1 option A). The adapter and the binary are compiled only with the
`test-support` feature, because they run on the open fixture erasure gate and the
generated Plugin registration: a normal build produces no `pos-experiment`
binary. Build it with `cargo build -p pos-experiment --features test-support`.
Its Draft limitations are listed on the wiki note
`ADR-062_R8_Recorded_Replay_Digests`, section 7, and in
`fixtures/conformance/support/limitations.md`. Results are Local-relaxation engineering evidence,
not hosted conformance. The fixtures are `fixtures/conformance` layer
`replay-conformance`, written by `scripts/generate_replay_conformance_fixtures.py`.

## Non-interference mode harness

`pos_experiment::non_interference_harness` is the ADR-059 mode harness of
ADR-062 Revision 8 slice N0 (#1227). It runs one control/canary fixture pair
in its Execution Mode, normalizes and compares the captures through the #181
framework in `pos-conformance`, signs the case as one `NIA1` (at most 4 KiB)
with the host executor key, and publishes the canonical bytes at their content
address `fixtures/conformance/non-interference/executions/<digest>.nia1`. The
Local runner spawns a fresh host process per run under a host kill timeout (a
killed run is non-executed `Unavailable`); the Replay runner rebuilds Projection
State from the recorded Events; the Fork runner runs the subject in an ordinary
Fork cut at a Tick Boundary. That F-mode evidence is engineering evidence for
every row except `NI-FORK-008`, which needs the ADR-064 records-form artifact
path of slice R6 (#1225) in slice N4 (#1232); F cases are re-run when #1204
lands (wiki `ADR-062_R8_NonInterference_Harness`). `WarmCache` cases are primed once before the pair,
every other variant runs cold. The Air-Gapped runner returns the typed
non-executed `Unavailable` until slice N7, and every non-executed case has no
artifact and no claim. An `NIR1` is built only from exactly 192 trusted `NIA1`.
The harness flips no inventory: `execution-matrix.json` changes only when the
capture adapters of slices N1 to N4 supply verifier-accepted executions. The
`pos-ni-local-probe` binary (feature `test-support`) is the harness probe of the
Local runner, not a capture adapter of any row.

## Sequential SQLite multi-rate demo

Start the local-only Gateway with an explicit SQLite file:

```bash
cargo run -p piglor-gateway --locked -- \
  serve 127.0.0.1:8080 /tmp/piglor-126.db
```

Create a Timeline and retain the returned `id`, then stop the Gateway before
opening the experiment process:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/timelines \
  -H 'content-type: application/json' \
  -d '{"name":"multi-rate-demo"}'
```

Point the experiment process at the same SQLite path and Timeline ID:

```bash
cargo run -p pos-experiment --locked -- \
  multi-rate-demo /tmp/piglor-126.db <timeline-id> \
  --ticks 20 --quantum-ms 100 --pace-ms 100
```

The defaults shown above are 20 finite Tick Boundaries, a 100 ms simulation quantum,
and 100 ms wall-clock pacing. `--ticks`, `--quantum-ms`, and `--pace-ms` override them.
Ticks and quantum must be non-zero; `--pace-ms 0` runs without sleeping. Pacing only
slows terminal output—driver eligibility comes exclusively from the printed monotonic
simulation nanoseconds, so machine speed does not change deterministic cadence.

After the demo exits, restart the Gateway against that SQLite file to inspect
the committed Timeline. The restarted host verifies the complete inventory
before serving routes. It can then commit Society Signals:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/timelines/<timeline-id>/signals \
  -H 'content-type: application/json' \
  -d '{"entity_id":"<society-entity-id>","dimension":"trust","value":0.75}'

```

Human actions use the [Gateway's versioned action contract](../piglor-gateway/README.md):
`world.action.v1` with the exact `world.action.v1.submit` capability and typed WAC1 payload.
The default Gateway process has no authority adapter and fails closed with `401` for
action submission; a host must configure authenticated authority and known World bodies.

Entity IDs are ULIDs generated by a PiglorOS client. Committed sequence order
remains authoritative. If another process advances the file while a host is
open, that host rejects protected operations until it is restarted and
recovers the new inventory. Do not write through raw SQL or any adapter that
bypasses `EventStore`.

The command prints every `TickOutcome` and the final fast/slow action counts, then exits.
On a store, cadence, or driver error, stop the failed process and start a fresh process; it
rehydrates projections from committed Timeline history, while an ambiguous in-memory session
must never continue. A fresh process resets driver and simulation-cadence state. To reproduce
a run, use a fresh Timeline (or an equivalent Fork) at the same durable head with the same
parameters. Re-running against the original Timeline intentionally appends another finite
batch rather than pretending to continue the prior process's cadence clock.

Run `cargo run -p pos-experiment --locked -- multi-rate-demo --help` for the compact usage.
