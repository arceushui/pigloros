# pos-experiment

`pos-experiment` is a simulation host for a durable PiglorOS Timeline. Its
`multi-rate-demo` command proves deterministic 100 ms / 200 ms agent cadence.
It writes only SQLite files no Gateway has served: a Gateway binds its store to
an execution mode, and a bound store refuses non-Gateway writers (ADR-134).
Live concurrent commands must share one erasure host.
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

Every family runs in Local and in Air-Gapped mode against the same oracle
(slice R5, #1224). `pos_experiment::replay_conformance::pair_report` runs the
Local and the Air-Gapped attempt of one case and reports the manifest and
`VRR1` of every leg of both; the two must have identical authoritative
results. An Air-Gapped attempt has no network: a network attempt is the
failure `network-denied` of provider
`pigloros.fixture.replay-conformance@2.0.0`. The report labels the Air-Gapped
results Local-relaxation engineering evidence until the Sandbox Provider runs
them.

`pos_experiment::replay_conformance::executor_declaration` is the adapter's
exact ADR-068 `FixtureExecutorV1` declaration (provider key, `exported-artifact`
subject adapter, pinned schema digests and capabilities). The composition root
of `tests/replay_provider_dispatch_public.rs` hands it to the independent
evaluator, which runs every family through a fresh `pos-experiment` process in
the Local and the Air-Gapped ExecutionProfile run; that test requires
`expected/replay-conformance/deletion-redaction.json` (ERA-001, #1296) to be
`executed` and every other replay record to stay `pending`.

`pos_experiment::profile_recomputation` enforces the named EPF1 on the host
side, independently of the subject (#1266, wiki
`ADR-062_R8_Profile_Recomputation_Enforcement`): a network gate on the request
inputs, the manifest Execution Mode through the composition mode of the host it
builds (`Experiment::new` or `Experiment::new_air_gapped`), and the EPF1
Event-count and execution-step (Tick) budgets. A cross-profile leg runs in its
own profile's Execution Mode. It enforces no other EPF1 field and claims no
network or process isolation.

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

`non_interference_harness::g_pub` holds the G-PUB capture adapters of slice N1
(#1229, wiki `ADR-062_R8_NonInterference_Executions`):
- `NI-PUBLIC-006` speaks HTTP to a fresh `piglor-gateway` router.
- `NI-EVAL-007` captures the `export_timeline_own` export and the EAI1 attempt
  over it.

Every mode imports the Events it produced into that public seam. The host
places the unauthorized value in a denied sibling Timeline of the seam store.
Run-local identities are captured position-relative. `pos-ni-g-pub-subject` is
the Local fresh-process subject of these rows.

`non_interference_harness::g_archive` holds the `NI-ARCHIVE-009` capture adapter
of slice N1b (#1284, wiki `ADR-127_Deterministic_Run_Evidence_Archive`). It uses
the G-PUB subject and seam: the export is projected onto the RVA1 members
(`pos_conformance::run_evidence_archive`), written by the RVA1 builder from
value-named staging files in a value-dependent order and chunking, and imported
by the independent reader `pos_reference::run_evidence_archive`. The six
surfaces are byte-exact; the `Denial` variant also records an import refused for
a wrong digest.

`non_interference_harness::g_fork` holds the G-FORK capture adapter of slice N4
(#1232, wiki `ADR-062_R8_NonInterference_Fork`) for `NI-FORK-008`, over the R6
Fork artifact exports below:
- Local runs the records-form Fork in the fresh process `pos-ni-g-fork-subject`.
- Replay records a run and rebuilds its export from the recorded Event Store
  (`replay_recorded_fork_v1`): `RCF1`/`SIV1` are read back and `RCP1`/`CFR1`
  recovered from the committed Fork Events, with `INT1`/`CFP1` from the recorded
  plan. No Driver runs and no Event is appended.
- Fork runs the records-form Fork in-process (owner answer Q7: a genuine ADR-064
  Fork execution, re-run when #1204 lands).

The host places the unauthorized value in the factual Timeline after the cut:
in the factual suffix inputs and in the participant Driver's hidden participant
field. The nine byte-exact surfaces are captured from the exported artifacts;
snapshots and ReproManifest are empty until #1204. The shared executor key and
capture helpers live in `non_interference_harness::fixture_evidence` and the
private `capture` module.

`non_interference_harness::g_plug` holds the G-PLUG capture adapters of slice N2
(#1230, wiki `ADR-062_R8_NonInterference_Plugin`) for `NI-TOOL-001`,
`NI-STATE-003` (state members), `NI-NET-010` and `NI-SERVICE-011`:
- The Plugin is reached only through the PWQ1/PWR1 public Plugin protocol codec
  of `pos-plugin-supervisor`, answered by an in-process deterministic fixture
  guest (`describe`, `reduce`, `drive`). A migrate-state request is refused.
- Every mode produces the Events of the guest's `drive`; the capture rebuilds
  the Plugin's state from them through `reduce` alone.
- Tools, frozen services and the network sequence are host-owned records. A
  lookup without a frozen record is a live call: non-executed `LiveCall`.
- The host writes the unauthorized value only to its own record file.
- The `NI-STATE-003` migration-only canary is non-executed `Unsupported` until
  PMF1 v2 (#621, wiki `ADR-059_R9_State_Migration_Scoping`).

`pos-ni-g-plug-subject` is the Local fresh-process subject of these rows. The
executions are engineering evidence, re-run on the Wasm worker path later.

## ADR-064 Fork artifact comparison

`pos_experiment::fork_artifacts` is ADR-062 Revision 8 slice R6 (#1225).
`run_fork_v1` records a deterministic factual history (each pass is admitted
with `PluginRegistry::admit_scheduled_pass` under attempt identities derived
from the Timeline and Tick and `commit_now_secs` 0, not through
`LocalScheduledAdmissionHostV1::admit`, whose fresh attempt ULID would enter
the recorded provenance; time-based admission checks are not exercised), cuts an ADR-064
counterfactual Fork from it and exports the run's `INT1` Interventions, `CFP1`
plan, `RCF1` frontier, `SIV1` invalidation, `RCP1` checkpoints and `CFR1`
result through their public encodings, each at the run's `WorldCut`
coordinate. `compare_fork_artifacts_v1` compares two exports with the R1
comparator, so a mismatching artifact is one `DVR1` at its coordinate. The
provisional Ticks come from the records form: the host declares the
provisional graph and a records-form stager stages it. Per owner answer Q7 such
a run is a genuine ADR-064 Fork execution, re-run when the ADR-064 R7 steps form
(#1204) lands. A factual suffix after the cut never reaches an artifact. Local
and Air-Gapped runs export the same bytes; an Air-Gapped run refuses an EPF1
that allows network (the run is in-process; no isolation is claimed). The module needs the `test-support` feature (the open
fixture erasure gate and the generated Plugin registration) and Linux (the
`pos-time` counterfactual module). Results are Local-relaxation engineering
evidence, not hosted conformance.
`record_fork_v1` also keeps the run's recorded Event Store, which
`replay_recorded_fork_v1` rebuilds the export from (slice N4, #1232). The
participant Driver `beta` writes the fixture's hidden participant field into
its factual Events after the cut; like the factual suffix it never reaches an
artifact.

`non_interference_harness::g_ops` (Linux only) holds the G-OPS capture adapters
of slice N3 (#1231, wiki `ADR-062_R8_NonInterference_Operations`) for
`NI-CACHE-002`, `NI-OBS-004`, `NI-TIME-005` and `NI-CRASH-012`:
- The subject is an Experiment whose one Driver is a supervisor-backed community
  Plugin Driver running the checked-in WAT guest `g_ops_guest.wat` in a fresh
  `pos-ni-g-ops-worker` process.
- The host places the unauthorized value in denied sibling work: cached sibling
  decisions of a host `ErasureExecutionHostV1` authorization cache, a sibling
  invocation's log message, declared-failure coordinate and trap, a support
  archive name, and a wall-clock offset and watchdog margin.
- Only the excluded bytes of each row's typed operational capture carry those
  values. The support bundle, crash report and support archive are capture
  records, not product features.

`pos-ni-g-ops-subject` is the Local fresh-process subject of these rows.

## Sequential SQLite multi-rate demo

The demo appends to an existing Timeline of an explicit SQLite file. The file
must not be one a Gateway has served: the first `piglor-gateway serve` binds a
store to its execution mode, and a bound store refuses every non-Gateway writer
(ADR-134 §8), so the earlier Gateway-then-experiment sequence on one file is no
longer supported. Point the experiment process at the SQLite path and Timeline
ID:

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

Human actions use the [Gateway's versioned action contract](../piglor-gateway/README.md):
`world.action.v1` with the exact `world.action.v1.submit` capability and typed WAC1 payload.
An unprovisioned Gateway fails closed with `401` for every protected route, and actions stay
refused until an installed World action catalogue exists (#461).

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
