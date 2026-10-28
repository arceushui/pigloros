# pos-plugin-conformance-adapter

The EAI1/EAO1 subject adapter of the community Plugin host (ADR-061 revision 8, #194/#615).

The EAI1/EAO1 subject adapter binary is owned by #194. Results are Local-relaxation engineering
evidence, not hosted conformance. The pos-plugin-worker binary must be built into the directory of
this binary.

## What it does

`pos-plugin-conformance-adapter` reads one EAI1 attempt from standard input, executes the
sub-cases of its payload, and writes one EAO1 observation to standard output. On a wire fault, or
when the attempt is not executed (a wrong payload `schema` string, a wrong schema member or a
faulty `PCW2` composite), it writes nothing and exits with a non-zero code. It is Linux only: on
other platforms the library is empty and `main` does nothing.

- Library: `pos_plugin_conformance_adapter`. `run(reader, writer)` resolves the worker as
  `pos-plugin-worker` next to `std::env::current_exe()` and reads no argument or environment
  variable for it; `run_with(runner, reader, writer)` takes the `SubCaseRunnerV1` that runs the
  sub-cases (the test entry).
- Each sub-case runs on a fresh in-memory evaluation world (`CommunityEvaluationWorldV1`) with a
  fresh supervised worker per member launch, at the fixture evaluation instant of the step (the
  sealed `FixtureWallSourceV1` of `pos-core`, which only this crate enables). The record's
  `worker_launches` is the supervisors' own count of launched workers
  (`CommunityPluginSupervisorV1::worker_launches()`) across each pass, not an inference from the
  outcome records.
- The outcome record of a pass is mapped to an EAO1 result as ADR-061 revision 8 decision 3
  states: an operational fault is `Unavailable`, never a typed failure and never an output.
- The payload grammar, the `PCW2` composite, the `PCA1` anchor and the oracle record are those of
  ADR-061 revision 8 decisions 7 and 8.

`cargo build -p pos-plugin-conformance-adapter` does not build the worker, so build it first.
`AdapterRunErrorV1::Worker` (exit code 4) is the documented contract for a binary whose
directory cannot be determined.

## Dependencies

The adapter links no Wasmtime and none of `pos-plugin-host`, `pos-plugin-worker`,
`pos-conformance`, `pos-store` or `pos-plugin-publisher` directly (`scripts/check-adapter-graph.sh`).
`pos-plugin-publisher` with `test-support` is a dev-dependency used by the runner tests.

## Fixtures

The checked-in Plugin conformance fixtures (`fixtures/conformance`, layer `plugin-conformance`) are
written by `scripts/generate_plugin_conformance_fixtures.py`, which also writes
`src/schema_digests.rs` (the pinned digest of each family's schema member) and verifies it with
`--check`. `tests/fixture_attempts_public.rs` builds the attempts from those files; the real worker
runs them in `apps/pos-plugin-worker/tests/conformance_fixtures_public.rs`. The acceptance
tests of the whole profile (the `positive`, `denied`, `malformed`, `resource-exhaustion`,
`deletion-redaction`, `downgrade` and `independent-evaluation` families in both Execution
Modes, the negative controls, the fresh-worker count and the no-partial-commit check) are
`apps/pos-plugin-worker/tests/conformance_adapter_public.rs`. They run `run_with` over a
recording runner that wraps the real world port (the recorded sub-case records and the committed
Events and state back the counting and no-partial-commit checks), and over `SupervisorRunnerV1`
with the real worker for the not-executed, unavailable and positive-oracle cases.
`scripts/check_handoff_readme.py` pins the three
sentences at the top of this file.
