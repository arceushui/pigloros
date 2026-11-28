# pos-plugin-conformance-adapter

The EAI1/EAO1 subject adapter for the community Plugin host.

The EAI1/EAO1 subject adapter is `apps/pos-plugin-conformance-adapter`. Results are
Local-relaxation engineering evidence, not hosted conformance. The pos-plugin-worker binary must
be built into the directory of this binary.

## What it does

`pos-plugin-conformance-adapter` reads one EAI1 attempt from standard input, executes the
sub-cases of its payload, and writes one EAO1 observation to standard output. On a wire fault, or
when the attempt is not executed (a wrong payload `schema` string, a wrong schema member or a
faulty `PCW2` composite), it writes nothing and exits with a non-zero code. It is Linux only: on
other platforms the library is empty and `main` does nothing.

- Library: `pos_plugin_conformance_adapter`. `run(reader, writer)` resolves the worker as
  `pos-plugin-worker` next to `std::env::current_exe()` and reads no argument or environment
  variable for it; `run_with(runner, reader, writer)` takes the `SubCaseRunnerV1` used to run
  the sub-cases in tests.
- Each sub-case runs in a fresh in-memory evaluation world (`CommunityEvaluationWorldV1`) with a
  fresh supervised worker per member launch, at the fixture evaluation instant of the step (the
  sealed `FixtureWallSourceV1` of `pos-core`, enabled only for this crate). The record's
  `worker_launches` is the supervisor's count of launched workers
  (`CommunityPluginSupervisorV1::worker_launches()`) across each pass, not an inference from
  outcome records.
- An operational fault maps to `Unavailable`, never a typed failure or output. A
  `ComponentTrap` maps to `Trapped` with its trap class only for an `independent-evaluation`
  sub-case that expects that class (`{"kind":"trapped","class":"<class>","export":"drive"}`);
  otherwise it is operational.
- The payload grammar, `PCW2` composite, `PCA1` anchor and oracle record are defined by the
  checked-in adapter modules and fixtures.

`cargo build -p pos-plugin-conformance-adapter` does not build the worker, so build it first.
`AdapterRunErrorV1::Worker` (exit code 4) is returned when the adapter cannot determine its binary
directory.

## Dependencies

The adapter links no Wasmtime and none of `pos-plugin-host`, `pos-plugin-worker`,
`pos-conformance`, `pos-store` or `pos-plugin-publisher` directly
(`scripts/check-adapter-graph.sh`). `pos-plugin-publisher` with `test-support` is a dev-dependency
used by the runner tests.

## Fixtures

The checked-in Plugin conformance fixtures (`fixtures/conformance`, layer `plugin-conformance`)
are written by `scripts/generate_plugin_conformance_fixtures.py`, which also writes
`src/schema_digests.rs` (the pinned digest of each family's schema member) and verifies it with
`--check`. `tests/fixture_attempts_public.rs` builds the attempts from those files; the real
worker runs them in `apps/pos-plugin-worker/tests/conformance_fixtures_public.rs`. The profile
acceptance tests (`positive`, `denied`, `malformed`, `resource-exhaustion`, `deletion-redaction`,
`downgrade` and `independent-evaluation` families in both Execution Modes, the negative controls,
the fresh-worker count and the no-partial-commit check) are in
`apps/pos-plugin-worker/tests/conformance_adapter_public.rs`. They run `run_with` over a
recording runner that wraps the real world port and over `SupervisorRunnerV1` with the real worker.

CI checks that this README names the adapter path, its evidence level and the worker location.
