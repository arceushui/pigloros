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
  sealed `FixtureWallSourceV1` of `pos-core`, which only this crate enables).
- The outcome record of a pass is mapped to an EAO1 result as ADR-061 revision 8 decision 3
  states: an operational fault is `Unavailable`, never a typed failure and never an output.
- The payload grammar, the `PCW2` composite, the `PCA1` anchor and the oracle record are those of
  ADR-061 revision 8 decisions 7 and 8.

`cargo build -p pos-plugin-conformance-adapter` does not build the worker. Build
`pos-plugin-worker` into the same target directory first.

## Dependencies

The adapter links no Wasmtime and none of `pos-plugin-host`, `pos-plugin-worker`,
`pos-conformance`, `pos-store` or `pos-plugin-publisher` directly (`scripts/check-adapter-graph.sh`).
`pos-plugin-publisher` with `test-support` is a dev-dependency: the signed-release test world is the
only source of signed closures before the fixture catalog (S3b).
