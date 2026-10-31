# pos-metric-conformance-adapter

The EAI1/EAO1 `exported-artifact` subject adapter of plugins/eval for the metric computation
profile `pigloros.w8.metric-computation` (ADR-062 Revision 7 slice 4, #1217).

Results are Local-relaxation engineering evidence of a Draft profile, not hosted conformance. A
pass claims metric computation only: no calibration quality, predictive benefit,
representativeness, external validity or deployment fitness (profile section 4.1 item 2). Any
hosted, Candidate or Stable claim still needs the Sandbox Provider, and Stable needs a second
independently developed implementation under test (section 4.5 item 5).

## What it does

`pos-metric-conformance-adapter` reads one EAI1 attempt from standard input, runs the sub-cases
of its payload and writes one EAO1 observation to standard output. On a wire fault, or when the
attempt is not executed (a schema member that is not the pinned provider 2.0.0 digest, or no
`MCS1` composite), it writes nothing and exits with a non-zero code. It runs the attempts of
claim layer `metric-conformance` in the Local and Air-Gapped modes; any other claim layer or
mode is `Unavailable`.

- Library: `pos_metric_conformance_adapter`. `run(reader, writer)` is the whole adapter; the
  binary only wires the process's standard streams to it.
- Each `MTI1` member is decoded and computed by plugins/eval's public `MetricInputV1`, and each
  `MTQ1` member by its quantization codec, so the implementation under test is the code users
  get. plugins/eval has no `MTR1` decoder: accepting a foreign `MTR1` (`dgr.3`) and the
  generator check (`ind.2`) belong to the independent evaluator and the generator, so the
  adapter records them without executing them.
- The gates of the other families: the subject holds only `read-public-bundle`, so any other
  requested capability and any network use is `capability-denied` before a member is read
  (`den.1`, `den.2`); a step request above the attempt's execution-step budget is a resource
  limit (`res.3`); an oversized member goes through the #222 transport's bounds, which reject a
  member above the 64 MiB selected ceiling with `FieldOutOfBounds` (`res.2`); a provider
  contract other than `pigloros.fixture.metric-conformance@2.0.0` is `incompatible-contract`
  with no fallback (`dgr.2`).
- A `canonical-output` family outputs its record of every sub-case, the RFC 8785 JSON of the
  oracle. A `namespaced-failure` family returns its family failure when every sub-case gave the
  expected closed error and first coordinate (or the expected refusal), else
  `subcase-mismatch`; a payload outside the grammar is `payload-invalid`.
- Usage: one execution step per member plugins/eval decodes; the other counters are 0.

## Fixtures and tests

`scripts/generate_metric_conformance_fixtures.py` writes the fixtures, the oracles and
`src/schema_digests.rs` (the pinned digest of each family's schema member) and verifies them
with `--check`. `tests/adapter_public.rs` builds the attempts from the checked-in files, drives
the binary through its process boundary with the pos-reference EAI1/EAO1 codec in both modes,
judges each observation as the evaluator judges a CNR1 case, and recomputes `ind.1`, `ind.3`
and `dgr.3` with pos-reference.
