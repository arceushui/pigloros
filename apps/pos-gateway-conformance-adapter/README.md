# pos-gateway-conformance-adapter

The EAI1/EAO1 `public-gateway-protocol` subject adapter of apps/piglor-gateway for profile
`pigloros.w8.gateway-client-seam` (provider `pigloros.fixture.gateway-client-conformance@2.0.0`,
Redmine #1295).

Results are Local-relaxation engineering evidence, not hosted conformance. The normative surface is
the documented ADR-014 route table only: no OpenAPI document, Golden Path transition or public
client action or authentication contract.

## What it does

`pos-gateway-conformance-adapter` reads one EAI1 attempt from standard input, runs the HTTP
exchanges of its payload and writes one EAO1 observation to standard output. On a wire fault, or
when the schema member is not the pinned provider 2.0.0 digest, it writes nothing and exits with a
non-zero code. It runs the attempts of claim layer `gateway-client-conformance` in the Local and
Air-Gapped modes; any other claim layer or mode is `Unavailable`.

- Library: `pos_gateway_conformance_adapter`. `run(reader, writer)` is the whole adapter; the
  binary only wires the process's standard streams to it. `executor_declaration` is its exact
  ADR-068 `FixtureExecutorV1`.
- Every sub-case runs on a fresh in-process Gateway over a verified empty in-memory erasure host.
  Its exchanges are raw HTTP requests through the Gateway's public `router` (loopback) and
  `spectator_router` (the non-loopback public listener), with no socket, so Local and Air-Gapped
  are the same execution.
- The `authorized` composition is the production serve composition (#1361): a fixture Local
  Principal document, which lets one actor create Timelines and read their Events and grants no
  action or signal, is provisioned and recomposed through the production Local Principal path,
  and the Gateway requires it for every protected operation. No production authority is sourced
  from the fixture document (ADR-108).
- Observations are normalized as the profile text states: ULID `id` members, cursors and error
  messages become placeholders.
- Usage: one execution step per sent exchange, the response bytes as output bytes, one Event per
  `201` signal or action response; the other counters are 0.

## Fixtures and tests

`scripts/generate_gateway_conformance_fixtures.py` writes the fixtures, the oracles, the executed
evidence-status records and `src/subject/schema_digests.rs`, and verifies them with `--check`.
`tests/adapter_public.rs` builds the attempts from the checked-in files and drives the library and
the binary through the pos-reference EAI1/EAO1 codec in both modes. `tests/provider_dispatch_public.rs`
runs every family through the evaluator's exact-identity dispatch (ADR-062 R8 N6) in the Local and
Air-Gapped ExecutionProfile runs and requires the flipped records.
