# Gateway v1 contract

The language-neutral contract of the PiglorOS Gateway, the only public application boundary
(ADR-022, Redmine #301). A client needs these files and nothing else: no Rust source, private
crate or database.

| File | What it is |
|------|------------|
| [`openapi.json`](openapi.json) | The canonical description: OpenAPI 3.1.1 with the JSON Schema 2020-12 dialect. |
| [`problem-types.json`](problem-types.json) | The closed RFC 9457 problem-type registry: every failure `code`, its `type` URN, `title` and permitted HTTP statuses. |
| [`examples/`](examples/) | Golden request and response pairs, positive and fail-closed, for every operation. |
| [`compatibility/baseline.json`](compatibility/baseline.json) | The frozen v1 baseline: every served operation, the components it reaches and the problem registry as published. |
| [`compatibility/examples/`](compatibility/examples/) | The frozen golden examples that stay valid for the whole compatibility window. |

`scripts/check_gateway_contract.py` checks all of them in CI, together with the served responses
recorded by the gateway-client-conformance fixtures; the routers are executed against those
fixtures, so the description and the served behavior cannot drift apart.

## Operations

Every operation has an `operationId` and an `x-pigloros-status`:

- `served`: the Gateway serves it today and its responses are drift-checked. `x-pigloros-listeners`
  names the listeners that serve it: `loopback` (the complete local API) or also `public` (the
  spectator-only Prediction Ledger routes of a non-loopback bind).
- `draft`: a Wave 9 resource family (owner ticket in `x-pigloros-owner`, #302 to #309). It is not
  served yet; only its golden examples validate, and it may change until its owner serves it.

## Schemas and media types

- Every component schema has a stable `$id` of the form `urn:pigloros:gateway:v1:schema:<name>`.
  Draft schemas carry `x-pigloros-maturity: draft`. Every Draft resource read composes the
  resource envelope (schema ID, resource ID, revision or generation, provenance, execution
  profile and capability-filtered availability).
- A request body is `application/json` (`content-type: application/json`; any other type is
  `415 invalid-request`).
- A success body is `application/json`; every failure, including unknown paths (`404`), unserved
  methods (`405`) and oversized bodies (`413`), is `application/problem+json`.
- `x-pigloros-limits` states every normative request and response limit with its value, unit,
  scope and enforcement: a `schema` limit by the named schema keywords, a `runtime` limit by the
  named problem.
- Events are ordered by Timeline sequence (`seq`), never by wall time. Draft values that must
  replay deterministically are integers (micro-units where fractional), never JSON numbers.

## Problems

Every failure body has `type` (`urn:pigloros:gateway:v1:problem:<code>`), `title`, `status`,
`detail`, `instance`, `code`, `schema_id` (`urn:pigloros:gateway:v1:schema:problem`) and
`retryable`. Branch on `code`, never on `detail`: its wording is not part of the contract.
`instance` is the matched route template (for example `/v1/timelines/{timeline_id}/events`), so
it never echoes an identifier; a request no route matches carries its request path. A protected
lookup answers `not-found-or-unavailable` and never reveals whether the resource exists.
`retryable: true` means an identical retry may succeed.

## Idempotency

A mutation that is retry-safe carries an `Idempotency-Key` header of 1 to 128 visible ASCII
characters (schema `idempotency-key`); every Draft mutation requires one, and of the served
routes `POST /v1/timelines/{timeline_id}/actions` does. Without it the request is
`400 invalid-request`. Repeating the key with the same request returns the original result
(`200` with the original committed Event for an action) without re-running approval; reusing
it with a different request is `409 idempotency-conflict`. A rejected action is never retried by
the Gateway. A `202` answer is an admission receipt: it never claims that an Event committed.
Only an Event with a Timeline sequence is a commit receipt.

## Polling and cursors

`GET /v1/timelines/{timeline_id}/events` returns one page in ascending Timeline Order:

- `from_seq` (inclusive, default `0`) starts a fresh read; `limit` is 1 to 100 (default 100).
- `next_from_seq` is null only when the Timeline is exhausted; otherwise it is the sequence of the
  first omitted Event.
- `next_cursor` (schema `event-cursor`) is an opaque continuation bound to the Timeline and to
  the host's erasure inventory generation; it is null when the host binds no generation. Pass it
  back unchanged as `?cursor=`; `cursor` and `from_seq` are mutually exclusive.
- A cursor of an older generation is `409 append-conflict`: restart from a fresh `from_seq`.
- A page is at most 1 MiB and may hold fewer than `limit` Events. Continue until
  `next_from_seq` is null.

## Compatibility and version negotiation

The rules below are normative (MUST) for the Gateway and for every client of v1. They are the
compatibility policy of section 11 of the Wave 9 acceptance specification.

1. **Major in the path.** The API major is the first path segment (`/v1/...`). A request under
   any other major (`/v2/...`, `/v01/...`) is `400 unsupported-version` with the request path as
   `instance`; it is never served by a fallback. Any other path no route serves is
   `404 not-found-or-unavailable`. A client falls back to another major only after this explicit
   answer, and discloses the version it uses.
2. **Unknown required versions fail closed.** A request that names a schema or Event version the
   Gateway does not support (for example `event_type: "world.action.v2"` or
   `descriptor.schema_version: 2`) is `400 unsupported-version`, with no upcast and no fallback.
3. **Incompatible profiles fail closed.** A request that binds an execution or conformance
   profile the deployment cannot serve is `409 incompatible-profile`; a Local deployment never
   claims an Air-Gapped profile.
4. **Unknown members are handled as each schema declares.** An open request object (no
   `additionalProperties: false`) ignores unknown members; a closed one rejects them. A
   schema-less value such as `EventView.payload` is preserved verbatim. Response schemas are
   closed so that the contract detects drift, but a client MUST ignore unknown response members:
   a later v1 revision may add optional ones.
5. **Additive changes only within v1.** Within v1 a change may add an optional member, an
   optional parameter or an operation, or accept more request values. Removing a member,
   parameter, response or operation, making a member or parameter required, narrowing what a
   request accepts, widening what a response returns (a type, an enumeration value or a bound),
   or changing a schema `$id`, its declared unknown-member handling or any other keyword (such as
   `pattern`, `format` or `default`) requires a new major that runs in parallel, with an explicit
   migration and retirement decision.
6. **Compatibility window.** The served operations frozen in `compatibility/baseline.json` stay
   supported through Wave 10 after Wave 9 acceptance, and every example under
   `compatibility/examples/` stays valid for that window, including the fail-closed ones: a
   request a frozen example rejects stays rejected. Draft operations join the baseline when their
   owner serves them.

`scripts/check_gateway_contract.py` enforces rules 1, 4 (the declaration), 5 and 6: it compares
the contract with the frozen baseline (requests must keep accepting what they accepted, responses
must keep guaranteeing what they guaranteed, a schema reached from both keeps its constraints
exactly) and validates the frozen examples, so a breaking change to a v1 schema fails CI. The
golden examples `unsupported-version-api-major`, `not-found-unrouted-path`,
`unknown-required-schema-event-type`, `unsupported-version-legacy-event-type`,
`draft-scenario-room-unsupported-schema-version`, `draft-decision-preview-incompatible-profile`,
`draft-replay-incompatible-profile` and `compatible-unknown-optional-member-ignored` are the
negotiation and unknown-member cases.

## Changing the contract

- Run `python3 scripts/check_gateway_contract.py` and
  `python3 scripts/test_check_gateway_contract.py` with the hash-pinned `jsonschema` of
  `requirements-pinned-dependencies.txt`.
- When an owner ticket turns a Draft operation into a served one, run
  `python3 scripts/check_gateway_contract.py --freeze`. It appends the newly served operations,
  the components they reach, any new problem type and the golden examples of served operations
  to the baseline; it never rewrites a frozen entry. Do not edit `compatibility/` by hand.
- A golden example is `{name, operation_id, request, request_valid, response}`. An example of a
  request no route serves has a null `operation_id` and names its `method` and query-free
  `target`.
