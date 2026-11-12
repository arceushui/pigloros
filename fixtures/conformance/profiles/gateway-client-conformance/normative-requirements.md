# Gateway client seam profile requirements

Profile `pigloros.w8.gateway-client-seam`, claim layer `GatewayClientConformance = 3`, subject
adapter `public-gateway-protocol`, provider `pigloros.fixture.gateway-client-conformance`
contract `2.0.0`, ABI 1.0 (Redmine #1295; owner decisions of 2026-11-07 on #1295). The normative
surface is the served routes of the Draft Gateway v1 contract `contracts/gateway/v1/openapi.json`
and its RFC 9457 problem-type registry (#301, #1312); `scripts/check_gateway_contract.py`
validates every expected response below against that description. There is no Golden Path
transition, Scenario Room, or new authentication or action contract in this profile. No fixture relies on a live
service or on the Gateway implementation as its oracle: every expected exchange is written by
`scripts/generate_gateway_conformance_fixtures.py` from this text.

## 1. Case payload

A case payload is RFC 8785 JSON with exactly the members `schema`
(`pigloros.gateway-client-conformance.case.v2`), `family` (the family name) and `subcases`
(1 to 64). There is no reader for provider contract 1.0.0. A sub-case has exactly `id`
(`<prefix>.<n>`), `title`, `composition` (`open` or `authorized`), `exchanges` (1 to 128), and
optionally `canary` (1 to 64 printable ASCII bytes). An exchange has exactly `router`
(`loopback` or `spectator`), `method` (`GET` or `POST`), `path`, `expect`, and optionally
`actor` (`true`), `body` (any JSON value other than null) and `capture` (`"timeline"`). An
optional member that is null is the same as an absent one. A `title` is 1 to 160 printable ASCII
bytes (space allowed), a `path` 1 to 256 printable ASCII bytes without space, and a sub-case `id`
is the family prefix, a dot and one or more decimal digits. A payload outside
this grammar is the failure `payload-invalid`.

## 2. Routes and capabilities

The path without its query names one route; any other path is outside the grammar.

| Route | Method and path | Capability |
|---|---|---|
| health | `GET /health` | `gateway.health.read` |
| ledger | `GET /v1/ledger` | `gateway.ledger.read` |
| create | `POST /v1/timelines` | `timeline.create` |
| events | `GET /v1/timelines/:id/events` | `timeline.events.read` |
| signals | `POST /v1/timelines/:id/signals` | `timeline.signals.append` |
| actions | `POST /v1/timelines/:id/actions` | `world.action.v1.submit` |

An exchange whose route capability the attempt does not hold is not sent; its observation is
`{"refused": "capability-denied"}`. The literal `{timeline}` in a path is replaced by the `id`
of the response of the last earlier sent exchange of the sub-case that sets `capture`; a path that
uses it before any capture is outside the grammar. A capturing exchange that is refused captures
nothing, and a captured response with no text `id` leaves the slot empty, so the exchanges that use
it cannot match.

## 3. Compositions

Every sub-case runs on its own fresh in-process Gateway over a verified empty in-memory erasure
host, driven through the `router` (loopback) or `spectator_router` (the non-loopback public
listener) of the same Gateway with raw HTTP requests, without any socket. No network is used
in either execution mode, so Local and Air-Gapped executions are the same.

- `open`: no host authorizer (the default Gateway).
- `authorized`: the nonproduction fixture registration of the Gateway action registry and a
  fixture authority, explicitly fixture-only, from which no production authority is sourced
  (ADR-108). Its Principal holds one grant for actor `01JC0GATEWAYF1XTVREACT0R00`: resource
  `timeline.events`, action `read`, purpose `read`, audience `gateway`. It grants no action.
  The fixture World body is `01JC0GATEWAYF1XTVREB0DY000`. An exchange with `actor` sends
  `x-piglor-actor-entity: 01JC0GATEWAYF1XTVREACT0R00`.

A request `body` is sent as compact JSON with `content-type: application/json`. Every request
carries `idempotency-key: <sub-case id>`; routes without an idempotency key ignore it, and two
identical actions of one sub-case are an exact retry.

## 4. Observations and normalization

The observation of a sent exchange is `{"status": <code>, "body": <body>}`. The body is
`{"json": <value>}` when the response bytes are one JSON value, else the string `"non-json"`.
The value is normalized; the identities, cursors and messages the documentation does not fix
are permitted nondeterministic operational fields:

- a member `next_cursor` whose value is `v1.<64 lowercase hex>.<ULID>.<positive integer>`
  becomes `"<cursor>"`;
- a member `detail` with a text value becomes `"<message>"`;
- in a member `id` or `instance` with a text value, every `/`-separated segment that is a ULID
  becomes `<ulid>`, so an `id` that is a ULID becomes `"<ulid>"` (a routed problem names its
  route template and carries no ID; only the path of a request no route serves can carry one).

Any other value, including a malformed ID or cursor, stays as it is, so the exchange does not
match. An exchange matches when its observation equals `expect`.

The payload of a `society.signal` Event is the CBOR map of its four text keys in declaration
order (`dimension`, `value`, `subject`, `object`), the value in the shortest IEEE 754 width that
holds it exactly, and an absent subject or object as null; `payload_hex` is its lowercase hex.

## 5. Results and usage

A `canonical-output` family (positive, deletion-redaction, independent-evaluation) outputs the
RFC 8785 JSON record `{"case_id", "claim_layer", "family", "oracle": {"kind":
"canonical-output"}, "output": {"subcases": [...]}}` followed by one LF. A sub-case record is
`{"id", "exchanges": [<observation>...]}`, with `"prohibited_data_present"` when the sub-case
has a `canary` (whether the canary bytes occur in any spectator response body), and with
`"digest"` in the independent-evaluation family (the BLAKE3 of the RFC 8785 JSON of the
observation list). A `namespaced-failure` family returns its family failure when every
exchange matches and no canary is present, else `subcase-mismatch`.

Usage: one execution step per sent exchange, the response body bytes as output bytes, and one
Event per `201` response of the signals or actions route. The other counters are 0.

## 6. Families

- **positive:** `/health` answers `{"ok": true}`; a created Timeline polls an empty exhausted
  page; a committed Society Signal is polled back with its canonical payload; `/v1/ledger` is
  empty.
- **denied** (`capability-denied`): an action without a host authorizer is the `401`
  `unauthenticated` problem and an action the fixture authority does not grant is the `403`
  `unauthorized` problem, each followed by an empty poll (denial without state change); a route
  whose capability the attempt does not hold is refused; a read on the `authorized` Gateway
  without the actor header is the `401` `unauthenticated` problem.
- **malformed** (`malformed-payload`): `cursor` with `from_seq` and `limit=101` are the `400`
  `invalid-request` problem; a Timeline ID that is not a ULID is `400` `invalid-request`;
  integer action `params` are the `422` `admission-rejected` problem, and nothing is committed.
- **resource-exhaustion** (`resource-limit`): 64 root Timelines are created and the 65th is the
  `429` `resource-limit-exceeded` problem.
- **deletion-redaction:** public-listener redaction. A canary Society Signal is committed
  through the loopback router; on the same Gateway the spectator router answers the Timeline
  events and signals routes with the `404` `not-found-or-unavailable` problem, still answers `/health` and `/v1/ledger`, and no
  spectator response contains the canary; the loopback poll still returns the Event. This is
  redaction from the public surface, not ADR-060 deletion (see `support/limitations.md`).
- **downgrade** (`incompatible-contract`): the legacy `world.action` event type is the `400`
  `unsupported-version` problem and the legacy `world.action.submit` capability is the `403`
  `unauthorized` problem, with no fallback and nothing committed.
- **independent-evaluation:** the digests of a health exchange and of a created Timeline with
  its empty page.

## 7. Compatibility and version negotiation

These rules bind the Gateway and every client of the v1 contract for the compatibility window;
`contracts/gateway/v1/README.md` states them in full and `scripts/check_gateway_contract.py`
enforces them against the frozen baseline `contracts/gateway/v1/compatibility/`.

- **Window:** the served operations frozen in the baseline stay supported through Wave 10 after
  Wave 9 acceptance, and every frozen golden example, positive or fail-closed, stays valid. A
  breaking change runs as a parallel new major with an explicit migration and retirement
  decision; the baseline only gains entries.
- **Additive fields:** within v1 a change may add only optional members, optional parameters,
  responses, response headers, operations and problem types, or accept more request values.
  Removing or newly requiring a member, narrowing what a request accepts, widening what a
  response returns (other than with a new problem type), or changing a schema identity is a new
  major. A served limit moves only in its declared
  direction: a `request` limit may grow, a `response` limit may shrink, a `both` limit is fixed.
- **Unknown problem codes:** the problem registry `problem-types.json` is open, and a later v1
  revision may add a problem type. A client handles a problem `code` it does not know by its HTTP
  status and `retryable` and never fails on it; a registered `code` is never removed or renamed
  within v1. Every other response enumeration is closed.
- **Unknown members:** an open request object ignores an unknown member; a closed one
  (`additionalProperties: false`, such as the `world.action.v1` payload) rejects it; a
  schema-less value such as `EventView.payload` is preserved verbatim. Response schemas are
  closed for drift detection, and a client ignores unknown response members.
- **Unknown versions fail closed:** a request naming an unsupported schema or Event version
  (`world.action`, `world.action.v2`) is the `400` `unsupported-version` problem with no upcast
  or fallback, and an execution profile the deployment cannot serve is the `409`
  `incompatible-profile` problem.
- **API major:** the major is the first path segment. A request under any other major
  (`/v<digits>/...` other than `/v1/...`) is the `400` `unsupported-version` problem whose
  `instance` is the request path; any other unrouted path is the `404`
  `not-found-or-unavailable` problem. A client falls back only after this explicit answer.
