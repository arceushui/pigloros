# Gateway client seam profile requirements

Profile `pigloros.w8.gateway-client-seam`, claim layer `GatewayClientConformance = 3`, subject
adapter `public-gateway-protocol`, provider `pigloros.fixture.gateway-client-conformance`
contract `2.0.0`, ABI 1.0 (Redmine #1295; owner decisions of 2026-11-07 on #1295). The normative
surface is only the documented Gateway HTTP route table of ADR-014 and
`apps/piglor-gateway/README.md`. There is no OpenAPI document, Golden Path transition, Scenario
Room, or new authentication or action contract in this profile. No fixture relies on a live
service or on the Gateway implementation as its oracle: every expected exchange is written by
`scripts/generate_gateway_conformance_fixtures.py` from this text.

## 1. Case payload

A case payload is RFC 8785 JSON with exactly the members `schema`
(`pigloros.gateway-client-conformance.case.v2`), `family` (the family name) and `subcases`
(1 to 64). There is no reader for provider contract 1.0.0. A sub-case has exactly `id`
(`<prefix>.<n>`), `title`, `composition` (`open` or `authorized`), `exchanges` (1 to 128), and
optionally `canary` (1 to 64 printable ASCII bytes). An exchange has exactly `router`
(`loopback` or `spectator`), `method` (`GET` or `POST`), `path`, `expect`, and optionally
`actor` (`true`), `body` (any JSON value) and `capture` (`"timeline"`). A payload outside this
grammar is the failure `payload-invalid`.

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
of the response of the last earlier exchange of the sub-case that sets `capture`; a path that
uses it before any capture is outside the grammar.

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

A request `body` is sent as compact JSON with `content-type: application/json`.

## 4. Observations and normalization

The observation of a sent exchange is `{"status": <code>, "body": <body>}`. The body is
`{"json": <value>}` when the response bytes are one JSON value, else the string `"non-json"`.
The value is normalized; the identities, cursors and messages the documentation does not fix
are permitted nondeterministic operational fields:

- a member `id` whose value is a ULID becomes `"<ulid>"`;
- a member `next_cursor` whose value is `v1.<64 lowercase hex>.<ULID>.<positive integer>`
  becomes `"<cursor>"`;
- a member `error` with a text value becomes `"<message>"`.

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
- **denied** (`capability-denied`): an action without a host authorizer is `401` and an action
  the fixture authority does not grant is `403`, each followed by an empty poll (denial without
  state change); a route whose capability the attempt does not hold is refused.
- **malformed** (`malformed-payload`): `cursor` with `from_seq` and `limit=101` are `400`; a
  Timeline ID that is not a ULID is `400`; integer action `params` are `422`, and nothing is
  committed.
- **resource-exhaustion** (`resource-limit`): 64 root Timelines are created and the 65th is
  `429`.
- **deletion-redaction:** public-listener redaction. A canary Society Signal is committed
  through the loopback router; on the same Gateway the spectator router answers the Timeline
  events and signals routes with `404`, still answers `/health` and `/v1/ledger`, and no
  spectator response contains the canary; the loopback poll still returns the Event. This is
  redaction from the public surface, not ADR-060 deletion (see `support/limitations.md`).
- **downgrade** (`incompatible-contract`): the legacy `world.action` event type is `400` and
  the legacy `world.action.submit` capability is `403`, with no fallback and nothing committed.
- **independent-evaluation:** the digests of a health exchange and of a created Timeline with
  its empty page.
