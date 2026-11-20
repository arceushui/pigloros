# Gateway client seam profile requirements

Profile `pigloros.w8.gateway-client-seam`, claim layer `GatewayClientConformance = 3`, subject
adapter `public-gateway-protocol`, provider `pigloros.fixture.gateway-client-conformance`
contract `2.0.0`, ABI 1.0 (Redmine #1295; owner decisions of 2026-11-07 on #1295). The normative
surface is the served routes of the Draft Gateway v1 contract `contracts/gateway/v1/openapi.json`
and its RFC 9457 problem-type registry (#301, #1312); `scripts/check_gateway_contract.py`
validates every expected response below against that description. There is no Golden Path
transition, Scenario Room execution, or new authentication or action contract in this profile;
Scenario Room authoring is the immutable revision routes of #303. No fixture relies on a live
service or on the Gateway implementation as its oracle: every expected exchange is written by
`scripts/generate_gateway_conformance_fixtures.py` from this text.

## 1. Case payload

A case payload is RFC 8785 JSON with exactly the members `schema`
(`pigloros.gateway-client-conformance.case.v2`), `family` (the family name) and `subcases`
(1 to 64). There is no reader for provider contract 1.0.0. A sub-case has exactly `id`
(`<prefix>.<n>`), `title`, `composition` (`open`, `authorized`, `authorized-air-gapped`,
`authorized-consented`, `authorized-rooms`, `authorized-erasure`, `authorized-erasure-held`,
`authorized-erasure-expired` or `authorized-erasure-closed`), `exchanges` (1 to 128), and
optionally `canary` (1 to 64 printable ASCII bytes). An exchange has exactly `router`
(`loopback` or `spectator`), `method` (`GET` or `POST`), `path`, `expect`, and optionally
`actor` (`true`), `body` (any JSON value other than null) and `capture` (`"timeline"`,
`"consent"`, `"room"` or `"erasure"`). An
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
| session | `GET /v1/session` | `session.read` |
| revoke | `POST /v1/me/consent-revocations` | `consent.revoke` |
| erasures | `POST /v1/me/erasures` | `erasure.request` |
| erasure | `GET /v1/me/erasures/:erasure` | `erasure.read` |
| rooms | `POST /v1/scenario-rooms` | `scenario-room.create` |
| revisions | `POST /v1/scenario-rooms/:room/revisions` | `scenario-room.derive` |
| revision | `GET /v1/scenario-rooms/:room/revisions/:revision` | `scenario-room.read` |

An exchange whose route capability the attempt does not hold is not sent; its observation is
`{"refused": "capability-denied"}`. The literal `{timeline}` in a path is replaced by the `id`
of the response of the last earlier sent exchange of the sub-case that sets `capture` to
`timeline`; a path that uses it before any such capture is outside the grammar. The literal
`{room}` in a path is likewise the `id` of the response of the last earlier sent exchange that
sets `capture` to `room`, and `:revision` is a positive decimal integer without a leading zero.
The literal `{erasure}` in a path is the `request_id` of the response of the last earlier sent
exchange that sets `capture` to `erasure`.
The literal
`{consent}` in a request body is replaced by the `consent_ref` of the first member of
`consents` of the response of the last earlier sent exchange that sets `capture` to `consent`;
a body that uses it before any such capture is outside the grammar. A capturing exchange that is refused captures
nothing, and a captured response with no text `id` leaves the slot empty, so the exchanges that use
it cannot match.

## 3. Compositions

Every sub-case runs on its own fresh in-process Gateway over a verified empty in-memory erasure
host, driven through the `router` (loopback) or `spectator_router` (the non-loopback public
listener) of the same Gateway with raw HTTP requests, without any socket. No network is used
in either execution mode, so Local and Air-Gapped executions are the same.

- `open`: no host authorizer (the default Gateway).
- `authorized`: the production serve composition with a fixture Local Principal document,
  from which no production authority is sourced (ADR-108), over a fresh store that its first
  `serve` binds to the Local execution mode `gateway-mode-local-v1` (ADR-134) with no operator
  network grant. The document is provisioned and recomposed through the production Local
  Principal path, and the Gateway requires that Principal for every protected operation. The
  Principal's ID is the 16 bytes `0x01` (`01040G2081040G2081040G2081`). Its one grant, issued at
  authority position 1 and binding no consent, is for actor `01JC0GATEWAYF1XTVREACT0R00` and the
  operations `timeline.create` (resource `timeline`, action `create`), `timeline.events.read`
  (resource `timeline.events`, action `read`) and `session.read` (resource `session`, action
  `read`), audience `gateway`. It grants no action, signal or network capability. Action payloads
  name the World body `01JC0GATEWAYF1XTVREB0DY000`. An exchange with `actor` sends
  `x-piglor-actor-entity: 01JC0GATEWAYF1XTVREACT0R00`.
- `authorized-air-gapped`: the same composition over a store bound to the Air-Gapped execution
  mode `gateway-mode-air-gapped-v1`.
- `authorized-consented`: the `authorized` composition (#309) whose fixture Local Principal is
  also granted `consent.revoke` (resource `consent`, action `revoke`) and binds one consent of
  the fixture actor to itself, purpose `operation`, data category `timeline`, export not
  permitted, so it governs `timeline.create`. The consent is recorded at sequence 1 of the Principal's consent
  Timeline; the consent-bound grant is issued at position 1 of its own authority Timeline, so
  the Principal's Session generation is 3 until the consent is revoked.
- `authorized-erasure`: the `authorized` composition (#1449) whose fixture Local Principal is
  granted only `erasure.request` (resource `erasure`, action `request`) and `erasure.read`
  (resource `erasure.status`, action `read`), served with the Local erasure authority (ADR-136):
  a fixture deployment trust state holds an operator-signed TPS1 whose one root is the fixture
  `erasure-bundle/fixture` root, the production `provision_local_erasure` registers a fixture
  role-2 signer and builds the bundle, which that root signs, and the Gateway's own
  `serve --require-local-erasure` loader composes the authority from the four serve
  credentials. No driver runs, so an admitted erasure stays `submitted`.
  `authorized-erasure-held` is the same composition in which the fixture actor already has one
  erasure in progress, admitted before the Gateway serves; `authorized-erasure-expired` is the
  same composition under a bundle that expired at Unix second 1; `authorized-erasure-closed`
  is the same Principal served with the closed erasure authority.
- `authorized-rooms`: the `authorized` composition (#303) whose fixture Local Principal is
  granted `timeline.create`, `session.read`, `consent.revoke`, `scenario-room.create` (resource `scenario-room`,
  action `create`), `scenario-room.derive` (resource `scenario-room.revision`, action `derive`)
  and `scenario-room.read` (resource `scenario-room.revisions`, action `read`), records the
  single-participant governance record `01JC0GATEWAYW90G0VERN00001`, and binds one consent of
  the fixture actor to itself, purpose `operation`, data category `timeline`, export permitted,
  so it governs `timeline.create` and a room may name it as its `privacy_export_ref`. Its
  Session generation is 3. A fixture room has the persona participant
  `01JC0GATEWAYF1XTVREACT0R00` (the fixture actor) and the society participant
  `01JC0GATEWAYW90S0C1ETY0001`, and requests the reviewed host catalogue plugin
  `gateway-world-actions` `0.1.0`, which owns the Event type `world.action.v1`, with one rule
  `gateway-world-actions.nudge.scale`.

A request `body` is sent as compact JSON with `content-type: application/json`. Every request
carries `idempotency-key: <sub-case id>`; routes without an idempotency key ignore it, and two
identical actions of one sub-case are an exact retry.

## 4. Observations and normalization

The observation of a sent exchange is `{"status": <code>, "body": <body>}`. The body is
`{"json": <value>}` when the response bytes are one JSON value, else the string `"non-json"`.
The value is normalized. First, every text value equal to the consent, room or erasure the
sub-case has captured so far (including by this exchange) becomes the slot literal
`"{consent}"`, `"{room}"` or `"{erasure}"`, so a response echoing the captured consent, room
or erasure is pinned and an echo of any other value stays raw. Then the identities, cursors and messages the documentation does not
fix are permitted nondeterministic operational fields:

- a member `next_cursor` whose value is `v1.<64 lowercase hex>.<ULID>.<positive integer>`
  becomes `"<cursor>"`;
- a member `detail` with a text value becomes `"<message>"`;
- in a member `id`, `consent_ref`, `timeline_id`, `event_id` or `instance` with a text value,
  every `/`-separated segment that is a ULID becomes `<ulid>`, so such a member that is a ULID
  becomes `"<ulid>"` (a routed problem names its route template and carries no ID; only the
  path of a request no route serves can carry one);
- a member `correlation_id` whose value is 32 lowercase hex digits, not all zero, becomes
  `"<correlation>"`, and a member `descriptor_hash` whose value is 64 lowercase hex digits, not
  all zero, becomes `"<hash>"` (a room's correlation ID is drawn per room, and its descriptor
  hash covers it);
- in an object whose `schema_id` is `urn:pigloros:gateway:v1:schema:scenario-room-revision`,
  the `digest` of its member `provenance`, when it is 64 lowercase hex digits not all zero,
  becomes `"<hash>"` (a room revision's provenance covers its descriptor hash and Event ID);
  so does the `provenance` `digest` of an `urn:pigloros:gateway:v1:schema:erasure` object and
  the `bound_inputs` `trust` of an `urn:pigloros:gateway:v1:schema:admission-receipt` object
  (the ERS1 state digest and the bundle digest cover the store's own erasure identity, drawn
  per store); every other provenance digest, such as a Session's, stays as it is;
- a member `request_id`, `operation_id` or `operation_url` is treated as a member `id`: every
  ULID segment of it becomes `<ulid>`, after a value equal to the captured erasure became
  `"{erasure}"`.

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

Usage: one execution step per sent exchange, the response body bytes as output bytes, and
the Events each `201` response commits: one for the signals, actions and revoke routes, and two
(the request claim and the revision) for the rooms and revisions routes. The other counters
are 0.

## 6. Families

- **positive:** `/health` answers `{"ok": true}`; a created Timeline polls an empty exhausted
  page; a committed Society Signal is polled back with its canonical payload; `/v1/ledger` is
  empty; the fixture Principal's `/v1/session` discloses its grants, generation 1, binding
  epoch 1, no consent, the EPF1 profile `unavailable`, and the Local mode with network
  `denied` on `authorized` or the Air-Gapped mode with network `absent` on
  `authorized-air-gapped`, each with the golden mode-profile digest and the provenance digest
  the `Session` schema states; on `authorized-consented` a revoked consent stops the operation
  it governs and is revoked exactly once; on `authorized-rooms` a Scenario Room naming the
  Principal's consent (captured from its Session) is created as revision 1 (`201`), an exact
  retry answers the same revision (`200`), the revision reads back (`200`), and a derive from
  revision 1 commits revision 2 as the third Event of the room Timeline (`201`), each echoing
  the captured room and consent and carrying the plugin composition hash and the rule set
  hash ADR-041 amendment A4 states; the sub-case's one idempotency key used for a different
  create is the `409` `idempotency-conflict` problem, a derive repeated from the same parent
  answers the head (`200`, the ADR-041 section 7 duplicate) and a different derive from that
  non-head parent is the `409` `append-conflict` problem; on `authorized-erasure` a
  private-subject-data erasure is admitted with the `202` admission receipt (the BLAKE3 of the
  sub-case ID as its key digest, the pinned Local erasure policy and the Local mode profile as
  bound inputs), an exact retry answers the same receipt, the same key for consented shared
  data is the `409` `idempotency-conflict` problem, and the erasure reads back `submitted` with
  generation 0, no obligation and the `exact` claim (#1449).
- **denied** (`capability-denied`): an action without a host authorizer is the `401`
  `unauthenticated` problem and an action the fixture authority does not grant is the `403`
  `unauthorized` problem, each followed by an empty poll (denial without state change); a route
  whose capability the attempt does not hold is refused; a read on the `authorized` Gateway
  without the actor header is the `401` `unauthenticated` problem; a Session read without the
  actor header on the `authorized` Gateway, and one on the `open` Gateway (which has no
  Principal), is the `401` `unauthenticated` problem; a room whose `privacy_export_ref` names a
  consent the Principal does not hold is the `403` `consent-invalid` problem, one naming its
  consent after the consent is revoked is the `403` `revoked` problem, and one whose persona the
  grant's actors do not cover is the `403` `unauthorized` problem; on `authorized` an erasure
  request is the `403` `unauthorized` problem, an erasure read the `404`
  `not-found-or-unavailable` problem and an erasure request without the actor header the `401`
  `unauthenticated` problem; on `authorized-erasure-closed` an erasure request is the
  non-retryable `503` `temporarily-unavailable` problem and a read is `404`; on
  `authorized-erasure-expired` an erasure request is the non-retryable `503`
  `temporarily-unavailable` problem.
- **malformed** (`malformed-payload`): `cursor` with `from_seq` and `limit=101` are the `400`
  `invalid-request` problem; a Timeline ID that is not a ULID is `400` `invalid-request`;
  integer action `params` are the `422` `admission-rejected` problem, and nothing is committed;
  a room naming a governance record the host does not record is the `422`
  `admission-rejected` problem; on `authorized-erasure` an erasure request whose
  `impact_acknowledged` is false is `400` `invalid-request`, one for `public-record` is the
  `400` `erasure-scope-retained` problem and an erasure ID that is not a ULID is `400`
  `invalid-request`.
- **resource-exhaustion** (`resource-limit`): 64 root Timelines are created and the 65th is the
  `429` `resource-limit-exceeded` problem; on `authorized-erasure-held` another erasure request
  of the subject is the retryable `429` `resource-limit-exceeded` problem.
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
