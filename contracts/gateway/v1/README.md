# Gateway v1 contract

The language-neutral contract of the PiglorOS Gateway, the only public application boundary
(ADR-022, Redmine #301). A client needs these files and nothing else: no Rust source, private
crate or database.

| File | What it is |
|------|------------|
| [`openapi.json`](openapi.json) | The canonical description: OpenAPI 3.1.1 with the JSON Schema 2020-12 dialect. |
| [`problem-types.json`](problem-types.json) | The open RFC 9457 problem-type registry: every failure `code`, its `type` URN, `title` and permitted HTTP statuses. A later v1 revision may add a problem type (rule 5). |
| [`execution-mode-profiles.json`](execution-mode-profiles.json) | The reviewed GMD1 declaration of the two Gateway execution-mode profiles (ADR-134), from which a client recomputes every `mode_profile_digest`. Its closed schema is [`execution-mode-profiles.schema.json`](execution-mode-profiles.schema.json). |
| [`examples/`](examples/) | Golden request and response pairs, positive and fail-closed, for every operation. |
| [`compatibility/baseline.json`](compatibility/baseline.json) | The frozen v1 baseline: every served operation, the components it reaches and the problem registry as published. |
| [`compatibility/examples/`](compatibility/examples/) | The frozen golden examples that stay valid for the whole compatibility window. |

`scripts/check_gateway_contract.py` checks all of them in CI, together with the served responses
recorded by the gateway-client-conformance fixtures. Those fixtures are also executed against the
served routers by `apps/pos-gateway-conformance-adapter`, so a served response they cover cannot
drift from the description. The golden examples are validated against the description only; the
Gateway's own router tests cover the unknown-member and API-major negotiation behavior they show.

## Operations

Every operation has an `operationId` and an `x-pigloros-status`:

- `served`: the Gateway serves it today and its responses are drift-checked. `x-pigloros-listeners`
  names the listeners that serve it: `loopback` (the complete local API) or also `public` (the
  spectator-only Prediction Ledger routes of a non-loopback bind).
- `draft`: a Wave 9 resource family (owner ticket in `x-pigloros-owner`, #302 to #309). It is not
  served yet; only its golden examples validate, and it may change until its owner serves it.

## Schemas and media types

- Every component schema has a stable `$id` of the form `urn:pigloros:gateway:v1:schema:<name>`.
  Draft schemas carry `x-pigloros-maturity: draft`. `Session` and every Draft resource read
  compose the resource envelope (schema ID, resource ID, revision or generation, provenance,
  `mode_profile`, `execution_profile` and capability-filtered availability, whose withheld
  reasons are `unknown`, `unauthorized`, `revoked`, `deleted` and `unavailable`). The envelope and
  the schemas it reaches are frozen with `GET /v1/session` (#1362), so every Draft resource
  composes the frozen envelope.
- `GET /v1/session` is served (#1362): the acting Principal's own Session, derived by the host
  from its recorded grant, the bound execution mode and the authority evaluator, never from the
  request. It requires the `session.read` grant like any protected operation.
  `contract.contract_version` is `1.0.0-draft` until Wave 9 acceptance and `1.0.0` from then on;
  a client accepts both.
- `POST /v1/me/consent-revocations` is served (#309): the acting Principal revokes one of the
  consents its `Session` lists, named by `consent_ref`, under the `consent.revoke` grant. The
  revocation is a `consent.revoked.v1` Event on the Principal's consent Timeline whose sequence
  is the ADR-039 fence; it takes effect before the next decision. From then on every operation
  the consent governs (the granted operations of its purpose and data categories) is
  `403 revoked`; every other operation stays available, and no consent ever governs reading the
  Session, revoking a consent or the network capability. A consent the acting entity is not a
  party to (its subject or grantee) is `404 not-found-or-unavailable`, and the Session lists only
  the consents the acting entity is a party to. Revocation stops future protected work and deletes nothing;
  erasure is a separate operation (see [Erasure](#erasure)).
- Open identifiers and server invariants. Frozen with Session, `ExecutionProfileId`,
  `GatewayModeProfileId`, `mode`, `execution_profile.reason` and `network_grants` are bounded,
  pattern-checked strings rather than enumerations, so a later v1 revision can add a profile,
  mode, reason or operator grant. What the Gateway emits today is a server invariant stated in
  each schema: the profile families of rule 3, the two modes `local` and `air-gapped` of
  `gateway-mode-local-v1` and `gateway-mode-air-gapped-v1`, the reason `not-installed`, and the
  operator grants `owntracks` and `public-read-only` (none in Air-Gapped mode). A client handles
  a value it does not know as unknown and never fails on it. `execution_profile.state`,
  `provenance.origin` and the Session `network` posture are deliberately closed in v1, like
  every other response enumeration except the problem `code`.
- `mode_profile` is the Gateway execution-mode profile (GMP1, ADR-134) the resource was produced
  under: its ID (`gateway-mode-local-v1` or `gateway-mode-air-gapped-v1`), mode, digest and the
  store `binding_epoch` recorded in the producing commit's evidence. Only `Session` reports the
  current binding, with the operator's `network_grants` and the Principal's `network` (`absent`
  in Air-Gapped mode; in Local mode `capability-granted` only for a Principal holding
  `gateway.network.v1`, a capability that authorizes no operation in v1, otherwise `denied`). An
  `Export` lists every produced-under binding in `produced_under_mode_profiles`. GMP1 profiles are
  composition-verified, never installed or qualified, and carry no reproducibility claim. Their
  public declaration is `execution-mode-profiles.json` (closed schema
  `execution-mode-profiles.schema.json`); `mode_profile_digest` is
  BLAKE3(UTF-8 `PiglorOS.GatewayModeProfile.v1` || 0x00 || canonical GMP1 bytes). The checker
  pins each profile's rotation chain (ADR-135 §7.6): every revision's digest, oldest first, each
  revision naming its predecessor as `previous_mode_profile_digest`. The examples under
  `examples/` and the gateway-client-conformance fixtures name the head; a frozen example under
  `compatibility/examples/` may name any revision of the chain, because rule 6 freezes its wire
  validity, not what the current release serves.
- The Scenario Room routes are served (#303): `createScenarioRoom`, `deriveScenarioRoomRevision`
  and `getScenarioRoomRevision`, each under its own grant (`scenario-room.create`, `.derive`,
  `.read`). Every `persona` participant must be an actor the Principal's grant covers, and
  `governance_ref` must be the host's governance record: the optional `governance_record_id` of
  the Local Principal provisioning document. A room may name only the Plugin of the reviewed host
  catalogue entry the Gateway ships (`gateway-world-actions` `0.1.0`). Each room is one Timeline,
  and the revision's `commit` is its `room.revision.v1` Event. `privacy_export_ref` must name a consent the
  acting Principal holds (the `consent_ref` of its `consent.granted.v1` Event): one it does not
  hold is `403 consent-invalid` and a revoked one `403 revoked`, checked under the operation's
  permit, so a revocation takes effect from the next room operation. The check precedes the
  Idempotency-Key lookup, so even an exact retry after the consent was revoked is `403 revoked`:
  a revoked consent stops all protected work on the room, replays included. Under decision 2a the
  consent need not match the room's purpose or data categories; a later #309 consent scope may
  narrow that. A room's Timeline is an ordinary root Timeline: it shares the root-Timeline
  ceiling and its `room.revision.v1` and `room.request.v1` Events are readable through
  `GET /v1/timelines/{timeline_id}/events` with the `timeline.events.read` grant.
- A malformed body, a missing or malformed `Idempotency-Key` and a malformed room ID are
  `400 invalid-request` before the authority decision and before any lookup; every other
  answer of a room operation follows the decision. An `Idempotency-Key` of a room operation is
  claimed once, as a plain Event on the host's request Timeline for a creation, or on the room's
  own Timeline for a derive, and stays claimed for that Timeline's lifetime (no ADR-038
  retention window applies to it). A refused request, a stale derive and a ceiling refusal
  claim nothing, so the key stays free for another request. A derive whose parent is not the
  head is decided before any key lookup or claim: it answers with the revision already derived
  from that parent (`200`) when it hashes like that revision (ADR-041 section 7), and is
  otherwise `409 append-conflict`, even when its `Idempotency-Key` was used for a different
  request, which would else be `409 idempotency-conflict`. A new room's ID is its claim's Event ID, so a retry after an interrupted attempt finishes the same
  room. A creation claims on the host's request Timeline (at most one claim per room, so the
  root-Timeline ceiling of 64 keeps it far below its Event ceiling); a derive claims on the room's
  own Timeline, which holds its claims and revisions, so a room holds at most half of
  `events_per_timeline` revisions. A ceiling is a permanent `429 resource-limit-exceeded`
  (`retryable: false`), as on every other route. Finding a claim reads its Timeline once, since
  the host has no entity index.
- A `ScenarioRoomRevision` (#303) is `principal-authored`. Its `provenance.digest` is
  BLAKE3(UTF-8 `PiglorOS.GatewayScenarioRoomRevision.v1` || 0x00 || the 32 bytes of
  `descriptor.descriptor_hash` || the 16 big-endian bytes of `commit.event_id` decoded as a
  Crockford base32 ULID), in lower-case hex. The descriptor's `rule_set_hash` and `descriptor_hash` are the RFC 8785
  hashes of the ADR-041 amendment of #303; `plugin_composition_hash` depends on the host's bundled
  Plugins and cannot be recomputed by a client. This `provenance.digest` is what
  `createDecisionPreview` binds as `scenario_room.digest`.
- `execution_profile` is EPF1-only (ADR-104): `state: installed` with an ADR-058 `profile_id` and
  its raw EPF1 `profile_digest`, or `state: unavailable` with `reason: not-installed`. Every
  Gateway resource reports `unavailable`, except a Decision Preview, which reports the EPF1 it was
  admitted under. In production no preview can be admitted until #1364 or #461 installs an EPF1.
- A request body is `application/json` (`content-type: application/json`; any other type is
  `415 invalid-request`).
- A success body is `application/json`; every failure, including unknown paths (`404`), unserved
  methods (`405`) and oversized bodies (`413`), is `application/problem+json`.
- `x-pigloros-limits` states every normative request and response limit with its value, unit,
  scope, `surface` (`served` or `draft`), `direction` and enforcement: a `schema` limit by the
  named schema keywords, a `runtime` limit by the named problem. The direction says how a served
  limit may move within v1: a `request` limit bounds what a client sends and may only grow, a
  `response` limit bounds what a client receives and may only shrink, and a `both` limit bounds a
  value that travels both ways and is fixed.
- Events are ordered by Timeline sequence (`seq`), never by wall time. Draft values that must
  replay deterministically are integers (micro-units where fractional), never JSON numbers.

## Preferences and OptionSpecs

`POST /v1/preferences`, `POST /v1/option-specs` and their
`GET .../{id}/revisions/{revision}` reads are served (#304). Both resources are user-authored and
subject-scoped: the subject is the acting entity (`x-piglor-actor-entity`), which the Local
Principal's grant must cover, and the operations need the grants `preference.create`,
`preference.read`, `option-spec.create` and `option-spec.read`. A request carries
`schema_version: 1`; any other version is `400 unsupported-version`.

- **Revisions.** Without `parent` a request creates revision 1 of a new resource; with `parent`
  it creates the next revision, and `parent` must name the current head (`409 append-conflict`
  otherwise). A stored revision never changes. Identical content is never deduplicated: an exact
  retry under the same `Idempotency-Key` returns the original revision (`200`), the same key with
  another request is `409 idempotency-conflict`.
- **Erasure.** Erasing a revision also rewrites the request digest its idempotency record kept,
  which is derived from the content, to a constant, so no byte derived from the erased values
  survives. A retry from the subject under that `Idempotency-Key`, with any request, then answers
  `410 deleted`; a retry from another entity is `409 idempotency-conflict` and never learns of the
  erasure.
- **Views.** A revision is answered only to its subject; any other caller, and an unknown or
  foreign parent, gets `404 not-found-or-unavailable`. A revision its subject erased answers
  `410 deleted` to that subject from a payload-free tombstone (resource, revision, subject and
  digest) and `404` to everyone else; no erased value is reconstructed. The Gateway keeps the
  revisions in its own store, outside every Timeline, with the execution-mode binding their
  commit recorded (`mode_profile`).
- **Digests.** `digest` is BLAKE3 of the ASCII domain tag
  `PiglorOS.GatewayPreferenceRevision.v1` or `PiglorOS.GatewayOptionSpecRevision.v1`, a 0x00
  byte, and the revision's canonical bytes: the RFC 8949 §4.2.1 deterministic CBOR array
  `[schema_id, schema_version, id, revision, parent_revision, subject_entity_id, entries]`, where
  `schema_id` is the literal `$id` URN of the revision schema
  (`urn:pigloros:gateway:v1:schema:preference-revision` or
  `urn:pigloros:gateway:v1:schema:option-spec-revision`), IDs are canonical ULID text and
  `parent_revision` is null for revision 1. A Preference entry is
  `[dimension, weight_micro]`, ordered by `dimension`; an OptionSpec entry is
  `[key, label, tags, lean_hint_micro, coordinates]` in the authored order, `tags` in byte
  order, an absent `lean_hint_micro` or `coordinates` null and `coordinates` the array
  `[x_micro, z_micro]`. The answered `weights`, `options` and `tags` follow the same order. A
  `revision-ref` names a revision by `id`, `revision` and this `digest`.
  `provenance.digest` is BLAKE3 of `PiglorOS.GatewayRevisionProvenance.v1`, a 0x00 byte and the
  deterministic CBOR array `[origin, principal_id, subject_entity_id, mode_profile_id,
  mode_profile_digest, binding_epoch, digest]`: text, ULIDs and lower-case hex digests, and an
  unsigned `binding_epoch`. The golden examples carry recomputed values.

## Decision Previews

`POST /v1/decision-previews` (`createDecisionPreview`) and
`GET /v1/decision-previews/{preview_id}` (`getDecisionPreview`) are served (#305, ADR-140), each
under its own grant: `decision-preview.create` (resource `decision-preview`) and
`decision-preview.read` (resource `decision-preview.status`). A preview is the
`pigloros.match-score.v1` Recommendation of the acting entity's own Preference and OptionSpec
revisions, bound to one exact Scenario Room revision and one installed EPF1. Every proposal is
inert, and nothing reaches the real world.

- **Admission order.** A malformed body, a missing or malformed `Idempotency-Key`, a malformed
  ULID, a `schema_version` that is any number other than the integer 1 (`400
  unsupported-version`; one that is no number is `400 invalid-request`), an oversized body (`413`)
  and another content type (`415`) are answered before the authority decision. After the
  decision the Principal takes one of four in-flight slots (`principal_concurrent_operations`);
  a fifth concurrent request, an exact retry included, is a retryable `429` without
  `Retry-After`. The claim of the key is then looked up: the same key with another request is
  `409 idempotency-conflict`. A fresh request passes, in order, the profile gate (a `profile_id`
  outside the bound mode's servable set of rule 3, or without an installed EPF1, is
  `409 incompatible-profile`; until #1364 and #461 install one, every fresh request stops here),
  the room (the revision must exist and its `provenance.digest` must be `scenario_room.digest`),
  the bindings (the Preference and the OptionSpec must be the acting entity's, unerased, with the
  named digests, and the acting entity a `persona` participant of the room) and the room's
  consent. Every room and binding refusal is the same `404 not-found-or-unavailable`, also
  towards the subject of an erased revision. The consent check comes after them, so a `403`
  reveals no more than a `202` would.
- **Commit.** One store command re-runs the claim lookup and the room and binding checks,
  applies the per-minute quota (`principal_admissions_per_minute`: the 33rd new claim of a
  Principal in a fixed one-minute window is a retryable `429` with `Retry-After` until the window
  closes; exact retries and refused requests are not counted) and the store ceiling, then
  appends a `preview.request.v1` claim and its `preview.result.v1` result to the host-owned
  `decision-previews` Timeline. The preview ID is the claim Event's ID. With the single Local
  Principal both quotas are in effect host-wide.
- **Idempotency.** An exact retry (the same key and request) re-checks the room's consent (a
  revoked one is `403 revoked`, recorded as a denial, and nothing is appended), finishes an
  attempt the host interrupted between its two appends, and answers the original `202` receipt
  bytes, also after a restart. "The same bytes" holds whenever a retry is answered `202`; a retry
  can still be refused by the authority, the consent, a bound or an unavailable host. When the
  result append fails after the claim committed, the claim stays: a host that cannot answer
  (erasure containment unavailable, a stale execution-mode binding) is a retryable
  `503 temporarily-unavailable`, and any other store failure is `500 internal-safe-failure`;
  either way an exact retry with the same key finishes the preview.
- **Receipt.** `request_id` and `operation_id` are both the preview ID, `operation_url` is
  `/v1/decision-previews/{preview_id}`, `idempotency_key_digest` is BLAKE3 of the key bytes, and
  `bound_inputs` is exactly `scenario_room`, `preference`, `option_spec` (the request's
  digests), `execution_profile` (the raw EPF1 digest) and `mode_profile` (the GMP1 digest of the
  binding the claim committed under).
- **Timeline.** `decision-previews` is a host Timeline: its identity is derived, it is opened by
  the first admission, and every client route answers for it exactly as for an unknown Timeline;
  it does not count against the root-Timeline ceiling. Each preview uses two Events, so a store
  holds at most `decision_previews_per_store` (5,000) previews; a fresh request beyond that is a
  permanent `429 resource-limit-exceeded` (`retryable: false`). The first preview of a store with
  an active erasure request on a Gateway without a Local erasure composition is a non-retryable
  `503`.
- **Read.** A preview is answered only to the Principal and actor that admitted it; any other
  caller and an unknown ID get the same `404`. The room's consent is re-checked on every read.
  `state` is `admitted` (no result yet, `generation` 1), `committed`, `failed` or `degraded`
  (`generation` 2). `committed` names the `preview.result.v1` Event (its `next_cursor` is null:
  no client reads the Timeline); `failure.code` is `input-deleted` when an input was erased
  before an interrupted attempt was finished. `uncertainty` is `unavailable` and `calibration`
  is `unavailable` with reason `no-resolved-predictions`: no result claims calibration.
- **Degradation.** The result Event records no score, winner or margin, so a read recomputes the
  Recommendation from the bound revisions. Once a Preference or OptionSpec revision of a
  computed preview is erased, the preview is `degraded`: `recommendation` is
  `{"status": "withheld"}` and `availability` withholds `/recommendation` with reason `deleted`
  (state `partial`); `committed` and the input refs stay. A `failed` preview stays `failed` and
  `available`. Degradation writes no Event, so `generation` does not change.
- **Match Score.** An OptionSpec tag matches a Preference dimension when the two are
  byte-identical. An option with `n` matched tags whose weights sum to `S` scores 0 when `n` is
  0, else `sign(S) * floor((2|S| + n) / (2n))` micro-units (the mean, rounded half away from
  zero); unmatched tags do not dilute it, and `lean_hint_micro` and `coordinates` are not used.
  When no option matches, the Recommendation is `insufficient-evidence`. Otherwise `scores` lists
  every option in authored order, `margin_micro` is the largest score minus the second-largest,
  `toss_up` is `margin_micro < 20000`, and `option_key` is the unique best option, or null for a
  Toss-up. The function is frozen: any change to an output is a new function ID.
- **Provenance.** `provenance.digest` (`host-derived`) is BLAKE3 of
  `PiglorOS.GatewayDecisionPreviewProvenance.v1`, a 0x00 byte and the deterministic CBOR array
  `["host-derived", principal_id, actor_entity_id, preview_id, claim_payload_digest,
  result_payload_digest | null, mode_profile_id, mode_profile_digest, binding_epoch]`: IDs as
  ULID text, digests as lower-case hex and the epoch as an unsigned integer. The payload digests
  are BLAKE3 of the claim and result Event payloads, so the digest changes once, when the result
  commits. `mode_profile` is the binding the claim's commit recorded. The golden examples carry
  recomputed values.

## Erasure

`POST /v1/me/erasures` (`requestErasure`) and `GET /v1/me/erasures/{erasure_id}` (`getErasure`)
are served by a Gateway composed with the single-host Local erasure authority (#309, ADR-136).
Each needs its own grant, `erasure.request` (resource `erasure`) or `erasure.read` (resource
`erasure.status`), and both are consent-exempt: a revoked consent never refuses them.

- **Subject and scope.** The subject is the Local Principal acting as `x-piglor-actor-entity`.
  Its data is the root Timelines that actor created and their Forks; Events by the actor in
  other Timelines, imported Timelines and host Timelines are out of scope. A request names one
  `scope` class. `private-subject-data` and `consented-shared-data` are destroyed; the other
  three are always retained, and a request for one is `400 erasure-scope-retained`, answered
  after the authority decision. A subject whose closure exceeds `erasure_closure_targets` is
  `400 erasure-scope-too-large`.
- **Admission.** A malformed body, a body whose `impact_acknowledged` is not `true` and a
  missing `Idempotency-Key` are `400 invalid-request` before the decision. The `erasure_id` is
  derived from the Principal, the actor and the key, so the `202` admission receipt's
  `request_id` and `operation_id` are that id, and `idempotency_key_digest` is BLAKE3 of the key
  bytes. `bound_inputs` binds the `policy`, the `trust` bundle and the `mode_profile` digest of
  the submission. An exact retry answers the same receipt bytes, also after a restart, a
  bundle rotation or a mode migration; the same key with another scope is
  `409 idempotency-conflict`. A subject has one active erasure at a time: another request
  while one has not reached its first receipt or has an active attempt is a retryable
  `429 resource-limit-exceeded` without `Retry-After`. Each actor may submit at most
  `floor((4096 - 512) / A)` erasures over the store's life, where `A` is the number of actors
  of the Local Principal (`erasure_store_requests`); the next is `409 erasure-quota-exhausted`,
  which a retry never clears. A Gateway without a Local erasure composition, or whose trust
  admission has expired, answers a non-retryable `503 temporarily-unavailable`.
- **Operator closure.** The operator can close new erasure admissions durably with
  `piglor-gateway erasure-admissions close <sqlite-path>` and reopen them with `open` (#1408).
  While they are closed, a fresh request is a non-retryable `503 erasure-admissions-closed` and
  nothing is requested; only reopening clears it. An exact retry of an admitted request still
  answers its receipt, and `getErasure` and the completion of admitted requests continue, also
  across a restart.
- **Projection.** An `Erasure` is answered only to its subject: an unknown id, another
  subject's id, a refused decision (also one past the denial-record bound, which only a refused
  caller reaches) and a Gateway without a Local erasure composition all answer the same
  `404 not-found-or-unavailable`. A saturated store executor is the one
  `429 resource-limit-exceeded` it answers, retryable without `Retry-After`. `state` is the
  ADR-060 lifecycle of the verified ERS1 head, `provenance.digest` the raw ERS1 state digest
  (`host-derived`), and `mode_profile` the binding the erasure was submitted under.
  `generation` is the head's ERS1 ordinal times 2^16 plus the acknowledgements committed in the
  active attempt; every attempt closes with a new ERS1 state, so it never decreases.
  `acknowledgements` counts the frozen obligations and the positive acknowledgements, in total
  and per acknowledgement class (`classes`, an open pattern string). A Local deployment cannot
  prove that no backup or plaintext Event payload survives, so a Local erasure ends in
  `partial-failure` with those classes negative. Nothing an erasure answer carries names a
  Timeline, Fork, selector, target, owner or bundle content.
- **Redaction generation.** An `Erasure` served by a Local erasure composition always carries
  `redaction_generation` (#1407): the number of client-cache redaction generations (ELCG1) the
  store has committed, across every erasure of every subject, `0` before the first. The store
  raises it by one in the same transaction that commits each `client-cache-signal` owner
  effect, so it never decreases, also across a restart, and never exceeds 2^53-1, the schema's
  JSON-safe `maximum`: a store at that bound refuses the next commit rather than answer a value
  a JSON client cannot represent. The member is optional in the schema, so a v1 client must
  not require it. See *Client cache* for what a client does with it. The value is store-wide,
  not per subject: it discloses to the caller how many client-cache redactions the host has
  committed, across every subject. This is intended (owner decision on #1407): every caller of
  `getErasure` on a Local host is an actor of its one Local Principal.

## Client cache

The rules below are normative for the Gateway and for every supported client of v1 (ADR-136
follow-up F2, #1407). A *managed representation* is any response body of a protected loopback
operation: a Timeline's Events, a Session, a consent, a Scenario Room, Preference or OptionSpec
revision, a Decision Preview or its admission receipt, an erasure receipt or projection, and every
problem.

1. **The Gateway marks every answer `no-store`.** Every response of every operation, problems
   included, carries `Cache-Control: no-store` (the required `CacheControl` response header of
   `openapi.json`), so no cache may store it. The same router layer also marks the routes
   outside `/v1` (`/`, `/ledger` and `/health`) and every unrouted answer: one rule covers every
   response the Gateway's router produces. A connection-level error that the HTTP server
   writes before any request reaches the router, and a connection the server closes after a
   handler panic, carry no representation and so no header.
2. **A supported client MUST NOT persist a managed representation.** It may hold one in memory
   only for as long as it renders or acts on it. RFC 9111 §5.2.2.5 states that `no-store` is
   not a reliable or sufficient mechanism for ensuring privacy: it binds caches, not the
   application that already holds the bytes. This client rule, not the header alone, carries the
   guarantee.
3. **A supported client MUST re-read and drop its copies after an erasure.** Once `getErasure`
   shows the `client-cache-signal` acknowledgement class positive (`acknowledgements.classes`),
   the client drops every local copy of a managed representation, including one held in memory,
   and re-reads what it still needs. A client that sees `redaction_generation` rise above the
   value it last saw does the same. After the redaction generation commits, the managed
   representations report the erasure: the subject's frozen Timeline is `403 deleted`, an
   erased Preference or OptionSpec revision is `410 deleted`, and the erasure's `replay_claim`
   is weakened (for a Local erasure `exact-authoritative-with-redacted-views` or weaker; it
   never strengthens).
4. **Withheld members.** A representation that mixes erased and kept members reports each
   erased member in `availability.withheld` as `{member, reason: "deleted"}`, with
   `availability.state` `partial`, or `unavailable` when nothing is left to show. A `degraded`
   Decision Preview withholds `/recommendation` with reason `deleted` and state `partial`; every
   other erased resource is wholly refused as in rule 3, so its `availability` withholds nothing.
5. **`Clear-Site-Data` is not sent.** The `Clear-Site-Data` response header (W3C) is a browser
   mechanism and only a precedent for rule 3: the Gateway never sends it, and a client must not
   wait for it.

## Problems

Every failure body has `type` (`urn:pigloros:gateway:v1:problem:<code>`), `title`, `status`,
`detail`, `instance`, `code`, `schema_id` (`urn:pigloros:gateway:v1:schema:problem`) and
`retryable`. Branch on `code`, never on `detail`: its wording is not part of the contract.
`instance` is the matched route template (for example `/v1/timelines/{timeline_id}/events`), so
it never echoes an identifier; a request no route matches carries its request path. A protected
lookup answers `not-found-or-unavailable` and never reveals whether the resource exists.
`retryable: true` means an identical retry may succeed. The registry is open: a client handles a
`code` it does not know by its HTTP status and `retryable` and never fails on it (rule 5). A
`503` is not always transient: `erasure-admissions-closed` stays until the operator reopens
erasure admissions, so it is not retryable.

Every loopback operation except `/health` and the public Ledger reads is protected by the host's
Local Principal (#1361): loopback reachability is the trust boundary, there is no credential
scheme, and a request names the entity it acts as in the optional `x-piglor-actor-entity` header,
which the Principal's grant must cover; a Society Signal's `entity_id` must be that entity. A
host without a provisioned Local Principal answers every protected operation
`401 unauthenticated` before reading its body, and so does a request without a valid actor. A
denied createPrediction is `403 unauthorized` or `403 revoked`, like a write while Ledger writes
are disabled. An authority decision precedes any protected
lookup, so a caller without a read grant receives the same answer for an unknown Timeline as for
an existing one. A missing Principal, or
authentication evidence outside its validity window, is `401 unauthenticated`; a missing grant
or capability is `403 unauthorized`; a grant, a delegation parent or consent that was revoked at
the evaluation or commit fence, or expired, is `403 revoked`; absent or unbound consent is
`403 consent-invalid`; a host that cannot vouch for its revocation state, or cannot durably
record the denial, is `503 temporarily-unavailable` (retryable). Every answered denial is
committed as a payload-free record in the host's authority store before it is answered. Denial
records are bounded per Principal (`principal_denial_records_per_minute`; with the single Local
Principal this is effectively host-wide) and per host (`denial_records_per_minute`) in a fixed
one-minute window that resets on restart, so a burst across a window boundary can reach twice the
bound. A denial over either bound is `429 resource-limit-exceeded` (retryable, with
`Retry-After` until the window closes): it gets no record of its own and is not answered as a
denial, but each bound's suppressed denials are counted in one durable marker per window. A
marker's count is an upper bound: a count whose write had an unknown outcome is re-emitted, so
it may be counted twice but never zero times. The
store keeps at most `authority_denial_records` records and never prunes them; when it is full,
a denial is `503 temporarily-unavailable` instead.

## Idempotency

A mutation that is retry-safe carries an `Idempotency-Key` header of 1 to 128 visible ASCII
characters (schema `idempotency-key`); every Draft mutation requires one, and of the served
routes `POST /v1/timelines/{timeline_id}/actions`, `POST /v1/me/consent-revocations`,
`POST /v1/me/erasures` and `POST /v1/decision-previews` do. A
consent revocation is monotonic: revoking a revoked consent returns its original revocation
(`200`) whatever its key, and the revocation Event records the key (with the Principal and the
acting entity), so reusing it for another consent is `409 idempotency-conflict`, also after a
restart. Without it the request is
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
   reports or serves an Air-Gapped profile. The servable sets are Local {`replay-v1`,
   `deterministic-local-v1`, `live-local-v1`} and Air-Gapped {`replay-v1`,
   `deterministic-air-gapped-v1`, `live-air-gapped-v1`} (ADR-135 §6). They
   are a server invariant, not a schema rule: an `installed` `execution_profile.profile_id` is
   always in the servable set of the resource's `mode_profile.mode`, while the schema keeps the
   identifier open so a later family stays within v1. A profile in the set is served only once
   its EPF1 is installed (ADR-134 §5):

   | Requested ADR-058 profile | Local | Air-Gapped | Served when |
   |---|---|---|---|
   | `replay-v1` | 409 | 409 | #1364 delivers its EPF1 |
   | `deterministic-local-v1` | 409 | 409 always (not servable) | Local: #1364 |
   | `deterministic-air-gapped-v1` | 409 always (not servable) | 409 | Air-Gapped: #1364 |
   | `live-local-v1` | 409 | 409 always (not servable) | Local: #461 |
   | `live-air-gapped-v1` | 409 always (not servable) | 409 | Air-Gapped: #461 installs its EPF1 |

   The positive examples that bind a profile, including the served Decision Preview examples,
   show the answer once its EPF1 is installed.
4. **Unknown members are handled as each schema declares.** An open request object (no
   `additionalProperties: false`) ignores unknown members; a closed one rejects them. A
   schema-less value such as `EventView.payload` is preserved verbatim. Response schemas are
   closed so that the contract detects drift, but a client MUST ignore unknown response members:
   a later v1 revision may add optional ones.
5. **Additive changes only within v1.** Within v1 a change may add an optional member, an
   optional parameter, a response, a response header or an operation, or accept more request
   values, and may append a problem type to `problem-types.json` (a new `Problem` `code`). The
   problem registry is open: a client MUST handle a `code` it does not know by its HTTP status
   and `retryable`, never fail on it, and MUST NOT assume the registry it was built against is
   complete. A registered `code` is never removed or renamed, its `type` and `title` never
   change and none of its statuses is withdrawn within v1. Every other response enumeration is
   closed. Removing a member, parameter, response, response header, security scheme or
   operation, making a member, parameter or response header required in a request (or no longer
   guaranteed in a response), narrowing what a request accepts, widening what a response
   returns (a type, an enumeration value other than a new problem `code`, or a bound), moving a
   served limit against its direction, or changing a schema `$id`, its declared unknown-member
   handling or any other keyword requires a new major that runs in parallel, with an explicit
   migration and retirement decision. The comparison is deliberately conservative:
   `oneOf`/`anyOf`/`allOf`/`prefixItems` keep their shape and `pattern`, `format` and `default`
   stay identical even where a change would be harmless.
6. **Compatibility window.** The served operations frozen in `compatibility/baseline.json` stay
   supported through Wave 10 after Wave 9 acceptance, and every example under
   `compatibility/examples/` stays valid for that window, including the fail-closed ones: a
   request a frozen example rejects stays rejected. Draft operations join the baseline when their
   owner serves them.

`scripts/check_gateway_contract.py` enforces rules 1, 4 (the declaration), 5 and 6: it compares
the contract with the frozen baseline (requests must keep accepting what they accepted, responses
must keep guaranteeing what they guaranteed, a schema reached from both keeps its constraints
exactly, and new codes are only appended to the `Problem` `code` enumeration) and validates the
frozen examples, so a breaking change to a v1 schema fails CI. CI runs it with
`--append-only origin/main`, which also fails when `compatibility/` lost or changed anything
since the merge base with `main`: a pull request cannot loosen the baseline together with the
contract. `servers` and `info.version` are not frozen: a client must not hard-code the server
URL, and the description's revision label is not part of the wire contract. The golden examples
`unsupported-version-api-major`, `not-found-unrouted-path`, `unknown-required-schema-event-type`,
`unsupported-version-legacy-event-type`, `scenario-room-unsupported-schema-version`,
`decision-preview-incompatible-profile`, `decision-preview-profile-not-installed`,
`draft-replay-incompatible-profile`, `preference-unsupported-schema-version` and
`compatible-unknown-optional-member-ignored` are the negotiation and unknown-member cases.

## Changing the contract

- Run `python3 scripts/check_gateway_contract.py` and
  `python3 scripts/test_check_gateway_contract.py` with the hash-pinned `jsonschema` of
  `requirements-pinned-dependencies.txt`.
- When an owner ticket turns a Draft operation into a served one, or adds an optional member,
  parameter, response or header to a served one, run
  `python3 scripts/check_gateway_contract.py --freeze`. It first checks the contract against the
  existing baseline, then appends the newly served operations, the optional additions to frozen
  ones, the components and security schemes they reach, the served limits, any new problem type
  (to the frozen registry and the frozen `Problem` `code` enumeration) and the golden examples
  of served operations. It never rewrites a frozen keyword, and the append-only check accepts
  exactly those additions. Do not edit `compatibility/` by hand.
- Parameters are declared on each operation (not on the path item), each with a `schema`.
- A golden example is `{name, operation_id, request, request_valid, response}`. An example of a
  request no route serves has a null `operation_id` and names its `method` and query-free
  `target`. Its `response` has a `status` and a `body`, and may state its `headers`: an example
  that states them states every required header of the response it answers (case-insensitive
  names, values of the declared schema) and no undeclared one; an example without `headers`
  asserts none, so a header added within v1 leaves every frozen example valid. The
  `client-cache-*` examples show `Cache-Control: no-store` (#1407).
