# piglor-gateway

The local-first HTTP Gateway: the only public application boundary of PiglorOS (ADR-022). Its
canonical, language-neutral contract is [Gateway v1](../../contracts/gateway/v1/README.md): an
OpenAPI 3.1.1 description, JSON Schema 2020-12 schemas, an RFC 9457 problem registry, golden
examples, and a frozen compatibility baseline. A client needs only that contract, never this
crate's Rust source.

This process is not the product MVP. It serves Timeline creation, Event polling, authenticated
`world.action.v1` proposals, Society Signals, the public Prediction Ledger and the Principal's own
`GET /v1/session` (see [Session](#session)). Every loopback
operation except `/health` and the public Ledger reads is protected by the host-pinned Local
Principal (see [Local Principal](#local-principal)): `GatewayAuthenticationAdapter`
implementations establish minimized `AuthenticatedPrincipalResultV1` evidence, and
`GatewayAuthorization` evaluates the pinned Principal, consent, capability, delegation, expiry
and revocation state. A host without a provisioned Local Principal answers every protected
operation `401 unauthenticated`. The other Wave 9 resource
families (Scenario Rooms, Preferences, OptionSpecs, Decision Previews, Projections, ensembles,
Replays, evidence, exports and erasure) are Draft operations of the contract that their owner
tickets (#303 to #309) will serve; consent revocation is served (#309, see
[Consents](#consents)). WebSocket streaming remains deferred.

## Run

```bash
# Memory store (default loopback): unprovisioned, so protected routes answer 401
cargo run -p piglor-gateway --locked -- serve --profile gateway-mode-local-v1

# SQLite persistence, with the Local Principal provisioned in the database
cargo run -p piglor-gateway --locked -- \
  serve --profile gateway-mode-local-v1 127.0.0.1:8080 /tmp/piglor-gw.db
```

### Execution mode

`serve` requires `--profile`, the Gateway execution-mode profile the process and its store serve
under (ADR-134): `gateway-mode-local-v1` or `gateway-mode-air-gapped-v1`. The binary is the same
for both modes. The profiles are release-compiled from the public declaration
[`execution-mode-profiles.json`](../../contracts/gateway/v1/execution-mode-profiles.json) and are
composition-verified: they are not installed EPF1 profiles and claim no reproducibility.

- **Network features need an operator grant.** Repeat `--network-grant <owntracks|public-read-only>`
  for each one. A non-loopback (spectator) bind needs `public-read-only`; `--owntracks-owner-key`
  needs `owntracks` and a loopback bind. Loopback ingress and the Fork-admission socket are not
  network. Air-Gapped accepts no grant, so it refuses OwnTracks, a non-loopback bind and any
  network `LEDGER_SOURCE`; `LEDGER_SOURCE` must always be a local path. Each refusal happens before
  the store, the ledger or a listener opens.
- **Air-Gapped serves only without a network path (ADR-135 §4).** Before the store, ledger or
  listeners open, `air-gapped-no-route` reads this process's `/proc/self` facts and refuses unless
  its network namespace holds only `lo` (plus the kernel's fallback tunnel devices, without
  addresses, routes or multicast memberships), it holds none of `CAP_NET_ADMIN`, `CAP_NET_RAW` and
  `CAP_SYS_ADMIN` (nor keeps them in its bounding set without `NoNewPrivs`), and a seccomp filter
  is installed. A missing or unparsable fact refuses (a kernel without `/proc/net/igmp` included);
  with IPv6 disabled the IPv6 files count as empty. Run it in a dedicated namespace, for example a
  unit with `PrivateNetwork=yes`, `NoNewPrivileges=yes`, an empty `CapabilityBoundingSet=` and
  `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`; HTTP clients join that namespace
  (`JoinsNamespaceOf=`). The tests run in the equivalent `scripts/air-gapped-namespace.sh` shape.
- **The store records its mode.** The first `serve` of an empty SQLite store binds it to the
  profile. A later `serve` must name the same profile; a populated store that no `serve` bound is
  refused (recreate development stores). Only `migrate-mode` changes the mode, while no other
  process uses the store:

  ```bash
  piglor-gateway migrate-mode /tmp/piglor-gw.db \
    --from gateway-mode-local-v1 --to gateway-mode-air-gapped-v1
  ```

  Air-Gapped mode has no network, so it refuses a Local Principal that holds the network
  capability `gateway.network.v1`: `provision-local-principal` refuses such a document on an
  Air-Gapped store, `serve` refuses to compose over one, and `migrate-mode` to Air-Gapped refuses a
  store whose Principal holds it, leaving the binding unchanged. A store holds one Principal and
  rotation is not supported, so keep the Local mode, or provision a new store whose Principal
  omits the capability.

- **One lock per store.** `serve` and the offline writers (`owntracks pair|rotate|revoke`,
  `provision-local-fork-authority`, `provision-local-principal`, `provision-local-erasure`) hold a
  shared non-blocking lock on
  `<sqlite-path>.gateway-mode.lock`; `migrate-mode` and `erasure-admissions close|open` hold it
  exclusively. Offline writers need a
  store a first `serve` has bound, and never bind one. An Air-Gapped store refuses `owntracks pair`
  and `rotate`. Only Gateway processes write a bound store; other hosts, such as `pos-experiment`,
  are refused.
- **A stale process stops.** A write by a process whose binding a migration replaced commits
  nothing, answers `503` `temporarily-unavailable`, and the process exits nonzero. A read that
  finds the store changed underneath it answers the same way, so a stale process can also stop
  on a `GET`. A Fork-admission listener request answers FARL1 code 8 and stops the process the
  same way.

## Local Principal

Loopback reachability is the Local trust boundary and one host-pinned Local Principal acts behind
it (owner decision D1 on #302); there is no credential scheme on the v1 routes. A protected request
names the entity it acts as in the `x-piglor-actor-entity` header, and the Principal's grant must
cover that entity and the operation. The Principal is provisioned once, explicitly, by the one-shot
[systemd unit](../../deploy/systemd/piglor-gateway-local-principal-provision.service) while the
Gateway is stopped; nothing is provisioned implicitly. Its one credential,
`pigloros.local-principal`, is a TOML document:

```toml
principal_id = "01JC0GATEWAYQ0CA1PR1NC1PA1"
trust_domain = "local"
actor_entity_ids = ["01JC0GATEWAYQ0CA1ACT0R0000"]
operations = ["session.read", "timeline.create", "timeline.events.read", "timeline.signals.append"]
```

The grantable operations are `consent.revoke`, `session.read`, `timeline.create`,
`timeline.events.read`, `timeline.signals.append`, `ledger.predictions.create`,
`world.action.v1.submit`, `preference.create`, `preference.read`, `option-spec.create`,
`option-spec.read`, `scenario-room.create`, `scenario-room.derive`, `scenario-room.read`,
`decision-preview.create` and `decision-preview.read` (ADR-140), plus the Principal network
capability `gateway.network.v1` (ADR-134 §4), which authorizes no operation in v1
and only makes the Session report `network: capability-granted` in Local mode. Encrypt it like the
Fork-admission credentials and provision:

```bash
systemd-creds encrypt --name=pigloros.local-principal \
  --with-key=host+tpm2 local-principal.toml pigloros.local-principal.cred
install -o root -g root -m 0600 pigloros.local-principal.cred \
  /etc/credstore.encrypted/pigloros.local-principal.cred
systemctl start piglor-gateway-local-principal-provision.service
```

Provisioning records one root capability grant in the database's authority records; the authority
registry snapshot and the Principal's evidence are derived from that record. An exact retry is
unchanged. `serve` only reads the record: before each protected decision it compares the record
with the authority it holds and, when another writer recorded a revocation of a Principal without
consents, rebuilds the authority from the record, so the next request is answered `403 revoked`.
A Principal with consents is read through the consent Timeline, which the serving host owns: once
another process records anything to the store, the host's protected reads and writes fail closed,
and once that includes a revocation, every decision its grants cover fails closed as
`503 temporarily-unavailable` (retryable) until the host restarts, and the restarted host sees it
(see [SQLite and host ownership](#sqlite-and-host-ownership)). A signal's `entity_id`
must be the request's actor; any other entity is a recorded `403 unauthorized`. An unprovisioned
host answers every protected route `401` before reading the request body.

### Consents

The document may also bind consents (#309, ADR-039) with a `[consent]` table: the subject who
consents and the actor the consents grant (both listed actors, shared by every consent), and one
`[[consent.grants]]` entry per consent, naming the ADR-059 purpose it covers and its data
categories (operation resources):

```toml
operations = ["consent.revoke", "session.read", "timeline.create", "timeline.events.read"]

[consent]
subject_entity_id = "01JC0GATEWAYQ0CA1ACT0R0000"
grantee_entity_id = "01JC0GATEWAYQ0CA1ACT0R0000"

[[consent.grants]]
purpose = "operation"
data_categories = ["timeline"]
export_permitted = false
```

A consent governs the granted operations whose purpose is its `purpose` (`operation`, `read` or
`action`) and whose resource is one of its `data_categories`; every operation is governed by at
most one consent, and at least one operation by none. No consent governs `session.read`,
`consent.revoke` or `gateway.network.v1`: the owner's exempt set keeps reading the Session
available, revoking must stay possible after any revocation, and the network capability
authorizes no data operation. Provisioning records each consent as one `consent.granted.v1`
Event on the Principal's consent Timeline, a root Timeline under a fixed identity that no client
can create, read or append, and gives each consent its own consent-bound grant of exactly the
operations it governs. All consents of one Principal share one subject and one grantee, the
subject of its one consent Timeline. Provisioning checks before it writes anything: a store that
holds another Principal, or other consents, refuses the document. An exact retry records nothing.

`POST /v1/me/consent-revocations` revokes one consent the Session lists, named by its
`consent_ref`, under the `consent.revoke` grant. The host appends its `consent.revoked.v1` Event
while it holds the authority commit fence exclusively, after every operation admitted before has
completed, and recomposes its consents before the next decision; from then on every operation the
consent governs, a World action included, is `403 revoked`, while every other operation stays
available. Revoking a revoked consent returns the original revocation (`200`), byte for byte: its
`generation` is its fence and its `mode_profile` the binding its commit was produced under. The
host reads the consent Timeline head before every decision, and a restarted host recomposes every
revocation from it. Once another process records anything to the store, the host fails closed
(`503 temporarily-unavailable`) on every read of the consent Timeline, so a revocation recorded
there makes every decision the host's grants cover fail closed until the host restarts; the
restarted host then sees it.

### Preferences and OptionSpecs

`POST /v1/preferences` and `POST /v1/option-specs` (#304) create revision 1 of a user-authored
Preference or OptionSpec, or with `parent` its next revision; `GET .../{id}/revisions/{revision}`
reads one. Each needs its own grant, and the acting entity is the revision's subject: only that
subject is answered, any other caller gets `404`. The Gateway stores the revisions in its own
database tables, outside every Timeline, each in one transaction with its idempotency record and
the execution-mode binding it was produced under, so they survive a restart. A parent must be the
current head (`409 append-conflict`), and only `Idempotency-Key` makes a retry return the original
revision. Erasure (the host-only `GatewayRevisionPortV1::erase_gateway_revision`, which the subject
erasure workflow #309 drives) deletes the row under `secure_delete`, checkpoints the write-ahead
log, rewrites the request digest of the idempotency record to a constant and keeps a payload-free
tombstone, so the subject then reads `410 deleted`, its retries under the key answer `410` and
every other caller gets `404` (or `409` for a retry under the same key). The contract README states the digests.

### Session

`GET /v1/session` (#1362) is a protected read like every other operation: the request names its
actor, and the Principal's grant must cover that actor and `session.read`. The answer is derived
by the host alone: the Principal's ID and the actors of its grant, the names of every grantable
operation and capability its recorded grant covers for that actor (decided by the same evaluator
as every request, recording nothing), its consents (each named by the `EventId` of its
`consent.granted.v1` Event, `granted` or `revoked`), the current execution mode with the operator's `--network-grant` values and the
Principal's network posture (`absent` in Air-Gapped mode; `capability-granted` in Local mode only
with `gateway.network.v1`, otherwise `denied`), and the EPF1 `execution_profile`, `unavailable`
until #461. `generation` is the head position of the recorded authority (both grants when it
binds consents) plus the consent Timeline head, so it advances with every grant, consent or
revocation. The contract's `Session` schema states the provenance digest.

**One Principal per database.** A database holds exactly one Local Principal, and rotation or a
changed grant is not supported yet. Provisioning a different document is refused with
`a different Local Principal`. To recover, provision the original document again (an exact retry
succeeds), or stop the Gateway, create a new database and provision the new document into it.

### Local erasure authority

The single-host erasure authority (ADR-136) is activated by a bundle that a TPS1 root signs. Its
offline first step is the one-shot
[systemd unit](../../deploy/systemd/piglor-gateway-local-erasure-provision.service), run after the
Local Principal is provisioned:

```text
piglor-gateway provision-local-erasure <sqlite-path> --issued-by <erasure-bundle/...>
    --signer-owner <owner-id> --out <absolute-path> [--expiry <unix-seconds>]
    [--signer-epoch <epoch>] [--rotation routine|compromise]
```

The unit reads exactly two credentials: `pigloros.local-erasure-signer`, the role-2 signer's
32-byte Ed25519 seed, and `pigloros.release-trust`, the deployment release anchor that
authenticates the installed TPS1 of the trust state store at `/var/lib/pigloros/trust-state.db`:

```toml
policy_id = "pigloros-local"
operator_public_key = "<64 lowercase hex characters>"
genesis_digest = "<64 lowercase hex characters>"
```

The command first claims `--out`, an absolute path, as a new file with mode `0600`: an existing
file is refused before the store is touched, and the claimed file is removed again if a later step
fails or panics. A run killed outright can leave an empty `--out` behind; it holds no bundle and
is safe to delete before the next run. The installed TPS1 must not be past its
`offline_valid_through`, `--issued-by` must name a current, unrevoked TPS1 root with the
`erasure-bundle/` key id prefix, and the TPS1 must not revoke the signer key
`erasure-signer/<64 hex>`. The `<sqlite-path>` must already be a bound Gateway store; a path that
names no file is refused before the mode lock is taken, so neither a database nor a lock file is
created for it. Provisioning then registers the signer key in the key registry under
`(--signer-owner, role 2, --signer-epoch)`, writes the store's erasure identity once from 32 random
bytes, opens the Erasure Host Timeline `pigloros.local-erasure.host` (the ULID prefix of
`CA("ELHT1", [store_identity])`), and writes the unsigned ELB1 to the claimed file. The holder of
the `erasure-bundle/` root signs it into ELB1S, on another machine if the key lives there.

An exact re-run emits the same bundle. A routine signer rotation re-runs it with a new signer
credential, a higher `--signer-epoch` and a new `--out`. A re-run on a store that already has its
Erasure Host Timeline writes only through the store itself, so it also works once the store holds
erasure requests; a store that holds erasure requests but has no Erasure Host Timeline is refused.
The key registry refuses another key for a registered identity, a lower epoch and a reused key. A
new signer epoch becomes the key registry's only active role-2 key, so the old signer can sign
nothing more, not even for a request pinned to its bundle. A routine rotation (the default
`--rotation routine`) is therefore refused, before any write, while any erasure request pins a
bundle: one frozen before its first attempt, or with an active attempt. Let the driver close those
attempts first, then rotate. After a key compromise, revoke the old signer key
`erasure-signer/<64 hex>` (and the bundle root, if it is compromised too) in the installed TPS1, then
re-run with `--rotation compromise`: the command registers the new key only once the TPS1 revokes the
old signer key and the root or signer of every pinned bundle. Requests pinned to the revoked bundle
stay contained. A re-run with the registered key changes nothing. The pin check and the key registration are
two steps, so run the command only with the Gateway stopped: a serving Gateway could pin a bundle
between them. The unit's `Conflicts=piglor-gateway.service` does this; never run it beside a
serving Gateway by other means. The
command holds the store lock shared, like every offline writer; the unit's
`Conflicts=piglor-gateway.service` stops `serve` while it updates the key registry. The unit writes
`/var/lib/pigloros/local-erasure-bundle.elb1` for the root `erasure-bundle/local`: move the file
away once it is signed, and override `ExecStart` in a drop-in to name another root or epoch.

> **Warning:** the default `--expiry 0` emits a bundle that never expires: it stays valid until a
> TPS1 revokes its root or signer key. Pass `--expiry <unix-seconds>` for a bundle that lapses on
> its own. The unit's fixed `--out` also makes every re-run fail with `--out must name a new file`
> until the previous bundle is moved away.

#### Serving with the Local erasure authority

`serve --require-local-erasure` composes the Local erasure authority over the `SQLite` store; it
needs the store path and runs only under the serve unit, whose credential directory
`/run/credentials/piglor-gateway.service` then holds exactly four more credentials (beside the
three Fork-admission credentials when `--require-local-fork-authority` is also given):

| Credential | Content |
|---|---|
| `pigloros.local-erasure-bundle` | the ELB1 bytes `provision-local-erasure` wrote |
| `pigloros.local-erasure-bundle-signature` | the ELB1S bytes the `erasure-bundle/` root signed |
| `pigloros.local-erasure-signer` | the role-2 signer's 32-byte Ed25519 seed, the key the bundle pins |
| `pigloros.release-trust` | the deployment release anchor (the TOML document above) |

Both serve modes read the installed TPS1 from the trust state store at
`/var/lib/pigloros/trust-state.db` through the same loader as `provision-local-erasure`; an
Air-Gapped deployment seeds that store with its bundled TPS1. Under the store lock and before the
erasure host opens, the Gateway checks the bundle against the TPS1, this binary's policy and
executor, the store's Local Principal and erasure identity and the key registry. Any credential,
trust, store or bundle error refuses startup with a payload-free reason; the Gateway never falls
back to the closed erasure authority when the flag is given. Without the flag (and on a Memory
store, which the flag refuses, or a non-Linux build) the Gateway composes the closed erasure
authority, which admits no Local erasure and refuses a store that holds erasure requests.

Once the host is recovered, a startup sweep deletes unreferenced erasure evidence objects once and
logs only its count (`Swept(n)` or `Skipped`); a skipped sweep never fails startup. The erasure
driver then runs once at startup and every 10 seconds (the compiled `LOCAL_ERASURE_DRIVER_TICK`).
Its admission trigger, which runs it at once after an erasure admission, is wired by the erasure
routes of the next ADR-136 slice (C5c) and is not active yet. Each run submits one driver step per
store command until no request has a step due, so other Gateway requests interleave between steps,
and logs how many request steps failed and were deferred to a later run, when any were. Composition
opens only an existing store bound to a compiled execution mode; it never creates a database. **The step that purges the local replica runs `VACUUM` inside its one
store command and holds every other Gateway request for its duration**, which grows with the store.

**Closing admissions.** `piglor-gateway erasure-admissions close <sqlite-path>` durably closes new
erasure admissions (#1408), `open` reopens them, and `status` prints `Erasure admissions: open` or
`closed`. `close` and `open` print one audit line naming the previous and the new state, such as
`Erasure admissions closed (were open)`. `close` and `open` take the store's exclusive mode lock, so
they refuse to run while `serve` holds the store: stop `serve`, change the record, and start `serve`
again (a commit from another process would make a serving host fail closed, `getErasure` and the
driver included; see [SQLite and host ownership](#sqlite-and-host-ownership)). `status` takes the
shared lock and only reads the record. Every verb refuses an unbound store and runs in every mode,
Air-Gapped included. A store without the record is open. The erasure host reads the record on every
submission and applies it after the exact-replay check: while it is closed a fresh `requestErasure`
is `503 erasure-admissions-closed` (not retryable) and nothing is retained, while an exact retry of
an admitted request still answers its receipt. `getErasure`, the driver and its startup sweep never
read the record, so every admitted request still completes, also across a restart. A record that
cannot be read refuses fresh requests as a retryable `503 temporarily-unavailable`.

**Rollout.** On a store bound by a first `serve`:

1. `provision-local-principal` (the Local Principal);
2. `provision-local-fork-authority`, when the deployment admits Local Forks;
3. `provision-local-erasure`, then sign the emitted ELB1 into ELB1S with the `erasure-bundle/`
   root, offline;
4. install the four credentials above as encrypted credentials of the serve unit and add
   `--require-local-erasure` to its `ExecStart` with a drop-in.

The provisioning commands keep the closed erasure authority, so they must all run before the first
erasure request: a store that holds one refuses them. The shipped
[serve unit](../../deploy/systemd/piglor-gateway.service) does not pass the flag: nothing provisions
the trust state store until #448, and a serve that requires the Local erasure authority without it
refuses to start. Rolling back means removing the drop-in; a store that holds erasure requests then
refuses the closed composition until the flag is restored.

### Separate deterministic experiment host

The Gateway remains an ingress/store façade; it does not run simulation drivers. A store a Gateway
has served is bound to its execution mode (ADR-134), and only Gateway processes write a bound
store, so `pos-experiment` cannot append to it. Run the ADR-019 two-process demonstration against
a SQLite file no Gateway has served; see the
[`pos-experiment` demo guide](../pos-experiment/README.md).

Binding a non-loopback address (with `--network-grant public-read-only`) serves only the public
Prediction Ledger routes:
`/`, `/ledger`, `/health`, and `/v1/ledger`. Timeline polling and all mutation
routes are absent from that public surface until #68 provides authentication.
Bind `127.0.0.1` to use the complete local Gateway API. The Compose default
publishes the container only on the host loopback interface; an intentional
public Ledger deployment may publish the container port because its
non-loopback listener is spectator-only.

## HTTP API

Read the [contract guide](../../contracts/gateway/v1/README.md) first: it is the client
documentation for the description, schemas and their `$id`s, the problem registry, media types,
`Idempotency-Key`, cursors, the compatibility window and version negotiation.
`scripts/check_gateway_contract.py` fails CI when the description, the golden examples, the
served responses recorded by the gateway-client-conformance fixtures, or the frozen v1 baseline
disagree. The table below summarizes the served routes; the contract wins. `/` and `/ledger`
are HTML conveniences outside the JSON contract.

| Method | Path | Body | Response |
|--------|------|------|----------|
| `GET` | `/health` | — | `{ "ok": true }` |
| `GET` | `/` | — | `302` redirect to `/ledger` |
| `GET` | `/ledger` | — | Public Prediction Ledger HTML |
| `GET` | `/v1/ledger` | — | Public Prediction Ledger JSON |
| `POST` | `/v1/timelines` | `{ "name": "..." }` | `{ "id", "name", "head" }` |
| `GET` | `/v1/timelines/:id/events?from_seq=0&limit=100` | — | `{ "events": [EventView], "next_from_seq", "next_cursor" }` |
| `POST` | `/v1/timelines/:id/actions` (header `Idempotency-Key`) | `{ "entity_id", "capability", "payload", "event_type"? }` | `EventView` |
| `POST` | `/v1/timelines/:id/signals` | `{ "entity_id", "dimension", "value", ... }` | `EventView` |
| `POST` | `/v1/ledger/predictions` | `NewPrediction` | `201` `{ "prediction_id" }` when Ledger writes are enabled |
| `POST` | `/v1/bridges/owntracks` | OwnTracks `location` (Basic authentication) | `[]`, only when the OwnTracks bridge is configured |

- **Actions:** `event_type` defaults to `world.action.v1`; `capability` must be exactly `world.action.v1.submit`. Legacy `world.action` and `world.action.submit` are unsupported. The JSON payload requires `actor_entity_id`, `body_entity_id`, `action_kind` (`impulse` or `target_velocity`), `params` (exactly two JSON float numbers ordered X, Z, in metres per second), `action_scope` (0), `catalogue_version`, and `tick`. Unknown payload fields, integers, strings, extra components, nonfinite values, and binary32 overflow are rejected. The Gateway rounds each finite source to binary32 before storing the shortest exact canonical CBOR float encoding; raw proposed actions must already contain that normalized pair. `impulse` adds the pair to horizontal velocity, while `target_velocity` sets it; vertical Y velocity is unchanged, and position advances over the pinned timestep. The pair is never rounded at the 100 mm position/sensor floor. The WAC1 array remains bounded to 4,096 bytes. A host-bound Gateway authorizer must allow the Principal/entity operation at the current authority fence before any domain approval; the World approver then checks actor identity, the known body ID, and the pinned actuator catalogue, and its approved draft stays tentative. The Gateway commits it only through atomic host admission (ADR-021): inside one host-owned store command it rechecks authorization, persists the Principal's authority chain, and the store compares that chain, the erasure generation, the observed Logical Head, and the remaining Event budget at its commit serialization point. The response is the committed Event named by the authoritative admission receipt. Every action carries an `Idempotency-Key` header of 1 to 128 visible ASCII characters; without one it is `400` `invalid-request`. An exact retry under the same key returns `200` with the original committed Event without re-running approval, a different request under the same key is `409` `idempotency-conflict`, and an action whose observed head moved is `409` `append-conflict`; a rejected action is never retried by the Gateway. An unprovisioned Gateway fails closed with `401`; a provisioned one still has no installed World action catalogue (#461), so an authorized action is refused without a commit.
- **Signals:** convenience wrapper for `society.signal` (see `plugins/society`).
- **Polling:** `limit` defaults to and may not exceed 100. `from_seq` is inclusive and starts a fresh read. `next_from_seq` is `null` only when the Timeline is exhausted; otherwise it is the inclusive sequence of the first omitted Event. A host-owned Gateway also returns `next_cursor`, which binds that sequence, Timeline, and installed erasure inventory generation. Continue a page with `?cursor=<next_cursor>`; a generation change rejects the cursor with `409` `append-conflict`, so restart from a fresh `from_seq`. `cursor` and `from_seq` cannot appear together. A future independent client will continue polling until exhaustion; this transport behavior is not, by itself, product MVP evidence.
- **Response budget:** each polling response is at most 1 MiB. The Gateway may return fewer than `limit` Events to stay within that budget. Polling uses the store's bounded-read seam and requests exactly `limit + 1` candidates so the first omitted Event becomes the cursor. The internal read byte bound covers all selected candidates at their per-field maxima; the separate wire-size check trims the page to 1 MiB. The memory adapter derives Fork-segment lengths from Timeline heads and seeks directly into contiguous per-Timeline Event vectors. SQLite derives the same segment ranges from indexed Timeline metadata and uses `(timeline_id, seq)` primary-key range predicates with `LIMIT` in both phases: it first selects only `seq`, `typeof(payload)`, `length(CAST(payload AS BLOB))`, and `length(CAST(event_type AS BLOB))`, validates them, and only then fetches at most the same bounded number of full Events in the same snapshot transaction. Neither adapter scans preceding Event history for a late cursor. SQLite files must use UTF-8 encoding, Event sequences must be contiguous from 1 through `timelines.head_seq`, and offline imports must preserve payloads with SQLite `BLOB` storage class. Existing SQLite files are sequence-validated once when opened; supported import APIs validate committed batches as they arrive. Opening UTF-16 or non-contiguous databases, or polling non-BLOB payload rows, fails closed with an actionable store error. Direct SQL mutation that bypasses `EventStore` while the database is open is outside the supported write boundary. Stored payloads over 256 KiB or imported `event_type` values over 64 KiB return a deterministic `413` `resource-limit-exceeded` problem. The metadata ceiling reserves at most 384 KiB for worst-case JSON escaping; together with the maximum payload's 512 KiB hex form and fixed Event fields this fits the 1 MiB envelope. The exact response-size check still handles decoded payload expansion. For Gateway-authored Events, admission serializes an exact `EventView`-equivalent envelope with worst-case sequence and cursor widths.
- **Fork traversal bound:** one poll traverses at most 64 parent links. Imported deeper chains and corrupt ancestry cycles fail with a `413` problem before an unbounded ancestry collection can grow. The bound does not change shallow Fork pagination, including Timelines exposing 10,001 logical Events.
- **Timeline bound:** one Gateway process accepts at most 64 **root** Timelines. Forks, identity-preserving imported children and the host Timelines (the Consent Timeline, the Local Principal's authority Timeline and the Erasure Host Timeline) do not consume root capacity. Quota checks use a bounded scalar store seam that stops at quota + 1 and never lists or clones Timeline metadata.
- **Owner:** `POST /v1/timelines` records the actor its decision admitted as the owner of the new root (ADR-136 §1), so a Local erasure of that actor selects the root and the Forks that inherit its owner; an unprotected composition creates an unowned root. Scenario Room Timelines stay unowned and are never selected by an erasure.
- **Host Timelines:** no client route reads, appends to or acts on a host Timeline, and a local Fork admission naming one as its parent is refused exactly as for a parent the store does not hold (`404 not-found-or-unavailable` on HTTP, code 4 on the Fork-admission socket).
- **Event bound:** each Timeline accepts at most 10,000 **owned** Events. A Fork's inherited parent Events remain readable but do not consume its own ceiling. This bounds incremental storage per Timeline without discouraging Forks.
- **Errors:** every failure, including malformed JSON bodies, unknown paths and unserved methods (`405`), is an RFC 9457 `application/problem+json` body whose `code` is one of the closed families of `problem-types.json` (see the [contract guide](../../contracts/gateway/v1/README.md#problems)). A path under another API major such as `/v2/...` is `400` `unsupported-version`; any other unrouted path is `404` `not-found-or-unavailable`. `detail` wording is not part of the contract.
- **Body limit:** 1 MiB (`MAX_HTTP_BODY_BYTES`); returns a `413` `resource-limit-exceeded` problem when exceeded.
- **Public listener:** on a non-loopback bind, only the four public Ledger routes
  above are registered. All Timeline and prediction-registration routes return the `404`
  `not-found-or-unavailable` problem.

Rust callers should start with `Gateway::read_events_page` (or
`Gateway::read_events_page_authorized`) and pass `EventPage::next_cursor` to
`Gateway::read_events_page_after` (or the authorized counterpart). The opaque
cursor binds its Timeline and, on a host-owned Gateway, its inventory generation;
continuation after a generation change returns `StaleEventCursor`.
`next_from_seq` is a sequence position for a separate fresh read, not a
generation-bound continuation. `read_events_from` succeeds only when the result
fits in one bounded page and returns an explicit error instead of silently
truncating a longer Timeline.

### EventView

Poll and append responses return:

```json
{
  "id": "<event ulid>",
  "entity": "<entity ulid>",
  "event_type": "world.action.v1",
  "seq": 1,
  "payload": [[87, 65, 67, 49], 1, ["<16 actor bytes>"], ["<16 body bytes>"], "impulse", [130, 249, 60, 0, 249, 0, 0], 0, 1, 1],
  "payload_hex": "894457414331..."
}
```

- **`payload`:** decoded JSON when the stored CBOR round-trips as JSON. Versioned actions expose the WAC1 array; byte strings become arrays of bytes. The actor/body placeholders above represent 16 bytes each.
- **`payload_hex`:** canonical stored bytes as lowercase hex — use when you need the exact CBOR blob.

## Architecture

```
HTTP (axum) → Gateway → EventStore (Memory | SQLite)
                      → broadcast bus (WebSocket follow-up)
```

This crate is a **store façade**, not a full `pos-runtime` host. Poll returns Events already appended to a bundled memory or SQLite store, including imported Events. Count, payload, metadata, Fork-depth, and response bounds apply regardless of Event origin. Custom `EventStore` adapters must implement the bounded-read and bounded root-count capabilities; safe defaults refuse Gateway operations instead of falling back to allocating reads or lists. When a `GatewayAuthorization` is configured, timeline reads require the host-provided actor context and are rechecked under the same authority fence used by action admission; no adapter credential or bearer value enters the Timeline.

### SQLite and host ownership

One erasure host owns the verified inventory generation used by its Gateway
routes. Its `EventStore` adapter serializes writes with immediate SQLite
transactions and a bounded busy timeout, and enforces Gateway ceilings
atomically. A separate process can advance the same SQLite file, but an
already-open host then rejects protected reads and writes rather than using a
stale inventory. Stop and restart that host to recover the complete committed
inventory before serving routes again. Concurrent Gateway and experiment
commands require the same host command stream, not two independently opened
hosts. Arbitrary SQL mutation that bypasses `EventStore` remains unsupported.
Imported Events remain safely bounded on read.

An external client does not reuse the 10,000-owned-Event ceiling as
a logical read limit: Forks may expose inherited plus owned Events beyond that
number. It follows monotonic cursors to exhaustion, caps every response at 1 MiB,
and caps cumulative response bytes at 64 MiB.

**Live bus:** `subscribe()` may return `Lagged` if a client falls behind; resync via event poll — the store is authoritative.

## Deferred (ADR-014)

- `GET /v1/timelines/:id/stream` (WebSocket)
- Auth / passkeys (#68)
- TLS, rate limits, multi-tenant hosting

## Local Fork admission (ADR-107)

Local Fork admission is a Linux systemd deployment. The managed Gateway starts
it only with `--require-local-fork-authority`; the fixed socket pathname and
credential directory are selected by the installed
[systemd unit](../../deploy/systemd/piglor-gateway.service), never by a shell
argument. The binary requires `CREDENTIALS_DIRECTORY` to be the exact unit
directory, so direct invocation fails before it opens the authority database.

The managed service has exactly three separate encrypted systemd credentials:
`pigloros.fork-admission-auth` (FACR1),
`pigloros.fork-admission-host-signer` (FAHK1), and
`pigloros.fork-classifier-profile` (FCP1, ADR-099 r11 / ADR-107 r6). The
one-shot provisioner reads only FACR1 and FAHK1. Create separate envelopes
with systemd 250 or newer; `host+tpm2` is the production default:

```bash
systemd-creds encrypt --name=pigloros.fork-admission-auth \
  --with-key=host+tpm2 FACR1.cbor pigloros.fork-admission-auth.cred
systemd-creds encrypt --name=pigloros.fork-admission-host-signer \
  --with-key=host+tpm2 FAHK1.cbor pigloros.fork-admission-host-signer.cred
install -o root -g root -m 0600 pigloros.fork-admission-auth.cred \
  /etc/credstore.encrypted/pigloros.fork-admission-auth.cred
install -o root -g root -m 0600 pigloros.fork-admission-host-signer.cred \
  /etc/credstore.encrypted/pigloros.fork-admission-host-signer.cred
```

Do not use `LoadCredential=`, `SetCredential=`, null-key encryption,
environment variables, command-line credential bytes, or one envelope for both
names. Create and destroy each plaintext separately in a root-only,
non-swappable staging location; verify its same-name decrypt before activation.

The service runs as `pigloros:pigloros`. Its runtime directory is
`/run/pigloros` with mode `0750`; its socket is
`/run/pigloros/fork-admission.sock` with mode `0660`. Group access only reaches
the pathname: `SO_PEERCRED` rejects a UID absent from FACR1 before it reads a
FAL1 frame. Both units use `PrivateMounts=yes`. The Gateway keeps its
loopback HTTP listener reachable and limits sockets with
`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`; the one-shot provisioner
also uses `PrivateNetwork=yes` and starts no listener, router, Plugin, or
background task.

Before provisioning, store independent offline encrypted backups of the exact
FACR1 and FAHK1 values under a separately controlled recovery key. Record each
credential name and SHA-256 in the deployment inventory. Keep the FAHK1 backup
separate from the authority database backup. With `host+tpm2`, retain the
original TPM2 and `/var/lib/systemd/credential.secret` for online envelope
recovery.

To restore, decrypt both offline backups separately in root-only non-swappable
staging, verify the recorded SHA-256 values and unequal seeds, re-encrypt each
under its exact credential name, install both root-owned `0600` envelopes, and
destroy the plaintext staging files. An initialized authority store is never
rebound: if either exact value cannot be restored, it remains unavailable.

Provision only through the installed disabled one-shot unit while the Gateway
service is stopped, then start the managed service:

```bash
systemctl start piglor-gateway-fork-admission-provision.service
systemctl enable --now piglor-gateway.service
```

The provision unit fails before database open for a direct shell invocation,
wrong credential directory, or extra, missing, or swapped credential. It also
fails if authority state already exists. The listener requires a complete
bounded FAL1 request ending in EOF and exposes no append-permit or public
permit-issuance path.

The HTTP routes and the listener share the one erasure host of the database
(ADR-109 revision 9): the process opens exactly one read-write adapter, owned
by the Gateway's store executor, so listener writes never make HTTP protected
operations fail with `503`. Managed startup fails closed in this order:
validation of the three managed credentials (FACR1, FAHK1, and the FCP1
classifier profile below), host recovery with a verified inventory (the binary
composes only the closed erasure authority, so a store with any erasure request
does not start), the read-only FCP1 preflight and the FAO1 open proof on the
host's adapter, private FRP1 journal reconciliation, the executor, then the TCP
listener and, last, the Unix socket.
Shutdown stops TCP, then the listener (an in-flight request finishes), then
drains the executor. A new admitted Fork runs inside the host's erasure
topology transition and returns code 0 only after the successor inventory is
published; while the host is not Ready it fails closed with code 5. A saturated
executor or a lost reply answers code 6, and an exact retry recovers a
committed result through FRP1. Code 8 (appended for ADR-134 §8) answers a
Bind or Fork whose store binding another process changed: the FAC1 committed
nothing, the Gateway stops serving and exits nonzero, and the client retries
against the restarted Gateway.

### Fork classifier profile (FCP1)

FCP1 selects the classifier source for locally admitted Forks. Its plaintext
is one deterministic-CBOR array `["FCP1", 1,
"piglor-gateway.local-fork-classifier/v1", [1*4 FCS1]]` of at most 786,688
bytes. Each row is the exact canonical FCS1 for one room revision descriptor
hash, carries that fixed registrar identifier, and rows are strictly
increasing by descriptor hash. It holds route identifiers and schema digests
only, never keys, payloads, or subject data. Record its activation digest,
`BLAKE3("pigloros/fork-classifier-profile/v1" || FCP1 bytes)`, with its
SHA-256 in the deployment inventory.

Encrypt it like the key credentials, from its own root-only non-swappable
staging file, verify its same-name decrypt byte-for-byte, and destroy the
plaintext before service start:

```bash
systemd-creds encrypt --name=pigloros.fork-classifier-profile \
  --with-key=host+tpm2 FCP1.cbor pigloros.fork-classifier-profile.cred
install -o root -g root -m 0600 pigloros.fork-classifier-profile.cred \
  /etc/credstore.encrypted/pigloros.fork-classifier-profile.cred
```

Startup order is fixed (ADR-109 revision 12): the three exact credential
files, FACR1/FAHK1, and the strict FCP1 decode are checked before the database
opens; after the erasure host opens, a read-only preflight on its adapter
requires every durable FCS1 to equal one FCP1 row byte-for-byte, before the
FAH1 open proof; then the delivery journal is reconciled, the session's
permit issuer and the immutable profile move into the store executor's private
Fork-admission slot, and only then are the sockets bound. At each Fork commit
or same-operation recovery, the executor registers the FCS1 row that the
durable FAR1 selects before the result is released. A missing, fourth,
renamed, unreadable, malformed, or oversized credential, a durable FCS1 for
another registrar, or an absent or changed row fails startup before the
listener exists and writes no authority record. A committed Fork whose
descriptor has no row stays retryable (code 6) and never falls back to another
table.

To activate or change FCP1 on an existing database: stop
`piglor-gateway.service`; back up the exact database file and all three
ciphertext files together; install the reviewed binary, unit, and new FCP1
envelope; run `systemctl daemon-reload`; and start the service once. A new
profile may add rows for new descriptor hashes, but every previously
registered row must stay byte-identical; changing a table needs a new room
revision descriptor hash. Keep the FCP1 recovery copy in the deployment
inventory apart from the database backup.

To restore, restore the database and the matching three-credential set as one
release while the service is stopped. Before any new classifier registration
or classified append, rollback may restore the prior binary, unit, database,
and credentials. After one exists, rollback can only stop the new activation:
an older binary must not reopen the listener, and committed FCS1, FCT1, FCR1,
and FOP1 records are never rewritten. Replay verifies those durable records
without FCP1.
