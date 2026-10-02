# piglor-gateway

Wave 6 local-first HTTP Gateway foundation ([ADR-014](../../docs/adr/ADR-014-gateway-mvp.md) / Redmine #69). This is a transport component, not the product MVP.

The Wave 9 external-client MVP target will use this documented HTTP boundary to create or select Timelines, submit authenticated `world.action.v1` proposals, and poll committed Events. This foundation is not the product MVP: the default Gateway process has no host-bound authority adapter, so action submission fails closed until a host configures one. `GatewayAuthenticationAdapter` implementations establish minimized `AuthenticatedPrincipalResultV1` evidence; `GatewayAuthorization` evaluates the pinned Principal, consent, capability, delegation, expiry, and revocation state. WebSocket, public client decision-preview contracts, and Replay/Fork routes remain deferred.

## Run

```bash
# Memory store (default loopback)
cargo run -p piglor-gateway --locked -- serve

# SQLite persistence
cargo run -p piglor-gateway --locked -- serve 127.0.0.1:8080 /tmp/piglor-gw.db
```

### Separate deterministic experiment host

The Gateway remains an ingress/store façade; it does not run simulation drivers. For the
ADR-019 two-process demonstration, start the Gateway with an explicit SQLite file, create a
Timeline through `POST /v1/timelines`, then stop the Gateway before running `pos-experiment`
against that exact file and returned ID. Restart the Gateway after the experiment exits:

```bash
cargo run -p piglor-gateway --locked -- \
  serve 127.0.0.1:8080 /tmp/piglor-126.db

# Record the Timeline ID from POST /v1/timelines, then stop Gateway (Ctrl-C).
cargo run -p pos-experiment --locked -- \
  multi-rate-demo /tmp/piglor-126.db <timeline-id> \
  --ticks 20 --quantum-ms 100 --pace-ms 100

cargo run -p piglor-gateway --locked -- \
  serve 127.0.0.1:8080 /tmp/piglor-126.db
```

The experiment is finite and uses caller-supplied simulation time for deterministic driver
cadence; wall-clock sleep only paces output. After the restart, a host-configured Gateway can
accept human actions and society signals; the default action route remains fail-closed. See the
[`pos-experiment` demo guide](../pos-experiment/README.md) for exact requests, overrides,
restart guidance, and the same-file requirement. Arbitrary raw-SQL writers remain outside
the supported multi-process boundary.

Binding a non-loopback address serves only the public Prediction Ledger routes:
`/`, `/ledger`, `/health`, and `/v1/ledger`. Timeline polling and all mutation
routes are absent from that public surface until #68 provides authentication.
Bind `127.0.0.1` to use the complete local Gateway API. The Compose default
publishes the container only on the host loopback interface; an intentional
public Ledger deployment may publish the container port because its
non-loopback listener is spectator-only.

## HTTP API

| Method | Path | Body | Response |
|--------|------|------|----------|
| `GET` | `/health` | — | `{ "ok": true }` |
| `GET` | `/` | — | `302` redirect to `/ledger` |
| `GET` | `/ledger` | — | Public Prediction Ledger HTML |
| `GET` | `/v1/ledger` | — | Public Prediction Ledger JSON |
| `POST` | `/v1/timelines` | `{ "name": "..." }` | `{ "id", "name", "head" }` |
| `GET` | `/v1/timelines/:id/events?from_seq=0&limit=100` | — | `{ "events": [EventView], "next_from_seq", "next_cursor" }` |
| `POST` | `/v1/timelines/:id/actions` | `{ "entity_id", "capability", "payload", "event_type"?, "ingress_id"? }` | `EventView` |
| `POST` | `/v1/timelines/:id/signals` | `{ "entity_id", "dimension", "value", ... }` | `EventView` |

- **Actions:** `event_type` defaults to `world.action.v1`; `capability` must be exactly `world.action.v1.submit`. Legacy `world.action` and `world.action.submit` are unsupported. The JSON payload requires `actor_entity_id`, `body_entity_id`, `action_kind` (`impulse` or `target_velocity`), `params` (exactly two JSON float numbers ordered X, Z, in metres per second), `action_scope` (0), `catalogue_version`, and `tick`. Unknown payload fields, integers, strings, extra components, nonfinite values, and binary32 overflow are rejected. The Gateway rounds each finite source to binary32 before storing the shortest exact canonical CBOR float encoding; raw proposed actions must already contain that normalized pair. `impulse` adds the pair to horizontal velocity, while `target_velocity` sets it; vertical Y velocity is unchanged, and position advances over the pinned timestep. The pair is never rounded at the 100 mm position/sensor floor. The WAC1 array remains bounded to 4,096 bytes. A host-bound Gateway authorizer must allow the Principal/entity operation at the current authority fence before any domain approval; the World approver then checks actor identity, the known body ID, and the pinned actuator catalogue, and its approved draft stays tentative. The Gateway commits it only through atomic host admission (ADR-021): inside one host-owned store command it rechecks authorization, persists the Principal's authority chain, and the store compares that chain, the erasure generation, the observed Logical Head, and the remaining Event budget at its commit serialization point. The response is the committed Event named by the authoritative admission receipt. With `ingress_id`, an exact retry returns `200` with the original committed Event without re-running approval, a different request under the same `ingress_id` returns `409`, and an action whose observed head moved returns `409`; a rejected action is never retried by the Gateway. The default production Gateway has no authority adapter and therefore fails closed with `401` until the host wires authentication, authority state, and a World body catalogue.
- **Signals:** convenience wrapper for `society.signal` (see `plugins/society`).
- **Polling:** `limit` defaults to and may not exceed 100. `from_seq` is inclusive and starts a fresh read. `next_from_seq` is `null` only when the Timeline is exhausted; otherwise it is the inclusive sequence of the first omitted Event. A host-owned Gateway also returns `next_cursor`, which binds that sequence, Timeline, and installed erasure inventory generation. Continue a page with `?cursor=<next_cursor>`; a generation change rejects the cursor with JSON `409`, so restart from a fresh `from_seq`. `cursor` and `from_seq` cannot appear together. A future independent client will continue polling until exhaustion; this transport behavior is not, by itself, product MVP evidence.
- **Response budget:** each polling response is at most 1 MiB. The Gateway may return fewer than `limit` Events to stay within that budget. Polling uses the store's bounded-read seam and requests exactly `limit + 1` candidates so the first omitted Event becomes the cursor. The internal read byte bound covers all selected candidates at their per-field maxima; the separate wire-size check trims the page to 1 MiB. The memory adapter derives Fork-segment lengths from Timeline heads and seeks directly into contiguous per-Timeline Event vectors. SQLite derives the same segment ranges from indexed Timeline metadata and uses `(timeline_id, seq)` primary-key range predicates with `LIMIT` in both phases: it first selects only `seq`, `typeof(payload)`, `length(CAST(payload AS BLOB))`, and `length(CAST(event_type AS BLOB))`, validates them, and only then fetches at most the same bounded number of full Events in the same snapshot transaction. Neither adapter scans preceding Event history for a late cursor. SQLite files must use UTF-8 encoding, Event sequences must be contiguous from 1 through `timelines.head_seq`, and offline imports must preserve payloads with SQLite `BLOB` storage class. Existing SQLite files are sequence-validated once when opened; supported import APIs validate committed batches as they arrive. Opening UTF-16 or non-contiguous databases, or polling non-BLOB payload rows, fails closed with an actionable store error. Direct SQL mutation that bypasses `EventStore` while the database is open is outside the supported write boundary. Stored payloads over 256 KiB or imported `event_type` values over 64 KiB return deterministic JSON `413`. The metadata ceiling reserves at most 384 KiB for worst-case JSON escaping; together with the maximum payload's 512 KiB hex form and fixed Event fields this fits the 1 MiB envelope. The exact response-size check still handles decoded payload expansion. For Gateway-authored Events, admission serializes an exact `EventView`-equivalent envelope with worst-case sequence and cursor widths.
- **Fork traversal bound:** one poll traverses at most 64 parent links. Imported deeper chains and corrupt ancestry cycles fail with JSON `413` before an unbounded ancestry collection can grow. The bound does not change shallow Fork pagination, including Timelines exposing 10,001 logical Events.
- **Timeline bound:** one Gateway process accepts at most 64 **root** Timelines. Forks and identity-preserving imported children do not consume root capacity. Quota checks use a bounded scalar store seam that stops at quota + 1 and never lists or clones Timeline metadata.
- **Event bound:** each Timeline accepts at most 10,000 **owned** Events. A Fork's inherited parent Events remain readable but do not consume its own ceiling. This bounds incremental storage per Timeline without discouraging Forks.
- **Errors:** JSON `{ "error": "..." }` includes `400` (bad id/type/query/page), `404` (unknown timeline), `413` (body/response too large), `429` (resource bound), and `500` (store). The action route also returns `401` (authentication or authority unavailable), `403` (authorization or capability denied), `409` (`ingress_id` reused for another request, or a stale observation), `422` (invalid typed payload or World domain validation), and `503` (the host erasure fence cannot admit the action). Negative, overflowed, duplicate, unknown, or otherwise malformed polling parameters use this JSON `400` envelope.
- **Body limit:** 1 MiB (`MAX_HTTP_BODY_BYTES`); returns `413` when exceeded.
- **Public listener:** on a non-loopback bind, only the four public Ledger routes
  above are registered. All Timeline and prediction-registration routes return `404`.

Rust callers should start with `Gateway::read_events_page` (or
`Gateway::read_events_page_authorized`) and pass `EventPage::next_cursor` to
`Gateway::read_events_page_after` (or the authorized counterpart). The opaque
cursor binds its Timeline and, on a host-owned Gateway, its inventory generation;
continuation after a generation change returns `StaleEventCursor`.
`next_from_seq` is a sequence position for a separate fresh read, not a
generation-bound continuation. The deprecated `read_events_from` compatibility
method succeeds only when the result fits in one bounded page and returns an
explicit error instead of silently truncating a longer Timeline.

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
committed result through FRP1.

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
