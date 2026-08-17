# piglor-gateway

Wave 6 local-first HTTP gateway ([ADR-014](../../docs/adr/ADR-014-gateway-mvp.md) / Redmine #69).

HTTP poll MVP for timelines, events, `world.action`, and `society.signal`. WebSocket stream and auth are deferred.

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
Timeline through `POST /v1/timelines`, then run `pos-experiment` against that exact file and
returned ID:

```bash
cargo run -p piglor-gateway --locked -- \
  serve 127.0.0.1:8080 /tmp/piglor-126.db

cargo run -p pos-experiment --locked -- \
  multi-rate-demo /tmp/piglor-126.db <timeline-id> \
  --ticks 20 --quantum-ms 100 --pace-ms 100
```

The experiment is finite and uses caller-supplied simulation time for deterministic driver
cadence; wall-clock sleep only paces output. Human actions and society signals may be posted
through this Gateway while it runs. See the
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
| `GET` | `/v1/timelines/:id/events?from_seq=0&limit=100` | — | `{ "events": [EventView], "next_from_seq" }` |
| `POST` | `/v1/timelines/:id/actions` | `{ "entity_id", "payload", "event_type"? }` | `EventView` |
| `POST` | `/v1/timelines/:id/signals` | `{ "entity_id", "dimension", "value", ... }` | `EventView` |

- **Actions:** `event_type` must be `world.action` (default). `payload` is arbitrary JSON → CBOR in the store.
- **Signals:** convenience wrapper for `society.signal` (see `plugins/society`).
- **Polling:** `limit` defaults to and may not exceed 100. `from_seq` is inclusive. `next_from_seq` is `null` only when the Timeline is exhausted; otherwise it is the inclusive sequence of the first omitted Event and clients must request it to continue. The bundled `pos-mvp` consumer follows the cursor until exhaustion.
- **Response budget:** each polling response is at most 1 MiB. The Gateway may return fewer than `limit` Events to stay within that budget. Polling uses the store's bounded-read seam and requests exactly `limit + 1` candidates so the first omitted Event becomes the cursor. The memory adapter derives Fork-segment lengths from Timeline heads and seeks directly into contiguous per-Timeline Event vectors. SQLite derives the same segment ranges from indexed Timeline metadata and uses `(timeline_id, seq)` primary-key range predicates with `LIMIT` in both phases: it first selects only `seq`, `typeof(payload)`, `length(CAST(payload AS BLOB))`, and `length(CAST(event_type AS BLOB))`, validates them, and only then fetches at most the same bounded number of full Events in the same snapshot transaction. Neither adapter scans preceding Event history for a late cursor. SQLite files must use UTF-8 encoding, Event sequences must be contiguous from 1 through `timelines.head_seq`, and offline imports must preserve payloads with SQLite `BLOB` storage class. Existing SQLite files are sequence-validated once when opened; supported import APIs validate committed batches as they arrive. Opening UTF-16 or non-contiguous databases, or polling non-BLOB payload rows, fails closed with an actionable store error. Direct SQL mutation that bypasses `EventStore` while the database is open is outside the supported write boundary. Stored payloads over 256 KiB or imported `event_type` values over 64 KiB return deterministic JSON `413`. The metadata ceiling reserves at most 384 KiB for worst-case JSON escaping; together with the maximum payload's 512 KiB hex form and fixed Event fields this fits the 1 MiB envelope. The exact response-size check still handles decoded payload expansion. For Gateway-authored Events, admission serializes an exact `EventView`-equivalent envelope with worst-case sequence and cursor widths.
- **Fork traversal bound:** one poll traverses at most 64 parent links. Imported deeper chains and corrupt ancestry cycles fail with JSON `413` before an unbounded ancestry collection can grow. The bound does not change shallow Fork pagination, including Timelines exposing 10,001 logical Events.
- **Timeline bound:** one Gateway process accepts at most 64 **root** Timelines. Forks and identity-preserving imported children do not consume root capacity. Quota checks use a bounded scalar store seam that stops at quota + 1 and never lists or clones Timeline metadata.
- **Event bound:** each Timeline accepts at most 10,000 **owned** Events. A Fork's inherited parent Events remain readable but do not consume its own ceiling. This bounds incremental storage per Timeline without discouraging Forks.
- **Errors:** JSON `{ "error": "..." }` with `400` (bad id/type/query/page), `404` (unknown timeline), `413` (body/response too large), `429` (resource bound), `500` (store). Negative, overflowed, duplicate, unknown, or otherwise malformed polling parameters use this JSON `400` envelope.
- **Body limit:** 1 MiB (`MAX_HTTP_BODY_BYTES`); returns `413` when exceeded.
- **Public listener:** on a non-loopback bind, only the four public Ledger routes
  above are registered. All Timeline and prediction-registration routes return `404`.

Rust callers should use public `Gateway::read_events_page` and follow
`EventPage::next_from_seq`. The deprecated `read_events_from` compatibility
method succeeds only when the result fits in one bounded page and returns an
explicit error instead of silently truncating a longer Timeline.

### EventView

Poll and append responses return:

```json
{
  "id": "<event ulid>",
  "entity": "<entity ulid>",
  "event_type": "world.action",
  "seq": 1,
  "payload": { "dx": 1 },
  "payload_hex": "a1..."
}
```

- **`payload`:** decoded JSON when the stored CBOR round-trips as JSON (typical for actions posted here).
- **`payload_hex`:** canonical stored bytes as lowercase hex — use when you need the exact CBOR blob.

## Architecture

```
HTTP (axum) → Gateway → EventStore (Memory | SQLite)
                      → broadcast bus (WebSocket follow-up)
```

This crate is a **store façade**, not a full `pos-runtime` host. Poll returns Events already appended to a bundled memory or SQLite store, including imported Events. Count, payload, metadata, Fork-depth, and response bounds apply regardless of Event origin. Custom `EventStore` adapters must implement the bounded-read and bounded root-count capabilities; safe defaults refuse Gateway operations instead of falling back to allocating reads or lists.

### Supported SQLite write boundary

The supported multi-process boundary permits PiglorOS Gateway and experiment-host
processes to open the same SQLite Timeline through `EventStore`. Immediate writer
transactions and a bounded busy timeout serialize their appends, and Gateway
ceilings are enforced atomically by the adapter. Arbitrary SQL mutation by tools
that bypass `EventStore` remains unsupported while the file is open. Imported
Events remain safely bounded on read.

The bundled `pos-mvp` consumer does not reuse the 10,000-owned-Event ceiling as
a logical read limit: Forks may expose inherited plus owned Events beyond that
number. It follows monotonic cursors to exhaustion, caps every response at 1 MiB,
and caps cumulative response bytes at 64 MiB.

**Live bus:** `subscribe()` may return `Lagged` if a client falls behind; resync via event poll — the store is authoritative.

## Deferred (ADR-014)

- `GET /v1/timelines/:id/stream` (WebSocket)
- Auth / passkeys (#68)
- TLS, rate limits, multi-tenant hosting
