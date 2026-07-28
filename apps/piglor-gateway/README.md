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

Binding non-loopback addresses prints a warning — there is no auth in this slice.

## HTTP API

| Method | Path | Body | Response |
|--------|------|------|----------|
| `GET` | `/health` | — | `{ "ok": true }` |
| `POST` | `/v1/timelines` | `{ "name": "..." }` | `{ "id", "name", "head" }` |
| `GET` | `/v1/timelines/:id/events?from_seq=0&limit=100` | — | `{ "events": [EventView], "next_from_seq" }` |
| `POST` | `/v1/timelines/:id/actions` | `{ "entity_id", "payload", "event_type"? }` | `EventView` |
| `POST` | `/v1/timelines/:id/signals` | `{ "entity_id", "dimension", "value", ... }` | `EventView` |

- **Actions:** `event_type` must be `world.action` (default). `payload` is arbitrary JSON → CBOR in the store.
- **Signals:** convenience wrapper for `society.signal` (see `plugins/society`).
- **Polling:** `limit` defaults to and may not exceed 100. `from_seq` is inclusive. `next_from_seq` is `null` only when the Timeline is exhausted; otherwise it is the inclusive sequence of the first omitted Event and clients must request it to continue. The bundled `pos-mvp` consumer follows the cursor until exhaustion.
- **Response budget:** each polling response is at most 1 MiB. The Gateway may return fewer than `limit` Events to stay within that budget. Polling uses the store's bounded-read seam: the memory adapter validates payload and `event_type` byte lengths before cloning, while SQLite first selects only `typeof(payload)`, `length(CAST(payload AS BLOB))`, and `length(CAST(event_type AS BLOB))`, validates them, and only then fetches full Events in the same snapshot transaction. SQLite files must use UTF-8 encoding and offline imports must preserve payloads with SQLite `BLOB` storage class; opening UTF-16 databases or polling non-BLOB payload rows fails closed with an actionable store error. Stored payloads over 256 KiB or imported `event_type` values over 64 KiB return deterministic JSON `413`. The metadata ceiling reserves at most 384 KiB for worst-case JSON escaping; together with the maximum payload's 512 KiB hex form and fixed Event fields this fits the 1 MiB envelope. The exact response-size check still handles decoded payload expansion. For Gateway-authored Events, admission serializes an exact `EventView`-equivalent envelope with worst-case sequence and cursor widths.
- **Fork traversal bound:** one poll traverses at most 64 parent links. Imported deeper chains and corrupt ancestry cycles fail with JSON `413` before an unbounded ancestry collection can grow. The bound does not change shallow Fork pagination, including Timelines exposing 10,001 logical Events.
- **Timeline bound:** one Gateway process accepts at most 64 **root** Timelines. Forks and identity-preserving imported children do not consume root capacity. Quota checks use a bounded scalar store seam that stops at quota + 1 and never lists or clones Timeline metadata.
- **Event bound:** each Timeline accepts at most 10,000 **owned** Events. A Fork's inherited parent Events remain readable but do not consume its own ceiling. This bounds incremental storage per Timeline without discouraging Forks.
- **Errors:** JSON `{ "error": "..." }` with `400` (bad id/type/query/page), `404` (unknown timeline), `413` (body/response too large), `429` (resource bound), `500` (store). Negative, overflowed, duplicate, unknown, or otherwise malformed polling parameters use this JSON `400` envelope.
- **Body limit:** 1 MiB (`MAX_HTTP_BODY_BYTES`); returns `413` when exceeded.

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

The local-first mutation boundary is one `Gateway` instance owning all writes to its SQLite file. Its async store mutex keeps each event-ceiling check and append in one critical section, including concurrent HTTP requests. Offline migration/import workflows may place Events in the file before the Gateway opens it, but concurrent out-of-process mutation is not a supported deployment and cannot claim the 10,000-Event enforcement guarantee. Imported Events remain safely bounded on read.

The bundled `pos-mvp` consumer does not reuse the 10,000-owned-Event ceiling as
a logical read limit: Forks may expose inherited plus owned Events beyond that
number. It follows monotonic cursors to exhaustion, caps every response at 1 MiB,
and caps cumulative response bytes at 64 MiB.

**Live bus:** `subscribe()` may return `Lagged` if a client falls behind; resync via event poll — the store is authoritative.

## Deferred (ADR-014)

- `GET /v1/timelines/:id/stream` (WebSocket)
- Auth / passkeys (#68)
- TLS, rate limits, multi-tenant hosting
