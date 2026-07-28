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
- **Response budget:** each polling response is at most 1 MiB. The Gateway may return fewer than `limit` Events to stay within that budget. A single externally-written Event that cannot fit returns deterministic JSON `413`; Gateway-authored Event payloads are capped at 256 KiB so they remain retrievable.
- **Timeline bound:** one Gateway process accepts at most 64 **root** Timelines. Forks and identity-preserving imported children do not consume root capacity.
- **Event bound:** each Timeline accepts at most 10,000 **owned** Events. A Fork's inherited parent Events remain readable but do not consume its own ceiling. This bounds incremental storage per Timeline without discouraging Forks.
- **Errors:** JSON `{ "error": "..." }` with `400` (bad id/type/query/page), `404` (unknown timeline), `413` (body/response too large), `429` (resource bound), `500` (store). Negative, overflowed, duplicate, unknown, or otherwise malformed polling parameters use this JSON `400` envelope.
- **Body limit:** 1 MiB (`MAX_HTTP_BODY_BYTES`); returns `413` when exceeded.

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

This crate is a **store façade**, not a full `pos-runtime` host. Poll returns Events already appended to the store, including Events created by a shared SQLite writer; count and byte pagination apply after every read regardless of origin.

### Supported SQLite write boundary

The local-first mutation boundary is one `Gateway` instance owning all writes to its SQLite file. Its async store mutex keeps each event-ceiling check and append in one critical section, including concurrent HTTP requests. Separate processes or direct `EventStore` writers may share the file for migration/import workflows, but concurrent out-of-process mutation is not a supported deployment and cannot claim the 10,000-Event enforcement guarantee. External Events remain safely bounded on read.

**Live bus:** `subscribe()` may return `Lagged` if a client falls behind; resync via event poll — the store is authoritative.

## Deferred (ADR-014)

- `GET /v1/timelines/:id/stream` (WebSocket)
- Auth / passkeys (#68)
- TLS, rate limits, multi-tenant hosting
