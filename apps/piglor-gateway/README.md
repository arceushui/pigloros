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
- **Polling:** `limit` defaults to and may not exceed 100. `from_seq` is inclusive; use `next_from_seq` for the next page. Existing clients that only read `events` remain compatible.
- **Resource bounds:** one Gateway process accepts at most 64 root Timelines and 10,000 events per Timeline. It returns `429` after either bound is reached.
- **Errors:** JSON `{ "error": "..." }` with `400` (bad id/type/page), `404` (unknown timeline), `413` (body too large), `429` (resource bound), `500` (store).
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

This crate is a **store façade**, not a full `pos-runtime` host. Poll only returns events appended to that store (by this process or another writer sharing SQLite).

**Live bus:** `subscribe()` may return `Lagged` if a client falls behind; resync via event poll — the store is authoritative.

## Deferred (ADR-014)

- `GET /v1/timelines/:id/stream` (WebSocket)
- Auth / passkeys (#68)
- TLS, rate limits, multi-tenant hosting
