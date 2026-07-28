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
| `GET` | `/` or `/ledger` | — | Public Prediction Ledger HTML |
| `GET` | `/v1/ledger` | — | Public Prediction Ledger JSON |
| `POST` | `/v1/timelines` | `{ "name": "..." }` | `{ "id", "name", "head" }` |
| `GET` | `/v1/timelines/:id/events?from_seq=0` | — | `{ "events": [EventView] }` |
| `POST` | `/v1/timelines/:id/actions` | `{ "entity_id", "payload", "event_type"? }` | `EventView` |
| `POST` | `/v1/timelines/:id/signals` | `{ "entity_id", "dimension", "value", ... }` | `EventView` |

- **Actions:** `event_type` must be `world.action` (default). `payload` is arbitrary JSON → CBOR in the store.
- **Signals:** convenience wrapper for `society.signal` (see `plugins/society`).
- **Errors:** JSON `{ "error": "..." }` with `400` (bad id/type), `404` (unknown timeline), `413` (body too large), `500` (store).
- **Body limit:** 1 MiB (`MAX_HTTP_BODY_BYTES`); returns `413` when exceeded.
- **Public listener:** on a non-loopback bind, only the four public Ledger routes
  above are registered. All Timeline and prediction-registration routes return `404`.

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
