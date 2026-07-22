# ADR-014: Wave 6 Gateway MVP

**Status:** Accepted  
**Redmine:** [#104](https://redmine.piglor.com/issues/104) (ADR) · [#69](https://redmine.piglor.com/issues/69) (implementation)  
**Canonical wiki:** [ADR-014 on Redmine](https://redmine.piglor.com/projects/pigloros/wiki/ADR-014_Wave6_Gateway_MVP)

In-repo copy for reviewers; if this drifts from Redmine, the wiki wins.

## Context

Wave 6 needs a local-first entry point for shared timelines: create timelines, poll events, post `world.action` and `society.signal`, without pulling HTTP into `pos-*` kernel crates.

## Decision

### Crate

- `apps/piglor-gateway` — library (`Gateway`, HTTP router) + `piglor-gateway` binary (`serve`, `version`).

### HTTP routes (MVP)

| Route | Purpose |
|-------|---------|
| `GET /health` | Liveness |
| `POST /v1/timelines` | Create root timeline |
| `GET /v1/timelines/:id/events?from_seq=` | Poll committed events |
| `POST /v1/timelines/:id/actions` | Append `world.action` only |
| `POST /v1/timelines/:id/signals` | Append `society.signal` (society plugin helper) |

JSON request bodies; CBOR payloads in `EventStore`. Responses use `EventView` (`payload` JSON when decodable + `payload_hex` for canonical bytes).

### Storage & concurrency

- `Memory` or `SQLite` via `pos-store`.
- `tokio::sync::Mutex` around `Box<dyn EventStore>`; lock released before broadcast fan-out.

### Security (this slice)

- **No auth** — default bind `127.0.0.1:8080`; warn on non-loopback.
- No TLS / rate limits / multi-tenant isolation.

### Observations

- Poll returns whatever is on the timeline (actions, signals, or events written by other processes). No in-process observation producer or reducers.

## Deferred

| Item | Notes |
|------|-------|
| WebSocket `/v1/timelines/:id/stream` | Bus + `subscribe()` stub; revisit after coverage/WS carve-out |
| Auth / passkeys | #68 |
| `pos-runtime` in-process host | Store façade only for MVP |
| Broader `world.action.*` taxonomy | Single `world.action` type enforced |
| gRPC, TiKV (#74) | Later waves |

## Implementation

- Code: `apps/piglor-gateway/`
- **Status:** HTTP poll MVP complete on `main` (Redmine #69 — update tracker manually)
- Tests: lib + HTTP integration; 100% coverage in CI
- CI: same gates as workspace (`--include-ignored`, llvm-cov 100%)

## Related

- ADR-011 — Wave 6 sequencing  
- ADR-012 — Society signal schema (`plugins/society`)  
- #87 — identity import (done)  
- #71 — society reducer scaffold (done)
