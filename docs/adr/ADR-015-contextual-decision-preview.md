# ADR-015: Wave 7 Contextual Decision Preview

**Status:** Accepted (in-repo)  
**Wave:** 7  
**Depends on:** Wave 5 `pos-mvp`, Wave 6 `piglor-gateway` + `plugins/society`

In-repo copy for reviewers; Redmine wiki is canonical when published.

## Context

Wave 5 closed the single-user loop: preferences → scored options → recommendation → calibration.

Wave 6 added shared-world seams: identity import (#87), society signals (#71), and HTTP gateway poll (#69 / ADR-014).

Wave 7 connects the decision preview to **live shared context** — society signals on a timeline nudge preferences before scoring.

## Decision

### MVP slice (this ADR)

Extend `pos-mvp` with optional gateway context:

```bash
cargo run -p pos-mvp -- --scenario work \
  --gateway http://127.0.0.1:8080 --timeline <ulid>
```

1. HTTP `GET /v1/timelines/:id/events?from_seq=0` on the gateway (ADR-014).
2. Fold `society.signal` events into per-dimension running means (`trust`, `opinion`, …).
3. Nudge matching preference keys: `adjusted = clamp(pref + (mean - 0.5) * 0.25, -1, 1)`.
4. Print context summary, then run the existing Wave 5 preview + backtest loop.

No new crate; sync HTTP via `ureq` in `pos-mvp` only. Gateway remains optional — without flags, behaviour is unchanged.

### Non-goals (deferred)

- LLM bridges / agent population (#72)
- Full `piglor-client` UI (#70)
- Fork/merge timelines for counterfactual branches
- Auth on gateway (#68) — loopback demos only

## Implementation

- Code: `apps/pos-mvp/src/gateway_context.rs`
- Tests: JSON fixture parsing + preference nudge (no network in unit tests)

## Wave 6 closure

Delivered on `main`:

| Item | Ticket | Status |
|------|--------|--------|
| Identity import | #87 | Done |
| Society scaffold | #71 | Done |
| Gateway HTTP poll MVP | #69 / ADR-014 | Done |

Deferred within Wave 6 umbrella: WebSocket, auth (#68), PyO3, client (#70), distributed store (#74).
