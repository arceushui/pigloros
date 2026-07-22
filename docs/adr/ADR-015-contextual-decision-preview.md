# ADR-015: Wave 7 Contextual Decision Preview

**Redmine:** [#106](https://redmine.piglor.com/issues/106) (ADR) · [#107](https://redmine.piglor.com/issues/107) (MVP) · [#76](https://redmine.piglor.com/issues/76) (plain language) · [#75](https://redmine.piglor.com/issues/75) (personal fork)

**Canonical wiki:** [ADR-015 on Redmine](https://redmine.piglor.com/projects/pigloros/wiki/ADR-015_Wave7_Contextual_Decision_Preview)

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
3. Nudge preference keys: exact society dim match **or** scenario aliases
   (`trust`→`quiet`/`focus`, `culture`→`nature`/`autonomy`, `opinion`→`city`/`collaboration`,
   `economy`→`food`/`energy`, `polarization`→`collaboration`/`energy`).
   Each pref key is adjusted **once** by the average of contributing nudges
   (overlapping aliases do not stack):
   `adjusted = clamp(pref + avg(nudges) , -1, 1)` where `nudge = (mean - 0.5) * 0.25`.
4. Means clamped to `[0, 1]`. HTTP poll: ULID-validated path, 10s timeout, no redirects,
   reject non-2xx, 1 MiB body cap, UTF-8 body required.
5. Print context summary, then run the existing Wave 5 preview + backtest loop.

No new crate; sync HTTP via `ureq` in `pos-mvp` only. Gateway remains optional — without flags, behaviour is unchanged.

### Non-goals (deferred)

- LLM bridges / agent population (#72)
- Full `piglor-client` UI (#70)
- Auth on gateway (#68) — loopback demos only
- Gateway-hosted fork API / WebSocket live twins (thin local `#75` CoW exists in `pos-mvp --fork-compare`)

## Follow-on (#75 thin slice — not full ticket)

`cargo run -p pos-mvp -- --fork-compare` runs a **local** Memory CoW of `shared-now`, forces each scenario option on a future arm, and prints a side-by-side `pos_time::compare` summary plus persona scores.

**Deferred for a later #75 vertical:** gateway-seeded shared timeline, experiment tick loop with agents/humans, compare-driven verdict (not score reprint).

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
