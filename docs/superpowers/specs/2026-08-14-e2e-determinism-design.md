# Redmine #126: Multi-rate Human/AI E2E Determinism

**Status:** Approved by `gpt-5.6-sol` CTO review on 2026-08-14
**ADR:** ADR-019 (update required; no new ADR)
**Scope:** Wave 6.5 end-to-end verification and the production seams required to make that verification honest

## Goal

Prove the accepted ADR-019 coordination model through the production path: two real AI agent drivers run at different deterministic cadences, society projections fold at host-owned Tick Boundaries, and a human action commits through the HTTP Gateway while an AI pass is active. Live projections, two fresh replays, and Gateway polling must agree on one contiguous logical Timeline order.

The deliverable also includes a runnable two-process demonstration. The Gateway remains an ingress/store facade; the experiment process remains the simulation host.

## Constraints

- One durable SQLite Timeline is authoritative. Gateway and experiment host use separate SQLite connections to the same file.
- Timeline `seq`, not `wall_time`, determines fold and replay order.
- Simulation cadence uses caller-supplied monotonic nanoseconds. Sleeping may pace a demo but never determines eligibility.
- A driver pass observes one immutable snapshot. Events committed while drivers run are folded only after the atomic AI batch.
- Due drivers execute in registration order and their drafts append as one batch.
- No in-memory cross-process escape hatch, Gateway store exposure, external timer scheduler, migration, or new CI workflow.
- Existing 99% line and region coverage policy remains unchanged.

## Approaches considered

### A. Cadence-aware `ExperimentSession` with a separate demo host — chosen

Connect the existing registry cadence mechanism to the existing Tick Boundary pipeline. The Gateway and experiment host coordinate through independent connections to one SQLite Timeline. Add only the store serialization needed to make this documented two-writer model reliable.

This proves the production host without duplicating fold logic and keeps ingress, simulation lifetime, recovery, and shutdown in their current modules.

### B. Test-only orchestration around `TickScheduler` — rejected

A test could manually capture, fold, call `TickScheduler`, append, and fold again. It is smaller, but it duplicates the critical Tick Boundary algorithm and would stay green even while `ExperimentSession::step_tick()` continues to call every driver. It therefore does not prove the shipped host.

### C. Embed simulation scheduling in `piglor-gateway serve` — rejected

This gives a one-command demo, but couples HTTP ingress, plugin composition, driver failures, simulation recovery, pacing, and shutdown. It contradicts the Gateway's store-facade boundary and would require a new architecture decision.

## Architecture

### Cadence-aware Tick Boundary

`ExperimentSession` gains:

```rust
pub fn step_cadenced(&mut self, now_ns: u128) -> Result<TickOutcome, ExperimentError>
```

It runs the same pre-fold, immutable snapshot, atomic append, and post-fold pipeline as `step_tick()`, but selects drivers through `PluginRegistry::tick_cadenced(timeline, now_ns)`. `step_tick()` remains the compatibility path that calls all drivers.

The session stores the last supplied cadence timestamp. A timestamp lower than the previous timestamp is rejected before folding or driver mutation, so the session remains healthy and retryable. Equal timestamps are allowed and simply leave interval-gated drivers ineligible. Driver eligibility uses checked interval arithmetic; overflow is an explicit runtime error, never a wraparound.

The first cadence call starts at simulation time zero. Each later demo/test call advances by a fixed quantum. Successful quiescent cadence boundaries still increment the session tick count and remain resumable.

The first successful stepping call latches a session into either `AllDrivers` (`step_tick`) or `Cadenced` (`step_cadenced`) mode. Calling the other stepping API on that session returns an explicit mode-mismatch error before any fold or driver mutation. This avoids undefined eligibility after mixing an un-timestamped all-driver pass with timestamped cadence state. A fresh `resume()` creates an unlatched session and is the supported way to choose a different mode.

### Configurable real agent cadence

`AgentDriver` gains a builder:

```rust
pub fn with_tick_interval(self, interval: Duration) -> Self
```

Its `Driver::tick_interval()` implementation returns that value. The existing constructor preserves its current default cadence. The E2E scenario registers two real `AgentPlugin`/`AgentDriver` pairs at 100 ms and 200 ms in a fixed order.

### Read-only live projection evidence

`ExperimentSession` exposes its completed-boundary projection state without exposing mutable runtime or store ownership:

```rust
pub fn projections(&self) -> Result<&ProjectionRegistry, ExperimentError>
```

The accessor returns `SessionFaulted` when the live session is unhealthy, because a failed boundary may already have changed in-memory projections. A healthy session exposes only state folded through its most recently completed boundary. The external Gateway integration test uses reducer-specific queries on this registry and compares them directly with two fresh replay registries. This makes live-versus-replay equality an observable contract rather than an inference from Event order.

### Atomic bounded append

The generic `EventStore` port gains a fail-closed bounded batch append:

```rust
fn append_bounded(
    &mut self,
    timeline: TimelineId,
    drafts: &[EventDraft],
    max_owned_events: u64,
) -> Result<Option<Vec<Event>>, CoreError>;
```

`Some(events)` means the entire batch committed. `None` means the entire batch would exceed the owned-event ceiling. The limit check and append are one adapter-owned critical section/transaction; partial batches are forbidden. The Gateway ordinary action/signal path uses this method. Identified ingress keeps its existing identity-first bounded operation so retries can recover a prior event even when the Timeline is full.

Memory performs the check and append under its existing exclusive owner. SQLite uses an `IMMEDIATE` transaction for all generic writes, reads the current local head inside that transaction, checks `head + drafts.len()` with checked arithmetic, and commits the full batch contiguously.

### SQLite writer serialization

Every SQLite connection installs a bounded busy timeout shorter than the Gateway command deadline. Generic append begins an `IMMEDIATE` transaction, matching other writer operations. This permits the accepted ADR-019 model—separate Gateway and experiment-host connections—without treating normal writer contention as a session fault.

The timeout bounds waiting; genuine timeout, I/O, malformed ancestry, and invariant failures continue to fail closed. A deterministic contention test first appends through store connection A, then holds an `IMMEDIATE` write lock through a raw SQLite blocker connection while store connection B begins its append on a worker thread. A start channel proves B reached the append call; a bounded no-result assertion proves it waits while the lock is held. Releasing the blocker lets B commit. A stitched read must then expose the two store-authored Events at contiguous sequence positions. This forces the serialization path rather than hoping two threads collide.

## E2E data flow

The integration test lives at `apps/piglor-gateway/tests/e2e_determinism.rs` and uses a real TCP listener on `127.0.0.1:0`:

1. Create a temporary SQLite file.
2. Start the public Axum router and create a Timeline through HTTP.
3. Submit an initial `society.signal` through HTTP.
4. Open the same Timeline in `ExperimentSession::resume()` through a second SQLite connection.
5. Register components in this exact order: (1) a reducer-only observation plugin with `EntityStateProjection`; (2) `SocietyPlugin`/`SocietyReducer`; (3) the fast real `AgentDriver`; (4) a separate driver-only `ObservationProbeDriver`; and (5) the slow real `AgentDriver`.
6. Reducer and probe are deliberately separate registrations: runtime snapshots resolve the first registered reducer, while the probe must execute after the blocked fast agent. The 100 ms probe has exactly one `ProjectionKey` for the human entity, emits no Events, and retains a fixed three-entry observation log.
7. Advance fixed simulation timestamps `0`, `100`, and `200 ms` and assert exact fast/slow decision counts.
8. On the fast agent's second decision at `100 ms`, a test policy blocks at a barrier after the immutable snapshot exists.
9. While blocked, POST `world.action` through actual HTTP and wait for the durable `201` response.
10. Release the fast agent. The probe executes later in registration order, after the durable HTTP commit, but must still receive the pre-pass snapshot and record action count `0`.
11. The post-fold incorporates the human action. At `200 ms`, the same probe receives the next immutable snapshot and records action count `1`.
12. Assert the exact probe history `[0, 0, 1]`, fast/slow decision counts `3` and `2`, live society/agent/probe projections, exact event counts, registration-order AI output, and contiguous Gateway polling.
13. Replay the durable Timeline twice into fresh projection registries containing the same reducers and assert both replay states equal the live state and each other, including final human-entity event count `1`.

The authoritative ordering is:

```text
pre-fold range
-> immutable ObservationSnapshot
-> fast agent blocks after snapshot capture
-> human HTTP commit while a driver is active
-> observation probe runs later but sees the pre-pass snapshot
-> atomic AI draft batch
-> post-fold through captured logical head
-> the probe sees the human action at the next boundary
```

## Demo

`pos-experiment` gains a finite `multi-rate-demo` command. It opens an existing SQLite Timeline, registers the approved plugin composition, and advances fixed simulation time. Defaults are 20 boundaries at a 100 ms simulation quantum with 100 ms wall-clock pacing. `--ticks`, `--quantum-ms`, and `--pace-ms` override those values; ticks and quantum must be non-zero, while pace may be zero. Sleeping only paces terminal output and never supplies cadence time.

```bash
cargo run -p piglor-gateway --locked -- \
  serve 127.0.0.1:8080 /tmp/piglor-126.db

cargo run -p pos-experiment --locked -- \
  multi-rate-demo /tmp/piglor-126.db <timeline-id> \
  --ticks 20 --quantum-ms 100 --pace-ms 100
```

Users submit society signals and human actions to the Gateway. The experiment command prints each `TickOutcome` and final counters. The Gateway README and experiment help explain that both processes must point to the same SQLite file.

## Error handling

- Decreasing simulation time: explicit experiment/runtime error before mutation; retry with a valid time is allowed.
- Mixed all-driver/cadenced stepping: explicit mode-mismatch error before mutation; rebuild or resume to select a different mode.
- Cadence interval arithmetic overflow: explicit runtime error; no driver executes.
- SQLite contention: wait up to the configured bounded timeout, then return a storage error.
- Event ceiling: HTTP 429 with no append; identified retries preserve duplicate/conflict semantics.
- Failure after folding or driver mutation begins: preserve #125 faulted-session behavior and recover through a fresh `resume()`.
- HTTP or barrier failure in the E2E fixture: release all waiters and shut down the listener so the test cannot hang.

## Verification

Test-first implementation covers:

- registry checked cadence arithmetic and deterministic ordering;
- monotonic `ExperimentSession::step_cadenced()` behavior, quiescence, fault boundaries, and compatibility of `step_tick()`;
- read-only completed-boundary projection access, fault-state refusal, and live-versus-replay state equality;
- configurable `AgentDriver` intervals;
- memory and SQLite `append_bounded()` all-or-nothing ceiling behavior;
- two SQLite connections contending successfully with contiguous sequence;
- Gateway ordinary and identified admission at the ceiling;
- the genuine TCP/Axum/Gateway/SQLite/Experiment/replay E2E scenario, including exact probe history `[0, 0, 1]` and fast/slow counts `3`/`2`;
- CLI defaults, overrides, zero-value rejection, invalid Timeline, finite termination, shutdown, and deterministic-time behavior;
- documentation command accuracy.

Existing CI is sufficient: `test` executes workspace tests and integration tests with `--include-ignored`; `clippy`, `coverage`, `asan`, `fmt`, dependency/security, Docker, WASM, and browser-parity gates remain required. No test is ignored or excluded from CI, and production coverage exclusions are forbidden.

## Documentation and ADR

ADR-019 is revised in place to state:

- cadence is driven by monotonic host-supplied simulation time;
- separate same-file SQLite writers serialize through immediate transactions and a bounded busy timeout;
- Gateway-owned event ceilings remain atomic under that supported two-writer model.

The Gateway README's statement that concurrent out-of-process mutation is unsupported is narrowed: arbitrary external database mutation remains unsupported, while a PiglorOS experiment host using the same store contract is explicitly supported. This is a clarification of the accepted architecture, not a new module or protocol, so no new ADR is needed.
