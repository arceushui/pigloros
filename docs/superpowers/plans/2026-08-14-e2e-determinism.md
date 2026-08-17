# Multi-rate Human/AI E2E Determinism Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship and prove the ADR-019 Wave 6.5 production path: deterministic multi-rate Agent drivers, human HTTP ingress during an atomic AI pass, consistent live projections, contiguous Gateway polling, and replay-equivalent state.

**Architecture:** `ExperimentSession` remains the Tick Boundary owner and gains a cadence-aware stepping mode driven by monotonic simulation time. Gateway and experiment host use separate connections to one SQLite Timeline; immediate transactions, a bounded busy timeout, and adapter-owned bounded append make that supported two-writer seam atomic. A real TCP/Axum integration test and a separate finite experiment CLI exercise the production modules without moving simulation ownership into Gateway.

**Tech Stack:** Rust workspace, `pos-core` EventStore port, Memory/SQLite adapters with rusqlite, `pos-runtime`, `pos-experiment`, `pos-plugin-agent`, `pos-plugin-society`, Axum/Tokio Gateway, `pos-time` replay, GitHub Actions, 99% line/region coverage.

## Global Constraints

- Follow `docs/superpowers/specs/2026-08-14-e2e-determinism-design.md` and accepted ADR-019 v14.
- One durable SQLite Timeline is authoritative; do not add an in-memory cross-process seam or expose Gateway store ownership.
- Timeline `seq` is authoritative; `wall_time` never reorders Events.
- Cadence uses monotonic caller-supplied simulation nanoseconds; wall-clock sleep is demo pacing only.
- Due drivers run in registration order against one immutable snapshot and append one atomic draft batch.
- Keep `step_tick()` compatibility, but reject mixing all-driver and cadenced modes on one session before mutation.
- Faulted sessions must refuse projection access and mutable work; recovery remains fresh `resume()`.
- No migration: product Timeline data is not deployed.
- No new external dependency, crate, plugin, protocol, CI workflow, ignored test, or production `coverage(off)`.
- Every commit gets targeted tests, exact-file staging, Redmine #126 and Notion journal updates, and storage monitoring.
- Run targeted tests during each red/green implementation step and the repository-required local coverage check after every code change. Before publication, run the full local workspace, ASan, coverage, WASM/browser, and dependency gates; GitHub Actions repeats the applicable gates remotely.

---

### Task 1: Atomic bounded append and SQLite writer serialization

**Files:**
- Modify: `crates/pos-core/src/store.rs`
- Modify: `crates/pos-store/src/memory.rs`
- Modify: `crates/pos-store/src/sqlite.rs`

**Interfaces:**
- Produces: `EventStore::append_bounded(&mut self, TimelineId, &[EventDraft], u64) -> Result<Option<Vec<Event>>, CoreError>`
- Produces: SQLite generic append serialized by `TransactionBehavior::Immediate` and a four-second busy timeout
- Consumes: existing logical-sequence translation, generic Timeline visibility checks, and adapter append helpers

- [x] **Step 1: Add failing EventStore default-contract tests**

Add a default-stub assertion beside `event_store_defaults_fail_closed`:

```rust
let result = store.append_bounded(
    TimelineId::new(),
    &[EventDraft::new(
        EntityId::new(),
        Kind::new("test.event"),
        CanonicalBytes::from_vec(Vec::new()),
    )],
    1,
);
assert!(result.unwrap_err().to_string().contains("atomic bounded append"));
```

- [x] **Step 2: Add failing MemoryStore ceiling tests**

Cover: exact-fit batch succeeds, over-limit batch returns `None`, rejection leaves head/events unchanged, empty batch succeeds without changing head, and a Fork counts only owned Events.

```rust
assert_eq!(store.append_bounded(timeline.id(), &two_drafts, 1).unwrap(), None);
assert_eq!(store.get_timeline(timeline.id()).unwrap().unwrap().head, Seq::ZERO);
assert!(store.read_own(timeline.id(), SeqRange::all()).unwrap().is_empty());
```

- [x] **Step 3: Add failing SQLite bounded-append and contention tests**

Use a temporary file. Verify the same ceiling cases as Memory. For contention:

```rust
let path = database.path().to_str().unwrap().to_owned();
let mut store_a = SqliteStore::open(&path).unwrap();
let timeline = store_a.create_timeline("contended").unwrap();
store_a.append(timeline.id(), &[draft("a")]).unwrap();
let mut store_b = SqliteStore::open(&path).unwrap();

let blocker = rusqlite::Connection::open(&path).unwrap();
blocker.execute_batch("BEGIN IMMEDIATE; UPDATE timelines SET name = name;").unwrap();

let (started_tx, started_rx) = std::sync::mpsc::channel();
let (done_tx, done_rx) = std::sync::mpsc::channel();
let timeline_id = timeline.id();
let worker = std::thread::spawn(move || {
    started_tx.send(()).unwrap();
    let result = store_b.append(timeline_id, &[draft("b")]);
    done_tx.send(result).unwrap();
});
started_rx.recv().unwrap();
assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
blocker.execute_batch("COMMIT;").unwrap();
assert_eq!(done_rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap().len(), 1);
worker.join().unwrap();
```

Both stores must be fully opened before the blocker acquires its lock, so schema initialization cannot consume the contention window. Read through a fresh store and assert sequences `[1, 2]` and payload order `a, b`.

- [x] **Step 4: Run the store tests and confirm RED**

Run:

```bash
cargo test -p pos-core event_store_defaults_fail_closed --locked
cargo test -p pos-store bounded_append --locked
cargo test -p pos-store sqlite_writer_contention --locked
```

Expected: failures because the new port and adapter behavior do not exist.

- [x] **Step 5: Add the fail-closed EventStore port**

Add to `EventStore`:

```rust
fn append_bounded(
    &mut self,
    _timeline: TimelineId,
    _drafts: &[EventDraft],
    _max_owned_events: u64,
) -> Result<Option<Vec<Event>>, CoreError> {
    Err(CoreError::Storage(
        "atomic bounded append is unsupported by this EventStore".to_owned(),
    ))
}
```

Do not fall back to `get_timeline()` plus `append()` because that recreates the race this task removes.

- [x] **Step 6: Implement MemoryStore all-or-nothing bounded append**

Reuse generic visibility validation and logical prefix translation. Compute `owned_head.checked_add(drafts.len())`; return a storage overflow error on conversion/arithmetic failure, `Ok(None)` when the result exceeds the maximum, otherwise call the same internal batch append used by `append()`.

- [x] **Step 7: Implement SQLite busy timeout, immediate append, and bounded append**

Add:

```rust
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(4);
```

Call `conn.busy_timeout(SQLITE_BUSY_TIMEOUT)` during every `open_with_hasher()`. Change `append_visible()` to `transaction_with_behavior(TransactionBehavior::Immediate)`. Implement bounded append with one immediate transaction that reads local `head_seq`, checks `head + batch_len <= max`, appends every draft through `append_one_in_transaction`, commits, and translates to logical sequence only after commit.

- [x] **Step 8: Run targeted tests and adapter regression suites**

Run:

```bash
cargo test -p pos-core event_store_defaults_fail_closed --locked
cargo test -p pos-store --all-features bounded_append --locked
cargo test -p pos-store --all-features sqlite_writer_contention --locked
cargo test -p pos-store --all-features --locked
```

Expected: all pass with no ignored tests.

- [x] **Step 9: Commit the store contract**

```bash
git add crates/pos-core/src/store.rs crates/pos-store/src/memory.rs crates/pos-store/src/sqlite.rs
git commit -m "feat: serialize bounded event appends"
```

Journal the exact tests and storage level.

---

### Task 2: Atomic Gateway event-ceiling admission

**Files:**
- Modify: `apps/piglor-gateway/src/executor.rs`
- Modify: `apps/piglor-gateway/src/lib.rs`
- Modify: `apps/piglor-gateway/README.md`

**Interfaces:**
- Consumes: `EventStore::append_bounded(..., MAX_EVENTS_PER_TIMELINE)` from Task 1
- Preserves: identified ingress identity-first bounded append and HTTP 429 mapping for `"event limit reached"`

- [x] **Step 1: Add failing executor tests for the ordinary path**

Create a recording EventStore double whose `get_timeline()` panics and whose `append_bounded()` records the maximum and returns either `Some(events)` or `None`. Assert ordinary action/signal admission calls only the atomic method when a ceiling is supplied.

```rust
fn append_bounded(
    &mut self,
    timeline: TimelineId,
    drafts: &[EventDraft],
    maximum: u64,
) -> Result<Option<Vec<Event>>, CoreError> {
    self.calls.push((timeline, drafts.len(), maximum));
    Ok(self.outcome.take())
}
```

- [x] **Step 2: Add a failing two-Gateway-connection ceiling test**

Open two `Gateway` instances on the same SQLite file and one Timeline at `MAX_EVENTS_PER_TIMELINE - 1`. Release two concurrent ordinary appends from a barrier. Assert exactly one succeeds, exactly one returns `GatewayError::EventLimitReached`, and a fresh store reports exactly the maximum owned head with no overflow.

- [x] **Step 3: Run Gateway tests and confirm RED**

Run:

```bash
cargo test -p piglor-gateway execute_append_command --locked
cargo test -p piglor-gateway sqlite_gateways_enforce_one_atomic_event_ceiling --locked
```

Expected: the recording double observes the old `get_timeline` path or both external writers can pass the pre-check.

- [x] **Step 4: Replace the executor pre-check with bounded append**

Implement without a separate metadata read:

```rust
let result = match maximum {
    Some(maximum) => store
        .append_bounded(timeline, drafts, maximum)
        .and_then(|events| {
            events.ok_or_else(|| CoreError::Storage("event limit reached".to_owned()))
        }),
    None => store.append(timeline, drafts),
};
```

Keep the existing error string so the established HTTP 429 conversion remains stable.

- [x] **Step 5: Correct the supported SQLite writer boundary documentation**

Replace the blanket prohibition in `apps/piglor-gateway/README.md` with:

```markdown
The supported multi-process boundary permits PiglorOS Gateway and experiment-host
processes to open the same SQLite Timeline through `EventStore`. Immediate writer
transactions and a bounded busy timeout serialize their appends, and Gateway
ceilings are enforced atomically by the adapter. Arbitrary SQL mutation by tools
that bypass `EventStore` remains unsupported while the file is open.
```

- [x] **Step 6: Run targeted Gateway tests**

Run:

```bash
cargo test -p piglor-gateway --all-features execute_append_command --locked
cargo test -p piglor-gateway --all-features sqlite_gateways_enforce_one_atomic_event_ceiling --locked
cargo test -p piglor-gateway --all-features concurrent_limit --locked
```

Expected: all pass; identified retry-at-ceiling tests remain green.

- [x] **Step 7: Commit Gateway admission**

```bash
git add apps/piglor-gateway/src/executor.rs apps/piglor-gateway/src/lib.rs apps/piglor-gateway/README.md
git commit -m "fix: enforce gateway event limits atomically"
```

Journal behavior, tests, and ADR-019 v14 linkage.

---

### Task 3: Checked runtime cadence and configurable real Agent intervals

**Files:**
- Modify: `crates/pos-runtime/src/error.rs`
- Modify: `crates/pos-runtime/src/registry.rs`
- Modify: `plugins/agent/src/lib.rs`

**Interfaces:**
- Produces: `RuntimeError::CadenceOverflow { driver, previous_ns, interval_ns }`
- Produces: `AgentDriver::with_tick_interval(Duration) -> AgentDriver`
- Preserves: default Agent cadence of 100 ms and registration-order draft batches

- [x] **Step 1: Add failing cadence-overflow tests**

Register a driver with `Duration::from_nanos(2)`, tick it at `u128::MAX - 1`, then tick at `u128::MAX`. Assert a named `CadenceOverflow` error and no second driver execution. Add a three-driver test proving due-driver draft order remains registration order when one driver is skipped.

- [x] **Step 2: Add failing AgentDriver interval tests**

Assert `AgentDriver::new(...).tick_interval() == Duration::from_millis(100)` and the builder returns 200 ms while preserving decision behavior.

- [x] **Step 3: Run runtime and Agent tests and confirm RED**

Run:

```bash
cargo test -p pos-runtime cadence --locked
cargo test -p pos-plugin-agent tick_interval --locked
```

- [x] **Step 4: Add checked due-time calculation**

Before snapshot creation, collect due driver IDs with:

```rust
let due_at = previous_ns.checked_add(interval_ns).ok_or_else(|| {
    RuntimeError::CadenceOverflow {
        driver: entry.name.clone(),
        previous_ns,
        interval_ns,
    }
})?;
let ready = now_ns >= due_at;
```

Because eligibility is fully computed before stepping, overflow emits no drafts and mutates no driver.

- [x] **Step 5: Add AgentDriver interval storage and builder**

Add `tick_interval: Duration`, initialize it to 100 ms, provide `with_tick_interval`, and override the trait method:

```rust
fn tick_interval(&self) -> Duration {
    self.tick_interval
}
```

- [x] **Step 6: Run targeted crate suites**

Run:

```bash
cargo test -p pos-runtime --all-features --locked
cargo test -p pos-plugin-agent --all-features --locked
cargo clippy -p pos-runtime -p pos-plugin-agent --all-targets --all-features --locked -- -D warnings
```

- [x] **Step 7: Commit cadence primitives**

```bash
git add crates/pos-runtime/src/error.rs crates/pos-runtime/src/registry.rs plugins/agent/src/lib.rs
git commit -m "feat: make agent cadence deterministic"
```

Journal the exact default/override/overflow/order evidence.

---

### Task 4: Cadence-aware ExperimentSession and fault-safe projection access

**Files:**
- Modify: `apps/pos-experiment/src/lib.rs`

**Interfaces:**
- Produces: `ExperimentSession::step_cadenced(now_ns: u128) -> Result<TickOutcome, ExperimentError>`
- Produces: `ExperimentSession::projections() -> Result<&ProjectionRegistry, ExperimentError>`
- Produces: `ExperimentError::CadenceTimeRegressed { previous_ns: u128, requested_ns: u128 }`
- Produces: `ExperimentError::StepModeMismatch { active: &'static str, requested: &'static str }`
- Consumes: `PluginRegistry::tick_cadenced` from Task 3

- [x] **Step 1: Add failing monotonic cadence tests**

Register 100 ms and 200 ms counting drivers. Call `step_cadenced(0)`, `step_cadenced(100_000_000)`, and `step_cadenced(200_000_000)`. Assert counts `3` and `2`, exact `TickOutcome` values, and registration-order output.

- [x] **Step 2: Add failing pre-mutation validation tests**

Cover equal time (allowed), decreasing time (error but session remains usable), `step_tick()` then `step_cadenced()` mismatch, and the reverse mismatch. Capture Timeline head, projection state, driver counts, and tick count before each invalid call; assert all remain unchanged.

- [x] **Step 3: Add failing projection accessor tests**

Assert a healthy completed boundary exposes reducer-specific state. Inject a driver failure after a pre-fold changed projections, then assert:

```rust
assert!(matches!(session.projections(), Err(ExperimentError::SessionFaulted)));
```

Also assert a resumed fresh session exposes the replay-hydrated projection.

- [x] **Step 4: Run Experiment tests and confirm RED**

Run:

```bash
cargo test -p pos-experiment step_cadenced --locked
cargo test -p pos-experiment projection_access --locked
```

- [x] **Step 5: Refactor one private Tick Boundary pipeline**

Add private selections:

```rust
enum StepMode { AllDrivers, Cadenced }
enum StepRequest { AllDrivers, Cadenced(u128) }
```

Store `step_mode: Option<StepMode>` and `last_simulation_time_ns: Option<u128>` in every constructor/resume/fork path. Refactor the current body into `step_boundary(selection)`. Select drafts with `step_all()` or `tick_cadenced()`, but leave pre-fold, validation, atomic append, post-fold, health, counters, quiescence, and stop handling shared.

Add exact public errors:

```rust
#[error("cadence time regressed from {previous_ns}ns to {requested_ns}ns")]
CadenceTimeRegressed { previous_ns: u128, requested_ns: u128 },
#[error("cannot use {requested} stepping after session selected {active} stepping")]
StepModeMismatch { active: &'static str, requested: &'static str },
```

`start()`, `resume()`, and the child returned by `fork()` all construct fresh runtime state with `step_mode: None` and `last_simulation_time_ns: None`. The parent session retains its existing mode/time. This matches the existing fresh-driver semantics for resume and fork; each new live session selects its own stepping mode on its first successful boundary.

- [x] **Step 6: Validate mode/time before capture and latch only on success**

`step_cadenced()` rejects `now_ns < last_simulation_time_ns` and mode mismatch before `capture_pending_range()`. `step_tick()` performs the same mode check. After a successful boundary, set the mode and Simulation Time. Errors after projection/driver mutation preserve existing fault semantics.

- [x] **Step 7: Add the fault-safe projection accessor**

```rust
pub fn projections(&self) -> Result<&pos_state::ProjectionRegistry, ExperimentError> {
    if self.health == SessionHealth::Faulted {
        Err(ExperimentError::SessionFaulted)
    } else {
        Ok(&self.registry.projections)
    }
}
```

- [x] **Step 8: Run the complete Experiment suite and clippy**

Run:

```bash
cargo test -p pos-experiment --all-features --locked -- --include-ignored
cargo clippy -p pos-experiment --all-targets --all-features --locked -- -D warnings
```

- [x] **Step 9: Commit the production host**

```bash
git add apps/pos-experiment/src/lib.rs
git commit -m "feat: add cadence-aware experiment boundaries"
```

Journal all state-machine and fault-boundary evidence.

---

### Task 5: Genuine HTTP multi-rate determinism integration test

**Files:**
- Modify: `apps/piglor-gateway/Cargo.toml`
- Create: `apps/piglor-gateway/tests/e2e_determinism.rs`

**Interfaces:**
- Consumes: public `router`, `AppState`, `Gateway`, `Experiment::resume`, `step_cadenced`, `projections`, Agent/Society plugins, `EntityStateProjection`, and `pos_time::replay`
- Produces: one normal workspace integration test executed by CI `test`, coverage, and ASan jobs

- [x] **Step 1: Add exact dev-dependencies**

Add path dev-dependencies for `pos-experiment`, `pos-runtime`, `pos-state`, `pos-time`, and `pos-plugin-agent`, plus workspace `tempfile`. Do not add an HTTP client dependency; use a small blocking TCP helper so the test covers real HTTP without expanding the dependency graph.

- [x] **Step 2: Build the failing HTTP fixture**

Use `#[tokio::test(flavor = "multi_thread", worker_threads = 4)]`. In `e2e_determinism.rs`, bind `tokio::net::TcpListener` to `127.0.0.1:0`, create the Gateway store through `open_store(StoreConfig::Sqlite { path })`, construct public `AppState`, and spawn `axum::serve(listener, router(state))` with a oneshot graceful shutdown.

Implement `request_http()` as an async wrapper around `tokio::task::spawn_blocking(move || request_http_blocking(...))`. The blocking function writes `Connection: close`, reads the full response, splits at `\r\n\r\n`, parses the status code, and decodes the JSON body; it never runs on a Tokio worker.

Add an RAII `FixtureGuard` that owns optional policy-release and server-shutdown senders plus the server `JoinHandle`. Its `Drop` sends both signals and aborts the server as a panic fallback. Its async `shutdown(mut self)` sends both signals, awaits the server, and clears the handle. Every success path calls `shutdown`; every panic/error path is still released by `Drop`.

- [x] **Step 3: Define the exact test-only reducer/driver split**

Register in this order:

```text
1. reducer-only observation plugin + EntityStateProjection
2. SocietyPlugin + SocietyReducer
3. fast AgentPlugin + AgentDriver(100 ms)
4. driver-only ObservationProbeDriver(100 ms)
5. slow AgentPlugin + AgentDriver(200 ms)
```

`ObservationProbeDriver` subscribes only to the human entity, reads `event_count`, appends it to an `Arc<Mutex<Vec<u64>>>` capped at three entries, and returns `StepOutput::empty()`.

- [x] **Step 4: Define the barrier AgentPolicy**

Wrap a deterministic action policy. When `AgentContext.tick == 1`, send `snapshot_ready` and wait for `release`. Return a fixed action afterward. The barrier is in the fast Agent's second decision, so the immutable snapshot already exists when the test receives readiness.

- [x] **Step 5: Write the E2E assertions before implementation is complete**

Through `request_http()`, create the Timeline and POST the initial society signal. Resume through a second SQLite connection. Step at `0`. Move the session into `tokio::task::spawn_blocking` for `100 ms`; after readiness, POST the human action and require HTTP 201 before releasing the fast policy. Recover the session from the blocking task, then step at `200 ms`.

Assert:

```rust
assert_eq!(*probe_log.lock().unwrap(), vec![0, 0, 1]);
assert_eq!(fast_decisions.load(Ordering::SeqCst), 3);
assert_eq!(slow_decisions.load(Ordering::SeqCst), 2);
```

Poll through HTTP to exhaustion and assert contiguous `seq`. Assert the human `world.action` sequence is lower than the `agent.action` emitted by the blocked pass.

- [x] **Step 6: Compare live projections with two fresh replays**

Read reducer-specific state from `session.projections()?`. Open two fresh stores/registries containing the same reducers, call `pos_time::replay` twice, and compare serialized reducer/entity states. Assert final human `event_count == 1`, society signal count/mean is exact, and fast/slow agent counts are `3`/`2`.

- [x] **Step 7: Run the integration test and fix only contract mismatches**

Run:

```bash
cargo test -p piglor-gateway --test e2e_determinism --locked -- --nocapture
```

Expected: one deterministic pass, no ignored test, no sleep-based cadence, listener always shut down.

- [x] **Step 8: Prove CI discovery**

Run:

```bash
cargo test -p piglor-gateway --test e2e_determinism --locked -- --list \
  | rg '^multi_rate_human_ai_replay_is_deterministic:'
```

Expected: the exact named test appears in the targeted test-harness stdout. Do not run a local full-workspace discovery build. After push, inspect the remote `test` job log and verify `multi_rate_human_ai_replay_is_deterministic` executes under the authoritative workspace `--include-ignored` command.

- [x] **Step 9: Commit the E2E proof**

```bash
git add apps/piglor-gateway/Cargo.toml apps/piglor-gateway/tests/e2e_determinism.rs Cargo.lock
git commit -m "test: prove multi-rate gateway replay determinism"
```

Stage `Cargo.lock` only if Cargo changed it. Journal exact sequence/probe/count/replay evidence.

---

### Task 6: Finite separate multi-rate experiment demo

**Files:**
- Modify: `apps/pos-experiment/Cargo.toml`
- Modify: `apps/pos-experiment/src/main.rs`
- Create: `apps/pos-experiment/README.md`
- Modify: `apps/piglor-gateway/README.md`

**Interfaces:**
- Produces CLI: `pos-experiment multi-rate-demo <sqlite-path> <timeline-id> [--ticks N] [--quantum-ms N] [--pace-ms N]`
- Defaults: 20 boundaries, 100 ms simulation quantum, 100 ms pacing
- Produces: `parse_args(&[String]) -> Result<Command, DemoError>`
- Produces: `run_multi_rate_demo(&DemoArgs) -> Result<DemoSummary, DemoError>`
- Consumes: Task 4 cadence API and configurable Agent drivers

- [x] **Step 1: Add failing pure argument-parser tests**

Cover help/no command, exact defaults, each override, reordered flags, duplicate flags, unknown flags, extra positionals, invalid Timeline ID, `ticks == 0`, `quantum_ms == 0`, and allowed `pace_ms == 0`.

```rust
assert_eq!(parsed.ticks, 20);
assert_eq!(parsed.quantum_ms, 100);
assert_eq!(parsed.pace_ms, 100);
```

- [x] **Step 2: Add failing finite-loop tests**

Use a temporary SQLite Timeline and `pace_ms = 0`. Run three boundaries and assert printed/returned outcomes have simulation times `0`, `100_000_000`, `200_000_000`, fast count `3`, slow count `2`, and finite termination after exactly three iterations. Add missing Timeline and overflowed millisecond-to-nanosecond tests.

- [x] **Step 3: Run CLI tests and confirm RED**

Run:

```bash
cargo test -p pos-experiment --bin pos-experiment multi_rate_demo --locked
```

- [x] **Step 4: Add only the required plugin dependencies**

Add path dependencies for `pos-plugin-agent` and `pos-plugin-society`. Do not add Gateway as a dependency; the demo opens the same SQLite file independently.

- [x] **Step 5: Implement parser and finite deterministic loop**

Define the interfaces in `main.rs`:

```rust
enum Command { Help, MultiRate(DemoArgs) }
struct DemoArgs {
    sqlite_path: String,
    timeline_id: TimelineId,
    ticks: u64,
    quantum_ms: u64,
    pace_ms: u64,
}
struct DemoSummary { boundaries: u64, fast_actions: u64, slow_actions: u64 }
#[derive(Debug, thiserror::Error)]
enum DemoError {
    #[error("{0}")] Usage(String),
    #[error("invalid Timeline id: {0}")] InvalidTimeline(String),
    #[error("ticks must be greater than zero")] ZeroTicks,
    #[error("quantum-ms must be greater than zero")] ZeroQuantum,
    #[error("simulation time overflow")] SimulationTimeOverflow,
    #[error(transparent)] Experiment(#[from] ExperimentError),
}
fn parse_args(args: &[String]) -> Result<Command, DemoError>;
fn run_multi_rate_demo(args: &DemoArgs) -> Result<DemoSummary, DemoError>;
```

In `run_multi_rate_demo`, build the plugin registry, resume the supplied Timeline, and for index `0..ticks` compute:

```rust
let now_ns = u128::from(index)
    .checked_mul(u128::from(quantum_ms))
    .and_then(|millis| millis.checked_mul(1_000_000))
    .ok_or(DemoError::SimulationTimeOverflow)?;
let outcome = session.step_cadenced(now_ns)?;
```

Sleep for `pace_ms` only after each completed boundary and skip sleep when it is zero. Print time, outcome, and final counts.

- [x] **Step 6: Document the two-process workflow**

Document exact Gateway and demo commands, same-file requirement, HTTP society/action examples, deterministic-time meaning, finite defaults, fault/restart guidance, and the fact that arbitrary SQL writers remain unsupported.

- [x] **Step 7: Run CLI and documentation-adjacent tests**

Run:

```bash
cargo test -p pos-experiment --all-features --locked -- --include-ignored
cargo run -p pos-experiment --locked -- multi-rate-demo --help
cargo clippy -p pos-experiment --all-targets --all-features --locked -- -D warnings
```

- [x] **Step 8: Commit the demo**

```bash
git add apps/pos-experiment/Cargo.toml apps/pos-experiment/src/main.rs apps/pos-experiment/README.md apps/piglor-gateway/README.md Cargo.lock
git commit -m "feat: add deterministic multi-rate demo"
```

Stage `Cargo.lock` only if changed. Journal commands and finite-loop evidence.

---

### Task 7: Requirement audit, review, remote gates, rebase, and integration

**Files:**
- Modify only if review or gates find an evidence-backed defect
- Update progress checkboxes in this plan as tasks complete

**Interfaces:**
- Consumes: all prior tasks
- Produces: Sol-approved, fully green, rebased, merged #126 with closed journals and cleaned worktree

- [x] **Step 1: Run focused local policy checks**

Run:

```bash
cargo fmt --all -- --check
git diff --check
bash scripts/check-test-policy.sh
bash scripts/check-pinned-dependencies.sh
bash scripts/test-check-pinned-dependencies.sh
bash scripts/check-asan-ci-policy.sh
python3 scripts/test_check_asan_ci_policy.py
```

- [x] **Step 2: Audit every design requirement against code/tests**

Produce a checklist mapping each design section to a file, test name, and expected assertion: atomic ceiling, forced contention, monotonic time, mode latch, fault-safe projections, real HTTP 201 mid-pass, `[0,0,1]`, `3/2`, contiguous sequence, two replays, finite demo, README, ADR-019 v14, CI discovery, no exclusions.

- [x] **Step 3: Request two-axis code review and final Sol CTO review**

Review `origin/main..HEAD` for repository standards and Redmine #126/spec compliance. The CTO reviewer must explicitly use `gpt-5.6-sol`. Address every evidence-backed blocker in separate exact-file commits, rerun affected tests, then obtain final `APPROVE`. Any new design decision updates ADR-019 before code.

- [ ] **Step 4: Push the working branch and open a PR**

```bash
git push -u origin ticket-126-e2e-determinism
gh pr create --base main --head ticket-126-e2e-determinism \
  --title "feat: prove multi-rate human AI determinism" \
  --body "Closes Redmine #126. Implements ADR-019 v14 and the approved E2E design."
```

- [ ] **Step 5: Monitor every GitHub gate and logs**

Require green: test with `--include-ignored`, coverage at or above 99% lines and regions, clippy pedantic/deny warnings, fmt, ASan, cargo-deny, audit, geiger, dependency graph, pinned dependencies, Docker, module report, Trunk, WASM, and browser parity. Diagnose failures from job logs; do not waive or skip a gate.

- [ ] **Step 6: Rebase onto current main and rerun gates**

```bash
git fetch origin main
git rebase origin/main
git push --force-with-lease
```

If rebase is a no-op, record the unchanged SHA. Trigger/observe a fresh complete CI set after the rebase state.

- [ ] **Step 7: Merge only after final evidence**

Require clean worktree, PR mergeable/clean, all gates green, exact Sol approval, ADR/Redmine/Notion current, and storage safe. Merge using the repository merge-commit convention.

- [ ] **Step 8: Verify main and close #126**

Fast-forward `/root/pigloros`, monitor post-merge main workflows to green, then mark Redmine #126 Resolved at 100% with merge SHA and evidence. Add a user-facing Notion section explaining what changed and how to run the demo.

- [ ] **Step 9: Clean exact completed resources**

Remove `/root/pigloros-ticket-126-e2e-determinism`, delete merged local/remote feature branches, and clean rebuildable artifacts. Preserve `/root/pigloros-ticket-169-geo-location-admission`. Record final free space and worktree inventory.
