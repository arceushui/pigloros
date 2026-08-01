# Core-Owned V1 `geo.location` Admission Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` or `executing-plans` to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Implement #169’s private, atomic V1 `geo.location` admission transaction required by Accepted ADR-053.

**Architecture:** A non-forgeable core admission request carries the already-minimized V1 payload and validated binding/consent state into a backend-owned transaction. Memory and SQLite atomically maintain the Event, Timeline/chain heads, immutable snapshot/link sidecar, geographic marker, and ADR-038 deduplication outcome; all generic geographic paths remain sealed.

**Tech Stack:** Rust 1.97.1, `pos-core`, `pos-store` Memory/SQLite, deterministic CBOR, BLAKE3, existing `StoreExecutor`.

## Global Constraints

- Existing V1 `geo.location` payload bytes are unchanged.
- No migration, backfill, dual write, upcast, H3 conversion, compatibility ladder, public HTTP route, or generic geographic API.
- Generic `EventStore` geographic append/import/read guards remain fail-closed.
- Snapshot/link storage is core-private and retained with the Timeline; private dedup state follows ADR-038’s seven-day lifecycle.
- Binding, consent identity/revision/hash, policy version, withdrawal state, Timeline, EntityId, and admission epoch are checked before dedup and rechecked in the same commit fence.
- `Accepted`/`Duplicate` are returned only after definite durable commitment; an uncertain irreversible outcome is retryable unavailable and never claims no mutation.
- Memory and SQLite parity, fault/race/replay checks, full CI gates, 100% lines/regions, and independent review are mandatory before merge.

---

### Task 1: Define private core admission contracts

**Files:**
- Create: `crates/pos-core/src/geo_admission.rs`
- Modify: `crates/pos-core/src/lib.rs`, `crates/pos-core/src/error.rs`
- Test: unit tests in `geo_admission.rs`

**Produces:** `GeoLocationAdmissionRequestV1`, immutable snapshot/link value types, opaque owner-keyed intent/fingerprint wrappers, `GeoLocationAdmissionOutcome`, and explicit unavailable/unknown error categories. These types must be constructible only by core-private constructors; ordinary Plugins and generic `EventStore` callers cannot manufacture them.

- [ ] Write failing tests proving canonical snapshot/link validation rejects a changed Timeline, Event sequence, consent hash, policy version, or epoch.
- [ ] Run `cargo test -p pos-core geo_admission` and observe the missing-module failure.
- [ ] Add the smallest private types and deterministic-CBOR validators to make those tests pass; use no floating point or caller-provided generated Event metadata.
- [ ] Add failing tests for exact same-intent, changed-intent, and unknown-outcome classification.
- [ ] Implement the outcome/value classification and rerun the focused tests.
- [ ] Commit only `pos-core` contract and tests.

### Task 2: Add the core-only storage port and Memory implementation

**Files:**
- Modify: `crates/pos-core/src/store.rs`, `crates/pos-core/src/lib.rs`
- Modify: `crates/pos-store/src/memory.rs`, `crates/pos-store/src/lib.rs`
- Test: `crates/pos-store/tests/geographic_admission.rs`

**Consumes:** Task 1 request/snapshot/link/outcome types.

**Produces:** A separate `GeoLocationAdmissionStore` capability, not a method on public generic append. Its single method performs the commit-fence check before deduplication and then atomically either appends every geographic artifact or none.

- [ ] Write failing Memory integration tests for accepted append, exact duplicate, conflict, revoked/stale fence denial before dedup, and no partial state after each failure.
- [ ] Run the integration test and observe the absent core admission capability.
- [ ] Implement the private port plus Memory maps/indexes for admission state, snapshots, links, geographic marker, and dedup recovery.
- [ ] Verify link uniqueness by `(timeline_id,event_id)`, both-direction lookup, and Timeline deletion cleanup; preserve generic guards.
- [ ] Rerun focused tests, then commit only the port/Memory/test changes.

### Task 3: Implement SQLite’s single transaction and current V1 schema initialization

**Files:**
- Modify: `crates/pos-store/src/sqlite.rs`
- Modify: `crates/pos-store/src/lib.rs`
- Test: `crates/pos-store/tests/geographic_admission.rs`

**Consumes:** Task 1 contracts and Task 2 behavioral contract.

**Produces:** SQLite tables/indexes created directly for current V1 development databases and one `BEGIN IMMEDIATE` operation that includes fence revalidation, dedup decision, Event/head write, snapshot/link insertion, marker update, and commit.

- [ ] Write failing SQLite parity tests for every Task 2 outcome plus commit failure, response-loss/unknown recovery, duplicate-link verification, and pre-existing unlinked geographic row fail-closed behavior.
- [ ] Run the SQLite integration test and observe the missing transactional implementation.
- [ ] Implement current-schema initialization only; do not introduce a migration path. Implement the transaction with checked rollback semantics and bounded error mapping.
- [ ] Add fault injection seams that prove pre-commit errors leave no mutation and post-commit uncertainty never appends speculatively during recovery.
- [ ] Rerun the focused SQLite tests and commit only SQLite/parity changes.

### Task 4: Wire the non-forgeable capability through the bounded Gateway executor

**Files:**
- Modify: `apps/piglor-gateway/src/executor.rs`, `apps/piglor-gateway/src/lib.rs`
- Test: `apps/piglor-gateway/src/lib.rs`, `apps/piglor-gateway/src/executor.rs`

**Consumes:** `GeoLocationAdmissionStore` from Tasks 1–3.

**Produces:** A bounded executor command available only to the core composition root, with explicit translation of accepted, duplicate, conflict, denied, unavailable, and unknown outcomes. It registers no HTTP route and gives no generic Gateway method permission to append geography.

- [ ] Write failing executor tests proving the command cannot be reached via generic action ingress and queue saturation/closure preserves bounded errors.
- [ ] Run the focused gateway tests and observe the absent command.
- [ ] Add the minimal executor command/reply plumbing and core-only façade.
- [ ] Add next-tick/event-notice assertions only for definite accepted new Events; duplicates and unknown results publish no new notice.
- [ ] Rerun focused tests and commit only Gateway changes.

### Task 5: Prove cross-backend lifecycle, Replay, and boundary invariants

**Files:**
- Modify: `crates/pos-store/tests/geographic_admission.rs`, `crates/pos-store/tests/geographic_boundary.rs`
- Modify: relevant unit-test modules only where fault seams are public test seams

**Consumes:** completed core, Memory, SQLite, and executor seams.

- [ ] Write failing parity/race tests for admission versus revoke, stale policy re-pair/re-consent, seven-day expiry, malformed/corrupt link, Replay lookup without a live policy/clock, and generic read/Fork/export denial.
- [ ] Run each focused test and confirm it fails for the required invariant rather than test setup.
- [ ] Make the smallest production changes required to satisfy each invariant; do not add test-only production branches or coverage exemptions.
- [ ] Run the focused Memory, SQLite, core, and Gateway suites; commit the completed acceptance tests and fixes.

### Task 6: Quality gates and independent review

**Files:** no intended production changes.

- [ ] Run `./scripts/ci.sh`, `cargo test --workspace --locked -- --include-ignored`, pedantic clippy, and the exact LLVM coverage command in a non-root test context.
- [ ] Fix every failure using a fresh failing test; rerun the affected test followed by all required gates.
- [ ] Request independent review against `main` and Accepted ADR-053; address findings with a separate review/fix cycle.
- [ ] Record evidence in Redmine #169 and Notion, resolve #169 only after a clean review and all gates, then begin #146’s dependent CLI/config implementation.
