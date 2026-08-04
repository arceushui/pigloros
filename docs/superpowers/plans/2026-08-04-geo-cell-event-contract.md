# Core-Owned GeoCell Event Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the accepted ADR-037 V1 `geo.cell` Event admission contract while preserving the existing `geo.location` path and all ADR-034 activation gates.

**Architecture:** Add a distinct `pos-core` contract module that owns the neutral validated GeoCell boundary, strict six-field canonical payload, immutable admission snapshot types, five-outcome admission result, and Replay verification port. Add independent MemoryStore and SQLite implementations that stage and commit snapshot/link/Event/head/dedup state as one unit; generic EventStore and Plugin/Gateway paths remain closed. The plugin only supplies an already validated ADR-031 cell through a neutral core constructor; `pos-core` never depends on `pos-plugin-geo`.

**Tech Stack:** Rust 2021, `pos-core`, `pos-store`, `pos-crypto` configured `Hasher`, `ciborium`/RFC 8949 canonical CBOR, SQLite WAL, in-memory adapter, existing ULID and Timeline primitives.

## Global Constraints

- Preserve `geo.location` behavior and its existing `GeoLocationAdmissionStore`; do not rename or reuse that trait for `geo.cell`.
- Keep `geo.cell` rejected by generic append, committed append, import, export, fork visibility, plugin schema registration, and gateway paths.
- Do not add migration, coexistence, backfill, dual-write, upcast, OwnTracks reinterpretation, route, or production activation.
- The outer Event schema is exactly V1; the payload is the ADR-037 six-field canonical CBOR map and must match the 262-byte fixture and 266-byte maximum.
- Snapshot ID/hash, Event ID, sequence, payload hash, Timeline head, and chain head are transaction-owned; callers cannot supply them.
- Private fingerprint and canonical intent never enter Event bytes, public results, logs, metrics, export, or Replay.
- The admission fingerprint is produced by the authenticated source-specific ingress; callers cannot choose or replace it at the Event/public boundary.
- The immutable snapshot uses the ADR-034 fifteen-field schema and raw `BLAKE3(canonical_snapshot_bytes)`; its retained object contains no request, fingerprint, or dedup intent.
- Memory and SQLite must provide equivalent atomicity, fault, concurrency, Replay, retention, and outcome classification.
- New tests must run through the repository CI test job (`--include-ignored`); no test is local-only.

---

### Task 1: Freeze the contract and neutral cell boundary

**Files:**
- Create: `crates/pos-core/src/geo_cell_admission.rs`
- Modify: `crates/pos-core/src/lib.rs`
- Modify: `crates/pos-core/src/error.rs`
- Modify: `plugins/geo/src/geo_cell.rs`
- Test: `crates/pos-core/src/geo_cell_admission.rs`

- [x] **Step 1: Write failing contract tests** for the exact ADR-037 fixture, six outer keys, signed bucket, 266-byte bound, duplicate/unknown/wrong-type/non-canonical/trailing input rejection, and conversion of the existing validated plugin cell into the neutral core value.
- [x] **Step 2: Run the focused tests and verify they fail** because the neutral value, payload codec, and error categories do not exist.
- [x] **Step 3: Implement the neutral `ValidatedGeoCellV1` value** with a private canonical byte representation and strict structural validation of the nested ADR-031 map. Add a plugin-side conversion that uses `GeoCellV1::encode_v1`, while keeping H3 implementation ownership in `plugins/geo`.
- [x] **Step 4: Implement `GeographicObservationV1` encode/decode** with strict canonical CBOR, `GeoCellObservationPolicyVersion(1)`, zero-only quality flags, signed source buckets, canonical ULID snapshot IDs, lower-case 64-character snapshot hashes, and exact fixture verification.
- [x] **Step 5: Run focused core and plugin tests** and commit `feat: add core geo.cell event codec`.

### Task 2: Define admission snapshots, request fencing, outcomes, and Replay

**Files:**
- Modify: `crates/pos-core/src/geo_cell_admission.rs`
- Modify: `crates/pos-core/src/lib.rs`
- Modify: `crates/pos-core/src/error.rs`
- Test: `crates/pos-core/src/geo_cell_admission.rs`

- [x] **Step 1: Write failing tests** for transaction-owned `AdmissionEntitlementSnapshotV1`, exact purpose/principal/scope/resolution fields, typed consent/snapshot hash domains, binding/consent/policy/epoch fence changes, five outcome variants, and non-enumerable recovery behavior.
- [x] **Step 2: Run the tests and verify the expected missing-type/API failures.**
- [x] **Step 3: Implement the distinct core-owned `GeographicAdmissionStore` port** with `ValidatedGeographicAdmissionV1`, `GeographicAdmissionOutcome::{Accepted,Duplicate,Conflict,Unavailable,OutcomeUnknown}`, transaction-owned result linkage, and an administrative fence seam usable only by trusted composition roots.
- [x] **Step 4: Implement canonical immutable snapshot/link types** and private exact-intent/fingerprint wrappers. Ensure source bucket and nested cell are the only geographic observation data in Event payload; no current disclosure consent or dedup material is serialized.
- [x] **Step 5: Implement the dedicated Replay verifier contract** that validates Event hash, exact snapshot link, immutable consent linkage, Event metadata, and typed hashes without consulting clock, network, current policy, or dedup.
- [x] **Step 6: Run focused core tests and commit `feat: define core geo.cell admission contract`.**

### Task 3: Add atomic MemoryStore admission

**Files:**
- Modify: `crates/pos-store/src/memory.rs`
- Test: `crates/pos-store/tests/geographic_cell_admission.rs`

- [x] **Step 1: Write failing MemoryStore integration tests** for accepted admission, exact duplicate, fingerprint conflict, fence denial before lookup, generated IDs/hashes, sidecar lockstep, atomic staged publication, seven-day expiry, concurrent-equivalent retry behavior, and unknown-outcome recovery.
- [x] **Step 2: Run the integration tests and verify they fail** because MemoryStore has no `GeographicAdmissionStore` implementation.
- [x] **Step 3: Add private MemoryStore state** for current geo.cell fences, immutable snapshots/links, private exact-intent dedup records, and geographic presence without reusing legacy location sidecars.
- [x] **Step 4: Implement staged admission**: recheck the fence, compare exact intent only after the fence, stage Event/head/chain/snapshot/link/dedup changes on cloned state, then publish all state together. Return `OutcomeUnknown` only through explicit test fault injection after a durable-commit boundary; never expose identifiers on unknown outcome.
- [x] **Step 5: Implement MemoryStore Replay verification and bounded dedup cleanup**, then run the full geographic-cell integration test file.
- [x] **Step 6: Commit `feat: add atomic in-memory geo.cell admission`.**

### Task 4: Add atomic SQLite admission without migration

**Files:**
- Modify: `crates/pos-store/src/sqlite.rs`
- Test: `crates/pos-store/tests/geographic_cell_admission.rs`
- Test: `crates/pos-store/tests/geographic_replay_verifier.rs`

- [x] **Step 1: Write failing SQLite tests** for fresh-database table creation, exact accepted/duplicate/conflict behavior, snapshot indexes, rollback at each staged write, definite commit failure, response-loss/unknown recovery, expiry, concurrency, and Replay corruption detection.
- [x] **Step 2: Run the tests and verify they fail** because the new tables and capability are absent.
- [x] **Step 3: Add fresh-install `CREATE TABLE IF NOT EXISTS` definitions** for geo.cell snapshots, immutable links, and private dedup intent. Do not add a migration or reuse `geographic_admission_*` legacy location tables.
- [x] **Step 4: Implement one `BEGIN IMMEDIATE` transaction** that re-fences state, validates exact entitlement, resolves exact dedup intent, allocates IDs/sequence, writes snapshot and both indexes, appends the reserved Event through a private transaction helper, updates heads, writes dedup, verifies pre-commit invariants, and commits once.
- [x] **Step 5: Implement explicit commit-outcome recovery** and dedicated Replay verification. Ensure any failure before commit rolls back and any uncertain post-commit path returns `OutcomeUnknown` without claiming no mutation or exposing linkage.
- [x] **Step 6: Run Memory+SQLite integration tests and commit `feat: add sqlite geo.cell admission`.**

### Task 5: Preserve all generic and activation boundaries

**Files:**
- Modify: `crates/pos-store/src/lib.rs`
- Modify: `crates/pos-runtime/src/schema.rs` only if a source-level reservation guard is required
- Modify: `plugins/geo/src/lib.rs` only for neutral cell conversion, never registration
- Test: `crates/pos-store/tests/geographic_boundary.rs`
- Test: `plugins/geo/src/lib.rs`

- [x] **Step 1: Write failing regression tests** proving generic append/import/export/fork, Plugin schema registration, gateway append, and disabled configuration cannot create or read `geo.cell`; only the dedicated capability accepts a validated request.
- [x] **Step 2: Run the regression tests and confirm the boundary behavior is explicit.**
- [x] **Step 3: Add only the minimal reservation/visibility guards** needed to keep all unprivileged paths closed; do not add activation, route, reducer, writer, or source adapter.
- [x] **Step 4: Run all boundary and legacy geo.location tests and commit `test: lock geo.cell activation boundary`.**

### Task 6: Full verification, review, and integration

**Files:**
- Modify: `docs/superpowers/plans/2026-08-04-geo-cell-event-contract.md` to mark completed steps.
- Modify: `scripts/ci.sh` or `.github/workflows/ci.yml` only if a required test/gate is not already covered.

- [x] **Step 1: Run focused tests, workspace tests with ignored tests, pedantic clippy, no-default-feature checks, dependency/policy checks, ASAN, and the configured 99% line/region coverage required by ADR-037.**
- [x] **Step 2: Run the two-axis code review against `main`, address every finding, and rerun every gate after the final fix.**
- [ ] **Step 3: Ask Harvey for final approval with exact commit and gate evidence.**
- [ ] **Step 4: Fetch/rebase onto current `origin/main`, rerun all gates after rebase, push the branch, open PR, wait for every remote check, and merge into `main`.**
- [ ] **Step 5: Update Redmine #149 and parent #64, append Notion closeout, verify merged main, and remove only the completed #149 worktree while preserving #169.**
