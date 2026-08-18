# Agent Decision Provider and Replay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement Redmine #62's bounded local provider-backed Agent decision path and provider-free immutable-Timeline replay verifier under Accepted ADR-046 revision 7.

**Architecture:** `pos-runtime` adds an anchored, append-aware Driver transaction while preserving deterministic Driver behavior. `pos-plugin-agent` adds a deep module around one bounded provider interface: exact protocol codecs and hashes stay internal, Live emits a decision record followed by an optional derived action, and replay verifies immutable source Events without a provider.

**Tech Stack:** Rust 2021 workspace, `pos-core`, `pos-runtime`, `pos-store`, `pos-plugin-agent`, `ciborium`, BLAKE3, Cargo nextest/LLVM coverage, GitHub Actions.

## Global Constraints

- ADR-046 revision 7 is Accepted and canonical; `docs/superpowers/specs/2026-08-17-agent-decision-provider-replay-design.md` is its implementation design.
- Keep existing `AgentDriver` and `AgentPolicy` behavior unchanged; provider-backed behavior is opt-in.
- Provider authority is limited to one bounded response per eligible Live boundary; it cannot select actor, Timeline, catalogue, provenance, Event type, or append behavior.
- No network, provider SDK, new external dependency, migration, backfill, dual-write, upcast, Gateway/client, sandbox/supervisor, ADR-021, or world/physics work.
- Exact PAC1/PQR1/PDP1/PDR1/PAA1 arrays, bounds, text grammar, no-action codes, classification precedence, and BLAKE3 contexts must match ADR-046.
- Replay receives no provider and never mutates or appends to the source Timeline.
- No test is skipped and no production coverage exclusion is added; final line and region coverage must each be at least 99%.

---

### Task 1: Anchored observation interface and Driver transaction hooks

**Files:**
- Modify: `crates/pos-runtime/src/driver.rs`
- Modify: `crates/pos-runtime/src/lib.rs`
- Modify: `crates/pos-runtime/src/error.rs`

**Interfaces:**
- Produces: `SnapshotAnchor`, `ObservationView::anchor()`, `Driver::requires_snapshot_anchor()`, `Driver::commit_step()`, and `Driver::abort_step()`.
- Preserves: existing `Driver` implementations compile unchanged through default methods.

- [ ] **Step 1: Write failing anchor and default-hook tests**

Add tests that build a snapshot with a known Timeline and `Seq`, assert every view returns the same anchor, assert `ObservationView::empty().anchor()` is `None`, and prove a legacy test Driver reports `requires_snapshot_anchor() == false` while default commit/abort are callable.

```rust
let anchor = SnapshotAnchor::new(timeline, Seq::from_u64(7));
let snapshot = ObservationSnapshot::anchored(anchor, std::iter::empty(), |_| None);
assert_eq!(snapshot.view_for(&[]).anchor(), Some(anchor));
assert_eq!(ObservationView::empty().anchor(), None);
assert!(!driver.requires_snapshot_anchor());
driver.commit_step();
driver.abort_step();
```

- [ ] **Step 2: Run the focused tests and confirm RED**

Run: `CARGO_TARGET_DIR=/root/pigloros/target cargo test -p pos-runtime --locked driver::tests::snapshot_anchor -- --exact`

Expected: compilation fails because the anchor interface does not exist.

- [ ] **Step 3: Implement the minimal runtime interface**

Add:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotAnchor {
    timeline_id: TimelineId,
    observed_through: Seq,
}

impl SnapshotAnchor {
    pub const fn new(timeline_id: TimelineId, observed_through: Seq) -> Self;
    pub const fn timeline_id(self) -> TimelineId;
    pub const fn observed_through(self) -> Seq;
}
```

Store `Option<SnapshotAnchor>` in `ObservationSnapshot`, expose it from `ObservationView`, and add the three default Driver methods exactly as specified. Add stable `RuntimeError` variants `MissingSnapshotAnchor`, `SnapshotTimelineMismatch`, and `PendingDriverStep`; messages name only host-controlled Driver/Timeline facts.

- [ ] **Step 4: Run runtime tests and confirm GREEN**

Run: `CARGO_TARGET_DIR=/root/pigloros/target cargo test -p pos-runtime --locked -- --include-ignored`

Expected: every runtime unit/doc test passes.

- [ ] **Step 5: Commit**

```bash
git add crates/pos-runtime/src/driver.rs crates/pos-runtime/src/lib.rs crates/pos-runtime/src/error.rs
git commit -m "feat(runtime): anchor driver observations"
```

### Task 2: Registry pending-step transaction and anchored Experiment host

**Files:**
- Modify: `crates/pos-runtime/src/registry.rs`
- Modify: `apps/pos-experiment/src/lib.rs`

**Interfaces:**
- Consumes: Task 1 Driver hooks and `SnapshotAnchor`.
- Produces: `step_all_anchored`, `tick_cadenced_anchored`, `commit_step`, `abort_step`, and host append integration.

- [ ] **Step 1: Write failing registry transaction tests**

Create a stateful test Driver whose `step` sets `staged = true`, whose commit increments `committed`, and whose abort clears staging. Cover:

```rust
assert!(registry.step_all(timeline).is_err()); // selected driver requires anchor
let drafts = registry.step_all_anchored(timeline, Seq::from_u64(3)).unwrap();
assert_eq!(drafts.len(), 1);
assert!(matches!(
    registry.step_all_anchored(timeline, Seq::from_u64(3)),
    Err(RuntimeError::PendingDriverStep)
));
registry.abort_step();
assert!(registry.step_all_anchored(timeline, Seq::from_u64(3)).is_ok());
registry.commit_step();
```

Also assert that an error from a later Driver aborts every earlier staged Driver, anchored cadence timestamps are committed only by `commit_step`, and repeated legacy deterministic-only `step_all`/`tick_cadenced`/`TickScheduler::tick` calls remain immediate and usable without commit or abort. A mixed registry must reject legacy cadence before eligibility calculation even when its anchor-requiring provider Driver is interval-gated and not due.

- [ ] **Step 2: Run focused registry tests and confirm RED**

Run: `CARGO_TARGET_DIR=/root/pigloros/target cargo test -p pos-runtime --locked registry::tests::anchored -- --nocapture`

Expected: compilation fails because anchored and transaction methods do not exist.

- [ ] **Step 3: Implement one registry selection helper**

Preserve legacy `step_all` and `tick_cadenced` as immediate paths. They preflight every registered Driver before cadence eligibility calculation and reject before mutation if any requires an anchor; otherwise they retain existing deterministic stepping and immediate cadence updates.

Implement explicit anchored all-driver and cadenced paths through one private transactional helper. Before any mutation it rejects an existing pending batch. It builds one shared anchored snapshot, steps in registration order, aborts already-staged Drivers on any error, and marks the registry pending only after all selected Drivers succeed. Anchored cadence `last_tick` values are staged separately and copied into entries only in `commit_step`.

`commit_step()` calls every staged Driver's infallible hook, applies staged cadence values, and clears pending state. `abort_step()` calls every staged Driver's hook, discards staged cadence values, and clears pending state. Empty successful anchored selections still become pending so the host explicitly closes every boundary. Legacy selections never become pending.

- [ ] **Step 4: Write failing Experiment append-boundary tests**

Extend fault-injection tests to assert:

- the pre-fold cursor reaches the Driver as `SnapshotAnchor.observed_through`;
- schema failure calls abort and leaves committed Driver tick unchanged;
- append failure calls abort and leaves committed Driver tick unchanged;
- successful non-empty and zero-draft boundaries call commit exactly once;
- no post-append capture runs before commit.

Exercise both production paths: `ExperimentSession::step_boundary` and `Experiment::run` through `advance_tick`/`append_driver_drafts`. Include a partial-Driver failure after one earlier Driver staged state and prove both paths abort it.

- [ ] **Step 5: Connect the host transaction**

In `ExperimentSession::step_boundary`, call anchored registry methods with `self.boundary.folded_through`. In `append_driver_drafts`, accept the already-folded cursor from `advance_tick` and call the anchored all-driver method. On Driver/schema/append failure call `registry.abort_step()` before preserving each path's existing error or session-fault behavior. After an empty success or successful atomic append call `registry.commit_step()` before post-append capture. Do not change store atomicity or the existing post-append fold.

- [ ] **Step 6: Run runtime and experiment tests**

Run: `CARGO_TARGET_DIR=/root/pigloros/target cargo test -p pos-runtime -p pos-experiment --locked -- --include-ignored`

Expected: all tests pass, including existing deterministic cadence and fault tests.

- [ ] **Step 7: Commit**

```bash
git add crates/pos-runtime/src/registry.rs apps/pos-experiment/src/lib.rs
git commit -m "feat(runtime): commit driver state after append"
```

### Task 3: Bounded catalogue, provenance, and protocol value types

**Files:**
- Create: `plugins/agent/src/protocol.rs`
- Modify: `plugins/agent/src/lib.rs`
- Modify: `plugins/agent/Cargo.toml`

**Interfaces:**
- Produces: `ActionCatalogueV1`, `AgentProviderProvenanceV1`, `AgentDecisionRequestV1`, `ProviderDecisionV1`, `DecisionRecordV1`, `AgentActionV1`, `ProviderAttempt`, `ProviderFailureCode`, and `AgentDecisionError`.

- [ ] **Step 1: Write failing bounded-value table tests**

Use table-driven cases for catalogue counts 0/1/64/65; action byte lengths 0/1/64/65; duplicate exact bytes; all ASCII control characters and representative non-ASCII `Cc`; valid Unicode; provider IDs at every grammar edge; printable version strings; confidence `0`, `1_000_000`, and `1_000_001`; and response lengths 0/4096/4097.

```rust
assert!(ActionCatalogueV1::try_new(vec!["move".into()]).is_ok());
assert!(ActionCatalogueV1::try_new(Vec::new()).is_err());
assert!(ActionCatalogueV1::try_new(vec!["a".into(), "a".into()]).is_err());
assert!(BoundedProviderBytes::try_from(vec![0; 4096]).is_ok());
assert!(BoundedProviderBytes::try_from(vec![0; 4097]).is_err());
```

- [ ] **Step 2: Run the focused Agent test and confirm RED**

Run: `CARGO_TARGET_DIR=/root/pigloros/target cargo test -p pos-plugin-agent --locked protocol::tests::bounded -- --nocapture`

Expected: compilation fails because protocol types do not exist.

- [ ] **Step 3: Implement private-field validated constructors**

Represent hashes as `[u8; 32]`, indices as validated `u8`, confidence as validated `u32`, and provider failure as an exhaustive four-variant enum with `code() -> u8`. Constructors enforce every ADR bound before values can reach an encoder. `ProviderAttempt::Oversized` stores only `Option<[u8; 32]>`; it has no byte buffer.

Add `blake3 = { workspace = true }` and `ulid = { workspace = true }` to the Agent crate. Both packages already exist in the workspace dependency set. Keep error displays finite and based on fixed validation labels, never provider-supplied text.

- [ ] **Step 4: Run Agent tests and confirm GREEN**

Run: `CARGO_TARGET_DIR=/root/pigloros/target cargo test -p pos-plugin-agent --locked -- --include-ignored`

- [ ] **Step 5: Commit**

```bash
git add plugins/agent/Cargo.toml plugins/agent/src/lib.rs plugins/agent/src/protocol.rs Cargo.lock
git commit -m "feat(agent): add bounded decision protocol types"
```

### Task 4: Exact CBOR codecs and domain-separated fixtures

**Files:**
- Modify: `plugins/agent/src/protocol.rs`
- Create: `plugins/agent/tests/protocol_fixtures.rs`

**Interfaces:**
- Consumes: Task 3 validated types.
- Produces: exact encode/decode methods and catalogue/request/response/record hashes.

- [ ] **Step 1: Write failing golden fixture tests**

Use fixed ULIDs created with `Ulid::from(16-byte-value)`, fixed hashes, and one-action catalogue. Assert complete hexadecimal bytes for PAC1, PQR1, both PDP1 forms, accepted/no-action PDR1, and PAA1. Assert all four BLAKE3 derive-key digests against literal 32-byte expected values generated once from an independent fixture script or `b3sum`-equivalent BLAKE3 API and then frozen in the test.

The fixture test must compare literals, not encode then decode the same implementation:

```rust
assert_eq!(hex(&catalogue.encode().unwrap()), PAC1_HEX);
assert_eq!(catalogue.hash(), PAC1_HASH);
assert_eq!(ProviderDecisionV1::decode(&decode_hex(PDP1_ACCEPTED_HEX)).unwrap(), accepted);
```

- [ ] **Step 2: Write failing malformed-wire matrix tests**

For each decoder cover over-limit input, empty/truncated input, trailing bytes, wrong array length/magic/version/type/byte width/range, map, tag, float, indefinite array/text/bytes, non-shortest integer, invalid UTF-8/text grammar, and nested over-limit catalogue. Assert a readable PDP1 magic with version `2` is classified as unsupported even when another V1 rule would fail; all V1 canonical/shape failures are malformed.

- [ ] **Step 3: Run fixture and malformed tests and confirm RED**

Run: `CARGO_TARGET_DIR=/root/pigloros/target cargo test -p pos-plugin-agent --test protocol_fixtures --locked -- --nocapture`

Expected: tests fail because exact codecs are absent.

- [ ] **Step 4: Implement the exact profile**

Use `ciborium::value::Value` only as a parser. Pattern-match exact arrays and primitive types, reject every unapproved `Value` variant, consume exactly one item, re-encode through protocol-owned writers, and compare bytes. Never use serde-derived structs for protocol encoding. Encode ULIDs with `id.inner().to_bytes()` and decode with `Ulid::from(bytes)` plus the correct ID newtype constructor.

Hash exact encoded slices through:

```rust
fn derive_hash(context: &'static str, bytes: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, bytes)
}
```

- [ ] **Step 5: Run Agent tests and confirm GREEN**

Run: `CARGO_TARGET_DIR=/root/pigloros/target cargo test -p pos-plugin-agent --locked -- --include-ignored`

- [ ] **Step 6: Commit**

```bash
git add plugins/agent/src/protocol.rs plugins/agent/tests/protocol_fixtures.rs
git commit -m "feat(agent): encode canonical decision records"
```

### Task 5: Local provider seam and append-staged Live Driver

**Files:**
- Create: `plugins/agent/src/provider.rs`
- Create: `plugins/agent/src/provider_driver.rs`
- Modify: `plugins/agent/src/lib.rs`

**Interfaces:**
- Consumes: Tasks 1–4 anchor, hooks, protocol, codec, and normalization types.
- Produces: `AgentDecisionProvider`, `FixtureAgentDecisionProvider`, and `ProviderBackedAgentDriver`.

- [ ] **Step 1: Write failing provider call-count and normalization tests**

Implement a counting fake provider and table-drive every `ProviderAttempt` and PDP1 response outcome. Assert zero calls when catalogue/provenance/anchor/request validation fails, exactly one call otherwise, no retry, every no-action code, digest presence rules, and the exact precedence 6 -> 8 -> 7 -> 9 -> 5 -> accepted.

```rust
let output = driver.step(timeline, anchored_view).unwrap();
assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
assert_eq!(output.drafts[0].event_type.as_str(), RECORDER_EVENT_TYPE);
assert_eq!(output.drafts.get(1).map(|d| d.event_type.as_str()), Some(EVENT_TYPE_ACTION));
```

- [ ] **Step 2: Write failing staged-state tests**

Assert two `step` calls without commit fail; `abort_step` permits retry with the same tick/request bytes; `commit_step` advances exactly once; accepted output order is record then action; normalized no-action emits only the record; Timeline mismatch fails before provider invocation; and action identity comes from catalogue lookup, not response bytes.

- [ ] **Step 3: Run focused tests and confirm RED**

Run: `CARGO_TARGET_DIR=/root/pigloros/target cargo test -p pos-plugin-agent --locked provider_driver::tests -- --nocapture`

- [ ] **Step 4: Implement the seam and fixture adapter**

The trait has exactly one method:

```rust
pub trait AgentDecisionProvider: Send + Sync {
    fn decide(&mut self, request: &AgentDecisionRequestV1) -> ProviderAttempt;
}
```

The fixture adapter returns preconfigured attempts from local memory and records only a call count for assertions. It performs no file, environment, process, socket, or clock access.

`ProviderBackedAgentDriver` owns the Agent identity, catalogue, provenance, boxed provider, Live Recorder, committed tick, optional staged tick, subscriptions, and cadence. It requires an anchor, constructs all identity/provenance fields locally, records PDR1 first, derives PAA1 only for accepted results, and converts fixed protocol failures into stable `RuntimeError::InvalidPayload` reasons.

- [ ] **Step 5: Extend `AgentReducer` for PAA1 without changing deterministic output**

Dispatch by protocol shape. If a payload carries PAA1 magic, decode it only with the strict PAA1 decoder and update `last_action` from its validated action identifier; malformed PAA1 never falls back. A non-PAA1 payload retains the existing private `ActionPayload` decode for deterministic `AgentDriver`. Preserve existing malformed semantics: every `agent.action` Event increments `action_count`, while decode failure leaves `last_action` unchanged. Add projection tests proving both valid formats update both fields without changing deterministic output. Document this as two active producers, not migration/backfill compatibility.

- [ ] **Step 6: Run Agent/runtime/experiment tests**

Run: `CARGO_TARGET_DIR=/root/pigloros/target cargo test -p pos-plugin-agent -p pos-runtime -p pos-experiment --locked -- --include-ignored`

- [ ] **Step 7: Commit**

```bash
git add plugins/agent/src/lib.rs plugins/agent/src/provider.rs plugins/agent/src/provider_driver.rs
git commit -m "feat(agent): record local provider decisions"
```

### Task 6: Pure immutable-Timeline replay verifier

**Files:**
- Create: `plugins/agent/src/replay.rs`
- Modify: `plugins/agent/src/lib.rs`
- Create: `plugins/agent/tests/provider_replay.rs`

**Interfaces:**
- Consumes: exact PDR1/PAA1 protocol and `pos_core::Event`.
- Produces: `AgentDecisionReplayVerifier::verify` and `ReplayCheckpoint` with host-owned Timeline input and no provider parameter or field. Revision 7 recovery uses sequence-bounded root-to-active segments, so each PDR1 must match the segment owning its `Event.seq`.

- [ ] **Step 1: Write failing accepted/no-action replay tests**

Build committed-looking Events with fixed contiguous `Seq` values. Construct the verifier with the host-owned Timeline input, then verify an accepted PDR1 plus immediately adjacent exact PAA1 and a standalone no-action PDR1. Assert the checkpoint equals the final consumed source sequence and input Events remain byte-identical after verification.

```rust
let checkpoint = verifier.verify(&events, None).unwrap();
assert_eq!(checkpoint.last_verified(), Seq::from_u64(2));
assert_eq!(events, original);
```

- [ ] **Step 2: Write failing fail-closed matrix and resume tests**

Cover malformed/unsupported PDR1; wrong entity, lineage-segment Timeline anchor, plugin/provider provenance, catalogue hash, request hash, record hash, action ID/confidence/tick; missing/non-adjacent/extra target action; action after no-action; every unexpected target `agent.action` payload including legacy-map, malformed, and wrong-magic bytes; duplicate/regressing/gapped source `Seq`; unrelated Recorder Events; unrelated Agent actions; resume checkpoint absent, prefix not beginning at sequence 1, incomplete prefix through checkpoint, or changed predecessor; unconsumed final accepted record; and full-prefix resume matching one-shot verification.

Add a compile-time construction test showing the verifier constructor accepts only host-validated root-to-active Timeline segments, target identity, provenance, and catalogue and has no provider argument. A counting provider is deliberately impossible to pass; Live-to-Replay integration asserts its call count does not increase during verification.

- [ ] **Step 3: Run replay tests and confirm RED**

Run: `CARGO_TARGET_DIR=/root/pigloros/target cargo test -p pos-plugin-agent --test provider_replay --locked -- --nocapture`

- [ ] **Step 4: Implement pure scan and checkpoint validation**

Scan borrowed `&[Event]` in `Seq` order. Generic unrelated Events pass through. A target PDR1 is fully validated against the host-owned sequence-bounded Timeline segment that owns its `Event.seq` and other host configuration plus its recomputed request hash. Accepted records consume and compare the next Event; no-action records consume one Event. Any `agent.action` for the target entity that is not consumed as the exact immediately adjacent action for an accepted record is an error regardless of whether its payload is PAA1, the deterministic legacy map, malformed, or wrong-magic bytes. Return a checkpoint only after no accepted record remains awaiting its adjacent action.

`ReplayCheckpoint` stores only the last verified source `Seq`. Resume input must be one complete contiguous immutable source range beginning at sequence 1, extending through the checkpoint, and optionally containing later Events. The verifier rescans and revalidates the entire prefix through the checkpoint before accepting the suffix. The verifier has no mutable provider cursor, store handle, append method, or provider type parameter.

- [ ] **Step 5: Run Agent tests and confirm GREEN**

Run: `CARGO_TARGET_DIR=/root/pigloros/target cargo test -p pos-plugin-agent --locked -- --include-ignored`

- [ ] **Step 6: Commit**

```bash
git add plugins/agent/src/lib.rs plugins/agent/src/replay.rs plugins/agent/tests/provider_replay.rs
git commit -m "feat(agent): verify recorded decisions on replay"
```

### Task 7: End-to-end atomicity, byte stability, and documentation

**Files:**
- Create: `apps/pos-experiment/tests/agent_provider_replay.rs`
- Modify: `plugins/agent/README.md` if present, otherwise create it
- Modify: `docs/superpowers/specs/2026-08-17-agent-decision-provider-replay-design.md` only if implementation naming needs a non-semantic clarification

**Interfaces:**
- Consumes: completed runtime/Agent modules.
- Produces: production-path proof and user-facing construction/replay example.

- [ ] **Step 1: Write the failing production-path integration test**

Use a Memory store and real `ExperimentSession`, register `AgentPlugin`/`AgentReducer` with a `ProviderBackedAgentDriver` using the fixture provider, then execute accepted and no-action boundaries. Assert exact source Event sequence, PDR1/PAA1 adjacency, one atomic accepted append, projection action state, committed Driver ticks, and a fresh `AgentDecisionReplayVerifier` checkpoint. Compare all PDR1/PAA1 payload bytes with independently derived fixture bytes.

Add an append-fault adapter case proving neither staged tick nor partial record/action commits, followed by fresh-session recovery. The provider call count must equal Live boundaries and remain unchanged through replay.

- [ ] **Step 2: Run the integration test and confirm RED, then GREEN**

Run before wiring final gaps: `CARGO_TARGET_DIR=/root/pigloros/target cargo test -p pos-experiment --test agent_provider_replay --locked -- --nocapture`

Expected first result: failure at the missing production wiring assertion. Implement only the necessary wiring, rerun, and expect PASS.

- [ ] **Step 3: Document exact use and constraints**

Document a local-only construction example with `ActionCatalogueV1`, fixed provenance hashes, `FixtureAgentDecisionProvider`, `ProviderBackedAgentDriver`, and `AgentDecisionReplayVerifier`. State that replay takes immutable source Events, never a provider; remote providers and SDKs require a new ADR; all IDs/catalogues/provenance are host-owned; and no raw response is persisted.

- [ ] **Step 4: Run focused package verification**

Run:

```bash
CARGO_TARGET_DIR=/root/pigloros/target cargo fmt --all -- --check
CARGO_TARGET_DIR=/root/pigloros/target cargo clippy -p pos-runtime -p pos-plugin-agent -p pos-experiment --all-targets --all-features --locked -- -D warnings
CARGO_TARGET_DIR=/root/pigloros/target cargo test -p pos-runtime -p pos-plugin-agent -p pos-experiment --locked -- --include-ignored
```

- [ ] **Step 5: Commit**

```bash
git add apps/pos-experiment/tests/agent_provider_replay.rs plugins/agent/README.md docs/superpowers/specs/2026-08-17-agent-decision-provider-replay-design.md
git commit -m "test(agent): prove live provider replay stability"
```

### Task 8: Full gates, CTO reviews, publication, merge, and cleanup

**Files:**
- Modify only files required by evidence-backed review findings.

**Interfaces:**
- Produces: reviewed, rebased, green, merged #62 with tracker/journal evidence and cleaned #62 worktree.

- [ ] **Step 1: Run plan/spec consistency checks**

Run:

```bash
rg -n "T[B]D|TO[D]O|implement[ ]later|fill[ ]in" docs/superpowers/specs/2026-08-17-agent-decision-provider-replay-design.md docs/superpowers/plans/2026-08-17-agent-decision-provider-replay.md
bash scripts/check-test-policy.sh
git diff --check
```

Expected: no placeholder or whitespace finding, and the repository test policy passes with no skipped-test or production coverage-exclusion violation.

- [ ] **Step 2: Run every repository gate with storage monitoring**

Use the repository's CI commands verbatim, capability-dropped where required. At minimum run formatting, clippy, locked workspace tests with ignored tests included, docs, dependency/security, ASan, WASM/browser parity, and LLVM coverage. Before and after heavy gates run `df -h /root` and `du -sh /root/pigloros/target`; remove only regenerable #62 artifacts if capacity becomes unsafe.

Coverage acceptance is explicit: line >= 99.00% and region >= 99.00%, with no skipped tests and no new production exclusions.

- [ ] **Step 3: Request two explicit `gpt-5.6-sol` CTO reviews**

First review Standards against repository rules and ADR-046; second review Spec against Redmine #62, the current Proposed/Accepted ADR state, golden fixtures, transaction behavior, and replay authority. Resolve every concrete finding test-first, rerun affected gates, and record verdicts in Redmine and Notion. User approval is not required for routine review corrections under the standing delegation.

- [ ] **Step 4: Rebase and reverify**

Fetch `origin/main`, rebase `ticket-62-agent-provider-replay` onto it, resolve conflicts with the dedicated merge-conflict workflow if needed, and rerun all gates on the rebased commit. Do not alter or remove the #169 worktree.

- [ ] **Step 5: Push working branch and monitor GitHub Actions**

Push the branch, open/update its PR, and inspect every GitHub Actions check and log. Fix failures without skipping gates. Repeat until all required checks are green and both CTO reviews approve.

- [ ] **Step 6: Merge, verify main, and close trackers**

Merge only the green rebased PR. Pull/fast-forward `/root/pigloros` main, verify the merge commit and required smoke/full checks on main, set Redmine #62 Resolved/100%, update ADR links if implementation names changed, and append the final usage/how-to/test/coverage/CI/merge evidence to the Notion journal.

- [ ] **Step 7: Clean only completed #62 resources**

Remove the merged #62 local worktree and local/remote feature branch using non-destructive Git worktree/branch commands. Retain `/root/pigloros-ticket-169-geo-location-admission`. Report final disk capacity and mark the active goal complete only after main and trackers are verified.
