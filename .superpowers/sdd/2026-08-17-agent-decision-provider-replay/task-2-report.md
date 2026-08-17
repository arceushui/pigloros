# Task 2 implementation report

Status: DONE

Commit: `2fe991b feat(runtime): commit driver state after append`

Implemented explicit anchored all-driver/cadenced registry transactions, pending-step guard, staged cadence, all-registered unanchored preflight, commit/abort fan-out, and both Experiment append-path integrations. Legacy deterministic registry and TickScheduler behavior remains immediate. Host tests cover append success, zero-draft commit, schema abort, append abort, anchor cursor, partial Driver failure, and cadence retry.

TDD evidence:

- Registry tests first failed to compile because anchored transaction methods were absent, then passed.
- Pending legacy-entry tests first failed with the wrong `MissingSnapshotAnchor` result, then passed with `PendingDriverStep` precedence.
- Experiment run-path test first failed with `MissingSnapshotAnchor`, then passed after both host paths used anchored transactions.

Verification:

- Capability-dropped `cargo test -p pos-runtime -p pos-experiment --locked -- --include-ignored`: 159 passed (77 experiment library + 14 CLI + 68 runtime), 0 failed, 0 ignored.
- `cargo fmt --all -- --check`: pass.
- `cargo clippy -p pos-runtime -p pos-experiment --all-targets --all-features --locked -- -D warnings`: pass.
- Root-only read-only fault-test artifacts were reproduced with ordinary root execution and eliminated by the repository's required capability-dropped invocation.

Concerns: none.

## Fix packet A — shared anchored registry helper

Status: DONE

Refactored `tick_cadenced_anchored` and `step_all_anchored` through the private
`step_anchored_transaction` helper. The helper owns anchored Driver selection,
one shared snapshot, registration-order stepping, geographic draft rejection,
partial-failure abort, draft collection, cadence staging, and pending-step
creation. Public behavior and the Task 1 snapshot-anchor fixes are unchanged;
Experiment tests were not modified as part of this packet.

Verification:

- `CARGO_TARGET_DIR=/root/pigloros/target cargo test -p pos-runtime --locked registry::tests::anchored -- --nocapture`: 3 passed, 0 failed.
- `CARGO_TARGET_DIR=/root/pigloros/target cargo test -p pos-runtime --locked -- --include-ignored`: 68 passed, 0 failed, 0 ignored; doc-tests 0 failed.
- `cargo fmt --all -- --check`: pass.
- `CARGO_TARGET_DIR=/root/pigloros/target cargo clippy -p pos-runtime --all-targets --all-features --locked -- -D warnings`: pass.

Concerns: pre-existing unstaged Experiment changes remain outside packet A and
are intentionally unmodified and unstaged.

## Fix packet B — two-host-path fault and ordering matrix

Status: DONE

Replaced the three uneven host tests with one table-driven real-behavior matrix
covering both `advance_tick` and `ExperimentSession::step_boundary`. Each path
now exercises non-empty commit, zero-draft commit, schema abort, append abort,
partial-Driver abort, and post-append capture failure. The stateful Driver proves
the pre-fold anchor, commit/abort counts, cleared staging, and unchanged
committed tick on every abort. The capture-aware store proves a non-empty append
sees zero commits, zero-draft and pre-append failures do not append, and every
post-step capture sees the committed state.

TDD evidence:

- RED mutation: temporarily moved `commit_step` before non-empty append in both
  production hosts, then ran the focused matrix. It failed as intended for
  `AdvanceTick NonEmpty`: append observed `[(1, 1)]` instead of `[(1, 0)]`.
- GREEN restoration: restored append-before-commit with `apply_patch`; the
  focused matrix passed (1 passed, 0 failed).

Verification:

- Focused host matrix: 1 passed, 0 failed.
- Capability-dropped `cargo test -p pos-runtime -p pos-experiment --locked --
  --include-ignored`: 157 passed (75 Experiment library + 14 CLI + 68 runtime),
  0 failed, 0 ignored; doc-tests passed.
- `cargo fmt --all -- --check`: pass.
- `cargo clippy -p pos-runtime -p pos-experiment --all-targets --all-features
  --locked -- -D warnings`: pass.
- `git diff --check`: pass; packet A's `crates/pos-runtime` change is untouched.

Concerns: none.
