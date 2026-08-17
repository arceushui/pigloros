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
