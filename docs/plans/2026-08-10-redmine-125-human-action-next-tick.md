# Redmine #125 — Human action next-tick fold/replay plan

ADR: Redmine `ADR-019-Async-Human-AI-Tick-Coordination` v13 (Accepted)

## Contract

The Timeline's logical stitched `seq` is authoritative. The experiment host folds exact contiguous logical ranges before and after an atomic driver pass. Gateway admission remains immediate, and no projection changes while `step_all` is active.

## Implementation sequence

1. Add red tests for root, child, and nested-Fork logical heads and public logical `Event.seq` consistency across append, identified recovery, ID lookup, stitched read, Gateway response/notice, and Replay.
2. Add a fail-closed `EventStore::logical_head` port. Correct Memory and SQLite Fork metadata/read planning so `fork_point` is a logical parent position while persisted child rows and `read_own` remain segment-local.
3. Translate public child Event results to logical `seq` in both adapters without changing persisted rows. Keep root behavior unchanged.
4. Add red experiment-host tests for pre-step human visibility, mid-step isolation, human/AI interleaving, conflicting `wall_time`, no-draft quiescence, counters, fault/recovery, cursor-safe Forks, and live-vs-Replay equivalence.
5. Implement the host-owned fold cursor, exact range validation, structured tick outcome, faulted-session guard, and resume-from-existing-Timeline recovery. Keep `PluginRegistry` and `ObservationSnapshot` unchanged.
6. Update API documentation and test policy references. Run targeted tests after each slice, then formatting, workspace tests including ignored tests, Clippy pedantic, 99% line/region coverage, Trunk, and cargo-deny.
7. Request independent Sol CTO review, address all blockers, push the working branch, monitor every GitHub Actions job/log, rebase onto current `main`, rerun gates, merge, verify post-merge `main`, update Redmine/Notion, and remove the worktree/branch.

## Failure invariants

- A range is fully validated before any reducer sees it.
- The fold cursor advances only after the complete validated range is folded.
- Failures before projection mutation or driver execution are retryable.
- Any failure after folding begins or `step_all` starts faults the live session; mutable driver work is never retried automatically.
- Recovery creates fresh compatible runtime state and rehydrates persisted logical Timeline order.
- A no-draft boundary is resumable quiescence for interactive callers; closed execution may stop on it.

## Production boundary

Gateway and tick host must target one durable SQLite Timeline. Separate same-file connections are permitted because SQLite append transactions serialize local writes and captured logical ranges are immutable. In-memory storage is not a cross-process production seam.
