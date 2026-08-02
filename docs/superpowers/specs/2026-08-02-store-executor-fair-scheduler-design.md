# StoreExecutor Fair Scheduler Design

**Ticket:** Redmine #167
**Status:** Proposed implementation design
**Date:** 2026-08-02
**Parent decision:** ADR-052, V1 StoreExecutor and synchronous EventStore isolation

## Problem

The merged StoreExecutor owns one synchronous EventStore behind a bounded Tokio
channel. Its worker currently executes commands in channel FIFO order. The
queue's reserved write capacity prevents reads from consuming the final write
slots, but it does not prevent a run of already-accepted reads from delaying a
write once the worker begins servicing that run.

Redmine #167 requires a deterministic scheduler that bounds read bursts and
prioritizes admitted writes without changing write sequence order. The change
must preserve the single StoreExecutor owner, command deadlines, queued-versus-
started semantics, graceful shutdown, and existing bounded-read guarantees.

## Decision

Keep one bounded inbound channel and add a bounded worker-local pending queue.
The worker will drain currently available envelopes into that queue before each
selection. The pending queue never exceeds the inbound channel capacity, so it
does not create an unbounded memory path or a second store owner.

Use a fixed `READ_BURST` of 8. The selection policy is:

1. Preserve the oldest pending write relative to other writes.
2. If a write is pending, select it before pending reads. This gives writes
   priority at every scheduling boundary.
3. If no write is pending, select the oldest pending read and increment the
   consecutive-read counter.
4. After eight reads, probe the inbound channel again before selecting another
   read. A newly admitted write is therefore serviced at the next scheduling
   boundary; a synchronous read already in progress is never preempted.
5. Reset the consecutive-read counter after every write.

Reads remain FIFO relative to other reads, and writes remain FIFO relative to
other writes. The scheduler may move a write ahead of pending reads, which is
the explicitly requested fairness behavior; it does not change the order in
which writes receive store-assigned sequence numbers.

The same policy applies while draining. Shutdown first stops accepting new
commands, drains accepted channel messages into the bounded pending queue, and
then services all pending commands using the scheduler. Expired envelopes are
still rejected through the existing atomic lifecycle claim before execution.

## Alternatives considered

### Two dedicated channels

Separate read and write channels would make priority obvious, but would require
duplicating capacity accounting and admission logic. It would also make the
existing reserved-capacity contract harder to reason about and would create
more opportunities for shutdown and cancellation races. Rejected.

### Leave FIFO unchanged

This preserves the smallest implementation and strongest historical ordering,
but it does not satisfy the starvation requirement: a bounded queue can still
contain a long read run ahead of a write. Rejected.

### Worker-local pending queue with fixed burst (selected)

This keeps the existing public submission seam and one bounded channel while
making selection deterministic and testable. The only new state is bounded
scheduler state owned by the existing worker. Selected.

## Invariants

- At most one worker owns and mutates the EventStore.
- The inbound channel plus pending queue hold at most `QUEUE_CAPACITY`
  envelopes, excluding the one currently executing.
- Writes are never reordered with other writes.
- Reads are never reordered with other reads.
- No read is preempted; bounded read chunks limit the maximum work before the
  next scheduling decision.
- A command is claimed with the existing queued-to-started deadline CAS before
  any store call. Expired queued commands never execute.
- A started command keeps its existing authoritative-result behavior, including
  writes that finish after their caller deadline.
- Shutdown drains accepted commands and retains the existing join/readiness
  guarantees.
- No persistent schema, EventStore trait, HTTP contract, or public command API
  changes.

## Test design

Tests will exercise the scheduler through the StoreExecutor boundary with real
test stores and deterministic synchronization primitives:

- A write queued behind an active bounded read is serviced before the next
  queued reads, proving the write does not starve.
- A sustained read stream cannot delay a queued write beyond the configured
  burst boundary; the test records operation order rather than timing.
- Multiple queued writes retain FIFO order and receive sequence numbers in that
  order even when reads are interleaved.
- Reads retain FIFO order when no writes are pending.
- Expired queued commands still do not execute, and started writes still return
  their commit result after deadline.
- Shutdown drains both pending reads and writes and leaves readiness closed.

The first scheduler test will be written and run red before production changes.
Focused gateway tests, workspace tests with ignored tests included, pedantic
Clippy, formatting/diff checks, the repository test-policy script, and the
capability-dropped LLVM coverage gate remain required before merge. CTO review
will be requested after implementation and again after any review correction.

## Scope and non-goals

This ticket does not add a distributed scheduler, a second EventStore owner,
wall-clock ordering, a configurable runtime fairness policy, metrics with
unbounded labels, or changes to ADR-032/#143 coordinate work. Digital-twin
bridge work remains the subsequent #60 milestone.
