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
The channel remains a transport bound, while a shared 64-permit admission
budget is the authoritative total-capacity bound. Every accepted envelope owns
one permit while it is in the channel, pending queue, or currently executing;
the permit is released only after the command is executed or expired. A second
56-permit read budget means reads cannot consume the eight write-reserved
permits. Consequently, channel contents plus pending contents plus the current
command can never exceed 64 envelopes, even while producers refill the channel
as the worker moves messages into its local queue.

The worker drains available envelopes into the pending queue without acquiring
new permits: every accepted envelope already owns its permit, and moving that
envelope from the inbound channel to local pending does not change the total
accepted-work count. Each envelope carries its `CommandClass` so worker
selection does not depend on the admission-only boolean currently passed to
`try_submit`.

Use a fixed `READ_BURST` of 8. The selection policy is:

1. Drain currently available envelopes into the pending queue. Draining moves
   already-admitted envelopes and therefore does not depend on unused permits.
2. While `reads_since_write < READ_BURST` and a read is pending, select the
   oldest pending read. This allows an admitted write to wait behind at most
   the current synchronous command plus the remainder of the eight-read burst.
3. If no read is pending before the threshold, select the oldest pending write
   when one is available; otherwise there is no selectable command yet.
4. Once the burst reaches eight, select the oldest pending write when one is
   available. A write that arrives after the eighth-read probe is selected at
   the next scheduling boundary, after the currently executing read returns.
5. If no write is pending at the threshold, continue with the oldest pending
   read; the counter remains saturated until a write is selected, so the next
   admitted write is prioritized immediately.
6. After a selected envelope is successfully claimed for execution, increment
   and saturate `reads_since_write` when it is a read, and reset the counter
   after every successfully claimed write. An envelope that fails the deadline
   claim is expired without executing and does not advance or reset the counter;
   selection continues for the next pending envelope.

Reads remain FIFO relative to other reads, and writes remain FIFO relative to
other writes. Cross-class FIFO is intentionally replaced by bounded read-burst
selection, which is the explicitly requested fairness behavior. It does not
change the order in which writes receive store-assigned sequence numbers.

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
- A shared permit budget bounds channel, pending, and current envelopes to
  `QUEUE_CAPACITY`; moving a message between channel and pending cannot create
  additional accepted work.
- Reads can hold at most `QUEUE_CAPACITY - RESERVED_WRITE_CAPACITY` permits.
- Writes are never reordered with other writes.
- Reads are never reordered with other reads.
- `CommandClass::Read` maps `RootCount`, `Read`, `ReadOne`, and `GetTimeline`;
  `CommandClass::Write` maps `AdmitOwnTracksIngress`, `AdmitGeoLocation`,
  `Purge`, `Create`, `Append`, `AppendIdentified`, and test-only `Panic`.
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

## ADR-052 disposition

ADR-052 contains both an early description of a single global FIFO and a later
normative fairness rule requiring bounded read bursts and write priority. This
ticket implements the later rule and supersedes the earlier cross-class FIFO
sentence for the local V1 executor. FIFO remains guaranteed within each class,
and write sequence assignment remains deterministic in write-arrival order;
callers must not rely on a read being ordered ahead of a write merely because
it entered the channel first. The Proposed ADR-052 text should carry this
clarification when that ADR reaches acceptance. No distributed or cross-process
ordering claim is introduced.

## Test design

Tests will exercise the scheduler through the StoreExecutor boundary with real
test stores and deterministic synchronization primitives:

- A write queued behind an active bounded read is serviced after the configured
  burst boundary and before the next read burst, proving the write does not
  starve.
- The eighth-read threshold is covered when a write is pending, the no-write
  path is covered while reads continue, and a write arriving after the probe is
  serviced at the next boundary; tests record operation order rather than time.
- Multiple queued writes retain FIFO order and receive sequence numbers in that
  order even when reads are interleaved.
- Reads retain FIFO order when no writes are pending.
- Concurrent producers cannot exceed the shared 64-envelope budget while the
  worker refills its pending queue; read admission still leaves eight write
  permits available.
- Expired queued commands still do not execute, and started writes still return
  their commit result after deadline.
- Commands expired while locally pending release their permits and never call
  the store.
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
