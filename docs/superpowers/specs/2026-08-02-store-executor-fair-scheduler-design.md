# StoreExecutor Fair Scheduler Design

**Ticket:** Redmine #167
**Status:** Proposed implementation design
**Date:** 2026-08-02
**Parent decision:** ADR-052, V1 StoreExecutor and synchronous EventStore isolation

The predecessor lifecycle/supervision work in Redmine #165 is complete and
squash-merged to `main` at `9473f32f67498564db24b1c33b15148d930e6d55`; #167 is
the local scheduler follow-up. This design authorizes no production work by
itself: #165 is the implemented baseline, #167 is the proposed fairness
amendment, and #166/#168 remain separately deferred and unauthorized.

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

Keep one bounded inbound channel and add a bounded worker-local pending queue
with capacity for at least the full 64-envelope admission bound. Normal
draining never drops or requeues an accepted envelope because the pending queue
is full.
The channel remains a transport bound, while a shared 64-permit admission
budget is the authoritative total-capacity bound. Every accepted envelope owns
one global permit while it is in the channel, pending queue, or currently
executing. A read envelope additionally owns one permit from a separate
56-permit read-class budget; a write owns no read-class permit. Permits are
released only after the envelope reaches a terminal state. Consequently,
channel contents plus pending contents plus the current command can never
exceed 64 envelopes, even while producers refill the channel as the worker
moves messages into its local queue, and reads cannot consume the eight
write-reserved global permits.

The worker drains available envelopes into the pending queue without acquiring
new permits: every accepted envelope already owns its permit, and moving that
envelope from the inbound channel to local pending does not change the total
accepted-work count. Each envelope carries its `CommandClass` so worker
selection does not depend on the admission-only boolean currently passed to
`try_submit`. The envelope retains its global and optional read permit until
the worker removes it from the channel or pending queue and the envelope is
dropped. A caller-side deadline expiry only marks the lifecycle expired; it
never releases admission capacity while the envelope remains accepted work.

### Permit ownership state machine

Admission owns the global permit and, for a read, the read-class permit as one
logical transaction under the existing lifecycle admission boundary. The
permit-bearing RAII `CommandEnvelope` conceptually contains the command,
deadline/lifecycle state, its successful-admission ordinal, one
`global_permit`, and an optional `read_permit`. The explicit ownership state
machine is:

```text
Unowned
   | Write: acquire global; Read: acquire global then read permit
   v
Admitting
   | reserve candidate ordinal; try_send under the lifecycle admission lock
   | full/closed send -> release every acquired permit and return failure
   | successful send -> commit ordinal and transfer intact envelope
   v
Owned(Channel)
   | worker receives envelope (initial blocking recv or nonblocking drain)
   v
Owned(Pending)
   | successful deadline claim immediately before execution
   v
Owned(Executing)
   | store result or worker unwind
   v
Released

Owned(Channel) or Owned(Pending)
   | deadline/expiry removal or worker-unwind cleanup
   v
Released
```

Admission is an `Admitting` rollback state before the envelope becomes
accepted work. A failed read-permit acquisition releases the already-acquired
global permit; a full or closed `try_send` releases the global permit plus the
optional read permit and commits neither the envelope nor its candidate
ordinal. The candidate ordinal is placed in the envelope before `try_send` and
becomes the committed admission ordinal only after that send succeeds. Writes
never acquire a read permit. Expiry releases directly from
`Owned(Channel)` or `Owned(Pending)` when the worker removes the envelope; an
executing envelope releases both of its permits only after the synchronous
store call returns or unwinds. No caller cancellation or deadline path releases
an owned permit while its envelope is still in the channel, pending queue, or
synchronous store call. Moving between owned states does not acquire or
release capacity. Exactly one owner performs the terminal drop on normal
completion, queued/pending expiry, or worker unwind; a failed admission is
rolled back before it enters accepted-work ownership. Every accepted command
receives exactly one terminal outcome: a result, a queued-expiry error, or an
explicit unhealthy/failure error. Normal shutdown never drops an accepted
envelope without a reply; it drains accepted work through the common scheduler
before terminal release. Tests
must exercise
global-acquisition failure, read-acquisition rollback, full and closed send
rollback, execution completion, expiry removal, and unwind release for both
write and read envelopes.

Use a fixed `READ_BURST` of 8. A scheduling boundary is the point immediately
after the worker's nonblocking drain loop has observed either
`try_recv() == Empty` or `try_recv() == Disconnected`, and before it selects
the next pending envelope. `Disconnected` is terminal-drain completion: no
future envelope can arrive, but the worker still emits the same
`DrainCompleted` record, applies the controller gate, and uses the common
selection/claim path for any pending work. The drain is one worker turn; the
worker does not wait for a new channel message while deciding at that
boundary. The worker uses blocking `recv()` only when no command is executing
and `pending` is empty. It transfers one intact permit-bearing envelope to
`Pending`, then performs the same nonblocking drain, emits `DrainCompleted`,
applies the controller gate, and uses the common selection/claim path; it never
transfers `Channel` directly to `Executing`. A disconnected worker terminates
only after pending work is terminally serviced or expired. The selection policy
is:

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
other writes after filtering envelopes that have already expired. Cross-class
FIFO is intentionally replaced by bounded read-burst selection, which is the
explicitly requested fairness behavior. For an event-producing write command
on the same Timeline, only non-expired commands that actually insert Events
inherit the write-class FIFO order. Each successfully inserted Event receives
its store-assigned sequence in write-class FIFO order. `Append` returns its
existing `Vec<Event>`; when nonempty, those Events evidence its inclusive
first-to-last sequence range. `AppendIdentified` participates only for
`Some(Appended(event))`; expired, rejected, errored, `None`, duplicate,
conflict, and non-event commands have no sequence-order claim. Cross-class
scheduling does not claim that a write entered before a read, or was admitted
earlier by another task, must execute first.
“Oldest” and write-arrival order mean the order of successful admission at the
channel send linearization point, not task-start order or wall-clock order. An
admission ordinal is allocated at that successful `try_send` linearization
point; a full or closed send fails before admission and consumes neither an
ordinal nor a permit-bearing envelope.

Admission is one transaction serialized by the lifecycle lock: while the
executor is `Open`, `try_submit` acquires the required permits, classifies the
command, reserves a candidate ordinal in the envelope, performs `try_send`,
and commits that ordinal only after the send succeeds while holding that lock.
Shutdown takes the same lock before transitioning to `Draining` and
notifying the worker. Thus a submission cannot be accepted after shutdown has
observed the transition, and a failed send releases all permits immediately.
The test-only producer trace publication is nonblocking and occurs outside this
lifecycle-lock critical section. `DrainCompleted` is a worker-causal boundary
record; `Selected` carries the envelope's admission ordinal and correlates the
worker selection with the producer record. Tests do not require producer and
worker trace records to arrive in publication order.

The same policy applies while draining. Shutdown first stops accepting new
commands, drains accepted channel messages into the bounded pending queue, and
then services all pending commands using the scheduler. The worker exits only
after the executing command has returned, the inbound channel is empty, and
the pending queue is empty. If the receiver reports `Disconnected`, no new
envelopes can arrive; while `pending` is nonempty, the worker continues
drain-completed/controller/select turns and services or expires pending
envelopes. It terminates only after pending work is terminally serviced or
expired. Direct cleanup is reserved for worker unwind; normal shutdown never
discards an accepted envelope or omits its terminal reply. The global and
optional read permits remain owned
by the envelope through the complete synchronous store call, then release on
normal completion, queued expiry, or worker unwind. Expired envelopes are
still rejected through the existing atomic lifecycle claim before execution;
the worker then drops their permits so capacity is reclaimed exactly once.

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
making selection deterministic and testable. The worker exclusively owns
`pending`, `reads_since_write`, and the EventStore. `ExecutorControl` owns
shared lifecycle state and admission budgets. Each accepted envelope
exclusively owns its permits and transfers intact through channel, pending, and
executing until terminal drop. The test trace/controller is test-only observer
state and has no lifecycle authority. Selected.

## Invariants

- At most one worker owns and mutates the EventStore.
- A shared permit budget bounds channel, pending, and current envelopes to
  `QUEUE_CAPACITY`; moving a message between channel and pending cannot create
  additional accepted work. Caller-side expiry cannot release a permit before
  the worker removes the corresponding envelope, and permits remain held
  through the complete synchronous store call.
- Reads can hold at most `QUEUE_CAPACITY - RESERVED_WRITE_CAPACITY` permits.
- Writes are never reordered with other writes.
- Reads are never reordered with other reads.
- `Command::class()` is the exhaustive single source of truth:
  `CommandClass::Read` maps `RootCount`, `Read`, `ReadOne`, and `GetTimeline`;
  `CommandClass::Write` maps `AdmitOwnTracksIngress`, `AdmitGeoLocation`,
  `Purge`, `Create`, `Append`, `AppendIdentified`, and test-only `Panic`.
- No read is preempted; bounded read chunks limit the maximum work before the
  next scheduling decision.
- If a write is pending at a scheduling boundary, at most `READ_BURST`
  successfully claimed reads may execute consecutively before a write is
  selected; the currently executing command is not preempted. Expired reads do
  not consume this bound. The post-eighth-read decision is made at the next
  drain-completed boundary, not at an arbitrary task or wall-clock instant.
- A command is claimed with the existing queued-to-started deadline CAS before
  any store call. Expired queued commands never execute.
- A started command keeps its existing authoritative-result behavior, including
  writes that finish after their caller deadline.
- Shutdown drains accepted commands, gives each accepted command exactly one
  terminal outcome, and retains the existing join/readiness guarantees.
- No persistent schema, EventStore trait, HTTP contract, or public command API
  changes.

## ADR-052 disposition

ADR-052 contains both an early description of a single global FIFO and a later
normative fairness rule requiring bounded read bursts and write priority. This
ticket proposes to implement the later rule and supersede the earlier
cross-class FIFO sentence for the local V1 executor. FIFO remains guaranteed
within each class after filtering expired envelopes, and event-producing write
sequence assignment remains deterministic in successful admission order for
the same Timeline; callers must not rely on a read being ordered ahead of a
write merely because it entered the channel first. Because ADR-052 is still
Proposed, production implementation requires both core-team acceptance of the
V8 ADR-052 clarification and explicit implementation authorization. A #167
journal note may record review and discussion, but cannot independently
authorize the ordering change. This design proposal is not itself
authorization. #166 and #168 remain separately deferred and unauthorized; no
distributed or cross-process ordering claim is introduced.

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
- Tests cover global/read acquisition rollback, full/closed-send rollback,
  normal completion, expiry removal from both `Channel` and `Pending`, and
  worker unwind with executing, channel, and pending envelopes; each proves
  exactly-once release for both read and write permits. A disconnected-while-
  pending test proves scheduler turns continue through drain/controller/select
  until every accepted envelope is serviced or expired, with no direct cleanup.
- Permit rollback tests use an injected inbound channel narrower than the
  global budget (for example, capacity 2 with a 64-permit global budget), so a
  full `try_send` after permit acquisition is reachable and its rollback can
  be observed.
- Expired queued commands still do not execute, and started writes still return
  their commit result after deadline.
- Commands expired while locally pending release their permits and never call
  the store.
- A caller-expired envelope continues to consume its permits until the worker
  removes it; saturation is observed before the worker sweep and capacity is
  available only after the sweep drops the envelope.
- An expired read at `reads_since_write == 7` does not consume the eighth-read
  slot, and an expired write at saturation does not reset priority ahead of a
  live write.
- With no pending read and `reads_since_write < READ_BURST`, queued writes are
  selected immediately and retain FIFO order.
- Oldest selection is deterministic by the observer's successful channel-send
  ordinals for coordinated concurrent producers.
- A test-only controller gate is placed exactly between `DrainCompleted` and
  `Selected`; it is driven by a channel/oneshot and never uses the lifecycle
  mutex. The controlled gate places a write after the eighth-read probe and
  proves it is selected at the next boundary. `Selected` includes the
  envelope's admission ordinal, command class, and burst counter.
- Same-Timeline write tests distinguish successful Event insertion from
  expired, rejected, errored, `None`, duplicate, conflict, and non-event
  commands before making any sequence-order assertion. Each successfully
  inserted Event participates in the claim; `Append` returns its existing
  `Vec<Event>` and its nonempty result evidences an inclusive sequence range;
  `AppendIdentified` participates only for `Some(Appended(event))`.
- A test-only StoreExecutor trace records an opaque admission ordinal at each
  successful channel send and emits `DrainCompleted` and `Selected` records
  with the command class and burst counter. Trace publication is nonblocking
  and outside the lifecycle-lock critical section. Tests coordinate only
  through this observer, its controller gate, and controlled-store barriers;
  they never lock, inspect, or use the lifecycle mutex as a scheduling oracle,
  and they assert only worker-causal `DrainCompleted -> Selected` order and
  correlate producer and worker records by admission ordinal; they never
  require admission-trace arrival before worker records. The test-only bounded
  trace channel is configured for every expected record; `try_send` overflow
  or observer closure fails the test rather than dropping a record. The
  controller also exposes test-only permit availability after an unwind;
  resubmission is not used as proof because an unhealthy executor cannot
  establish a valid release path.
- Shutdown timeout/cancellation with one executing command, channel work, and
  local pending work is retried after release; replies are delivered exactly
  once, readiness is closed during draining, and post-transition submissions
  are rejected.
- A disconnected receiver with accepted pending work emits terminal-drain
  `DrainCompleted`, passes through the controller gate, and services or expires
  every pending envelope through the common selection path before terminating;
  the test asserts no direct channel-close cleanup path is used.

After ADR-052 is accepted and implementation is explicitly authorized, the
first scheduler test will be written and run red before production changes.
Before merge, run the exact repository gates:
`cargo fmt --all -- --check`; and the `scripts/ci.sh` test step, which runs
`test_log="$(mktemp)"`; `cargo test --workspace --locked -- --include-ignored
2>&1 | tee "$test_log"`; followed by
`bash scripts/assert-no-ignored-in-test-summary.sh "$test_log"`;
`cargo clippy --workspace --all-targets --locked -- -D warnings -W clippy::pedantic`;
and
`RUSTC_BOOTSTRAP=1 cargo llvm-cov --workspace --locked --summary-only
--fail-under-lines 99 --fail-under-regions 99 -- --include-ignored`.
Also run `./scripts/ci.sh` with both `trunk` and `cargo-deny` installed, so
Trunk policy and dependency checks cannot fall back or be skipped. The GitHub
quality gates must all be green: pinned dependencies, fmt, test, clippy,
coverage, audit, deny, geiger, ASan, Docker smoke, and Trunk policy. CTO review
will be requested after implementation and again after any review correction,
but only after ADR acceptance and implementation authorization.

## Scope and non-goals

This ticket does not add a distributed scheduler, a second EventStore owner,
wall-clock ordering, a configurable runtime fairness policy, metrics with
unbounded labels, or changes to ADR-032/#143 coordinate work. Digital-twin
bridge work remains the subsequent #60 milestone.

## Review evidence

The primary workspace verified canonical Redmine ADR-052 version 8 on
2026-08-02: status `Proposed`, parent `ADR`, no malformed literal newline
sequence, the #165 merge/resolution reconciliation, and this proposed #167
clarification. The CTO review at 2026-08-02T16:02:16Z returned
`REQUEST_CHANGES`; its first-round corrections were incorporated, but the
second review at 2026-08-02T16:13:27Z also returned `REQUEST_CHANGES` with
additional permit, test-controller, trace, and gate-precision corrections now
incorporated above. The third review at 2026-08-02T16:22:55Z returned
`REQUEST_CHANGES` with an initial-receive fairness blocker and further
trace/API/terminal-test/gate/ownership precision corrections incorporated
above. The fourth review at 2026-08-02T16:31:35Z also returned
`REQUEST_CHANGES` with shutdown/disconnect, trace-causality, ordinal, gate, and
authorization-conditionality corrections now incorporated above. The fifth
review at 2026-08-02T16:39:37Z returned `REQUEST_CHANGES` for a remaining
channel-close-cleanup wording contradiction, which was removed. The sixth
review returned `REQUEST_CHANGES` because `Disconnected` was not yet defined as
a scheduling boundary; terminal-drain completion and its explicit test are now
defined above. The final CTO review at 2026-08-02T16:52:15Z returned
`APPROVE`; it confirmed the terminal-drain boundary, exact gate commands,
and the two-part ADR-052 acceptance/implementation-authorization gate.
Canonical Redmine acceptance remains a separate authorization gate. The
private Redmine host is not reachable from the CTO review sandbox, so that
sandbox result is not treated as live-state evidence.
