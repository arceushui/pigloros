# Lifecycle safety

Internal PiglorOS guidance for contract design and boundary review.

## Authority and resource ownership

- Trace every policy-bearing field to its authenticated producer across the real
  process boundary. Well-formed records, matching partial digests, and opaque
  wrappers cannot manufacture provenance. Join admitted capabilities on their
  shared operation identity before using them together.
- Enumerate every resource owner, clone, maintenance path, and inherited handle.
  Callback scope constrains borrows and control flow; caller-owned transferred
  data has a separate lifetime. Follow handle-shaped names through normalization
  and reopening before claiming kernel-object identity survives a library call.
- Keep quota charged until the last storage-owning handle is released. Fork can
  extend open-file-description lifetime before close-on-exec takes effect.
  Releasing a metadata handle may itself revoke process-level authority.
- A single-owner queue must own maintenance access as well as requests. Specify
  pre-start cancellation, already-started non-cancellable work, result recovery,
  stuck-worker health, and shutdown. Release failed unused reservations before
  idle waits; accepted work retains its owner until completion.
- Preserve authenticated progress across retry refusal. Spend one-use authority
  before a fallible consumption attempt, while retaining cleanup custody
  independently. Bind at-most-once behavior to the outer tick or operation, not
  merely to helper-call counts.
- Destructive reconciliation distinguishes absence, observation failure, and
  contradictory partial evidence. Require the cleanup predicate and unique
  ownership or agreement from all claimants before destroying a shared resource.
- Audit success, failure, and abandonment for evidence handles as well as product
  handles. Evidence collection must not retain the resource whose release it is
  supposed to witness. Object creation must establish required ownership as well
  as permissions; inherited permissions alone do not establish owner identity.

## Budgets and error precedence

- Deterministic admission uses a versioned semantic budget and canonical request
  order. CPU timing, queue timing, and live capacity may pause or fail an operation
  but must not silently select authoritative Timeline history.
- Locate each parser/allocation enforcement checkpoint. A limit checked after a
  completed parse cannot prove peak allocation was bounded during parsing.
  Exact payload limits must include the caller's required framing.
- Classify validation as input-local, resolvable from indexed inputs, or dependent
  on unvisited inputs. Define mixed-error precedence and budget-truncation
  behavior; inspect eager library preparation before validating partial graphs.
- Cross primary refusal with cleanup/finish failures. Preserve mandatory safety
  classifications, quarantine state, and callback counts in the closed error
  representation; generic cleanup failure must not erase an established fence.
- A sentinel overlaps actor-controlled exit values unless the contract proves
  otherwise. Require positive state evidence rather than inferring exclusive
  state from a conventional status code.
