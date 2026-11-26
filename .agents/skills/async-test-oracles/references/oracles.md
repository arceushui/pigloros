# Concurrent and native fixture lessons

Internal PiglorOS guidance. Apply the relevant checks to the actual fixture.

- Separate ready-reply scheduling from remote-response delay. Synchronize on the
  semantic prerequisite with child-exit detection and a bounded deadline. A later
  ordered protocol reply can establish that earlier requests reached an observer;
  an immediate shared-state read cannot prove that no request escaped.
- A virtual-time poll must yield toward a future wake, not repeatedly complete
  an elapsed sleep. A liveness test needs an independent stop condition, and
  every blocking thread or subprocess must be bounded even when its peer fails.
- Check the documented rejection effect before waiting for a reply: rejected
  input may never enter the response protocol. Observe input at the earliest
  relevant side effect rather than counting only completed responses.
- Qualify cancellation using the native operation whose contract names that
  effect, with a real negative control. Delaying SDK result consumption is not
  delaying native completion; a callback error alone proves only its specified
  caller-visible result.
- Keep the product lifecycle driver in qualification fixtures while evaluating
  its results independently. Trace every required event through actual retirement,
  not only successful product return. Keep fixture admission custody separate
  from the product deadline; retain ownership through the entire asynchronous
  operation without widening production limits to accommodate fixture contention.
- Account for fixture failure paths as ownership code. Release shared store or
  SDK handles before directory deletion, and restore process-global test state
  before framework or instrumentation exit work. Temporary values may survive
  across sequential awaits until lexical scope ends; make release order explicit.
- Use a descriptor witness that follows the required owner and object lifetime.
  Forked children may retain descriptors before exec. A guard's lexical release
  is not proof of the last kernel reference disappearing.
- Before narrowing a lock, inventory every protected resource, counter, callback,
  and resettable evidence ledger. Separate custody only with attribution or
  quiescence evidence, not from the guard name or a timing correlation.
- Keep mutation oracles independent of mutated expressions and available in the
  package scope used by mutation. For fault injection, satisfy earlier guards
  and preserve downstream preconditions so a later error cannot mask a permissive
  guard. Source-policy tests must exercise valid alternate syntax and both
  ancestor and descendant exclusion directions.
- Preserve shared test-double defaults; add observations through explicit scenario
  configuration and run old consumers alongside new cases. A diagnostic batch
  should collect all scenarios before its verdict without weakening conformance.
- Keep diagnostic capture bounded while preserving an explicit overflow or
  truncation signal. Compare framing for each concatenated record. Modeled inputs
  remain modeled evidence even if serialized in the same format as native receipts.
