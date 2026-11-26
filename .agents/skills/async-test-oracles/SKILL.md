---
name: async-test-oracles
description: Build reliable PiglorOS tests for concurrent protocols, deadlines, cancellation, and resource cleanup. Use when a fixture can hang, race an observation, or misattribute native lifecycle evidence; use diagnosing-bugs for the broader diagnosis loop.
---

# Asynchronous Test Oracles

Internal PiglorOS workflow. Read [oracle lessons](references/oracles.md) before
changing a concurrent or native qualification fixture. Use
[evidence-contracts](../evidence-contracts/SKILL.md) for the governing lifecycle
and [rust-quality-gates](../rust-quality-gates/SKILL.md) for Rust validation.

Identify the exact observable effect, its owner, and the earliest boundary that
can witness it. Draw the request, effect, reply, and cleanup ordering before
choosing a synchronization signal. A completion counter does not witness every
earlier side effect, and an error return does not prove native cancellation.

Use an ordered protocol barrier for negative observations and an independent
deadline for liveness. Bound every participant and ensure the deadline still
runs when the implementation is broken. Preserve ownership across accepted work,
then verify retirement through the end of the trace.

Keep modeled unit validation separate from empirical qualification claims. Use
the production lifecycle driver where practical with an independent evaluator.
Preserve shared fixture defaults and verify their existing consumers when adding
new capabilities.

## Pre-flight

- [ ] The oracle observes the stated effect and has an independent negative control.
- [ ] Earlier admission checks permit reaching the tested boundary.
- [ ] Every wait and blocking participant has a reachable stopping rule.
- [ ] Cleanup, quota, handle, and evidence lifetimes match the actual owner.
- [ ] Test scope and evidence provenance support exactly the reported claim.
