---
name: evidence-contracts
description: Define or audit PiglorOS public-contract acceptance claims, conformance fixtures, and authority boundaries. Use when specifying evidence or changing a contract; use prepare-adr for architecture decisions and code-review for an independent PR review.
---

# Evidence Contracts

Internal PiglorOS workflow. Read [contract lessons](references/contracts.md)
before designing acceptance criteria or changing a public seam. Read
[execution modes](references/execution-modes.md) when locality, network access,
or reproducibility is part of a claim. Use the exact vocabulary in
[CONTEXT.md](../../../CONTEXT.md).

For resource budgets, recovery, ownership, cancellation, or destructive cleanup,
read [lifecycle safety](references/lifecycle-safety.md) before specifying the
boundary. For asynchronous witnesses, use
[async-test-oracles](../async-test-oracles/SKILL.md).

For each claim identify its audience, public boundary, pass/fail condition,
module/schema owner, authoritative artifact, evaluator, maturity, and remaining
gate. Keep host evidence, evaluator validation, independent reproduction, and
authorship independence distinct.

Trace contract changes through consumers, adapters, exhaustive matches, fixtures,
migrations, and composition roots. Keep caller-supplied authority separate from
the trusted composition that grants it. Unsupported attestations remain pending;
metadata or a valid signature alone cannot establish behavior or trust.

Use small deterministic fixtures that exercise the declared boundary without
strengthening domain semantics. Preserve normative compatibility policy and
recompute dependent conformance fields. Significant boundary changes require the
accepted decision through `prepare-adr` before implementation unless the user
explicitly authorizes proceeding while Proposed.

## Pre-flight

- [ ] Every acceptance claim has an owner, public witness, and explicit scope.
- [ ] Integrity, authority, Replay, and empirical validity remain distinct.
- [ ] Changed consumers and conformance metadata match the normative contract.
- [ ] Pending evidence remains structurally pending; no placeholder proves a claim.
