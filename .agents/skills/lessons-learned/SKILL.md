---
name: lessons-learned
description: Route PiglorOS work to the project skills that own durable lessons. Read before implementation and load only the owners relevant to the task.
disable-model-invocation: true
---

# Lessons Learned

Internal PiglorOS entry point. Durable lessons live with the workflow that owns
them; add future guidance there instead of growing a second checklist here.
Raw observations and dated execution records stay outside Git.

Read `CONTEXT.md` and `README.md` first. Keep each task in its own worktree,
stage only task files, honor local resource constraints, and check required
command exit codes before dependent mutations. Opening a PR never grants
permission to merge: Trunk queue entry requires explicit maintainer instruction.

## Choose the owner

Read each applicable skill entry point and the references it calls for before
performing that part of the task. Several owners may apply; do not load all
reference files by default.

| Task | Owning skill |
| --- | --- |
| Task isolation, commits, PR publication, cleanup | [using-git-worktrees](../using-git-worktrees/SKILL.md) |
| Rust edits, tests, lint, coverage closure | [rust-quality-gates](../rust-quality-gates/SKILL.md) |
| Concurrent protocol tests, cancellation and cleanup witnesses | [async-test-oracles](../async-test-oracles/SKILL.md) |
| Hosted gates, workflow changes, mutation, sanitizer, cache tuning | [ci-verification](../ci-verification/SKILL.md) |
| Contract acceptance, authority, conformance, evidence claims | [evidence-contracts](../evidence-contracts/SKILL.md) |
| Explicitly requested independent Standards and Spec review | [code-review](../code-review/SKILL.md) |
| Reproducible bug diagnosis and performance regressions | [diagnosing-bugs](../diagnosing-bugs/SKILL.md) |
| Redmine ticket work and lifecycle | [start-work](../start-work/SKILL.md) |
| Epic decomposition, callable slices, stack file ownership | [implementation-ticket-slicing](../implementation-ticket-slicing/SKILL.md) |
| Significant architecture choice before implementation | [prepare-adr](../prepare-adr/SKILL.md) |
| Canonical ADR hierarchy, formatting, revision approval | [adr-wiki](../adr-wiki/SKILL.md) |
| Documentation ownership, publication, external read-back | [technical-documentation-pipeline](../technical-documentation-pipeline/SKILL.md) |
| Live agents, worktrees, tracker and PR status reconciliation | [worktree-status](../worktree-status/SKILL.md) |
| Shared observation records and skill authoring | [task-observer](../task-observer/SKILL.md) |

## Pre-flight verification

Before delivery, re-read applicable owner guidance against the diff, commands,
records, and handoff. Preserve required local, hosted, and external-record checks
and state any pending evidence. Completion means the requested end state;
post-merge work applies only when that work is authorized.

For skill updates, check for synthesis, ownership, contradictions, and reachable
references. Run new read-only or authorized embedded commands against real data
and inspect plausible output. Validate mutating or destructive examples by
syntax and exact-target inspection; execute them only when authorized.
