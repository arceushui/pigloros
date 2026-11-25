---
name: implement
description: "Implement authorized PiglorOS work from a specification or identified tickets, using the project workflow owners."
disable-model-invocation: true
---

# Implement

Implement the requested specification through the accepted project boundaries.
Use [using-git-worktrees](../using-git-worktrees/SKILL.md) to isolate the task and
deliver coherent commits. For authorized Redmine ticket work, use
[start-work](../start-work/SKILL.md); a generic task or PR reference does not
authorize tracker mutation.

Use TDD at pre-agreed seams when requested. For a new crate, plugin, binary,
public contract, or other significant architecture choice, follow
[prepare-adr](../prepare-adr/SKILL.md) before implementation.

Use [rust-quality-gates](../rust-quality-gates/SKILL.md) for current hosted
verification and coverage policy. Preserve hooks, remove uncoverable new code,
and obtain fresh evidence after review fixes. Do not duplicate gate commands here
or infer permission for manual local Cargo.

Use [code-review](../code-review/SKILL.md) when independent review is requested.
A merge requires a clean review of the final head and green required CI; neither
result grants merge authority. Commit from the task worktree and publish within
the user's authorized scope.

Before delivery, check the requested behavior, acceptance evidence, task-only
diff, committed revision, and remaining gates. Report pending checks honestly.
