---
name: using-git-worktrees
description: Isolate a PiglorOS task in its own Git worktree, publish coherent commits and a pull request, and clean up the task checkout. Use when starting repository work or preparing delivery; use worktree-status for read-only fleet status.
---

# Using Git Worktrees

Internal PiglorOS workflow. Read [delivery lessons](references/delivery.md)
before creating, publishing, or removing a task worktree.

## Isolate the task

Inspect the current checkout, local changes, existing worktrees, and the intended
base before creating a task-named branch and worktree. Record the base commit.
Never implement directly on `main` or borrow another task's checkout. If the
shared Git directory is read-only, use the isolated-clone fallback in the lessons.

Keep unrelated files and configuration out of the task diff. Before any branch
mutation, re-check the exact branch, live ownership, and resource constraints.
Prefer separate branches for independent workers; integrate a dependency-complete
state before publishing shared work.

Record an approval hold against its exact object and scope. An upstream fix
does not prove a consumer is repaired until that consumer integrates and
validates it; unrelated authorized work can continue while the held decision
waits.

## Publish and clean up

Stage explicit task paths, inspect the staged diff, and require successful checks
before the dependent commit or push. Retain the repository hooks. Reconcile a
shared remote tip without rewriting another worker's commits; never update a
branch merely because `main` advanced. Resolve actual conflicts within repository
policy.

For stacked PRs, verify live parent ancestry as well as hosted base names and
native stack metadata. Source history and the hosting service's relationship
graph are separate. Repair stale stack metadata only through supported lifecycle
operations, preserving source identities; do not infer a Git conflict from a
hosting eligibility error. Use `resolving-merge-conflicts` for actual conflicts.

For an authorized PR request, push the task branch and open the PR with truthful
scope, validation, and remaining checks. Opening a PR does not authorize queueing
or merging. Merge only through Trunk, and add `ready-to-merge` only when the
maintainer explicitly asks. See [merge policy](../../../docs/merge-queue.md).

Remove the task worktree only after its commits are preserved on the remote and
its status is clean. Keep the remote PR branch available for review.

## Pre-flight

- [ ] Worktree and base identify this task; unrelated edits remain untouched.
- [ ] Staged paths, commit, remote branch, and PR agree on the intended change.
- [ ] Required checks succeeded or the handoff explicitly names pending evidence.
- [ ] The requested end state is met without assuming merge authority.
- [ ] Cleanup removes only this task's clean, published checkout.
