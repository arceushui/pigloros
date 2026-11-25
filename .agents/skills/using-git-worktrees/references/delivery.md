# Commits and worktrees

Internal PiglorOS guidance. Apply the relevant lessons within the current task's
authorization and repository policy.

- **Never `git add -A`.** It stages everything including skills files with pre-existing yamllint issues and unrelated local configuration. Stage only the files you changed: `git add path/to/changed/file.rs`.

- **Commit before removing a worktree.** Uncommitted changes disappear when a worktree is force-removed. Commit and push from the task worktree, verify the remote branch, and remove only that clean worktree. Merge through the Trunk merge queue only; add `ready-to-merge` only on explicit maintainer instruction.

- **`git reset` can lose your staging.** If you `git reset HEAD .agents/` then `git add specific files`, make sure the files you're adding are the ones with actual changes. If a file was already committed, `git add` won't re-stage it.

- **Define completion by the requested end state.** A local green run is not delivery by itself. Verify the committed worktree, pushed branch, pull-request gates, tracker state, and external records required by the task. Verify the merged target branch and post-merge workflows only when merging is part of the authorized delivery scope; opening a PR does not grant merge authority.

- **Reconcile project records before reporting status.** Compare the repository, Redmine, Notion, GitHub, roadmap, worktrees, and product acceptance. If they disagree, name stale or conflicting labels, distinguish the current Wave from its milestone design, and never infer the project stage from one source.

- **Stage only task files and re-check mutation boundaries.** Before cleanup, rebasing, or an external write, confirm live ownership, current state, and exact targets immediately before the mutation; never delete an active worktree or overwrite a shared record from a stale inventory.

- **Reconcile a shared PR immediately before pushing.** Concurrent workers can land equivalent or overlapping fixes while a rebase or hook is running. Fetch the PR branch, compare the merge base and commits, merge its current tip, and drop patches already present. Never rebase or force-push a shared branch to replace a concurrent update.

- **Publish only dependency-complete shared-branch commits.** Parallel agents may prepare disjoint edits, but a slice that depends on uncommitted coordinator work must not be pushed alone. Integrate and commit one coherent state, or isolate independently mergeable commits in separate worktrees.

- **Respect explicit local resource limits.** When local Cargo, coverage, mutation, or formatter work would violate a stated storage/memory constraint, use unchanged hosted gates for that evidence and record the limitation. Do not lower scope or thresholds, and do not treat a capacity estimate as authorization to run locally.

- **Stop on a failed check before any dependent mutation.** A resolved tool call is not a successful one: read each required verification's exit code and halt before staging, committing, pushing, or writing to an external system. Treat deliberately expected nonzero probes separately.

- **Disable implicit Git maintenance under local resource limits.** Scope `-c gc.auto=0 -c maintenance.auto=false` to mutating Git commands, not only build hooks. If housekeeping starts anyway, identify the process and inspect its state before stopping it, and never delete a pack merely because it was recently written.

- **Open a draft PR after architecture approval and the first dependency-complete slice.** Keep scope, exact-head evidence, and blockers truthful, update the description as results change, and do not let a draft imply passing gates or permission to queue.

- **Persistence is not merge authority.** A request to keep going is not authorization to queue or merge a protected PR; state the evidence and the one maintainer action needed.

- **Keep isolation when the shared Git directory is read-only.** Create an isolated bare clone in an approved writable temporary location, add the task branch as a worktree from it, record the exact base commit, and keep the normal branch and PR workflow. Never edit another task's checkout.
