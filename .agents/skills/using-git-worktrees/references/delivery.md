# Commits and worktrees

Internal PiglorOS guidance. Apply the relevant lessons within the current task's
authorization and repository policy.

- **Stage only intended changes.** Use explicit task paths and inspect the staged
  diff, including after any staging reset. Leave unrelated configuration and
  another task's files untouched.

- **Define completion by the requested end state.** A local green run is not delivery by itself. Verify the committed worktree, pushed branch, pull-request gates, tracker state, and external records required by the task. Verify the merged target branch and post-merge workflows only when merging is part of the authorized delivery scope; opening a PR does not grant merge authority.

- **Reconcile project records before reporting status.** Compare the repository, Redmine, Notion, GitHub, roadmap, worktrees, and product acceptance. If they disagree, name stale or conflicting labels, distinguish the current Wave from its milestone design, and never infer the project stage from one source.

- **Re-check mutation boundaries.** Before cleanup, conflict repair, or an
  external write, confirm live ownership, current state, and exact targets;
  never delete an active worktree or overwrite a shared record from a stale inventory.

- **Reconcile a shared PR immediately before pushing.** Concurrent workers can
  publish overlapping fixes while a hook runs. Fetch the PR branch, compare its
  merge base and commits, and merge its current tip without duplicating work.
  Never rebase or force-push a shared branch to replace a concurrent update.

- **Publish only dependency-complete shared-branch commits.** Parallel agents may prepare disjoint edits, but a slice that depends on uncommitted coordinator work must not be pushed alone. Integrate and commit one coherent state, or isolate independently mergeable commits in separate worktrees.

- **Respect execution constraints.** Hosted CI supplies Cargo evidence under
  current policy. Respect explicit resource limits for permitted checks and
  hooks too. Do not lower scope or thresholds, or treat spare capacity as
  authorization for a prohibited local run.

- **Stop on a failed check before any dependent mutation.** A resolved tool call is not a successful one: read each required verification's exit code and halt before staging, committing, pushing, or writing to an external system. Treat deliberately expected nonzero probes separately.

- **Disable implicit Git maintenance under local resource limits.** Scope `-c gc.auto=0 -c maintenance.auto=false` to mutating Git commands, not only build hooks. If housekeeping starts anyway, identify the process and inspect its state before stopping it, and never delete a pack merely because it was recently written.

- **Publish an authorized dependency-complete slice.** For a requested PR, open
  a draft when required architecture approval exists and the first coherent
  slice is ready for review. Keep scope, exact-head evidence, and blockers
  truthful. A draft implies neither passing gates nor permission to queue.

- **Persistence is not merge authority.** A request to keep going is not authorization to queue or merge a protected PR; state the evidence and the one maintainer action needed.

- **Keep isolation when the shared Git directory is read-only.** Create an isolated bare clone in an approved writable temporary location, add the task branch as a worktree from it, record the exact base commit, and keep the normal branch and PR workflow. Never edit another task's checkout.
