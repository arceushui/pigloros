## Agent instructions

Before starting any task, read `CONTEXT.md` for domain vocabulary and `README.md` for the project overview. ADRs live on Redmine wiki (`redmine.piglor.com/projects/pigloros/wiki`).

Before writing code, read the `lessons-learned` skill — it documents every mistake made in prior sessions so you don't repeat them.

### Worktree isolation

Every task MUST run in its own `git worktree` — never work directly on `main`. Name the worktree after the task or ticket (e.g. `#83-hasher-port`). Commit from the worktree, then remove it when done.

See `using-git-worktrees` skill for the full workflow.

```bash
git worktree add ../pigloros-<task-name> main
cd ../pigloros-<task-name>
# ... work ...
git worktree remove ../pigloros-<task-name>
```

### Issue tracker

Redmine: `redmine.piglor.com/projects/pigloros`. GitHub Issues (`arceushui/pigloros`) is for community contributions. See `.agents/issue-tracker.md`.

### Multi-agent models

Use the project model-selection policy in `.agents/model-policy.md` when delegating implementation and independent review work.

### Triage labels

Default five-label vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `.agents/triage-labels.md`.

### Domain knowledge

- **CONTEXT.md** — domain glossary (use exact terms, don't drift to synonyms)
- **Redmine wiki** — canonical ADRs
- **Notion** — design docs and Wave specs (MCP configured)
- See `.agents/domain.md` for consumer rules

### Coverage and quality gates

Hosted CI is the evidence for build, test, lint, coverage and mutation results.
Do not run Cargo locally: push the branch and read the jobs
(`gh run view <run-id> --log-failed`). Only `cargo generate-lockfile` may run
locally; the versioned `.githooks/pre-commit` hook runs `cargo fmt --check` and
Clippy on commit, so keep `core.hooksPath=.githooks` and never skip it.

CI enforces the workspace gates: `cargo fmt`, Clippy (pedantic, warnings
denied), `cargo nextest run --workspace --all-features --locked --run-ignored
all`, doctests via `cargo test --doc -- --include-ignored`, and coverage via
`cargo llvm-cov nextest` at 99% lines and regions. If new code cannot be
covered by a test, **remove it** — don't leave dead branches. The 1% tolerance
is only for LLVM regions with no source mapping; it does not exempt tests or
production code.

### Merging

Merge only through the Trunk merge queue, which enqueues pull requests labelled
`ready-to-merge`. Add that label once the PR has passed its independent code
review (re-reviewed after every later change, all High/Medium/Low findings
fixed) and its CI is green. `/trunk merge` comments are disabled. Never press
Merge or call the GitHub merge API. Before pushing a fix, `git fetch origin`
and `git merge origin/main` (and the updated parent branch of a stacked PR) so
the PR runs against the baseline the queue uses; never rebase, amend or
force-push a pushed branch. A real fix may be pushed while the PR is queued —
it ejects the PR, so relabel after CI is green again. See
[`docs/merge-queue.md`](docs/merge-queue.md).

### Features and sizing

- **0 → 1** (new crate, plugin, or binary): architecture-first, ADR required
- **0 → many** (test expansion): keep tests focused on public interfaces (seams), not internals
- **MVP ≠ simplest** — cut the thinnest slice *of the final architecture*, built on the seams the full vision requires (ports, schema versions, documented extension points). Never ship a shortcut that must be thrown away when the future arrives

### Agent rules

Each rule the owner has had to repeat, with what enforces it. When the owner
corrects an agent, fix the mistake and add the rule here; enforce it with code
when it can be, and drop a rule once its mistake can no longer happen.

| Rule | Enforced by |
| --- | --- |
| No local Cargo except `cargo generate-lockfile` | `scripts/agent_command_guard.py` (Claude Code `PreToolUse` hook in `.claude/settings.json`) denies it; tested by `scripts/test_agent_command_guard.py` in CI |
| Never skip git hooks (`--no-verify`, `commit -n`, overriding `core.hooksPath`) without the owner's approval for that commit | Same guard asks the owner |
| Never rebase, amend or force-push a pushed branch; merge `origin/main` instead | Same guard asks the owner |
| Merge only through the Trunk queue | Branch protection and the queue (`docs/merge-queue.md`) |
| Stale `Cargo.lock` after a merge: restore main's lock before `cargo generate-lockfile` | `.githooks/pre-commit` rejects a stale lock; the restore order is a judgment call |
| Label `ready-to-merge` only after a clean independent review and green CI | Judgment call — nothing enforces it |
| Root-cause the first failing job before a rerun | Judgment call — nothing enforces it |
| No legacy or compatibility shims; replace directly | Judgment call — review finding |
| A slow CI lane rebuilds only what its inputs changed: key a cached build by its input hash (signed when it enters a trust chain), store multi-GB results where they are not evicted (release assets, not the 10 GB Actions cache), and never cache by disabling a check | Per-lane workflow policy oracles pin the cache steps, for example `scripts/check_qemu_closure_workflow_policy.py` for the QEMU kernel cache; when to add a cache is a judgment call |
