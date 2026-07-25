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

### Domain knowledge

- **CONTEXT.md** — domain glossary (use exact terms, don't drift to synonyms)
- **Redmine wiki** — canonical ADRs
- **Notion** — design docs and Wave specs (MCP configured)

### Coverage rule

After every code change, run `cargo llvm-cov --fail-under-lines 100 --fail-under-regions 99`. If new code cannot be covered by a test, **remove it** — don't leave dead branches. Prefer deleting/simplifying over exemptions.

### Quality gates (local)

```bash
cargo fmt --all -- --check
cargo test --workspace --locked -- --include-ignored
cargo clippy --workspace --all-targets --locked -- -D warnings -W clippy::pedantic
RUSTC_BOOTSTRAP=1 cargo llvm-cov --workspace --locked --summary-only \
  --fail-under-lines 100 --fail-under-regions 99 -- --include-ignored
```

### Features and sizing

- **0 → 1** (new crate, plugin, or binary): architecture-first, ADR required
- **0 → many** (test expansion): keep tests focused on public interfaces (seams), not internals
- **MVP ≠ simplest** — cut the thinnest slice *of the final architecture*, built on the seams the full vision requires (ports, schema versions, documented extension points). Never ship a shortcut that must be thrown away when the future arrives
