## Agent skills

### Worktree isolation

Every task MUST run in its own `git worktree` — never work directly on `main`. Create a worktree named after the task or ticket (e.g. `#83-hasher-port`, `#85-upcaster-registry`). Commit from the worktree, then remove it when done.

```bash
git worktree add ../pigloros-<task-name> main
cd ../pigloros-<task-name>
# ... work ...
git worktree remove ../pigloros-<task-name>
```

### Issue tracker

Internal roadmap lives in Redmine at `redmine.piglor.com/projects/pigloros`. GitHub Issues (`arceushui/pigloros`) is for community contributions when the project goes open source. See `.agents/issue-tracker.md`.

### Triage labels

Default five-role label vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `.agents/triage-labels.md`.

### Domain docs

Single-context layout — `CONTEXT.md` at repo root. Architectural decisions (ADRs) live canonically on Redmine wiki at `redmine.piglor.com/projects/pigloros/wiki`. See `.agents/domain.md`.
