---
name: worktree-status
description: Report the live status of PiglorOS agents and Git worktrees, including ticket/ADR review state, branch divergence, uncommitted changes, quality gates, and the specific approvals or interventions needed from the user. Use when the user asks about agent progress, worktree status, pending reviews, merge readiness, cleanup candidates, or what they need to decide next.
---

# Worktree Status

Report the current state; do not mutate branches, worktrees, tickets, ADRs, or
agents unless the user separately asks for an action.

## Gather

1. List live agents. Record agent name and running/completed state. Do not
   infer an agent from a worktree name.
2. List Git worktrees. For each, inspect:
   - path and branch;
   - latest commit;
   - commits ahead of and behind `main`;
   - tracked and untracked changes;
   - a mapped Redmine ticket/ADR only when the branch name, commit, agent task,
     or local documentation provides evidence.
3. For a worktree with an active or completed implementation agent, report the
   latest known tests, coverage, review, and merge status. Say `unknown` when
   no evidence is available; do not claim a gate passed from an old result.
4. Query canonical Redmine ADRs only when the user asks for ADR review status.
   Local worktrees do not mirror Redmine wiki pages, so distinguish local code
   state from canonical ADR status.

Use read-only commands equivalent to:

```bash
git worktree list --porcelain
git -C <worktree> status --short --branch
git -C <worktree> rev-list --count main..HEAD
git -C <worktree> rev-list --count HEAD..main
git -C <worktree> log -1 --oneline
```

## Report

Lead with the active-agent count. Then provide one compact table:

| Worktree | Agent | Ticket / ADR | Branch state | Delivery state |
| --- | --- | --- | --- | --- |

Use clear delivery states: `active`, `awaiting review`, `ready to merge`,
`blocked`, `dormant`, `stale`, or `cleanup candidate`. Do not call a worktree
ready to merge while it has uncommitted changes, unresolved review findings,
failed/missing required gates, or an unreviewed required ADR.

## Your intervention

End with a separate **Your intervention** section. Include only decisions the
user must make, each with the recommendation and consequence:

- approve, reject, or request changes to a Proposed/Under Review ADR;
- review a branch before merge when project policy requires review;
- choose between materially different product/specification alternatives;
- resolve an actual merge conflict or blocked external dependency;
- explicitly authorize removal of a worktree with uncommitted work;
- approve merging/pushing when the user has reserved that authority.

Do **not** ask the user to intervene for routine implementation, routine test
failures that are in scope to fix, a clean dormant worktree, or an ordinary
rebase that can be performed safely. If no decision is needed, write:

`Your intervention: none — <brief reason>.`

For every intervention, state the exact object and safe next action. Example:

```markdown
## Your intervention

- **ADR-031 — approve or request changes.** Recommendation: approve only after
  reviewing its privacy/coarsening decision; implementation #142 remains
  blocked until then.
- **ticket-144-owntracks-contract — review before merge.** Recommendation:
  address the P1 canonical-CBOR finding before approving merge.
```

## Pre-flight

Before sending the status:

- [ ] Separate live-agent status from worktree state.
- [ ] Mark unknown evidence as unknown.
- [ ] Do not confuse a local search with canonical Redmine ADR status.
- [ ] Do not recommend deletion of dirty worktrees without explicit approval.
- [ ] Include the **Your intervention** section, even when it says none.
