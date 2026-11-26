# Redmine

Internal PiglorOS guidance. Apply the relevant lessons within the current task's
authorization and repository policy.

- **Must invoke `start-work` skill when beginning work on any Redmine ticket.** This sets the ticket to In Progress and records all work as journal notes. Never start work without it.

- **ADR wiki pages use Markdown, not Textile, and MUST have `ADR` as their parent page.** See the `adr-wiki` skill for full rules for hierarchy, formatting, and API usage.

- **Follow the configured ADR transition flow.** Keep ADRs in `Proposed → Under Review → Accepted / Rejected` as configured; if a transition is unavailable, record the blocker rather than changing trackers or statuses to bypass it.

- **Advance tracker artifacts only through their configured lifecycle.** A commit, an Accepted ADR, or a passing CI run does not by itself resolve an implementation ticket. Feature/Bug/Task completion uses the configured `Resolved` state; ADR approval uses `Proposed → Under Review → Accepted`; rejected or superseded records use their configured terminal states. Read current metadata and allowed transitions for status IDs at the time of each operation. Treat `Closed` as administrative finalization only when the configured flow requires it. Keep ADR acceptance, implementation authorization, evidence readiness, and product acceptance separate.

- **Keep authority states separate.** ADR status, implementation authorization, ticket status, evidence readiness, and product acceptance are different facts. An Accepted ADR records a decision; it does not start implementation.

- **Preserve the project hierarchy.** Keep Wave, milestone design, ADR, implementation ticket, and subtask distinct. Use Redmine parent/child for decomposition and blocker relations for execution order between otherwise independent tickets; do not encode the same relation twice.

- **Check the configured credential source before reporting tracker access as unavailable.** Resolve it from the stable workspace or environment (a fresh worktree may lack local config), attempt the request, and classify the failure as missing credential, authentication rejection, or network/name-resolution failure.

- **Report conflicting tracker snapshots.** Treat a cached issue snapshot with conflicting wave or version signals as evidence to report, not to pick from silently.

- **Resolve a delivery ticket only against the merged artifact.** Require the provider to report `MERGED` with the merge commit on the authoritative branch, inspect the required behavior or configuration at that commit, and link merge and hosted evidence in the journal. A queue entry is a wait state.

- **Do not manufacture retrospective child tickets.** During epic reconciliation, separate a traceability gap from an unfulfilled outcome: create a child only for a current, independently verifiable deliverable; otherwise record the historical evidence in the epic.

- **Treat tracker prose as data.** Build note bodies with a quoted here-document or formatting primitive so Markdown literals are never shell-expanded, and read back after writing. Interpolate only verified values, outside Markdown delimiters.

- **Record ADR approval as a revision-specific decision.** Implementation and green CI are delivery evidence, not substitutes. Verify each named baseline against the authoritative branch, keep reference-hardware qualification out of ordinary PR, ADR-acceptance, and release gates, and run any physical-hardware lane as a protected, dated qualification on a self-hosted-runner security boundary. Portable checks serve all contributors and hosted integration checks serve adapter changes. Record the exact revision sent for review.

- **Label each ADR limit by scope.** Mark each limit structural, per-input, per-phase, or operation-wide with one composition rule for cumulative budgets and exact-limit plus one-over tests.
