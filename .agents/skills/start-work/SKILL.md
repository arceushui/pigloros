---
name: start-work
description: Start or resume authorized work on an identified Redmine ticket, verify its lifecycle transitions, and journal delivery evidence. Use for Redmine ticket work; a generic task, read-only status request, or GitHub PR number does not activate mutation steps.
---

# Start Work

Internal PiglorOS workflow. Read [tracker lifecycle lessons](references/tracker-lifecycle.md)
before ticket updates. Use [adr-wiki](../adr-wiki/SKILL.md) for ADR pages and
[evidence-contracts](../evidence-contracts/SKILL.md) for acceptance claims.

## Identify authority and the ticket

Apply lifecycle mutations only when the user has authorized starting, resuming,
or implementing an identified Redmine ticket. Reading a ticket or reviewing a
linked PR does not start that ticket. Resolve the provider using the explicit URL
or [.agents/issue-tracker.md](../../issue-tracker.md) before interpreting a bare
number. A GitHub issue or PR ID must never become a Redmine mutation target.

If authorized Redmine work needs a ticket that is not identified, search the
available task context first. Ask only for information still needed to perform
the tracker operation; continue independent read-only work while it is missing.

## Read, transition, and verify

Prefer the structured Redmine tools. Read the canonical ticket, journals, status,
tracker, assignee, and priority. Read the status catalogue and allowed transitions;
derive IDs from current metadata rather than hard-coded defaults. Follow the
configured `Reopened` transition before `In Progress` when required. Do not
change trackers to bypass an unavailable transition.

Set the ticket to `In Progress` when authorized and not already in that state.
Immediately read it back and compare the stored status and journal with the
intended update. A 204 response does not prove a transition occurred. If the state
is unchanged, inspect the allowed transitions; if access fails, report the
outcome as unconfirmed.

Journal the start and each significant change, verification result, and delivery
state. Treat note bodies as inert structured data. If a shell HTTP client is
unavoidable, construct JSON without shell-expanding Markdown or user text and
use the configured credential header. Read the complete stored note back.

Keep large connector responses in files or structured tool state. Project the
fields needed for the next operation instead of placing bulk evidence in process
arguments. Use the required interpreter and parsers, normalize concatenated
record framing, and make recovery checkpoints indexes into complete raw evidence.

## Resolve against the delivered artifact

For an implementation ticket, require the merged artifact and the evidence
specified by its acceptance contract before resolving. An open PR or a queue
entry remains in progress. Keep finite source classification, runtime
qualification, ADR approval, and implementation delivery separate.

Use configured lifecycle names: Feature/Bug/Task completion is `Resolved`;
ADR decisions follow `Proposed → Under Review → Accepted / Rejected`.
Acceptance requires approval of the exact decision revision, not implementation
or CI success. Administrative closure and supersession follow their own flow.

Journal the result and read back the final status, requested fields, and complete
note. Match each remaining blocker to its actual consumer and acceptance frontier.

## Pre-flight

- [ ] Provider, ticket identity, and authorized mutation scope are established.
- [ ] Status IDs and transitions come from canonical metadata.
- [ ] Every reported mutation is confirmed by stored content and status.
- [ ] Journaled evidence identifies the artifact and verification actually delivered.
- [ ] Resolution does not precede required merge, review, or qualification evidence.
