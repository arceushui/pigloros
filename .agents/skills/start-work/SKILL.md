---
name: start-work
description: |
  Mandatory workflow when starting work on a Redmine ticket. Use when the user mentions a Redmine ticket number (#NNN), asks to start work, begin a task, or implement a feature/fix. Sets ticket to In Progress and records all work as journal notes.
---

# Start Work

Internal PiglorOS workflow. Before ticket or epic updates, read
[tracker lifecycle lessons](references/tracker-lifecycle.md). For ADR content or
hierarchy, also use [adr-wiki](../adr-wiki/SKILL.md); for acceptance evidence,
use [evidence-contracts](../evidence-contracts/SKILL.md).

Every work session referencing a Redmine ticket MUST follow this flow. No exceptions.

## Step 1 — Identify the ticket

Extract the Redmine ticket number from the user's message. Look for patterns like `#NNN`, `ticket NNN`, `issue NNN`, or explicit Redmine URLs.

If no ticket number is given, ask: *"Which Redmine ticket is this for?"*

## Step 2 — Fetch ticket details

```bash
curl -s -H "X-Redmine-API-Key: <key>" \
  "https://redmine.piglor.com/issues/<NNN>.json?include=journals"
```

Record: status, tracker, subject, assignee, priority.

Read the canonical status catalogue and this ticket's allowed transitions. Map
status names to their configured IDs; examples below describe the current
PiglorOS catalogue, not universal Redmine IDs. For reopened work, follow the
configured `Reopened` transition before `In Progress` when required. Never guess
an intermediate ID or change trackers to bypass the workflow.

## Step 3 — Set to In Progress

If the ticket is **not** already `In Progress`, transition it:

```bash
curl -s -X PUT \
  -H "X-Redmine-API-Key: <key>" \
  -H "Content-Type: application/json" \
  -d '{"issue": {"status_id": 2}}' \
  "https://redmine.piglor.com/issues/<NNN>.json"
```

Use ID 2 only after verifying it is the configured `In Progress` status and the
transition is allowed. Always use the `X-Redmine-API-Key` header.

Immediately fetch the canonical ticket after the write and compare its stored
status and journal with the intended values. A 204 response does not prove a
transition occurred. If the state is unchanged, inspect allowed transitions;
if the service fails, record the state as unconfirmed rather than claiming it.

## Step 4 — Log the start

Prefer the configured structured Redmine tool. Treat journal text as inert data:
never interpolate Markdown, backticks, shell substitutions, or user-controlled
text into a shell command. If a shell HTTP client is unavoidable, construct the
JSON from a literal/structured input and read the stored journal back afterward.

Keep large responses in files or structured tool state; project only the fields
needed for the next operation. Never embed bulk connector output in process
arguments. Use a verified interpreter with the required parsers. Normalize record
framing before combining receipts and keep recovery checkpoints as indexes into
complete raw evidence rather than copies of every response.

Add a journal note recording that work has begun:

```bash
curl -s -X PUT \
  -H "X-Redmine-API-Key: <key>" \
  -H "Content-Type: application/json" \
  -d '{"issue": {"notes": "Started work on ticket <NNN>."}}' \
  "https://redmine.piglor.com/issues/<NNN>.json"
```

## Step 5 — Record all work

Throughout the session, every significant action MUST be recorded:

- **After each code change** — note what files were modified and why
- **After tests pass/fail** — note test results
- **On completion** — note the final state, any remaining issues, and set the appropriate status

Journal notes are added via:

```bash
curl -s -X PUT \
  -H "X-Redmine-API-Key: <key>" \
  -H "Content-Type: application/json" \
  -d '{"issue": {"notes": "<what was done>"}}' \
  "https://redmine.piglor.com/issues/<NNN>.json"
```

## Step 6 — Close or resolve

When work is complete:

For an implementation delivery ticket, verify the merged artifact and required
evidence before resolving, as specified in the tracker lifecycle lessons. An
open PR or a queue entry remains In Progress. Keep architecture approval and
implementation delivery separate.

- **Feature / Bug / Task** → `Resolved` (status_id=3)
- **ADR** → `Under Review` (status_id=8), then `Accepted` (status_id=9)
- **Rejected / Superseded** → `Closed` (status_id=5) or `Rejected` (status_id=6)

Add a final journal note summarising the work before closing.

## Completion criterion

The ticket's journal contains notes for every significant action taken during
the session, and the status reflects the current state (`In Progress` during
work, `Resolved`/`Accepted` when done). Before resolving, audit every evidence
class required by the ticket, ADR, repository policy, or standing instruction:
final-head hosted gates and an independent full-diff review are separate. Do
not resolve while a required final review is missing or has unresolved blockers.
Read the canonical ticket back after the final update.

Before reporting any lifecycle mutation successful, verify its stored status,
requested fields, and complete journal text. Match each blocker to its actual
consumer and acceptance frontier; source completion, merged delivery, and runtime
qualification remain separate facts.
