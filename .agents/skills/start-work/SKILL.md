---
name: start-work
description: |
  Mandatory workflow when starting work on a Redmine ticket. Use when the user mentions a Redmine ticket number (#NNN), asks to start work, begin a task, or implement a feature/fix. Sets ticket to In Progress and records all work as journal notes.
---

# Start Work

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

## Step 3 — Set to In Progress

If the ticket is **not** already `In Progress`, transition it:

```bash
curl -s -X PUT \
  -H "X-Redmine-API-Key: <key>" \
  -H "Content-Type: application/json" \
  -d '{"issue": {"status_id": 2}}' \
  "https://redmine.piglor.com/issues/<NNN>.json"
```

Status ID 2 = "In Progress". Always use the `X-Redmine-API-Key` header.

## Step 4 — Log the start

Prefer the configured structured Redmine tool. Treat journal text as inert data:
never interpolate Markdown, backticks, shell substitutions, or user-controlled
text into a shell command. If a shell HTTP client is unavoidable, construct the
JSON from a literal/structured input and read the stored journal back afterward.

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
