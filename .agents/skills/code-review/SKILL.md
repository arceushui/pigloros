---
name: code-review
description: Review the changes since a fixed point (commit, branch, tag, or merge-base) along two axes — Standards (does the code follow this repo's documented coding standards?) and Spec (does the code match what the originating issue/PRD asked for?). Runs both reviews in parallel sub-agents and reports them side by side. Use when the user wants to review a branch, a PR, work-in-progress changes, or asks to "review since X".
---

Two-axis review of the diff between `HEAD` and a fixed point the user supplies:

- **Standards** — does the code conform to this repo's documented coding standards?
- **Spec** — does the code faithfully implement the originating issue / PRD / spec?

Both axes run as **parallel sub-agents** so they don't pollute each other's context, then this skill aggregates their findings.

Run this workflow only when the user explicitly requests review. Implementation
completion, a CI result, or idle hosted time does not authorize a review.

The issue tracker should have been provided to you — run `/setup-matt-pocock-skills` if `docs/agents/issue-tracker.md` is missing.

## Process

### 1. Pin the review snapshot and mode

Whatever the user said is the fixed point — a commit SHA, branch name, tag, `main`, `HEAD~5`, etc. If they didn't specify one, ask for it.

Work in the authoritative task worktree. Record its absolute path, the resolved
base SHA, feature-head SHA, merge-base SHA, changed-file list, and full commit
list. Capture the diff command once: `git diff <fixed-point>...HEAD` (three-dot,
so the comparison is against the merge-base).

Before going further, confirm the fixed point resolves and the diff is non-empty.
Require each reviewer to repeat the worktree path and both SHAs before reporting.
A rebase or remediation commit invalidates the snapshot and any closure verdict.

Use **final mode** by default. If the user explicitly asks for a quick review,
use a bounded fast mode that still checks both axes but reports only verified,
high-confidence findings within the requested time/scope budget. Do not present
fast mode as final approval.

### 2. Identify the spec source

Look for the originating spec, in this order:

1. Issue references in the commit messages (`#123`, `Closes #45`, GitLab `!67`, etc.) — fetch via the workflow in `docs/agents/issue-tracker.md`.
2. A path the user passed as an argument.
3. A PRD/spec file under `docs/`, `specs/`, or `.scratch/` matching the branch name or feature.
4. If nothing is found, ask the user where the spec is. If they say there isn't one, the **Spec** sub-agent will skip and report "no spec available".

Collect the complete acceptance record, not only requirement prose: ticket
journals, PR description, linked reports and measurements, accepted ADR
revisions, active configuration/profile, and explicit ticket ownership for
deferred requirements. Record the product's compatibility policy; retained old
or legacy paths are findings unless the active specification requires them.

### 3. Identify the standards sources

Anything in the repo that documents how code should be written, such as `CODING_STANDARDS.md` or `CONTRIBUTING.md`.

On top of whatever the repo documents, the Standards axis always carries the **smell baseline** below — a fixed set of Fowler code smells (_Refactoring_, ch.3) that applies even when a repo documents nothing. Two rules bind it:

- **The repo overrides.** A documented repo standard always wins; where it endorses something the baseline would flag, suppress the smell.
- **Always a judgement call.** Each smell is a labelled heuristic ("possible Feature Envy"), never a hard violation — and, like any standard here, skip anything tooling already enforces.

Each smell reads *what it is* → *how to fix*; match it against the diff:

- **Mysterious Name** — a function, variable, or type whose name doesn't reveal what it does or holds. → rename it; if no honest name comes, the design's murky.
- **Duplicated Code** — the same logic shape appears in more than one hunk or file in the change. → extract the shared shape, call it from both.
- **Feature Envy** — a method that reaches into another object's data more than its own. → move the method onto the data it envies.
- **Data Clumps** — the same few fields or params keep travelling together (a type wanting to be born). → bundle them into one type, pass that.
- **Primitive Obsession** — a primitive or string standing in for a domain concept that deserves its own type. → give the concept its own small type.
- **Repeated Switches** — the same `switch`/`if`-cascade on the same type recurs across the change. → replace with polymorphism, or one map both sites share.
- **Shotgun Surgery** — one logical change forces scattered edits across many files in the diff. → gather what changes together into one module.
- **Divergent Change** — one file or module is edited for several unrelated reasons. → split so each module changes for one reason.
- **Speculative Generality** — abstraction, parameters, or hooks added for needs the spec doesn't have. → delete it; inline back until a real need shows.
- **Message Chains** — long `a.b().c().d()` navigation the caller shouldn't depend on. → hide the walk behind one method on the first object.
- **Middle Man** — a class or function that mostly just delegates onward. → cut it, call the real target direct.
- **Refused Bequest** — a subclass or implementer that ignores or overrides most of what it inherits. → drop the inheritance, use composition.

### 4. Spawn both sub-agents in parallel

Send a single message with two `Agent` tool calls. Use the `general-purpose` subagent for both.

**Standards sub-agent prompt** — include:

- The full diff command and commit list.
- The list of standards-source files you found in step 3, **plus the smell baseline from step 3** pasted in full — the sub-agent has no other access to it.
- The brief: "Report — per file/hunk where relevant — (a) every place the diff violates a documented standard: cite the standard (file + the rule); and (b) any baseline smell you spot: name it and quote the hunk. Distinguish hard violations from judgement calls — documented-standard breaches can be hard, but baseline smells are always judgement calls, and a documented repo standard overrides the baseline. Skip anything tooling enforces. **Expose every risk, regardless of size — a minor data clump or a debatable name is worth reporting. Do not suppress findings because they seem 'small'.**"
- Ask it to distinguish ordinary public-contract tests from narrowly justified
  impossible-state fault injection, and accidental duplication from an
  intentionally independent test oracle.
- When workflow logic moved into a referenced script, require policy tests and
  adversarial fixtures to follow that executable indirection.

**Spec sub-agent prompt** — include:

- The diff command and commit list.
- The path or fetched contents of the spec.
- The brief: "Report: (a) requirements the spec asked for that are missing or partial; (b) behaviour in the diff that wasn't asked for (scope creep); (c) requirements that look implemented but where the implementation looks wrong. Quote the spec line for each finding. **Surface every deviation, no matter how small — a method name that differs from the spec, an optional field made required, a default value mismatch — everything counts. Do not filter by severity.**"
- Require each finding to identify the active configuration, reachable
  transition, exact normative object, and owning ticket/module. A representable
  enum value is not automatically reachable; an individually valid old/new
  endpoint pair is not automatically a valid transition.
- For bounded aggregate formats, require evidence that nested cardinalities fit
  the enclosing representation. For extensible inputs, close governance
  envelopes exactly while validating provider-owned payloads through their
  pinned schema rather than freezing them in a partial shared type.

If the spec is missing, skip the Spec sub-agent and note this in the final report.

### 5. Adjudicate and aggregate

Preserve the two raw reports under `## Standards` and `## Spec`; do not let one
axis mask the other. Then add a separate disposition table. For every candidate
finding, verify the cited current lines and full call chain, recount severity,
separate the evidence from the proposed remedy, identify overlaps without
deleting provenance, and classify it as accepted, rejected, or deferred with
ownership, merge impact, and reason.

Independent review discovers risks; the coordinator's source-backed
adjudication determines the merge verdict. Challenge false blockers caused by
partial call-chain reads, impossible active states, or delivery owned by a
different ticket, while still flagging incorrect provisional behavior in the
current diff.

**Expose every risk.** Do not suppress findings because they seem trivial — a naming inconsistency, an optional field handling, a minor spec deviation. The reviewer's job is to surface; triage happens after.

End with a one-line summary: total findings per axis, and the worst issue _within each axis_ (if any). Don't pick a single winner across axes — that's the reranking the separation exists to prevent.

For closure, freeze one exact code-and-spec snapshot, require the relevant
hosted gates on that SHA, and run both complete merge-base reviews. Any code,
rebase, accepted-decision, or acceptance-evidence change requires a fresh
closure review. Review fixes must be the smallest behavioral changes with
public-boundary regressions where possible and must not introduce unrelated
coverage debt.

An intermediate external-bot review does not replace the final local two-axis
review. If an opt-in bot reports that automatic review is disabled, use its
documented explicit review command and verify acknowledgement before waiting;
a mention or comment alone is not evidence that review started.

## Pre-flight

- [ ] Review was explicitly requested and the requested mode is stated.
- [ ] Worktree, base, head, merge-base, files, commits, and spec revisions are pinned.
- [ ] Reviewers received compatibility policy, ownership, and acceptance evidence.
- [ ] Every finding has a source-backed disposition without collapsing the axes.
- [ ] Any merge verdict applies to the exact final head and current gate rollup.

## Why two axes

A change can pass one axis and fail the other:

- Code that follows every standard but implements the wrong thing → **Standards pass, Spec fail.**
- Code that does exactly what the issue asked but breaks the project's conventions → **Spec pass, Standards fail.**

Reporting them separately stops one axis from masking the other.
