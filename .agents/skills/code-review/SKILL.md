---
name: code-review
description: Independently review PiglorOS changes along Standards and Spec axes, with parallel reviewers and source-backed dispositions. Use for requested branch, PR, work-in-progress, or revision-bound external decision-document reviews.
---

Two-axis review of the diff between `HEAD` and a fixed point the user supplies:

- **Standards** — does the code conform to this repo's documented coding standards?
- **Spec** — does the code faithfully implement the originating issue / PRD / spec?

Both axes run as **parallel sub-agents** so they don't pollute each other's context, then this skill aggregates their findings.

Run this workflow only when the user explicitly requests review. Implementation
completion, a CI result, or idle hosted time does not authorize a review.

Use the repository's configured tracker in [.agents/issue-tracker.md](../../issue-tracker.md).

## Project review evidence

Before either axis starts, read [review evidence lessons](references/review-evidence.md)
and include the applicable boundary, oracle, and exact-tree checks in each
reviewer's brief. Preserve the user's constraints unchanged in every prompt.
Use [evidence-contracts](../evidence-contracts/SKILL.md) when claims or public
contracts are under review. These lessons supplement the two-axis process.

## Process

### Choose the review object

For repository changes, use the Git snapshot process below. For an explicitly
requested external decision-document review, pin the native object ID, provider
version, complete canonical body hash, accepted baseline revision, and candidate
revision instead. Review the full native document with the same independent
Standards and Spec axes; do not invent a code diff or require a commit to make
the review fit. Retain a revision-bound decision-review receipt separately from
implementation review, and read the current provider version again before
issuing a verdict. Git-only inventory requirements below apply to code mode.

### 1. Pin the review snapshot and mode

Use the supplied fixed point or the target base of the identified PR. Resolve it
to a commit before reviewing. Ask only when the available task context identifies
neither a fixed point nor a PR base.

Work in the authoritative task worktree. Record its absolute path, the resolved
base SHA, feature-head SHA, merge-base SHA, changed-file list, and full commit
list. Capture the diff command once: `git diff <fixed-point>...HEAD` (three-dot,
so the comparison is against the merge-base).

Before going further, confirm the fixed point resolves and the diff is non-empty.
Require each reviewer to repeat the worktree path and both SHAs before reporting.
Any changed head invalidates the snapshot and its closure verdict.

Use immutable artifact identities for each snapshot. After a failed mutation,
stop dependent snapshot commands and verify the intended head actually changed
before creating a new receipt; never overwrite an earlier review's identity.

Pin governing policy sources too: the worktree or provider, path or object ID,
commit or revision, and content identity. Resolve normative quotes against that
same tree or accepted external revision before accepting or rejecting a finding.
Record higher-priority user overrides separately; another checkout's policy
does not establish the contract future consumers of this PR will read.

Use **final mode** by default. If the user explicitly asks for a quick review,
use a bounded fast mode that still checks both axes but reports only verified,
high-confidence findings within the requested time/scope budget. Do not present
fast mode as final approval.

### 2. Identify the spec source

Look for the originating spec, in this order:

The user's requirements and PR description are valid acceptance sources. Use
available conversation context rather than asking for the same brief again.

1. References in commit messages. Resolve explicit URLs and provider-qualified
   identifiers through their originating provider. Use the configured Redmine
   tracker for unqualified internal ticket references. A GitHub PR or issue
   number and a GitLab merge request such as `!67` are not Redmine ticket IDs;
   establish provenance before fetching an ambiguous reference.
2. A path the user passed as an argument.
3. A PRD/spec file under `docs/`, `specs/`, or `.scratch/` matching the branch name or feature.
4. If nothing is found, ask the user where the spec is. If they say there isn't one, the **Spec** sub-agent will skip and report "no spec available".

Collect the complete acceptance record, not only requirement prose: ticket
journals, PR description, linked reports and measurements, accepted ADR
revisions, active configuration/profile, and explicit ticket ownership for
deferred requirements. Record the product's compatibility policy; retained old
or legacy paths are findings unless the active specification requires them.

Follow linked accepted appendices to close the active normative contract. Keep
an explicit requirement/claim manifest with revision provenance; historical
transcripts are discovery leads rather than an unbounded mandatory review corpus.
Apply prohibitions to their named actor, operation, and evidence layer; a ban on
forged native evidence does not prohibit ordinary modeled unit inputs.

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
- For source-analysis policy, verify cfg/test classification in every consumer,
  including raw coverage and complexity inventories. For security, inspect actual
  alert results and configuration reachability, not only analyzer execution.

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

Keep reviewer output bounded and retrieve large reports separately. Resuming an
idle reviewer requires the scheduler operation that starts a turn; message
delivery alone may not execute work. A completion notification is insufficient:
require the files/requirements actually inspected and any omissions before
crediting a full review. Assign a live owner for the next phase.

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
accepted-decision, or acceptance-evidence change requires a fresh
closure review. Review fixes must be the smallest behavioral changes with
public-boundary regressions where possible and must not introduce unrelated
coverage debt.

An intermediate external-bot review does not replace the final local two-axis
review. If an opt-in bot reports that automatic review is disabled, use its
documented explicit review command and verify acknowledgement before waiting;
a mention or comment alone is not evidence that review started.

## Pre-flight

- [ ] Review was explicitly requested and the requested mode is stated.
- [ ] Git snapshot or native document identity, baseline, and spec revisions are pinned.
- [ ] Reviewer file/requirement coverage and omissions are explicit.
- [ ] Reviewers received compatibility policy, ownership, and acceptance evidence.
- [ ] Every finding has a source-backed disposition without collapsing the axes.
- [ ] Any merge verdict applies to the exact final head and current gate rollup.

## Why two axes

A change can pass one axis and fail the other:

- Code that follows every standard but implements the wrong thing → **Standards pass, Spec fail.**
- Code that does exactly what the issue asked but breaks the project's conventions → **Spec pass, Standards fail.**

Reporting them separately stops one axis from masking the other.
