---
name: implementation-ticket-slicing
description: Decompose implementation tickets under an epic into the smallest independently reviewable code changes after inspecting the existing codebase, then keep each PR narrowly scoped.
---

# Implementation Ticket Slicing

Use this skill whenever an implementation ticket belongs to an epic or a larger feature. The goal is a sequence of small, mergeable changes that follows the existing architecture and avoids a large file or cross-module rewrite in one PR.

## Code-first decomposition

Before proposing or implementing a ticket:

0. If the user authorized starting, resuming, or implementing an identified Redmine ticket, invoke `start-work` first. For read-only planning or review, do not mutate ticket status; follow `start-work` to identify the provider and ticket.
1. Read the repository context, project overview, applicable ADRs/specifications, and the relevant existing tests.
2. Inspect the actual code paths, public seams, callers, persistence/schema boundaries, and nearby history. Do not split work from the ticket prose alone.
3. Map the change surface: files, modules, interfaces, tests, migrations, and dependency edges. Identify whether the work is a vertical behavior slice or a mechanical wide refactor.
4. Find the thinnest slice of the final architecture that can compile, be tested through a public seam, and be reviewed independently. Prefer a useful vertical slice over a horizontal layer-only change.
5. Split follow-up tickets wherever a slice would otherwise require unrelated behavior, several independent seams, multiple large files, or a speculative compatibility path.

Do not create artificial micro-PRs that cannot stand on their own. A slice is appropriately sized when its acceptance criteria are coherent, its blocking edges are explicit, and its diff can be understood without loading the whole epic.

Before publishing another ticket, search existing ownership and reconcile
overlapping scope. Keep a delegated slice callable through its authority and
consumer seams; do not separate an implementation from the wiring needed to make
it valid. Slicing changes the review unit, not the whole-ticket delivery scope.
Include genuine proof-bearing fixture migration and replacement-contract tests
in the corresponding slice.

Map file ownership across stacked slices before building them. Prefer disjoint
modules or seams; central registries and manifests need an explicit owner. When
shared-file edits are unavoidable, document the overlap and land the prerequisite
before building its dependent slice where practical. Do not add speculative
entries merely to avoid a later conflict. A squash merge alone does not guarantee
a conflict; inspect actual ancestry and edits.

## Ticket and PR contract

The inspection record should map the concrete files, modules, interfaces, tests, migrations, and dependency edges. Each published implementation ticket should state:

- the existing project hierarchy and the correct Redmine relation type for each decomposition or execution dependency; keep Wave, milestone design, ADR, implementation ticket, and subtask distinct, use parent/child relations for decomposition, and use blocker relations only for execution order between independent tickets;
- the end-to-end behavior or seam it delivers;
- explicit in-scope and out-of-scope work;
- the stable architectural areas, public seams, and blast radius found during inspection; keep exact file paths in the transient inspection record rather than the published ticket;
- acceptance tests at the public interface;
- genuine blockers and the dependency order; and
- the expected narrow PR boundary, including a warning when a proposed change would touch a large file or many unrelated modules.

When this skill is used with `to-tickets`, follow `to-tickets` for the published-ticket format and its rule to avoid specific file paths. The code inspection still happens first; its file-level findings guide the split without becoming brittle ticket text.

For wide mechanical refactors, use an expand–migrate–contract sequence. Keep the old and new forms compatible during migration, batch call-site changes by a bounded area, and remove the old form only after all callers have moved. Do not disguise a broad refactor as one feature ticket.

## Implementation pre-flight

Before coding, re-read this checklist and confirm:

- the code inspection identified the real seam and the smallest viable slice;
- the ticket has no hidden unrelated work;
- the change does not introduce a new crate, plugin, binary, durable public API, dependency, storage/security boundary, protocol, or coordinate model without the required architecture decision;
- tests exercise public behavior rather than implementation details; and
- the worktree and branch are isolated from `main`.

During implementation, keep the diff aligned with the ticket. Never use `git add -A`; stage only files changed for this slice. Do not add placeholder code, speculative fields, dead branches, or lint suppressions merely to complete the shape of a future ticket.

After each change, verify the gates applicable to its language, artifact, and
scope. Documentation-only paths selected by `.github/rust-scope.yml` skip Rust
build, test, coverage, and cargo-crap jobs while retaining required documentation
and policy checks. For Rust-affecting changes, use
[rust-quality-gates](../rust-quality-gates/SKILL.md) for exact-head hosted
evidence, ignored-test inclusion, and the 99% line/region floors. Keep repository
hooks and do not run manual local Cargo validation. Simplify or remove
uncoverable new code instead of exempting it.

Before opening the PR, inspect `git diff --stat` and the full diff against the fixed point. Confirm that every changed file belongs to the ticket, the PR description names the delivered seam and follow-up tickets, and the acceptance evidence is reproducible. Commit from the isolated worktree before removing it. Use `code-review` for explicitly requested review with a fixed point and independent Standards and Spec axes; address findings and re-review the resulting exact head. Independent review is required before merge under repository policy. A conflict-free PR or passing subset of checks is not merge readiness.

## Consolidated project learning

This skill incorporates the recurring lessons that most directly prevent oversized implementation work:

- inspect before splitting; “make the change easy, then make the easy change” is a design step, not permission for an unbounded refactor;
- preserve domain boundaries and put adapter-specific behavior in adapters;
- prefer iterator-based public APIs and avoid speculative generality;
- treat coverage as a design signal: delete untestable production paths and make subprocess evidence deterministic before changing thresholds;
- keep expensive validation attributable and avoid duplicating expensive deterministic work in hooks or CI; and
- keep review evidence tied to the authoritative worktree, fixed point, and exact revision under review.

When later work reveals a repeatable decomposition failure, record it as a candidate maintenance lesson rather than changing this skill during ordinary implementation. Update the skill only through a separately authorized maintenance ticket and pull request, with the generalized lesson replacing any one-off ticket note.

## Final verification

Before delivering the ticket or PR, perform one final pass against the rules above. Check the code-first inspection record, scope boundary, blocking edges, diff size/file spread, test evidence, quality-gate results, and worktree isolation. Do not call the slice complete while any of these is unresolved.
