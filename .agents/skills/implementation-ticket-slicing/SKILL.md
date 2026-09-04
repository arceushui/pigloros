---
name: implementation-ticket-slicing
description: Decompose implementation tickets under an epic into the smallest independently reviewable code changes after inspecting the existing codebase, then keep each PR narrowly scoped.
---

# Implementation Ticket Slicing

Use this skill whenever an implementation ticket belongs to an epic or a larger feature. The goal is a sequence of small, mergeable changes that follows the existing architecture and avoids a large file or cross-module rewrite in one PR.

## Code-first decomposition

Before proposing or implementing a ticket:

1. Read the repository context, project overview, applicable ADRs/specifications, and the relevant existing tests.
2. Inspect the actual code paths, public seams, callers, persistence/schema boundaries, and nearby history. Do not split work from the ticket prose alone.
3. Map the change surface: files, modules, interfaces, tests, migrations, and dependency edges. Identify whether the work is a vertical behavior slice or a mechanical wide refactor.
4. Find the thinnest slice of the final architecture that can compile, be tested through a public seam, and be reviewed independently. Prefer a useful vertical slice over a horizontal layer-only change.
5. Split follow-up tickets wherever a slice would otherwise require unrelated behavior, several independent seams, multiple large files, or a speculative compatibility path.

Do not create artificial micro-PRs that cannot stand on their own. A slice is appropriately sized when its acceptance criteria are coherent, its blocking edges are explicit, and its diff can be understood without loading the whole epic.

## Ticket and PR contract

The inspection record should map the concrete files, modules, interfaces, tests, migrations, and dependency edges. Each published implementation ticket should state:

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

After each code change, run the project’s required quality gates, including formatting, workspace tests with ignored tests included, pedantic Clippy, and the 99% LLVM line/region coverage gate. If a new branch cannot be covered, simplify or remove it rather than exempting production code. If local resource constraints prevent a gate, record the limitation and use the repository’s equivalent hosted gate; do not weaken the threshold.

Before opening the PR, inspect `git diff --stat` and the full diff against the fixed point. Confirm that every changed file belongs to the ticket, the PR description names the delivered seam and follow-up tickets, and the acceptance evidence is reproducible. Commit from the isolated worktree before removing it. Request a separate code review only when that review workflow has been explicitly authorized.

## Consolidated project learning

This skill incorporates the recurring lessons that most directly prevent oversized implementation work:

- inspect before splitting; “make the change easy, then make the easy change” is a design step, not permission for an unbounded refactor;
- preserve domain boundaries and put adapter-specific behavior in adapters;
- prefer iterator-based public APIs and avoid speculative generality;
- treat coverage as a design signal: delete untestable production paths and make subprocess evidence deterministic before changing thresholds;
- keep expensive validation attributable and avoid duplicating expensive deterministic work in hooks or CI; and
- keep review evidence tied to the authoritative worktree, fixed point, and exact revision under review.

When later work reveals a repeatable decomposition failure, update this skill with the generalized lesson rather than accumulating a one-off ticket note.

## Final verification

Before delivering the ticket or PR, perform one final pass against the rules above. Check the code-first inspection record, scope boundary, blocking edges, diff size/file spread, test evidence, quality-gate results, and worktree isolation. Do not call the slice complete while any of these is unresolved.
