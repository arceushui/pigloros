---
name: lessons-learned
description: Anti-patterns and mistakes to avoid when working on this project. Read before starting any implementation.
disable-model-invocation: true
---

# Lessons Learned

Mistakes made during pigloros development sessions. Read before coding.

## Commits and worktrees

1. **Never `git add -A`.** It stages everything including skills files with pre-existing yamllint issues, stray config files (`opencode.json`, `skills-lock.json`). Stage only the files you changed: `git add path/to/changed/file.rs`.

2. **Worktree changes can be lost.** When a worktree is force-removed, uncommitted changes in it are gone. Commit from the worktree before removing it. Push from the worktree, then merge into main from the main checkout.

3. **`git reset` can lose your staging.** If you `git reset HEAD .agents/` then `git add specific files`, make sure the files you're adding are the ones with actual changes. If a file was already committed, `git add` won't re-stage it.

## Code edits

4. **Never use sed for multi-line code changes.** sed corrupts source files when the pattern doesn't match exactly. Python inline scripts are safer for batch operations. For single-file edits, always use the edit tool.

5. **Use restore when sed corrupts a file.** `git checkout -- path/to/file.rs` restores to HEAD. Don't try to manually fix sed corruption.

## Coverage

6. **`?` operator creates uncoverable LLVM sub-regions.** Replace `?` in production hot paths with `.map()`, `.and_then()`, or `.ok().flatten()` combinators — they propagate errors without creating sub-region artifacts that LLVM can't track. Similarly, `matches!()` in assertions creates macro-internal sub-regions; use `.to_string().contains()` for type-safe pattern checks in test contracts. CI requires 99% line and region coverage; the 1% tolerance is only for source-unmappable LLVM regions after a fresh non-root run.

7. **Coverage rule: delete, don't exempt.** If new code can't be covered by a test, remove the code — don't use `coverage(off)` on production code.

8. **Run all quality gates after EVERY change.** Including after code review fixes. `cargo test`, `cargo clippy`, `cargo llvm-cov`. No exceptions.

## Redmine

9. **Must invoke `start-work` skill when beginning work on any Redmine ticket.** This sets the ticket to In Progress and records all work as journal notes. Never start work without it.

10. **ADR wiki pages use Markdown, not Textile, and MUST have `ADR` as their parent page.** See the `adr-wiki` skill for full rules on hierarchy, formatting, and API usage.

11. **ADR tracker workflow is broken.** No allowed transitions from "Proposed" status. ADR issues can't be closed via API or UI. To close an ADR via API: switch it to Feature tracker (tracker_id=2), then close (status_id=5).

11. **Close completed issues after every commit.** Use the correct status:
    - **Feature / Bug / Task** → `Resolved` (status_id=3), NOT Closed
    - **ADR** → `Accepted` (status_id=9), flow: Proposed→Under Review→Accepted
    - Only use Closed (status_id=5) for rejected or superseded issues

## Redmine ADR workflow setup (one-time admin fix)

The ADR tracker (id=5) has zero allowed transitions from its default status "Proposed" (id=7). Until this is fixed, ADRs cannot be accepted/closed. Here's the fix:

1. Go to your Redmine instance: `https://redmine.piglor.com`
2. Navigate to **Administration** → **Workflow** → **Status transitions**
3. Select **Tracker: ADR** and **Role: Manager** (and Developer)
4. Click **Edit**
5. For row "Proposed" (status 7), check these columns:
   - **Under Review** (status 8)
   - **Accepted** (status 9)
   - **Rejected** (status 6)
6. For row "Under Review" (status 8), check:
   - **Accepted** (status 9)
   - **Rejected** (status 6)
7. Click **Save**
8. Repeat for Developer role (role_id=4) if developers should manage ADRs

After this, ADRs can follow the flow: `Proposed → Under Review → Accepted / Rejected`. The API will also work for these transitions.

## Design

12. **Leave-one-out for per-entity baselines.** When computing entity-specific metrics, exclude the current observation from the historical baseline. Otherwise single-observation entities get perfect scores.

13. **Prefer iterators over owned collections in API.** `fn plugin_names() -> impl Iterator<Item = &str>` is consistent. `fn plugin_versions() -> HashMap<String, String>` is not.

14. **Don't ship placeholder code.** `crps = brier_score` with a "placeholder for future" comment is speculative generality. Either implement it properly from a spec requirement, or don't add the field.

15. **Never add `#[allow(clippy::*)]` to suppress lints.** If clippy flags a pattern (e.g. `clippy::question_mark`, `clippy::match_like_matches_macro`), fix the code to match the idiomatic pattern instead of silencing the lint. Suppressing lints hides real design problems and is harder to maintain. For `needless_pass_by_value` on `fn store_err(e: E)`: use `impl From<E> for MyError` instead — it eliminates the fn entirely, works as a `map_err` function item, and keeps the port definition clean.

16. **Respect domain boundaries in imports.** Port definitions (e.g. `store.rs` / `LedgerStore`) must not import adapter-specific types from other crates. If an adapter needs a `From<E>` impl, put it in the adapter file (e.g. `event_store.rs`), not in the port. If a type feels missing from the port, consider whether it's a genuine port concept or an adapter detail.

## Code review

17. **Always request code review after completing code changes, before starting new work.** Use the `code-review` skill with the appropriate fixed point (e.g. `main..HEAD` or a prior commit). Address all findings as a separate round of fixes, then let the reviewer confirm before moving to the next task. Do not start new tickets until the current review cycle is closed.

## CI / GitHub Actions

18. **Every test type must run in CI — no local-only tests.** GitHub Actions (`.github/workflows/ci.yml`) is the single source of truth for what passes. When adding any test — unit test, integration test (`tests/` directory), doctest, or `#[ignore]`d test — verify that `cargo test --workspace --locked -- --include-ignored` in the `test` job actually executes it. The `--include-ignored` flag is mandatory so `#[ignore]` cannot silently skip. If you write an integration test that lives in `tests/`, it MUST be picked up by the workspace test job; if it isn't, the test is dead and the CI green light is a lie. Before claiming a ticket is done, name the CI job/steps that run your new test.

19. **GitHub Actions workflow `name:` must be lowercase-with-hyphens.** All workflow YAML files under `.github/workflows/` must use the same naming convention: lowercase words separated by hyphens (e.g. `name: ci`, `name: cargo-deny`, `name: deploy`, `name: trunk-check`). No PascalCase (`Deploy`, `Trunk Check`), no ALLCAPS. This keeps the Actions sidebar predictable and sortable.

20. **Keep ADR version scope separate from implementation scope.** The current product implementation is V1, but an ADR may legitimately document future V2/V3 evolution. Track whether a decision applies now or is deferred independently from its version label; do not rewrite valid future-version design as current behavior, and do not call current V1 work V2 merely because the ADR discusses later evolution.

## Compiled lessons from task-observation history

The following lessons consolidate recurring observations from project work. Keep this file as the single tracked lessons-learned document; the raw observation history remains an agent-workflow record.

### Delivery and authority

- Define completion by the requested end-state: committed worktree, pushed branch, passing pull-request checks, merged target branch, post-merge workflows, and tracker/release state as applicable. Local code and a green local test run are not delivery by themselves.
- Reconcile the repository, Redmine, Notion, GitHub, roadmap, and worktree before reporting project stage. If sources disagree, name the conflict instead of silently choosing one.
- Removing an implementation does not remove the product claim around it. Search code, README, examples, roadmap pages, and external docs after deletions.
- Keep ADR status, implementation authorization, ticket status, evidence readiness, and product acceptance separate. An Accepted ADR records a decision; it does not start implementation.
- Preserve the hierarchy between Wave, milestone design, ADR, implementation ticket, and subtask. Use Redmine parent/child for decomposition and blocker relations for execution order between independent tickets.

### Acceptance and evidence

- State acceptance criteria separately from evidence. Every claim needs an audience, boundary, pass/fail condition, authoritative artifact, schema owner, evaluator, maturity, and remaining gate.
- Metadata, fixture IDs, digests, or screenshots do not prove behavior. Mandatory conformance cases must execute through the public boundary, and equality claims must bind to independently produced outputs.
- Keep host evidence, evaluator validation, independent reproduction, and authorship/organizational independence as distinct fields.
- Use the smallest deterministic fixture that proves the claim. Do not strengthen domain semantics merely because a fixture makes a stronger statement convenient.
- Separate computational Replay from empirical/world-model validity, general world evidence from Persona calibration, and route-level security enforcement from future architecture.

### Hosted CI and quality gates

- Treat hosted CI as an independent environment probe. Permission, process identity, ordering, cache, target, and runner behavior can differ from a root local checkout.
- For workflow changes, run a canary pull request, inspect every hosted job, fix failures in the isolated worktree, require a clean ruleset, merge, and verify the post-merge `main` workflows.
- Compile documentation explicitly with rustdoc warnings denied. Compiler, test, and Clippy success do not validate rustdoc links.
- Every test type must execute in CI, including integration tests, doctests, and ignored tests covered by policy. A test outside the workspace job is not evidence.
- Use explicit sanitizer-compatible fuzz targets and include every manifest that can affect an isolated workspace in path filters.
- Make informational jobs cancellation-safe. Avoid `always()` steps that hold replacement runs in a concurrency group.
- Keep path-filtered fuzz and mutation checks advisory unless an always-emitted aggregator represents skipped work safely; do not confuse scheduled/manual ThreadSanitizer with a universal PR gate.

### Coverage, lint, and interfaces

- Coverage thresholds are design constraints: remove dead or uncoverable production branches instead of exempting them, and keep `coverage(off)` test-only.
- Rust constructs and macros can create difficult LLVM regions; choose equivalent idiomatic forms deliberately when coverage evidence requires it.
- Never suppress Clippy to hide design problems. Prefer fallible test functions, idiomatic code, and diff-level suppression guards.
- Keep ports independent from adapter-specific types, and keep dependencies behind the correct seam. Prefer iterator-returning APIs when callers only need traversal.
- Do not ship placeholder calculations, speculative fields, or future behavior disguised as current implementation. Defer unsupported contracts explicitly.

### Product and roadmap communication

- Map every objective and competitor insight to a primary Wave, supporting Wave, user-visible acceptance gate, and named evidence. Strategy is not operational until it points to proof.
- A Living Overview explains current product truth, not agent process history. Lead with user value; put exclusions, review transcripts, and execution detail in their proper pages.
- Use one dominant reading path with a visible current position and next step. Use diagrams for sequence and transformation, tables for exact mappings, and child pages at the moment deeper detail is useful.
- Keep current landscape pages distinct from dated update archives and evidence reports. Separate evidence, inference, roadmap implication, and “not evidenced” claims.
- Examples should clarify without accidentally narrowing a general product to one market. First-impression reviews should distinguish intrigue, comprehension, operational clarity, willingness to try, and willingness to trust.

### Notion, diagrams, and external documentation

- Treat Mermaid code as literal: do not apply rich-text escaping inside code fences, use `<br>` for label breaks, and quote labels containing special characters.
- In Notion tables, use native Markdown links or plain text; do not place raw HTML anchors or block-level markup in cells.
- A child-page creation can append a structural `<page>` block to its parent. Fetch the live parent, remove the generated block, reinsert it at the intended index position, and fetch parent and child after the write. Use `<mention-page>` or Markdown links for inline references.
- After delegated or external documentation edits, fetch the canonical saved text and verify schemas, links, parent hierarchy, authority markers, vocabulary, and maturity claims. A success summary is not read-back evidence.

### Execution modes and terminology

- Keep Local/Connected, Air-Gapped, Deterministic, and Live Exploration separate. Deployment locality, network permission, and reproducibility are independent axes.
- Use the project glossary exactly: **Timeline**, **Fork**, **PersonaModel**, **Society Signal**, **Brier Score**, and **Calibration Report** carry defined meanings and should not be replaced by looser synonyms.

### Safe records and handoff

- Shared append-only logs need collision-aware numbering: read the live file, assert the next number is unused, append, then verify count, uniqueness, and survival.
- Stage only files changed for the task. Before destructive cleanup or external mutation, re-check ownership, current state, and exact targets at the mutation boundary.
- Before handoff, review the diff, run required gates, request independent review for code changes, verify hosted and post-merge state, read back external records, confirm clean worktrees, and report advisory risks honestly.
