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
