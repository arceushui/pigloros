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

6. **100% regions is a known LLVM limitation.** Trait default methods create unmappable regions. Accept 99.99% regions (1 LLVM artifact out of 8900+). Lines and functions can and must be 100%. CI uses `--fail-under-regions 99`.

7. **Coverage rule: delete, don't exempt.** If new code can't be covered by a test, remove the code — don't use `coverage(off)` on production code.

8. **Run all quality gates after EVERY change.** Including after code review fixes. `cargo test`, `cargo clippy`, `cargo llvm-cov`. No exceptions.

## Redmine

9. **ADR wiki pages use Markdown, not Textile.** Use `## Heading` not `h2. Heading`. Match the style of ADR-011: `**Status:** Accepted | **Wave:** ...` header, `---` separator, `## Context`, etc.

10. **ADR tracker workflow is broken.** No allowed transitions from "Proposed" status. ADR issues can't be closed via API or UI. To close an ADR via API: switch it to Feature tracker (tracker_id=2), then close (status_id=5).

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
