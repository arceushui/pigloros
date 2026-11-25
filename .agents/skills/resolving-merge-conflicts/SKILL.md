---
name: resolving-merge-conflicts
description: "Use when you need to resolve an in-progress git merge/rebase conflict."
---

1. **See the current state** of the merge/rebase. Check git history, and the conflicting files.

2. **Find the primary sources** for each conflict. Understand deeply why each change was made, and what the original intent was. Read the commit messages, check the PRs, check original issues/tickets.

3. **Resolve each hunk.** Preserve both intents where possible. Where incompatible, pick the one matching the merge's stated goal and note the trade-off. Do **not** invent new behaviour.

4. Discover the project's **automated checks** and run them — typically typecheck, then tests, then format. Fix anything the merge broke.

5. **Finish the permitted operation.** Stage explicit task paths and inspect the
   complete result before committing. Do not rewrite a pushed branch or update it
   merely because `main` moved; follow `using-git-worktrees` and repository merge
   policy. For any authorized history replay, inventory merge-only resolutions
   and prove per-layer content preservation as well as live parent ancestry;
   replaying non-merge commits can silently lose real resolution changes.
   For an already authorized in-progress rebase, continue after resolving each
   conflict and repeat as needed until all remaining commits are applied. Confirm
   the operation has finished before reporting completion; this is not authority
   to begin a new rebase or rewrite a pushed branch.
