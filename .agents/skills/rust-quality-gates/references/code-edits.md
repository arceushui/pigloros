# Code edits

Internal PiglorOS guidance. Apply the relevant lessons within the current task's
authorization and repository policy.

- **Use the repository edit tool for multi-line changes.** `sed` and inline rewrite scripts can corrupt source when a pattern or snapshot is stale. Prefer `apply_patch`, keep the change narrow, and inspect the diff immediately.

- **Restore a corrupted file from a known baseline before repairing it.** Preserve any intended changes first, then use a file-scoped restore and reapply the change with the edit tool. Never repair a damaged file by guessing at the original text.

- **Audit compile-facing public paths when Cargo must run remotely.** Trace every new integration-test import through the crate root, check edited scopes for helper-name shadowing, and inspect the complete namespace-facing diff. A public item inside a module is not necessarily exported from the crate root, and formatting cannot prove name resolution.

- **Removing an implementation does not remove its product claim.** After deleting code, search the README, examples, roadmap pages, and external documentation for stale promises and update or remove them.

- **Don't ship placeholder code.** `crps = brier_score` with a "placeholder for future" comment is speculative generality. Either implement it properly from a spec requirement, or don't add the field. Defer unsupported contracts explicitly.

- **Never add `#[allow(clippy::*)]` to suppress lints.** If clippy flags a pattern (e.g. `clippy::question_mark`, `clippy::match_like_matches_macro`), fix the code to match the idiomatic pattern instead of silencing the lint. Suppressing lints hides real design problems and is harder to maintain. For `needless_pass_by_value` on `fn store_err(e: E)`: use `impl From<E> for MyError` instead — it eliminates the fn entirely, works as a `map_err` function item, and keeps the port definition clean.

- **Respect domain boundaries in imports.** Port definitions (e.g. `store.rs` / `LedgerStore`) must not import adapter-specific types from other crates. If an adapter needs a `From<E>` impl, put it in the adapter file (e.g. `event_store.rs`), not in the port. If a type feels missing from the port, consider whether it's a genuine port concept or an adapter detail.

- **Sanitize authenticated subprocess failures at the boundary.** Raw exceptions, arguments, and inherited stderr can leak credentials even when application logging is careful. Capture streams explicitly, sanitize at the request boundary, and test with a fake credential and a forced timeout.

- **Rotate exposed credentials.** If a secret is exposed, tell its owner and require rotation without echoing the value.

- **Rebind hosted formatter hunks to the current source.** After items moved, a formatter diff from CI is tied to the old snapshot: resolve each hunk's full context uniquely against the current file, reject missing or ambiguous contexts, apply in current source order, and verify the complete diff instead of replaying old line numbers.

- **Preserve lifetimes and failure order when extracting a stateful read.** Record resource ownership and drop order, snapshot scope, fallible-operation order, and accounting checkpoints before choosing a helper shape; a returned fact must not release a resource the caller still needs.

- **Remove obsolete private wrappers after context propagation.** Enumerate old and new helper callers across production, tests, and every feature configuration (including no-default-features); keep wrappers at live public or still-used boundaries, otherwise remove them or gate them to their real consumers, let owner tests supply an ordinary context, and never add a lint suppression or production call just to keep one alive.
