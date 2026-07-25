---
name: implement
description: "Implement a piece of work based on a spec or set of tickets."
disable-model-invocation: true
---

Implement the work described by the user in the spec or tickets.

Use /tdd where possible, at pre-agreed seams.

## Quality gates (run after EVERY code change)

After every change — including after code review fixes — run the full suite:

```bash
cargo test --workspace --locked -- --include-ignored    # all tests, 0 failures
cargo clippy --workspace --all-targets --locked -- -D warnings -W clippy::pedantic
RUSTC_BOOTSTRAP=1 cargo llvm-cov --workspace --locked --summary-only \
  --fail-under-lines 100 --fail-under-regions 100 -- --include-ignored
```

If any gate fails, fix it before moving on. Do NOT skip gates — not even for "trivial" changes or after code review.

**Coverage rule:** If new code cannot be covered by a test, **remove it** — do not leave dead code. Prefer deleting/simplifying untestable branches over exemptions or `coverage(off)`.

Once done, use /code-review to review the work, then re-run gates after applying review fixes.

Commit your work to the current branch.
