# Test & coverage policy

Shared reference for humans and agents. `.cursor/rules/test-policy.mdc` mirrors this in-repo.

## Rules

1. Prefer not adding `#[ignore]`. If present, CI still runs it via `--include-ignored`.
2. **Never** put `coverage(off)` on production code — only on `#[test]` / `#[tokio::test]` or inside `#[cfg(test)]`.
3. Prefer deleting/simplifying unhittable branches over exemptions.
4. Do not use rustdoc ` ```ignore ` fences — use ` ```text ` or a real doctest.

## Enforcement

| Layer | Tool | Notes |
|---|---|---|
| Attrs / doctests | Trunk `rust-test-policy` | `coverage(off)` test-only; bans ` ```ignore ` |
| Git hooks | Trunk pre-commit / pre-push | Run once per clone: `trunk git-hooks sync` |
| Runtime | `cargo test -- --include-ignored` | Ignored tests still execute |
| Summary check | `scripts/assert-no-ignored-in-test-summary.sh` | Matches `test result:` line only (no log prose FP) |
| Coverage | `cargo llvm-cov` with `--include-ignored` | 100% lines + regions |
| Dependencies | **cargo-deny** | Crates/licenses/advisories/sources only |

## Local setup

```bash
# One-time per clone (enables Trunk-managed hooks):
trunk git-hooks sync

# Full CI parity:
./scripts/ci.sh
```

## cargo-deny ≠ source attributes

`cargo-deny` cannot ban `#[ignore]` or `coverage(off)`. Those are covered by Trunk + runtime flags above.
