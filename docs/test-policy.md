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
| Coverage | `cargo llvm-cov` with `--include-ignored` | At least 99% lines + regions |
| Dependencies | **cargo-deny** | Crates/licenses/advisories/sources only |

## Coverage attribution policy

The 99% line-and-region floor allows for LLVM coverage regions that cannot be
mapped to a source line or segment after a fresh non-root run. It is a
reporting-tolerance only: all tests still run with `--include-ignored`, and
`coverage(off)` remains test-only. Do not use the allowance to exempt
production code or avoid writing a reachable behavior test.

## Hardware-dependent startup

Portable unit and coverage jobs must not require a physical GPU, display server,
audio device, or other host hardware. Tests still execute the public startup
path, but hardware adapters must use the framework's supported headless or
no-device configuration under `cfg(test)`. This is not a skipped test or a
coverage exemption: production code remains instrumented, the package/build
gate compiles the production adapter, and a real-device integration gate must
exercise behavior where CI can provide that device.

For the Bevy world client, unit/coverage builds retain `DefaultPlugins` while
using Bevy's documented no-renderer `WgpuSettings { backends: None }` setup and
disabling Winit. The optimized WASM package gate compiles the full production
renderer, and browser parity executes in real headless Chrome. Native GPU
device creation itself is not portable on GitHub's hosted GPU-less runners.

## Local setup

```bash
# One-time per clone (enables Trunk-managed hooks):
trunk git-hooks sync

# Full CI parity:
./scripts/ci.sh
```

## cargo-deny ≠ source attributes

`cargo-deny` cannot ban `#[ignore]` or `coverage(off)`. Those are covered by Trunk + runtime flags above.
