# Test & coverage policy

Shared reference for humans and agents. `.cursor/rules/test-policy.mdc` mirrors this in-repo.

## Rules

1. Prefer not adding `#[ignore]`. If present, CI still runs it via `--include-ignored`.
2. **Never** put `coverage(off)` on production code — only on `#[test]` / `#[tokio::test]` or inside `#[cfg(test)]`.
3. Prefer deleting/simplifying unhittable branches over exemptions.
4. Do not use rustdoc ` ```ignore ` fences — use ` ```text ` or a real doctest.
5. Pull requests recognized as documentation-only by `.github/rust-scope.yml` skip Rust test, coverage, and cargo-crap jobs; Rust-affecting changes retain those gates.

## Enforcement

| Layer | Tool | Notes |
|---|---|---|
| Attrs / doctests | Trunk `rust-test-policy` | `coverage(off)` test-only; bans ` ```ignore ` |
| Git hook | Versioned repository pre-commit runs Trunk `rust-test-policy`, then regenerates/stages `Cargo.lock` for manifest changes | Run once per clone: `git config core.hooksPath .githooks` |
| Runtime | `cargo test -- --include-ignored` | Ignored tests still execute |
| Summary check | `scripts/assert-no-ignored-in-test-summary.sh` | Matches `test result:` line only (no log prose FP) |
| Coverage | `cargo llvm-cov` with `--include-ignored` | At least 99% lines + 99% regions for Rust-affecting changes |
| Change risk | `cargo-crap` over the hosted LCOV report | Existing function scores must not regress; new functions must score at most 30 for Rust-affecting changes |
| Dependencies | **cargo-deny** | Crates/licenses/advisories/sources only |

## Coverage attribution policy

The 99% line / 99% region floor allows for LLVM coverage regions that cannot be
mapped to a source line or segment after a fresh non-root run. It is a
reporting-tolerance only: all tests still run with `--include-ignored`, and
`coverage(off)` remains test-only. Do not use the allowance to exempt
production code or avoid writing a reachable behavior test.

## Change-risk policy

For Rust-affecting changes, the hosted coverage job publishes its completed
LCOV report to a separate, required `cargo-crap` check running pinned v0.2.2.
Documentation-only pull requests skip both jobs. The verdict uses zero
tool tolerance and treats one IEEE-754 representation step (one ULP) as
numerical equality; every larger score increase fails, including increases on
moved functions. Every new function must score at most 30. Standard Cargo
integration-test, benchmark, and example directories are excluded from
complexity scoring; their execution still contributes coverage to production
code. Repository `.cargo-crap.toml` files are prohibited so a change cannot
suppress or truncate the report.

Each successful `main` workflow publishes a 90-day baseline artifact named for
its exact commit. A pull request downloads the artifact for its base SHA, so
newly merged functions become existing baseline entries on the next change.
The pull request job polls for the artifact for up to five minutes to cover the
short interval while the corresponding `main` workflow is still finishing. If
that trusted artifact has expired or the base never completes green CI, the
pull request must rebase onto a green `main` commit.

PR #58 has one explicit initialization exception for pre-gate base
`45bdac85b29d273573583f846ba7acd2b3a12573`: only when no Rust, Cargo, toolchain,
or cargo-crap configuration input changed may the hosted job generate the
baseline directly from the same LCOV artifact. No other base SHA can use this
path. The gate treats missing coverage pessimistically and bounds source
analysis to two threads.

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

## Resource-intensive sanitizer jobs

The complete workspace ASan gate retains all features and test targets, but
partitions their execution across four hosted shards because Cargo runs separate
test executables serially. The `bundle-coverage` and `bundle-public` shards run
the two `pos-conformance` bundle integration targets independently. The
`moat-proof` shard runs the slow moat integration target independently, while
`remainder` runs `--workspace --exclude pos-conformance --tests`, then the
`pos-conformance` library, binaries, and the profile/provider integration
targets. Each shard serializes Cargo build/link jobs and bounds test threads at
two. The required
`asan (address sanitizer)` aggregate runs with `always()` and succeeds only when
every shard succeeds. Partitioning reduces wall-clock time by repeating setup
and build work on independent runners; it does not remove a package, feature,
test target, sanitizer, or coverage requirement. ASan plus
`build-std` produces unusually large test-binary links; concurrent lld workers
can exhaust the runner's available resources and crash with `SIGBUS` before any
test executes.

The job uses the dated `nightly-2026-07-01` toolchain rather than a floating
nightly. The 2026-08-07 nightly (`rustc 1.99.0-nightly`) crashed its bundled
lld with `SIGBUS` both with concurrent links and after Cargo serialization,
before any test executed. The available pinned Rust 1.98 nightly candidate
makes the sanitizer toolchain reproducible and avoids silently adopting that
linker; a fresh remote run must still prove the candidate and complete gate.

The dated candidate reached a definitive hosted-runner failure annotation:
`No space left on device`. ASan did not report a product defect, and no test
failed. The pinned toolchain action already exported `CARGO_INCREMENTAL=0` in
the failed run, so the explicit step setting policy-locks existing behavior; it
is not credited as a new size reduction. The new candidate is the test profile's
`line-tables-only` debuginfo, which Cargo documents as retaining filename/line
backtraces without full type and variable metadata. This changes artifact size
only; sanitizer instrumentation, debug assertions, packages, features, test
targets, and execution scope remain.

`scripts/check-asan-ci-policy.sh` enforces the exact shard matrix, target
partition, per-shard resource settings, fail-closed aggregate, and complete
ASan scope by parsing the workflow's executable YAML semantics. Adversarial
fixtures prove that disabled/non-failing steps, environment-based test runners,
detached sanitizer flags, `--no-run`, shell success overrides, skipped
prerequisites, injected setup steps, and test-skip arguments are rejected. The
ASan job graph and pinned setup-step sequence must match exactly, and each test
step may contain only `name`, `env`, and `run` so it cannot select a nested
Cargo configuration.

### Controlled Bevy reflection metadata roots

ADR-018 authorizes exactly two anchored LeakSanitizer templates for Bevy
0.19's deliberate application-lifetime `GenericTypeCell` metadata caches:
`TypeInfo` and `TypePathComponent`. The suppression file may contain only
those two exact lines; a broader `GenericTypeCell<*>` wildcard is forbidden.
The production policy checker locks the file's exact bytes. Runtime output may
contain zero or more process-local suppression tables. Every emitted row must
match one approved template and have positive counters; repeated rows across
different process tables are aggregated only for diagnostics. Root and byte
counts are not cross-run invariants because LSan evaluates reachability and
records matched suppressions separately in each test process.

The complete workspace/all-features/all-test-target ASan scope and
`detect_leaks=1` remain unchanged across the four shards. A separate 1,234-byte
intentional leak runs under the same sanitizer, symbolizer, suppression file,
and options; it must exit nonzero, report exactly one allocation, and match
neither approved rule.
Any unexpected or malformed suppression row/table, duplicate template within
one process table, zero measurement, unrelated leak, or negative-control
success fails CI. Bevy, Rust nightly, LLVM, sanitizer, or runner-image upgrades
require an unsuppressed audit and removal review for both rules.

## Local setup

```bash
# One-time per clone (enables the versioned pre-commit hook):
git config core.hooksPath .githooks

# Full CI parity:
./scripts/ci.sh
```

## cargo-deny ≠ source attributes

`cargo-deny` cannot ban `#[ignore]` or `coverage(off)`. Those are covered by Trunk + runtime flags above.
