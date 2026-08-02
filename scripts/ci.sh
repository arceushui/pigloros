#!/usr/bin/env bash
# Local parity with GitHub Actions (Redmine #100 + Trunk Check).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> trunk check (rust-test-policy: coverage(off) test-only; no ignore doctest fences)"
if command -v trunk >/dev/null 2>&1; then
  trunk check --all --ci --no-progress
else
  echo "WARNING: trunk not on PATH; running scripts/check-test-policy.sh fallback"
  bash "$ROOT/scripts/check-test-policy.sh"
fi

echo "==> pinned dependency policy"
bash "$ROOT/scripts/check-pinned-dependencies.sh"
bash "$ROOT/scripts/test-check-pinned-dependencies.sh"

echo "==> cargo deny (dependency policy)"
if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny --locked check
else
  echo "WARNING: cargo-deny not on PATH; skipping (install: cargo install cargo-deny)"
fi

echo "==> fmt"
cargo fmt --all -- --check

echo "==> test (--include-ignored)"
# Run ignored tests too so #[ignore] cannot silently skip a path.
test_log="$(mktemp)"
trap 'rm -f "$test_log"' EXIT
cargo test --workspace --locked -- --include-ignored 2>&1 | tee "$test_log"
bash "$ROOT/scripts/assert-no-ignored-in-test-summary.sh" "$test_log"

echo "==> clippy"
cargo clippy --workspace --all-targets --locked -- -D warnings -W clippy::pedantic

# 99% coverage floor: production code is fully instrumented (coverage(off) is test-only).
# Unnecessary code is deleted/simplified rather than left as dead branches.
echo "==> coverage (99% lines + regions)"
export RUSTC_BOOTSTRAP=1
cargo llvm-cov --workspace --locked --summary-only \
  --fail-under-lines 99 \
  --fail-under-regions 99 \
  -- --include-ignored

echo "==> CI gates OK"
