#!/usr/bin/env bash
# Local parity with .github/workflows/ci.yml (Redmine #100).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> fmt"
cargo fmt --all -- --check

echo "==> test"
cargo test --workspace --locked

echo "==> clippy"
cargo clippy --workspace --all-targets --locked -- -D warnings -W clippy::pedantic

# 100% coverage requirement: production code is fully instrumented (coverage(off) is test-only).
# Unnecessary code is deleted/simplified rather than left as dead branches.
echo "==> coverage (100% lines + regions)"
export RUSTC_BOOTSTRAP=1
cargo llvm-cov --workspace --locked --summary-only \
  --fail-under-lines 100 \
  --fail-under-regions 100

echo "==> CI gates OK"
