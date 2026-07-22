#!/usr/bin/env bash
# Local parity with GitHub Actions (Redmine #100 + Trunk Check).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> trunk check"
if command -v trunk >/dev/null 2>&1; then
  trunk check --all --ci --no-progress
else
  echo "WARNING: trunk not on PATH; skipping (install: curl https://get.trunk.io | bash)"
fi

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
