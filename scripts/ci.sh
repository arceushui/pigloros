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

# Honest floor: production code is fully instrumented (coverage(off) is test-only).
# Measured coverage is ~99.9% lines / ~99.7% regions; the floor below leaves headroom
# for a handful of infallible-in-practice error arms. See README for exact numbers.
echo "==> coverage (honest floor: lines + regions @ 99%)"
export RUSTC_BOOTSTRAP=1
cargo llvm-cov --workspace --locked --summary-only \
  --fail-under-lines 99 \
  --fail-under-regions 99

echo "==> CI gates OK"
