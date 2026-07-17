#!/usr/bin/env bash
# Local parity with .github/workflows/ci.yml (Redmine #100).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> fmt"
cargo fmt --all -- --check

echo "==> test"
cargo test --workspace

echo "==> clippy"
cargo clippy --workspace --all-targets -- -D warnings -W clippy::pedantic

echo "==> coverage (lines + regions @ 100%)"
export RUSTC_BOOTSTRAP=1
cargo llvm-cov --workspace --summary-only \
  --fail-under-lines 100 \
  --fail-under-regions 100

echo "==> CI gates OK"
