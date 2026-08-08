#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    CARGO_TARGET_DIR="$PWD/target"
  else
    CARGO_TARGET_DIR=/root/pigloros/target
  fi
fi
export CARGO_TARGET_DIR

wasm_rustflags="${RUSTFLAGS:-}"
if [[ -n "$wasm_rustflags" ]]; then
  wasm_rustflags+=' '
fi
wasm_rustflags+='--cfg getrandom_backend="wasm_js"'
export RUSTFLAGS="$wasm_rustflags"

cargo check -p piglor-world-client --target wasm32-unknown-unknown --locked --no-default-features
wasm-pack build apps/piglor-world-client --target web --release -- --locked
wasm-pack test --headless --chrome apps/piglor-world-client --locked --no-default-features --test wasm_parity
