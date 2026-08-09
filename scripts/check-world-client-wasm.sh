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

mode="${1:-all}"
case "$mode" in
  all | package | browser) ;;
  *)
    printf 'usage: %s [all|package|browser]\n' "$0" >&2
    exit 2
    ;;
esac

if [[ "$mode" == "all" || "$mode" == "package" ]]; then
  cargo check -p piglor-world-client --target wasm32-unknown-unknown --locked --no-default-features
  wasm-pack build apps/piglor-world-client --target web --release -- --locked
fi

if [[ "$mode" == "all" || "$mode" == "browser" ]]; then
  wasm-pack test --headless --chrome apps/piglor-world-client --locked --no-default-features --test wasm_parity
fi
