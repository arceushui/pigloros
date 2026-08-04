#!/usr/bin/env bash
# Contract test for the world-client WASM packaging script and CI job.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$root/scripts/check-world-client-wasm.sh"
workflow="$root/.github/workflows/ci.yml"
manifest="$root/apps/piglor-world-client/Cargo.toml"

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

test -x "$script" || fail "missing executable $script"

grep -Fqx 'cargo check -p piglor-world-client --target wasm32-unknown-unknown --locked --no-default-features' "$script" \
  || fail 'script is missing the locked wasm32 cargo check'
grep -Fqx 'wasm-pack build apps/piglor-world-client --target web --release -- --locked' "$script" \
  || fail 'script is missing the locked wasm-pack web build'
grep -Fqx 'wasm-pack test apps/piglor-world-client --headless --chrome -- --locked' "$script" \
  || fail 'script is missing the locked headless Chrome wasm-pack test'

grep -Fq 'world-client-wasm:' "$workflow" \
  || fail 'CI is missing the additive world-client-wasm job'
grep -Fq 'toolchain: 1.97.1' "$workflow" \
  || fail 'world-client-wasm job is missing Rust 1.97.1'
grep -Fq 'rustup target add wasm32-unknown-unknown' "$workflow" \
  || fail 'world-client-wasm job is missing the wasm32 target'
grep -Fq 'tool: wasm-pack' "$workflow" \
  || fail 'world-client-wasm job is missing wasm-pack installation'
grep -Fq 'setup-chrome' "$workflow" \
  || fail 'world-client-wasm job is missing Chrome setup'
grep -Fq 'bash scripts/check-world-client-wasm.sh' "$workflow" \
  || fail 'world-client-wasm job does not invoke the packaging script'

grep -Fq 'features = ["3d", "webgl2"]' "$manifest" \
  || fail 'world-client manifest is not explicitly WebGL2-only'
if grep -Fq 'webgpu' "$manifest"; then
  fail 'world-client manifest selects WebGPU'
fi

printf 'World-client WASM contract OK.\n'
