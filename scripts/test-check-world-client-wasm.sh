#!/usr/bin/env bash
# Contract test for the world-client WASM packaging script and CI job.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$root/scripts/check-world-client-wasm.sh"
workflow="$root/.github/workflows/ci.yml"
local_ci="$root/scripts/ci.sh"
manifest="$root/apps/piglor-world-client/Cargo.toml"
index="$root/apps/piglor-world-client/index.html"

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

test -x "$script" || fail "missing executable $script"

grep -Fqx 'cargo check -p piglor-world-client --target wasm32-unknown-unknown --locked --no-default-features' "$script" \
  || fail 'script is missing the locked wasm32 cargo check'
grep -Fqx 'wasm-pack build apps/piglor-world-client --target web --release -- --locked' "$script" \
  || fail 'script is missing the locked wasm-pack web build'
grep -Fqx 'wasm-pack test --headless --chrome apps/piglor-world-client --locked --no-default-features --test wasm_parity' "$script" \
  || fail 'script is missing the locked headless Chrome wasm-pack test'
grep -Fq 'CARGO_TARGET_DIR=/root/pigloros/target' "$script" \
  || fail 'script is missing the shared local Cargo target default'
grep -Fq 'CARGO_TARGET_DIR="$PWD/target"' "$script" \
  || fail 'script is missing the GitHub Actions Cargo target override'

job_block="$(awk '
  /^  world-client-wasm:/ { in_job = 1 }
  in_job && /^  [[:alnum:]_-]+:/ && $0 !~ /^  world-client-wasm:/ { exit }
  in_job { print }
' "$workflow")"
[[ -n "$job_block" ]] || fail 'CI is missing the additive world-client-wasm job'

assert_job_contains() {
  grep -Fq "$1" <<<"$job_block" || fail "world-client-wasm job is missing: $1"
}

assert_job_contains 'toolchain: 1.97.1'
assert_job_contains 'rustup target add wasm32-unknown-unknown'
assert_job_contains 'tool: wasm-pack@0.15.0'
assert_job_contains 'chrome-version: 151.0.7922.47'
assert_job_contains 'install-chromedriver: true'
assert_job_contains 'bash scripts/test-check-world-client-wasm.sh'
assert_job_contains 'bash scripts/check-world-client-wasm.sh'

grep -Fq 'bash "$ROOT/scripts/check-world-client-wasm.sh"' "$local_ci" \
  || fail 'local CI parity is missing the real WASM packaging/browser gate'

action_lines="$(grep -E '^[[:space:]]*-[[:space:]]+uses:' <<<"$job_block" || true)"
[[ -n "$action_lines" ]] || fail 'world-client-wasm job has no action steps'
while IFS= read -r action_line; do
  [[ "$action_line" =~ uses:[[:space:]]+[^[:space:]]+@[0-9a-f]{40}([[:space:]]|$) ]] \
    || fail "world-client-wasm action is not pinned to a 40-character SHA: $action_line"
done <<<"$action_lines"

grep -Fq 'features = ["3d", "webgl2"]' "$manifest" \
  || fail 'world-client manifest is not explicitly WebGL2-only'
grep -Fq 'default = ["runtime"]' "$manifest" \
  || fail 'world-client manifest does not default to the runtime feature'
grep -Fq 'runtime = ["dep:bevy", "dep:wasm-bindgen"]' "$manifest" \
  || fail 'world-client runtime feature does not own the Bevy shell dependencies'
grep -Fq 'getrandom = { version = "0.4.3", default-features = false, features = ["wasm_js"] }' "$manifest" \
  || fail 'world-client manifest does not enable getrandom wasm_js support'
grep -Fq 'getrandom03 = { package = "getrandom", version = "0.3.4", default-features = false, features = ["wasm_js"] }' "$manifest" \
  || fail 'world-client manifest does not enable getrandom 0.3 wasm_js support'
grep -Fq 'getrandom_backend="wasm_js"' "$script" \
  || fail 'WASM script does not select the getrandom wasm_js backend'
grep -Fq 'crate-type = ["cdylib", "rlib"]' "$manifest" \
  || fail 'world-client library is not configured for WASM packaging'
grep -Fq 'id="piglor-world-status" role="status"' "$index" \
  || fail 'world-client page is missing its loading status'
grep -Fq 'status.dataset.state = "error"' "$index" \
  || fail 'world-client page is missing its startup error state'
grep -Fq 'import("./pkg/piglor_world_client.js")' "$index" \
  || fail 'world-client page does not catch module-loading failures'
grep -Fq 'document.createElement("canvas").getContext("webgl2")' "$index" \
  || fail 'world-client page does not preflight WebGL2 availability'
grep -Fq 'window.addEventListener("error"' "$index" \
  || fail 'world-client page does not surface asynchronous window errors'
grep -Fq 'window.addEventListener("unhandledrejection"' "$index" \
  || fail 'world-client page does not surface asynchronous promise failures'
grep -Fq 'status.hidden = true' "$index" \
  || fail 'world-client page removes rather than retaining its hidden error status'
if grep -Fq 'webgpu' "$manifest"; then
  fail 'world-client manifest selects WebGPU'
fi

printf 'World-client WASM contract OK.\n'
