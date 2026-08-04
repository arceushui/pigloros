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
assert_job_contains 'tool: wasm-pack'
assert_job_contains 'chrome-version: stable'
assert_job_contains 'install-chromedriver: true'
assert_job_contains 'bash scripts/check-world-client-wasm.sh'

action_lines="$(grep -E '^[[:space:]]*-[[:space:]]+uses:' <<<"$job_block" || true)"
[[ -n "$action_lines" ]] || fail 'world-client-wasm job has no action steps'
while IFS= read -r action_line; do
  [[ "$action_line" =~ uses:[[:space:]]+[^[:space:]]+@[0-9a-f]{40}([[:space:]]|$) ]] \
    || fail "world-client-wasm action is not pinned to a 40-character SHA: $action_line"
done <<<"$action_lines"

grep -Fq 'features = ["3d", "webgl2"]' "$manifest" \
  || fail 'world-client manifest is not explicitly WebGL2-only'
if grep -Fq 'webgpu' "$manifest"; then
  fail 'world-client manifest selects WebGPU'
fi

printf 'World-client WASM contract OK.\n'
