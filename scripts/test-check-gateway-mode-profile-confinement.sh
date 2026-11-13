#!/usr/bin/env bash
# Contract test for check-gateway-mode-profile-confinement.sh: it passes on a clean tree, allows
# the Gateway and its contract, and fails on a profile string planted anywhere else.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$root/scripts/check-gateway-mode-profile-confinement.sh"
workflow="$root/.github/workflows/ci.yml"

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

test -x "$script" || fail "missing executable $script"
grep -Fq 'bash scripts/check-gateway-mode-profile-confinement.sh' "$workflow" \
  || fail 'CI does not run the confinement check'
grep -Fq 'bash scripts/test-check-gateway-mode-profile-confinement.sh' "$workflow" \
  || fail 'CI does not run the confinement check test'

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git -C "$work" init -q
git -C "$work" config user.email confinement@test.invalid
git -C "$work" config user.name confinement
mkdir -p "$work/apps/piglor-gateway/src" "$work/contracts/gateway/v1" "$work/crates/consumer/src" \
  "$work/scripts"
printf 'const MAGIC: &str = "GMP1";\n' > "$work/apps/piglor-gateway/src/lib.rs"
printf '{"magic": "GMD1"}\n' > "$work/contracts/gateway/v1/declaration.json"
printf '[dependencies]\npiglor-gateway = { path = "../../apps/piglor-gateway" }\n' \
  > "$work/crates/consumer/Cargo.toml"
printf 'fn main() {}\n' > "$work/crates/consumer/src/main.rs"
cp "$script" "$work/scripts/check-gateway-mode-profile-confinement.sh"
git -C "$work" add -A

PIGLOROS_CONFINEMENT_ROOT="$work" bash "$script" >/dev/null \
  || fail 'a tree that keeps the strings in the Gateway and its contract was refused'

for planted in 'GMP1' 'GMD1' 'PiglorOS.GatewayModeProfile.v1'; do
  printf '// %s\n' "$planted" > "$work/crates/consumer/src/planted.rs"
  git -C "$work" add crates/consumer/src/planted.rs
  if PIGLOROS_CONFINEMENT_ROOT="$work" bash "$script" >/dev/null 2>&1; then
    fail "a planted $planted outside the Gateway was accepted"
  fi
  git -C "$work" rm -q --cached crates/consumer/src/planted.rs
  rm "$work/crates/consumer/src/planted.rs"
done

PIGLOROS_CONFINEMENT_ROOT="$work" bash "$script" >/dev/null \
  || fail 'the clean tree was refused after removing the planted strings'

printf '%s\n' 'confinement check test passed'
