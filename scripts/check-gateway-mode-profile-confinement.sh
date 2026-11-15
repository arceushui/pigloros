#!/usr/bin/env bash
# The Gateway execution-mode profile record, its declaration magic and its digest domain stay
# inside the Gateway and its public contract (ADR-134 §3). The check is on strings only: crates
# that depend on piglor-gateway are allowed, and Rust visibility plus the Gateway's
# compile_fail doctests keep the record private.
#
# PIGLOROS_CONFINEMENT_ROOT names another Git work tree to check (used by the script's test).
set -euo pipefail

root="${PIGLOROS_CONFINEMENT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
self='scripts/check-gateway-mode-profile-confinement.sh'
test_script='scripts/test-check-gateway-mode-profile-confinement.sh'

command -v git >/dev/null || { printf '%s\n' 'git is required' >&2; exit 1; }

# `git grep` exits 1 when nothing matches; any other nonzero status is a failure of the check.
status=0
matches="$(git -C "${root}" grep -n -I -F \
  -e 'GMP1' -e 'GMD1' -e 'PiglorOS.GatewayModeProfile.v1' \
  -- . \
  ':(exclude)apps/piglor-gateway/' \
  ':(exclude)contracts/gateway/v1/' \
  ":(exclude)${self}" \
  ":(exclude)${test_script}")" || status=$?
if [[ "${status}" -gt 1 ]]; then
  printf '%s\n' 'git grep failed' >&2
  exit 1
fi
if [[ -n "${matches}" ]]; then
  printf '%s\n' 'Gateway execution-mode profile strings outside the Gateway and its contract:' \
    "${matches}" >&2
  exit 1
fi

printf '%s\n' 'verified the Gateway execution-mode profile confinement'
