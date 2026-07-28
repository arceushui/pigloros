#!/usr/bin/env bash
# Self-test the policy checker against both compliant and floating references.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="$root/scripts/check-pinned-dependencies.sh"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

mkdir -p "$fixture/.github/workflows"
printf '%s\n' \
  'FROM example@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  > "$fixture/Dockerfile"
printf '%s\n' \
  'steps:' \
  '  - uses: owner/action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v1' \
  > "$fixture/.github/workflows/valid.yml"
bash "$checker" "$fixture"

printf '%s\n' '  - uses: owner/action@v1' > "$fixture/.github/workflows/floating-action.yml"
if bash "$checker" "$fixture" >/dev/null 2>&1; then
  echo 'ERROR: floating GitHub Action was accepted' >&2
  exit 1
fi
rm "$fixture/.github/workflows/floating-action.yml"

printf '%s\n' 'FROM example:1' > "$fixture/Dockerfile"
if bash "$checker" "$fixture" >/dev/null 2>&1; then
  echo 'ERROR: floating Docker image was accepted' >&2
  exit 1
fi

printf 'Pinned dependency checker tests passed.\n'
