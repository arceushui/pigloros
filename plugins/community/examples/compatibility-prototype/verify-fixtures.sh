#!/usr/bin/env bash
# Rebuild the compatibility Components and require byte-identical fixtures.
#
# With REBUILT_DIR set (it must be empty or absent), the rebuilt Components and
# their SHA256SUMS are kept there, so CI can publish them for committing;
# otherwise they go to a temporary directory that is removed on exit. The
# committed checks report their failures only after the rebuild, so a missing
# or stale fixture still yields the full set of rebuilt Components.
#
# Usage: PROTOTYPE_TOOLS=DIR [REBUILT_DIR=DIR] verify-fixtures.sh
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
committed="${here}/fixtures"
if [[ -n "${REBUILT_DIR:-}" ]]; then
  # Stale files in REBUILT_DIR would be compared as if freshly rebuilt.
  if [[ -e "${REBUILT_DIR}" && -n "$(ls -A -- "${REBUILT_DIR}")" ]]; then
    echo "REBUILT_DIR ${REBUILT_DIR} must be empty or absent" >&2
    exit 1
  fi
  mkdir -p -- "${REBUILT_DIR}"
  rebuilt="$(cd -- "${REBUILT_DIR}" && pwd)"
else
  rebuilt="$(mktemp -d)"
  trap 'rm -rf -- "${rebuilt}"' EXIT
fi

status=0
if ! (
  cd -- "${committed}"
  sha256sum --check --strict SHA256SUMS
); then
  echo "committed fixtures do not match their SHA256SUMS" >&2
  status=1
fi
bash "${here}/build-fixtures.sh" "${rebuilt}"
shopt -s nullglob
for component in "${rebuilt}"/*.wasm; do
  name="$(basename -- "${component}")"
  if [[ ! -f "${committed}/${name}" ]]; then
    echo "committed fixture ${name} is missing" >&2
    status=1
  fi
done
if ! diff --recursive --brief -- "${committed}" "${rebuilt}"; then
  echo "rebuilt Components differ from the committed fixtures" >&2
  (
    cd -- "${rebuilt}"
    cat SHA256SUMS
  )
  status=1
fi
if [[ "${status}" -ne 0 ]]; then
  exit 1
fi
cat -- "${committed}/SHA256SUMS"
