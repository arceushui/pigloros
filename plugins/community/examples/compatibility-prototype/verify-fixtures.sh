#!/usr/bin/env bash
# Rebuild the compatibility Components and require byte-identical fixtures.
#
# Usage: PROTOTYPE_TOOLS=DIR verify-fixtures.sh
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
committed="${here}/fixtures"
rebuilt="$(mktemp -d)"
trap 'rm -rf -- "${rebuilt}"' EXIT

(
  cd -- "${committed}"
  sha256sum --check --strict SHA256SUMS
)
bash "${here}/build-fixtures.sh" "${rebuilt}"
if ! diff --recursive --brief -- "${committed}" "${rebuilt}"; then
  echo "rebuilt Components differ from the committed fixtures" >&2
  (
    cd -- "${rebuilt}"
    cat SHA256SUMS
  )
  exit 1
fi
cat -- "${committed}/SHA256SUMS"
