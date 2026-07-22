#!/usr/bin/env bash
# Whole-repo test/coverage policy check (fallback when Trunk is unavailable).
# Delegates per-file logic to .trunk/rust-test-policy.py (single source of truth).
#
# Usage: check-test-policy.sh [ROOT]
set -euo pipefail

ROOT="$(cd "${1:-.}" && pwd)"
cd "$ROOT"

POLICY="$ROOT/.trunk/rust-test-policy.py"
if [[ ! -f "$POLICY" ]]; then
  echo "ERROR: missing $POLICY" >&2
  exit 1
fi

echo "==> test policy ($ROOT): rust-test-policy on all *.rs"
failed=0
while IFS= read -r -d '' f; do
  if ! python3 "$POLICY" "$f"; then
    failed=1
  fi
done < <(find . -name '*.rs' -not -path './target/*' -not -path './.trunk/*' -print0 | sort -z)

if [[ "$failed" -ne 0 ]]; then
  echo "ERROR: rust-test-policy failed" >&2
  exit 1
fi
echo "==> test policy OK"
