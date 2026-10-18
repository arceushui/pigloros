#!/usr/bin/env bash
# Enforce the ASan CI policy: one serialized-link archive build plus
# archive-consuming test shards.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$ROOT/scripts/check_asan_ci_policy.py" "${1:-$ROOT/.github/workflows/ci.yml}"
