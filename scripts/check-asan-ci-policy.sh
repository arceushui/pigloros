#!/usr/bin/env bash
# Keep the complete workspace ASan gate serialized on hosted runners.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$ROOT/scripts/check_asan_ci_policy.py" "${1:-$ROOT/.github/workflows/ci.yml}"
