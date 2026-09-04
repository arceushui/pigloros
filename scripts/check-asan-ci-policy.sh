#!/usr/bin/env bash
# Keep Cargo build/link work serialized within each hosted ASan shard.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$ROOT/scripts/check_asan_ci_policy.py" "${1:-$ROOT/.github/workflows/ci.yml}"
