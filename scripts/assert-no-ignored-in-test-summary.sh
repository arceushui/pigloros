#!/usr/bin/env bash
# Fail if a cargo test log reports ignored tests in the summary line (not prose elsewhere).
# Usage: assert-no-ignored-in-test-summary.sh <cargo-test.log>
set -euo pipefail

log="${1:?usage: assert-no-ignored-in-test-summary.sh <logfile>}"

if grep -E 'test result:.*; [1-9][0-9]* ignored;' "$log"; then
  echo "ERROR: cargo test summary reports ignored tests (use --include-ignored or remove #[ignore])." >&2
  exit 1
fi
