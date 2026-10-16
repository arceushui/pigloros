#!/usr/bin/env bash
# Fail if a test log reports ignored or skipped tests in a summary line (not prose elsewhere).
# Accepts libtest (`cargo test`) and cargo-nextest logs. Every log must carry at
# least one summary, so a run that never reached its summary fails closed.
# Usage: assert-no-ignored-in-test-summary.sh <test.log>...
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: assert-no-ignored-in-test-summary.sh <logfile>..." >&2
  exit 2
fi

status=0
for log in "$@"; do
  # CI forces colour; strip SGR sequences so styled counts still match.
  plain="$(sed 's/\x1b\[[0-9;]*m//g' "$log")"
  if ! grep -Eq '^test result:|^ *Summary \[' <<<"$plain"; then
    echo "ERROR: $log has no libtest or nextest summary line." >&2
    status=1
    continue
  fi
  if grep -E '^test result:.*; [1-9][0-9]* ignored;' <<<"$plain"; then
    echo "ERROR: $log: cargo test summary reports ignored tests (use --include-ignored or remove #[ignore])." >&2
    status=1
  fi
  if grep -E '^ *Summary \[.*[^0-9][1-9][0-9]* skipped' <<<"$plain"; then
    echo "ERROR: $log: nextest summary reports skipped tests (use --run-ignored all and no filter)." >&2
    status=1
  fi
done
exit "$status"
