#!/usr/bin/env bash
# Fail if a test log reports ignored or skipped tests in a summary line (not prose elsewhere).
# Accepts libtest (`cargo test`) and cargo-nextest logs. Every log must carry at
# least one summary, so a run that never reached its summary fails closed.
#
# --partitioned takes the nextest logs of every `--partition` shard of one run.
# Each shard skips the tests of the others, so instead of rejecting skips it
# requires every shard to report the same total (run + skipped) and the shards'
# run counts to add up to exactly that total.
# Usage: assert-no-ignored-in-test-summary.sh [--partitioned] <test.log>...
set -euo pipefail

partitioned=false
if [[ ${1:-} == --partitioned ]]; then
  partitioned=true
  shift
fi
if [[ $# -eq 0 ]]; then
  echo "usage: assert-no-ignored-in-test-summary.sh [--partitioned] <logfile>..." >&2
  exit 2
fi

status=0
total=""
run_sum=0
for log in "$@"; do
  # CI forces colour; strip SGR sequences so styled counts still match.
  # $'\033' keeps this portable to BSD sed, which lacks the \x escape.
  plain="$(sed $'s/\033\\[[0-9;]*m//g' "$log")"
  if [[ $partitioned == true ]]; then
    summary="$(grep -E '^ *Summary \[' <<<"$plain" || true)"
    if [[ $(grep -c . <<<"$summary") -ne 1 ]]; then
      echo "ERROR: $log must hold exactly one nextest summary line." >&2
      status=1
      continue
    fi
    run="$(sed -nE 's/.*[^0-9]([0-9]+) tests? run:.*/\1/p' <<<"$summary")"
    skipped="$(sed -nE 's/.*[^0-9]([0-9]+) skipped.*/\1/p' <<<"$summary")"
    if [[ -z $run ]]; then
      echo "ERROR: $log: unreadable nextest summary: $summary" >&2
      status=1
      continue
    fi
    shard_total=$((run + ${skipped:-0}))
    if [[ -n $total && $shard_total -ne $total ]]; then
      echo "ERROR: $log: shard total $shard_total differs from $total." >&2
      status=1
    fi
    total="${total:-$shard_total}"
    run_sum=$((run_sum + run))
    continue
  fi
  if ! grep -Eq '^test result:|^ *Summary \[' <<<"$plain"; then
    echo "ERROR: $log has no libtest or nextest summary line." >&2
    status=1
    continue
  fi
  if grep -E '^test result:.*; [1-9][0-9]* ignored;' <<<"$plain"; then
    echo "ERROR: $log: libtest (cargo test) summary reports ignored tests (use --include-ignored or remove #[ignore])." >&2
    status=1
  fi
  if grep -E '^ *Summary \[.*[^0-9][1-9][0-9]* skipped' <<<"$plain"; then
    echo "ERROR: $log: nextest summary reports skipped tests (use --run-ignored all and no filter)." >&2
    status=1
  fi
done

if [[ $partitioned == true && $status -eq 0 ]]; then
  if [[ $run_sum -ne $total ]]; then
    echo "ERROR: shards ran $run_sum tests; the run holds $total (a test was skipped or run twice)." >&2
    exit 1
  fi
  echo "Shards ran all $total tests exactly once."
fi
exit "$status"
