#!/usr/bin/env bash

set -euo pipefail

BASELINE_RETRY_ATTEMPTS=30
BASELINE_RETRY_DELAY_SECONDS=10
# Right after a merge, main's CI for the trusted base is still running and has
# not yet published its baseline. While that same-repository main run is
# queued or in progress, keep polling for the artifact, bounded by the total
# wait below (the cargo-crap step and job timeouts leave room for it).
MAIN_RUN_POLL_DELAY_SECONDS=60
BASELINE_WAIT_LIMIT_SECONDS=7200

if [[ "${EVENT_NAME}" != "pull_request" ]]; then
  echo 'bootstrap=true' >> "${GITHUB_OUTPUT}"
  exit 0
fi

TRUSTED_BASE_SHA="$(git merge-base "${BASE_SHA}" origin/main)"
BASELINE_ARTIFACT_NAME="cargo-crap-baseline-${TRUSTED_BASE_SHA}"
WAIT_STARTED_AT="$(date +%s)"

publish_baseline_if_available() {
  local run_ids run_id='' candidate
  run_ids="$(gh api --method GET --paginate \
    "repos/${GITHUB_REPOSITORY}/actions/artifacts" \
    -f name="${BASELINE_ARTIFACT_NAME}" -f per_page=100 \
    --jq ".artifacts[] |
      select(.expired == false) |
      select(.workflow_run.head_branch == \"main\") |
      select(.workflow_run.head_sha == \"${TRUSTED_BASE_SHA}\") |
      select(.workflow_run.head_repository_id == .workflow_run.repository_id) |
      .workflow_run.id")"
  while IFS= read -r candidate; do
    [[ -n "${candidate}" ]] || continue
    run_id="${candidate}"
    break
  done <<< "${run_ids}"
  if [[ -n "${run_id}" ]]; then
    echo "run-id=${run_id}" >> "${GITHUB_OUTPUT}"
    echo "baseline-sha=${TRUSTED_BASE_SHA}" >> "${GITHUB_OUTPUT}"
    echo 'bootstrap=false' >> "${GITHUB_OUTPUT}"
    exit 0
  fi
}

# Sets MAIN_RUN to "<id> <status> <conclusion>" for the same-repository main
# ci.yml run of the trusted base: an unfinished run wins, otherwise the newest
# completed one. MAIN_RUN stays empty when main has no such run.
read_main_run() {
  local runs id status conclusion completed=''
  runs="$(gh api --method GET --paginate \
    "repos/${GITHUB_REPOSITORY}/actions/workflows/ci.yml/runs" \
    -f branch=main -f head_sha="${TRUSTED_BASE_SHA}" -f per_page=100 \
    --jq ".workflow_runs[] |
      select(.head_branch == \"main\") |
      select(.head_sha == \"${TRUSTED_BASE_SHA}\") |
      select(.head_repository.id == .repository.id) |
      \"\(.id) \(.status) \(.conclusion // \"none\")\"")"
  MAIN_RUN=''
  while read -r id status conclusion; do
    [[ -n "${id}" ]] || continue
    if [[ "${status}" != "completed" ]]; then
      MAIN_RUN="${id} ${status} ${conclusion}"
      return
    fi
    [[ -n "${completed}" ]] || completed="${id} ${status} ${conclusion}"
  done <<< "${runs}"
  MAIN_RUN="${completed}"
}

for ((attempt = 1; attempt <= BASELINE_RETRY_ATTEMPTS; attempt++)); do
  publish_baseline_if_available
  if (( attempt < BASELINE_RETRY_ATTEMPTS )); then
    printf 'Trusted main baseline %s for base %s is not available yet (attempt %s/%s); retrying in %ss\n' \
      "${TRUSTED_BASE_SHA}" "${BASE_SHA}" "${attempt}" \
      "${BASELINE_RETRY_ATTEMPTS}" "${BASELINE_RETRY_DELAY_SECONDS}"
    sleep "${BASELINE_RETRY_DELAY_SECONDS}"
  fi
done

while true; do
  read_main_run
  if [[ -z "${MAIN_RUN}" ]]; then
    reason="no main ci.yml run exists for trusted base ${TRUSTED_BASE_SHA}"
    break
  fi
  read -r main_run_id main_run_status main_run_conclusion <<< "${MAIN_RUN}"
  if [[ "${main_run_status}" == "completed" ]]; then
    publish_baseline_if_available
    reason="main ci.yml run ${main_run_id} for trusted base ${TRUSTED_BASE_SHA} completed with conclusion ${main_run_conclusion} without publishing ${BASELINE_ARTIFACT_NAME}"
    break
  fi
  elapsed=$(($(date +%s) - WAIT_STARTED_AT))
  if ((elapsed + MAIN_RUN_POLL_DELAY_SECONDS > BASELINE_WAIT_LIMIT_SECONDS)); then
    reason="main ci.yml run ${main_run_id} for trusted base ${TRUSTED_BASE_SHA} is still ${main_run_status} after ${elapsed}s; the ${BASELINE_WAIT_LIMIT_SECONDS}s wait bound expired without ${BASELINE_ARTIFACT_NAME}"
    break
  fi
  printf 'Waiting for main ci.yml run %s (%s) to publish %s (%ss of %ss elapsed); checking again in %ss\n' \
    "${main_run_id}" "${main_run_status}" "${BASELINE_ARTIFACT_NAME}" \
    "${elapsed}" "${BASELINE_WAIT_LIMIT_SECONDS}" "${MAIN_RUN_POLL_DELAY_SECONDS}"
  sleep "${MAIN_RUN_POLL_DELAY_SECONDS}"
  publish_baseline_if_available
done

# If the trusted main artifact is missing (for example, after a failed main
# run), bootstrap only when this PR cannot change Rust or Cargo policy inputs.
# The generated baseline then describes the unchanged production Rust surface;
# Rust-affecting PRs continue to fail closed rather than self-baselining.
if git diff --quiet "${BASE_SHA}...HEAD" -- \
  '*.rs' '**/Cargo.toml' Cargo.toml Cargo.lock rust-toolchain.toml \
  .cargo/config.toml .cargo-crap.toml; then
  echo "::notice::Trusted main baseline unavailable: ${reason}; bootstrapping because this pull request changes no Rust or Cargo policy inputs"
  echo 'bootstrap=true' >> "${GITHUB_OUTPUT}"
  exit 0
fi
echo "::error::Trusted main baseline unavailable: ${reason}; failing closed because this pull request changes Rust or Cargo policy inputs"
exit 1
