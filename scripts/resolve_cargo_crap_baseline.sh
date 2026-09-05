#!/usr/bin/env bash

set -euo pipefail

BASELINE_RETRY_ATTEMPTS=30
BASELINE_RETRY_DELAY_SECONDS=10

if [[ "${EVENT_NAME}" != "pull_request" ]]; then
  echo 'bootstrap=true' >> "${GITHUB_OUTPUT}"
  exit 0
fi

BASELINE_ARTIFACT_NAME="cargo-crap-baseline-${BASE_SHA}"

for ((attempt = 1; attempt <= BASELINE_RETRY_ATTEMPTS; attempt++)); do
  run_ids="$(gh api --method GET --paginate \
    "repos/${GITHUB_REPOSITORY}/actions/artifacts" \
    -f name="${BASELINE_ARTIFACT_NAME}" -f per_page=100 \
    --jq ".artifacts[] |
      select(.expired == false) |
      select(.workflow_run.head_branch == \"main\") |
      select(.workflow_run.head_sha == \"${BASE_SHA}\") |
      select(.workflow_run.head_repository_id == .workflow_run.repository_id) |
      .workflow_run.id")"
  run_id=''
  while IFS= read -r candidate; do
    [[ -n "${candidate}" ]] || continue
    run_id="${candidate}"
    break
  done <<< "${run_ids}"
  if [[ -n "${run_id}" ]]; then
    echo "run-id=${run_id}" >> "${GITHUB_OUTPUT}"
    echo 'bootstrap=false' >> "${GITHUB_OUTPUT}"
    exit 0
  fi
  if (( attempt < BASELINE_RETRY_ATTEMPTS )); then
    echo "Trusted baseline ${BASE_SHA} is not available yet (attempt ${attempt}/${BASELINE_RETRY_ATTEMPTS}); retrying in ${BASELINE_RETRY_DELAY_SECONDS}s"
    sleep "${BASELINE_RETRY_DELAY_SECONDS}"
  fi
done

# One-time initialization for this PR's pre-gate base. No future
# base may silently substitute a PR-controlled baseline.
test "${BASE_SHA}" = "45bdac85b29d273573583f846ba7acd2b3a12573"
git diff --quiet "${BASE_SHA}...HEAD" -- \
  '*.rs' '**/Cargo.toml' Cargo.toml Cargo.lock rust-toolchain.toml \
  .cargo/config.toml .cargo-crap.toml
echo 'bootstrap=true' >> "${GITHUB_OUTPUT}"
