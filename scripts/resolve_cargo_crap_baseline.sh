#!/usr/bin/env bash

set -euo pipefail

BASELINE_RETRY_ATTEMPTS=30
BASELINE_RETRY_DELAY_SECONDS=10
# Right after a merge, main's CI for the trusted base is still running and has
# not yet published its baseline. While that same-repository main run's
# cargo-crap job is unfinished, keep polling for the artifact, bounded by the
# total wait below (the cargo-crap step and job timeouts leave room for it).
# A main run that has not registered yet is awaited only for the shorter
# registration window.
MAIN_RUN_POLL_DELAY_SECONDS=60
BASELINE_WAIT_LIMIT_SECONDS=7200
MAIN_RUN_REGISTRATION_LIMIT_SECONDS=600
# A transient GitHub API failure is retried; persistent failures fail closed
# without reaching the bootstrap decision.
GH_API_ATTEMPTS=3
GH_API_RETRY_DELAY_SECONDS=30
# When the trusted base never gets its own baseline (its main run failed, was
# cancelled or skipped, does not exist, or outlasted the wait bound), use the
# baseline of the nearest first-parent main ancestor among this many commits
# before it. An older baseline is never weaker: every main commit already
# passed the no-existing-function-grows rule against its own base, so changes
# made after the ancestor are charged to this pull request, never hidden.
# First-parent history is main's own history because main lands only squash
# and merge-queue commits, so the trusted base is always on its mainline. The
# walk adds at most this many sequential artifact queries after the wait
# bound; the resolver step's timeout leaves room for them, and a step that
# still runs out of time fails closed.
ANCESTOR_BASELINE_WALK_LIMIT=30

if [[ "${EVENT_NAME}" != "pull_request" ]]; then
  echo 'bootstrap=true' >> "${GITHUB_OUTPUT}"
  exit 0
fi

TRUSTED_BASE_SHA="$(git merge-base "${BASE_SHA}" origin/main)"
BASELINE_ARTIFACT_NAME="cargo-crap-baseline-${TRUSTED_BASE_SHA}"
WAIT_STARTED_AT="$(date +%s)"

# Runs the GitHub API request "$@" into GH_API_OUTPUT, retrying failures. Exits the script
# (never returns) once every attempt failed.
gh_api() {
  local failure
  for ((failure = 1; failure <= GH_API_ATTEMPTS; failure++)); do
    if GH_API_OUTPUT="$(gh api "$@")"; then
      return 0
    fi
    if ((failure < GH_API_ATTEMPTS)); then
      printf 'GitHub API request %s failed (attempt %s/%s); retrying in %ss\n' \
        "$4" "${failure}" "${GH_API_ATTEMPTS}" "${GH_API_RETRY_DELAY_SECONDS}"
      sleep "${GH_API_RETRY_DELAY_SECONDS}"
    fi
  done
  echo "::error::GitHub API request $4 failed ${GH_API_ATTEMPTS} consecutive times; failing closed without a trusted main baseline"
  exit 1
}

# Publishes the baseline of main commit $1 and exits when a non-expired
# same-repository main artifact cargo-crap-baseline-$1 exists for exactly that
# commit; returns otherwise. A non-empty $2 is printed as a notice first.
publish_baseline_of() {
  local sha="$1" run_id='' candidate
  gh_api --method GET --paginate \
    "repos/${GITHUB_REPOSITORY}/actions/artifacts" \
    -f name="cargo-crap-baseline-${sha}" -f per_page=100 \
    --jq ".artifacts[] |
      select(.expired == false) |
      select(.workflow_run.head_branch == \"main\") |
      select(.workflow_run.head_sha == \"${sha}\") |
      select(.workflow_run.head_repository_id == .workflow_run.repository_id) |
      .workflow_run.id"
  while IFS= read -r candidate; do
    [[ -n "${candidate}" ]] || continue
    run_id="${candidate}"
    break
  done <<< "${GH_API_OUTPUT}"
  if [[ -n "${run_id}" ]]; then
    [[ -z "${2:-}" ]] || echo "::notice::$2"
    echo "run-id=${run_id}" >> "${GITHUB_OUTPUT}"
    echo "baseline-sha=${sha}" >> "${GITHUB_OUTPUT}"
    echo 'bootstrap=false' >> "${GITHUB_OUTPUT}"
    exit 0
  fi
}

publish_baseline_if_available() {
  publish_baseline_of "${TRUSTED_BASE_SHA}"
}

# Sets MAIN_RUN to "<id> <status> <conclusion>" for the same-repository main
# ci.yml run of the trusted base: an unfinished run wins, otherwise the newest
# completed one. MAIN_RUN stays empty when main has no such run.
read_main_run() {
  local id status conclusion completed=''
  gh_api --method GET --paginate \
    "repos/${GITHUB_REPOSITORY}/actions/workflows/ci.yml/runs" \
    -f branch=main -f head_sha="${TRUSTED_BASE_SHA}" -f per_page=100 \
    --jq ".workflow_runs[] |
      select(.head_branch == \"main\") |
      select(.head_sha == \"${TRUSTED_BASE_SHA}\") |
      select(.head_repository.id == .repository.id) |
      \"\(.id) \(.status) \(.conclusion // \"none\")\""
  MAIN_RUN=''
  while read -r id status conclusion; do
    [[ -n "${id}" ]] || continue
    if [[ "${status}" != "completed" ]]; then
      MAIN_RUN="${id} ${status} ${conclusion}"
      return
    fi
    [[ -n "${completed}" ]] || completed="${id} ${status} ${conclusion}"
  done <<< "${GH_API_OUTPUT}"
  MAIN_RUN="${completed}"
}

# Publishes the baseline of the nearest of the ANCESTOR_BASELINE_WALK_LIMIT
# first-parent ancestors of the trusted base that has one, and returns when
# none has. A failed git call aborts the resolver (set -e) instead of being
# read as "no ancestors".
publish_ancestor_baseline() {
  local ancestors ancestor
  ancestors="$(git rev-list --first-parent --skip=1 \
    --max-count="${ANCESTOR_BASELINE_WALK_LIMIT}" "${TRUSTED_BASE_SHA}")"
  while IFS= read -r ancestor; do
    [[ -n "${ancestor}" ]] || continue
    publish_baseline_of "${ancestor}" \
      "Using the cargo-crap baseline of main ancestor ${ancestor} because ${reason}"
  done <<< "${ancestors}"
}

# Sets CRAP_JOB to "<status> <conclusion>" for the cargo-crap job of main run
# $1's latest attempt; CRAP_JOB stays empty until that job is listed.
read_crap_job() {
  gh_api --method GET --paginate \
    "repos/${GITHUB_REPOSITORY}/actions/runs/$1/jobs" \
    -f filter=latest -f per_page=100 \
    --jq ".jobs[] |
      select(.name == \"cargo-crap\") |
      \"\(.status) \(.conclusion // \"none\")\""
  CRAP_JOB="$(head -n 1 <<< "${GH_API_OUTPUT}")"
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
  elapsed=$(($(date +%s) - WAIT_STARTED_AT))
  read_main_run
  if [[ -z "${MAIN_RUN}" ]]; then
    if ((elapsed + MAIN_RUN_POLL_DELAY_SECONDS > MAIN_RUN_REGISTRATION_LIMIT_SECONDS)); then
      reason="no main ci.yml run exists for trusted base ${TRUSTED_BASE_SHA} after ${elapsed}s"
      break
    fi
    printf 'No main ci.yml run for trusted base %s yet (%ss of %ss registration window elapsed); checking again in %ss\n' \
      "${TRUSTED_BASE_SHA}" "${elapsed}" "${MAIN_RUN_REGISTRATION_LIMIT_SECONDS}" "${MAIN_RUN_POLL_DELAY_SECONDS}"
    sleep "${MAIN_RUN_POLL_DELAY_SECONDS}"
    publish_baseline_if_available
    continue
  fi
  read -r main_run_id main_run_status main_run_conclusion <<< "${MAIN_RUN}"
  if [[ "${main_run_status}" == "completed" ]]; then
    publish_baseline_if_available
    reason="main ci.yml run ${main_run_id} for trusted base ${TRUSTED_BASE_SHA} completed with conclusion ${main_run_conclusion} without publishing ${BASELINE_ARTIFACT_NAME}"
    break
  fi
  read_crap_job "${main_run_id}"
  read -r crap_job_status crap_job_conclusion <<< "${CRAP_JOB:-pending none}"
  if [[ "${crap_job_status}" == "completed" ]]; then
    publish_baseline_if_available
    reason="the cargo-crap job of main ci.yml run ${main_run_id} for trusted base ${TRUSTED_BASE_SHA} completed with conclusion ${crap_job_conclusion} without publishing ${BASELINE_ARTIFACT_NAME}"
    break
  fi
  if ((elapsed + MAIN_RUN_POLL_DELAY_SECONDS > BASELINE_WAIT_LIMIT_SECONDS)); then
    reason="main ci.yml run ${main_run_id} for trusted base ${TRUSTED_BASE_SHA} is still ${main_run_status} after ${elapsed}s; the ${BASELINE_WAIT_LIMIT_SECONDS}s wait bound expired without ${BASELINE_ARTIFACT_NAME}"
    break
  fi
  printf 'Waiting for main ci.yml run %s (%s, cargo-crap job %s) to publish %s (%ss of %ss elapsed); checking again in %ss\n' \
    "${main_run_id}" "${main_run_status}" "${crap_job_status}" "${BASELINE_ARTIFACT_NAME}" \
    "${elapsed}" "${BASELINE_WAIT_LIMIT_SECONDS}" "${MAIN_RUN_POLL_DELAY_SECONDS}"
  sleep "${MAIN_RUN_POLL_DELAY_SECONDS}"
  publish_baseline_if_available
done

publish_ancestor_baseline
reason="${reason}, and none of its ${ANCESTOR_BASELINE_WALK_LIMIT} nearest first-parent main ancestors has a baseline"

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
