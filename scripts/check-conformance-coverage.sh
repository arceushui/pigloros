#!/usr/bin/env bash
set -euo pipefail

coverage_json="${1:?usage: $0 COVERAGE_JSON}"
[[ -s "${coverage_json}" ]] || {
  echo "coverage JSON is missing: ${coverage_json}" >&2
  exit 1
}
command -v jq >/dev/null || {
  echo "jq is required to enforce conformance coverage" >&2
  exit 1
}

sources=(
  crates/pos-conformance/src/bin/materialize-conformance-bundles.rs
  crates/pos-conformance/src/bin/materialize-conformance-bundles/atomic_publication.rs
  crates/pos-conformance/src/bin/verify-conformance-bundle.rs
  crates/pos-conformance/src/bundle_contract.rs
  crates/pos-conformance/src/independent_bundle_verifier.rs
  crates/pos-conformance/src/lib.rs
  crates/pos-conformance/src/profile_contract.rs
  crates/pos-conformance/src/provider_contract.rs
  crates/pos-conformance/src/wire_syntax.rs
)

failed=0
for source in "${sources[@]}"; do
  mapfile -t missed < <(
    jq -r --arg source "/${source}" '
      .data[].files[]
      | select(.filename | endswith($source))
      | .summary.regions.notcovered
    ' "${coverage_json}"
  )
  if (( ${#missed[@]} != 1 )); then
    echo "coverage JSON must contain exactly one record for ${source}" >&2
    failed=1
  elif (( missed[0] >= 10 )); then
    echo "${source}: ${missed[0]} missed regions; required fewer than 10" >&2
    failed=1
  else
    echo "${source}: ${missed[0]} missed regions"
  fi
done
exit "${failed}"
