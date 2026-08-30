#!/usr/bin/env bash
set -euo pipefail

source_root="fixtures/conformance"
temporary_root="$(mktemp -d)"
trap 'rm -rf -- "${temporary_root}"' EXIT

new_fixture_copy() {
  local name="$1"
  local destination="${temporary_root}/${name}"
  mkdir "${destination}"
  cp -a "${source_root}/." "${destination}/"
  printf '%s\n' "${destination}"
}

replace_json() {
  local path="$1"
  local filter="$2"
  local replacement="${path}.replacement"
  jq "${filter}" "${path}" >"${replacement}"
  mv "${replacement}" "${path}"
}

expect_rejection() {
  local fixture_root="$1"
  local expected_message="$2"
  local output="${fixture_root}.log"
  if bash scripts/verify-conformance-fixtures.sh "${fixture_root}" >"${output}" 2>&1; then
    echo "invalid fixture copy was accepted: ${fixture_root}" >&2
    exit 1
  fi
  grep -Fq "${expected_message}" "${output}" || {
    echo "fixture copy failed for the wrong reason: ${fixture_root}" >&2
    cat "${output}" >&2
    exit 1
  }
}

profile="${source_root}/profiles/artifact-integrity/profile.json"
positive_input="$(jq -r '.fixtures[] | select(.family == "positive") | .input' "${profile}")"
malformed_input="$(jq -r '.fixtures[] | select(.family == "malformed") | .input' "${profile}")"
positive_schema="$(jq -r '.fixtures[] | select(.family == "positive") | .schema' "${profile}")"

unknown_input_root="$(new_fixture_copy unknown-input-field)"
replace_json "${unknown_input_root}/${positive_input}" '.undeclared_evidence = true'
expect_rejection "${unknown_input_root}" "required pinned-schema result"

valid_malformed_root="$(new_fixture_copy valid-malformed-input)"
replace_json "${valid_malformed_root}/${malformed_input}" '.stimulus = "now-valid"'
expect_rejection "${valid_malformed_root}" "required pinned-schema result"

unsupported_schema_root="$(new_fixture_copy unsupported-schema-keyword)"
replace_json "${unsupported_schema_root}/${positive_schema}" '.oneOf = []'
expect_rejection "${unsupported_schema_root}" "required pinned-schema result"

unknown_authority_root="$(new_fixture_copy unknown-authority-field)"
replace_json "${unknown_authority_root}/support/draft-execution-authority.json" \
  '.undeclared_authority = true'
expect_rejection "${unknown_authority_root}" "invalid Draft authority declaration fields"

echo "conformance fixture validator negative controls passed"
