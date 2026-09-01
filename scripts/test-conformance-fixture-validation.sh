#!/usr/bin/env bash
set -euo pipefail

source_root="fixtures/conformance"
temporary_base="$(mktemp -d)"
temporary_root="${temporary_base}/providers/fixtures"
mkdir -p "${temporary_root}"
trap 'rm -rf -- "${temporary_base}"' EXIT

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

refresh_checksums() {
  local fixture_root="$1"
  local path="$2"
  local relative="${path#"${fixture_root}/"}"
  local blake3 sha256 sums_sha256
  blake3="$(b3sum "${path}" | awk '{print $1}')"
  sha256="$(sha256sum "${path}" | awk '{print $1}')"
  sed -i -E "s|^[0-9a-f]{64}  ${relative}$|${blake3}  ${relative}|" \
    "${fixture_root}/BLAKE3SUMS"
  sed -i -E "s|^[0-9a-f]{64}  ${relative}$|${sha256}  ${relative}|" \
    "${fixture_root}/SHA256SUMS"
  sums_sha256="$(sha256sum "${fixture_root}/BLAKE3SUMS" | awk '{print $1}')"
  sed -i -E "s|^[0-9a-f]{64}  BLAKE3SUMS$|${sums_sha256}  BLAKE3SUMS|" \
    "${fixture_root}/SHA256SUMS"
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

expect_adapter_rejection() {
  local fixture_root="$1"
  local expected_message="$2"
  local output="${fixture_root}.adapter.log"
  if bash scripts/generate-conformance-fixture-records.sh "${fixture_root}" --check >"${output}" 2>&1; then
    echo "invalid provider fixture copy was accepted: ${fixture_root}" >&2
    exit 1
  fi
  grep -Fq "${expected_message}" "${output}" || {
    echo "provider fixture copy failed for the wrong reason: ${fixture_root}" >&2
    cat "${output}" >&2
    exit 1
  }
}

expect_adapter_acceptance() {
  local fixture_root="$1"
  bash scripts/generate-conformance-fixture-records.sh "${fixture_root}" --write
  bash scripts/generate-conformance-fixture-records.sh "${fixture_root}" --check
  bash scripts/verify-conformance-fixtures.sh "${fixture_root}"
}

profile="${source_root}/profiles/artifact-integrity/profile.json"
positive_input="$(jq -r '.fixtures[] | select(.family == "positive") | .input' "${profile}")"
malformed_input="$(jq -r '.fixtures[] | select(.family == "malformed") | .input' "${profile}")"
positive_schema="$(jq -r '.fixtures[] | select(.family == "positive") | .schema' "${profile}")"

unknown_input_root="$(new_fixture_copy unknown-input-field)"
replace_json "${unknown_input_root}/${positive_input}" '.undeclared_evidence = true'
expect_adapter_rejection "${unknown_input_root}" "input fixture is not independently reproducible"

valid_malformed_root="$(new_fixture_copy valid-malformed-input)"
replace_json "${valid_malformed_root}/${malformed_input}" '.stimulus = "now-valid"'
expect_adapter_rejection "${valid_malformed_root}" "input fixture is not independently reproducible"

unsupported_schema_root="$(new_fixture_copy unsupported-schema-keyword)"
replace_json "${unsupported_schema_root}/${positive_schema}" '.oneOf = []'
expect_adapter_rejection "${unsupported_schema_root}" "unsupported JSON adapter semantics"

for media_case in \
  'schema|application/cbor' \
  'payload|application/cbor' \
  'oracle|application/cbor' \
  'evidence_status|application/cbor'; do
  IFS='|' read -r media_field non_json_media <<<"${media_case}"
  non_json_root="$(new_fixture_copy "opaque-${media_field}-media-type")"
  replace_json "${non_json_root}/providers/artifact-integrity/provider.json" \
    ".artifact_media_types.${media_field} = \"${non_json_media}\""
  expect_adapter_rejection "${non_json_root}" "invalid pigloros-json-v1 fixture adapter declaration"
  expect_rejection "${non_json_root}" "invalid pigloros-json-v1 fixture adapter declaration"
done

unknown_adapter_root="$(new_fixture_copy unknown-fixture-adapter)"
replace_json "${unknown_adapter_root}/providers/artifact-integrity/provider.json" \
  '.fixture_adapter.id = "future-plugin-v1"'
expect_adapter_rejection "${unknown_adapter_root}" "unsupported provider fixture adapter: future-plugin-v1"
expect_rejection "${unknown_adapter_root}" "unsupported provider fixture adapter: future-plugin-v1"

nested_adapter_root="$(new_fixture_copy nested-unknown-fixture-adapter)"
mkdir -p "${nested_adapter_root}/providers/nested/artifact-integrity"
cp "${nested_adapter_root}/providers/artifact-integrity/provider.json" \
  "${nested_adapter_root}/providers/nested/artifact-integrity/provider.json"
replace_json "${nested_adapter_root}/providers/nested/artifact-integrity/provider.json" \
  '.fixture_adapter.id = "future-plugin-v1"'
replace_json "${nested_adapter_root}/profiles/artifact-integrity/profile.json" \
  '.fixture_providers[0].manifest = "providers/nested/artifact-integrity/provider.json"'
expect_adapter_rejection "${nested_adapter_root}" "unsupported provider fixture adapter: future-plugin-v1"
expect_rejection "${nested_adapter_root}" "unsupported provider fixture adapter: future-plugin-v1"

unsafe_package_root="$(new_fixture_copy unsafe-provider-package-path)"
replace_json "${unsafe_package_root}/providers/artifact-integrity/provider.json" \
  '.package_path = "../provider.cbor"'
expect_rejection "${unsafe_package_root}" "invalid provider manifest for artifact-integrity"

opaque_adapter_root="$(new_fixture_copy opaque-provider-adapter)"
replace_json "${opaque_adapter_root}/providers/artifact-integrity/provider.json" '
  .fixture_adapter.id = "opaque-provider-v1" |
  .artifact_media_types = {
    schema: "application/octet-stream",
    payload: "application/octet-stream",
    oracle: "application/octet-stream",
    evidence_status: "application/octet-stream"
  }'
while IFS= read -r schema; do
  printf 'opaque-schema-v1\n' >"${opaque_adapter_root}/${schema}"
done < <(jq -r '.schemas[]' "${opaque_adapter_root}/providers/artifact-integrity/provider.json")
expect_adapter_acceptance "${opaque_adapter_root}"
opaque_secret_input="${opaque_adapter_root}/${positive_input}"
printf '\xa1\x66secret\x50abcdefghijklmnop' >"${opaque_secret_input}"
refresh_checksums "${opaque_adapter_root}" "${opaque_secret_input}"
expect_rejection "${opaque_adapter_root}" "forbidden secret material found"

unknown_adapter_config_root="$(new_fixture_copy unknown-adapter-config-field)"
replace_json "${unknown_adapter_config_root}/providers/artifact-integrity/provider.json" \
  '.fixture_adapter.config.plugin_entrypoint = "example"'
expect_adapter_rejection "${unknown_adapter_config_root}" "invalid pigloros-json-v1 fixture adapter declaration"
expect_rejection "${unknown_adapter_config_root}" "invalid pigloros-json-v1 fixture adapter declaration"

legacy_provider_root="$(new_fixture_copy legacy-provider-fields)"
replace_json "${legacy_provider_root}/providers/artifact-integrity/provider.json" \
  '.fixture_operations = .fixture_adapter.config.operations |
   .fixture_payloads = .fixture_adapter.config.payloads |
   del(.fixture_adapter)'
expect_adapter_rejection "${legacy_provider_root}" "provider fixture adapter declaration is missing or invalid"
expect_rejection "${legacy_provider_root}" "provider fixture adapter declaration is missing or invalid"

unknown_authority_root="$(new_fixture_copy unknown-authority-field)"
replace_json "${unknown_authority_root}/support/draft-execution-authority.json" \
  '.undeclared_authority = true'
expect_rejection "${unknown_authority_root}" "invalid Draft authority declaration fields"

versioned_profile_id_root="$(new_fixture_copy versioned-profile-id)"
replace_json "${versioned_profile_id_root}/profiles/artifact-integrity/profile.json" \
  '.profile_id = "pigloros.w8.artifact-integrity.1.0.0"'
expect_rejection "${versioned_profile_id_root}" \
  "invalid public profile manifest for artifact-integrity"

foreign_normative_root="$(new_fixture_copy foreign-profile-normative-requirements)"
replace_json "${foreign_normative_root}/profiles/artifact-integrity/profile.json" \
  '.normative_requirements = "profiles/replay-conformance/normative-requirements.md"'
expect_rejection "${foreign_normative_root}" \
  "invalid public profile manifest for artifact-integrity"

divergent_positive_root="$(new_fixture_copy divergent-positive-oracle)"
replace_json "${divergent_positive_root}/providers/empirical-evaluation/provider.json" \
  '.fixture_contracts.positive.allowed_divergence = {
    "classification": "canonical-bytes",
    "first_coordinate": "expected/assessment"
  }'
expect_adapter_rejection "${divergent_positive_root}" \
  "invalid pigloros-json-v1 fixture adapter declaration"

short_plugin_id_root="$(new_fixture_copy short-plugin-invocation-id)"
replace_json "${short_plugin_id_root}/providers/plugin-conformance/provider.json" \
  '.fixture_adapter.config.payloads.denied.with_operation.stimulus.input["invocation-id"] |= .[:-1]'
expect_adapter_rejection "${short_plugin_id_root}" \
  "generated fixture does not satisfy its provider schema"

publication_wrapper_prefix="${temporary_base}/publication-wrapper-prefix.sh"
sed -n '1,/^first_fingerprint=/p' scripts/materialize-conformance-bundles.sh \
  >"${publication_wrapper_prefix}"
if grep -Eq '(\[\[.*publication_parent|mkdir .*publication_parent|realpath .*publication_parent|readlink .*publication_parent)' \
  "${publication_wrapper_prefix}"; then
  echo "materialization wrapper traverses the publication parent before Rust" >&2
  exit 1
fi

echo "conformance fixture validator negative controls passed"
