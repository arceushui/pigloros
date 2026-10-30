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

missing_auxiliary_root="$(new_fixture_copy missing-auxiliary-key)"
replace_json "${missing_auxiliary_root}/providers/artifact-integrity/provider.json" 'del(.auxiliary)'
expect_adapter_rejection "${missing_auxiliary_root}" "invalid provider auxiliary declaration"
expect_rejection "${missing_auxiliary_root}" "invalid provider auxiliary declaration"

unsafe_auxiliary_root="$(new_fixture_copy unsafe-auxiliary-path)"
replace_json "${unsafe_auxiliary_root}/providers/artifact-integrity/provider.json" \
  '.auxiliary.positive = [{path: "inputs/../support/LICENSE", media_type: "application/octet-stream"}]'
expect_adapter_rejection "${unsafe_auxiliary_root}" "invalid provider auxiliary declaration"
expect_rejection "${unsafe_auxiliary_root}" "invalid provider auxiliary declaration"

unknown_family_auxiliary_root="$(new_fixture_copy unknown-auxiliary-family)"
replace_json "${unknown_family_auxiliary_root}/providers/artifact-integrity/provider.json" \
  '.auxiliary.unknown = []'
expect_adapter_rejection "${unknown_family_auxiliary_root}" "invalid provider auxiliary declaration"
expect_rejection "${unknown_family_auxiliary_root}" "invalid provider auxiliary declaration"

json_auxiliary_root="$(new_fixture_copy json-adapter-auxiliary)"
replace_json "${json_auxiliary_root}/providers/artifact-integrity/provider.json" \
  '.auxiliary.positive = [{path: "inputs/artifact-integrity/positive.pcw2", media_type: "application/octet-stream"}]'
expect_adapter_rejection "${json_auxiliary_root}" "invalid pigloros-json-v1 fixture adapter declaration"
expect_rejection "${json_auxiliary_root}" "invalid pigloros-json-v1 fixture adapter declaration"

opaque_auxiliary_root="$(new_fixture_copy opaque-provider-auxiliary)"
replace_json "${opaque_auxiliary_root}/providers/artifact-integrity/provider.json" '
  .fixture_adapter.id = "opaque-provider-v1" |
  .artifact_media_types = {
    schema: "application/octet-stream",
    payload: "application/octet-stream",
    oracle: "application/octet-stream",
    evidence_status: "application/octet-stream"
  } |
  .auxiliary.positive = [{path: "inputs/artifact-integrity/positive.pcw2", media_type: "application/octet-stream"}]'
while IFS= read -r schema; do
  printf 'opaque-schema-v1\n' >"${opaque_auxiliary_root}/${schema}"
done < <(jq -r '.schemas[]' "${opaque_auxiliary_root}/providers/artifact-integrity/provider.json")
printf 'auxiliary composite placeholder\n' \
  >"${opaque_auxiliary_root}/inputs/artifact-integrity/positive.pcw2"
expect_adapter_acceptance "${opaque_auxiliary_root}"
rm -- "${opaque_auxiliary_root}/inputs/artifact-integrity/positive.pcw2"
bash scripts/generate-conformance-fixture-records.sh "${opaque_auxiliary_root}" --write
expect_rejection "${opaque_auxiliary_root}" "empty conformance fixture"

watchdog_root="$(new_fixture_copy plugin-watchdog-drift)"
replace_json "${watchdog_root}/providers/plugin-conformance/provider.json" \
  '.fixture_contracts.denied.watchdog_ms = 1000'
expect_rejection "${watchdog_root}" "invalid provider manifest for plugin-conformance"

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

# The Plugin provider's plugin-signed-v1 adapter (ADR-061 revision 8 decision 7, R8-F8).
plugin_provider="providers/plugin-conformance/provider.json"

# R8-F3: the checked-in Plugin provider declares the v2 contract, and nothing names the old one.
jq -e '.contract_version == "2.1.0" and .abi_major == 0 and .abi_minor == 0 and
  has("auxiliary") and .fixture_adapter.id == "plugin-signed-v1"' \
  "${source_root}/${plugin_provider}" >/dev/null
if git grep -nIF -e 'plugin-conformance@1.0.0' -- . \
  ':(exclude)scripts/test-conformance-fixture-validation.sh'; then
  echo "a checked-in file names the Plugin 1.0.0 provider contract" >&2
  exit 1
fi
if grep -rlE '"contract_version": ?"1\.0\.0"' "${source_root}/oracles/plugin-conformance" \
  "${source_root}/inputs/plugin-conformance" "${source_root}/providers/plugin-conformance"; then
  echo "a Plugin fixture file carries the 1.0.0 contract version" >&2
  exit 1
fi

missing_plugin_auxiliary_root="$(new_fixture_copy plugin-missing-auxiliary-key)"
replace_json "${missing_plugin_auxiliary_root}/${plugin_provider}" 'del(.auxiliary)'
expect_adapter_rejection "${missing_plugin_auxiliary_root}" "invalid provider auxiliary declaration"
expect_rejection "${missing_plugin_auxiliary_root}" "invalid provider auxiliary declaration"

old_contract_root="$(new_fixture_copy plugin-old-contract-version)"
replace_json "${old_contract_root}/${plugin_provider}" '.contract_version = "1.0.0"'
expect_adapter_rejection "${old_contract_root}" \
  "invalid plugin-signed-v1 fixture adapter declaration"
expect_rejection "${old_contract_root}" \
  "invalid plugin-signed-v1 fixture adapter declaration"

moved_composite_root="$(new_fixture_copy plugin-moved-composite)"
replace_json "${moved_composite_root}/${plugin_provider}" \
  '.auxiliary.positive[0].path = "inputs/plugin-conformance/elsewhere.pcw2"'
expect_adapter_rejection "${moved_composite_root}" \
  "invalid plugin-signed-v1 fixture adapter declaration"

corrupt_composite_root="$(new_fixture_copy plugin-corrupt-composite)"
printf '\x00' | dd of="${corrupt_composite_root}/inputs/plugin-conformance/positive.pcw2" \
  bs=1 seek=100 count=1 conv=notrunc status=none
expect_adapter_rejection "${corrupt_composite_root}" \
  "auxiliary fixture member is not independently reproducible"

# `render` writes the payload, oracle, evidence-status record and composite of one family, and
# they are the checked-in bytes.
rendered_root="${temporary_base}/rendered-plugin-family"
mkdir -p "${rendered_root}/inputs/plugin-conformance"
bash scripts/conformance-fixture-adapters/plugin-signed-v1.sh render \
  "${source_root}/${plugin_provider}" "${source_root}/support/fixture-family-contract.json" \
  plugin-conformance-positive plugin-conformance positive public-plugin-protocol \
  "${rendered_root}/inputs/plugin-conformance/positive.json" "${rendered_root}/oracle.json" \
  "${rendered_root}/evidence.json"
cmp -- "${rendered_root}/inputs/plugin-conformance/positive.json" \
  "${source_root}/inputs/plugin-conformance/positive.json"
cmp -- "${rendered_root}/inputs/plugin-conformance/positive.pcw2" \
  "${source_root}/inputs/plugin-conformance/positive.pcw2"
cmp -- "${rendered_root}/oracle.json" "${source_root}/oracles/plugin-conformance/positive.json"
cmp -- "${rendered_root}/evidence.json" "${source_root}/expected/plugin-conformance/positive.json"

# The metric provider's metric-cbor-v1 adapter (ADR-062 Revision 7 section 6 slice 1, #1211).
metric_provider="providers/metric-conformance/provider.json"
jq -e '.contract_version == "2.0.0" and .fixture_adapter == {id: "metric-cbor-v1", config: {}}' \
  "${source_root}/${metric_provider}" >/dev/null
if grep -rlF 'fixture-ratio' "${source_root}/providers/metric-conformance" \
  "${source_root}/oracles/metric-conformance" "${source_root}/expected/metric-conformance"; then
  echo "a metric provider, oracle or evidence file still carries the fixture-ratio placeholder" >&2
  exit 1
fi

metric_old_contract_root="$(new_fixture_copy metric-old-contract-version)"
replace_json "${metric_old_contract_root}/${metric_provider}" '.contract_version = "1.0.0"'
expect_adapter_rejection "${metric_old_contract_root}" \
  "invalid metric-cbor-v1 fixture adapter declaration"
expect_rejection "${metric_old_contract_root}" \
  "invalid metric-cbor-v1 fixture adapter declaration"

metric_config_root="$(new_fixture_copy metric-adapter-config)"
replace_json "${metric_config_root}/${metric_provider}" '.fixture_adapter.config.operations = {}'
expect_adapter_rejection "${metric_config_root}" \
  "invalid metric-cbor-v1 fixture adapter declaration"

metric_moved_composite_root="$(new_fixture_copy metric-moved-composite)"
replace_json "${metric_moved_composite_root}/${metric_provider}" \
  '.auxiliary.malformed[0].path = "inputs/metric-conformance/elsewhere.mcs1"'
expect_adapter_rejection "${metric_moved_composite_root}" \
  "invalid metric-cbor-v1 fixture adapter declaration"

metric_corrupt_composite_root="$(new_fixture_copy metric-corrupt-composite)"
printf '\x00' | dd of="${metric_corrupt_composite_root}/inputs/metric-conformance/positive.mcs1" \
  bs=1 seek=100 count=1 conv=notrunc status=none
expect_adapter_rejection "${metric_corrupt_composite_root}" \
  "auxiliary fixture member is not independently reproducible"

metric_oracle_root="$(new_fixture_copy metric-edited-oracle)"
sed -i 's/"brier_micros":97500/"brier_micros":97501/' \
  "${metric_oracle_root}/oracles/metric-conformance/positive.json"
expect_adapter_rejection "${metric_oracle_root}" \
  "oracle fixture is not independently reproducible: metric-conformance-positive"

# `render` writes the payload, oracle, evidence-status record and composite of one family, and
# they are the checked-in bytes.
rendered_metric_root="${temporary_base}/rendered-metric-family"
mkdir -p "${rendered_metric_root}/inputs/metric-conformance"
bash scripts/conformance-fixture-adapters/metric-cbor-v1.sh render \
  "${source_root}/${metric_provider}" "${source_root}/support/fixture-family-contract.json" \
  metric-conformance-malformed metric-conformance malformed exported-artifact \
  "${rendered_metric_root}/inputs/metric-conformance/malformed.json" \
  "${rendered_metric_root}/oracle.json" "${rendered_metric_root}/evidence.json"
cmp -- "${rendered_metric_root}/inputs/metric-conformance/malformed.json" \
  "${source_root}/inputs/metric-conformance/malformed.json"
cmp -- "${rendered_metric_root}/inputs/metric-conformance/malformed.mcs1" \
  "${source_root}/inputs/metric-conformance/malformed.mcs1"
cmp -- "${rendered_metric_root}/oracle.json" \
  "${source_root}/oracles/metric-conformance/malformed.json"
cmp -- "${rendered_metric_root}/evidence.json" \
  "${source_root}/expected/metric-conformance/malformed.json"

# The replay provider's replay-cbor-v1 adapter (ADR-062 Revision 8 slice R4, #1222). Provider
# contract 1.0.0 has no reader: a 1.0.0 declaration is rejected.
replay_provider="providers/replay-conformance/provider.json"
jq -e '.contract_version == "2.0.0" and .fixture_adapter == {id: "replay-cbor-v1", config: {}}' \
  "${source_root}/${replay_provider}" >/dev/null
if grep -rlF 'pigloros.fixture.replay-conformance@1.0.0' "${source_root}/inputs/replay-conformance" \
  "${source_root}/providers/replay-conformance" "${source_root}/oracles/replay-conformance"; then
  echo "a replay provider, input or oracle file still names provider contract 1.0.0" >&2
  exit 1
fi

replay_old_contract_root="$(new_fixture_copy replay-old-contract-version)"
replace_json "${replay_old_contract_root}/${replay_provider}" '.contract_version = "1.0.0"'
expect_adapter_rejection "${replay_old_contract_root}" \
  "invalid replay-cbor-v1 fixture adapter declaration"
expect_rejection "${replay_old_contract_root}" \
  "invalid replay-cbor-v1 fixture adapter declaration"

replay_moved_composite_root="$(new_fixture_copy replay-moved-composite)"
replace_json "${replay_moved_composite_root}/${replay_provider}" \
  '.auxiliary.positive[0].path = "inputs/replay-conformance/elsewhere.rcs1"'
expect_adapter_rejection "${replay_moved_composite_root}" \
  "invalid replay-cbor-v1 fixture adapter declaration"

replay_corrupt_composite_root="$(new_fixture_copy replay-corrupt-composite)"
printf '\x00' | dd of="${replay_corrupt_composite_root}/inputs/replay-conformance/positive.rcs1" \
  bs=1 seek=100 count=1 conv=notrunc status=none
expect_adapter_rejection "${replay_corrupt_composite_root}" \
  "auxiliary fixture member is not independently reproducible"

replay_oracle_root="$(new_fixture_copy replay-edited-oracle)"
sed -i 's/"outcome":"VerifiedExact"/"outcome":"Diverged"/' \
  "${replay_oracle_root}/oracles/replay-conformance/positive.json"
expect_adapter_rejection "${replay_oracle_root}" \
  "oracle fixture is not independently reproducible: replay-conformance-positive"

# A W8H1 entry put back to pending, or bound to another file's digest, is rejected.
replay_pending_root="$(new_fixture_copy replay-pending-w8h1)"
replace_json "${replay_pending_root}/expected-authority/inventory.json" \
  '.entries[0].materialization_status = "pending"'
expect_rejection "${replay_pending_root}" \
  "invalid #172 expected-authority inventory lifecycle or entries"
replay_rebound_root="$(new_fixture_copy replay-rebound-w8h1)"
replace_json "${replay_rebound_root}/expected-authority/inventory.json" \
  '.entries[0].fixture_bytes_digest = .entries[3].fixture_bytes_digest'
expect_rejection "${replay_rebound_root}" "W8H1 entry RPL-001 does not bind"

# `render` writes the payload, oracle, evidence-status record and composite of one family, and
# they are the checked-in bytes.
rendered_replay_root="${temporary_base}/rendered-replay-family"
mkdir -p "${rendered_replay_root}/inputs/replay-conformance"
bash scripts/conformance-fixture-adapters/replay-cbor-v1.sh render \
  "${source_root}/${replay_provider}" "${source_root}/support/fixture-family-contract.json" \
  replay-conformance-denied replay-conformance denied exported-artifact \
  "${rendered_replay_root}/inputs/replay-conformance/denied.json" \
  "${rendered_replay_root}/oracle.json" "${rendered_replay_root}/evidence.json"
cmp -- "${rendered_replay_root}/inputs/replay-conformance/denied.json" \
  "${source_root}/inputs/replay-conformance/denied.json"
cmp -- "${rendered_replay_root}/inputs/replay-conformance/denied.rcs1" \
  "${source_root}/inputs/replay-conformance/denied.rcs1"
cmp -- "${rendered_replay_root}/oracle.json" \
  "${source_root}/oracles/replay-conformance/denied.json"
cmp -- "${rendered_replay_root}/evidence.json" \
  "${source_root}/expected/replay-conformance/denied.json"

publication_wrapper_prefix="${temporary_base}/publication-wrapper-prefix.sh"
sed -n '1,/^first_fingerprint=/p' scripts/materialize-conformance-bundles.sh \
  >"${publication_wrapper_prefix}"
if grep -Eq '(\[\[.*publication_parent|mkdir .*publication_parent|realpath .*publication_parent|readlink .*publication_parent)' \
  "${publication_wrapper_prefix}"; then
  echo "materialization wrapper traverses the publication parent before Rust" >&2
  exit 1
fi

echo "conformance fixture validator negative controls passed"
