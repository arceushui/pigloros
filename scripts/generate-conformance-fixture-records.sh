#!/usr/bin/env bash
set -euo pipefail

fixture_root="${1:-fixtures/conformance}"
profile_root="${fixture_root}/profiles"

command -v jq >/dev/null || {
  echo "jq is required to independently regenerate conformance fixture records" >&2
  exit 1
}
command -v b3sum >/dev/null || {
  echo "b3sum is required to independently regenerate conformance inventories" >&2
  exit 1
}

[[ -d "${profile_root}" && -d "${fixture_root}/inputs" && -d "${fixture_root}/expected" ]] || {
  echo "missing conformance fixture directories under ${fixture_root}" >&2
  exit 1
}

generated_root="$(mktemp -d)"
trap 'rm -rf "${generated_root}"' EXIT

generated_count=0
declare -A seen_expected_paths=()
while IFS=$'\t' read -r case_id claim_layer family schema_path input_path expected_path; do
  [[ -n "${case_id}" && -n "${claim_layer}" && -n "${family}" ]] || {
    echo "profile contains an empty fixture identity" >&2
    exit 1
  }
  [[ "${input_path}" == inputs/* && "${expected_path}" == expected/* ]] || {
    echo "fixture paths must remain under inputs/ and expected/: ${case_id}" >&2
    exit 1
  }
  [[ "${schema_path}" == support/schemas/*.schema.json && "${schema_path}" != *".."* ]] || {
    echo "fixture schema path must remain under support/schemas/: ${case_id}" >&2
    exit 1
  }
  [[ "${input_path}" != *".."* && "${expected_path}" != *".."* ]] || {
    echo "unsafe fixture path: ${case_id}" >&2
    exit 1
  }
  expected_from_input="expected/${input_path#inputs/}"
  [[ "${expected_path}" == "${expected_from_input}" ]] || {
    echo "fixture input/result paths are not paired: ${case_id}" >&2
    exit 1
  }
  [[ -n "${seen_expected_paths[${expected_path}]+seen}" ]] && {
    echo "fixture result path is declared more than once: ${expected_path}" >&2
    exit 1
  }
  seen_expected_paths[${expected_path}]=seen

  input_file="${fixture_root}/${input_path}"
  expected_file="${fixture_root}/${expected_path}"
  schema_file="${fixture_root}/${schema_path}"
  [[ -s "${schema_file}" && -s "${input_file}" && -s "${expected_file}" ]] || {
    echo "missing fixture pair: ${case_id}" >&2
    exit 1
  }
  jq -e --arg family "${family}" \
    '.properties.family.const == $family and .additionalProperties == false' \
    "${schema_file}" >/dev/null || {
    echo "fixture schema does not bind its family: ${case_id}" >&2
    exit 1
  }
  jq -e \
    --arg case_id "${case_id}" \
    --arg claim_layer "${claim_layer}" \
    --arg family "${family}" \
    '.case_id == $case_id and .claim_layer == $claim_layer and .family == $family and
     ((.subject | type) == "string") and (.subject != "") and
     ((.assertion | type) == "string") and (.assertion != "")' \
    "${input_file}" >/dev/null || {
    echo "input fixture does not match its public profile declaration: ${case_id}" >&2
    exit 1
  }

  case "${family}" in
    positive) result=accepted ;;
    denied) result=rejected ;;
    malformed) result=namespaced-failure ;;
    resource-exhaustion) result=resource-limit ;;
    deletion-redaction) result=destroyed ;;
    downgrade) result=not-authorized ;;
    independent-evaluation) result=corroborated ;;
    *)
      echo "unknown public fixture family: ${family}" >&2
      exit 1
      ;;
  esac

  generated_file="${generated_root}/${expected_path}"
  mkdir -p "$(dirname "${generated_file}")"
  generated_input="${generated_root}/${input_path}"
  mkdir -p "$(dirname "${generated_input}")"
  jq -c '.' "${input_file}" > "${generated_input}"
  cmp -- "${generated_input}" "${input_file}" || {
    echo "input fixture is not canonical JSON: ${case_id}" >&2
    exit 1
  }
  input_blake3_digest="$(b3sum "${input_file}" | awk '{print $1}')"
  jq -n \
    --arg claim_layer "${claim_layer}" \
    --arg case_id "${case_id}" \
    --arg family "${family}" \
    --arg input_blake3_digest "${input_blake3_digest}" \
    --arg result "${result}" \
    '{claim_layer: $claim_layer, case_id: $case_id, family: $family, input_blake3_digest: $input_blake3_digest, result: $result, status: "pending", draft_expected_result: {kind: "namespaced-failure", owner_id: "pigloros.core", contract_version: "1.0.0", code_id: "provenance-missing"}}' \
    > "${generated_file}"
  cmp -- "${generated_file}" "${expected_file}" || {
    echo "expected fixture record is not independently reproducible: ${case_id}" >&2
    exit 1
  }
  generated_count=$((generated_count + 1))
done < <(
  find "${profile_root}" -mindepth 2 -maxdepth 2 -type f -name profile.json -print0 |
    sort -z |
    xargs -0 -r jq -r '.fixtures[] | [.case_id, .claim_layer, .family, .schema, .input, .expected] | @tsv'
)

if (( generated_count != 49 )); then
  echo "independently regenerated ${generated_count} fixture records; expected 49" >&2
  exit 1
fi

generated_authority="${generated_root}/expected-authority/inventory.json"
mkdir -p "$(dirname "${generated_authority}")"
jq -n '
  [
    {fixture_id: "RPL-001", execution_class: "RecordedReplay", expected_outcome: "VerifiedExact"},
    {fixture_id: "PRF-001", execution_class: "ProfileRecomputation", expected_outcome: "VerifiedExact"},
    {fixture_id: "PRF-002", execution_class: "CrossProfileConformance", expected_outcome: "VerifiedExact"},
    {fixture_id: "DIV-001", execution_class: "ProfileRecomputation", expected_outcome: "Diverged"},
    {fixture_id: "INV-001", execution_class: "DeterministicProfile", expected_outcome: "InvalidManifest"},
    {fixture_id: "INV-002", execution_class: "DeterministicProfile", expected_outcome: "UnverifiableArtifactsMissing"},
    {fixture_id: "INV-003", execution_class: "DeterministicProfile", expected_outcome: "IncompatibleProfile"},
    {fixture_id: "RES-001", execution_class: "ProfileRecomputation", expected_outcome: "ResourceLimitExceeded"},
    {fixture_id: "LIVE-001", execution_class: "LiveUnverified", expected_outcome: "NonDeterministicAdmission"},
    {fixture_id: "ERA-001", execution_class: "RecordedReplay", expected_outcome: "OutcomePreservedReplayClaimDegraded"},
    {fixture_id: "SEC-001", execution_class: "DeterministicProfile", expected_outcome: "TypedFailure"}
  ] |
  map(. + {
    fixture_bytes_path: null,
    fixture_bytes_digest: null,
    expected_result_path: null,
    expected_result_digest: null,
    materialization_status: "pending"
  }) |
  {
    magic: "W8H1",
    version: 1,
    lifecycle: "Draft",
    digest_algorithm: "BLAKE3-256",
    source: "#172 wave8-execution-repro-handoff-v1",
    entries: .
  }
' > "${generated_authority}"
cmp -- "${generated_authority}" "${fixture_root}/expected-authority/inventory.json" || {
  echo "Draft authority inventory is not independently reproducible" >&2
  exit 1
}

generated_sha256="${generated_root}/SHA256SUMS"
generated_blake3="${generated_root}/BLAKE3SUMS"
(
  cd "${fixture_root}"
  find expected-authority expected inputs matrix profiles support -type f -print0 |
    sort -z |
    xargs -0 b3sum
) > "${generated_blake3}"
(
  cd "${fixture_root}"
  { printf '%s\0' BLAKE3SUMS; find expected-authority expected inputs matrix profiles support -type f -print0; } |
    sort -z |
    xargs -0 sha256sum
) > "${generated_sha256}"
cmp -- "${generated_blake3}" "${fixture_root}/BLAKE3SUMS" || {
  echo "BLAKE3SUMS is not independently reproducible" >&2
  exit 1
}
cmp -- "${generated_sha256}" "${fixture_root}/SHA256SUMS" || {
  echo "SHA256SUMS is not independently reproducible" >&2
  exit 1
}

echo "independently regenerated ${generated_count} public fixture records, the Draft authority inventory, and byte inventories"
