#!/usr/bin/env bash
set -euo pipefail

fixture_root="${1:-fixtures/conformance}"
profile_root="${fixture_root}/profiles"
mode="${2:---check}"
[[ "${mode}" == "--check" || "${mode}" == "--write" ]] || {
  echo "usage: $0 [fixture-root] [--check|--write]" >&2
  exit 1
}

command -v jq >/dev/null || {
  echo "jq is required to independently regenerate conformance fixture records" >&2
  exit 1
}
command -v b3sum >/dev/null || {
  echo "b3sum is required to independently regenerate conformance inventories" >&2
  exit 1
}

[[ -d "${profile_root}" && -d "${fixture_root}/providers" && -d "${fixture_root}/inputs" && -d "${fixture_root}/expected" ]] || {
  echo "missing conformance fixture directories under ${fixture_root}" >&2
  exit 1
}

generated_root="$(mktemp -d)"
trap 'rm -rf "${generated_root}"' EXIT

generated_count=0
declare -A seen_expected_paths=()
while IFS=$'\t' read -r case_id claim_layer family schema_path input_path expected_path subject_adapter provider_id; do
  [[ -n "${case_id}" && -n "${claim_layer}" && -n "${family}" ]] || {
    echo "profile contains an empty fixture identity" >&2
    exit 1
  }
  [[ "${input_path}" == inputs/* && "${expected_path}" == expected/* ]] || {
    echo "fixture paths must remain under inputs/ and expected/: ${case_id}" >&2
    exit 1
  }
  expected_schema_prefix="providers/${claim_layer}/schemas/"
  [[ "${schema_path}" == "${expected_schema_prefix}${family}.schema.json" && "${schema_path}" != *".."* ]] || {
    echo "fixture schema path must remain provider-owned: ${case_id}" >&2
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
  generated_file="${generated_root}/${expected_path}"
  mkdir -p "$(dirname "${generated_file}")"
  generated_input="${generated_root}/${input_path}"
  mkdir -p "$(dirname "${generated_input}")"
  case "${family}" in
    positive)
      result=accepted
      oracle_kind=canonical-output
      operation=execute-positive-case
      [[ "${subject_adapter}" != "public-plugin-protocol" ]] || operation=describe
      jq -cn --arg case_id "${case_id}" --arg claim_layer "${claim_layer}" --arg family "${family}" --arg provider_contract "${provider_id}@1.0.0" --arg subject_adapter "${subject_adapter}" --arg operation "${operation}" \
        '{case_id:$case_id,claim_layer:$claim_layer,family:$family,provider_contract:$provider_contract,subject_adapter:$subject_adapter,stimulus:{operation:$operation,arguments:{seed:1}},expected:{result:"accepted",post_state:{committed:true}}}' > "${generated_input}"
      ;;
    denied)
      result=rejected
      oracle_kind=namespaced-failure
      code_id=capability-denied
      operation=mutate-subject
      [[ "${subject_adapter}" != "public-plugin-protocol" ]] || operation=drive
      jq -cn --arg case_id "${case_id}" --arg claim_layer "${claim_layer}" --arg family "${family}" --arg provider_contract "${provider_id}@1.0.0" --arg subject_adapter "${subject_adapter}" --arg operation "${operation}" \
        '{case_id:$case_id,claim_layer:$claim_layer,family:$family,provider_contract:$provider_contract,subject_adapter:$subject_adapter,stimulus:{operation:$operation,required_capability:"mutate-subject",pre_state:{revision:1}},expected:{failure_code:"capability-denied",post_state:{revision:1}}}' > "${generated_input}"
      ;;
    malformed)
      result=namespaced-failure
      oracle_kind=namespaced-failure
      code_id=malformed-payload
      if [[ "${subject_adapter}" == "public-plugin-protocol" ]]; then
        jq -cn --arg case_id "${case_id}" --arg claim_layer "${claim_layer}" --arg family "${family}" --arg provider_contract "${provider_id}@1.0.0" --arg subject_adapter "${subject_adapter}" \
          '{case_id:$case_id,claim_layer:$claim_layer,family:$family,provider_contract:$provider_contract,subject_adapter:$subject_adapter,stimulus:{operation:"reduce",payload:"malformed-provider-payload"},expected:{failure_code:"malformed-payload"}}' > "${generated_input}"
      else
        jq -cn --arg case_id "${case_id}" --arg claim_layer "${claim_layer}" --arg family "${family}" --arg provider_contract "${provider_id}@1.0.0" --arg subject_adapter "${subject_adapter}" \
          '{case_id:$case_id,claim_layer:$claim_layer,family:$family,provider_contract:$provider_contract,subject_adapter:$subject_adapter,stimulus:"malformed-provider-payload",expected:{failure_code:"malformed-payload"}}' > "${generated_input}"
      fi
      ;;
    resource-exhaustion)
      result=resource-limit
      oracle_kind=namespaced-failure
      code_id=resource-limit
      operation=consume-execution-steps
      [[ "${subject_adapter}" != "public-plugin-protocol" ]] || operation=drive
      jq -cn --arg case_id "${case_id}" --arg claim_layer "${claim_layer}" --arg family "${family}" --arg provider_contract "${provider_id}@1.0.0" --arg subject_adapter "${subject_adapter}" --arg operation "${operation}" \
        '{case_id:$case_id,claim_layer:$claim_layer,family:$family,provider_contract:$provider_contract,subject_adapter:$subject_adapter,stimulus:{operation:$operation},limit:{kind:"execution-steps",maximum:10000000,requested:10000001},expected:{failure_code:"resource-limit"}}' > "${generated_input}"
      ;;
    deletion-redaction)
      result=destroyed
      oracle_kind=canonical-output
      operation=redact-synthetic-subject
      [[ "${subject_adapter}" != "public-plugin-protocol" ]] || operation=migrate-state
      jq -cn --arg case_id "${case_id}" --arg claim_layer "${claim_layer}" --arg family "${family}" --arg provider_contract "${provider_id}@1.0.0" --arg subject_adapter "${subject_adapter}" --arg operation "${operation}" \
        '{case_id:$case_id,claim_layer:$claim_layer,family:$family,provider_contract:$provider_contract,subject_adapter:$subject_adapter,pre_state:{prohibited_data:"synthetic-secret",retained_metadata:{record_id:"synthetic-1"}},stimulus:{operation:$operation},expected:{post_state:{prohibited_data_present:false,retained_metadata:{record_id:"synthetic-1"}}}}' > "${generated_input}"
      ;;
    downgrade)
      result=not-authorized
      oracle_kind=namespaced-failure
      code_id=incompatible-contract
      operation=verify-release-admission
      [[ "${subject_adapter}" != "public-plugin-protocol" ]] || operation=migrate-state
      jq -cn --arg case_id "${case_id}" --arg claim_layer "${claim_layer}" --arg family "${family}" --arg provider_id "${provider_id}" --arg provider_contract "${provider_id}@1.0.0" --arg subject_adapter "${subject_adapter}" --arg operation "${operation}" \
        '{case_id:$case_id,claim_layer:$claim_layer,family:$family,provider_contract:$provider_contract,subject_adapter:$subject_adapter,stimulus:{operation:$operation,from_provider:{provider_id:$provider_id,contract_version:"1.0.0",abi_major:1,abi_minor:1},to_provider:{provider_id:$provider_id,contract_version:"1.0.0",abi_major:1,abi_minor:0},allow_fallback:false},expected:{failure_code:"incompatible-contract"}}' > "${generated_input}"
      ;;
    independent-evaluation)
      result=corroborated
      oracle_kind=canonical-output
      independent_input="PiglorOS independent fixture ${claim_layer}"
      expected_digest="$(printf '%s' "${independent_input}" | b3sum | awk '{print $1}')"
      if [[ "${subject_adapter}" == "public-plugin-protocol" ]]; then
        jq -cn --arg case_id "${case_id}" --arg claim_layer "${claim_layer}" --arg family "${family}" --arg provider_contract "${provider_id}@1.0.0" --arg subject_adapter "${subject_adapter}" --arg input "${independent_input}" --arg expected_digest "${expected_digest}" \
          '{case_id:$case_id,claim_layer:$claim_layer,family:$family,provider_contract:$provider_contract,subject_adapter:$subject_adapter,stimulus:{operation:"describe"},algorithm:"BLAKE3-256",input:$input,expected_digest:$expected_digest}' > "${generated_input}"
      else
        jq -cn --arg case_id "${case_id}" --arg claim_layer "${claim_layer}" --arg family "${family}" --arg provider_contract "${provider_id}@1.0.0" --arg subject_adapter "${subject_adapter}" --arg input "${independent_input}" --arg expected_digest "${expected_digest}" \
          '{case_id:$case_id,claim_layer:$claim_layer,family:$family,provider_contract:$provider_contract,subject_adapter:$subject_adapter,algorithm:"BLAKE3-256",input:$input,expected_digest:$expected_digest}' > "${generated_input}"
      fi
      ;;
    *)
      echo "unknown public fixture family: ${family}" >&2
      exit 1
      ;;
  esac

  input_blake3_digest="$(b3sum "${generated_input}" | awk '{print $1}')"
  if [[ "${oracle_kind}" == "canonical-output" ]]; then
    oracle="$(jq -cn '{kind:"canonical-output"}')"
  else
    oracle="$(jq -cn --arg owner_id "${provider_id}" --arg code_id "${code_id}" '{kind:"namespaced-failure",owner_id:$owner_id,contract_version:"1.0.0",code_id:$code_id}')"
  fi
  jq -n \
    --arg claim_layer "${claim_layer}" \
    --arg case_id "${case_id}" \
    --arg family "${family}" \
    --arg input_blake3_digest "${input_blake3_digest}" \
    --arg result "${result}" \
    --argjson oracle "${oracle}" \
    '{claim_layer: $claim_layer, case_id: $case_id, family: $family, input_blake3_digest: $input_blake3_digest, result: $result, status: "pending", draft_expected_result: $oracle}' \
    > "${generated_file}"
  if [[ "${mode}" == "--write" ]]; then
    install -m 0644 -- "${generated_input}" "${input_file}"
    install -m 0644 -- "${generated_file}" "${expected_file}"
  else
    cmp -- "${generated_input}" "${input_file}" || {
      echo "input fixture is not independently reproducible: ${case_id}" >&2
      exit 1
    }
    cmp -- "${generated_file}" "${expected_file}" || {
      echo "expected fixture record is not independently reproducible: ${case_id}" >&2
      exit 1
    }
  fi
  generated_count=$((generated_count + 1))
done < <(
  while IFS= read -r -d '' profile; do
    provider_manifest="${fixture_root}/$(jq -r '.fixture_provider_manifest' "${profile}")"
    provider_id="$(jq -r '.provider_id' "${provider_manifest}")"
    subject_adapter="$(jq -r '.subject_adapter' "${profile}")"
    jq -r --arg provider_id "${provider_id}" --arg subject_adapter "${subject_adapter}" \
      '.fixtures[] | [.case_id, .claim_layer, .family, .schema, .input, .expected, $subject_adapter, $provider_id] | @tsv' "${profile}"
  done < <(find "${profile_root}" -mindepth 2 -maxdepth 2 -type f -name profile.json -print0 | sort -z)
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
  find expected-authority expected inputs matrix profiles providers support -type f -print0 |
    sort -z |
    xargs -0 b3sum
) > "${generated_blake3}"
(
  cd "${fixture_root}"
  { printf '%s\0' BLAKE3SUMS; find expected-authority expected inputs matrix profiles providers support -type f -print0; } |
    sort -z |
    xargs -0 sha256sum
) > "${generated_sha256}"
if [[ "${mode}" == "--write" ]]; then
  install -m 0644 -- "${generated_blake3}" "${fixture_root}/BLAKE3SUMS"
  (
    cd "${fixture_root}"
    { printf '%s\0' BLAKE3SUMS; find expected-authority expected inputs matrix profiles providers support -type f -print0; } |
      sort -z |
      xargs -0 sha256sum
  ) > "${generated_sha256}"
  install -m 0644 -- "${generated_sha256}" "${fixture_root}/SHA256SUMS"
else
  cmp -- "${generated_blake3}" "${fixture_root}/BLAKE3SUMS" || {
    echo "BLAKE3SUMS is not independently reproducible" >&2
    exit 1
  }
  cmp -- "${generated_sha256}" "${fixture_root}/SHA256SUMS" || {
    echo "SHA256SUMS is not independently reproducible" >&2
    exit 1
  }
fi

echo "independently regenerated ${generated_count} public fixture records, the Draft authority inventory, and byte inventories"
