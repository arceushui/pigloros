#!/usr/bin/env bash
set -euo pipefail

command_name="$1"
provider_manifest="$2"
family_contract="$3"

validate_provider() {
  local fixture_root="${provider_manifest%/providers/*}"
  jq -e --slurpfile families "${family_contract}" '
    .fixture_adapter.id == "opaque-provider-v1" and
    (.fixture_adapter.config.operations | keys | sort) ==
      ([$families[0].families[].name] | sort) and
    (.fixture_adapter.config.payloads | keys | sort) ==
      ([$families[0].families[].name] | sort) and
    all(.fixture_adapter.config.payloads[];
      (keys - ["with_operation", "without_operation"] | length) == 0 and
      (.with_operation | type == "object") and
      ((has("without_operation") | not) or (.without_operation | type == "object")))
  ' "${provider_manifest}" >/dev/null
  while IFS= read -r schema; do
    [[ "$(<"${fixture_root}/${schema}")" == "opaque-schema-v1" ]]
  done < <(jq -r '.schemas[]' "${provider_manifest}")
}

case "${command_name}" in
  validate)
    validate_provider
    ;;
  render)
    validate_provider
    case_id="$4"
    claim_layer="$5"
    family="$6"
    subject_adapter="$7"
    input_path="$8"
    oracle_path="$9"
    evidence_path="${10}"
    provider_id="$(jq -er '.provider_id' "${provider_manifest}")"
    contract_version="$(jq -er '.contract_version' "${provider_manifest}")"
    abi_major="$(jq -er '.abi_major' "${provider_manifest}")"
    abi_minor="$(jq -er '.abi_minor' "${provider_manifest}")"
    operation="$(jq -r --arg family "${family}" '.fixture_adapter.config.operations[$family] // ""' "${provider_manifest}")"
    payload="$(jq -c --arg family "${family}" '.fixture_adapter.config.payloads[$family]' "${provider_manifest}")"
    oracle_kind="$(jq -er --arg family "${family}" '.families[] | select(.name == $family) | .oracle.kind' "${family_contract}")"
    code_id="$(jq -r --arg family "${family}" '.families[] | select(.name == $family) | .oracle.code_id // ""' "${family_contract}")"
    jq -cn \
      --arg case_id "${case_id}" --arg claim_layer "${claim_layer}" \
      --arg family "${family}" --arg provider_id "${provider_id}" \
      --arg contract_version "${contract_version}" --arg subject_adapter "${subject_adapter}" \
      --arg operation "${operation}" --argjson abi_major "${abi_major}" \
      --argjson abi_minor "${abi_minor}" --argjson payload "${payload}" '
      def interpolate:
        if type == "string" then
          if . == "$abi_major" then $abi_major
          elif . == "$abi_minor" then $abi_minor
          elif . == "$abi_minor_next" then ($abi_minor + 1)
          else gsub("\\$operation"; $operation)
            | gsub("\\$provider_id"; $provider_id)
            | gsub("\\$contract_version"; $contract_version)
          end
        elif type == "array" then map(interpolate)
        elif type == "object" then with_entries(.value |= interpolate)
        else . end;
      ($payload | if $operation == "" then .without_operation else .with_operation end | interpolate) as $body |
      {case_id:$case_id, claim_layer:$claim_layer, family:$family,
       provider_contract:($provider_id + "@" + $contract_version), subject_adapter:$subject_adapter,
       opaque_body:($body | @base64)}
    ' >"${input_path}"
    input_digest="$(b3sum "${input_path}" | awk '{print $1}')"
    if [[ "${oracle_kind}" == "canonical-output" ]]; then
      jq -cn --arg case_id "${case_id}" --arg claim_layer "${claim_layer}" \
        --arg family "${family}" --arg input_digest "${input_digest}" \
        '{case_id:$case_id,claim_layer:$claim_layer,family:$family,
          oracle:{kind:"canonical-output"},opaque_input_blake3_digest:$input_digest}' >"${oracle_path}"
    else
      jq -cn --arg case_id "${case_id}" --arg claim_layer "${claim_layer}" \
        --arg family "${family}" --arg owner_id "${provider_id}" \
        --arg contract_version "${contract_version}" --arg code_id "${code_id}" \
        '{case_id:$case_id,claim_layer:$claim_layer,family:$family,
          oracle:{kind:"namespaced-failure",owner_id:$owner_id,
            contract_version:$contract_version,code_id:$code_id}}' >"${oracle_path}"
    fi
    jq -cn --arg case_id "${case_id}" --arg claim_layer "${claim_layer}" \
      --arg family "${family}" --arg input_digest "${input_digest}" \
      '{case_id:$case_id,claim_layer:$claim_layer,family:$family,
        input_blake3_digest:$input_digest,status:"pending",execution_result:null,executed_at:null}' >"${evidence_path}"
    ;;
  *)
    echo "usage: $0 validate|render PROVIDER FAMILY_CONTRACT [...]" >&2
    exit 2
    ;;
esac
