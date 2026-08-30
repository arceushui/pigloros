#!/usr/bin/env bash
set -euo pipefail

fixture_root="${1:-fixtures/conformance}"
profile_root="${fixture_root}/profiles"
family_contract="${fixture_root}/support/fixture-family-contract.json"
mode="${2:---check}"

# This is the current JSON provider adapter. It owns JSON payload expansion and
# JSON-Schema checks; CPF1's generic catalog builder and verifier treat the
# resulting provider artifacts as opaque bytes.
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

[[ -d "${profile_root}" && -d "${fixture_root}/providers" && -d "${fixture_root}/inputs" && -d "${fixture_root}/expected" && -d "${fixture_root}/oracles" && -s "${family_contract}" ]] || {
  echo "missing conformance fixture directories under ${fixture_root}" >&2
  exit 1
}

jq -e '
  .magic == "FFM1" and .version == 1 and
  (.families | type == "array" and length > 0) and
  ([.families[].name] as $names |
    ($names | all(type == "string" and length > 0)) and
    ($names | unique | length == ($names | length))) and
  all(.families[];
    (.operation == "required" or .operation == "optional") and
    (.oracle.kind == "canonical-output" or .oracle.kind == "namespaced-failure") and
    (if .oracle.kind == "namespaced-failure" then
       (.oracle.code_id | type == "string" and length > 0)
     else
       (has("code_id") | not)
     end) and
    (.failure_outcome == "invalid-manifest" or
     .failure_outcome == "incompatible-profile" or
     .failure_outcome == "resource-limit-exceeded") and
    (.replay_claim == "exact" or
     .replay_claim == "exact-authoritative-with-redacted-views" or
     .replay_claim == "incompatible-profile") and
    (.redaction_state == "none" or .redaction_state == "redacted-views") and
    (has("input_with_operation") | not) and
    (has("input_without_operation") | not)
  )
' "${family_contract}" >/dev/null || {
  echo "invalid canonical fixture-family contract" >&2
  exit 1
}

generated_root="$(mktemp -d)"
trap 'rm -rf "${generated_root}"' EXIT

generated_count=0
declare -A seen_expected_paths=()
while IFS=$'\t' read -r case_id claim_layer family schema_path input_path expected_path oracle_path subject_adapter provider_id contract_version abi_major abi_minor encoded_payload operation; do
  [[ -n "${case_id}" && -n "${claim_layer}" && -n "${family}" ]] || {
    echo "profile contains an empty fixture identity" >&2
    exit 1
  }
  [[ "${input_path}" == inputs/* && "${expected_path}" == expected/* && "${oracle_path}" == oracles/* ]] || {
    echo "fixture paths must remain under inputs/, expected/, and oracles/: ${case_id}" >&2
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
  expected_oracle="oracles/${input_path#inputs/}"
  [[ "${oracle_path}" == "${expected_oracle}" ]] || {
    echo "fixture input/oracle paths are not paired: ${case_id}" >&2
    exit 1
  }
  [[ -n "${seen_expected_paths[${expected_path}]+seen}" ]] && {
    echo "fixture result path is declared more than once: ${expected_path}" >&2
    exit 1
  }
  seen_expected_paths[${expected_path}]=seen

  input_file="${fixture_root}/${input_path}"
  expected_file="${fixture_root}/${expected_path}"
  oracle_file="${fixture_root}/${oracle_path}"
  schema_file="${fixture_root}/${schema_path}"
  [[ -s "${schema_file}" ]] &&
    { [[ "${mode}" == "--write" ]] || [[ -s "${input_file}" && -s "${expected_file}" && -s "${oracle_file}" ]]; } || {
    echo "missing fixture pair: ${case_id}" >&2
    exit 1
  }
  jq -e --arg family "${family}" '
    def supported_schema:
      type == "object" and
      ((keys) - ["$schema", "additionalProperties", "const", "maximum", "minLength",
        "minimum", "pattern", "properties", "required", "type"] | length) == 0 and
      ((.properties // {}) | type == "object") and
      all((.properties // {})[]; supported_schema);
    supported_schema and
    .properties.family.const == $family and .additionalProperties == false
  ' \
    "${schema_file}" >/dev/null || {
    echo "fixture schema uses unsupported JSON adapter semantics: ${case_id}" >&2
    exit 1
  }
  generated_file="${generated_root}/${expected_path}"
  mkdir -p "$(dirname "${generated_file}")"
  generated_input="${generated_root}/${input_path}"
  mkdir -p "$(dirname "${generated_input}")"
  generated_oracle="${generated_root}/${oracle_path}"
  mkdir -p "$(dirname "${generated_oracle}")"
  family_metadata="$(jq -ce --arg family "${family}" '.families[] | select(.name == $family)' "${family_contract}")" || {
    echo "profile declares an unknown fixture family: ${case_id}" >&2
    exit 1
  }
  operation_requirement="$(jq -r '.operation' <<<"${family_metadata}")"
  if [[ "${operation_requirement}" == "required" && -z "${operation}" ]]; then
    echo "provider omits required fixture operation: ${case_id}" >&2
    exit 1
  fi
  oracle_kind="$(jq -r '.oracle.kind' <<<"${family_metadata}")"
  code_id="$(jq -r '.oracle.code_id // empty' <<<"${family_metadata}")"
  payload_metadata="$(printf '%s' "${encoded_payload}" | base64 --decode)"
  jq -cn \
    --arg case_id "${case_id}" \
    --arg claim_layer "${claim_layer}" \
    --arg family "${family}" \
    --arg provider_id "${provider_id}" \
    --arg contract_version "${contract_version}" \
    --arg provider_contract "${provider_id}@${contract_version}" \
    --arg subject_adapter "${subject_adapter}" \
    --arg operation "${operation}" \
    --argjson abi_major "${abi_major}" \
    --argjson abi_minor "${abi_minor}" \
      --argjson payload_metadata "${payload_metadata}" '
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
        else .
        end;
      ($payload_metadata |
        if $operation == "" then .without_operation else .with_operation end |
        interpolate) as $payload |
      if ($payload | type) != "object" then error("fixture payload must be an object") else
        {
          case_id: $case_id,
          claim_layer: $claim_layer,
          family: $family,
          provider_contract: $provider_contract,
          subject_adapter: $subject_adapter
        } + $payload
      end
    ' > "${generated_input}"

  input_blake3_digest="$(b3sum "${generated_input}" | awk '{print $1}')"
  if [[ "${oracle_kind}" == "canonical-output" ]]; then
    jq -c '{case_id,claim_layer,family,oracle:{kind:"canonical-output"},output:(.expected // {algorithm,expected_digest})}' \
      "${generated_input}" > "${generated_oracle}"
  else
    jq -cn --arg case_id "${case_id}" --arg claim_layer "${claim_layer}" --arg family "${family}" --arg owner_id "${provider_id}" --arg contract_version "${contract_version}" --arg code_id "${code_id}" \
      '{case_id:$case_id,claim_layer:$claim_layer,family:$family,oracle:{kind:"namespaced-failure",owner_id:$owner_id,contract_version:$contract_version,code_id:$code_id}}' \
      > "${generated_oracle}"
  fi
  jq -n \
    --arg claim_layer "${claim_layer}" \
    --arg case_id "${case_id}" \
    --arg family "${family}" \
    --arg input_blake3_digest "${input_blake3_digest}" \
    '{claim_layer: $claim_layer, case_id: $case_id, family: $family, input_blake3_digest: $input_blake3_digest, status: "pending", execution_result: null, executed_at: null}' \
    > "${generated_file}"
  if [[ "${mode}" == "--write" ]]; then
    install -m 0644 -- "${generated_input}" "${input_file}"
    install -m 0644 -- "${generated_file}" "${expected_file}"
    install -m 0644 -- "${generated_oracle}" "${oracle_file}"
  else
    cmp -- "${generated_input}" "${input_file}" || {
      echo "input fixture is not independently reproducible: ${case_id}" >&2
      exit 1
    }
    cmp -- "${generated_file}" "${expected_file}" || {
      echo "expected fixture record is not independently reproducible: ${case_id}" >&2
      exit 1
    }
    cmp -- "${generated_oracle}" "${oracle_file}" || {
      echo "oracle fixture is not independently reproducible: ${case_id}" >&2
      exit 1
    }
  fi
  generated_count=$((generated_count + 1))
done < <(
  while IFS= read -r -d '' profile; do
    provider_manifest="${fixture_root}/$(jq -r '.fixture_provider_manifest' "${profile}")"
    jq -r --slurpfile provider "${provider_manifest}" '
      $provider[0] as $provider |
      .fixtures[] |
      [
        .case_id, .claim_layer, .family, .schema, .input, .expected, .oracle,
        $provider.subject_adapter, $provider.provider_id, $provider.contract_version,
        ($provider.abi_major | tostring), ($provider.abi_minor | tostring),
        ($provider.fixture_payloads[.family] | @base64),
        ($provider.fixture_operations[.family] // "")
      ] | @tsv
    ' "${profile}"
  done < <(find "${profile_root}" -mindepth 2 -maxdepth 2 -type f -name profile.json -print0 | sort -z)
)

expected_count="$(find "${profile_root}" -mindepth 2 -maxdepth 2 -type f -name profile.json -print0 | xargs -0 jq '[.fixtures[]] | length' | awk '{total += $1} END {print total + 0}')"
if (( generated_count != expected_count || generated_count == 0 )); then
  echo "independently regenerated ${generated_count} fixture records; expected ${expected_count}" >&2
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
  find expected-authority expected inputs matrix oracles profiles providers support -type f -print0 |
    sort -z |
    xargs -0 b3sum
) > "${generated_blake3}"
(
  cd "${fixture_root}"
  { printf '%s\0' BLAKE3SUMS; find expected-authority expected inputs matrix oracles profiles providers support -type f -print0; } |
    sort -z |
    xargs -0 sha256sum
) > "${generated_sha256}"
if [[ "${mode}" == "--write" ]]; then
  install -m 0644 -- "${generated_blake3}" "${fixture_root}/BLAKE3SUMS"
  (
    cd "${fixture_root}"
    { printf '%s\0' BLAKE3SUMS; find expected-authority expected inputs matrix oracles profiles providers support -type f -print0; } |
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
