#!/usr/bin/env bash
set -euo pipefail

fixture_root="${1:-fixtures/conformance}"
profile_root="${fixture_root}/profiles"
family_contract="${fixture_root}/support/fixture-family-contract.json"
mode="${2:---check}"

# This command dispatches every provider through its explicitly declared fixture
# adapter. Adapter implementations are reviewed executable contracts under
# scripts/conformance-fixture-adapters; undeclared adapters fail closed.
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
family_names="$(jq -c '[.families[].name]' "${family_contract}")"

validate_json_fixture_adapter() {
  local provider_manifest="$1"
  jq -e --argjson family_names "${family_names}" '
    (.fixture_adapter | keys | sort) == (["config", "id"] | sort) and
    .fixture_adapter.id == "pigloros-json-v1" and
    (.fixture_adapter.config | keys | sort) == (["operations", "payloads"] | sort) and
    (.fixture_adapter.config.operations | keys | sort) == ($family_names | sort) and
    all(.fixture_adapter.config.operations[];
      . == null or (type == "string" and length > 0)) and
    (.fixture_adapter.config.payloads | keys | sort) == ($family_names | sort) and
    all(.fixture_adapter.config.payloads[];
      (keys - ["with_operation", "without_operation"] | length) == 0 and
      (.with_operation | type == "object") and
      ((has("without_operation") | not) or (.without_operation | type == "object"))) and
    .artifact_media_types == {
      schema: "application/schema+json",
      payload: "application/json",
      oracle: "application/json",
      evidence_status: "application/json"
    }
  ' "${provider_manifest}" >/dev/null || {
    echo "invalid pigloros-json-v1 fixture adapter declaration: ${provider_manifest#"${fixture_root}/"}" >&2
    exit 1
  }
}

mapfile -t provider_manifest_paths < <(
  jq -r '.fixture_providers[].manifest' "${profile_root}"/*/profile.json | sort -u
)
for manifest_path in "${provider_manifest_paths[@]}"; do
  [[ "${manifest_path}" == providers/*/provider.json && "/${manifest_path}/" != *"/../"* ]] || {
    echo "unsafe provider manifest path: ${manifest_path}" >&2
    exit 1
  }
  provider_manifest="${fixture_root}/${manifest_path}"
  adapter_id="$(jq -er '.fixture_adapter.id | select(type == "string" and length > 0)' "${provider_manifest}")" || {
    echo "provider fixture adapter declaration is missing or invalid: ${provider_manifest#"${fixture_root}/"}" >&2
    exit 1
  }
  [[ "${adapter_id}" =~ ^[a-z][a-z0-9]*(-[a-z][a-z0-9]*)*$ && ${#adapter_id} -le 64 ]] || {
    echo "provider fixture adapter id must be lowercase kebab-case: ${adapter_id}" >&2
    exit 1
  }
  case "${adapter_id}" in
    pigloros-json-v1) validate_json_fixture_adapter "${provider_manifest}" ;;
    *)
      adapter="scripts/conformance-fixture-adapters/${adapter_id}.sh"
      [[ -f "${adapter}" ]] || {
        echo "unsupported provider fixture adapter: ${adapter_id}" >&2
        exit 1
      }
      bash "${adapter}" validate "${provider_manifest}" "${family_contract}" || {
        echo "invalid ${adapter_id} fixture adapter declaration: ${provider_manifest#"${fixture_root}/"}" >&2
        exit 1
      }
      ;;
  esac
done

generated_root="$(mktemp -d)"
trap 'rm -rf "${generated_root}"' EXIT

generated_count=0
declare -A seen_expected_paths=()

while IFS=$'\t' read -r case_id claim_layer family schema_path declared_schema_path input_path expected_path oracle_path subject_adapter provider_id contract_version abi_major abi_minor schema_media_type payload_media_type oracle_media_type evidence_status_media_type provider_relative adapter_id encoded_payload operation; do
  [[ -n "${case_id}" && -n "${claim_layer}" && -n "${family}" ]] || {
    echo "profile contains an empty fixture identity" >&2
    exit 1
  }
  [[ "${input_path}" == inputs/* && "${expected_path}" == expected/* && "${oracle_path}" == oracles/* ]] || {
    echo "fixture paths must remain under inputs/, expected/, and oracles/: ${case_id}" >&2
    exit 1
  }
  [[ "${schema_path}" == "${declared_schema_path}" && "${schema_path}" == providers/* && "${schema_path}" != *".."* ]] || {
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
  generated_file="${generated_root}/${expected_path}"
  mkdir -p "$(dirname "${generated_file}")"
  generated_input="${generated_root}/${input_path}"
  mkdir -p "$(dirname "${generated_input}")"
  generated_oracle="${generated_root}/${oracle_path}"
  mkdir -p "$(dirname "${generated_oracle}")"
  provider_manifest="${fixture_root}/${provider_relative}"
  if [[ "${adapter_id}" != "pigloros-json-v1" ]]; then
    adapter="scripts/conformance-fixture-adapters/${adapter_id}.sh"
    bash "${adapter}" render "${provider_manifest}" "${family_contract}" \
      "${case_id}" "${claim_layer}" "${family}" "${subject_adapter}" \
      "${generated_input}" "${generated_oracle}" "${generated_file}"
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
    continue
  fi
  jq -e --arg family "${family}" '
    def supported_schema:
      type == "object" and
      ((keys) - ["$schema", "additionalProperties", "const", "maximum", "minLength",
        "minimum", "pattern", "properties", "required", "type"] | length) == 0 and
      ((has("type") | not) or
        (.type == "array" or .type == "boolean" or .type == "integer" or
         .type == "null" or .type == "number" or .type == "object" or
         .type == "string")) and
      ((has("required") | not) or
        ((.required | type) == "array" and
         all(.required[]; type == "string") and
         ((.required | unique | length) == (.required | length)))) and
      ((has("additionalProperties") | not) or
        (.additionalProperties | type == "boolean")) and
      ((has("minimum") | not) or (.minimum | type == "number")) and
      ((has("maximum") | not) or (.maximum | type == "number")) and
      ((has("minLength") | not) or
        (.minLength | type == "number" and . >= 0 and floor == .)) and
      ((has("pattern") | not) or (.pattern | type == "string")) and
      ((.properties // {}) | type == "object") and
      all((.properties // {})[]; supported_schema);
    supported_schema and
    .properties.family.const == $family and .additionalProperties == false
  ' \
    "${schema_file}" >/dev/null || {
    echo "fixture schema uses unsupported JSON adapter semantics: ${case_id}" >&2
    exit 1
  }
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

  if jq -e --slurpfile schema "${schema_file}" '
    def has_json_type($expected):
      if $expected == "integer" then
        type == "number" and floor == .
      else
        type == $expected
      end;
    def validates($schema):
      . as $value |
      ((($schema | has("type")) | not) or has_json_type($schema.type)) and
      ((($schema | has("const")) | not) or $value == $schema.const) and
      ((($schema | has("minimum")) | not) or
        (($value | type) != "number" or $value >= $schema.minimum)) and
      ((($schema | has("maximum")) | not) or
        (($value | type) != "number" or $value <= $schema.maximum)) and
      ((($schema | has("minLength")) | not) or
        (($value | type) != "string" or ($value | length) >= $schema.minLength)) and
      ((($schema | has("pattern")) | not) or
        (($value | type) != "string" or ($value | test($schema.pattern)))) and
      ((($schema | has("required")) | not) or
        (($value | type) != "object" or
         all($schema.required[]; . as $required | $value | has($required)))) and
      ((($schema | has("properties")) | not) or
        (($value | type) != "object" or
         all($schema.properties | to_entries[];
           (.key as $key | .value as $property_schema |
            (($value | has($key) | not) or
             ($value[$key] | validates($property_schema))))))) and
      ((if $schema | has("additionalProperties") then
          $schema.additionalProperties
        else
          true
        end) or
        (($value | type) != "object" or
         all($value | keys[];
           . as $key | ($schema.properties // {}) | has($key))));
    validates($schema[0])
  ' "${generated_input}" >/dev/null; then
    payload_matches_schema=true
  else
    payload_matches_schema=false
  fi
  if [[ "${family}" == "malformed" ]]; then
    [[ "${payload_matches_schema}" == false ]] || {
      echo "malformed fixture unexpectedly satisfies its provider schema: ${case_id}" >&2
      exit 1
    }
  else
    [[ "${payload_matches_schema}" == true ]] || {
      echo "generated fixture does not satisfy its provider schema: ${case_id}" >&2
      exit 1
    }
  fi

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
  jq -e \
    --arg case_id "${case_id}" \
    --arg claim_layer "${claim_layer}" \
    --arg family "${family}" \
    --arg input_blake3_digest "${input_blake3_digest}" \
    '.case_id == $case_id and .claim_layer == $claim_layer and
     .family == $family and .input_blake3_digest == $input_blake3_digest and
     .status == "pending" and .execution_result == null and .executed_at == null and
     (keys | sort) == (["case_id", "claim_layer", "executed_at", "execution_result", "family", "input_blake3_digest", "status"] | sort)' \
    "${generated_file}" >/dev/null || {
    echo "generated evidence-status record is invalid: ${case_id}" >&2
    exit 1
  }
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
    while IFS=$'\t' read -r provider_relative owned_case_ids; do
      provider_manifest="${fixture_root}/${provider_relative}"
      jq -r \
        --argjson owned_case_ids "${owned_case_ids}" \
        --arg provider_relative "${provider_relative}" \
        --slurpfile provider "${provider_manifest}" '
        $provider[0] as $provider |
        .fixtures[] |
        select(.case_id as $case_id | $owned_case_ids | index($case_id)) |
        [
          .case_id, .claim_layer, .family, .schema, $provider.schemas[.family],
          .input, .expected, .oracle,
          $provider.subject_adapter, $provider.provider_id, $provider.contract_version,
          ($provider.abi_major | tostring), ($provider.abi_minor | tostring),
          $provider.artifact_media_types.schema,
          $provider.artifact_media_types.payload,
          $provider.artifact_media_types.oracle,
          $provider.artifact_media_types.evidence_status,
          $provider_relative,
          $provider.fixture_adapter.id,
          ($provider.fixture_adapter.config.payloads[.family] | @base64),
          ($provider.fixture_adapter.config.operations[.family] // "")
        ] | @tsv
      ' "${profile}"
    done < <(jq -r '.fixture_providers[] | [.manifest, (.fixture_case_ids | tojson)] | @tsv' "${profile}")
  done < <(find "${profile_root}" -mindepth 2 -maxdepth 2 -type f -name profile.json -print0 | sort -z)
)

if (( generated_count == 0 )); then
  echo "the fixture tree does not contain fixtures owned by a declared adapter" >&2
  exit 1
fi

generated_authority="${generated_root}/expected-authority/inventory.json"
mkdir -p "$(dirname "${generated_authority}")"
jq -n '
  [
    {fixture_id: "RPL-001", execution_classes: ["RecordedReplay"], profiles: ["replay-v1"], expected_outcome: "VerifiedExact"},
    {fixture_id: "PRF-001", execution_classes: ["ProfileRecomputation"], profiles: ["deterministic-local-v1"], expected_outcome: "VerifiedExact"},
    {fixture_id: "PRF-002", execution_classes: ["CrossProfileConformance"], profiles: ["deterministic-air-gapped-v1", "deterministic-local-v1"], expected_outcome: "VerifiedExact"},
    {fixture_id: "DIV-001", execution_classes: ["ProfileRecomputation"], profiles: ["deterministic-local-v1"], expected_outcome: "Diverged"},
    {fixture_id: "INV-001", execution_classes: ["CrossProfileConformance", "ProfileRecomputation"], profiles: ["deterministic-air-gapped-v1", "deterministic-local-v1"], expected_outcome: "InvalidManifest"},
    {fixture_id: "INV-002", execution_classes: ["CrossProfileConformance", "ProfileRecomputation"], profiles: ["deterministic-air-gapped-v1", "deterministic-local-v1"], expected_outcome: "UnverifiableArtifactsMissing"},
    {fixture_id: "INV-003", execution_classes: ["CrossProfileConformance", "ProfileRecomputation"], profiles: ["deterministic-air-gapped-v1", "deterministic-local-v1"], expected_outcome: "IncompatibleProfile"},
    {fixture_id: "RES-001", execution_classes: ["ProfileRecomputation"], profiles: ["deterministic-local-v1"], expected_outcome: "ResourceLimitExceeded"},
    {fixture_id: "LIVE-001", execution_classes: ["LiveUnverified"], profiles: ["live-local-v1"], expected_outcome: "NonDeterministicAdmission"},
    {fixture_id: "ERA-001", execution_classes: ["RecordedReplay"], profiles: ["replay-v1"], expected_outcome: "OutcomePreservedReplayClaimDegraded"},
    {fixture_id: "SEC-001", execution_classes: ["CrossProfileConformance", "ProfileRecomputation"], profiles: ["deterministic-air-gapped-v1", "deterministic-local-v1"], expected_outcome: "TypedFailure"}
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
if [[ "${mode}" == "--write" ]]; then
  install -m 0644 -- "${generated_authority}" "${fixture_root}/expected-authority/inventory.json"
else
  cmp -- "${generated_authority}" "${fixture_root}/expected-authority/inventory.json" || {
    echo "Draft authority inventory is not independently reproducible" >&2
    exit 1
  }
fi

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
