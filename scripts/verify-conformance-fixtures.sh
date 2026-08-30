#!/usr/bin/env bash
set -euo pipefail

fixture_root="${1:-fixtures/conformance}"
family_contract="${fixture_root}/support/fixture-family-contract.json"

command -v b3sum >/dev/null || {
  echo "b3sum is required to independently verify BLAKE3 authority digests" >&2
  exit 1
}
command -v jq >/dev/null || {
  echo "jq is required to validate conformance fixture JSON" >&2
  exit 1
}

if [[ ! -d "${fixture_root}/inputs" || ! -d "${fixture_root}/expected" || ! -d "${fixture_root}/oracles" || ! -d "${fixture_root}/providers" || ! -d "${fixture_root}/support" || ! -s "${family_contract}" ]]; then
  echo "missing conformance fixture directories under ${fixture_root}" >&2
  exit 1
fi

jq -e '
  (keys | sort) == (["families", "magic", "version"] | sort) and
  .magic == "FFM1" and .version == 1 and
  (.families | type == "array" and length > 0) and
  ([.families[].name] as $names |
    ($names | all(type == "string" and length > 0)) and
    ($names | unique | length == ($names | length))) and
  all(.families[];
    (keys | sort) == (["name", "operation", "oracle"] | sort) and
    (.operation == "required" or .operation == "optional") and
    (.oracle.kind == "canonical-output" or .oracle.kind == "namespaced-failure") and
    (if .oracle.kind == "namespaced-failure" then
       (.oracle | keys | sort) == (["code_id", "kind"] | sort) and
       (.oracle.code_id | type == "string" and length > 0)
     else
       (.oracle | keys) == ["kind"]
     end) and
    (has("input_with_operation") | not) and
    (has("input_without_operation") | not)
  )
' "${family_contract}" >/dev/null || {
  echo "invalid canonical fixture-family contract" >&2
  exit 1
}
family_names="$(jq -c '[.families[].name]' "${family_contract}")"
family_count="$(jq '.families | length' "${family_contract}")"

matrix_path="${fixture_root}/matrix/execution-matrix.json"
authority_path="${fixture_root}/expected-authority/inventory.json"
draft_authority_path="${fixture_root}/support/draft-execution-authority.json"
[[ -s "${matrix_path}" && -s "${authority_path}" && -s "${draft_authority_path}" ]] || {
  echo "missing conformance inventory artifacts" >&2
  exit 1
}

matrix_lifecycle="$(jq -r '.lifecycle' "${matrix_path}")"
case "${matrix_lifecycle}" in
  Draft) ;;
  *)
    echo "invalid ADR-059 matrix lifecycle: ${matrix_lifecycle}" >&2
    exit 1
    ;;
esac

jq -e --arg matrix_lifecycle "${matrix_lifecycle}" \
  '
  . as $root |
  ($root | keys | sort) == ([
    "case_count", "cases", "equality_predicates", "executed_case_count",
    "expected_result_policy", "lifecycle", "magic", "matrix_id", "mode_count",
    "row_count", "rows", "source", "variant_count", "version"
  ] | sort) and
  $root.magic == "NIM1" and $root.version == 1 and $root.lifecycle == $matrix_lifecycle and
  $root.row_count == 12 and $root.variant_count == 4 and $root.mode_count == 4 and
  $root.case_count == 192 and ($root.rows | length == 12) and
  ([$root.rows[].fixture_id] == [
    "NI-TOOL-001", "NI-CACHE-002", "NI-STATE-003", "NI-OBS-004",
    "NI-TIME-005", "NI-PUBLIC-006", "NI-EVAL-007", "NI-FORK-008",
    "NI-ARCHIVE-009", "NI-NET-010", "NI-SERVICE-011", "NI-CRASH-012"
  ]) and
  ([$root.rows[].fixture_id] | unique | length == 12) and
  ($root.equality_predicates | length == 12) and
  ([$root.equality_predicates[].fixture_id] == [$root.rows[].fixture_id]) and
  all($root.equality_predicates[];
    (keys | sort) == (["AuthEq", "OpEq", "PublicEq", "fixture_id"] | sort) and
    (.AuthEq | type == "string") and
    (.PublicEq | type == "string") and
    (.OpEq | type == "string")
  ) and
  ($root.cases | length == 192) and
  ([$root.cases[].case_id] | unique | length == 192) and
  all($root.rows[];
    (keys | sort) == ([
      "case_count", "channel", "classification", "equality", "executed_case_count",
      "fixture_id", "modes", "observable_surfaces", "sole_unauthorized_delta", "variants"
    ] | sort) and
    (.fixture_id | test("^NI-[A-Z]+-[0-9]{3}$")) and
    (.variants == ["S", "D", "W", "C"]) and
    (.modes == ["L", "A", "R", "F"]) and .case_count == 16 and
    .executed_case_count == 0) and
  all($root.cases[];
    (keys | sort) == ([
      "authority_fixture_id", "authority_result_digest", "case_id", "executed",
      "expected_result", "expected_result_digest", "fixture_id", "mode", "variant"
    ] | sort) and
    (.fixture_id | test("^NI-[A-Z]+-[0-9]{3}$")) and
    (.variant | IN("S", "D", "W", "C")) and
    (.mode | IN("L", "A", "R", "F")) and
    .case_id == ("\(.fixture_id)-\(.variant)-\(.mode)") and
    .executed == false and .expected_result_digest == null and
    .authority_fixture_id == null and .authority_result_digest == null and
    .expected_result == null)
  and .executed_case_count == 0
  and all($root.rows[]; . as $row | ([$root.cases[] | select(.fixture_id == $row.fixture_id)] | length == 16))
' "${matrix_path}" >/dev/null || {
  echo "invalid ADR-059 matrix inventory" >&2
  exit 1
}

jq -e '
  (keys | sort) == (["digest_algorithm", "entries", "lifecycle", "magic", "source", "version"] | sort) and
  .magic == "W8H1" and .version == 1 and
  .lifecycle == "Draft" and
  .digest_algorithm == "BLAKE3-256" and
  (.entries | length == 11) and
  ([.entries[].fixture_id] == [
    "RPL-001", "PRF-001", "PRF-002", "DIV-001", "INV-001", "INV-002",
    "INV-003", "RES-001", "LIVE-001", "ERA-001", "SEC-001"
  ]) and
  ([.entries[].fixture_id] | unique | length == 11) and
  all(.entries[];
    (keys | sort) == ([
      "execution_class", "expected_outcome", "expected_result_digest",
      "expected_result_path", "fixture_bytes_digest", "fixture_bytes_path",
      "fixture_id", "materialization_status"
    ] | sort) and
    (.fixture_bytes_path == null) and (.expected_result_path == null) and
    (.fixture_bytes_digest == null) and (.expected_result_digest == null) and
    .materialization_status == "pending"
  )
' "${authority_path}" >/dev/null || {
  echo "invalid #172 expected-authority inventory lifecycle or entries" >&2
  exit 1
}

jq -e '
  (keys | sort) == ([
    "authority_kind", "effective_timeline_position", "execution_profiles",
    "fixture_authority_key_id", "fixture_authority_public_key_hex", "lifecycle",
    "magic", "offline_valid_through", "trust_policy_epoch", "trust_policy_id", "version"
  ] | sort) and
  all(.execution_profiles[];
    (keys | sort) == ([
      "capability_ids", "network_allowed", "profile_id", "reproducibility_classes",
      "semantic_version"
    ] | sort))
' "${draft_authority_path}" >/dev/null || {
  echo "invalid Draft authority declaration fields" >&2
  exit 1
}

authority_lifecycle="$(jq -r '.lifecycle' "${authority_path}")"
if [[ "${authority_lifecycle}" != "${matrix_lifecycle}" ]]; then
  echo "authority inventory and ADR-059 matrix lifecycles disagree" >&2
  exit 1
fi
authority_inventory_sha256="$(sha256sum "${authority_path}" | awk '{print $1}')"
matrix_blake3_digest="$(b3sum "${matrix_path}" | awk '{print $1}')"

mapfile -t inputs < <(find "${fixture_root}/inputs" -type f -print | sort)
mapfile -t expected < <(find "${fixture_root}/expected" -type f -print | sort)
mapfile -t oracles < <(find "${fixture_root}/oracles" -type f -print | sort)

if (( ${#inputs[@]} != 49 || ${#expected[@]} != 49 || ${#oracles[@]} != 49 )); then
  echo "expected exactly 49 layer-specific input, evidence-status, and oracle records" >&2
  exit 1
fi

profile_root="${fixture_root}/profiles"
mapfile -t profile_layers < <(
  find "${profile_root}" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | LC_ALL=C sort
)
if (( ${#profile_layers[@]} != 7 )); then
  echo "expected exactly seven public profile manifests" >&2
  exit 1
fi
declare -A profile_wire_codes=()
for layer in "${profile_layers[@]}"; do
  profile="${profile_root}/${layer}/profile.json"
  [[ -s "${profile}" ]] || {
    echo "missing public profile manifest for ${layer}" >&2
    exit 1
  }
  wire_code="$(jq -r '.wire_code' "${profile}")"
  [[ "${wire_code}" =~ ^[0-6]$ ]] && [[ -z "${profile_wire_codes[${wire_code}]:-}" ]] || {
    echo "invalid or duplicate public profile wire code for ${layer}" >&2
    exit 1
  }
  profile_wire_codes["${wire_code}"]=1
  jq -e \
    --arg layer "${layer}" \
    --arg authority "expected-authority/inventory.json" \
    --arg authority_sha256 "${authority_inventory_sha256}" \
    --arg matrix "matrix/execution-matrix.json" \
    --arg matrix_lifecycle "${matrix_lifecycle}" \
    --arg matrix_blake3 "${matrix_blake3_digest}" \
    --argjson wire_code "${wire_code}" \
    --argjson matrix_size "$(wc -c < "${matrix_path}")" \
    --argjson family_names "${family_names}" \
    --argjson family_count "${family_count}" \
    '((keys | sort) == (([
        "authority_inventory", "authority_inventory_sha256_digest", "bundle_modes",
        "claim_layer", "execution_profiles", "fixture_provider_manifest", "fixture_root",
        "fixtures", "profile_id", "subject_adapter", "wire_code"
      ] + (if $layer == "knowledge-non-interference" then [
        "adr_059_execution_matrix", "adr_059_execution_matrix_blake3_digest",
        "adr_059_execution_matrix_status", "matrix", "matrix_blake3_digest", "matrix_size_bytes"
      ] else [] end)) | sort)) and
      .claim_layer == $layer and
      .wire_code == $wire_code and .fixture_root == $layer and
      (.subject_adapter | type == "string" and length > 0) and
      .authority_inventory == $authority and .authority_inventory_sha256_digest == $authority_sha256 and
      (.execution_profiles | length == 2) and (.bundle_modes | length == 2) and
      (.fixtures | length == $family_count) and
      all(.fixtures[];
        (keys | sort) == (["case_id", "claim_layer", "expected", "family", "input", "oracle", "schema"] | sort)) and
      all(.fixtures[]; .claim_layer == $layer) and
      all(.fixtures[]; .schema == ("providers/" + $layer + "/schemas/" + .family + ".schema.json")) and
      [.fixtures[].family] == $family_names and
      .fixture_provider_manifest == ("providers/" + $layer + "/provider.json") and
      (if $layer == "knowledge-non-interference" then
        .adr_059_execution_matrix == $matrix and
        .adr_059_execution_matrix_blake3_digest == $matrix_blake3 and
        .adr_059_execution_matrix_status == $matrix_lifecycle and
        .matrix == $matrix and .matrix_size_bytes == $matrix_size and
        .matrix_blake3_digest == $matrix_blake3
       else
        (has("adr_059_execution_matrix") | not) and
        (has("adr_059_execution_matrix_blake3_digest") | not) and
        (has("adr_059_execution_matrix_status") | not) and
        (has("matrix") | not) and (has("matrix_size_bytes") | not) and
        (has("matrix_blake3_digest") | not)
       end)' \
    "${profile}" >/dev/null || {
    echo "invalid public profile manifest for ${layer}" >&2
    exit 1
  }
  provider_manifest="${fixture_root}/$(jq -r '.fixture_provider_manifest' "${profile}")"
  [[ -s "${provider_manifest}" ]] || {
    echo "missing provider manifest for ${layer}" >&2
    exit 1
  }
  jq -e --arg layer "${layer}" --argjson family_names "${family_names}" --argjson family_count "${family_count}" \
    '(keys | sort) == ([
       "abi_major", "abi_minor", "artifact_media_types", "claim_layer", "contract_version", "fixture_contracts",
       "fixture_operations", "fixture_payloads", "package_path", "provider_id", "schemas",
       "subject_adapter"
     ] | sort) and
     .claim_layer == $layer and
     (.provider_id | type == "string" and length > 0) and
     (.contract_version | type == "string" and length > 0) and
     (.abi_major | type == "number") and (.abi_minor | type == "number") and
     (.package_path | type == "string" and length > 0) and
     (.artifact_media_types | keys | sort) == (["oracle", "payload", "schema"] | sort) and
     all(.artifact_media_types[];
       type == "string" and length > 2 and length <= 127 and
       test("^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")) and
     (.subject_adapter | type == "string" and length > 0) and
     (.fixture_operations | keys | sort) == ($family_names | sort) and
     all(.fixture_operations[]; . == null or (type == "string" and length > 0)) and
     (.fixture_payloads | keys | sort) == ($family_names | sort) and
     all(.fixture_payloads[];
       (.with_operation | type == "object") and
       ((has("without_operation") | not) or (.without_operation | type == "object"))
     ) and
     (.schemas | length == $family_count) and
     (.fixture_contracts | keys | sort) == ($family_names | sort) and
     all(.fixture_contracts[];
       (keys | sort) == (["deterministic_budget", "minimum_capability_ids", "network_allowed", "watchdog_ms"] | sort) and
       (.deterministic_budget | keys | sort) == ([
         "memory_bytes", "cpu_fuel", "host_calls", "event_count",
         "output_bytes", "storage_bytes", "execution_steps", "simulation_time_ns"
       ] | sort) and
       all(.deterministic_budget[]; type == "number" and . >= 0 and floor == .) and
       (.watchdog_ms | type == "number" and . > 0 and floor == .) and
       (.network_allowed | type == "boolean") and
       (.minimum_capability_ids | type == "array") and
       all(.minimum_capability_ids[]; type == "string" and length > 0) and
       (.minimum_capability_ids == (.minimum_capability_ids | unique | sort))
     )' "${provider_manifest}" >/dev/null || {
    echo "invalid provider manifest for ${layer}" >&2
    exit 1
  }
  subject_adapter="$(jq -r '.subject_adapter' "${provider_manifest}")"
  jq -e --arg subject_adapter "${subject_adapter}" '.subject_adapter == $subject_adapter' "${profile}" >/dev/null || {
    echo "profile subject adapter does not match its provider manifest: ${layer}" >&2
    exit 1
  }
  while IFS=$'\t' read -r case_id fixture_layer family schema_path input_path expected_path oracle_path; do
    family_metadata="$(jq -ce --arg family "${family}" '.families[] | select(.name == $family)' "${family_contract}")" || {
      echo "profile declares an unknown fixture family: ${case_id}" >&2
      exit 1
    }
    [[ -n "${family_metadata}" ]] || exit 1
    for path in "${schema_path}" "${input_path}" "${expected_path}" "${oracle_path}"; do
      [[ "${path}" != /* && "${path}" != *".."* ]] || {
        echo "unsafe profile fixture path for ${layer}: ${path}" >&2
        exit 1
      }
      [[ -s "${fixture_root}/${path}" ]] || {
        echo "missing profile fixture for ${layer}: ${path}" >&2
        exit 1
      }
    done
    # Provider schema, payload, and oracle bytes are opaque to CPF1. The
    # provider-specific generator validates the current JSON adapter.
    input_blake3_digest="$(b3sum "${fixture_root}/${input_path}" | awk '{print $1}')"
    jq -e \
      --arg case_id "${case_id}" \
      --arg fixture_layer "${fixture_layer}" \
      --arg family "${family}" \
      --arg input_blake3_digest "${input_blake3_digest}" \
      '.case_id == $case_id and .claim_layer == $fixture_layer and
       .family == $family and
       .input_blake3_digest == $input_blake3_digest and
       .status == "pending" and
       .execution_result == null and .executed_at == null and
       (has("result") | not) and (has("draft_expected_result") | not) and
       (keys | sort) == (["case_id", "claim_layer", "executed_at", "execution_result", "family", "input_blake3_digest", "status"] | sort)' \
      "${fixture_root}/${expected_path}" >/dev/null || {
      echo "invalid pending evidence-status record for ${layer}: ${expected_path}" >&2
      exit 1
    }
  done < <(jq -r '.fixtures[] | [.case_id, .claim_layer, .family, .schema, .input, .expected, .oracle] | @tsv' "${profile}")
done
for wire_code in {0..6}; do
  [[ -n "${profile_wire_codes[${wire_code}]:-}" ]] || {
    echo "missing public profile wire code ${wire_code}" >&2
    exit 1
  }
done

mapfile -t declared_inputs < <(
  for profile in "${profile_root}"/*/profile.json; do
    jq -r '.fixtures[].input' "${profile}"
  done | sort -u
)
mapfile -t declared_expected < <(
  for profile in "${profile_root}"/*/profile.json; do
    jq -r '.fixtures[].expected' "${profile}"
  done | sort -u
)
mapfile -t declared_oracles < <(
  for profile in "${profile_root}"/*/profile.json; do
    jq -r '.fixtures[].oracle' "${profile}"
  done | sort -u
)
if (( ${#declared_inputs[@]} != 49 || ${#declared_expected[@]} != 49 || ${#declared_oracles[@]} != 49 )); then
  echo "expected every layer-specific fixture triple to be declared exactly once" >&2
  exit 1
fi

mapfile -t actual_input_paths < <(find "${fixture_root}/inputs" -type f -printf 'inputs/%P\n' | sort)
mapfile -t actual_expected_paths < <(find "${fixture_root}/expected" -type f -printf 'expected/%P\n' | sort)
mapfile -t actual_oracle_paths < <(find "${fixture_root}/oracles" -type f -printf 'oracles/%P\n' | sort)
if ! diff -u \
  <(printf '%s\n' "${actual_input_paths[@]}") \
  <(printf '%s\n' "${declared_inputs[@]}") >/dev/null ||
  ! diff -u \
  <(printf '%s\n' "${actual_expected_paths[@]}") \
  <(printf '%s\n' "${declared_expected[@]}") >/dev/null ||
  ! diff -u \
  <(printf '%s\n' "${actual_oracle_paths[@]}") \
  <(printf '%s\n' "${declared_oracles[@]}") >/dev/null; then
  echo "profile manifests do not declare the complete fixture inventory" >&2
  exit 1
fi

if [[ ! -s "${fixture_root}/SHA256SUMS" || ! -s "${fixture_root}/BLAKE3SUMS" ]]; then
  echo "missing conformance fixture digest inventory" >&2
  exit 1
fi

jq -e \
  --arg authority_lifecycle "${authority_lifecycle}" \
  --arg matrix_lifecycle "${matrix_lifecycle}" \
  --arg matrix_blake3 "${matrix_blake3_digest}" '
  .authority_inventory.path == "expected-authority/inventory.json" and
  .authority_inventory.digest_algorithm == "SHA-256" and
  .authority_inventory.status == $authority_lifecycle and
  .adr_059_execution_matrix.path == "matrix/execution-matrix.json" and
  .adr_059_execution_matrix.digest_algorithm == "BLAKE3-256" and
  .adr_059_execution_matrix.blake3_digest == $matrix_blake3 and
  .adr_059_execution_matrix.status == $matrix_lifecycle and
  .adr_059_execution_matrix.executed_case_count == 0
' "${fixture_root}/support/publication-review.json" >/dev/null || {
  echo "Draft authority handoff metadata is invalid" >&2
  exit 1
}

jq -e --arg authority_sha256 "${authority_inventory_sha256}" \
  '.authority_inventory.sha256_digest == $authority_sha256' \
  "${fixture_root}/support/publication-review.json" >/dev/null || {
  echo "profile-bound authority inventory digest is incorrect" >&2
  exit 1
}

(cd "${fixture_root}" && sha256sum --check --strict SHA256SUMS)
(cd "${fixture_root}" && b3sum --check BLAKE3SUMS)

mapfile -t blake3_paths < <(
  sed -E 's/^[0-9a-f]{64}  //' "${fixture_root}/BLAKE3SUMS" | sort
)
mapfile -t expected_blake3_paths < <(
  cd "${fixture_root}" &&
    find expected-authority expected inputs matrix oracles profiles providers support \
      -type f -printf '%p\n' | sort
)
if ! diff -u \
  <(printf '%s\n' "${expected_blake3_paths[@]}") \
  <(printf '%s\n' "${blake3_paths[@]}") >/dev/null; then
  echo "BLAKE3SUMS does not cover the complete public fixture inventory" >&2
  exit 1
fi

for input in "${inputs[@]}"; do
  relative_path="${input#"${fixture_root}/inputs/"}"
  expected_path="${fixture_root}/expected/${relative_path}"
  oracle_path="${fixture_root}/oracles/${relative_path}"
  [[ -f "${expected_path}" && -f "${oracle_path}" ]] || {
    echo "missing evidence-status or oracle pair for ${input}" >&2
    exit 1
  }
done

publishable_roots=(
  "${fixture_root}/inputs"
  "${fixture_root}/expected"
  "${fixture_root}/oracles"
  "${fixture_root}/profiles"
  "${fixture_root}/matrix"
  "${fixture_root}/expected-authority"
  "${fixture_root}/providers"
  "${fixture_root}/support"
)
if [[ -d "${fixture_root}/published" ]]; then
  publishable_roots+=("${fixture_root}/published")
fi
secret_pattern='-----BEGIN[[:space:]]+[A-Z0-9 -]*PRIVATE KEY-----|"(api[_-]?key|apikey|password|credential|credentials|access[_-]?token|refresh[_-]?token|authorization|bearer[_-]?token|client[_-]?secret|subject[_-]?secret|private[_-]?key|privatekey|secret)([_-]?digest)?"[[:space:]]*:[[:space:]]*"[^"[:space:]]+"|(Bearer|Basic)[[:space:]]+[A-Za-z0-9._~+/=-]{16,}|(AKIA|ASIA)[0-9A-Z]{16}|(gh[pousr]_|github_pat_|glpat-|xox[baprs]-|sk_(live|test)_|AIza)[A-Za-z0-9._-]{16,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'

json_secret_query='
  def normalized: ascii_downcase | gsub("-"; "_");
  def sensitive:
    (normalized) as $key |
    $key == "api_key" or $key == "apikey" or $key == "password" or
    $key == "credential" or $key == "credentials" or
    $key == "access_token" or $key == "refresh_token" or
    $key == "authorization" or $key == "bearer_token" or
    $key == "client_secret" or $key == "subject_secret" or
    $key == "private_key" or $key == "privatekey" or
    $key == "secret" or $key == "token";
  def sensitive_digest:
    (normalized) as $key |
    ($key | endswith("_digest")) and
    (($key | sub("_digest$"; "")) | sensitive);
  def empty_sensitive_value:
    . == null or (type == "string" and . == "");
  def contains_secret:
    if type == "object" then
      any(to_entries[];
        ((.key | sensitive) and ((.value | empty_sensitive_value) | not)) or
        (.key | sensitive_digest) or
        (.value | contains_secret))
    elif type == "array" then
      any(.[]; contains_secret)
    else false
    end;
  contains_secret
'
for root in "${publishable_roots[@]}"; do
  while IFS= read -r -d '' symlink_path; do
    echo "symlinks are not allowed in public conformance fixtures: ${symlink_path}" >&2
    exit 1
  done < <(find -P "${root}" -type l -print0)

  while IFS= read -r -d '' json_file; do
    if jq -e "${json_secret_query}" "${json_file}" >/dev/null; then
      echo "forbidden secret material found in JSON fixture: ${json_file}" >&2
      exit 1
    else
      scan_status=$?
      if (( scan_status != 1 )); then
        echo "secret scan could not parse JSON fixture: ${json_file}" >&2
        exit "${scan_status}"
      fi
    fi
  done < <(find -P "${root}" -type f -name '*.json' -print0)
done

mapfile -d '' publishable_files < <(
  for root in "${publishable_roots[@]}"; do
    find -P "${root}" -type f -print0
  done
)
for publishable_file in "${publishable_files[@]}"; do
  if grep -n -i -I -E -- "${secret_pattern}" "${publishable_file}"; then
    echo "forbidden secret material found in public conformance fixtures" >&2
    exit 1
  else
    scan_status=$?
    if (( scan_status != 1 )); then
      echo "secret scan could not inspect all publishable conformance fixtures" >&2
      exit "${scan_status}"
    fi
  fi
done

mapfile -t profiles < <(find "${profile_root}" -type f -print | sort)
if (( ${#profiles[@]} != 7 )); then
  echo "expected exactly seven public profile manifests" >&2
  exit 1
fi

mapfile -t support < <(find "${fixture_root}/support" -type f -print | sort)
mapfile -t provider_files < <(find "${fixture_root}/providers" -type f -print | sort)
mapfile -t provider_schemas < <(find "${fixture_root}/providers" -type f -name '*.schema.json' -print | sort)
mapfile -t provider_manifests < <(find "${fixture_root}/providers" -type f -name 'provider.json' -print | sort)
if (( ${#provider_schemas[@]} != 49 )); then
  echo "expected exactly 49 provider-owned family schemas" >&2
  exit 1
fi
if (( ${#provider_manifests[@]} != 7 )); then
  echo "expected exactly seven provider-owned package manifests" >&2
  exit 1
fi
expected_support=(
  "${fixture_root}/support/LICENSE"
  "${fixture_root}/support/NOTICE"
  "${fixture_root}/support/build-provenance.json"
  "${fixture_root}/support/draft-execution-authority.json"
  "${fixture_root}/support/fixture-family-contract.json"
  "${fixture_root}/support/limitations.md"
  "${fixture_root}/support/normative-requirements.md"
  "${fixture_root}/support/publication-review.json"
  "${fixture_root}/support/sbom.json"
  "${fixture_root}/support/schema-cpf1-v1.cddl"
  "${fixture_root}/support/source-provenance.json"
)
if [[ "${support[*]}" != "${expected_support[*]}" ]]; then
  echo "public support artifact inventory does not match the current CPF1 contract" >&2
  exit 1
fi

jq -e '
  .magic == "DFA1" and .version == 1 and .lifecycle == "Draft" and
  .authority_kind == "repository-test-fixture-only" and
  (.trust_policy_id | type == "string" and length > 0) and
  (.trust_policy_epoch | type == "number" and . > 0 and floor == .) and
  (.effective_timeline_position | type == "number" and . >= 0 and floor == .) and
  (.fixture_authority_key_id | type == "string" and length > 0) and
  (.fixture_authority_public_key_hex | test("^[0-9a-f]{64}$")) and
  (.execution_profiles | length == 2) and
  ([.execution_profiles[].profile_id] | sort == ["deterministic-air-gapped-v1", "deterministic-local-v1"]) and
  all(.execution_profiles[];
    .semantic_version == "1.0.0" and .network_allowed == false and
    .capability_ids == [] and
    .reproducibility_classes == ["ProfileRecomputation", "CrossProfileConformance"]
  )
' "${fixture_root}/support/draft-execution-authority.json" >/dev/null || {
  echo "invalid Draft execution-authority source" >&2
  exit 1
}

for path in "${inputs[@]}" "${expected[@]}" "${oracles[@]}" "${profiles[@]}" "${provider_files[@]}" "${support[@]}"; do
  [[ -s "${path}" ]] || {
    echo "empty conformance fixture: ${path}" >&2
    exit 1
  }
done

echo "verified ${#profiles[@]} public profiles, ${#inputs[@]} public inputs, ${#expected[@]} evidence-status records, ${#oracles[@]} oracle records, ${#provider_manifests[@]} provider manifests, ${#provider_schemas[@]} provider schemas, and ${#support[@]} support artifacts"
