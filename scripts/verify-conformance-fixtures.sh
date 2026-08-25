#!/usr/bin/env bash
set -euo pipefail

fixture_root="${1:-fixtures/conformance}"

command -v b3sum >/dev/null || {
  echo "b3sum is required to independently verify BLAKE3 authority digests" >&2
  exit 1
}

if [[ ! -d "${fixture_root}/inputs" || ! -d "${fixture_root}/expected" || ! -d "${fixture_root}/support" ]]; then
  echo "missing conformance fixture directories under ${fixture_root}" >&2
  exit 1
fi

matrix_path="${fixture_root}/matrix/adr-059-complete.json"
authority_path="${fixture_root}/expected-authority/inventory.json"
[[ -s "${matrix_path}" && -s "${authority_path}" ]] || {
  echo "missing Draft conformance inventory artifacts" >&2
  exit 1
}

jq -e '
  . as $root |
  $root.magic == "NIM1" and $root.version == 1 and $root.lifecycle == "Draft" and
  $root.row_count == 12 and $root.variant_count == 4 and $root.mode_count == 4 and
  $root.case_count == 192 and ($root.rows | length == 12) and
  ([$root.rows[].fixture_id] == [
    "NI-TOOL-001", "NI-CACHE-002", "NI-STATE-003", "NI-OBS-004",
    "NI-TIME-005", "NI-PUBLIC-006", "NI-EVAL-007", "NI-FORK-008",
    "NI-ARCHIVE-009", "NI-NET-010", "NI-SERVICE-011", "NI-CRASH-012"
  ]) and
  ([$root.rows[].fixture_id] | unique | length == 12) and
  ($root.cases | length == 192) and
  ([$root.cases[].case_id] | unique | length == 192) and
  all($root.rows[]; (.fixture_id | test("^NI-[A-Z]+-[0-9]{3}$")) and
    (.variants == ["S", "D", "W", "C"]) and
    (.modes == ["L", "A", "R", "F"]) and .case_count == 16 and
    .executed_case_count == 0) and
  all($root.cases[]; (.fixture_id | test("^NI-[A-Z]+-[0-9]{3}$")) and
    (.variant | IN("S", "D", "W", "C")) and
    (.mode | IN("L", "A", "R", "F")) and
    .case_id == ("\(.fixture_id)-\(.variant)-\(.mode)") and
    .executed == false and .expected_result_digest == null)
  and all($root.rows[]; . as $row | ([$root.cases[] | select(.fixture_id == $row.fixture_id)] | length == 16))
' "${matrix_path}" >/dev/null || {
  echo "invalid ADR-059 Draft matrix inventory" >&2
  exit 1
}

jq -e '
  .magic == "W8H1" and .version == 1 and
  .lifecycle == "Candidate" and .digest_algorithm == "BLAKE3-256" and
  (.entries | length == 11) and
  ([.entries[].fixture_id] == [
    "RPL-001", "PRF-001", "PRF-002", "DIV-001", "INV-001", "INV-002",
    "INV-003", "RES-001", "LIVE-001", "ERA-001", "SEC-001"
  ]) and
  ([.entries[].fixture_id] | unique | length == 11) and
  all(.entries[];
    (.fixture_bytes_path | type == "string") and
    (.expected_result_path | type == "string") and
    (.fixture_bytes_digest | type == "string" and test("^[0-9a-f]{64}$")) and
    (.expected_result_digest | type == "string" and test("^[0-9a-f]{64}$")) and
    .materialization_status == "materialized"
  )
' "${authority_path}" >/dev/null || {
  echo "invalid #172 Candidate expected-authority inventory" >&2
  exit 1
}

mapfile -t authority_files < <(
  jq -r '.entries[] | .fixture_bytes_path, .expected_result_path' "${authority_path}"
)
if (( ${#authority_files[@]} != 22 )); then
  echo "expected eleven authority fixture/result pairs" >&2
  exit 1
fi
for authority_file in "${authority_files[@]}"; do
  [[ -s "${fixture_root}/${authority_file}" ]] || {
    echo "missing authority artifact: ${fixture_root}/${authority_file}" >&2
    exit 1
  }
done

authority_inventory_sha256="$(sha256sum "${authority_path}" | awk '{print $1}')"
matrix_blake3_digest="$(b3sum "${matrix_path}" | awk '{print $1}')"
while IFS=$'\t' read -r fixture_id fixture_path fixture_digest result_path result_digest expected_outcome; do
  for value in "${fixture_path}" "${result_path}"; do
    [[ "${value}" != /* && "${value}" != *".."* ]] || {
      echo "unsafe authority artifact path for ${fixture_id}: ${value}" >&2
      exit 1
    }
  done
  actual_fixture_digest="$(b3sum "${fixture_root}/${fixture_path}" | awk '{print $1}')"
  actual_result_digest="$(b3sum "${fixture_root}/${result_path}" | awk '{print $1}')"
  [[ "${actual_fixture_digest}" == "${fixture_digest}" ]] || {
    echo "BLAKE3 mismatch for authority fixture ${fixture_id}" >&2
    exit 1
  }
  [[ "${actual_result_digest}" == "${result_digest}" ]] || {
    echo "BLAKE3 mismatch for authority result ${fixture_id}" >&2
    exit 1
  }
  jq -e --arg fixture_id "${fixture_id}" --arg outcome "${expected_outcome}" \
    '.fixture_id == $fixture_id and .outcome == $outcome' \
    "${fixture_root}/${result_path}" >/dev/null || {
    echo "authority result metadata disagrees with inventory for ${fixture_id}" >&2
    exit 1
  }
done < <(
  jq -r '.entries[] | [
    .fixture_id,
    .fixture_bytes_path,
    .fixture_bytes_digest,
    .expected_result_path,
    .expected_result_digest,
    .expected_outcome
  ] | @tsv' "${authority_path}"
)

mapfile -t inputs < <(find "${fixture_root}/inputs" -type f -print | sort)
mapfile -t expected < <(find "${fixture_root}/expected" -type f -print | sort)

if (( ${#inputs[@]} != 7 || ${#expected[@]} != 7 )); then
  echo "expected exactly seven input and seven expected-result records" >&2
  exit 1
fi

profile_root="${fixture_root}/profiles"
profile_layers=(
  artifact-integrity
  replay-conformance
  knowledge-non-interference
  gateway-client-conformance
  plugin-conformance
  metric-conformance
  empirical-evaluation
)
profile_inputs=(
  artifact-positive.json
  replay-negative.json
  knowledge-malformed.json
  gateway-resource-limit.json
  plugin-deletion.json
  metric-downgrade.json
  empirical-independent.json
)
for index in "${!profile_layers[@]}"; do
  layer="${profile_layers[${index}]}"
  profile="${profile_root}/${layer}/profile.json"
  [[ -s "${profile}" ]] || {
    echo "missing public profile manifest for ${layer}" >&2
    exit 1
  }
  jq -e \
    --arg layer "${layer}" \
    --arg input "inputs/${profile_inputs[${index}]}" \
    --arg expected "expected/${profile_inputs[${index}]}" \
    --arg authority "expected-authority/inventory.json" \
    --arg authority_sha256 "${authority_inventory_sha256}" \
    --arg matrix "matrix/adr-059-complete.json" \
    --arg matrix_blake3 "${matrix_blake3_digest}" \
    --argjson matrix_size "$(wc -c < "${matrix_path}")" \
    '.claim_layer == $layer and .input == $input and .expected == $expected and
      .authority_inventory == $authority and .authority_inventory_sha256_digest == $authority_sha256 and
      .adr_059_execution_matrix == $matrix and .adr_059_execution_matrix_blake3_digest == $matrix_blake3 and
      .adr_059_execution_matrix_status == "Draft" and
      (.execution_profiles | length == 2) and (.bundle_modes | length == 2) and
      (if $layer == "knowledge-non-interference" then (.matrix == $matrix and .matrix_size_bytes == $matrix_size and .matrix_blake3_digest == $matrix_blake3) else true end)' \
    "${profile}" >/dev/null || {
    echo "invalid public profile manifest for ${layer}" >&2
    exit 1
  }
done

if [[ ! -s "${fixture_root}/SHA256SUMS" ]]; then
  echo "missing conformance fixture digest inventory" >&2
  exit 1
fi

jq -e '
  .candidate_status == "approved" and
  .deletion_review == "approved" and
  .secret_scan == "clean" and
  .authority_inventory.path == "expected-authority/inventory.json" and
  .authority_inventory.digest_algorithm == "SHA-256" and
  .authority_inventory.status == "Candidate" and
  .adr_059_execution_matrix.path == "matrix/adr-059-complete.json" and
  .adr_059_execution_matrix.digest_algorithm == "BLAKE3-256" and
  .adr_059_execution_matrix.status == "Draft" and
  .adr_059_execution_matrix.executed_case_count == 0
' "${fixture_root}/support/provenance.json" >/dev/null || {
  echo "Candidate publication review evidence is missing or not approved" >&2
  exit 1
}

jq -e --arg authority_sha256 "${authority_inventory_sha256}" \
  '.authority_inventory.sha256_digest == $authority_sha256' \
  "${fixture_root}/support/provenance.json" >/dev/null || {
  echo "profile-bound authority inventory digest is incorrect" >&2
  exit 1
}

(cd "${fixture_root}" && sha256sum --check --strict SHA256SUMS)

for input in "${inputs[@]}"; do
  expected_path="${fixture_root}/expected/$(basename "${input}")"
  [[ -f "${expected_path}" ]] || {
    echo "missing expected-result pair for ${input}" >&2
    exit 1
  }
done

if rg -n -i 'private[ _-]?key|begin[ _-]?secret|subject[ _-]?secret|credential|password' \
  "${fixture_root}/inputs" "${fixture_root}/expected"; then
  echo "forbidden secret marker found in public conformance fixtures" >&2
  exit 1
fi

mapfile -t profiles < <(find "${profile_root}" -type f -print | sort)
if (( ${#profiles[@]} != 7 )); then
  echo "expected exactly seven public profile manifests" >&2
  exit 1
fi

mapfile -t support < <(find "${fixture_root}/support" -type f -print | sort)
if (( ${#support[@]} != 7 )); then
  echo "expected exactly seven required public support artifacts" >&2
  exit 1
fi

for path in "${inputs[@]}" "${expected[@]}" "${profiles[@]}" "${support[@]}"; do
  [[ -s "${path}" ]] || {
    echo "empty conformance fixture: ${path}" >&2
    exit 1
  }
done

echo "verified ${#profiles[@]} public profiles, ${#inputs[@]} public inputs, ${#expected[@]} expected-result records, and ${#support[@]} support artifacts"
