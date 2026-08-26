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

matrix_path="${fixture_root}/matrix/execution-matrix.json"
authority_path="${fixture_root}/expected-authority/inventory.json"
[[ -s "${matrix_path}" && -s "${authority_path}" ]] || {
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
    (.AuthEq | type == "string") and
    (.PublicEq | type == "string") and
    (.OpEq | type == "string")
  ) and
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
    (.fixture_bytes_path == null) and (.expected_result_path == null) and
    (.fixture_bytes_digest == null) and (.expected_result_digest == null) and
    .materialization_status == "pending"
  )
' "${authority_path}" >/dev/null || {
  echo "invalid #172 expected-authority inventory lifecycle or entries" >&2
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

if (( ${#inputs[@]} != 49 || ${#expected[@]} != 49 )); then
  echo "expected exactly 49 layer-specific input and expected-result records" >&2
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
for index in "${!profile_layers[@]}"; do
  layer="${profile_layers[${index}]}"
  profile="${profile_root}/${layer}/profile.json"
  [[ -s "${profile}" ]] || {
    echo "missing public profile manifest for ${layer}" >&2
    exit 1
  }
  jq -e \
    --arg layer "${layer}" \
    --arg authority "expected-authority/inventory.json" \
    --arg authority_sha256 "${authority_inventory_sha256}" \
    --arg matrix "matrix/execution-matrix.json" \
    --arg matrix_lifecycle "${matrix_lifecycle}" \
    --arg matrix_blake3 "${matrix_blake3_digest}" \
    --argjson matrix_size "$(wc -c < "${matrix_path}")" \
    '.claim_layer == $layer and
      .authority_inventory == $authority and .authority_inventory_sha256_digest == $authority_sha256 and
      .adr_059_execution_matrix == $matrix and .adr_059_execution_matrix_blake3_digest == $matrix_blake3 and
      .adr_059_execution_matrix_status == $matrix_lifecycle and
      (.execution_profiles | length == 2) and (.bundle_modes | length == 2) and
      (.fixtures | length == 7) and
      all(.fixtures[]; .claim_layer == $layer) and
      ([.fixtures[].family] == ["positive", "negative", "malformed", "resource", "deletion", "downgrade", "independent-evaluation"]) and
      (if $layer == "knowledge-non-interference" then (.matrix == $matrix and .matrix_size_bytes == $matrix_size and .matrix_blake3_digest == $matrix_blake3) else true end)' \
    "${profile}" >/dev/null || {
    echo "invalid public profile manifest for ${layer}" >&2
    exit 1
  }
  while IFS=$'\t' read -r input_path expected_path; do
    for path in "${input_path}" "${expected_path}"; do
      [[ "${path}" != /* && "${path}" != *".."* ]] || {
        echo "unsafe profile fixture path for ${layer}: ${path}" >&2
        exit 1
      }
      [[ -s "${fixture_root}/${path}" ]] || {
        echo "missing profile fixture for ${layer}: ${path}" >&2
        exit 1
      }
    done
  done < <(jq -r '.fixtures[] | [.input, .expected] | @tsv' "${profile}")
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
if (( ${#declared_inputs[@]} != 49 || ${#declared_expected[@]} != 49 )); then
  echo "expected every layer-specific fixture pair to be declared exactly once" >&2
  exit 1
fi

mapfile -t actual_input_paths < <(find "${fixture_root}/inputs" -type f -printf 'inputs/%P\n' | sort)
mapfile -t actual_expected_paths < <(find "${fixture_root}/expected" -type f -printf 'expected/%P\n' | sort)
if ! diff -u \
  <(printf '%s\n' "${actual_input_paths[@]}") \
  <(printf '%s\n' "${declared_inputs[@]}") >/dev/null ||
  ! diff -u \
  <(printf '%s\n' "${actual_expected_paths[@]}") \
  <(printf '%s\n' "${declared_expected[@]}") >/dev/null; then
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
  .candidate_status == "pending" and
  .deletion_review == "pending" and
  .secret_scan == "pending" and
  .authority_inventory.path == "expected-authority/inventory.json" and
  .authority_inventory.digest_algorithm == "SHA-256" and
  .authority_inventory.status == $authority_lifecycle and
  .adr_059_execution_matrix.path == "matrix/execution-matrix.json" and
  .adr_059_execution_matrix.digest_algorithm == "BLAKE3-256" and
  .adr_059_execution_matrix.blake3_digest == $matrix_blake3 and
  .adr_059_execution_matrix.status == $matrix_lifecycle and
  .adr_059_execution_matrix.executed_case_count == 0
' "${fixture_root}/support/provenance.json" >/dev/null || {
  echo "Draft authority handoff metadata is invalid" >&2
  exit 1
}

jq -e --arg authority_sha256 "${authority_inventory_sha256}" \
  '.authority_inventory.sha256_digest == $authority_sha256' \
  "${fixture_root}/support/provenance.json" >/dev/null || {
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
    find expected-authority expected inputs matrix profiles support \
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
  [[ -f "${expected_path}" ]] || {
    echo "missing expected-result pair for ${input}" >&2
    exit 1
  }
done

publishable_roots=(
  "${fixture_root}/inputs"
  "${fixture_root}/expected"
  "${fixture_root}/profiles"
  "${fixture_root}/matrix"
  "${fixture_root}/expected-authority"
  "${fixture_root}/support"
)
secret_pattern='-----BEGIN[[:space:]]+[A-Z0-9 -]*PRIVATE KEY-----|"(api[_-]?key|apikey|password|credential|credentials|access[_-]?token|refresh[_-]?token|authorization|bearer[_-]?token|client[_-]?secret|subject[_-]?secret|private[_-]?key|privatekey|secret)"[[:space:]]*:[[:space:]]*"[^"[:space:]]+"|(Bearer|Basic)[[:space:]]+[A-Za-z0-9._~+/=-]{16,}|(AKIA|ASIA)[0-9A-Z]{16}|(gh[pousr]_|github_pat_|glpat-|xox[baprs]-|sk_(live|test)_|AIza)[A-Za-z0-9._-]{16,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
if grep -R -n -i -I -E -- "${secret_pattern}" "${publishable_roots[@]}"; then
  echo "forbidden secret material found in public conformance fixtures" >&2
  exit 1
else
  scan_status=$?
  if (( scan_status != 1 )); then
    echo "secret scan could not inspect all publishable conformance fixtures" >&2
    exit "${scan_status}"
  fi
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
