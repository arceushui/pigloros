#!/usr/bin/env bash
set -euo pipefail

fixture_root="${1:-fixtures/conformance}"

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
  .magic == "NIM1" and .version == 1 and .lifecycle == "Draft" and
  .row_count == 12 and .variant_count == 4 and .mode_count == 4 and
  .case_count == 192 and (.rows | length == 12) and
  all(.rows[]; (.fixture_id | test("^NI-[A-Z]+-[0-9]{3}$")) and
    (.variants == ["S", "D", "W", "C"]) and
    (.modes == ["L", "A", "R", "F"]) and .case_count == 16 and
    .executed_case_count == 0 and .expected_result_digest == null)
' "${matrix_path}" >/dev/null || {
  echo "invalid ADR-059 Draft matrix inventory" >&2
  exit 1
}

jq -e '
  .magic == "W8H1" and .version == 1 and .lifecycle == "Draft" and
  (.entries | length == 11) and
  all(.entries[]; .expected_result_digest == null and .materialization_status == "open-draft-slot")
' "${authority_path}" >/dev/null || {
  echo "invalid #172 expected-authority inventory" >&2
  exit 1
}

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
    '.claim_layer == $layer and .input == $input and .expected == $expected and (.execution_profiles | length == 2) and (.bundle_modes | length == 2) and (if $layer == "knowledge-non-interference" then .matrix == "matrix/adr-059-complete.json" else true end)' \
    "${profile}" >/dev/null || {
    echo "invalid public profile manifest for ${layer}" >&2
    exit 1
  }
done

if [[ ! -s "${fixture_root}/SHA256SUMS" ]]; then
  echo "missing conformance fixture digest inventory" >&2
  exit 1
fi

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
