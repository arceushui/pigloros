#!/usr/bin/env bash
set -euo pipefail

fixture_root="${1:-fixtures/conformance}"

if [[ ! -d "${fixture_root}/inputs" || ! -d "${fixture_root}/expected" || ! -d "${fixture_root}/support" ]]; then
  echo "missing conformance fixture directories under ${fixture_root}" >&2
  exit 1
fi

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
    '.claim_layer == $layer and .input == $input and .expected == $expected and (.execution_profiles | length == 2) and (.bundle_modes | length == 2)' \
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
