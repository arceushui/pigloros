#!/usr/bin/env bash
set -euo pipefail

fixture_root="${1:-fixtures/conformance}"
profile_root="${fixture_root}/profiles"

command -v jq >/dev/null || {
  echo "jq is required to independently regenerate conformance fixture records" >&2
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
while IFS=$'\t' read -r case_id claim_layer family input_path expected_path; do
  [[ -n "${case_id}" && -n "${claim_layer}" && -n "${family}" ]] || {
    echo "profile contains an empty fixture identity" >&2
    exit 1
  }
  [[ "${input_path}" == inputs/* && "${expected_path}" == expected/* ]] || {
    echo "fixture paths must remain under inputs/ and expected/: ${case_id}" >&2
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
  [[ -s "${input_file}" && -s "${expected_file}" ]] || {
    echo "missing fixture pair: ${case_id}" >&2
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
    negative) result=rejected ;;
    malformed) result=typed-failure ;;
    resource) result=resource-limit ;;
    deletion) result=destroyed ;;
    downgrade) result=not-authorized ;;
    independent-evaluation) result=corroborated ;;
    *)
      echo "unknown public fixture family: ${family}" >&2
      exit 1
      ;;
  esac

  generated_file="${generated_root}/${expected_path}"
  mkdir -p "$(dirname "${generated_file}")"
  jq -n \
    --arg claim_layer "${claim_layer}" \
    --arg case_id "${case_id}" \
    --arg family "${family}" \
    --arg result "${result}" \
    '{claim_layer: $claim_layer, case_id: $case_id, family: $family, result: $result, status: "pending"}' \
    > "${generated_file}"
  cmp -- "${generated_file}" "${expected_file}" || {
    echo "expected fixture record is not independently reproducible: ${case_id}" >&2
    exit 1
  }
  generated_count=$((generated_count + 1))
done < <(
  find "${profile_root}" -mindepth 2 -maxdepth 2 -type f -name profile.json -print0 |
    sort -z |
    xargs -0 -r jq -r '.fixtures[] | [.case_id, .claim_layer, .family, .input, .expected] | @tsv'
)

if (( generated_count != 49 )); then
  echo "independently regenerated ${generated_count} fixture records; expected 49" >&2
  exit 1
fi

echo "independently regenerated ${generated_count} public conformance fixture records"
