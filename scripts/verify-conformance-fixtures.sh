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

mapfile -t support < <(find "${fixture_root}/support" -type f -print | sort)
if (( ${#support[@]} != 7 )); then
  echo "expected exactly seven required public support artifacts" >&2
  exit 1
fi

for path in "${inputs[@]}" "${expected[@]}" "${support[@]}"; do
  [[ -s "${path}" ]] || {
    echo "empty conformance fixture: ${path}" >&2
    exit 1
  }
done

echo "verified ${#inputs[@]} public inputs, ${#expected[@]} expected-result records, and ${#support[@]} support artifacts"
