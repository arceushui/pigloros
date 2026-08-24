#!/usr/bin/env bash
set -euo pipefail

fixture_root="${1:-fixtures/conformance}"

if [[ ! -d "${fixture_root}/inputs" || ! -d "${fixture_root}/expected" ]]; then
  echo "missing conformance fixture directories under ${fixture_root}" >&2
  exit 1
fi

mapfile -t inputs < <(find "${fixture_root}/inputs" -type f -print | sort)
mapfile -t expected < <(find "${fixture_root}/expected" -type f -print | sort)

if (( ${#inputs[@]} != 7 || ${#expected[@]} != 7 )); then
  echo "expected exactly seven input and seven expected-result records" >&2
  exit 1
fi

if rg -n -i 'private[ _-]?key|begin[ _-]?secret|subject[ _-]?secret|credential|password' \
  "${fixture_root}/inputs" "${fixture_root}/expected"; then
  echo "forbidden secret marker found in public conformance fixtures" >&2
  exit 1
fi

for path in "${inputs[@]}" "${expected[@]}"; do
  [[ -s "${path}" ]] || {
    echo "empty conformance fixture: ${path}" >&2
    exit 1
  }
done

echo "verified ${#inputs[@]} public inputs and ${#expected[@]} expected-result records"
