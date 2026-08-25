#!/usr/bin/env bash
set -euo pipefail

output_root="${1:-${RUNNER_TEMP:-/tmp}/pigloros-conformance-bundles}"
mkdir -p "${output_root}"

PIGLOROS_MATERIALIZE_CONFORMANCE="${output_root}" \
  cargo test -p pos-conformance --lib \
  bundle_contract::tests::materialize_fixture_bundles_when_requested -- --exact

mapfile -t materialized_files < <(
  find "${output_root}" -type f \( -name '*.cbor' -o -name '*.cfb1' \) -print | sort
)
if ((${#materialized_files[@]} != 70)); then
  echo "expected 70 deterministic CPF1/profile/manifest/archive files, found ${#materialized_files[@]}" >&2
  exit 1
fi

(cd "${output_root}" && sha256sum --tag "${materialized_files[@]#${output_root}/}" > SHA256SUMS)
echo "materialized ${#materialized_files[@]} deterministic conformance files under ${output_root}"
