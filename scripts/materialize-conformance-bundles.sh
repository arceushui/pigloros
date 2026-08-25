#!/usr/bin/env bash
set -euo pipefail

if (($# > 1)); then
  echo "usage: $0 [published-output-root]" >&2
  exit 2
fi

source_inventory="fixtures/conformance/SHA256SUMS"
[[ -s "${source_inventory}" ]] || {
  echo "missing checked-in conformance source inventory" >&2
  exit 1
}
(cd fixtures/conformance && sha256sum --check --strict SHA256SUMS)

: "${PIGLOROS_CONFORMANCE_SIGNING_KEY:?materialization requires a non-repository signing key}"
source_digest="$(sha256sum "${source_inventory}" | awk '{print $1}')"
publication_id="${PIGLOROS_CONFORMANCE_PUBLICATION_ID:-${source_digest}}"
output_root="${1:-fixtures/conformance/published/${publication_id}}"
if [[ -e "${output_root}" ]]; then
  echo "refusing to overwrite retained conformance publication: ${output_root}" >&2
  exit 1
fi
temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/pigloros-conformance.XXXXXX")"
first_output="${temporary_root}/first"
second_output="${temporary_root}/second"
trap 'rm -rf "${temporary_root}"' EXIT

PIGLOROS_CONFORMANCE_SIGNING_KEY="${PIGLOROS_CONFORMANCE_SIGNING_KEY}" \
  cargo run -p pos-conformance --bin materialize-conformance-bundles --locked -- "${first_output}"
PIGLOROS_CONFORMANCE_SIGNING_KEY="${PIGLOROS_CONFORMANCE_SIGNING_KEY}" \
  cargo run -p pos-conformance --bin materialize-conformance-bundles --locked -- "${second_output}"
diff -rq "${first_output}" "${second_output}"
mkdir -p "$(dirname "${output_root}")"
mv "${first_output}" "${output_root}"

mapfile -t materialized_files < <(
  find "${output_root}" -type f \( -name '*.cbor' -o -name '*.cfb1' \) -print | sort
)
authority_lifecycle="$(jq -r '.lifecycle' fixtures/conformance/expected-authority/inventory.json)"
case "${authority_lifecycle}" in
  Draft) lifecycle_count=1 ;;
  Candidate) lifecycle_count=2 ;;
  *)
    echo "unsupported authority inventory lifecycle: ${authority_lifecycle}" >&2
    exit 1
    ;;
esac
expected_file_count=$((7 * lifecycle_count * 5))
if ((${#materialized_files[@]} != expected_file_count)); then
  echo "expected ${expected_file_count} deterministic CPF1/profile/manifest/archive files, found ${#materialized_files[@]}" >&2
  exit 1
fi

(cd "${output_root}" && sha256sum --tag "${materialized_files[@]#${output_root}/}" > SHA256SUMS)
cp "${source_inventory}" "${output_root}/SOURCE-SHA256SUMS"
{
  printf 'source_sha256=%s\n' "${source_digest}"
  printf 'source_revision=%s\n' "$(git rev-parse HEAD)"
} > "${output_root}/SOURCE-BINDING"
echo "materialized ${#materialized_files[@]} signed conformance files under retained path ${output_root}"
