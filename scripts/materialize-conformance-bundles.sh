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
(cd fixtures/conformance && b3sum --check BLAKE3SUMS)

: "${PIGLOROS_CONFORMANCE_SIGNING_KEY:?materialization requires a non-repository signing key}"
source_digest="$(sha256sum "${source_inventory}" | awk '{print $1}')"
publication_id="${PIGLOROS_CONFORMANCE_PUBLICATION_ID:-${source_digest}}"
output_root="${1:-fixtures/conformance/published/${publication_id}}"
if [[ -e "${output_root}" ]]; then
  echo "refusing to overwrite existing Draft conformance output: ${output_root}" >&2
  exit 1
fi
publication_parent="$(dirname "${output_root}")"
mkdir -p "${publication_parent}"
temporary_root="$(mktemp -d "${publication_parent}/.pigloros-conformance.XXXXXX")"
first_output="${temporary_root}/first"
second_output="${temporary_root}/second"
trap 'rm -rf "${temporary_root}"' EXIT

PIGLOROS_CONFORMANCE_SIGNING_KEY="${PIGLOROS_CONFORMANCE_SIGNING_KEY}" \
  cargo run -p pos-conformance --bin materialize-conformance-bundles --locked -- "${first_output}"
PIGLOROS_CONFORMANCE_SIGNING_KEY="${PIGLOROS_CONFORMANCE_SIGNING_KEY}" \
  cargo run -p pos-conformance --bin materialize-conformance-bundles --locked -- "${second_output}"

diff -rq "${first_output}" "${second_output}"

clean_checkout="${temporary_root}/clean-checkout"
clean_output="${temporary_root}/clean-output"
mkdir -p "${clean_checkout}"
git archive --format=tar HEAD | tar -xf - -C "${clean_checkout}"
bash "${clean_checkout}/scripts/verify-conformance-fixtures.sh" \
  "${clean_checkout}/fixtures/conformance"
(cd "${clean_checkout}" && \
  CARGO_TARGET_DIR="${temporary_root}/clean-target" \
  PIGLOROS_CONFORMANCE_SIGNING_KEY="${PIGLOROS_CONFORMANCE_SIGNING_KEY}" \
  cargo run -p pos-conformance --bin materialize-conformance-bundles --locked -- "${clean_output}")
diff -rq "${first_output}" "${clean_output}"

mapfile -t materialized_files < <(find "${first_output}" -type f -print | sort)
mapfile -t profile_files < <(
  find "${first_output}" -type f -name 'CPF1-*.cbor' -print | sort
)
mapfile -t manifest_files < <(
  find "${first_output}" -type f -name 'manifest-*.cbor' -print | sort
)
mapfile -t archive_files < <(
  find "${first_output}" -type f -name 'bundle-*.cfb1' -print | sort
)
authority_lifecycle="$(jq -r '.lifecycle' fixtures/conformance/expected-authority/inventory.json)"
case "${authority_lifecycle}" in
  Draft) lifecycle_count=1 ;;
  *)
    echo "unsupported authority inventory lifecycle: ${authority_lifecycle}" >&2
    exit 1
    ;;
esac
expected_profile_count=$((7 * lifecycle_count))
expected_manifest_count=$((7 * lifecycle_count * 2))
expected_archive_count=$((7 * lifecycle_count * 2))
expected_file_count=$((expected_profile_count + expected_manifest_count + expected_archive_count))
if ((
  ${#profile_files[@]} != expected_profile_count ||
  ${#manifest_files[@]} != expected_manifest_count ||
  ${#archive_files[@]} != expected_archive_count ||
  ${#materialized_files[@]} != expected_file_count
)); then
  echo "expected ${expected_profile_count} profiles, ${expected_manifest_count} manifests, and ${expected_archive_count} archives; found ${#profile_files[@]} profiles, ${#manifest_files[@]} manifests, ${#archive_files[@]} archives, and ${#materialized_files[@]} total files" >&2
  exit 1
fi
if ((${#archive_files[@]} == 0)); then
  echo "materialization produced no archives" >&2
  exit 1
fi
cargo run -p pos-conformance --bin verify-conformance-bundle --locked -- "${archive_files[@]}"

(cd "${first_output}" && sha256sum --tag "${materialized_files[@]#${first_output}/}" > SHA256SUMS)
cp "${source_inventory}" "${first_output}/SOURCE-SHA256SUMS"
{
  printf 'source_sha256=%s\n' "${source_digest}"
  printf 'source_revision=%s\n' "$(git rev-parse HEAD)"
} > "${first_output}/SOURCE-BINDING"
mv --no-clobber --no-target-directory "${first_output}" "${output_root}"
if [[ -e "${first_output}" ]]; then
  echo "Draft conformance output appeared during materialization: ${output_root}" >&2
  exit 1
fi
echo "materialized ${#materialized_files[@]} signed Draft conformance files under ${output_root}"
