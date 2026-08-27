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
(cd "${clean_checkout}" && \
  CARGO_TARGET_DIR="${temporary_root}/clean-target" \
  PIGLOROS_CONFORMANCE_SIGNING_KEY="${PIGLOROS_CONFORMANCE_SIGNING_KEY}" \
  cargo run -p pos-conformance --bin materialize-conformance-bundles --locked -- "${clean_output}")
diff -rq "${first_output}" "${clean_output}"

mapfile -t materialized_files < <(find "${first_output}" -type f -print | sort)
mapfile -t profile_files < <(
  find "${first_output}" -type f -name 'CPF2-*.cbor' -print | sort
)
mapfile -t manifest_files < <(
  find "${first_output}" -type f -name 'manifest-*.cbor' -print | sort
)
mapfile -t archive_files < <(
  find "${first_output}" -type f -name '*.cfb1' -print | sort
)
metadata_file="${first_output}/MATERIALIZATION-METADATA.json"
jq -e '
  .format == 1 and
  (.lifecycles | type == "array" and length > 0) and
  (.layers | type == "array" and length > 0) and
  (.modes | type == "array" and length > 0)
' "${metadata_file}" >/dev/null
layer_count="$(jq -r '.layers | length' "${metadata_file}")"
lifecycle_count="$(jq -r '.lifecycles | length' "${metadata_file}")"
mode_count="$(jq -r '.modes | length' "${metadata_file}")"
expected_profile_count=$((layer_count * lifecycle_count))
expected_manifest_count=$((expected_profile_count * mode_count))
expected_archive_count=$((expected_profile_count * mode_count))
expected_file_count=$((expected_profile_count + expected_manifest_count + expected_archive_count + 1))
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

diff -rq "${first_output}" "${second_output}"
diff -rq "${first_output}" "${clean_output}"
PIGLOROS_CONFORMANCE_SIGNING_KEY="${PIGLOROS_CONFORMANCE_SIGNING_KEY}" \
  cargo run -p pos-conformance --bin materialize-conformance-bundles --locked -- "${output_root}"
diff -rq "${first_output}" "${output_root}"
echo "atomically materialized ${#materialized_files[@]} signed Draft conformance files under ${output_root}"
