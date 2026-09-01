#!/usr/bin/env bash
set -euo pipefail

if (($# > 1)); then
  echo "usage: $0 [publication-parent]" >&2
  exit 2
fi

source_inventory="fixtures/conformance/SHA256SUMS"
[[ -s "${source_inventory}" ]] || {
  echo "missing checked-in conformance source inventory" >&2
  exit 1
}
(cd fixtures/conformance && sha256sum --check --strict SHA256SUMS)

: "${PIGLOROS_CONFORMANCE_SIGNING_KEY:?Draft materialization requires the public deterministic repository test-fixture signing key}"
# This public deterministic key proves fixture reproducibility and internal
# consistency only. It provides neither authenticity nor Candidate publication
# authority; #198 owns Candidate publication and its trust policy.
source_digest="$(sha256sum "${source_inventory}" | awk '{print $1}')"
publication_parent="${1:-fixtures/conformance/published}"
output_root="${publication_parent}/${source_digest}"
temporary_root="$(mktemp -d)"
trap 'rm -rf -- "${temporary_root}"' EXIT

# Atomic publication deliberately requires an existing trusted parent. The
# orchestrator owns creation of that parent; the binary opens and retains it
# before producing any bundle bytes.
mkdir -p -- "${publication_parent}"

first_fingerprint="$(
  cargo run --quiet -p pos-conformance --bin materialize-conformance-bundles \
    --locked -- --fingerprint
)"
second_fingerprint="$(
  cargo run --quiet -p pos-conformance --bin materialize-conformance-bundles \
    --locked -- --fingerprint
)"
[[ "${first_fingerprint}" == "${second_fingerprint}" ]] || {
  echo "repeated conformance materialization produced different bytes" >&2
  exit 1
}

clean_checkout="${temporary_root}/clean-checkout"
mkdir -p "${clean_checkout}"
git archive --format=tar HEAD | tar -xf - -C "${clean_checkout}"
clean_fingerprint="$(cd "${clean_checkout}" && \
  CARGO_TARGET_DIR="${temporary_root}/clean-target" \
  PIGLOROS_CONFORMANCE_SIGNING_KEY="${PIGLOROS_CONFORMANCE_SIGNING_KEY}" \
  cargo run --quiet -p pos-conformance --bin materialize-conformance-bundles \
    --locked -- --fingerprint)"
[[ "${first_fingerprint}" == "${clean_fingerprint}" ]] || {
  echo "clean-checkout conformance materialization produced different bytes" >&2
  exit 1
}

cargo run -p pos-conformance --bin materialize-conformance-bundles \
  --locked -- "${output_root}"

mapfile -t materialized_files < <(find "${output_root}" -type f -print | sort)
mapfile -t profile_files < <(
  find "${output_root}" -type f -name 'CPF1-*.cbor' -print | sort
)
mapfile -t manifest_files < <(
  find "${output_root}" -type f -name 'manifest-*.cbor' -print | sort
)
mapfile -t archive_files < <(
  find "${output_root}" -type f -name '*.cfb1' -print | sort
)
metadata_file="${output_root}/MATERIALIZATION-METADATA.json"
output_checksums="${output_root}/SHA256SUMS"
jq -e '
  .format == 1 and
  (.lifecycles | type == "array" and length > 0) and
  (.layers | type == "array" and length > 0) and
  (.modes | type == "array" and length > 0) and
  (.published_file_count | type == "number" and . > 0 and floor == .)
' "${metadata_file}" >/dev/null
layer_count="$(jq -r '.layers | length' "${metadata_file}")"
lifecycle_count="$(jq -r '.lifecycles | length' "${metadata_file}")"
mode_count="$(jq -r '.modes | length' "${metadata_file}")"
expected_profile_count=$((layer_count * lifecycle_count))
expected_manifest_count=$((expected_profile_count * mode_count))
expected_archive_count=$((expected_profile_count * mode_count))
expected_file_count="$(jq -r '.published_file_count' "${metadata_file}")"
if ((
  ${#profile_files[@]} != expected_profile_count ||
  ${#manifest_files[@]} != expected_manifest_count ||
  ${#archive_files[@]} != expected_archive_count ||
  ${#materialized_files[@]} != expected_file_count
)); then
  echo "expected ${expected_profile_count} profiles, ${expected_manifest_count} manifests, and ${expected_archive_count} archives; found ${#profile_files[@]} profiles, ${#manifest_files[@]} manifests, ${#archive_files[@]} archives, and ${#materialized_files[@]} total files" >&2
  exit 1
fi
(cd "${output_root}" && sha256sum --check --strict "$(basename "${output_checksums}")")
if ((${#archive_files[@]} == 0)); then
  echo "materialization produced no archives" >&2
  exit 1
fi
cargo run -p pos-conformance --bin verify-conformance-bundle --locked -- "${archive_files[@]}"

echo "atomically materialized ${#materialized_files[@]} signed Draft conformance files under ${output_root}"
