#!/usr/bin/env bash
set -euo pipefail

profile="fixtures/conformance/profiles/artifact-integrity/profile.json"
blake_inventory="fixtures/conformance/BLAKE3SUMS"
sha_inventory="fixtures/conformance/SHA256SUMS"
backup_root="$(mktemp -d)"
replacement="$(mktemp)"
log="$(mktemp)"
negative_target="$(mktemp -d)"

restore_fixture() {
  cp -- "${backup_root}/profile.json" "${profile}"
  cp -- "${backup_root}/BLAKE3SUMS" "${blake_inventory}"
  cp -- "${backup_root}/SHA256SUMS" "${sha_inventory}"
  rm -rf -- "${backup_root}" "${negative_target}"
  rm -f -- "${replacement}" "${log}"
}
trap restore_fixture EXIT

cp -- "${profile}" "${backup_root}/profile.json"
cp -- "${blake_inventory}" "${backup_root}/BLAKE3SUMS"
cp -- "${sha_inventory}" "${backup_root}/SHA256SUMS"
jq '.fixtures[0].claim_layer = "replay-conformance"' "${profile}" >"${replacement}"
mv -- "${replacement}" "${profile}"

replace_inventory_digest() {
  local inventory="$1"
  local digest="$2"
  local relative="$3"
  awk -v digest="${digest}" -v relative="${relative}" \
    '$2 == relative { print digest "  " relative; next } { print }' \
    "${inventory}" >"${replacement}"
  mv -- "${replacement}" "${inventory}"
}

replace_inventory_digest "${blake_inventory}" \
  "$(b3sum "${profile}" | awk '{print $1}')" \
  "profiles/artifact-integrity/profile.json"
replace_inventory_digest "${sha_inventory}" \
  "$(sha256sum "${profile}" | awk '{print $1}')" \
  "profiles/artifact-integrity/profile.json"
replace_inventory_digest "${sha_inventory}" \
  "$(sha256sum "${blake_inventory}" | awk '{print $1}')" BLAKE3SUMS

# The materialization step builds this crate immediately before this negative
# control. A fresh hosted target directory proves the build script evaluates
# the mutated source rather than any generated catalog retained by Cargo.
if CARGO_TARGET_DIR="${negative_target}" cargo check -p pos-conformance --locked >"${log}" 2>&1; then
  echo "pos-conformance build accepted a fixture with a mismatched claim layer" >&2
  exit 1
fi
grep -Fq "claim layer does not match its profile" "${log}" || {
  echo "pos-conformance build rejected the fixture for the wrong reason" >&2
  cat "${log}" >&2
  exit 1
}

echo "pos-conformance build rejected a fixture with a mismatched claim layer"
