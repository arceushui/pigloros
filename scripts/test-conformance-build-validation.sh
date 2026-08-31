#!/usr/bin/env bash
set -euo pipefail

profile="fixtures/conformance/profiles/artifact-integrity/profile.json"
provider="fixtures/conformance/providers/artifact-integrity/provider.json"
blake_inventory="fixtures/conformance/BLAKE3SUMS"
sha_inventory="fixtures/conformance/SHA256SUMS"
backup_root="$(mktemp -d)"
replacement="$(mktemp)"
log="$(mktemp)"
negative_target="$(mktemp -d)"

restore_fixture() {
  cp -- "${backup_root}/profile.json" "${profile}"
  cp -- "${backup_root}/provider.json" "${provider}"
  cp -- "${backup_root}/BLAKE3SUMS" "${blake_inventory}"
  cp -- "${backup_root}/SHA256SUMS" "${sha_inventory}"
  rm -rf -- "${backup_root}" "${negative_target}"
  rm -f -- "${replacement}" "${log}"
}
trap restore_fixture EXIT

cp -- "${profile}" "${backup_root}/profile.json"
cp -- "${provider}" "${backup_root}/provider.json"
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

refresh_inventory_digest() {
  local source="$1"
  local relative="$2"
  replace_inventory_digest "${blake_inventory}" \
    "$(b3sum "${source}" | awk '{print $1}')" "${relative}"
  replace_inventory_digest "${sha_inventory}" \
    "$(sha256sum "${source}" | awk '{print $1}')" "${relative}"
  replace_inventory_digest "${sha_inventory}" \
    "$(sha256sum "${blake_inventory}" | awk '{print $1}')" BLAKE3SUMS
}

refresh_inventory_digest "${profile}" "profiles/artifact-integrity/profile.json"

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

cp -- "${backup_root}/profile.json" "${profile}"
cp -- "${backup_root}/BLAKE3SUMS" "${blake_inventory}"
cp -- "${backup_root}/SHA256SUMS" "${sha_inventory}"
jq '.package_support.licence = "support/NOTICE" |
    .package_support.notices = "support/LICENSE"' \
  "${provider}" >"${replacement}"
mv -- "${replacement}" "${provider}"
refresh_inventory_digest "${provider}" "providers/artifact-integrity/provider.json"
if CARGO_TARGET_DIR="${negative_target}" cargo check -p pos-conformance --locked >"${log}" 2>&1; then
  echo "pos-conformance build accepted provider support paths with swapped roles" >&2
  exit 1
fi
grep -Fq "provider package support paths do not match their declared roles" "${log}" || {
  echo "pos-conformance build rejected swapped provider support roles for the wrong reason" >&2
  cat "${log}" >&2
  exit 1
}

cp -- "${backup_root}/provider.json" "${provider}"
cp -- "${backup_root}/BLAKE3SUMS" "${blake_inventory}"
cp -- "${backup_root}/SHA256SUMS" "${sha_inventory}"
jq '.abi_minor = 65535' "${provider}" >"${replacement}"
mv -- "${replacement}" "${provider}"
refresh_inventory_digest "${provider}" "providers/artifact-integrity/provider.json"
if CARGO_TARGET_DIR="${negative_target}" cargo check -p pos-conformance --locked >"${log}" 2>&1; then
  echo "pos-conformance build accepted a provider ABI minor without downgrade headroom" >&2
  exit 1
fi
grep -Fq "provider manifest does not match profile claim layer" "${log}" || {
  echo "pos-conformance build rejected the maximum provider ABI minor for the wrong reason" >&2
  cat "${log}" >&2
  exit 1
}

echo "pos-conformance build rejected invalid claim, support-role, and downgrade-headroom inputs"
