#!/usr/bin/env bash
# Prove that a built piglor-gateway image carries its third-party notices (#798).
# Usage: check-gateway-image-notices.sh IMAGE
# The files must exist, be non-empty and be readable by the image's runtime user.
set -euo pipefail

image="${1:?usage: check-gateway-image-notices.sh IMAGE}"
dir=/usr/share/doc/piglor-gateway/third-party

# Runs inside the image as its runtime user; prints the failing condition.
inspect='
user="$(id -un)"
[ "${user}" = appuser ] || { echo "image runs as ${user}, expected appuser" >&2; exit 1; }
for file in "$@"; do
  [ -s "${file}" ] || { echo "missing or empty: ${file}" >&2; exit 1; }
  head -c 1 -- "${file}" >/dev/null || { echo "unreadable: ${file}" >&2; exit 1; }
done'

docker run --rm --entrypoint sh "${image}" -c "${inspect}" sh \
  "${dir}/THIRD-PARTY-NOTICES.txt" "${dir}/third-party-notices.json"
printf 'Gateway image notices OK.\n'
