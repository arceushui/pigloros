#!/usr/bin/env bash
# Prove that a built piglor-gateway image carries its third-party notices (#798).
# Usage: check-gateway-image-notices.sh IMAGE
# The files must exist, be non-empty and be readable by the image's runtime user.
set -euo pipefail

image="${1:?usage: check-gateway-image-notices.sh IMAGE}"
dir=/usr/share/doc/piglor-gateway/third-party

for name in THIRD-PARTY-NOTICES.txt third-party-notices.json; do
  docker run --rm --entrypoint sh "${image}" -c \
    'test "$(id -un)" = appuser && test -s "$1" && head -c 1 -- "$1" >/dev/null' \
    sh "${dir}/${name}"
done
printf 'Gateway image notices OK.\n'
