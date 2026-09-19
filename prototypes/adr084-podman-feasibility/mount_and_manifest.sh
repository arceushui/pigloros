#!/usr/bin/env bash
set -euo pipefail

image_id="$1"
manifest_script="$2"
output="$3"
mounted_image="$(/usr/bin/podman image mount "${image_id}")"

cleanup_mount() {
  /usr/bin/podman image unmount "${image_id}" >/dev/null 2>&1 || true
}
trap cleanup_mount EXIT

python3 "${manifest_script}" "${mounted_image}" "${output}"
