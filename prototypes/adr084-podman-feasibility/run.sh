#!/usr/bin/env bash
set -euo pipefail

prototype_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
workspace_dir="$(cd -- "${prototype_dir}/../.." && pwd)"
artifact_dir="${workspace_dir}/artifacts/adr084-podman-feasibility"
build_dir="${RUNNER_TEMP:-/tmp}/pigloros-adr084-build-${GITHUB_RUN_ID:-manual}-${GITHUB_RUN_ATTEMPT:-0}"
image_tag="localhost/pigloros-adr084-probe:${GITHUB_SHA:-prototype}"

mkdir -p "${artifact_dir}" "${build_dir}"

cleanup() {
  /usr/bin/podman rm --all --force --filter label=io.pigloros.prototype=adr084 >/dev/null 2>&1 || true
}
trap cleanup EXIT

{
  printf 'question=Can distro Podman+crun satisfy the ADR-084 release barrier on this hosted architecture?\n'
  printf 'runner_image=%s-%s\n' "${ImageOS:-unknown}" "${ImageVersion:-unknown}"
  printf 'architecture=%s\n' "$(uname -m)"
  printf 'kernel=%s\n' "$(uname -r)"
  printf 'uid=%s\n' "$(id -u)"
  printf 'user=%s\n' "$(id -un)"
  printf 'cgroup_fs=%s\n' "$(stat -fc %T /sys/fs/cgroup)"
  printf 'subuid=%s\n' "$(grep -F "$(id -un):" /etc/subuid || true)"
  printf 'subgid=%s\n' "$(grep -F "$(id -un):" /etc/subgid || true)"
  /usr/bin/podman --version
  /usr/bin/crun --version
} | tee "${artifact_dir}/environment.txt"

/usr/bin/podman info --format json >"${artifact_dir}/podman-info.json"
jq -e '.host.security.rootless == true' "${artifact_dir}/podman-info.json" >/dev/null
jq -e '.host.cgroupVersion == "v2"' "${artifact_dir}/podman-info.json" >/dev/null
jq -e '.host.ociRuntime.name == "crun" or .host.ociRuntime.path == "/usr/bin/crun"' \
  "${artifact_dir}/podman-info.json" >/dev/null

musl-gcc -static -Os -Wall -Wextra -Werror -o "${build_dir}/launcher" "${prototype_dir}/launcher.c"
musl-gcc -static -Os -Wall -Wextra -Werror -o "${build_dir}/adapter" "${prototype_dir}/adapter.c"
cp "${prototype_dir}/Containerfile" "${build_dir}/Containerfile"

/usr/bin/podman build --runtime=/usr/bin/crun --pull=never \
  --tag "${image_tag}" "${build_dir}" 2>&1 | tee "${artifact_dir}/podman-build.log"
/usr/bin/podman image inspect "${image_tag}" >"${artifact_dir}/image-inspect.json"
image_id="$(jq -er '.[0].Id' "${artifact_dir}/image-inspect.json")"

/usr/bin/podman save --format oci-archive --output "${artifact_dir}/image.oci.tar" "${image_tag}"
mkdir -p "${build_dir}/oci-layout"
tar -xf "${artifact_dir}/image.oci.tar" -C "${build_dir}/oci-layout"
case "$(uname -m)" in
  x86_64) oci_architecture="amd64" ;;
  aarch64) oci_architecture="arm64" ;;
  *) printf 'unsupported prototype architecture\n' >&2; exit 1 ;;
esac
python3 "${prototype_dir}/validate_oci.py" "${build_dir}/oci-layout" \
  "${artifact_dir}/oci-validation.json" --architecture "${oci_architecture}"

/usr/bin/podman image rm --force "${image_id}" >/dev/null
/usr/bin/podman load --input "${artifact_dir}/image.oci.tar" \
  >"${artifact_dir}/podman-load.txt"
/usr/bin/podman image inspect "${image_tag}" >"${artifact_dir}/image-import-inspect.json"
image_id="$(jq -er '.[0].Id' "${artifact_dir}/image-import-inspect.json")"
image_reference="${image_id}"
printf '%s\n' "${image_reference}" >"${artifact_dir}/image-reference.txt"

/usr/bin/podman unshare bash "${prototype_dir}/mount_and_manifest.sh" \
  "${image_id}" "${prototype_dir}/rootfs_manifest.py" \
  "${artifact_dir}/rootfs-manifest.json"

python3 "${prototype_dir}/generate_vectors.py" >"${artifact_dir}/adr085-vectors.json"
python3 "${prototype_dir}/driver.py" --image "${image_reference}" \
  --seccomp "${prototype_dir}/seccomp.json" --artifact-dir "${artifact_dir}"

printf 'ADR-084 prototype passed on %s\n' "$(uname -m)" | tee "${artifact_dir}/verdict.txt"
find "${artifact_dir}" -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum \
  >"${artifact_dir}/SHA256SUMS"
