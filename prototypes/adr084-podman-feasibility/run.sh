#!/usr/bin/env bash
set -euo pipefail

prototype_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
workspace_dir="$(cd -- "${prototype_dir}/../.." && pwd)"
artifact_dir="${workspace_dir}/artifacts/adr084-podman-feasibility"
build_dir="${RUNNER_TEMP:-/tmp}/pigloros-adr084-build-${GITHUB_RUN_ID:-manual}-${GITHUB_RUN_ATTEMPT:-0}"
image_tag="localhost/pigloros-adr084-probe:${GITHUB_SHA:-prototype}"

mkdir -p "${artifact_dir}" "${build_dir}"

case "$(uname -m)" in
  x86_64)
    evidence_architecture="x86_64"
    oci_architecture="amd64"
    ;;
  aarch64)
    evidence_architecture="aarch64"
    oci_architecture="arm64"
    ;;
  *) printf 'unsupported prototype architecture\n' >&2; exit 1 ;;
esac

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

blake3_commit="df610ddc3b93841ffc59a87e3da659a15910eb46"
blake3_source="${build_dir}/blake3-source"
git init --quiet "${blake3_source}"
git -C "${blake3_source}" remote add origin https://github.com/BLAKE3-team/BLAKE3.git
git -C "${blake3_source}" fetch --quiet --depth=1 origin "${blake3_commit}"
git -C "${blake3_source}" checkout --quiet --detach FETCH_HEAD
test "$(git -C "${blake3_source}" rev-parse HEAD)" = "${blake3_commit}"
{
  printf 'repository=https://github.com/BLAKE3-team/BLAKE3.git\n'
  printf 'commit=%s\n' "${blake3_commit}"
  printf 'tree=%s\n' "$(git -C "${blake3_source}" rev-parse 'HEAD^{tree}')"
  git -C "${blake3_source}" archive --format=tar HEAD | sha256sum | \
    sed 's/  -$/  git-archive.tar/'
  sha256sum \
    "${blake3_source}/c/blake3.c" \
    "${blake3_source}/c/blake3_dispatch.c" \
    "${blake3_source}/c/blake3_portable.c" \
    "${blake3_source}/c/blake3.h" \
    "${blake3_source}/c/blake3_impl.h"
} >"${artifact_dir}/blake3-source-identity.txt"
cp "${blake3_source}/LICENSE_A2" "${artifact_dir}/blake3-LICENSE_A2.txt"
blake3_defines=(
  -DBLAKE3_USE_NEON=0
  -DBLAKE3_NO_SSE2
  -DBLAKE3_NO_SSE41
  -DBLAKE3_NO_AVX2
  -DBLAKE3_NO_AVX512
)
musl-gcc -Os -Wall -Wextra -Werror "${blake3_defines[@]}" \
  -I"${blake3_source}/c" -c "${prototype_dir}/launcher.c" \
  -o "${build_dir}/launcher.o"
for source in blake3 blake3_dispatch blake3_portable; do
  musl-gcc -Os -Wall -Wextra -Werror -Wno-unused-function \
    "${blake3_defines[@]}" -I"${blake3_source}/c" \
    -c "${blake3_source}/c/${source}.c" -o "${build_dir}/${source}.o"
done
musl-gcc -static -o "${build_dir}/launcher" \
  "${build_dir}/launcher.o" "${build_dir}/blake3.o" \
  "${build_dir}/blake3_dispatch.o" "${build_dir}/blake3_portable.o"
python3 "${prototype_dir}/generate_adapter_transport.py" "${build_dir}"
cp "${build_dir}/adapter-transport-vectors.json" "${artifact_dir}/"
musl-gcc -static -Os -Wall -Wextra -Werror -I"${build_dir}" \
  -o "${build_dir}/adapter" "${prototype_dir}/adapter.c"
musl-gcc -static -Os -Wall -Wextra -Werror -o "${build_dir}/cache-probe" \
  "${prototype_dir}/cache_probe.c"
musl-gcc -static -Os -Wall -Wextra -Werror -o "${build_dir}/native-matrix" \
  "${prototype_dir}/native_matrix.c"
musl-gcc -static -Os -Wall -Wextra -Werror -o "${build_dir}/seccomp-probe" \
  "${prototype_dir}/seccomp_probe.c"
case "${evidence_architecture}" in
  x86_64)
    as --32 -o "${build_dir}/foreign-probe.o" "${prototype_dir}/foreign_x86.S"
    ld -m elf_i386 -e _start -o "${build_dir}/foreign-probe" \
      "${build_dir}/foreign-probe.o"
    ;;
  aarch64)
    arm-linux-gnueabihf-as -o "${build_dir}/foreign-probe.o" \
      "${prototype_dir}/foreign_arm.S"
    arm-linux-gnueabihf-ld -e _start -o "${build_dir}/foreign-probe" \
      "${build_dir}/foreign-probe.o"
    ;;
esac
cc -O2 -Wall -Wextra -Werror -o "${build_dir}/trace-seccomp" \
  "${prototype_dir}/trace_seccomp.c"
cc -O2 -Wall -Wextra -Werror -o "${build_dir}/prefilter-exec" \
  "${prototype_dir}/prefilter_exec.c"
cp "${prototype_dir}/Containerfile" "${build_dir}/Containerfile"

libseccomp_archive="${build_dir}/libseccomp-2.6.1.tar.gz"
curl --fail --location --silent --show-error \
  https://github.com/seccomp/libseccomp/releases/download/v2.6.1/libseccomp-2.6.1.tar.gz \
  --output "${libseccomp_archive}"
printf '%s  %s\n' \
  '501f66c667225d53791b97e1d7cf85ab764c297d04881f60f38f451c4b0ee1be' \
  "${libseccomp_archive}" | sha256sum --check --strict -
tar -xzf "${libseccomp_archive}" -C "${build_dir}"
libseccomp_prefix="${build_dir}/libseccomp-install"
(
  cd "${build_dir}/libseccomp-2.6.1"
  ./configure --prefix="${libseccomp_prefix}" --disable-shared --enable-static
  make -j2
  make install
) 2>&1 | tee "${artifact_dir}/libseccomp-build.log"

seccomp_dir="${artifact_dir}/seccomp"
distinct_seccomp_dir="${artifact_dir}/seccomp-distinct"
mkdir -p "${seccomp_dir}" "${distinct_seccomp_dir}"
scs1="${workspace_dir}/crates/pos-conformance/vectors/systemd-provider-v260.2/systemd-v260.2-${evidence_architecture}.scs1.cbor"
distinct_scs1="${distinct_seccomp_dir}/derived-cachestat.scs1.cbor"
python3 "${prototype_dir}/derive_distinct_scs1.py" \
  "${scs1}" "${distinct_scs1}"
python3 "${prototype_dir}/prepare_seccomp.py" \
  --architecture "${evidence_architecture}" --scs1 "${scs1}" \
  --libseccomp-archive "${libseccomp_archive}" --output-dir "${seccomp_dir}"
python3 "${prototype_dir}/prepare_seccomp.py" \
  --architecture "${evidence_architecture}" --scs1 "${distinct_scs1}" \
  --libseccomp-archive "${libseccomp_archive}" \
  --output-dir "${distinct_seccomp_dir}"
cc -O2 -Wall -Wextra -Werror \
  -I"${libseccomp_prefix}/include" "${prototype_dir}/compile_seccomp.c" \
  "${libseccomp_prefix}/lib/libseccomp.a" -o "${build_dir}/compile-seccomp"
"${build_dir}/compile-seccomp" "${evidence_architecture}" \
  "${seccomp_dir}/libseccomp-interface-v1.txt" \
  "${seccomp_dir}/readback-only-pnr.txt" \
  "${seccomp_dir}/exported-seccomp.bpf" \
  "${seccomp_dir}/compiler-metadata.json"
python3 "${prototype_dir}/verify_seccomp_bpf.py" \
  --architecture "${evidence_architecture}" \
  --bpf "${seccomp_dir}/exported-seccomp.bpf" \
  --interface "${seccomp_dir}/libseccomp-interface-v1.txt" \
  --report "${seccomp_dir}/bpf-verification.json" \
  --base64 "${seccomp_dir}/exported-seccomp.base64"
"${build_dir}/compile-seccomp" "${evidence_architecture}" \
  "${distinct_seccomp_dir}/libseccomp-interface-v1.txt" \
  "${distinct_seccomp_dir}/readback-only-pnr.txt" \
  "${distinct_seccomp_dir}/exported-seccomp.bpf" \
  "${distinct_seccomp_dir}/compiler-metadata.json"
python3 "${prototype_dir}/verify_seccomp_bpf.py" \
  --architecture "${evidence_architecture}" \
  --bpf "${distinct_seccomp_dir}/exported-seccomp.bpf" \
  --interface "${distinct_seccomp_dir}/libseccomp-interface-v1.txt" \
  --report "${distinct_seccomp_dir}/bpf-verification.json" \
  --base64 "${distinct_seccomp_dir}/exported-seccomp.base64"
cp "${seccomp_dir}/libseccomp-interface-v1.txt" \
  "${build_dir}/libseccomp-interface-v1.txt"

/usr/bin/podman build --runtime=/usr/bin/crun --pull=never --identity-label=false \
  --timestamp=0 --unsetenv=PATH --unsetlabel=io.buildah.version \
  --tag "${image_tag}" "${build_dir}" 2>&1 | tee "${artifact_dir}/podman-build.log"
/usr/bin/podman image inspect "${image_tag}" >"${artifact_dir}/image-inspect.json"
image_id="$(jq -er '.[0].Id' "${artifact_dir}/image-inspect.json")"

/usr/bin/podman save --format oci-archive --output "${build_dir}/podman-source.oci.tar" \
  "${image_tag}"
mkdir -p "${build_dir}/podman-source-layout"
tar -xf "${build_dir}/podman-source.oci.tar" -C "${build_dir}/podman-source-layout"
python3 "${prototype_dir}/build_oci_archive.py" \
  "${build_dir}/podman-source-layout" "${artifact_dir}/image.oci.tar" \
  --architecture "${oci_architecture}" --image-id "${image_tag}"
python3 "${prototype_dir}/validate_oci_archive.py" \
  "${artifact_dir}/image.oci.tar" "${build_dir}/oci-layout" \
  "${artifact_dir}/oci-archive-validation.json"
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

python3 "${prototype_dir}/generate_runtime_subject.py" \
  "${artifact_dir}/oci-validation.json" "${artifact_dir}/rootfs-manifest.json" \
  "${build_dir}/launcher" "${build_dir}/adapter" \
  "${artifact_dir}/runtime-subject.json"
python3 "${prototype_dir}/validate_runtime_subject.py" \
  "${artifact_dir}/runtime-subject.json" "${artifact_dir}/oci-validation.json" \
  "${artifact_dir}/rootfs-manifest.json" "${build_dir}/launcher" \
  "${build_dir}/adapter" "${artifact_dir}/runtime-subject-validation.json"

python3 "${prototype_dir}/generate_vectors.py" >"${artifact_dir}/adr085-vectors.json"
python3 "${prototype_dir}/validate_vectors.py" "${artifact_dir}/adr085-vectors.json" \
  "${artifact_dir}/adr085-vector-validation.json"
python3 "${prototype_dir}/driver.py" --architecture "${evidence_architecture}" \
  --image "${image_reference}" \
  --seccomp "${seccomp_dir}/oci-seccomp-profile.json" \
  --seccomp-bpf-base64 "${seccomp_dir}/exported-seccomp.base64" \
  --seccomp-bpf "${seccomp_dir}/exported-seccomp.bpf" \
  --seccomp-interface "${seccomp_dir}/libseccomp-interface-v1.txt" \
  --scs1 "${scs1}" \
  --distinct-seccomp "${distinct_seccomp_dir}/oci-seccomp-profile.json" \
  --distinct-seccomp-bpf-base64 "${distinct_seccomp_dir}/exported-seccomp.base64" \
  --distinct-seccomp-bpf "${distinct_seccomp_dir}/exported-seccomp.bpf" \
  --distinct-scs1 "${distinct_scs1}" \
  --seccomp-tracer "${build_dir}/trace-seccomp" \
  --prefilter "${build_dir}/prefilter-exec" \
  --eai1-hello "${build_dir}/eai1_hello.bin" \
  --eai1-hold "${build_dir}/eai1_hold.bin" \
  --eai1-memory "${build_dir}/eai1_memory.bin" \
  --eai1-tasks "${build_dir}/eai1_tasks.bin" \
  --eai1-cpu "${build_dir}/eai1_cpu.bin" \
  --eai1-file "${build_dir}/eai1_file.bin" \
  --eai1-watchdog "${build_dir}/eai1_watchdog.bin" \
  --eao1-hello "${build_dir}/eao1_hello.bin" \
  --runtime-subject "${artifact_dir}/runtime-subject.json" \
  --configured-defaults "${prototype_dir}/configured-default-injection.conf" \
  --configured-security-defaults \
    "${prototype_dir}/configured-security-default-injection.conf" \
  --artifact-dir "${artifact_dir}"

python3 "${prototype_dir}/write_evidence_manifest.py" \
  "${artifact_dir}" "${build_dir}" "${prototype_dir}" \
  --architecture "${oci_architecture}"

jq -e '.adr069_compatible == false and .observed_terminal_code == 8 and .required_terminal_code == 7' \
  "${artifact_dir}/elm-file.json" >/dev/null
printf 'ADR-084 prototype completed on %s; Podman+crun candidate is incompatible with the required SIGXFSZ file-limit evidence\n' \
  "$(uname -m)" | tee "${artifact_dir}/verdict.txt"
find "${artifact_dir}" -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum \
  >"${artifact_dir}/SHA256SUMS"
