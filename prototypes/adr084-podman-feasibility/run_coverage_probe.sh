#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  printf 'usage: %s ARCHITECTURE ARTIFACT_DIR\n' "$0" >&2
  exit 2
fi

readonly architecture=$1
readonly artifact_root=$2
readonly prototype_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly fixture_dir="${prototype_dir}/coverage-fixture"
readonly evidence_dir="${artifact_root}/adr079"
readonly build_dir="${RUNNER_TEMP}/pigloros-adr079-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${architecture}"
readonly target="${architecture}-unknown-linux-musl"
readonly image="localhost/pigloros-adr079-coverage:${GITHUB_SHA}-${architecture}"

mkdir -p "${evidence_dir}" "${build_dir}"
cd "${fixture_dir}"

# cargo-llvm-cov owns the instrumented build/report environment. Counter
# relocation is the one additional candidate-C mechanism being measured.
source <(cargo llvm-cov show-env --sh --target "${target}")
if [[ -n ${CARGO_ENCODED_RUSTFLAGS:-} ]]; then
  CARGO_ENCODED_RUSTFLAGS+=$'\x1f'
fi
CARGO_ENCODED_RUSTFLAGS+='-Cllvm-args=-runtime-counter-relocation'
export CARGO_ENCODED_RUSTFLAGS
cargo build --workspace --target "${target}"

readonly host_target=$(rustc -vV | sed -n 's/^host: //p')
readonly llvm_bin="$(rustc --print sysroot)/lib/rustlib/${host_target}/bin"
readonly llvm_cov="${llvm_bin}/llvm-cov"
readonly llvm_profdata="${llvm_bin}/llvm-profdata"
readonly cargo_target_dir="${CARGO_TARGET_DIR:-${CARGO_LLVM_COV_TARGET_DIR}}"
readonly launcher="${cargo_target_dir}/${target}/debug/coverage-launcher"
readonly adapter="${cargo_target_dir}/${target}/debug/coverage-adapter"
test -x "${launcher}" -a -x "${adapter}"
test -x "${llvm_cov}" -a -x "${llvm_profdata}"

{
  rustc -vV
  cargo llvm-cov --version
  "${llvm_cov}" --version
  "${llvm_profdata}" --version
  printf 'target=%s\n' "${target}"
  printf 'cargo_encoded_rustflags=%q\n' "${CARGO_ENCODED_RUSTFLAGS}"
  printf 'llvm_profile_file_build_environment=%s\n' "${LLVM_PROFILE_FILE}"
  sha256sum "$(command -v cargo-llvm-cov)" "${llvm_cov}" "${llvm_profdata}" \
    "${launcher}" "${adapter}"
} >"${evidence_dir}/tool-and-object-identities.txt"

cp "${launcher}" "${build_dir}/coverage-launcher"
cp "${adapter}" "${build_dir}/coverage-adapter"
cp "${prototype_dir}/Containerfile.coverage" "${build_dir}/Containerfile"
/usr/bin/podman build --runtime=/usr/bin/crun --pull=never --identity-label=false \
  --timestamp=0 --unsetenv=PATH --unsetlabel=io.buildah.version \
  --tag "${image}" "${build_dir}" >"${evidence_dir}/image-build.log" 2>&1
/usr/bin/podman image inspect "${image}" >"${evidence_dir}/image-inspect.json"

podman_arguments=(
  --http-proxy=false
  --runtime=/usr/bin/crun
  --pull=never
  --network=none
  --no-hosts
  --read-only
  --read-only-tmpfs=false
  --cap-drop=all
  --security-opt=no-new-privileges
  --pids-limit=16
  --memory=128m
  --memory-swap=128m
  --entrypoint=/launcher
)

mkdir -p "${evidence_dir}/clean"
chmod 0777 "${evidence_dir}/clean"

set +e
/usr/bin/podman run --rm "${podman_arguments[@]}" \
  --volume="${evidence_dir}/clean:/work:rw" "${image}" clean \
  >"${evidence_dir}/clean.stdout" 2>"${evidence_dir}/clean.stderr"
clean_status=$?
set -e
printf '%s\n' "${clean_status}" >"${evidence_dir}/clean.return-code"

if [[ ${clean_status} -ne 0 ]]; then
  grep -q '^LAUNCHER_BEFORE_EXEC mode=clean ' "${evidence_dir}/clean.stderr"
  grep -Fq 'adapter environment is not empty: [("__LLVM_PROFILE_RT_INIT_ONCE", "__LLVM_PROFILE_RT_INIT_ONCE")]' \
    "${evidence_dir}/clean.stderr"
  test "$(find "${evidence_dir}/clean" -maxdepth 1 -name 'launcher-*.profraw' -type f | wc -l)" -eq 1
  test "$(find "${evidence_dir}/clean" -maxdepth 1 -name 'adapter-*.profraw' -type f | wc -l)" -eq 1
  printf '%s\n' \
    '{' \
    '  "schema": "pigloros.adr079-profile-probe.v1",' \
    "  \"architecture\": \"${architecture}\"," \
    '  "compatible": false,' \
    '  "stopped_after_mandatory_failure": true,' \
    '  "failed_acceptance_criterion": 3,' \
    '  "launcher_exec_environment": "explicit-empty-envp",' \
    '  "adapter_environment": {' \
    '    "__LLVM_PROFILE_RT_INIT_ONCE": "__LLVM_PROFILE_RT_INIT_ONCE"' \
    '  },' \
    '  "forced_kill_test_run": false,' \
    '  "reason": "LLVM continuous profiling recreates a profile runtime environment entry before adapter main"' \
    '}' >"${evidence_dir}/profile-evidence.json"
  printf 'ADR-079 candidate C is incompatible on %s: profile runtime environment injection\n' \
    "${architecture}"
  exit 0
fi

printf 'ADR-079 candidate C unexpectedly preserved an empty adapter environment; update the bounded probe before making further claims\n' >&2
exit 1
