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

for scenario in clean kill; do
  mkdir -p "${evidence_dir}/${scenario}"
  chmod 0777 "${evidence_dir}/${scenario}"
done

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

readonly kill_name="pigloros-adr079-kill-${GITHUB_RUN_ID}-${architecture}"
set +e
/usr/bin/podman run --rm=false --name="${kill_name}" "${podman_arguments[@]}" \
  --volume="${evidence_dir}/kill:/work:rw" "${image}" kill \
  >"${evidence_dir}/kill.stdout" 2>"${evidence_dir}/kill.stderr" &
kill_wait_pid=$!
set -e
for _ in $(seq 1 200); do
  if grep -q '^ADAPTER_READY mode=kill ' "${evidence_dir}/kill.stderr"; then
    break
  fi
  if ! kill -0 "${kill_wait_pid}" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
grep -q '^LAUNCHER_BEFORE_EXEC mode=kill ' "${evidence_dir}/kill.stderr"
grep -q '^ADAPTER_READY mode=kill ' "${evidence_dir}/kill.stderr"
/usr/bin/podman kill --signal=KILL "${kill_name}" >/dev/null
set +e
wait "${kill_wait_pid}"
kill_status=$?
set -e
/usr/bin/podman rm --force "${kill_name}" >/dev/null
test "${kill_status}" -eq 137
printf '%s\n' "${kill_status}" >"${evidence_dir}/kill.return-code"

grep -q '^LAUNCHER_BEFORE_EXEC mode=clean ' "${evidence_dir}/clean.stderr"
grep -q '^ADAPTER_READY mode=clean ' "${evidence_dir}/clean.stderr"
test "$(find "${evidence_dir}/clean" -maxdepth 1 -name '*.profraw' | wc -l)" -eq 2
test "$(find "${evidence_dir}/kill" -maxdepth 1 -name '*.profraw' | wc -l)" -eq 2
test "$(find "${evidence_dir}/clean" -maxdepth 1 -name 'launcher-*.profraw' | wc -l)" -eq 1
test "$(find "${evidence_dir}/clean" -maxdepth 1 -name 'adapter-*.profraw' | wc -l)" -eq 1
test "$(find "${evidence_dir}/kill" -maxdepth 1 -name 'launcher-*.profraw' | wc -l)" -eq 1
test "$(find "${evidence_dir}/kill" -maxdepth 1 -name 'adapter-*.profraw' | wc -l)" -eq 1

mapfile -t raw_profiles < <(find "${evidence_dir}/clean" "${evidence_dir}/kill" \
  -maxdepth 1 -name '*.profraw' -type f | sort)
"${llvm_profdata}" merge -sparse "${raw_profiles[@]}" \
  -o "${evidence_dir}/combined.profdata"
"${llvm_cov}" export --format=text "${launcher}" --object "${adapter}" \
  --instr-profile="${evidence_dir}/combined.profdata" \
  >"${evidence_dir}/official-combined.json"
"${llvm_cov}" export --format=lcov "${launcher}" --object "${adapter}" \
  --instr-profile="${evidence_dir}/combined.profdata" \
  >"${evidence_dir}/official-combined.lcov"
"${llvm_cov}" export --format=text "${launcher}" \
  --instr-profile="${evidence_dir}/combined.profdata" \
  >"${evidence_dir}/launcher-only.json"
"${llvm_cov}" export --format=text "${adapter}" \
  --instr-profile="${evidence_dir}/combined.profdata" \
  >"${evidence_dir}/adapter-only.json"

readonly cargo_profile_dir=$(dirname -- "${LLVM_PROFILE_FILE}")
mkdir -p "${cargo_profile_dir}"
for profile in "${raw_profiles[@]}"; do
  cp "${profile}" "${cargo_profile_dir}/$(basename -- "$(dirname -- "${profile}")")-$(basename -- "${profile}")"
done
cargo llvm-cov report --target "${target}" --json \
  --output-path "${evidence_dir}/cargo-llvm-cov.json"
cargo llvm-cov report --target "${target}" --lcov \
  --output-path "${evidence_dir}/cargo-llvm-cov.lcov"

cp "${raw_profiles[0]}" "${build_dir}/corrupt.profraw"
truncate -s 32 "${build_dir}/corrupt.profraw"
if "${llvm_profdata}" merge -sparse "${build_dir}/corrupt.profraw" \
  -o "${build_dir}/corrupt.profdata" \
  >"${evidence_dir}/corrupt-profile.stdout" \
  2>"${evidence_dir}/corrupt-profile.stderr"; then
  printf 'corrupt raw profile was accepted\n' >&2
  exit 1
fi

python3 "${prototype_dir}/validate_coverage_evidence.py" \
  "${evidence_dir}" "${launcher}" "${adapter}" "${architecture}"
