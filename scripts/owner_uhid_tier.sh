#!/usr/bin/env bash
# ADR-110 E20 U-tier (Redmine #1476): run the hostio U-tier tests against kernel
# uhid devices backed by the software authenticator, as the unprivileged runner
# user, and export their coverage.
#
# Only two steps use sudo: the virtual-device helper (/dev/uhid is root only)
# and handing each new hidraw node to the runner user (UG1, Redmine #1474). The
# tests, the build and the coverage export run as the runner user. The helper's
# profile files belong to root, so they are handed over before the export.
#
# Usage: owner_uhid_tier.sh OUTPUT_DIRECTORY
# Needs: the uhid module loaded, cargo-llvm-cov, jq, and RUSTC_BOOTSTRAP=1.
set -euo pipefail

output=${1:?usage: owner_uhid_tier.sh OUTPUT_DIRECTORY}
mkdir -p "${output}"
output=$(cd "${output}" && pwd)
work="${RUNNER_TEMP:-/tmp}/owner-uhid"
rm -rf "${work}"
mkdir -p "${work}"
evidence="${output}/owner-uhid-evidence.txt"
: >"${evidence}"
# A fresh six-digit PIN for every run; it is never written to a file.
pin=$(printf '%06d' $(((RANDOM * 32768 + RANDOM) % 900000 + 100000)))

# Instrument everything this script builds and runs, the root helper included.
# shellcheck disable=SC1090
source <(cargo llvm-cov show-env --export-prefix)
cargo llvm-cov clean --workspace
target_dir=${CARGO_TARGET_DIR:-${CARGO_LLVM_COV_TARGET_DIR}}

cargo build --locked -p pos-owner-ctap --features test-support --example uhid-fido
helper="${target_dir}/debug/examples/uhid-fido"
tests=$(cargo test --locked -p pos-owner-ctap --features test-support --test hostio --no-run \
  --message-format=json |
  jq -r 'select(.executable != null and .target.name == "hostio") | .executable')
test -x "${helper}"
test -x "${tests}"

# Wait for the helper's ready file, failing if the helper died first. $1 is the PID of the
# `sudo` process that started the helper. sudo keeps the caller's real uid, so the runner user
# may signal it (kill -0 is permitted) and it lives exactly as long as the helper does; the CI
# log of the first run shows every phase passing this wait.
wait_ready() {
  local pid=$1 ready=$2 deadline=$((SECONDS + 30))
  until [[ -e "${ready}" ]]; do
    kill -0 "${pid}" 2>/dev/null || {
      echo "the uhid helper exited before it was ready" >&2
      return 1
    }
    ((SECONDS < deadline)) || {
      echo "the uhid helper was not ready within 30 s" >&2
      return 1
    }
    sleep 0.2
  done
}

# Wait until exactly $1 FIDO hidraw nodes (usage page 0xF1D0) exist, let udev settle,
# and hand each node to the runner user. This is the CI-only hand-over of UG1; it
# does not exercise systemd uaccess.
hand_over() {
  local want=$1 deadline=$((SECONDS + 30)) nodes entry
  while :; do
    nodes=()
    for entry in /sys/class/hidraw/hidraw*; do
      [[ -r "${entry}/device/report_descriptor" ]] || continue
      if [[ "$(od -An -N3 -tx1 "${entry}/device/report_descriptor" | tr -d ' \n')" == 06d0f1 ]]; then
        nodes+=("/dev/${entry##*/}")
      fi
    done
    ((${#nodes[@]} == want)) && break
    ((SECONDS < deadline)) || {
      echo "expected ${want} FIDO hidraw nodes, found ${#nodes[@]}" >&2
      return 1
    }
    sleep 0.2
  done
  sudo udevadm settle --timeout=10
  for entry in "${nodes[@]}"; do
    sudo chown "$(id -u):$(id -g)" "${entry}"
    sudo chmod 600 "${entry}"
    echo "U-tier hand-over: $(stat -c '%n %U:%G %a' "${entry}")" | tee -a "${evidence}"
  done
}

# One scenario: start the helper with $2 devices, run the hostio tests of that
# scenario, then stop the helper and require a clean exit.
phase() {
  local name=$1 devices=$2
  local ready="${work}/${name}.ready" stop="${work}/${name}.stop"
  sudo env "LLVM_PROFILE_FILE=${LLVM_PROFILE_FILE}" "${helper}" \
    --ready "${ready}" --stop "${stop}" --pin "${pin}" --devices "${devices}" &
  local helper_pid=$!
  local status=0
  if wait_ready "${helper_pid}" "${ready}" && hand_over "${devices}"; then
    OWNER_CTAP_UHID="${name}" OWNER_CTAP_UHID_PIN="${pin}" OWNER_CTAP_UHID_STOP="${stop}" \
      OWNER_CTAP_UHID_EVIDENCE="${evidence}" "${tests}" --test-threads=1 uhid:: || status=$?
  else
    status=1
  fi
  : >"${stop}"
  wait "${helper_pid}" || status=$?
  return "${status}"
}

phase one 1
phase two 2
phase unplug 1

# Every scenario left its evidence: three lines from `one` and one each from `two` and `unplug`.
test "$(grep -c '^U ' "${evidence}")" -eq 5

# The helper's profile files belong to root.
sudo find "${target_dir}" -name '*.profraw' -user root \
  -exec chown "$(id -u):$(id -g)" {} +
cargo llvm-cov report --lcov --output-path "${output}/owner-uhid.lcov"
checkout=$(git rev-parse HEAD)
jq -n --arg checkout "${checkout}" --arg root "${PWD}" \
  --arg digest "$(sha256sum "${output}/owner-uhid.lcov" | cut -d' ' -f1)" \
  '{version: 1, checkout: $checkout, workspace_root: $root, lcov_sha256: $digest}' \
  >"${output}/owner-uhid-lcov-receipt.json"
cat "${evidence}"
