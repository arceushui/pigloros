#!/usr/bin/env bash
# Produce #444 part (a) packaged-closure evidence (ADR-087 gate 5) on a
# GitHub-hosted runner of the guest's own architecture.
#
#   build ARCH OUT   realise the pinned guest and record its store identities
#   boot ARCH OUT    boot it once under QEMU TCG in an empty network namespace
#   seal OUT         hash every evidence file into OUT/SHA256SUMS
#
# scripts/check_qemu_closure_evidence.py judges the result between boot and
# seal. This script records; it decides nothing beyond its own preconditions.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
flake="${root}/deploy/nixos"

provenance_files=(
  scripts/check_qemu_closure_evidence.py
  scripts/qemu-closure-evidence.sh
  scripts/qemu_qmp_query_kvm.py
  deploy/nixos/flake.nix
  deploy/nixos/flake.lock
  deploy/nixos/modules/mountfsd-activation.nix
  deploy/nixos/qemu-evidence/guest.nix
  deploy/nixos/qemu-evidence/collect-evidence.sh
  deploy/nixos/dev-trust/root-hash-dev-test.crt
)

usage() {
  printf 'usage: %s build|boot ARCH OUT | seal OUT\n' "$0" >&2
  exit 2
}

require_architecture() {
  case "$1" in
  x86_64 | aarch64) ;;
  *) usage ;;
  esac
  if [[ "$(uname -m)" != "$1" ]]; then
    printf 'runner architecture %s is not %s\n' "$(uname -m)" "$1" >&2
    exit 1
  fi
}

store_path() {
  jq --exit-status --raw-output --arg name "$1" '.[$name]' "$2/host/store-paths.json"
}

build() {
  local architecture="$1" out="$2" vm built
  require_architecture "${architecture}"
  mkdir -p "${out}/host"
  nix flake metadata --json --no-update-lock-file "${flake}" >"${out}/host/flake-metadata.json"
  nix eval --json --no-update-lock-file "${flake}#qemuEvidence.${architecture}" \
    >"${out}/host/store-paths.json"
  vm="$(store_path vm "${out}")"
  built="$(nix build --no-update-lock-file --no-link --print-build-logs --print-out-paths \
    "${flake}#nixosConfigurations.qemu-evidence-${architecture}.config.system.build.piglorQemuEvidenceVm")"
  if [[ "${built}" != "${vm}" ]]; then
    printf 'built %s, expected %s\n' "${built}" "${vm}" >&2
    exit 1
  fi
  local names=(vm toplevel kernel systemd qemu trustedCertificate kernelConfig collector collectorUnit)
  local paths=() name
  for name in "${names[@]}"; do
    paths+=("$(store_path "${name}" "${out}")")
  done
  nix path-info --json --json-format 2 "${paths[@]}" >"${out}/host/path-info.json"
  nix path-info --json --json-format 2 --recursive "$(store_path toplevel "${out}")" \
    >"${out}/host/toplevel-closure.json"
  cp -- "$(store_path trustedCertificate "${out}")" "${out}/host/system-trusted-keys.pem"
  cp -- "$(store_path kernelConfig "${out}")" "${out}/host/kernel-config"
  record_provenance "${out}"
}

# The tested commit and the reviewed inputs the evidence depends on.
record_provenance() {
  local out="$1" file
  {
    printf 'git-head\t%s\n' "$(git -C "${root}" rev-parse HEAD)"
    printf 'github-sha\t%s\n' "${GITHUB_SHA:?}"
    printf 'pr-head-sha\t%s\n' "${EVIDENCE_PR_HEAD_SHA:?}"
    # The raw commit object names both merge parents even in a shallow clone.
    git -C "${root}" cat-file commit HEAD | awk '/^$/ { body = 1 } !body && $1 == "parent" { print "merge-parent\t" $2 }'
    for file in "${provenance_files[@]}"; do
      printf 'file\t%s\t%s\n' "${file}" "$(sha256sum <"${root}/${file}" | cut -d' ' -f1)"
    done
  } >"${out}/host/provenance"
}

# The exact running image of the recorded QEMU package: nixpkgs wraps
# qemu-system-<arch> with wrapGApp, so it is either that binary or its
# .qemu-system-<arch>-wrapped target.
is_qemu_image() { # EXE QEMU_STORE_PATH ARCH
  [[ $1 == "$2/bin/qemu-system-$3" || $1 == "$2/bin/.qemu-system-$3-wrapped" ]]
}

# "<state> <start time>" from /proc/PID/stat, or nothing if PID is gone.
# The comm field may hold spaces, so fields are read after its last ')'.
process_stat() { # PID
  local stat
  stat="$(sudo cat "/proc/$1/stat" 2>/dev/null || true)"
  [[ -n ${stat} ]] || return 0
  local fields
  read -r -a fields <<<"${stat##*) }"
  printf '%s %s\n' "${fields[0]}" "${fields[19]}"
}

# True when the process PID that started at START has exited: it is gone,
# a zombie, or its PID now belongs to a process with another start time.
qemu_gone() { # PID START
  local stat
  stat="$(process_stat "$1")"
  [[ -z ${stat} || ${stat%% *} == [ZX] || ${stat#* } != "$2" ]]
}

# Stop the observed QEMU process if it is still running, and wait for it.
stop_qemu() { # PID START
  qemu_gone "$1" "$2" && return 0
  sudo kill -KILL "$1" || true
  for _ in $(seq 30); do
    qemu_gone "$1" "$2" && return 0
    sleep 1
  done
  return 1
}

# Copy QEMU's argv, executable and network interfaces. A failed read is
# reported through the status, never by exiting before the cleanup.
record_qemu() { # PID OUT
  local failed=0
  sudo cat "/proc/$1/cmdline" >"$2/host/qemu-argv" || failed=1
  sudo readlink "/proc/$1/exe" >"$2/host/qemu-exe" || failed=1
  # The interfaces of QEMU's own network namespace.
  sudo cat "/proc/$1/net/dev" >"$2/host/qemu-net-dev" || failed=1
  return "${failed}"
}

write_cleanup_record() { # PID START WORK OUT
  {
    if [[ -n $1 ]] && qemu_gone "$1" "$2"; then
      printf 'qemu-process\texited\n'
    else
      printf 'qemu-process\tunobserved-or-running\n'
    fi
    if [[ ! -e $3 ]]; then
      printf 'work-directory\tremoved\n'
    else
      printf 'work-directory\tpresent\n'
    fi
  } >"$4/host/vm-cleanup"
}

# Everything after the launch, on every path: wait for the launcher, keep
# the console and guest record, stop the exact QEMU process, remove the
# working directory and record both (ADR-069 R13 §4). Fails only at the end.
finish_boot() { # LAUNCHER QEMU_PID QEMU_START OBSERVE_FAILED WORK OUT
  local status=0 stopped=0
  wait "$1" || status=$?
  printf '%s\n' "${status}" >"$6/host/vm-exit-status"
  tail -n 200 "$6/host/serial-console.log" || true
  if [[ -d "$5/xchg/guest" ]]; then
    cp -R -- "$5/xchg/guest" "$6/guest"
  fi
  if [[ -n $2 ]]; then
    stop_qemu "$2" "$3" || stopped=1
  fi
  rm -rf -- "$5"
  write_cleanup_record "$2" "$3" "$5" "$6"
  if [[ -z $2 || ${status} -ne 0 || $4 -ne 0 || ${stopped} -ne 0 ]]; then
    printf 'VM observation failed (QEMU PID %s, exit status %s, observation failed %s, stop failed %s)\n' \
      "${2:-none}" "${status}" "$4" "${stopped}" >&2
    return 1
  fi
}

boot() {
  local architecture="$1" out="$2" work runner qemu qemu_pid="" qemu_start="" pid observe_failed=0
  require_architecture "${architecture}"
  qemu="$(store_path qemu "${out}")"
  work="$(mktemp -d)"
  mkdir -p "${work}/xchg"
  shopt -s nullglob
  local runners=("$(store_path vm "${out}")"/bin/run-*-vm)
  shopt -u nullglob
  if [[ ${#runners[@]} -ne 1 ]]; then
    printf 'expected one VM runner, found %s\n' "${#runners[@]}" >&2
    exit 1
  fi
  runner="${runners[0]}"
  {
    printf 'uname\t%s\n' "$(uname -srvm)"
    if [[ -e /dev/kvm ]]; then
      printf 'dev-kvm\t%s\n' "$(stat -c '%A %U %G' /dev/kvm)"
    else
      printf 'dev-kvm\tabsent\n'
    fi
  } >"${out}/host/runner"

  # Default-deny egress: QEMU runs as the runner user in a fresh network
  # namespace that has only a down loopback, and the guest has no NIC.
  sudo unshare --net -- setpriv --reuid="$(id -u)" --regid="$(id -g)" --clear-groups -- \
    env -i PATH="${PATH}" HOME="${HOME}" TMPDIR="${work}" USE_TMPDIR=1 \
    timeout --kill-after=60 2700 \
    bash -c 'printf "%s\n" "$$" >"$1" && exec "$2"' launcher "${work}/qemu.pid" "${runner}" \
    </dev/null >"${out}/host/serial-console.log" 2>&1 &
  local launcher=$!
  # The launcher shell writes its own PID, then execs the VM runner, which
  # execs QEMU: the same process becomes QEMU.
  for _ in $(seq 120); do
    pid="$(cat "${work}/qemu.pid" 2>/dev/null || true)"
    if [[ ${pid} =~ ^[0-9]+$ ]] && is_qemu_image "$(sudo readlink "/proc/${pid}/exe" 2>/dev/null || true)" \
      "${qemu}" "${architecture}"; then
      # The start time pins this exact process against PID reuse.
      qemu_start="$(process_stat "${pid}")"
      if [[ ${qemu_start} =~ ^[A-Za-z]\ [0-9]+$ ]]; then
        qemu_pid="${pid}"
        qemu_start="${qemu_start#* }"
        break
      fi
    fi
    sleep 1
  done
  if [[ -n ${qemu_pid} ]]; then
    record_qemu "${qemu_pid}" "${out}" || observe_failed=1
    # The accelerator QEMU itself reports (ADR-069 R13 §2.3).
    python3 -I "${root}/scripts/qemu_qmp_query_kvm.py" "${work}/qmp.sock" "${qemu_pid}" \
      >"${out}/host/qemu-query-kvm.json" || observe_failed=1
  else
    # Say why, so the next run names the cause rather than a timeout.
    {
      printf 'QEMU was not observed; launcher PID file: %s\n' "${pid:-missing}"
      if [[ ${pid} =~ ^[0-9]+$ ]]; then
        sudo ls -l "/proc/${pid}/exe" || true
        sudo cat "/proc/${pid}/comm" || true
      fi
      ps -o pid,ppid,user,stat,comm,args -u "$(id -u)" || true
    } >&2
  fi
  finish_boot "${launcher}" "${qemu_pid}" "${qemu_start}" "${observe_failed}" "${work}" "${out}"
}

seal() {
  local out="$1" digest
  (
    cd "${out}"
    find . -type f ! -path ./SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >SHA256SUMS
  )
  digest="$(sha256sum "${out}/SHA256SUMS" | cut -d' ' -f1)"
  printf 'SHA256SUMS sha256 %s\n' "${digest}"
  if [[ -n ${GITHUB_STEP_SUMMARY-} ]]; then
    printf 'Evidence manifest `SHA256SUMS` sha256: `%s`\n' "${digest}" >>"${GITHUB_STEP_SUMMARY}"
  fi
}

# Sourcing the script (scripts/test_qemu_closure_evidence_producer.py) only
# defines the functions.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  case "${1-}" in
  build | boot)
    [[ $# -eq 3 ]] || usage
    "$1" "$2" "$3"
    ;;
  seal)
    [[ $# -eq 2 ]] || usage
    seal "$2"
    ;;
  *) usage ;;
  esac
fi
