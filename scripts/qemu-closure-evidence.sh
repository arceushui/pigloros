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
shopt -s extglob

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
flake="${root}/deploy/nixos"

provenance_files=(
  scripts/check_qemu_closure_evidence.py
  scripts/qemu-closure-evidence.sh
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

boot() {
  local architecture="$1" out="$2" work runner qemu_pid="" status=0 pid
  require_architecture "${architecture}"
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
  # execs QEMU: the same process becomes QEMU. nixpkgs wraps qemu-system-*
  # with wrapGApp, so the running image is bin/.qemu-system-<arch>-wrapped.
  for _ in $(seq 120); do
    pid="$(cat "${work}/qemu.pid" 2>/dev/null || true)"
    if [[ ${pid} =~ ^[0-9]+$ && "$(sudo readlink "/proc/${pid}/exe" 2>/dev/null || true)" == */bin/?(.)qemu-system-* ]]; then
      qemu_pid="${pid}"
      break
    fi
    sleep 1
  done
  if [[ -n ${qemu_pid} ]]; then
    sudo cat "/proc/${qemu_pid}/cmdline" >"${out}/host/qemu-argv"
    sudo readlink "/proc/${qemu_pid}/exe" >"${out}/host/qemu-exe"
    # The interfaces of QEMU's own network namespace.
    sudo cat "/proc/${qemu_pid}/net/dev" >"${out}/host/qemu-net-dev"
    # The accelerator QEMU itself reports (ADR-069 R13 §2.3).
    query_qmp "${work}/qmp.sock" >"${out}/host/qemu-query-kvm.json"
  else
    # Say why, so the next run names the cause rather than a timeout.
    {
      printf 'QEMU was not observed; launcher PID file: %s\n' "${pid:-missing}"
      if [[ ${pid} =~ ^[0-9]+$ ]]; then
        sudo ls -l "/proc/${pid}/exe" || true
        sudo cat "/proc/${pid}/comm" || true
        readlink "/proc/${pid}/exe" || true
      fi
      ps -o pid,ppid,user,stat,comm,args -u "$(id -u)" || true
    } >&2
  fi
  wait "${launcher}" || status=$?
  printf '%s\n' "${status}" >"${out}/host/vm-exit-status"
  tail -n 200 "${out}/host/serial-console.log"
  if [[ -d "${work}/xchg/guest" ]]; then
    cp -R -- "${work}/xchg/guest" "${out}/guest"
  fi
  # Stop the exact QEMU process and remove every disposable object before
  # any evidence is accepted (ADR-069 R13 §4). After a normal exit the wait
  # above has already reaped QEMU, so the kill only acts on a stuck process.
  if [[ -n ${qemu_pid} ]] && sudo kill -0 "${qemu_pid}" 2>/dev/null; then
    sudo kill -KILL "${qemu_pid}" || true
  fi
  rm -rf -- "${work}"
  {
    if [[ -n ${qemu_pid} && ! -e "/proc/${qemu_pid}" ]]; then
      printf 'qemu-process\texited\n'
    else
      printf 'qemu-process\tunobserved-or-running\n'
    fi
    if [[ ! -e ${work} ]]; then
      printf 'work-directory\tremoved\n'
    else
      printf 'work-directory\tpresent\n'
    fi
  } >"${out}/host/vm-cleanup"
  if [[ -z ${qemu_pid} || ${status} -ne 0 ]]; then
    printf 'VM observation failed (QEMU PID %s, exit status %s)\n' "${qemu_pid:-none}" "${status}" >&2
    exit 1
  fi
}

# One QMP exchange: capabilities, then query-kvm. Prints the query reply.
query_qmp() {
  python3 -I - "$1" <<'PYTHON'
import json, socket, sys
import time
# QEMU creates the listening socket shortly after its exec; retry briefly.
for attempt in range(60):
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(10)
    try:
        client.connect(sys.argv[1])
        break
    except (FileNotFoundError, ConnectionRefusedError):
        client.close()
        time.sleep(0.5)
else:
    sys.exit("QMP socket never accepted a connection")
stream = client.makefile("rw")
def reply():
    while True:
        message = json.loads(stream.readline())
        if "event" not in message:
            return message
reply()  # greeting
for command in ("qmp_capabilities", "query-kvm"):
    stream.write(json.dumps({"execute": command}) + "\n")
    stream.flush()
    answer = reply()
print(json.dumps(answer, sort_keys=True))
PYTHON
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
