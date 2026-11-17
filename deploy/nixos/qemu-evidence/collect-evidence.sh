# Records the packaged-closure state that ADR-087 gate 5 asks #444 to show.
# writeShellApplication adds the shebang, errexit, nounset and pipefail.
# Every file is raw command output; scripts/check_qemu_closure_evidence.py on
# the host owns every judgement. A missing `status` file means no evidence.

# The state of the task whose stat file is $1, or nothing once it is gone.
# Fails if the task's directory exists but its stat cannot be read. The comm
# field may hold spaces, so fields are read after its last ')'.
task_state() { # STAT_FILE
  local stat fields
  if ! stat="$(cat "$1")"; then
    [[ ! -e ${1%/stat} ]]
    return
  fi
  read -r -a fields <<<"${stat##*) }"
  printf '%s %s\n' "${fields[0]}" "${fields[19]}"
}

# The start time of PID, or nothing once every one of its threads has exited.
# A zombie thread-group leader whose other threads still run is a process
# that still exists, so it keeps its start time.
start_time() { # PID
  local state task
  state="$(task_state "/proc/$1/stat")" || return 1
  [[ -n ${state} ]] || return 0
  if [[ ${state%% *} == [ZX] ]]; then
    for task in "/proc/$1/task/"*/stat; do
      task="$(task_state "${task}")" || return 1
      if [[ -n ${task} && ${task%% *} != [ZX] ]]; then
        printf '%s\n' "${state#* }"
        return 0
      fi
    done
    return 0
  fi
  printf '%s\n' "${state#* }"
}

# The PID, user and mount namespaces of PID.
namespaces() { # PID
  local ns link
  for ns in pid user mnt; do
    link="$(readlink "/proc/$1/ns/${ns}")" || return 1
    printf '%s\t%s\n' "${ns}" "${link}"
  done
}

# Record PID's executable, environment and namespaces in processes/PID. A
# process that exits during the scan, so that its start time is gone or
# differs afterwards (a reused PID), is skipped; any other failed read fails.
record_process() { # PID
  local before after recorded=0
  before="$(start_time "$1")" || return 1
  [[ -n ${before} ]] || return 0
  mkdir "processes/$1" || return 1
  if readlink "/proc/$1/exe" >"processes/$1/exe" \
    && cat "/proc/$1/environ" >"processes/$1/environ" \
    && namespaces "$1" >"processes/$1/namespaces"; then
    recorded=1
  fi
  after="$(start_time "$1")" || return 1
  if [[ ${after} != "${before}" ]]; then
    rm -r -- "processes/$1"
    return 0
  fi
  if [[ ${recorded} -eq 0 ]]; then
    printf 'cannot read running process %s\n' "$1" >&2
    return 1
  fi
}

# scripts/test_qemu_closure_evidence_producer.py sources the functions above.
if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
  return 0
fi

out="$1"
mkdir -p "$out"
cd "$out"

# Package and kernel identity, including this collector's own store path.
readlink -f "$0" >collector
uname -m >uname-machine
uname -r >uname-release
systemctl --version >systemctl-version
readlink -f /run/current-system >current-system
readlink -f /run/booted-system >booted-system
readlink -f /run/booted-system/kernel >booted-kernel
systemd_package="$(readlink -f /run/current-system/systemd)"
printf '%s\n' "${systemd_package}" >systemd-package
# systemd-detect-virt exits 1 when it prints "none".
systemd-detect-virt --vm >detect-virt-vm || true
systemd-detect-virt --container >detect-virt-container || true
for marker in /run/systemd/container /run/host/container-manager; do
  if [[ -e ${marker} || -L ${marker} ]]; then
    printf '%s\tpresent\n' "${marker}"
  else
    printf '%s\tabsent\n' "${marker}"
  fi
done >container-markers

# Boot nonce, and the guest's disks and overlays (ADR-069 R13 §4).
cat /proc/sys/kernel/random/boot_id >boot-id
cat /proc/self/mountinfo >mountinfo

# Kernel command line, configuration and log.
cat /proc/cmdline >proc-cmdline
zcat /proc/config.gz >kernel-config
journalctl --dmesg --boot --no-pager --output=cat >kernel-log

# .builtin_trusted_keys: /proc/keys gives its serial; keyctl lists and
# describes every member. Its name is not published for lookup by name.
cat /proc/keys >proc-keys
mapfile -t keyrings < <(awk '$8 == "keyring" && $9 == ".builtin_trusted_keys:" { print $1 }' proc-keys)
if [[ ${#keyrings[@]} -ne 1 ]]; then
  printf 'expected one .builtin_trusted_keys keyring, found %s\n' "${#keyrings[@]}" >&2
  exit 1
fi
keyring="$((16#${keyrings[0]}))"
read -r -a members <<<"$(keyctl rlist "${keyring}")"
{
  printf '%s\t%s\n' "${keyring}" "$(keyctl rdescribe "${keyring}")"
  for member in "${members[@]}"; do
    printf '%s\t%s\n' "${member}" "$(keyctl rdescribe "${member}")"
  done
} >builtin-trusted-keys

# Every verity.d directory systemd consults: CONF_PATHS_NULSTR, extended by
# the nixpkgs 0003-add-rootprefix-to-lookup-dir-paths patch with PREFIX/lib.
for dir in /etc/verity.d /run/verity.d /usr/local/lib/verity.d /usr/lib/verity.d \
  "${systemd_package}/lib/verity.d"; do
  if [[ -e ${dir} || -L ${dir} ]]; then
    printf '%s\t%s\n' "${dir}" "$(stat -c %F "${dir}")"
    find "${dir}" -mindepth 1 -printf '%p\t%y\n'
  else
    printf '%s\tabsent\n' "${dir}"
  fi
done >verity-d

# mountfsd: units, drop-ins, unit and manager environment, and every process
# of the started service (the daemon and its fixed workers).
systemctl start systemd-mountfsd.service
systemctl cat systemd-mountfsd.service systemd-mountfsd.socket >mountfsd-units
systemctl show systemd-mountfsd.service \
  --property=Id,ActiveState,SubState,MainPID,ControlGroup,FragmentPath,DropInPaths,ExecStart,Environment,EnvironmentFiles,PassEnvironment,UnsetEnvironment \
  >mountfsd-service-properties
systemctl show systemd-mountfsd.socket \
  --property=Id,ActiveState,SubState,FragmentPath,DropInPaths,Listen \
  >mountfsd-socket-properties
systemctl show-environment >manager-environment
control_group="$(systemctl show --property=ControlGroup --value systemd-mountfsd.service)"
for _ in $(seq 60); do
  workers=0
  while read -r pid; do
    if [[ "$(readlink "/proc/${pid}/exe")" == */systemd-mountwork ]]; then
      workers=$((workers + 1))
    fi
  done <"/sys/fs/cgroup${control_group}/cgroup.procs"
  if [[ ${workers} -gt 0 ]]; then
    break
  fi
  sleep 1
done
mkdir processes
while read -r pid; do
  record_process "${pid}"
done <"/sys/fs/cgroup${control_group}/cgroup.procs"
namespaces 1 >pid1-namespaces

printf 'complete\n' >status
