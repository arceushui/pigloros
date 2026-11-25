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

# --- Part (b): MountImage cases -------------------------------------------

# Every loop device with a backing file, and every device-mapper device:
#   loop NAME BACKING_FILE RESOLVED_PATH MAJOR:MINOR PARTITIONS
#   dm NAME DM_NAME DM_UUID MAJOR:MINOR SLAVES
# RESOLVED_PATH is the backing file resolved in this namespace, or "-".
devices() {
  local block name backing resolved
  for block in /sys/block/loop* /sys/block/dm-*; do
    [[ -e ${block} ]] || continue
    name="${block##*/}"
    if [[ ${name} == loop* ]]; then
      [[ -e ${block}/loop/backing_file ]] || continue
      backing="$(cat "${block}/loop/backing_file")"
      resolved="$(readlink -e -- "${backing}" || printf -- '-')"
      printf 'loop\t%s\t%s\t%s\t%s\t%s\n' "${name}" "${backing}" "${resolved}" "$(cat "${block}/dev")" \
        "$(find -H "${block}" -mindepth 1 -maxdepth 1 -name "${name}p*" -printf '%f\n' | sort | paste -sd, -)"
    else
      printf 'dm\t%s\t%s\t%s\t%s\t%s\n' "${name}" "$(cat "${block}/dm/name")" "$(cat "${block}/dm/uuid")" \
        "$(cat "${block}/dev")" "$(find "${block}/slaves" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | paste -sd, -)"
    fi
  done
}

# Read the held root's readback file through the mount: the whole file, then
# its first block alone. Each line is "<what>\t<exit status>\t<sha256 or error>".
readback() { # ROOT
  local file="$1/usr/share/pigloros/readback" digest status what
  for what in file block-0; do
    status=0
    if [[ ${what} == file ]]; then
      digest="$(sha256sum <"${file}" 2>&1)" || status=$?
    else
      digest="$(dd if="${file}" bs=4096 count=1 status=none 2>&1 | sha256sum 2>&1)" || status=$?
    fi
    if [[ ${status} -eq 0 ]]; then
      digest="${digest%% *}"
    else
      digest="${digest//[$'\t\n']/ }"
    fi
    printf '%s\t%s\t%s\n' "${what}" "${status}" "${digest}"
  done
}

# Snapshot the devices into FILE until no loop device and no device-mapper
# device remain, for at most 60 s: their removal can lag the unmount.
settled_devices() { # FILE
  for _ in $(seq 60); do
    devices >"$1"
    if [[ ! -s $1 ]]; then
      return 0
    fi
    sleep 1
  done
}

# The provider's empty private runtime directories, as its startup leaves them.
provision_runtime() {
  local directory
  for directory in /run/pigloros /run/pigloros/sandbox /run/pigloros/sandbox/registry \
    /run/pigloros/sandbox/attempts; do
    mkdir -m 0700 "${directory}"
  done
}

# Run the driver on one image. It reports the activation on its first line,
# holds a mounted root while this records the live kernel state, and releases
# it when its standard input closes. Afterwards the runtime tree is recorded
# and removed: restart reconciliation is part (c).
driver_case() { # NAME IMAGE CERTIFICATE_DER DESCRIPTION
  local dir="cases/$1" fifo=/run/piglor-evidence-control control line root pid status=0 start
  mkdir -p "${dir}"
  # The image's own /adapter and its signed argument vector, which the driver
  # binds in the staged SIM1.
  printf '%s\n' "$2" "$3" "$4" "${images}/adapter" honest >"${dir}/arguments"
  provision_runtime
  devices >"${dir}/devices-before"
  # The control FIFO lives on the guest's tmpfs, not on the 9p evidence share.
  mkfifo -m 0600 "${fifo}"
  start="$(cut -d ' ' -f 1 /proc/uptime)"
  pos-sandboxd-conformance "$2" "$3" "$4" "${images}/adapter" honest <"${fifo}" >"${dir}/report" 2>"${dir}/driver-stderr" &
  pid=$!
  exec {control}>"${fifo}"
  for _ in $(seq 600); do
    if [[ -s ${dir}/report ]] || ! kill -0 "${pid}" 2>/dev/null; then
      break
    fi
    sleep 0.5
  done
  # Seconds from the driver's start to its activation report, for reading
  # the TCG run against the provider's 60 s MountImage bounds.
  awk -v start="${start}" '{ printf "activation-seconds\t%.2f\n", $1 - start }' /proc/uptime >"${dir}/timing"
  line="$(head -n 1 "${dir}/report")"
  if [[ ${line} == activation$'\t'mounted$'\t'* ]]; then
    root="${line##*$'\t'}"
    devices >"${dir}/devices-held"
    cat /proc/self/mountinfo >"${dir}/mountinfo-held"
    dmsetup table >"${dir}/dm-table-held"
    readback "${root}" >"${dir}/readback"
  fi
  exec {control}>&-
  wait "${pid}" || status=$?
  rm -- "${fifo}"
  printf '%s\n' "${status}" >"${dir}/driver-status"
  settled_devices "${dir}/devices-after"
  find /run/pigloros -printf '%P\t%y\t%m\n' | sort >"${dir}/runtime-after"
  rm -rf /run/pigloros
}

# One raw MountImage call with the provider's exact parameters, so that the
# reply mountfsd sends is recorded verbatim. varlinkctl exits with the reply,
# closing the returned mount descriptor; the devices must then go away.
mountfsd_reply_case() { # IMAGE
  local dir=cases/mountfsd-reply image=/run/piglor-evidence-image.raw status=0 fd start
  mkdir -p "${dir}"
  cp -- "$1" "${image}"
  devices >"${dir}/devices-before"
  # Pass a read-only descriptor, as the provider does, not a path.
  exec {fd}<"${image}"
  start="$(cut -d ' ' -f 1 /proc/uptime)"
  # varlinkctl's own default timeout is shorter than this cold first call
  # under aarch64 TCG (run 43903782177); its duration is recorded instead.
  varlinkctl call --timeout=600 --push-fd="${fd}" /run/systemd/io.systemd.MountFileSystem \
    io.systemd.MountFileSystem.MountImage \
    '{"imageFileDescriptor":0,"readOnly":true,"growFileSystems":false,"imagePolicy":"root=signed+erofs:=absent","relaxExtensionReleaseChecks":false,"veritySharing":false,"allowInteractiveAuthentication":false}' \
    >"${dir}/reply" 2>"${dir}/stderr" || status=$?
  awk -v start="${start}" '{ printf "mountimage-seconds\t%.2f\n", $1 - start }' /proc/uptime >"${dir}/timing"
  exec {fd}<&-
  printf '%s\n' "${status}" >"${dir}/status"
  settled_devices "${dir}/devices-after"
  rm -- "${image}"
}

# --- ADR-069 R14: the network a PrivateNetwork= unit gets -----------------

# The sysctl behind "net.core.fb_tunnels_only_for_init_net".
FB_TUNNELS_SYSCTL=/proc/sys/net/core/fb_tunnels_only_for_init_net

# What a unit sees of its network, as raw `ip` output, written under DIR.
network_probe() { # DIR
  readlink /proc/self/ns/net >"$1/netns"
  ip -o link show >"$1/links"
  ip -o addr show >"$1/addrs"
  ip -4 route show table all >"$1/routes4"
  ip -6 route show table all >"$1/routes6"
}

# One transient PrivateNetwork=yes unit's network with the sysctl set to VALUE.
# The kernel reads the sysctl when it creates a network namespace, so each
# value governs the next unit. The unit runs with this script's PATH for `ip`
# and with this script's own bash (${BASH}): a NixOS unit's default PATH holds
# no bash, so `systemd-run bash` fails to find it. `stderr` holds systemd-run's
# client-side errors (an executable that is not found, a bus error) and the
# unit's own standard error. A start-job or unit failure that systemd-run does
# not print can leave `stderr` empty: the unit's `journal` is then the
# explanation. (--quiet suppresses informational output; whether it also hides
# a start-job failure is not verified here.)
network_case() { # NAME VALUE
  local dir="network/$1" status=0
  mkdir -p "${dir}"
  printf '%s\n' "$2" >"${FB_TUNNELS_SYSCTL}"
  cat "${FB_TUNNELS_SYSCTL}" >"${dir}/sysctl"
  systemd-run --quiet --unit="piglor-network-$1" --wait --collect --pipe \
    --property=PrivateNetwork=yes --setenv=PATH \
    "${BASH}" -c "set -o errexit; $(declare -f network_probe); network_probe \"\$1\"" probe \
    "${PWD}/${dir}" 2>"${dir}/stderr" || status=$?
  journalctl --boot --no-pager --output=short-monotonic --unit="piglor-network-$1.service" \
    >"${dir}/journal" || true
  printf '%s\n' "${status}" >"${dir}/status"
}

# Put the sysctl back to the value recorded at boot in network/boot-sysctl,
# so later cases run as the package ships.
restore_fb_tunnels() {
  cat network/boot-sysctl >"${FB_TUNNELS_SYSCTL}"
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

# Part (b). The positive image is signed by the key the kernel trusts; the
# tampered one has one data byte flipped after signing; the wrong-key image is
# signed by a key no kernel trusts, first alone and then with that key's
# certificate in /run/verity.d, which only userspace verification would read.
images="${PIGLOR_EVIDENCE_IMAGES:?}"
mkdir cases
# The raw call runs first. Its first MountImage also loads what mountfsd's
# probing needs, which under aarch64 TCG took longer than the provider's 60 s
# bound (run 43854451008). So the driver cases measure warm activations only;
# the cold call's duration is recorded in its timing file.
mountfsd_reply_case "${images}/positive.raw"
for case in positive tampered wrong-key; do
  driver_case "${case}" "${images}/${case}.raw" "${images}/${case}.der" "$(cat "${images}/${case}.description")"
done
mkdir /run/verity.d
cp -- "${images}/wrong-key.crt" /run/verity.d/piglor-untrusted.crt
find /run/verity.d -mindepth 1 -printf '%p\t%y\n' >cases/verity-d-planted
driver_case verity-d "${images}/wrong-key.raw" "${images}/wrong-key.der" "$(cat "${images}/wrong-key.description")"
rm -r -- /run/verity.d
journalctl --dmesg --boot --no-pager --output=cat >cases/kernel-log
# mountfsd's own log, with monotonic times, for reading each case's refusal.
journalctl --boot --no-pager --output=short-monotonic --unit=systemd-mountfsd.service >cases/mountfsd-log

# ADR-069 R14: the init namespace and its fallback tunnel devices, then the
# unit namespace under each value of the fallback-tunnel sysctl. The modules
# guest.nix loads are the ones that create fallback devices.
mkdir network
cat "${FB_TUNNELS_SYSCTL}" >network/boot-sysctl
readlink /proc/1/ns/net >network/init-netns
ip -o link show >network/init-links
cat /proc/modules >network/modules
for value in 0 1 2; do
  network_case "fb-${value}" "${value}"
done
restore_fb_tunnels

printf 'complete\n' >status
