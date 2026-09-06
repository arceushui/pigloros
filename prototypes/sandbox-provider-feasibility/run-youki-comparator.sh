#!/usr/bin/env bash
set -euo pipefail

architecture=${1:?architecture is required}
expected_archive_sha256=${2:?archive SHA-256 is required}
youki_version=0.7.0
youki_source_commit=94ba653efbb180ce04650f6ae01a8e6bc8f96d92
archive="youki-${youki_version}-${architecture}-gnu.tar.gz"
download_url="https://github.com/youki-dev/youki/releases/download/v${youki_version}/${archive}"
evidence_dir=youki-comparator-evidence
summary=youki-comparator.txt
scratch=$(mktemp -d "${RUNNER_TEMP:-/tmp}/pigloros-youki-comparator.XXXXXX")
runtime_root="$scratch/runtime"
bundle="$scratch/bundle"
container_id="pigloros-youki-comparator-${architecture}"
container_pid=

cleanup() {
  if test -x "$scratch/youki"; then
    sudo "$scratch/youki" --root "$runtime_root" delete --force "$container_id" \
      >/dev/null 2>&1 || true
  fi
  case "$scratch" in
    "${RUNNER_TEMP:-/tmp}"/pigloros-youki-comparator.*) rm -rf "$scratch" ;;
    *) printf 'refusing to remove unexpected scratch path: %s\n' "$scratch" >&2 ;;
  esac
}
trap cleanup EXIT

mkdir -p "$evidence_dir" "$runtime_root" "$bundle"
curl --fail --location --silent --show-error "$download_url" --output "$scratch/$archive"
printf '%s  %s\n' "$expected_archive_sha256" "$scratch/$archive" | sha256sum --check
tar -xzf "$scratch/$archive" -C "$scratch"
youki_binary=$(find "$scratch" -type f -name youki -perm -u+x -print -quit)
test -n "$youki_binary"
if test "$youki_binary" != "$scratch/youki"; then
  mv "$youki_binary" "$scratch/youki"
fi

cc -static -Os -Wall -Wextra -Werror youki-comparator-payload.c \
  -o "$scratch/payload"

prepare_rootfs() {
  rm -rf "$bundle/rootfs"
  mkdir -p "$bundle/rootfs/dev/pts" "$bundle/rootfs/dev/shm" \
    "$bundle/rootfs/etc" "$bundle/rootfs/proc" "$bundle/rootfs/sys" \
    "$bundle/rootfs/tmp"
  cp "$scratch/payload" "$bundle/rootfs/payload"
}

prepare_rootfs

cp youki-comparator-config.json "$bundle/config.json"
test "$(jq -r '.ociVersion' "$bundle/config.json")" = 1.1.0

cp "$bundle/config.json" "$evidence_dir/oci-config.json"
"$scratch/youki" --version | tee "$evidence_dir/youki-version.txt"
grep -q '^spec: 1\.1\.0$' "$evidence_dir/youki-version.txt"
sha256sum "$scratch/youki" "$scratch/$archive" | tee "$evidence_dir/youki-digests.txt"
stat --format='youki_binary_bytes=%s' "$scratch/youki" | tee "$evidence_dir/youki-size.txt"
ldd "$scratch/youki" | tee "$evidence_dir/youki-ldd.txt"
"$scratch/youki" features >"$evidence_dir/youki-features.json"

source_archive="$scratch/youki-source.tar.gz"
curl --fail --location --silent --show-error \
  "https://github.com/youki-dev/youki/archive/${youki_source_commit}.tar.gz" \
  --output "$source_archive"
mkdir "$scratch/source"
tar -xzf "$source_archive" -C "$scratch/source"
source_checkout=$(find "$scratch/source" -mindepth 1 -maxdepth 1 -type d -print -quit)
source_root="$source_checkout/crates"
find "$source_root/libcontainer/src" -type f -name '*.rs' -print0 |
  sort -z | xargs -0 wc -l >"$evidence_dir/libcontainer-lines.txt"
find "$source_root/libcgroups/src" -type f -name '*.rs' -print0 |
  sort -z | xargs -0 wc -l >"$evidence_dir/libcgroups-lines.txt"
cp "$source_root/libcontainer/Cargo.toml" "$evidence_dir/libcontainer-Cargo.toml"
cp "$source_root/libcgroups/Cargo.toml" "$evidence_dir/libcgroups-Cargo.toml"

lifecycle_started=$(date +%s%N)
sudo "$scratch/youki" --root "$runtime_root" create --bundle "$bundle" \
  --pid-file "$scratch/container.pid" "$container_id"
sudo "$scratch/youki" --root "$runtime_root" state "$container_id" \
  | tee "$evidence_dir/state-created.json"
test "$(jq -r '.ociVersion' "$evidence_dir/state-created.json")" = 1.1.0
sudo "$scratch/youki" --root "$runtime_root" start "$container_id"
sudo "$scratch/youki" --root "$runtime_root" state "$container_id" \
  | tee "$evidence_dir/state-running.json"
container_pid=$(jq -r '.pid' "$evidence_dir/state-running.json")
test "$container_pid" -gt 1

: >"$evidence_dir/namespaces.txt"
for namespace in mnt pid ipc uts net cgroup; do
  host_inode=$(readlink "/proc/self/ns/$namespace")
  container_inode=$(sudo readlink "/proc/$container_pid/ns/$namespace")
  printf '%s;host=%s;container=%s\n' "$namespace" "$host_inode" "$container_inode" \
    | tee -a "$evidence_dir/namespaces.txt"
  test "$host_inode" != "$container_inode"
done
printf 'user;host=%s;container=%s;requested=false\n' \
  "$(readlink /proc/self/ns/user)" "$(sudo readlink "/proc/$container_pid/ns/user")" \
  | tee -a "$evidence_dir/namespaces.txt"

sudo awk '/^Cap(Inh|Prm|Eff|Bnd|Amb):|^NoNewPrivs:/' \
  "/proc/$container_pid/status" | tee "$evidence_dir/process-security.txt"
grep -q '^NoNewPrivs:[[:space:]]*1$' "$evidence_dir/process-security.txt"
test "$(awk '/^CapEff:/ { print $2 }' "$evidence_dir/process-security.txt")" = 0000000000000000

cgroup_path=$(sudo awk -F: '$1 == "0" { print $3 }' "/proc/$container_pid/cgroup")
test -n "$cgroup_path"
cgroup_dir="/sys/fs/cgroup$cgroup_path"
{
  printf 'cgroup_path=%s\n' "$cgroup_path"
  printf 'memory.max=%s\n' "$(sudo cat "$cgroup_dir/memory.max")"
  printf 'cpu.max=%s\n' "$(sudo cat "$cgroup_dir/cpu.max")"
  printf 'pids.max=%s\n' "$(sudo cat "$cgroup_dir/pids.max")"
} | tee "$evidence_dir/cgroup-readback.txt"
grep -q '^memory.max=67108864$' "$evidence_dir/cgroup-readback.txt"
grep -q '^cpu.max=10000 100000$' "$evidence_dir/cgroup-readback.txt"
grep -q '^pids.max=16$' "$evidence_dir/cgroup-readback.txt"

sudo "$scratch/youki" --root "$runtime_root" kill "$container_id" KILL
for _ in $(seq 1 100); do
  test ! -e "/proc/$container_pid" && break
  sleep 0.05
done
test ! -e "/proc/$container_pid"
sudo "$scratch/youki" --root "$runtime_root" delete --force "$container_id"
test ! -e "$cgroup_dir"
if sudo "$scratch/youki" --root "$runtime_root" state "$container_id" \
  >"$evidence_dir/state-after-delete.txt" 2>&1; then
  printf 'deleted container unexpectedly remained addressable\n' >&2
  exit 1
fi
lifecycle_us=$((($(date +%s%N) - lifecycle_started) / 1000))

jq '.process.args = ["/payload", "1"]' "$bundle/config.json" >"$scratch/sample-config.json"
mv "$scratch/sample-config.json" "$bundle/config.json"
: >"$evidence_dir/launch-cleanup-samples-us.txt"
for sample in $(seq 1 30); do
  sample_id="pigloros-youki-${architecture}-${sample}"
  container_id=$sample_id
  prepare_rootfs
  jq --arg path "pigloros/$sample_id" '.linux.cgroupsPath = $path' \
    "$bundle/config.json" >"$scratch/sample-config.json"
  mv "$scratch/sample-config.json" "$bundle/config.json"
  sample_started=$(date +%s%N)
  sudo timeout --kill-after=2s 10s "$scratch/youki" --root "$runtime_root" \
    run --bundle "$bundle" "$sample_id"
  sample_us=$((($(date +%s%N) - sample_started) / 1000))
  printf '%s\n' "$sample_us" >>"$evidence_dir/launch-cleanup-samples-us.txt"
  printf 'youki_sample=%s;duration_us=%s\n' "$sample" "$sample_us"
done
launch_cleanup_p95_us=$(sort -n "$evidence_dir/launch-cleanup-samples-us.txt" | sed -n '29p')

libcontainer_lines=$(tail -n 1 "$evidence_dir/libcontainer-lines.txt" | awk '{ print $1 }')
libcgroups_lines=$(tail -n 1 "$evidence_dir/libcgroups-lines.txt" | awk '{ print $1 }')
{
  printf 'youki_comparator=executed-cleanup-ok\n'
  printf 'architecture=%s\n' "$architecture"
  printf 'version=%s\n' "$youki_version"
  printf 'archive_sha256=%s\n' "$expected_archive_sha256"
  printf 'source_commit=%s\n' "$youki_source_commit"
  printf 'oci_version=1.1.0\n'
  printf 'namespace_separation=mnt-pid-ipc-uts-net-cgroup\n'
  printf 'user_namespace=requested-false\n'
  printf 'cgroup_readback=memory-cpu-pids-ok\n'
  printf 'process_security=no-new-privileges-empty-effective-capabilities\n'
  printf 'lifecycle_us=%s\n' "$lifecycle_us"
  printf 'launch_cleanup_samples=30\n'
  printf 'launch_cleanup_p95_us=%s\n' "$launch_cleanup_p95_us"
  printf 'libcontainer_rust_lines=%s\n' "$libcontainer_lines"
  printf 'libcgroups_rust_lines=%s\n' "$libcgroups_lines"
  printf 'network_policy=external-not-proved\n'
  printf 'signed_image_admission=external-not-proved\n'
  printf 'pigloros_authority_and_evidence=external-not-proved\n'
  printf 'rootfs_reuse=requires-fresh-preparation-after-runtime-setup\n'
} | tee "$summary"
