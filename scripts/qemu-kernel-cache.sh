#!/usr/bin/env bash
# Reuse the #444 evidence guest's kernel build (ADR-087 gate 5) across runs.
#
#   key ARCH         print the cache key: the signing key name and the kernel
#                    derivation's store hash
#   build ARCH       (main only) build every kernel output
#   export ARCH DIR  (main only) sign every built kernel output into a file
#                    binary cache in DIR, then verify DIR
#   verify ARCH DIR  require DIR to hold every output's closure, intact and
#                    signed by a key in trusted-public-keys
#   import ARCH DIR  copy every kernel output from DIR into the store
#   fetch ARCH DIR   download ARCH's published cache into DIR; print hit=true,
#                    or hit=false when nothing is published for this kernel
#   publish ARCH DIR (main only) upload DIR as ARCH's release asset
#   prune ARCH       (main only) delete ARCH's assets for other kernel
#                    derivations once they are a week old, keeping the newest
#                    of them
#   selftest DIR     (pull requests; needs jq, which the hosted Ubuntu runners
#                    ship) run the same signing, verifying and import
#                    code on a throwaway input-addressed path with a throwaway
#                    key. It proves the committed public key is trusted, not
#                    that the environment's secret matches it; export checks
#                    that on main.
#
# Every output the kernel derivation declares is cached (nixpkgs declares out,
# dev and modules); a missing output would make Nix rebuild the derivation.
#
# The guest kernel is rebuilt from source with the dev/test certificate, which
# took about 86 of the 105 minutes of every evidence run. Its derivation
# depends only on deploy/nixos and the pinned nixpkgs, so the same derivation
# hash names the same build.
#
# Storage: one asset per kernel derivation on the qemu-kernel-cache release
# (a prerelease, never "latest"), named after the cache key. Release assets are
# not evicted; the Actions cache, always near its 10 GB limit, evicted the
# kernel within hours of saving it. Fetching needs only read access; only the
# main-only kernel cache job publishes. Where the files live is not part of
# the trust: every path must still carry the main-only signature. The release
# must stay mutable: the repository's immutable-releases setting is off
# (2026-11-20), and turning it on would stop publish and prune.
#
# Trust: the Nix daemon keeps require-sigs = true (scripts/install-pinned-nix.sh).
# export signs every path it writes with the secret key in
# QEMU_KERNEL_CACHE_SIGNING_KEY and refuses a key whose public half is not in
# the trusted-public-keys that /etc/nix/nix.conf gives both the client and the
# daemon; install-pinned-nix.sh trusts that public half. The secret belongs to
# the qemu-kernel-cache GitHub environment, whose deployment policy allows only
# main. That policy is a repository setting, which the workflow policy oracle
# cannot read. import never disables signature checks, so the daemon refuses an
# unsigned or foreign path. Only main publishes; pull requests fetch the
# asset named by the exact key. The key name is part of that key, so a
# rotated key never fetches entries signed by the old one.
# Needs bash 4.4 or later (inherit_errexit); the hosted Ubuntu runners ship 5.x.
set -euo pipefail
# A failure inside $(...) stops the script too, as it does outside.
shopt -s inherit_errexit

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
flake="${root}/deploy/nixos"
key_file=""
signing_key_name=piglor-qemu-kernel-1
release_tag=qemu-kernel-cache
# GitHub refuses release assets of 2 GiB or more.
asset_limit=$((2 * 1024 * 1024 * 1024))

usage() {
  printf 'usage: %s key ARCH | build ARCH | prune ARCH | export ARCH DIR | verify ARCH DIR | import ARCH DIR | fetch ARCH DIR | publish ARCH DIR | selftest DIR\n' "$0" >&2
  exit 2
}

require_architecture() {
  case "$1" in
  x86_64 | aarch64) ;;
  *) usage ;;
  esac
}

kernel_attribute() {
  printf '%s#nixosConfigurations.qemu-evidence-%s.config.boot.kernelPackages.kernel' "${flake}" "$1"
}

# The concrete path of every kernel output, evaluated against the local
# store. Passing them instead of flake installables keeps `nix copy` from
# evaluating the flake against the file binary cache, and keeps export from
# building anything.
kernel_paths() {
  nix eval --raw --no-update-lock-file "$(kernel_attribute "$1")" --apply \
    'kernel: builtins.concatStringsSep "\n" (map (output: (builtins.getAttr output kernel).outPath) kernel.outputs) + "\n"'
}

read_kernel_paths() {
  mapfile -t paths < <(kernel_paths "$1")
  local path
  if ((${#paths[@]} == 0)); then
    printf 'the kernel has no output paths\n' >&2
    exit 1
  fi
  for path in "${paths[@]}"; do
    if ! [[ ${path} =~ ^/nix/store/[0-9a-z]{32}-[^/]+$ ]]; then
      printf 'unexpected kernel output path: %s\n' "${path}" >&2
      exit 1
    fi
  done
}

cache_key() {
  local drv hash
  drv="$(nix eval --raw --no-update-lock-file "$(kernel_attribute "$1").drvPath")"
  hash="$(basename -- "${drv}")"
  hash="${hash%%-*}"
  if ! [[ ${hash} =~ ^[0-9a-z]{32}$ ]]; then
    printf 'unexpected kernel derivation path: %s\n' "${drv}" >&2
    exit 1
  fi
  printf 'qemu-kernel-%s-%s-%s\n' "${signing_key_name}" "$1" "${hash}"
}

key() {
  local name
  name="$(cache_key "$1")"
  printf 'key=%s\n' "${name}"
}

build() {
  local kernel
  kernel="$(kernel_attribute "$1")"
  nix build --no-update-lock-file --no-link --print-build-logs "${kernel}^*"
}

remove_key_file() {
  if [[ -n ${key_file} ]]; then
    rm -f -- "${key_file}"
  fi
}

trusted_public_keys() {
  nix config show trusted-public-keys
}

# in_list WORD LIST: LIST, whitespace-separated, contains WORD as a whole
# entry. read -d '' -a takes every line and splits without glob expansion;
# it returns 1 at the end of input, which is not an error here.
in_list() {
  local entry entries
  read -r -d '' -a entries <<<"$2" || true
  for entry in "${entries[@]}"; do
    if [[ ${entry} == "$1" ]]; then
      return 0
    fi
  done
  return 1
}

require_trusted() {
  if ! in_list "$1" "$(trusted_public_keys)"; then
    printf 'the signing key public half %s is not in trusted-public-keys\n' "$1" >&2
    exit 1
  fi
}

# sign_into SECRET DIR PATH...: write the closures of PATH... to the file
# binary cache DIR, each signed with SECRET held in a private temporary file.
sign_into() {
  local secret=$1 dir=$2
  shift 2
  trap remove_key_file EXIT
  trap 'exit 143' TERM
  trap 'exit 130' INT
  key_file="$(umask 077 && mktemp)"
  printf '%s' "${secret}" >"${key_file}"
  # Compressed NARs keep each architecture's asset under GitHub's 2 GiB limit.
  nix copy --to "file://${dir}?compression=zstd&secret-key=${key_file}" "$@"
  remove_key_file
}

# verify_paths DIR PATH...: every path in the closures must be intact and
# signed by a key in trusted-public-keys, which is what the daemon checks.
verify_paths() {
  local dir=$1
  shift
  nix store verify --recursive --store "file://${dir}" --sigs-needed 1 "$@"
}

verify_cache() {
  read_kernel_paths "$1"
  verify_paths "$2" "${paths[@]}"
}

export_cache() {
  local secret public
  secret="${QEMU_KERNEL_CACHE_SIGNING_KEY:-}"
  # No child process inherits the secret; it reaches nix on stdin or as a
  # 0600 file.
  unset QEMU_KERNEL_CACHE_SIGNING_KEY
  if [[ -z ${secret} ]]; then
    printf 'QEMU_KERNEL_CACHE_SIGNING_KEY is not set\n' >&2
    exit 1
  fi
  public="$(printf '%s' "${secret}" | nix key convert-secret-to-public)"
  if [[ ${public} != "${signing_key_name}":* ]]; then
    printf 'the signing key is not named %s\n' "${signing_key_name}" >&2
    exit 1
  fi
  require_trusted "${public}"
  read_kernel_paths "$1"
  sign_into "${secret}" "$2" "${paths[@]}"
  verify_cache "$1" "$2"
}

# import_paths DIR PATH...: the daemon checks every signature.
import_paths() {
  local dir=$1
  shift
  nix copy --from "file://${dir}" "$@"
}

import_cache() {
  read_kernel_paths "$1"
  import_paths "$2" "${paths[@]}"
}

# The release's fully uploaded assets, one "NAME<TAB>CREATED" line each;
# nothing when the release does not exist yet. An upload that never finished
# is not listed, so the next main run replaces it.
release_assets() {
  local listing errors status=0
  errors="$(mktemp)"
  listing="$(gh release view "${release_tag}" --json assets \
    --jq '.assets[] | select(.state == "uploaded") | [.name, .createdAt] | @tsv' 2>"${errors}")" || status=$?
  if ((status != 0)); then
    if [[ $(<"${errors}") == 'release not found' ]]; then
      rm -f -- "${errors}"
      return 0
    fi
    cat -- "${errors}" >&2
    rm -f -- "${errors}"
    exit "${status}"
  fi
  rm -f -- "${errors}"
  printf '%s\n' "${listing}"
}

asset_names() {
  local name created
  while IFS=$'\t' read -r name created; do
    if [[ -n ${name} ]]; then
      printf '%s\n' "${name}"
    fi
  done <<<"$1"
}

# The archive holds only the binary cache's regular files and directories,
# at relative paths.
require_cache_archive() {
  local entry verbose names
  verbose="$(tar -tvf "$1")"
  names="$(tar -tf "$1")"
  while IFS= read -r entry; do
    if [[ ${entry} != [-d]* ]]; then
      printf 'the kernel cache archive holds a non-regular entry: %s\n' "${entry}" >&2
      exit 1
    fi
  done <<<"${verbose}"
  while IFS= read -r entry; do
    if ! [[ ${entry} =~ ^(\./)?([A-Za-z0-9+_.-]+/)*[A-Za-z0-9+_.-]*$ ]] || [[ /${entry}/ == */../* ]]; then
      printf 'unexpected kernel cache archive entry: %s\n' "${entry}" >&2
      exit 1
    fi
  done <<<"${names}"
}

fetch_cache() {
  local name assets downloads
  name="$(cache_key "$1").tar"
  # Assigned first: a failure inside an argument's $(...) would not stop the script.
  assets="$(release_assets)"
  assets="$(asset_names "${assets}")"
  if ! in_list "${name}" "${assets}"; then
    printf 'no published kernel cache %s\n' "${name}" >&2
    printf 'hit=false\n'
    return 0
  fi
  downloads="$(mktemp -d)"
  # A download that fails is a miss: main then rebuilds and replaces the
  # asset. An archive that downloads but is malformed, or fails the
  # signature check afterwards, is an error.
  if ! gh release download "${release_tag}" --pattern "${name}" --dir "${downloads}"; then
    rm -rf -- "${downloads}"
    printf 'the kernel cache %s could not be downloaded\n' "${name}" >&2
    printf 'hit=false\n'
    return 0
  fi
  require_cache_archive "${downloads}/${name}"
  # The caller's directory is emptied first: refuse a shallow path.
  if [[ $2 != /*/* ]]; then
    printf 'the kernel cache directory %s must be an absolute path two levels deep\n' "$2" >&2
    exit 2
  fi
  rm -rf -- "$2"
  mkdir -p -- "$2"
  tar -xf "${downloads}/${name}" -C "$2" --no-same-owner --no-same-permissions
  rm -rf -- "${downloads}"
  printf 'hit=true\n'
}

publish_cache() {
  local name archive uploads size
  name="$(cache_key "$1").tar"
  uploads="$(mktemp -d)"
  archive="${uploads}/${name}"
  tar -cf "${archive}" -C "$2" .
  size="$(stat -c %s -- "${archive}")"
  printf 'kernel cache archive %s: %s bytes\n' "${name}" "${size}"
  if ((size >= asset_limit)); then
    printf 'the kernel cache archive %s is 2 GiB or larger\n' "${name}" >&2
    exit 1
  fi
  # The two architectures publish at once: whichever creates the release
  # first wins, and the other must then find it.
  if ! gh release view "${release_tag}" >/dev/null 2>&1; then
    gh release create "${release_tag}" --prerelease --latest=false \
      --title 'QEMU evidence kernel cache' \
      --notes 'Signed Nix binary caches of the QEMU evidence guest kernel, one asset per kernel derivation (scripts/qemu-kernel-cache.sh).' ||
      gh release view "${release_tag}" >/dev/null
  fi
  # --clobber replaces an asset whose earlier upload never finished.
  gh release upload "${release_tag}" "${archive}" --clobber
  rm -rf -- "${uploads}"
}

# Runs on every main run, so a failed deletion is retried. Assets of every
# key name are pruned, including a rotated one. An asset goes only when it is
# more than a week old and is not the newest asset besides the current one: a
# rerun of an older main commit publishes its own kernel, and the kernel that
# pull requests fetch is then that newest other asset.
prune() {
  local name current assets created cutoff others
  current="$(cache_key "$1").tar"
  cutoff="$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)"
  assets="$(release_assets)"
  others=""
  while IFS=$'\t' read -r name created; do
    if [[ ${name} == qemu-kernel-*-"$1"-*.tar && ${name} != "${current}" ]]; then
      others+="${name}"$'\t'"${created}"$'\n'
    fi
  done <<<"${assets}"
  if [[ -z ${others} ]]; then
    return 0
  fi
  others="$(printf '%s' "${others}" | sort -t $'\t' -k2,2r)"
  # The first line is the newest other asset, which is kept.
  while IFS=$'\t' read -r name created; do
    if [[ ${created} < "${cutoff}" ]]; then
      gh release delete-asset "${release_tag}" "${name}" --yes
    fi
  done < <(printf '%s\n' "${others}" | tail -n +2)
}

# A path the store did not build or substitute from a trusted cache: built
# locally from an input-addressed derivation with a unique name, so it has no
# signature. A content-addressed path (nix store add-file, builtins.toFile)
# needs no signature at all and would prove nothing.
selftest_sample() {
  local nonce path info
  nonce="$(date +%s%N)"
  path="$(nix build --impure --no-link --print-out-paths --expr "derivation {
    name = \"qemu-kernel-cache-selftest-${nonce}\";
    system = builtins.currentSystem;
    builder = \"/bin/sh\";
    args = [ \"-c\" \"echo ${nonce} > \$out\" ];
  }")"
  info="$(nix path-info --json --json-format 1 "${path}")"
  # --argjson rejects empty or malformed output, which jq -e would pass.
  if ! jq -e -n --argjson info "${info}" '$info | [.[]] | length == 1 and all(.ca == null)' >/dev/null; then
    printf 'the self-test sample %s is content-addressed or its path-info is unreadable\n' "${path}" >&2
    exit 1
  fi
  printf '%s\n' "${path}"
}

selftest() {
  local dir=$1 secret public path entry entries found=false refused trusted
  # Read once, so both trust checks below judge the same, non-empty list.
  trusted="$(trusted_public_keys)"
  read -r -d '' -a entries <<<"${trusted}" || true
  for entry in "${entries[@]}"; do
    if [[ ${entry} =~ ^${signing_key_name}:[A-Za-z0-9+/]{43}=$ ]]; then
      found=true
    fi
  done
  if [[ ${found} != true ]]; then
    printf 'trusted-public-keys has no %s key\n' "${signing_key_name}" >&2
    exit 1
  fi
  secret="$(nix key generate-secret --key-name qemu-kernel-cache-selftest)"
  public="$(printf '%s' "${secret}" | nix key convert-secret-to-public)"
  if in_list "${public}" "${trusted}"; then
    printf 'the throwaway key %s is unexpectedly trusted\n' "${public}" >&2
    exit 1
  fi
  path="$(selftest_sample)"
  sign_into "${secret}" "${dir}" "${path}"
  NIX_CONFIG="trusted-public-keys = ${public}" verify_paths "${dir}" "${path}"
  if refused="$(verify_paths "${dir}" "${path}" 2>&1)"; then
    printf 'a path signed by an untrusted key passed verification\n' >&2
    exit 1
  fi
  if [[ ${refused} != *untrusted* ]]; then
    printf 'verification failed for a reason other than trust:\n%s\n' "${refused}" >&2
    exit 1
  fi
  nix store delete "${path}"
  if refused="$(import_paths "${dir}" "${path}" 2>&1)"; then
    printf 'the daemon imported a path signed by an untrusted key\n' >&2
    exit 1
  fi
  if [[ ${refused} != *signature* ]]; then
    printf 'the import failed for a reason other than its signature:\n%s\n' "${refused}" >&2
    exit 1
  fi
  printf 'kernel cache self-test passed\n'
}

case "${1:-}" in
key | build | prune)
  (($# == 2)) || usage
  require_architecture "$2"
  "$1" "$2"
  ;;
export | verify | import | fetch | publish)
  (($# == 3)) || usage
  require_architecture "$2"
  "$1_cache" "$2" "$3"
  ;;
selftest)
  (($# == 2)) || usage
  selftest "$2"
  ;;
*) usage ;;
esac
