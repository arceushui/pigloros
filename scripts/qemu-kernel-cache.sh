#!/usr/bin/env bash
# Reuse the #444 evidence guest's kernel build (ADR-087 gate 5) across runs.
#
#   key ARCH         print the cache key: the signing key name and the kernel
#                    derivation's store hash
#   build ARCH       (main only) build the kernel and its dev output
#   export ARCH DIR  (main only) sign the built kernel and its dev output into
#                    a file binary cache in DIR, then verify DIR
#   verify ARCH DIR  require DIR to hold both closures, intact and signed by a
#                    key in trusted-public-keys
#   import ARCH DIR  copy the kernel and its dev output from DIR into the store
#   selftest DIR     (pull requests) run the same signing, verifying and import
#                    code on a throwaway store path with a throwaway key
#
# The guest kernel is rebuilt from source with the dev/test certificate, which
# took about 86 of the 105 minutes of every evidence run. Its derivation
# depends only on deploy/nixos and the pinned nixpkgs, so the same derivation
# hash names the same build.
#
# Trust: the Nix daemon keeps require-sigs = true (scripts/install-pinned-nix.sh).
# export signs every path it writes with the secret key in
# QEMU_KERNEL_CACHE_SIGNING_KEY and refuses a key whose public half is not in
# the trusted-public-keys that /etc/nix/nix.conf gives both the client and the
# daemon; install-pinned-nix.sh trusts that public half. The secret belongs to
# the qemu-kernel-cache GitHub environment, whose deployment policy allows only
# main. That policy is a repository setting, which the workflow policy oracle
# cannot read. import never disables signature checks, so the daemon refuses an
# unsigned or foreign path. Only main runs save the cache; pull requests
# restore it by the exact key. The key name is part of the cache key, so a
# rotated key never restores entries signed by the old one.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
flake="${root}/deploy/nixos"
key_file=""
signing_key_name=piglor-qemu-kernel-1

usage() {
  printf 'usage: %s key ARCH | build ARCH | export ARCH DIR | verify ARCH DIR | import ARCH DIR | selftest DIR\n' "$0" >&2
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

# The concrete output paths, evaluated against the local store. Passing them
# instead of flake installables keeps `nix copy` from evaluating the flake
# against the file binary cache, and keeps export from building anything.
kernel_paths() {
  local kernel
  kernel="$(kernel_attribute "$1")"
  nix eval --raw --no-update-lock-file "${kernel}.outPath"
  printf '\n'
  nix eval --raw --no-update-lock-file "${kernel}.dev.outPath"
  printf '\n'
}

read_kernel_paths() {
  mapfile -t paths < <(kernel_paths "$1")
  local path
  if ((${#paths[@]} != 2)); then
    printf 'expected two kernel output paths, got %d\n' "${#paths[@]}" >&2
    exit 1
  fi
  for path in "${paths[@]}"; do
    if ! [[ ${path} =~ ^/nix/store/[0-9a-z]{32}-[^/]+$ ]]; then
      printf 'unexpected kernel output path: %s\n' "${path}" >&2
      exit 1
    fi
  done
}

key() {
  local drv hash
  drv="$(nix eval --raw --no-update-lock-file "$(kernel_attribute "$1").drvPath")"
  hash="$(basename -- "${drv}")"
  hash="${hash%%-*}"
  if ! [[ ${hash} =~ ^[0-9a-z]{32}$ ]]; then
    printf 'unexpected kernel derivation path: %s\n' "${drv}" >&2
    exit 1
  fi
  printf 'key=qemu-kernel-%s-%s-%s\n' "${signing_key_name}" "$1" "${hash}"
}

build() {
  local kernel
  kernel="$(kernel_attribute "$1")"
  nix build --no-update-lock-file --no-link --print-build-logs "${kernel}" "${kernel}.dev"
}

remove_key_file() {
  if [[ -n ${key_file} ]]; then
    rm -f -- "${key_file}"
  fi
}

trusted_public_keys() {
  nix config show trusted-public-keys
}

require_trusted() {
  if [[ " $(trusted_public_keys) " != *" $1 "* ]]; then
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
  # The Actions cache compresses the directory, so the NARs stay uncompressed.
  nix copy --to "file://${dir}?compression=none&secret-key=${key_file}" "$@"
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

import_cache() {
  read_kernel_paths "$1"
  nix copy --from "file://$2" "${paths[@]}"
}

selftest() {
  local dir=$1 secret public sample path entry found=false refused
  for entry in $(trusted_public_keys); do
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
  if (require_trusted "${public}") 2>/dev/null; then
    printf 'the throwaway key %s is unexpectedly trusted\n' "${public}" >&2
    exit 1
  fi
  sample="$(mktemp)"
  printf 'qemu-kernel-cache self-test %s\n' "$(date +%s%N)" >"${sample}"
  path="$(nix store add-file --name qemu-kernel-cache-selftest "${sample}")"
  rm -f -- "${sample}"
  sign_into "${secret}" "${dir}" "${path}"
  NIX_CONFIG="trusted-public-keys = ${public}" verify_paths "${dir}" "${path}"
  if verify_paths "${dir}" "${path}" 2>/dev/null; then
    printf 'a path signed by an untrusted key passed verification\n' >&2
    exit 1
  fi
  nix store delete "${path}"
  if refused="$(nix copy --from "file://${dir}" "${path}" 2>&1)"; then
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
key | build)
  (($# == 2)) || usage
  require_architecture "$2"
  "$1" "$2"
  ;;
export | verify | import)
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
