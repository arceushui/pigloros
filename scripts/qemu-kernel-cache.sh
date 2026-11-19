#!/usr/bin/env bash
# Reuse the #444 evidence guest's kernel build (ADR-087 gate 5) across runs.
#
#   key ARCH         print the cache key: the kernel derivation's store hash
#   build ARCH       (main only) build the kernel and its dev output
#   export ARCH DIR  (main only) sign the built kernel and its dev output into
#                    a file binary cache in DIR, then verify DIR
#   verify ARCH DIR  require DIR to hold both paths, intact and signed by a
#                    key the Nix daemon trusts
#   import ARCH DIR  copy the kernel and its dev output from DIR into the store
#
# The guest kernel is rebuilt from source with the dev/test certificate, which
# took about 86 of the 105 minutes of every evidence run. Its derivation
# depends only on deploy/nixos and the pinned nixpkgs, so the same derivation
# hash names the same build.
#
# Trust: the Nix daemon keeps require-sigs = true (scripts/install-pinned-nix.sh).
# export signs every path it writes with the secret key in
# QEMU_KERNEL_CACHE_SIGNING_KEY and refuses a key whose public half the daemon
# does not trust; install-pinned-nix.sh trusts that public half. The secret
# belongs to the qemu-kernel-cache GitHub environment, whose deployment policy
# allows only main. That policy is a repository setting, which the workflow
# policy oracle cannot read. import never disables signature checks, so the
# daemon refuses an unsigned or foreign path. Only main runs save the cache;
# pull requests restore it by the exact key.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
flake="${root}/deploy/nixos"
key_file=""

usage() {
  printf 'usage: %s key ARCH | build ARCH | export ARCH DIR | verify ARCH DIR | import ARCH DIR\n' "$0" >&2
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
  printf 'key=qemu-kernel-%s-%s\n' "$1" "${hash}"
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

verify_cache() {
  read_kernel_paths "$1"
  nix store verify --store "file://$2" --sigs-needed 1 "${paths[@]}"
}

export_cache() {
  local public trusted
  if [[ -z ${QEMU_KERNEL_CACHE_SIGNING_KEY:-} ]]; then
    printf 'QEMU_KERNEL_CACHE_SIGNING_KEY is not set\n' >&2
    exit 1
  fi
  public="$(printf '%s' "${QEMU_KERNEL_CACHE_SIGNING_KEY}" | nix key convert-secret-to-public)"
  trusted="$(nix config show trusted-public-keys)"
  if [[ " ${trusted} " != *" ${public} "* ]]; then
    printf 'the signing key public half %s is not in trusted-public-keys\n' "${public}" >&2
    exit 1
  fi
  read_kernel_paths "$1"
  trap remove_key_file EXIT
  trap 'exit 143' TERM
  trap 'exit 130' INT
  key_file="$(umask 077 && mktemp)"
  printf '%s' "${QEMU_KERNEL_CACHE_SIGNING_KEY}" >"${key_file}"
  # The Actions cache compresses the directory, so the NARs stay uncompressed.
  nix copy --to "file://$2?compression=none&secret-key=${key_file}" "${paths[@]}"
  remove_key_file
  verify_cache "$1" "$2"
}

import_cache() {
  read_kernel_paths "$1"
  nix copy --from "file://$2" "${paths[@]}"
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
*) usage ;;
esac
