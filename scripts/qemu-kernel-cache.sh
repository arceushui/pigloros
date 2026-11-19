#!/usr/bin/env bash
# Reuse the #444 evidence guest's kernel build (ADR-087 gate 5) across runs.
#
#   key ARCH         print the cache key: the kernel derivation's store hash
#   export ARCH DIR  (main only) build the kernel and its dev output, then
#                    write them, signed, to a file binary cache in DIR
#   import ARCH DIR  copy the kernel and its dev output from DIR into the store
#
# The guest kernel is rebuilt from source with the dev/test certificate, which
# took about 86 of the 105 minutes of every evidence run. Its derivation
# depends only on deploy/nixos and the pinned nixpkgs, so the same derivation
# hash names the same build.
#
# Trust: the Nix daemon keeps require-sigs = true (scripts/install-pinned-nix.sh).
# export signs every path it writes with the secret key in
# QEMU_KERNEL_CACHE_SIGNING_KEY, a secret of the qemu-kernel-cache environment
# that only main may deploy to; install-pinned-nix.sh trusts its public half.
# import never passes --no-check-sigs, so the daemon refuses an unsigned or
# foreign path and the evidence job fails closed. Only main runs save the cache;
# pull requests restore it by the exact key.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
flake="${root}/deploy/nixos"

usage() {
  printf 'usage: %s key ARCH | export ARCH DIR | import ARCH DIR\n' "$0" >&2
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

export_cache() {
  local kernel key_file status=0
  kernel="$(kernel_attribute "$1")"
  if [[ -z ${QEMU_KERNEL_CACHE_SIGNING_KEY:-} ]]; then
    printf 'QEMU_KERNEL_CACHE_SIGNING_KEY is not set\n' >&2
    exit 1
  fi
  nix build --no-update-lock-file --no-link --print-build-logs "${kernel}" "${kernel}.dev"
  key_file="$(umask 077 && mktemp)"
  printf '%s' "${QEMU_KERNEL_CACHE_SIGNING_KEY}" >"${key_file}"
  nix copy --no-update-lock-file \
    --to "file://$2?compression=zstd&secret-key=${key_file}" \
    "${kernel}" "${kernel}.dev" || status=$?
  rm -f -- "${key_file}"
  return "${status}"
}

import_cache() {
  local kernel
  kernel="$(kernel_attribute "$1")"
  nix copy --no-update-lock-file --from "file://$2" "${kernel}" "${kernel}.dev"
}

case "${1:-}" in
key)
  (($# == 2)) || usage
  require_architecture "$2"
  key "$2"
  ;;
export)
  (($# == 3)) || usage
  require_architecture "$2"
  export_cache "$2" "$3"
  ;;
import)
  (($# == 3)) || usage
  require_architecture "$2"
  import_cache "$2" "$3"
  ;;
*) usage ;;
esac
