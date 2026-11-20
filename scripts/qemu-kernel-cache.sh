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
# A failure inside $(...) stops the script too, as it does outside.
shopt -s inherit_errexit

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
  if ! jq -e '[.[]] | length == 1 and all(.ca == null)' >/dev/null <<<"${info}"; then
    printf 'the self-test sample %s is content-addressed\n' "${path}" >&2
    exit 1
  fi
  printf '%s\n' "${path}"
}

selftest() {
  local dir=$1 secret public path entry found=false refused
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
