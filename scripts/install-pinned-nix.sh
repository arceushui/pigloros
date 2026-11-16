#!/usr/bin/env bash
# Install the hash-pinned Nix 2.34.9 release (the nixos-26.05 Nix) as a
# multi-user daemon on a GitHub-hosted Ubuntu runner. The only substituter is
# cache.nixos.org, with signatures required; builds stay sandboxed.
# Usage: install-pinned-nix.sh
set -euo pipefail

# The effective trust settings, each exactly as nix.conf below sets them.
declare -A expected_settings=(
  [substituters]=https://cache.nixos.org
  [trusted-public-keys]=cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
  [require-sigs]=true
  [sandbox]=true
)

# Print each effective setting of the Nix at $1; fail if any differs.
check_nix_settings() {
  local setting value status=0
  for setting in substituters trusted-public-keys require-sigs sandbox; do
    value="$("$1" config show "${setting}")"
    printf '%s = %s\n' "${setting}" "${value}"
    if [[ ${value} != "${expected_settings[${setting}]}" ]]; then
      printf 'effective %s is %q, expected %q\n' "${setting}" "${value}" \
        "${expected_settings[${setting}]}" >&2
      status=1
    fi
  done
  return "${status}"
}

# Sourced by scripts/test_qemu_closure_evidence_producer.py for the check above.
if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
  return 0
fi

version=2.34.9
case "$(uname -m)" in
x86_64)
  system=x86_64-linux
  sha256=e8912e087582b3799e0e5a6b06f9d63386c54821f77ad4de3b9b748736ad364e
  ;;
aarch64)
  system=aarch64-linux
  sha256=f0bb2518db6c9db3f925be3edb76f6e0da17cb72fba329493f510ca08e5111a7
  ;;
*)
  printf 'unsupported runner architecture: %s\n' "$(uname -m)" >&2
  exit 1
  ;;
esac

work="$(mktemp -d)"
trap 'rm -rf -- "${work}"' EXIT
tarball="${work}/nix-${version}-${system}.tar.xz"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --output "${tarball}" \
  "https://releases.nixos.org/nix/nix-${version}/nix-${version}-${system}.tar.xz"
printf '%s  %s\n' "${sha256}" "${tarball}" | sha256sum --check --strict
tar -xJf "${tarball}" -C "${work}"

cat >"${work}/nix.conf" <<'EOF'
experimental-features = nix-command flakes
substituters = https://cache.nixos.org
trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=
require-sigs = true
sandbox = true
accept-flake-config = false
max-jobs = auto
cores = 0
EOF

"${work}/nix-${version}-${system}/install" --daemon --yes --no-channel-add \
  --nix-extra-conf-file "${work}/nix.conf"

printf '%s\n' /nix/var/nix/profiles/default/bin >>"${GITHUB_PATH}"
/nix/var/nix/profiles/default/bin/nix --version
check_nix_settings /nix/var/nix/profiles/default/bin/nix
