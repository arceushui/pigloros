#!/usr/bin/env bash
set -euo pipefail

# Usage: prepare-ubuntu-package-mirror.sh <apt-get install arguments...>
#
# Installs Ubuntu packages on a hosted runner through one ordered apt mirror
# list: mirrors.edge.kernel.org first, then the runner's own mirrors (the
# Azure or EC2 archive), then the Ubuntu archive and security hosts. The
# network phases (index refresh and package download) are bounded; if either
# fails or exceeds the bound, the list is rewritten without edge.kernel.org
# and both run once more. Installation then uses only the downloaded packages.
# Every caller goes through this script; none runs apt-get itself.
#
# Why the bounds: in job 133057405149 edge.kernel.org was down. apt fell over
# to the EC2 mirror for InRelease after about 16 s, then printed Ign on edge
# for every index file and produced no further output for 584 s, until the
# 10-minute job timeout. Retries are off so the mirror method fails over at
# once instead of retrying a dead host, the 10 s connect/read timeout caps
# each attempt, and the 180 s bound per phase stops any stall the log could
# not explain. The refresh fails on any index error, so nothing continues
# with stale indices.
APT_NETWORK_TIMEOUT_SECONDS=180
EDGE_MIRROR=https://mirrors.edge.kernel.org/ubuntu
apt_dir="${PIGLOROS_APT_DIR:-/etc/apt}"
sources="${apt_dir}/sources.list.d/ubuntu.sources"
mirror_list="${apt_dir}/pigloros-mirrors.txt"

if (($# == 0)); then
  echo "::error::usage: $0 <apt-get install arguments...>"
  exit 2
fi

mirrors=("${EDGE_MIRROR}")
for runner_list in "${apt_dir}/apt-mirrors.txt" "${apt_dir}/apt-security-mirrors.txt"; do
  [[ -r "${runner_list}" ]] || continue
  while read -r uri _ || [[ -n "${uri}" ]]; do
    if [[ "${uri}" =~ ^https?:// ]]; then
      mirrors+=("${uri%/}")
    fi
  done < "${runner_list}"
done
mirrors+=(http://archive.ubuntu.com/ubuntu http://security.ubuntu.com/ubuntu)

# Writes the mirror list, leaving out any URI given as an argument.
write_mirror_list() {
  local uri skip entries='' priority=0
  local -A listed=()
  for skip in "$@"; do
    listed[${skip}]=1
  done
  for uri in "${mirrors[@]}"; do
    [[ -z "${listed[${uri}]:-}" ]] || continue
    listed[${uri}]=1
    priority=$((priority + 1))
    entries+="${uri}"$'\t'"priority:${priority}"$'\n'
  done
  printf '%s' "${entries}" | sudo tee "${mirror_list}" > /dev/null
}

# Refreshes every index and downloads the requested packages, each bounded.
fetch_packages() {
  sudo timeout --kill-after=15 "${APT_NETWORK_TIMEOUT_SECONDS}" \
    apt-get update --error-on=any &&
    sudo timeout --kill-after=15 "${APT_NETWORK_TIMEOUT_SECONDS}" \
      apt-get install --yes --download-only "$@"
}

write_mirror_list
printf '%s\n' \
  'Acquire::Retries "0";' \
  'Acquire::http::Timeout "10";' \
  'Acquire::https::Timeout "10";' |
  sudo tee "${apt_dir}/apt.conf.d/80pigloros-mirror-retries" > /dev/null
sudo sed -i -E \
  -e "s|^URIs: mirror\+file:/etc/apt/apt-(security-)?mirrors\.txt$|URIs: mirror+file:${mirror_list}|" \
  "${sources}"
if ! grep -qxF "URIs: mirror+file:${mirror_list}" "${sources}"; then
  echo "::error::${sources} has no mirror+file Ubuntu archive source to redirect"
  exit 1
fi

if ! fetch_packages "$@"; then
  echo "::warning::apt could not refresh indices and download packages within ${APT_NETWORK_TIMEOUT_SECONDS}s per phase; retrying without ${EDGE_MIRROR}"
  write_mirror_list "${EDGE_MIRROR}"
  if ! fetch_packages "$@"; then
    echo "::error::apt could not refresh indices and download packages without ${EDGE_MIRROR} either; failing closed"
    exit 1
  fi
fi
sudo apt-get install --yes --no-download "$@"
