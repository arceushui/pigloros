#!/usr/bin/env bash
set -euo pipefail

# Usage: prepare-ubuntu-package-mirror.sh <apt-get install arguments...>
#
# Installs Ubuntu packages on a hosted runner through one ordered apt mirror
# list: the runner's own in-region mirrors first (the image's apt-mirrors.txt,
# for example azure.archive.ubuntu.com), then the Ubuntu archive and security
# hosts. The network phases (index refresh and package download) are bounded;
# if either fails or exceeds the bound, both run once more, with the list
# rewritten without the runner's first mirror when the runner has a list. Installation then uses only the
# downloaded packages. Every caller goes through this script; none runs
# apt-get itself.
#
# No third-party mirror is listed. mirrors.edge.kernel.org used to come first,
# but hosted runners have no IPv6 route to it ("Network is unreachable") and on
# 2026-11-16 its IPv4 address timed out as well; the runner's own mirror is in
# the same cloud region and already falls back to the Ubuntu hosts.
#
# Why the bounds: in job 133057405149 the first mirror was down. apt fell over
# for InRelease after about 16 s, then printed Ign for every index file and
# produced no further output for 584 s, until the 10-minute job timeout.
# Retries are off so the mirror method fails over at once instead of retrying a
# dead host, the 10 s connect/read timeout caps each attempt, and the 120 s
# bound per phase stops any stall the log could not explain: two failed
# attempts of both phases (4 x 130 s with the kill grace) still end inside a
# 10-minute job. The refresh fails on any index error, so nothing continues
# with stale indices.
#
# Every apt-get call reads only the rewritten ubuntu.sources, so a flaky
# third-party source on the runner (packages.microsoft.com and others) can
# neither fail the strict refresh nor supply the installed packages.
APT_NETWORK_TIMEOUT_SECONDS=120
APT_KILL_AFTER_SECONDS=10
UBUNTU_FALLBACKS=(http://archive.ubuntu.com/ubuntu http://security.ubuntu.com/ubuntu)
apt_dir="${PIGLOROS_APT_DIR:-/etc/apt}"
sources="${apt_dir}/sources.list.d/ubuntu.sources"
mirror_list="${apt_dir}/pigloros-mirrors.txt"
ubuntu_only_parts="${apt_dir}/pigloros-sources.d"
apt_scope=(-o Dir::Etc::sourcelist=/dev/null -o "Dir::Etc::sourceparts=${ubuntu_only_parts}")

if (($# == 0)); then
  echo "::error::usage: $0 <apt-get install arguments...>"
  exit 2
fi

mirrors=()
for runner_list in "${apt_dir}/apt-mirrors.txt" "${apt_dir}/apt-security-mirrors.txt"; do
  [[ -r "${runner_list}" ]] || continue
  while read -r uri _ || [[ -n "${uri}" ]]; do
    if [[ "${uri}" =~ ^https?:// ]]; then
      mirrors+=("${uri%/}")
    fi
  done < "${runner_list}"
done
mirrors+=("${UBUNTU_FALLBACKS[@]}")
# The retry leaves out the runner's first mirror; without a runner list it
# keeps every entry, because the Ubuntu hosts are then the only mirrors.
retry_skip=()
retry_note=''
if [[ "${mirrors[0]}" != "${UBUNTU_FALLBACKS[0]}" ]]; then
  retry_skip=("${mirrors[0]}")
  retry_note=" without ${mirrors[0]}"
fi

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

# Runs one bounded network phase of apt-get against the Ubuntu sources only.
# On failure sets FAILURE to the phase and how it ended.
bounded_apt() {
  local phase="$1" status=0
  shift
  sudo timeout --kill-after="${APT_KILL_AFTER_SECONDS}" "${APT_NETWORK_TIMEOUT_SECONDS}" \
    apt-get "${apt_scope[@]}" "$@" || status=$?
  ((status != 0)) || return 0
  case "${status}" in
    124 | 137) FAILURE="${phase} timed out after ${APT_NETWORK_TIMEOUT_SECONDS}s (status ${status})" ;;
    *) FAILURE="${phase} failed with status ${status}" ;;
  esac
  return 1
}

# Refreshes every Ubuntu index, then downloads the requested packages.
fetch_packages() {
  bounded_apt "index refresh" update --error-on=any &&
    bounded_apt "package download" install --yes --download-only "$@"
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
sudo mkdir -p "${ubuntu_only_parts}"
sudo cp "${sources}" "${ubuntu_only_parts}/ubuntu.sources"

FAILURE=''
if ! fetch_packages "$@"; then
  echo "::warning::apt ${FAILURE} on the Ubuntu sources; retrying once with the mirror list${retry_note}"
  write_mirror_list "${retry_skip[@]}"
  if ! fetch_packages "$@"; then
    echo "::error::apt ${FAILURE} on the Ubuntu sources again with the mirror list${retry_note}; failing closed"
    exit 1
  fi
fi
if ! sudo apt-get "${apt_scope[@]}" install --yes --no-download "$@"; then
  echo "::error::apt could not install the downloaded packages; failing closed"
  exit 1
fi
