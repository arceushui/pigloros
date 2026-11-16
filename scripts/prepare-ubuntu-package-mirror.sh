#!/usr/bin/env bash
set -euo pipefail

# Point the hosted runner's Ubuntu archive and security sources at one ordered
# apt mirror list: mirrors.edge.kernel.org first, then the runner's own mirrors
# (the Azure archive on GitHub-hosted runners), then the Ubuntu archive and
# security hosts. apt's mirror method falls through to the next entry when one
# cannot be reached, and every download is retried with bounded timeouts. The
# optional argument is the apt configuration directory (default /etc/apt).
apt_dir="${1:-/etc/apt}"
sources="${apt_dir}/sources.list.d/ubuntu.sources"
mirror_list="${apt_dir}/pigloros-mirrors.txt"

mirrors=(https://mirrors.edge.kernel.org/ubuntu)
for runner_list in "${apt_dir}/apt-mirrors.txt" "${apt_dir}/apt-security-mirrors.txt"; do
  [[ -r "${runner_list}" ]] || continue
  while read -r uri _ || [[ -n "${uri}" ]]; do
    if [[ "${uri}" =~ ^https?:// ]]; then
      mirrors+=("${uri%/}")
    fi
  done < "${runner_list}"
done
mirrors+=(http://archive.ubuntu.com/ubuntu http://security.ubuntu.com/ubuntu)

declare -A listed=()
entries=''
priority=0
for uri in "${mirrors[@]}"; do
  [[ -z "${listed[${uri}]:-}" ]] || continue
  listed[${uri}]=1
  priority=$((priority + 1))
  entries+="${uri}"$'\t'"priority:${priority}"$'\n'
done

printf '%s' "${entries}" | sudo tee "${mirror_list}" > /dev/null
printf '%s\n' \
  'Acquire::Retries "5";' \
  'Acquire::http::Timeout "30";' \
  'Acquire::https::Timeout "30";' |
  sudo tee "${apt_dir}/apt.conf.d/80pigloros-mirror-retries" > /dev/null
sudo sed -i -E \
  -e "s|^URIs: mirror\+file:/etc/apt/apt-(security-)?mirrors\.txt$|URIs: mirror+file:${mirror_list}|" \
  "${sources}"
if ! grep -qxF "URIs: mirror+file:${mirror_list}" "${sources}"; then
  echo "::error::${sources} has no mirror+file Ubuntu archive source to redirect" >&2
  exit 1
fi
