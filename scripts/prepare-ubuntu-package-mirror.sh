#!/usr/bin/env bash
set -euo pipefail

# Prefer the kernel.org mirror, but keep apt's mirror+file failover so one
# unreachable mirror cannot fail every package install. InRelease signatures
# are still checked against the Ubuntu archive keyring, whichever mirror serves.
printf '%s\n' \
  https://mirrors.edge.kernel.org/ubuntu \
  http://azure.archive.ubuntu.com/ubuntu \
  http://archive.ubuntu.com/ubuntu \
  | sudo tee /etc/apt/pigloros-mirrors.txt >/dev/null
printf '%s\n' \
  https://mirrors.edge.kernel.org/ubuntu \
  http://security.ubuntu.com/ubuntu \
  | sudo tee /etc/apt/pigloros-security-mirrors.txt >/dev/null
sudo sed -i \
  -e 's|^URIs: mirror+file:/etc/apt/apt-mirrors\.txt$|URIs: mirror+file:/etc/apt/pigloros-mirrors.txt|' \
  -e 's|^URIs: mirror+file:/etc/apt/apt-security-mirrors\.txt$|URIs: mirror+file:/etc/apt/pigloros-security-mirrors.txt|' \
  /etc/apt/sources.list.d/ubuntu.sources
