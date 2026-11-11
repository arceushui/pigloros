#!/usr/bin/env bash
set -euo pipefail

sudo sed -i \
  -e 's|^URIs: mirror+file:/etc/apt/apt-mirrors\.txt$|URIs: https://mirrors.edge.kernel.org/ubuntu|' \
  -e 's|^URIs: mirror+file:/etc/apt/apt-security-mirrors\.txt$|URIs: https://mirrors.edge.kernel.org/ubuntu|' \
  /etc/apt/sources.list.d/ubuntu.sources
