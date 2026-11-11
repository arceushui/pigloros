#!/usr/bin/env bash
set -euo pipefail

sudo sed -i \
  -e 's|mirror+file:/etc/apt/apt-mirrors.txt|https://mirrors.edge.kernel.org/ubuntu|g' \
  -e 's|mirror+file:/etc/apt/apt-security-mirrors.txt|https://mirrors.edge.kernel.org/ubuntu|g' \
  /etc/apt/sources.list.d/ubuntu.sources
