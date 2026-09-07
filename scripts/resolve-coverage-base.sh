#!/usr/bin/env bash
# Resolve the coverage comparison base exactly as covgate does.
set -euo pipefail

base_ref=${1:?usage: resolve-coverage-base.sh BASE_REF}
if [[ -z "${base_ref}" || "${base_ref}" =~ ^0+$ ]]; then
  base_ref="$(git rev-parse HEAD^1)"
fi

git merge-base "${base_ref}" HEAD
