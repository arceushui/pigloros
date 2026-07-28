#!/usr/bin/env bash
# Enforce pinned Action references (PyYAML) and Docker base-image digests.
# Usage: check-pinned-dependencies.sh [repository-root]
set -euo pipefail

root="$(cd "${1:-.}" && pwd)"
checker_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
failed=0

if ! python3 -c 'import yaml' 2>/dev/null; then
  printf 'ERROR: PyYAML is required; install requirements-pinned-dependencies.txt with hashes.\n' >&2
  failed=1
elif ! python3 "$checker_dir/check-pinned-yaml-references.py" "$root"; then
  failed=1
fi

mapfile -d '' -t dockerfiles < <(
  find "$root" -iname 'Dockerfile*' -type f -not -path "$root/target/*" -print0 | sort -z
)
for dockerfile in "${dockerfiles[@]}"; do
  mapfile -t bases < <(grep -Ei '^[[:space:]]*FROM[[:space:]]+' "$dockerfile" || true)
  for base in "${bases[@]}"; do
    if [[ ! "$base" =~ @sha256:[0-9a-f]{64}([[:space:]]|$) ]]; then
      printf 'ERROR: Docker base image is not pinned to a sha256 digest: %s (%s)\n' \
        "$base" "${dockerfile#"$root"/}" >&2
      failed=1
    fi
  done
done

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

printf 'Pinned dependency policy OK.\n'
