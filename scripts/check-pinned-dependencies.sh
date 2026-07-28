#!/usr/bin/env bash
# Enforce immutable GitHub Action and Docker base-image references.
# Usage: check-pinned-dependencies.sh [repository-root]
set -euo pipefail

root="$(cd "${1:-.}" && pwd)"
failed=0

mapfile -d '' -t workflows < <(find "$root/.github/workflows" -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 | sort -z)
for workflow in "${workflows[@]}"; do
  mapfile -t references < <(grep -E '^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]+[^[:space:]]+/[^[:space:]]+@' "$workflow" || true)
  for reference in "${references[@]}"; do
    if [[ ! "$reference" =~ @[0-9a-f]{40}([[:space:]]|#|$) ]]; then
      printf 'ERROR: GitHub Action is not pinned to a full commit SHA: %s (%s)\n' \
        "$reference" "${workflow#"$root"/}" >&2
      failed=1
    fi
  done
done

mapfile -d '' -t dockerfiles < <(find "$root" -name 'Dockerfile*' -type f -not -path "$root/target/*" -print0 | sort -z)
for dockerfile in "${dockerfiles[@]}"; do
  mapfile -t bases < <(grep -E '^[[:space:]]*FROM[[:space:]]+' "$dockerfile" || true)
  for base in "${bases[@]}"; do
    if [[ ! "$base" =~ @sha256:[0-9a-f]{64}([[:space:]]|$) ]]; then
      printf 'ERROR: Docker base image is not pinned to a digest: %s (%s)\n' \
        "$base" "${dockerfile#"$root"/}" >&2
      failed=1
    fi
  done
done

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

printf 'Pinned dependency policy OK.\n'
