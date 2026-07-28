#!/usr/bin/env bash
# Syntactically enforce immutable-looking Action and Docker references.
# Usage: check-pinned-dependencies.sh [repository-root]
set -euo pipefail

root="$(cd "${1:-.}" && pwd)"
failed=0
uses_line_re="^[[:space:]]*(-[[:space:]]*)?(uses|\"uses\"|'uses')[[:space:]]*:[[:space:]]*(.*)$"

config_files=()
if [[ -d "$root/.github/workflows" ]]; then
  mapfile -d '' -t workflow_files < <(
    find "$root/.github/workflows" -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 | sort -z
  )
  config_files+=("${workflow_files[@]}")
fi
if [[ -d "$root/.github/actions" ]]; then
  mapfile -d '' -t action_files < <(
    find "$root/.github/actions" -type f \( -name 'action.yml' -o -name 'action.yaml' \) -print0 | sort -z
  )
  config_files+=("${action_files[@]}")
fi

for config_file in "${config_files[@]}"; do
  line_number=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))
    if [[ ! "$line" =~ $uses_line_re ]]; then
      if [[ "$line" =~ (^|[\{,])[[:space:]]*(uses|\"uses\"|\'uses\')[[:space:]]*: ]] || \
        [[ "$line" =~ ^[[:space:]]*\?[[:space:]]*(uses|\"uses\"|\'uses\')[[:space:]]*$ ]]; then
        printf 'ERROR: uses must use a normal single-line YAML key: %s:%d\n' \
          "${config_file#"$root"/}" "$line_number" >&2
        failed=1
      fi
      continue
    fi

    value=${BASH_REMATCH[3]}
    if [[ "$value" =~ ^\|[-+]?([[:space:]]*#.*)?$ || "$value" =~ ^\>[-+]?([[:space:]]*#.*)?$ || -z "$value" ]]; then
      printf 'ERROR: uses must be a single-line reference: %s:%d\n' \
        "${config_file#"$root"/}" "$line_number" >&2
      failed=1
      continue
    fi

    if [[ "$value" =~ ^\"([^\"]+)\"[[:space:]]*(#.*)?$ ]]; then
      reference=${BASH_REMATCH[1]}
    elif [[ "$value" =~ ^\'([^\']+)\'[[:space:]]*(#.*)?$ ]]; then
      reference=${BASH_REMATCH[1]}
    elif [[ "$value" =~ ^([^[:space:]#]+)[[:space:]]*(#.*)?$ ]]; then
      reference=${BASH_REMATCH[1]}
    else
      printf 'ERROR: uses must contain exactly one single-line reference: %s:%d\n' \
        "${config_file#"$root"/}" "$line_number" >&2
      failed=1
      continue
    fi

    if [[ "$reference" == ./* ]]; then
      continue
    fi
    if [[ "$reference" == docker://* ]]; then
      if [[ ! "$reference" =~ ^docker://[^@[:space:]]+@sha256:[0-9a-f]{64}$ ]]; then
        printf 'ERROR: Docker Action is not pinned to a sha256 digest: %s (%s:%d)\n' \
          "$reference" "${config_file#"$root"/}" "$line_number" >&2
        failed=1
      fi
      continue
    fi
    if [[ ! "$reference" =~ ^[^/@[:space:]]+/[^@[:space:]]+@[0-9a-f]{40}$ ]]; then
      printf 'ERROR: external Action reference is not pinned to a 40-hex revision: %s (%s:%d)\n' \
        "$reference" "${config_file#"$root"/}" "$line_number" >&2
      failed=1
    fi
  done < "$config_file"
done

mapfile -d '' -t dockerfiles < <(
  find "$root" -name 'Dockerfile*' -type f -not -path "$root/target/*" -print0 | sort -z
)
for dockerfile in "${dockerfiles[@]}"; do
  mapfile -t bases < <(grep -E '^[[:space:]]*FROM[[:space:]]+' "$dockerfile" || true)
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

printf 'Pinned dependency syntax policy OK.\n'
