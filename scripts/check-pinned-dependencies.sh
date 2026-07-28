#!/usr/bin/env bash
# Syntactically enforce immutable-looking Action and Docker references.
# Usage: check-pinned-dependencies.sh [repository-root]
set -euo pipefail

root="$(cd "${1:-.}" && pwd)"
failed=0
uses_line_re="^[[:space:]]*(-[[:space:]]*)?(uses|\"uses\"|'uses')[[:space:]]*:[[:space:]]*(.*)$"
encoded_scalar_escape_re='\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})'
declare -A inspection_state=()

report_error() {
  printf 'ERROR: %s\n' "$1" >&2
  failed=1
}

inspect_config() {
  local config_file=$1
  local canonical
  local line
  local line_number
  local reference
  local value

  if [[ ! -f "$config_file" ]]; then
    report_error "referenced YAML file does not exist: ${config_file#"$root"/}"
    return
  fi
  canonical=$(realpath "$config_file")
  case "$canonical" in
    "$root"/*) ;;
    *)
      report_error "referenced YAML file escapes repository root: $config_file"
      return
      ;;
  esac

  case "${inspection_state[$canonical]:-unseen}" in
    visiting)
      report_error "local uses cycle detected at ${canonical#"$root"/}"
      return
      ;;
    done) return ;;
  esac
  inspection_state[$canonical]=visiting

  line_number=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))
    if [[ "$line" =~ $encoded_scalar_escape_re ]]; then
      report_error "hexadecimal and Unicode escapes are forbidden in checked YAML: ${canonical#"$root"/}:$line_number"
      continue
    fi
    if [[ ! "$line" =~ $uses_line_re ]]; then
      if [[ "$line" =~ (^|[\{\[,])[[:space:]]*(uses|\"uses\"|\'uses\')[[:space:]]*: ]] || \
        [[ "$line" =~ [\{\[].*(uses|\"uses\"|\'uses\')[[:space:]]*: ]] || \
        [[ "$line" =~ ^[[:space:]]*(-[[:space:]]*)?\?[[:space:]]*(uses|\"uses\"|\'uses\')[[:space:]]*(:.*)?$ ]]; then
        report_error "compact, flow, and explicit-key uses syntax is forbidden: ${canonical#"$root"/}:$line_number"
      fi
      continue
    fi

    value=${BASH_REMATCH[3]}
    if [[ "$value" =~ ^\|[-+]?([[:space:]]*#.*)?$ || "$value" =~ ^\>[-+]?([[:space:]]*#.*)?$ || -z "$value" ]]; then
      report_error "uses must be a single-line reference: ${canonical#"$root"/}:$line_number"
      continue
    fi

    if [[ "$value" =~ ^\"([^\"]+)\"[[:space:]]*(#.*)?$ ]]; then
      reference=${BASH_REMATCH[1]}
    elif [[ "$value" =~ ^\'([^\']+)\'[[:space:]]*(#.*)?$ ]]; then
      reference=${BASH_REMATCH[1]}
    elif [[ "$value" =~ ^([^[:space:]#]+)[[:space:]]*(#.*)?$ ]]; then
      reference=${BASH_REMATCH[1]}
    else
      report_error "uses must contain exactly one single-line reference: ${canonical#"$root"/}:$line_number"
      continue
    fi

    if [[ "$reference" == ./* ]]; then
      inspect_local_reference "$reference" "$canonical" "$line_number"
    elif [[ "$reference" == docker://* ]]; then
      if [[ ! "$reference" =~ ^docker://[^@[:space:]]+@sha256:[0-9a-f]{64}$ ]]; then
        report_error "Docker Action is not pinned to a sha256 digest: $reference (${canonical#"$root"/}:$line_number)"
      fi
    elif [[ ! "$reference" =~ ^[^/@[:space:]]+/[^@[:space:]]+@[0-9a-f]{40}$ ]]; then
      report_error "external Action reference is not pinned to a 40-hex revision: $reference (${canonical#"$root"/}:$line_number)"
    fi
  done < "$canonical"

  inspection_state[$canonical]=done
}

inspect_local_reference() {
  local reference=$1
  local source_file=$2
  local line_number=$3
  local target
  local canonical_target
  local action_yml
  local action_yaml

  target=$(realpath -m "$root/${reference#./}")
  case "$target" in
    "$root"/*) ;;
    *)
      report_error "local uses reference escapes repository root: $reference (${source_file#"$root"/}:$line_number)"
      return
      ;;
  esac

  if [[ "$target" == *.yml || "$target" == *.yaml ]]; then
    case "$target" in
      "$root/.github/workflows/"*) ;;
      *)
        report_error "local reusable workflow must be under .github/workflows: $reference (${source_file#"$root"/}:$line_number)"
        return
        ;;
    esac
    inspect_config "$target"
    return
  fi

  if [[ ! -d "$target" ]]; then
    report_error "local Action directory does not exist: $reference (${source_file#"$root"/}:$line_number)"
    return
  fi
  canonical_target=$(realpath "$target")
  case "$canonical_target" in
    "$root"/*) ;;
    *)
      report_error "local Action directory escapes repository root: $reference (${source_file#"$root"/}:$line_number)"
      return
      ;;
  esac

  action_yml="$canonical_target/action.yml"
  action_yaml="$canonical_target/action.yaml"
  if [[ -f "$action_yml" && -f "$action_yaml" ]]; then
    report_error "local Action has ambiguous metadata (both action.yml and action.yaml): $reference"
  elif [[ -f "$action_yml" ]]; then
    inspect_config "$action_yml"
  elif [[ -f "$action_yaml" ]]; then
    inspect_config "$action_yaml"
  else
    report_error "local Action is missing action.yml or action.yaml: $reference (${source_file#"$root"/}:$line_number)"
  fi
}

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
  inspect_config "$config_file"
done

mapfile -d '' -t dockerfiles < <(
  find "$root" -iname 'Dockerfile*' -type f -not -path "$root/target/*" -print0 | sort -z
)
for dockerfile in "${dockerfiles[@]}"; do
  mapfile -t bases < <(grep -Ei '^[[:space:]]*FROM[[:space:]]+' "$dockerfile" || true)
  for base in "${bases[@]}"; do
    if [[ ! "$base" =~ @sha256:[0-9a-f]{64}([[:space:]]|$) ]]; then
      report_error "Docker base image is not pinned to a sha256 digest: $base (${dockerfile#"$root"/})"
    fi
  done
done

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

printf 'Pinned dependency syntax policy OK.\n'
