#!/usr/bin/env bash
# Emit rust=false only when every pull-request change is documentation-only.
# Non-pull-request runs are full-repository checks and always emit rust=true.
set -euo pipefail

rust=true
if [[ "${GITHUB_EVENT_NAME:?}" != "pull_request" ]]; then
  :
else
  base_ref="$(jq -er '.pull_request.base.ref' "${GITHUB_EVENT_PATH:?}")"
  git fetch --no-tags origin "$base_ref"
  rust=false
  while IFS= read -r path; do
    printf 'changed: %s\n' "$path"
    case "$path" in
      *.md|*.mdx|*.adoc|*.rst|.agents/*|.cursor/*|docs/*)
        ;;
      *)
        rust=true
        break
        ;;
    esac
  done < <(
    git diff --no-renames --name-only --diff-filter=ACDMRT "origin/${base_ref}...HEAD"
  )
fi

printf 'rust=%s\n' "$rust" >> "${GITHUB_OUTPUT:?}"
printf 'Rust-affecting scope: %s\n' "$rust"
