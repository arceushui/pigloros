#!/usr/bin/env bash
# Emit rust=true when a pull request can affect Rust builds, policies, or reports.
# Non-pull-request runs are full-repository checks and always emit rust=true.
set -euo pipefail

rust=false
if [[ "${GITHUB_EVENT_NAME:?}" != "pull_request" ]]; then
  rust=true
else
  base_ref="$(jq -er '.pull_request.base.ref' "${GITHUB_EVENT_PATH:?}")"
  git fetch --no-tags origin "$base_ref"
  while IFS= read -r path; do
    printf 'changed: %s\n' "$path"
    case "$path" in
      *.rs|Cargo.toml|*/Cargo.toml|Cargo.lock|rust-toolchain.toml|\
      rustfmt.toml|clippy.toml|deny.toml|.cargo/*|fuzz/*|scripts/*|\
      .githooks/*|Dockerfile|Dockerfile.*|docker/*|\
      requirements-pinned-dependencies.txt|.github/workflows/*|\
      Trunk.yaml|trunk.yaml|.trunk/*|.pre-commit-config.yaml|\
      .yamllint*|.markdownlint*|apps/piglor-world-client/*)
        rust=true
        ;;
    esac
  done < <(
    git diff --name-only --diff-filter=ACMR "origin/${base_ref}...HEAD"
  )
fi

printf 'rust=%s\n' "$rust" >> "${GITHUB_OUTPUT:?}"
printf 'Rust-affecting scope: %s\n' "$rust"
