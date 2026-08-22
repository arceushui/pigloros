#!/usr/bin/env bash
set -euo pipefail

base_ref="${1:-origin/main}"
base_commit="$(git merge-base HEAD "${base_ref}")"

if git diff --unified=0 "${base_commit}" -- \
  ':(glob)**/*.rs' 'Cargo.toml' ':(glob)**/Cargo.toml' \
  | grep -E -n '^\+[^+]*#[[:space:]]*!?[[:space:]]*\[[[:space:]]*allow([[:space:]]*\(|[[:space:]]*=)';
then
  echo "new lint suppression attributes are forbidden; fix the warning instead" >&2
  exit 1
fi
