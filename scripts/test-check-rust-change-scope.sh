#!/usr/bin/env bash
# Contract tests for the documentation-only pull-request scope classifier.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$root/scripts/check-rust-change-scope.sh"
fixture="$(mktemp -d)"
trap 'rm -rf -- "$fixture"' EXIT

git init --bare "$fixture/origin.git" >/dev/null
git init "$fixture/work" >/dev/null
cd "$fixture/work"
git config user.email ci@example.invalid
git config user.name ci-scope-test
printf 'base\n' > README.md
printf 'rust\n' > old.rs
git add README.md old.rs
git commit -m base >/dev/null
git branch -M main
git remote add origin "$fixture/origin.git"
git push --set-upstream origin main >/dev/null
printf '{"pull_request":{"base":{"ref":"main"}}}\n' > event.json

run_scope() {
  local output="$fixture/scope.out"
  : > "$output"
  GITHUB_EVENT_NAME="$1" \
    GITHUB_EVENT_PATH="$PWD/event.json" \
    GITHUB_OUTPUT="$output" \
    bash "$script" >/dev/null
  cat "$output"
}

git checkout -b docs >/dev/null
printf 'docs\n' > NOTES.md
git add NOTES.md
git commit -m docs >/dev/null
[[ "$(run_scope pull_request)" == 'rust=false' ]] || {
  printf 'ERROR: documentation-only pull request was not skipped\n' >&2
  exit 1
}

git checkout -B wit main >/dev/null
printf 'plugin\n' > plugin.wit
git add plugin.wit
git commit -m wit >/dev/null
[[ "$(run_scope pull_request)" == 'rust=true' ]] || {
  printf 'ERROR: non-Rust build input was incorrectly skipped\n' >&2
  exit 1
}

git checkout -B deletion main >/dev/null
rm old.rs
git add -u
git commit -m deletion >/dev/null
[[ "$(run_scope pull_request)" == 'rust=true' ]] || {
  printf 'ERROR: deleted Rust input was incorrectly skipped\n' >&2
  exit 1
}

[[ "$(run_scope push)" == 'rust=true' ]] || {
  printf 'ERROR: non-pull-request run was not full-scope\n' >&2
  exit 1
}

printf 'Rust change scope classifier tests passed.\n'
