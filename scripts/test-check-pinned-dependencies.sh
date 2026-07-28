#!/usr/bin/env bash
# Self-test the policy checker against realistic valid and bypass syntax.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="$root/scripts/check-pinned-dependencies.sh"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
digest=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

make_case() {
  case_root="$fixture/$1"
  mkdir -p "$case_root/.github/workflows" "$case_root/.github/actions/example"
  printf 'FROM example@sha256:%s\n' "$digest" > "$case_root/Dockerfile"
}

expect_pass() {
  if ! bash "$checker" "$1" >/dev/null; then
    printf 'ERROR: valid fixture was rejected: %s\n' "$1" >&2
    exit 1
  fi
}

expect_fail() {
  if bash "$checker" "$1" >/dev/null 2>&1; then
    printf 'ERROR: invalid fixture was accepted: %s\n' "$1" >&2
    exit 1
  fi
}

# The checker must enforce the repository that invokes this self-test too.
expect_pass "$root"

make_case valid
printf '%s\n' \
  'jobs:' \
  '  build:' \
  "    uses: owner/repository/.github/workflows/build.yml@$sha # v1" \
  '    steps:' \
  "      - uses: owner/action@$sha # v1" \
  "      - uses: docker://example/image@sha256:$digest" \
  > "$case_root/.github/workflows/valid.yml"
printf '%s\n' \
  'runs:' \
  '  using: composite' \
  '  steps:' \
  '    - uses: ./local-action' \
  "    - uses: owner/nested-action@$sha # v2" \
  "    - uses: 'docker://example/image@sha256:$digest'" \
  > "$case_root/.github/actions/example/action.yaml"
expect_pass "$case_root"

make_case floating-workflow-action
printf '%s\n' 'steps:' '  - uses: owner/action@v1' > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root"

make_case floating-composite-action
printf '%s\n' 'runs:' '  steps:' '    - uses: owner/action@main' > "$case_root/.github/actions/example/action.yml"
expect_fail "$case_root"

make_case floating-reusable-workflow
printf '%s\n' 'jobs:' '  call:' '    uses: owner/repository/.github/workflows/build.yml@v1' > "$case_root/.github/workflows/test.yaml"
expect_fail "$case_root"

make_case folded-action
printf '%s\n' 'steps:' '  - uses: >-' "      owner/action@$sha" > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root"

make_case literal-action
printf '%s\n' 'steps:' '  - uses: |' "      owner/action@$sha" > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root"

make_case multiline-action
printf '%s\n' 'steps:' '  - uses:' "      owner/action@$sha" > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root"

make_case flow-style-action
printf '%s\n' "steps: [{ uses: owner/action@$sha }]" > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root"

make_case quoted-folded-action
printf '%s\n' 'steps:' '  - "uses": >' "      owner/action@$sha" > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root"

make_case tagged-docker-action
printf '%s\n' 'steps:' '  - uses: docker://example/image:latest' > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root"

make_case short-docker-action-digest
printf '%s\n' 'steps:' '  - uses: docker://example/image@sha256:bbbb' > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root"

make_case floating-docker-base
printf '%s\n' 'FROM example:1' > "$case_root/Dockerfile"
expect_fail "$case_root"

printf 'Pinned dependency checker tests passed.\n'
