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
  printf 'from example@sha256:%s AS builder\nFrOm runtime@sha256:%s\n' \
    "$digest" "$digest" > "$case_root/Dockerfile"
}

expect_pass() {
  if ! bash "$checker" "$1" >/dev/null; then
    printf 'ERROR: valid fixture was rejected: %s\n' "$1" >&2
    exit 1
  fi
}

expect_fail() {
  expected=${2:-}
  if output=$(bash "$checker" "$1" 2>&1); then
    printf 'ERROR: invalid fixture was accepted: %s\n' "$1" >&2
    exit 1
  fi
  if [[ -n "$expected" && "$output" != *"$expected"* ]]; then
    printf 'ERROR: fixture failed for the wrong reason: %s\n%s\n' "$1" "$output" >&2
    exit 1
  fi
}

# The checker must enforce the repository that invokes this self-test too.
expect_pass "$root"

make_case valid
mkdir -p "$case_root/tools/actions/root" "$case_root/tools/actions/child"
printf '%s\n' \
  'jobs:' \
  '  call-local:' \
  '    uses: ./.github/workflows/reusable.yml' \
  '  call-remote:' \
  "    uses: owner/repository/.github/workflows/build.yml@$sha # v1" \
  '  build:' \
  '    steps:' \
  "      - uses: owner/action@$sha # v1" \
  "      - uses: docker://example/image@sha256:$digest" \
  '      - uses: ./tools/actions/root' \
  > "$case_root/.github/workflows/valid.yml"
printf '%s\n' \
  'jobs:' \
  '  call:' \
  "    uses: owner/repository/.github/workflows/nested.yml@$sha" \
  > "$case_root/.github/workflows/reusable.yml"
printf '%s\n' \
  'runs:' \
  '  using: composite' \
  '  steps:' \
  "    - uses: owner/nested-action@$sha # v2" \
  "    - uses: 'docker://example/image@sha256:$digest'" \
  > "$case_root/.github/actions/example/action.yaml"
printf '%s\n' \
  'runs:' \
  '  using: composite' \
  '  steps:' \
  '    - uses: ./tools/actions/child' \
  > "$case_root/tools/actions/root/action.yml"
printf '%s\n' \
  'runs:' \
  '  using: composite' \
  '  steps:' \
  "    - uses: owner/deep-action@$sha" \
  > "$case_root/tools/actions/child/action.yaml"
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

make_case compact-json-action
printf '%s\n' '{"steps":[{"uses":"owner/action@main"}]}' > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root" 'compact, flow, and explicit-key uses syntax is forbidden'

make_case compact-sequence-action
printf '%s\n' "steps: [uses: owner/action@$sha]" > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root" 'compact, flow, and explicit-key uses syntax is forbidden'

make_case tagged-compact-action-key
printf '%s\n' "steps: [{ ? !!str \"uses\" : owner/action@$sha }]" > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root" 'compact, flow, and explicit-key uses syntax is forbidden'

make_case sequence-explicit-action-key
printf '%s\n' 'steps:' '  - ? uses' '    : owner/action@main' > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root" 'compact, flow, and explicit-key uses syntax is forbidden'

make_case escaped-json-action-key
printf '%s\n' '{"steps":[{"\u0075ses":"owner/action@main"}]}' > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root" 'hexadecimal and Unicode escapes are forbidden in checked YAML'

make_case escaped-yaml-action-key
printf '%s\n' 'steps:' '  - "\x75ses": owner/action@main' > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root" 'hexadecimal and Unicode escapes are forbidden in checked YAML'

make_case quoted-folded-action
printf '%s\n' 'steps:' '  - "uses": >' "      owner/action@$sha" > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root"

make_case tagged-docker-action
printf '%s\n' 'steps:' '  - uses: docker://example/image:latest' > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root"

make_case short-docker-action-digest
printf '%s\n' 'steps:' '  - uses: docker://example/image@sha256:bbbb' > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root"

make_case recursive-local-action
mkdir -p "$case_root/tools/actions/root" "$case_root/tools/actions/child"
printf '%s\n' 'steps:' '  - uses: ./tools/actions/root' > "$case_root/.github/workflows/test.yml"
printf '%s\n' 'runs:' '  steps:' '    - uses: ./tools/actions/child' > "$case_root/tools/actions/root/action.yml"
printf '%s\n' 'runs:' '  steps:' '    - uses: owner/action@main' > "$case_root/tools/actions/child/action.yml"
expect_fail "$case_root" 'external Action reference is not pinned'

make_case missing-local-action-metadata
mkdir -p "$case_root/tools/actions/missing"
printf '%s\n' 'steps:' '  - uses: ./tools/actions/missing' > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root" 'local Action is missing action.yml or action.yaml'

make_case missing-local-reusable-workflow
printf '%s\n' 'jobs:' '  call:' '    uses: ./.github/workflows/missing.yml' > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root" 'referenced YAML file does not exist'

make_case ambiguous-local-action-metadata
mkdir -p "$case_root/tools/actions/ambiguous"
printf '%s\n' 'steps:' '  - uses: ./tools/actions/ambiguous' > "$case_root/.github/workflows/test.yml"
printf '%s\n' 'runs:' '  steps: []' > "$case_root/tools/actions/ambiguous/action.yml"
printf '%s\n' 'runs:' '  steps: []' > "$case_root/tools/actions/ambiguous/action.yaml"
expect_fail "$case_root" 'local Action has ambiguous metadata'

make_case lexical-root-escape
printf '%s\n' 'steps:' '  - uses: ./../outside-action' > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root" 'local uses reference escapes repository root'

make_case symlink-root-escape
mkdir -p "$fixture/outside-action" "$case_root/tools/actions"
printf '%s\n' 'runs:' '  steps: []' > "$fixture/outside-action/action.yml"
ln -s "$fixture/outside-action" "$case_root/tools/actions/escape"
printf '%s\n' 'steps:' '  - uses: ./tools/actions/escape' > "$case_root/.github/workflows/test.yml"
expect_fail "$case_root" 'local uses reference escapes repository root'

make_case local-action-cycle
mkdir -p "$case_root/tools/actions/first" "$case_root/tools/actions/second"
printf '%s\n' 'steps:' '  - uses: ./tools/actions/first' > "$case_root/.github/workflows/test.yml"
printf '%s\n' 'runs:' '  steps:' '    - uses: ./tools/actions/second' > "$case_root/tools/actions/first/action.yml"
printf '%s\n' 'runs:' '  steps:' '    - uses: ./tools/actions/first' > "$case_root/tools/actions/second/action.yml"
expect_fail "$case_root" 'local uses cycle detected'

make_case floating-docker-base
printf '%s\n' 'from example:1' > "$case_root/Dockerfile"
expect_fail "$case_root" 'Docker base image is not pinned'

make_case mixed-case-floating-docker-base
printf '%s\n' 'fRoM example:1 AS builder' > "$case_root/Dockerfile"
expect_fail "$case_root" 'Docker base image is not pinned'

printf 'Pinned dependency checker tests passed.\n'
