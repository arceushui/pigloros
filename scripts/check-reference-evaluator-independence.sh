#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

forbidden_packages='^(pos-conformance|pos-core|pos-store|pos-time|pos-runtime|pos-experiment|pos-plugin-[^ ]+) v'
dependency_tree="$(cargo tree -p pos-reference --edges normal --prefix none --locked)"
if grep -Eq "${forbidden_packages}" <<<"${dependency_tree}"; then
  printf '%s\n' 'pos-reference links a forbidden PiglorOS implementation crate' >&2
  exit 1
fi

cargo build -p pos-reference --bin pos-reference-evaluator --locked
target_directory="$(cargo metadata --format-version 1 --no-deps --locked \
  | jq -r '.target_directory')"
binary="${target_directory}/debug/pos-reference-evaluator"
test -x "${binary}"

forbidden_symbols='(pos_conformance|pos_core|pos_store|pos_time|pos_runtime|pos_experiment|pos_plugin_[[:alnum:]_]+)::'
if nm --demangle --defined-only "${binary}" | grep -Eq "${forbidden_symbols}"; then
  printf '%s\n' 'evaluator binary contains a forbidden PiglorOS implementation symbol' >&2
  exit 1
fi

printf '%s\n' 'verified independent evaluator dependency graph and binary symbols'
