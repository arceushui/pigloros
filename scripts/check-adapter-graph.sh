#!/usr/bin/env bash
# The conformance adapter keeps the Wasmtime worker, the trust-holding crates and the
# test-support fixtures out of its own dependency edges (ADR-061 revision 8 decision 2, R8-A9).
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

package='pos-plugin-conformance-adapter'

# The whole normal graph: no Wasmtime, no host, no worker.
forbidden_graph='^(wasmtime|pos-plugin-host|pos-plugin-worker) v'
dependency_tree="$(cargo tree -p "${package}" --edges normal --prefix none --locked)"
if grep -Eq "${forbidden_graph}" <<<"${dependency_tree}"; then
  printf '%s\n' "${package} links Wasmtime, pos-plugin-host or pos-plugin-worker" >&2
  exit 1
fi

# The adapter's own direct normal edges: the crates it reaches only through pos-runtime stay
# transitive (a dev-dependency edge has a kind and is not listed here).
forbidden_direct='^(pos-conformance|pos-store|pos-plugin-publisher|pos-plugin-host|pos-plugin-worker|pos-experiment|wasmtime)$'
direct_edges="$(cargo metadata --format-version 1 --no-deps --locked \
  | jq -r --arg package "${package}" \
    '.packages[] | select(.name == $package) | .dependencies[] | select(.kind == null) | .name')"
if grep -Eq "${forbidden_direct}" <<<"${direct_edges}"; then
  printf '%s\n' "${package} has a forbidden direct normal dependency" >&2
  exit 1
fi

printf '%s\n' "verified the ${package} dependency graph"
