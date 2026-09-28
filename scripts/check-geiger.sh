#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$root"

reports_dir="${RUNNER_TEMP:-/tmp}/pigloros-geiger"
mkdir -p -- "$reports_dir"
export reports_dir

scan_package() {
  package="$1"
  manifest="$2"
  report="$reports_dir/${package}.json"
  printf 'cargo geiger: %s\n' "$package"
  cargo geiger \
    --all-features \
    --all-targets \
    --locked \
    --manifest-path "$manifest" \
    --output-format Json \
    --color never \
    >"$report" || return

  jq -e --arg package "$package" '
    [
      .packages[]
      | select(.package.id.name == $package)
      | select(.package.id.source | has("Path"))
      | .unsafety.used
      | [
          .functions.unsafe_,
          .exprs.unsafe_,
          .item_impls.unsafe_,
          .item_traits.unsafe_,
          .methods.unsafe_
        ]
      | add
    ]
    | length == 1 and .[0] == 0
  ' "$report" >/dev/null
}

export -f scan_package

# Each package manifest is a valid cargo-geiger root. Keep scans sequential:
# geiger cleans the shared Cargo target directory before collecting dep-info,
# so concurrent scans can delete files that another scan is still reading.
cargo metadata --locked --no-deps --format-version 1 \
  | jq -j '.packages[] | .name, "\u0000", .manifest_path, "\u0000"' \
  | xargs -0 -r -n 2 bash -c 'scan_package "$1" "$2"' _
