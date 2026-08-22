#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$root"

reports_dir="${RUNNER_TEMP:-/tmp}/pigloros-geiger"
mkdir -p -- "$reports_dir"

while IFS=$'\t' read -r package manifest; do
  report="$reports_dir/${package}.json"
  printf 'cargo geiger: %s\n' "$package"
  cargo geiger \
    --all-features \
    --all-targets \
    --locked \
    --manifest-path "$manifest" \
    --output-format Json \
    --color never \
    >"$report"

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
done < <(
  cargo metadata --locked --no-deps --format-version 1 \
    | jq -r '.packages[] | [.name, .manifest_path] | @tsv'
)
