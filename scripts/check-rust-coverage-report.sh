#!/usr/bin/env bash
# Fail closed when a changed Rust file has no executable LLVM coverage totals.
set -euo pipefail

coverage_report=${1:?usage: check-rust-coverage-report.sh COVERAGE_JSON BASE_REF}
base_ref=${2:?usage: check-rust-coverage-report.sh COVERAGE_JSON BASE_REF}
repo_root="$(git rev-parse --show-toplevel)"

if [[ ! -s "$coverage_report" ]]; then
  echo "ERROR: LLVM coverage report is missing or empty: $coverage_report" >&2
  exit 1
fi

missing=()
while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  absolute_path="$repo_root/$path"
  if ! jq -e --arg path "$path" --arg absolute_path "$absolute_path" '
    def default_bool($value; $default):
      if $value == null then $default else $value end;
    def has_positive_line_total:
      .segments as $segments
      | any(
          range(0; ($segments | length) - 1)
          | $segments[.] as $start
          | $segments[.+1] as $end
          | (($start | length) >= 4)
            and (($end | length) >= 2)
            and (($start[0] | type) == "number")
            and (($end[0] | type) == "number")
            and ($end[0] >= $start[0])
            and (default_bool($start[3]; true) == true)
        );
    def has_positive_region_total:
      .segments as $segments
      | any(
          range(0; ($segments | length) - 1)
          | $segments[.] as $start
          | $segments[.+1] as $end
          | (($start | length) >= 6)
            and (($end | length) >= 2)
            and (($start[0] | type) == "number")
            and (($end[0] | type) == "number")
            and ($end[0] >= $start[0])
            and (default_bool($start[3]; true) == true)
            and (default_bool($start[4]; true) == true)
            and (default_bool($start[5]; false) == false)
        );
    any(
      .data[]?.files[]?;
      ((.filename == $path) or (.filename == $absolute_path))
      and (has_positive_line_total or has_positive_region_total)
    )
  ' "$coverage_report" >/dev/null; then
    missing+=("$path")
  fi
done < <(git -C "$repo_root" diff --name-only --diff-filter=ACMR "$base_ref" HEAD -- '*.rs')

if ((${#missing[@]} > 0)); then
  printf 'Changed Rust files missing positive LLVM coverage totals:\n' >&2
  printf '  %s\n' "${missing[@]}" >&2
  exit 1
fi
