#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import math
import pathlib
import sys
from typing import Any


MAX_REPORTED_FILES = 25


class CoverageExportError(ValueError):
    """The llvm-cov export JSON or floor threshold is malformed or inconsistent."""


def _require_threshold(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CoverageExportError(f"invalid {name} threshold: {value!r}")
    threshold = float(value)
    if not math.isfinite(threshold) or threshold < 0.0 or threshold > 100.0:
        raise CoverageExportError(f"invalid {name} threshold: {value!r}")
    return threshold


def _require_metric(totals: dict[str, Any], name: str) -> tuple[int, int, float]:
    metric = totals.get(name)
    if not isinstance(metric, dict):
        raise CoverageExportError(f"missing {name} coverage totals")
    count = metric.get("count")
    covered = metric.get("covered")
    percent = metric.get("percent")
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or isinstance(covered, bool)
        or not isinstance(covered, int)
        or isinstance(percent, bool)
        or not isinstance(percent, (int, float))
    ):
        raise CoverageExportError(f"malformed {name} coverage totals")
    if count <= 0 or covered < 0 or covered > count:
        raise CoverageExportError(
            f"invalid {name} coverage counts: covered={covered}, count={count}"
        )
    if not math.isfinite(percent) or percent < 0.0 or percent > 100.0:
        raise CoverageExportError(f"invalid {name} coverage percent: {percent!r}")
    computed = (covered / count) * 100.0
    if abs(percent - computed) > 1e-4:
        raise CoverageExportError(
            f"inconsistent {name} coverage percent: reported={percent}, computed={computed}"
        )
    return covered, count, min(float(percent), computed)


def _missed_count(metric: Any) -> int:
    if not isinstance(metric, dict):
        return 0
    count = metric.get("count")
    covered = metric.get("covered")
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or isinstance(covered, bool)
        or not isinstance(covered, int)
    ):
        return 0
    return max(0, count - covered)


def uncovered_lines_from_segments(segments: list[Any]) -> list[int]:
    """Return sorted 1-based line numbers with zero execution count from LLVM segments.

    Each LLVM export segment is ``[line, col, count, has_count, is_region_entry,
    is_gap_region?]`` marking state transitions in source order. Active non-gap
    counted states propagate across intermediate lines until the next segment.
    """
    parsed: list[tuple[int, int, int, bool, bool]] = []
    for segment in segments:
        if not isinstance(segment, list) or len(segment) < 5:
            continue
        line, col, count, has_count, _is_entry = segment[:5]
        is_gap = bool(segment[5]) if len(segment) >= 6 else False
        if (
            isinstance(line, bool)
            or not isinstance(line, int)
            or isinstance(col, bool)
            or not isinstance(col, int)
            or isinstance(count, bool)
            or not isinstance(count, int)
            or not isinstance(has_count, bool)
        ):
            continue
        parsed.append((line, col, count, has_count, is_gap))

    line_max_count: dict[int, int] = {}

    def record(line_number: int, count: int) -> None:
        previous = line_max_count.get(line_number)
        if previous is None or count > previous:
            line_max_count[line_number] = count

    for idx, (line, _col, count, has_count, is_gap) in enumerate(parsed):
        if not has_count or is_gap:
            continue
        record(line, count)
        if idx + 1 < len(parsed):
            next_line, next_col, _, _, _ = parsed[idx + 1]
            for spanned_line in range(line + 1, next_line):
                record(spanned_line, count)
            if next_line > line and next_col > 1:
                record(next_line, count)
    return sorted(line for line, max_count in line_max_count.items() if max_count == 0)


def format_line_ranges(lines: list[int]) -> str:
    """Format sorted line numbers into compact ranges (e.g. ``12-14, 20``)."""
    if not lines:
        return ""
    ranges: list[str] = []
    start = end = lines[0]
    for line in lines[1:]:
        if line == end + 1:
            end = line
        else:
            ranges.append(f"{start}" if start == end else f"{start}-{end}")
            start = end = line
    ranges.append(f"{start}" if start == end else f"{start}-{end}")
    return ", ".join(ranges)


def check_coverage_data(
    payload: Any,
    *,
    fail_under_lines: float,
    fail_under_regions: float,
) -> tuple[str, list[str]]:
    """Validate workspace totals and return ``(summary_line, failure_details)``."""
    lines_floor = _require_threshold(fail_under_lines, "fail-under-lines")
    regions_floor = _require_threshold(fail_under_regions, "fail-under-regions")
    if not isinstance(payload, dict):
        raise CoverageExportError("coverage JSON root must be an object")
    data = payload.get("data")
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        raise CoverageExportError("coverage JSON must contain exactly one data entry")
    entry = data[0]
    totals = entry.get("totals")
    if not isinstance(totals, dict):
        raise CoverageExportError("coverage JSON data[0] is missing totals")

    lines_covered, lines_count, lines_pct = _require_metric(totals, "lines")
    regions_covered, regions_count, regions_pct = _require_metric(totals, "regions")
    summary = (
        f"Workspace coverage: lines {lines_covered}/{lines_count} ({lines_pct}%); "
        f"regions {regions_covered}/{regions_count} ({regions_pct}%)"
    )

    failures: list[str] = []
    if lines_pct < lines_floor:
        failures.append(
            f"line coverage {lines_pct:.4f}% is below threshold {lines_floor:.2f}%"
        )
    if regions_pct < regions_floor:
        failures.append(
            f"region coverage {regions_pct:.4f}% is below threshold {regions_floor:.2f}%"
        )

    if failures:
        files = entry.get("files")
        if isinstance(files, list):
            incomplete: list[tuple[int, int, str, str]] = []
            for file_entry in files:
                if not isinstance(file_entry, dict):
                    continue
                filename = str(file_entry.get("filename", "<unknown>"))
                file_summary = file_entry.get("summary")
                if not isinstance(file_summary, dict):
                    continue
                missed_lines = _missed_count(file_summary.get("lines"))
                missed_regions = _missed_count(file_summary.get("regions"))
                if missed_lines > 0 or missed_regions > 0:
                    segments = file_entry.get("segments")
                    missing_str = (
                        format_line_ranges(uncovered_lines_from_segments(segments))
                        if isinstance(segments, list)
                        else ""
                    )
                    incomplete.append((missed_regions, missed_lines, filename, missing_str))
            incomplete.sort(key=lambda item: (-item[0], -item[1], item[2]))
            for missed_regions, missed_lines, filename, missing_str in incomplete[:MAX_REPORTED_FILES]:
                detail = (
                    f"  {filename}: missed_lines={missed_lines}, "
                    f"missed_regions={missed_regions}"
                )
                if missing_str:
                    detail += f" (lines: {missing_str})"
                failures.append(detail)
            omitted = len(incomplete) - MAX_REPORTED_FILES
            if omitted > 0:
                failures.append(f"  ... and {omitted} more files")
    return summary, failures


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Enforce workspace coverage floors from llvm-cov export JSON."
    )
    parser.add_argument("coverage_json", type=pathlib.Path)
    parser.add_argument("--fail-under-lines", type=float, required=True)
    parser.add_argument("--fail-under-regions", type=float, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        raw = args.coverage_json.read_text(encoding="utf-8")
        payload = json.loads(raw)
        summary, failures = check_coverage_data(
            payload,
            fail_under_lines=args.fail_under_lines,
            fail_under_regions=args.fail_under_regions,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, CoverageExportError) as error:
        print(f"ERROR: workspace coverage floor check failed: {error}", file=sys.stderr)
        return 1

    print(summary)
    if failures:
        for line in failures:
            print(f"ERROR: {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
