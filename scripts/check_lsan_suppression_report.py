#!/usr/bin/env python3
"""Validate every observed row in a multi-process LSan report."""

from __future__ import annotations

import pathlib
import re
import sys


TYPE_INFO_TEMPLATE = (
    "^<bevy_reflect::utility::GenericTypeCell<"
    "bevy_reflect::type_info::TypeInfo>>::get_or_insert_by_type_id::*$"
)
TYPE_PATH_TEMPLATE = (
    "^<bevy_reflect::utility::GenericTypeCell<"
    "bevy_reflect::utility::TypePathComponent>>::get_or_insert_by_type_id::*$"
)
EXPECTED_TEMPLATES = {
    TYPE_INFO_TEMPLATE: "TypeInfo",
    TYPE_PATH_TEMPLATE: "TypePathComponent",
}
SEPARATOR = "-----------------------------------------------------"
HEADER = "  count      bytes template"
ROW = re.compile(r"^\s*(\d+)\s+(\d+)\s+(.+?)\s*$")
UNSUPPRESSED_MARKERS = (
    "ERROR: LeakSanitizer: detected memory leaks",
    "SUMMARY: AddressSanitizer:",
    "SUMMARY: LeakSanitizer:",
)


class ReportError(RuntimeError):
    """The LSan report violates the exact-template observation policy."""


def check_report(report: str) -> dict[str, tuple[int, int]]:
    if any(marker in report for marker in UNSUPPRESSED_MARKERS):
        raise ReportError("unsuppressed LeakSanitizer finding")

    lines = report.splitlines()
    measurements: dict[str, tuple[int, int]] = {}
    index = 0
    while index < len(lines):
        if lines[index].strip() != "Suppressions used:":
            index += 1
            continue

        if index == 0 or lines[index - 1].strip() != SEPARATOR:
            raise ReportError("suppression table is missing its opening separator")
        if index + 1 >= len(lines) or lines[index + 1] != HEADER:
            raise ReportError("suppression table header changed")

        index += 2
        seen_in_table: set[str] = set()
        row_count = 0
        while index < len(lines) and lines[index].strip() != SEPARATOR:
            match = ROW.fullmatch(lines[index])
            if match is None:
                raise ReportError("malformed suppression row")
            count, size = (int(value) for value in match.group(1, 2))
            template = match.group(3)
            label = EXPECTED_TEMPLATES.get(template)
            if label is None:
                raise ReportError("suppression template changed")
            if label in seen_in_table:
                raise ReportError(f"duplicate {label} row within one table")
            if count <= 0 or size <= 0:
                raise ReportError(
                    f"{label} suppression measurements must be positive"
                )
            seen_in_table.add(label)
            prior_count, prior_size = measurements.get(label, (0, 0))
            measurements[label] = (prior_count + count, prior_size + size)
            row_count += 1
            index += 1

        if index >= len(lines):
            raise ReportError("suppression table is unterminated")
        if row_count == 0:
            raise ReportError("suppression table contains no rows")
        index += 1

    return measurements


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {pathlib.Path(sys.argv[0]).name} REPORT", file=sys.stderr)
        return 2

    try:
        report = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
        measurements = check_report(report)
    except (OSError, ReportError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    observed = "; ".join(
        f"{label} count={measurements[label][0]} bytes={measurements[label][1]}"
        for label in ("TypeInfo", "TypePathComponent")
        if label in measurements
    )
    print(f"==> approved LSan suppression observations: {observed or 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
