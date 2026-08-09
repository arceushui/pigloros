#!/usr/bin/env python3
"""Validate the single approved row in a canonical LSan suppression report."""

from __future__ import annotations

import pathlib
import re
import sys


EXPECTED_TEMPLATE = (
    "^<bevy_reflect::utility::GenericTypeCell<"
    "bevy_reflect::type_info::TypeInfo>>::get_or_insert_by_type_id::*$"
)
ROW = re.compile(r"^\s*(\d+)\s+(\d+)\s+(.+?)\s*$", re.MULTILINE)


class ReportError(RuntimeError):
    """The LSan report does not contain the one approved suppression row."""


def check_report(report: str) -> tuple[int, int]:
    if report.count("Suppressions used:") != 1:
        raise ReportError("expected exactly one suppression table")

    _, _, after_heading = report.partition("Suppressions used:")
    table, separator, _ = after_heading.partition(
        "-----------------------------------------------------"
    )
    if not separator:
        raise ReportError("suppression table is unterminated")
    rows = [
        (int(count), int(size), template)
        for count, size, template in ROW.findall(table)
    ]
    if len(rows) != 1:
        raise ReportError("expected exactly one suppression row")

    count, size, template = rows[0]
    if template != EXPECTED_TEMPLATE:
        raise ReportError("suppression template changed")
    if count <= 0 or size <= 0:
        raise ReportError("suppression measurements must be positive")
    return count, size


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {pathlib.Path(sys.argv[0]).name} REPORT", file=sys.stderr)
        return 2

    try:
        report = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
        count, size = check_report(report)
    except (OSError, ReportError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(f"==> approved LSan suppression: count={count} bytes={size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
