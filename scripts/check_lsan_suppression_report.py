#!/usr/bin/env python3
"""Validate the two approved rows in a canonical LSan suppression report."""

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
TYPE_INFO_MEASUREMENT = (754, 93_042)
ROW = re.compile(r"^\s*(\d+)\s+(\d+)\s+(.+?)\s*$", re.MULTILINE)


class ReportError(RuntimeError):
    """The LSan report does not contain exactly the two approved rows."""


def check_report(report: str) -> dict[str, tuple[int, int]]:
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
    if len(rows) != 2:
        raise ReportError("expected exactly two suppression rows")

    measurements: dict[str, tuple[int, int]] = {}
    for count, size, template in rows:
        label = EXPECTED_TEMPLATES.get(template)
        if label is None:
            raise ReportError("suppression template changed")
        if label in measurements:
            raise ReportError(f"duplicate {label} suppression row")
        if count <= 0 or size <= 0:
            raise ReportError(f"{label} suppression measurements must be positive")
        measurements[label] = (count, size)

    type_info = measurements["TypeInfo"]
    if type_info != TYPE_INFO_MEASUREMENT:
        raise ReportError(
            "TypeInfo suppression measurement drift: "
            f"expected count={TYPE_INFO_MEASUREMENT[0]} "
            f"bytes={TYPE_INFO_MEASUREMENT[1]}, "
            f"got count={type_info[0]} bytes={type_info[1]}"
        )
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

    type_info = measurements["TypeInfo"]
    type_path = measurements["TypePathComponent"]
    print(
        "==> approved LSan suppressions: "
        f"TypeInfo count={type_info[0]} bytes={type_info[1]}; "
        f"TypePathComponent count={type_path[0]} bytes={type_path[1]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
