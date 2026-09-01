#!/usr/bin/env python3
"""Fail when a cargo-crap delta regresses or adds a function above the ceiling."""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Any


REPORT_VERSION = "0.2.2"
NEW_FUNCTION_THRESHOLD = 30.0
ALLOWED_STATUSES = {"regressed", "improved", "new", "unchanged", "moved"}


class ReportError(RuntimeError):
    """The cargo-crap report is malformed or violates the quality policy."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReportError(message)


def validated_entries(report: Any) -> list[dict[str, Any]]:
    require(isinstance(report, dict), "cargo-crap report must be a JSON object")
    require(report.get("version") == REPORT_VERSION, "unsupported cargo-crap report version")
    entries = report.get("entries")
    require(isinstance(entries, list), "cargo-crap report entries must be an array")
    require(bool(entries), "cargo-crap report must contain analyzed functions")
    require(isinstance(report.get("removed"), list), "cargo-crap removed must be an array")

    for index, entry in enumerate(entries):
        require(isinstance(entry, dict), f"entry {index} must be an object")
        require(isinstance(entry.get("file"), str), f"entry {index} file must be a string")
        require(
            isinstance(entry.get("function"), str),
            f"entry {index} function must be a string",
        )
        line = entry.get("line")
        require(
            isinstance(line, int) and not isinstance(line, bool) and line > 0,
            f"entry {index} line must be a positive integer",
        )
        crap = entry.get("crap")
        require(
            isinstance(crap, (int, float)) and not isinstance(crap, bool) and crap >= 1,
            f"entry {index} CRAP score must be a number at least 1",
        )
        require(
            entry.get("status") in ALLOWED_STATUSES,
            f"entry {index} has an unsupported status",
        )
    return entries


def policy_findings(report: Any) -> list[dict[str, Any]]:
    entries = validated_entries(report)
    return [
        entry
        for entry in entries
        if entry["status"] == "regressed"
        or (entry["status"] == "new" and entry["crap"] > NEW_FUNCTION_THRESHOLD)
    ]


def check_report(path: pathlib.Path) -> None:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReportError(f"cannot read cargo-crap report: {error}") from error

    findings = policy_findings(report)
    for entry in findings:
        reason = (
            "CRAP score regressed"
            if entry["status"] == "regressed"
            else f"new function exceeds CRAP {NEW_FUNCTION_THRESHOLD:g}"
        )
        print(
            f"{entry['file']}:{entry['line']}: {reason}: "
            f"{entry['function']} scored {entry['crap']:.2f}",
            file=sys.stderr,
        )
    require(not findings, f"cargo-crap policy rejected {len(findings)} function(s)")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_cargo_crap_report.py REPORT.json", file=sys.stderr)
        return 2
    try:
        check_report(pathlib.Path(sys.argv[1]))
    except ReportError as error:
        print(f"cargo-crap policy error: {error}", file=sys.stderr)
        return 1
    print("cargo-crap policy OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
