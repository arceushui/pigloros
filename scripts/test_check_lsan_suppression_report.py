#!/usr/bin/env python3
"""Tests for canonical LeakSanitizer suppression-report validation."""

from __future__ import annotations

import importlib.util
import pathlib
import shlex
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKER_PATH = ROOT / "scripts" / "check_lsan_suppression_report.py"
SPEC = importlib.util.spec_from_file_location(
    "check_lsan_suppression_report", CHECKER_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

TYPE_INFO_TEMPLATE = (
    "^<bevy_reflect::utility::GenericTypeCell<"
    "bevy_reflect::type_info::TypeInfo>>::get_or_insert_by_type_id::*$"
)
TYPE_PATH_TEMPLATE = (
    "^<bevy_reflect::utility::GenericTypeCell<"
    "bevy_reflect::utility::TypePathComponent>>::get_or_insert_by_type_id::*$"
)


def table(*rows: str) -> str:
    return "\n".join(
        (
            "-----------------------------------------------------",
            "Suppressions used:",
            "  count      bytes template",
            *rows,
            "-----------------------------------------------------",
        )
    )


class LsanSuppressionReportTests(unittest.TestCase):
    def test_accepts_no_suppression_table(self) -> None:
        self.assertEqual(CHECKER.check_report("test result: ok"), {})

    def test_accepts_one_approved_row_with_observed_measurement(self) -> None:
        self.assertEqual(
            CHECKER.check_report(table(f"      6        144 {TYPE_PATH_TEMPLATE}")),
            {"TypePathComponent": (6, 144)},
        )

    def test_accepts_both_approved_rows_without_locking_measurements(self) -> None:
        self.assertEqual(
            CHECKER.check_report(
                table(
                    f"    209      25416 {TYPE_INFO_TEMPLATE}",
                    f"     57       1674 {TYPE_PATH_TEMPLATE}",
                )
            ),
            {"TypeInfo": (209, 25_416), "TypePathComponent": (57, 1_674)},
        )

    def test_aggregates_approved_rows_across_process_tables(self) -> None:
        report = "\n".join(
            (
                table(f"      2        240 {TYPE_INFO_TEMPLATE}"),
                "test result: ok",
                table(
                    f"      3        360 {TYPE_INFO_TEMPLATE}",
                    f"      6        144 {TYPE_PATH_TEMPLATE}",
                ),
            )
        )
        self.assertEqual(
            CHECKER.check_report(report),
            {"TypeInfo": (5, 600), "TypePathComponent": (6, 144)},
        )

    def test_ignores_numeric_test_output_outside_suppression_tables(self) -> None:
        report = "123 456 unrelated test output\n" + table(
            f"      6        144 {TYPE_PATH_TEMPLATE}"
        )
        self.assertEqual(
            CHECKER.check_report(report), {"TypePathComponent": (6, 144)}
        )

    def test_rejects_duplicate_template_within_one_table(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.check_report(
                table(
                    f"      2        240 {TYPE_INFO_TEMPLATE}",
                    f"      3        360 {TYPE_INFO_TEMPLATE}",
                )
            )

    def test_rejects_unknown_suppression_row(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.check_report(table("      1       1234 unrelated::*"))

    def test_rejects_changed_template(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.check_report(table("      1        120 GenericTypeCell*"))

    def test_rejects_zero_measurements(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.check_report(table(f"      0          0 {TYPE_PATH_TEMPLATE}"))

    def test_rejects_empty_suppression_table(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.check_report(table())

    def test_rejects_malformed_suppression_row(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.check_report(table(f"      six      144 {TYPE_PATH_TEMPLATE}"))

    def test_rejects_unterminated_suppression_table(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.check_report(
                "Suppressions used:\n"
                "  count      bytes template\n"
                f"      6        144 {TYPE_PATH_TEMPLATE}\n"
            )

    def test_rejects_unsuppressed_lsan_error(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.check_report("ERROR: LeakSanitizer: detected memory leaks")

    def test_rejects_unsuppressed_lsan_summary(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.check_report(
                "SUMMARY: AddressSanitizer: 1234 byte(s) leaked in 1 allocation(s)."
            )

    def test_pipefail_propagates_a_failing_sanitizer_process(self) -> None:
        producer = shlex.join(
            [
                sys.executable,
                "-c",
                "print('test result: ok'); raise SystemExit(23)",
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / "asan.log"
            validator = shlex.join([sys.executable, str(CHECKER_PATH), str(log)])
            command = (
                "set -euo pipefail\n"
                f"{producer} 2>&1 | tee {shlex.quote(str(log))}\n"
                f"{validator}\n"
            )
            completed = subprocess.run(
                ["bash", "-c", command],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(completed.returncode, 23)
        self.assertNotIn("approved LSan suppression", completed.stdout)


if __name__ == "__main__":
    unittest.main()
