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

TEMPLATE = (
    "^<bevy_reflect::utility::GenericTypeCell<"
    "bevy_reflect::type_info::TypeInfo>>::get_or_insert_by_type_id::*$"
)


def report(*rows: str) -> str:
    return "\n".join(
        (
            "test result: ok. 1 passed; 0 failed",
            "-----------------------------------------------------",
            "Suppressions used:",
            "  count      bytes template",
            *rows,
            "-----------------------------------------------------",
        )
    )


class LsanSuppressionReportTests(unittest.TestCase):
    def test_accepts_one_approved_row_and_returns_measurements(self) -> None:
        self.assertEqual(
            CHECKER.check_report(report(f"    370      38078 {TEMPLATE}")),
            (370, 38_078),
        )

    def test_ignores_numeric_test_output_outside_the_suppression_table(self) -> None:
        self.assertEqual(
            CHECKER.check_report(
                "123 456 unrelated test output\n"
                + report(f"    370      38078 {TEMPLATE}")
            ),
            (370, 38_078),
        )

    def test_rejects_missing_table(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.check_report("test result: ok")

    def test_rejects_duplicate_table(self) -> None:
        table = report(f"    370      38078 {TEMPLATE}")
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.check_report(f"{table}\n{table}")

    def test_rejects_extra_suppression_row(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.check_report(
                report(
                    f"    370      38078 {TEMPLATE}",
                    "      1       1234 unrelated::*",
                )
            )

    def test_rejects_changed_template(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.check_report(report("    370      38078 GenericTypeCell*"))

    def test_rejects_zero_measurements(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.check_report(report(f"      0          0 {TEMPLATE}"))

    def test_pipefail_propagates_a_failing_sanitizer_process(self) -> None:
        valid_report = report(f"    370      38078 {TEMPLATE}")
        producer = shlex.join(
            [
                sys.executable,
                "-c",
                f"print({valid_report!r}); raise SystemExit(23)",
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
