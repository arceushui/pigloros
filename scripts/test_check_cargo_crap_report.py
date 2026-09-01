#!/usr/bin/env python3
"""Adversarial tests for the cargo-crap delta report policy."""

from __future__ import annotations

import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKER_PATH = ROOT / "scripts" / "check_cargo_crap_report.py"
SPEC = importlib.util.spec_from_file_location("check_cargo_crap_report", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def entry(*, status: str, crap: float) -> dict:
    return {
        "file": "src/lib.rs",
        "function": "example",
        "line": 7,
        "cyclomatic": 2,
        "coverage": 100.0,
        "crap": crap,
        "baseline_crap": None if status == "new" else crap,
        "delta": None if status == "new" else 0.0,
        "status": status,
    }


def report(*entries: dict) -> dict:
    return {"version": "0.2.2", "entries": list(entries), "removed": []}


class CargoCrapReportTests(unittest.TestCase):
    def test_unchanged_legacy_score_above_ceiling_passes(self) -> None:
        self.assertEqual(CHECKER.policy_findings(report(entry(status="unchanged", crap=51))), [])

    def test_regression_below_absolute_ceiling_fails(self) -> None:
        findings = CHECKER.policy_findings(report(entry(status="regressed", crap=12)))
        self.assertEqual(len(findings), 1)

    def test_new_function_above_ceiling_fails(self) -> None:
        findings = CHECKER.policy_findings(report(entry(status="new", crap=30.01)))
        self.assertEqual(len(findings), 1)

    def test_new_function_at_ceiling_passes(self) -> None:
        self.assertEqual(CHECKER.policy_findings(report(entry(status="new", crap=30))), [])

    def test_improved_moved_and_removed_functions_pass(self) -> None:
        value = report(entry(status="improved", crap=4), entry(status="moved", crap=7))
        value["removed"] = [{"file": "src/old.rs", "function": "old", "baseline_crap": 9}]
        self.assertEqual(CHECKER.policy_findings(value), [])

    def test_unknown_report_version_fails_closed(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.policy_findings({"version": "9.9.9", "entries": [], "removed": []})

    def test_unknown_status_fails_closed(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.policy_findings(report(entry(status="waived", crap=1)))

    def test_boolean_score_is_not_accepted_as_a_number(self) -> None:
        with self.assertRaises(CHECKER.ReportError):
            CHECKER.policy_findings(report(entry(status="new", crap=True)))


if __name__ == "__main__":
    unittest.main()
