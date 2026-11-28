#!/usr/bin/env python3
"""Unit tests for scripts/check_workspace_coverage_floor.py."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

import check_workspace_coverage_floor as floor


def make_payload(
    *,
    lines_covered: int = 995,
    lines_count: int = 1000,
    regions_covered: int = 992,
    regions_count: int = 1000,
    files: list[dict] | None = None,
) -> dict:
    return {
        "data": [
            {
                "totals": {
                    "lines": {
                        "count": lines_count,
                        "covered": lines_covered,
                        "percent": (lines_covered / lines_count) * 100.0 if lines_count else 0.0,
                    },
                    "regions": {
                        "count": regions_count,
                        "covered": regions_covered,
                        "percent": (
                            (regions_covered / regions_count) * 100.0 if regions_count else 0.0
                        ),
                    },
                },
                "files": files if files is not None else [],
            }
        ]
    }


class WorkspaceCoverageFloorTests(unittest.TestCase):
    def test_accepts_totals_at_or_above_floors(self) -> None:
        summary, failures = floor.check_coverage_data(
            make_payload(lines_covered=990, lines_count=1000, regions_covered=990, regions_count=1000),
            fail_under_lines=99.0,
            fail_under_regions=99.0,
        )
        self.assertEqual(failures, [])
        self.assertEqual(
            summary,
            "Workspace coverage: lines 990/1000 (99.0%); regions 990/1000 (99.0%)",
        )

    def test_rejects_lines_or_regions_below_floor_and_reports_missing_lines(self) -> None:
        payload = make_payload(
            lines_covered=989,
            lines_count=1000,
            regions_covered=985,
            regions_count=1000,
            files=[
                {
                    "filename": "crates/pos-core/src/lib.rs",
                    "summary": {
                        "lines": {"count": 100, "covered": 97},
                        "regions": {"count": 120, "covered": 115},
                    },
                    "segments": [
                        [10, 1, 5, True, True, False],
                        [12, 1, 0, True, True, False],
                        [13, 1, 0, True, False, False],
                        [14, 1, 0, True, False, False],
                        [15, 1, 0, True, False, True],  # gap region ignored
                        [20, 1, 0, True, True, False],
                        [20, 8, 2, True, True, False],  # covered later on same line
                        [25, 1, 0, True, True, False],
                    ],
                }
            ],
        )
        summary, failures = floor.check_coverage_data(
            payload, fail_under_lines=99.0, fail_under_regions=99.0
        )
        self.assertIn("lines 989/1000", summary)
        joined = "\n".join(failures)
        self.assertIn("line coverage 98.9000% is below threshold 99.00%", joined)
        self.assertIn("region coverage 98.5000% is below threshold 99.00%", joined)
        self.assertIn("crates/pos-core/src/lib.rs", joined)
        self.assertIn("lines: 12-14, 25", joined)

    def test_rejects_rounded_up_percent_when_computed_ratio_is_below_floor(self) -> None:
        payload = make_payload(
            lines_covered=9899995,
            lines_count=10000000,
            regions_covered=1000,
            regions_count=1000,
        )
        # Reported percent rounded up to 99.0 within 1e-4 tolerance, but exact
        # ratio is 98.99995% — must still fail closed.
        payload["data"][0]["totals"]["lines"]["percent"] = 99.0
        _summary, failures = floor.check_coverage_data(
            payload, fail_under_lines=99.0, fail_under_regions=99.0
        )
        self.assertTrue(any("line coverage" in msg for msg in failures))

    def test_fails_closed_on_malformed_or_tampered_payloads(self) -> None:
        bad_payloads = [
            [],
            {},
            {"data": []},
            {"data": [{}, {}]},
            {"data": [{}]},
            {"data": [{"totals": {"lines": {"count": 0, "covered": 0, "percent": 100.0},
                                  "regions": {"count": 10, "covered": 10, "percent": 100.0}}}]},
            {"data": [{"totals": {"lines": {"count": 10, "covered": 11, "percent": 100.0},
                                  "regions": {"count": 10, "covered": 10, "percent": 100.0}}}]},
            {"data": [{"totals": {"lines": {"count": 100, "covered": 50, "percent": 99.5},
                                  "regions": {"count": 100, "covered": 100, "percent": 100.0}}}]},
            {"data": [{"totals": {"lines": {"count": True, "covered": 1, "percent": 100.0},
                                  "regions": {"count": 1, "covered": 1, "percent": 100.0}}}]},
        ]
        for payload in bad_payloads:
            with self.subTest(payload=payload), self.assertRaises(floor.CoverageFloorError):
                floor.check_coverage_data(
                    payload, fail_under_lines=99.0, fail_under_regions=99.0
                )

    def test_cli_exit_codes_for_passing_failing_and_missing_files(self) -> None:
        script = pathlib.Path(floor.__file__)
        with tempfile.TemporaryDirectory() as directory:
            passing = pathlib.Path(directory) / "pass.json"
            passing.write_text(json.dumps(make_payload()), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(script), "--fail-under-lines", "99",
                 "--fail-under-regions", "99", str(passing)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Workspace coverage: lines 995/1000", result.stdout)

            failing = pathlib.Path(directory) / "fail.json"
            failing.write_text(json.dumps(make_payload(regions_covered=980)), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(script), "--fail-under-lines", "99",
                 "--fail-under-regions", "99", str(failing)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("region coverage 98.0000%", result.stderr)

            missing = pathlib.Path(directory) / "absent.json"
            result = subprocess.run(
                [sys.executable, str(script), "--fail-under-lines", "99",
                 "--fail-under-regions", "99", str(missing)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
