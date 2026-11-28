#!/usr/bin/env python3

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


def make_segment(
    line: int,
    col: int,
    count: int,
    *,
    has_count: bool = True,
    is_entry: bool = True,
    is_gap: bool = False,
) -> list[int | bool]:
    return [line, col, count, has_count, is_entry, is_gap]


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

    def test_accepts_exact_equality_despite_float_multiplication_artifact(self) -> None:
        # Independently constructed 58/100 fixture: (58 / 100) * 100.0 == 57.99999999999999
        # in IEEE-754 binary64, which must still satisfy an exact 58% floor.
        payload = {
            "data": [
                {
                    "totals": {
                        "lines": {"count": 100, "covered": 58, "percent": 58.0},
                        "regions": {"count": 50, "covered": 29, "percent": 58.0},
                    },
                    "files": [],
                }
            ]
        }
        summary, failures = floor.check_coverage_data(
            payload, fail_under_lines=58.0, fail_under_regions=58.0
        )
        self.assertEqual(failures, [])
        self.assertEqual(
            summary,
            "Workspace coverage: lines 58/100 (58.0%); regions 29/50 (58.0%)",
        )

    def test_rejects_lines_or_regions_below_floor_and_reports_multiline_spans(self) -> None:
        payload = make_payload(
            lines_covered=989,
            lines_count=1000,
            regions_covered=985,
            regions_count=1000,
            files=[
                {
                    "filename": "crates/pos-core/src/lib.rs",
                    "summary": {
                        "lines": {"count": 100, "covered": 94},
                        "regions": {"count": 120, "covered": 115},
                    },
                    "segments": [
                        make_segment(10, 1, count=5),
                        make_segment(12, 1, count=0),
                        make_segment(16, 1, count=5, is_entry=False),
                        make_segment(17, 1, count=0, is_entry=False, is_gap=True),
                        make_segment(20, 1, count=0),
                        make_segment(20, 8, count=2),
                        make_segment(25, 1, count=0),
                        make_segment(26, 1, count=0, has_count=False, is_entry=False),
                        [30, 1, 0, True, True, "not-a-bool"],
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
        self.assertIn("lines: 12-15, 25", joined)
        self.assertNotIn("30", joined)

    def test_rejects_single_metric_failures_independently(self) -> None:
        _summary, line_only = floor.check_coverage_data(
            make_payload(lines_covered=989, lines_count=1000, regions_covered=995, regions_count=1000),
            fail_under_lines=99.0,
            fail_under_regions=99.0,
        )
        self.assertEqual(len(line_only), 1)
        self.assertIn("line coverage", line_only[0])

        _summary, region_only = floor.check_coverage_data(
            make_payload(lines_covered=995, lines_count=1000, regions_covered=989, regions_count=1000),
            fail_under_lines=99.0,
            fail_under_regions=99.0,
        )
        self.assertEqual(len(region_only), 1)
        self.assertIn("region coverage", region_only[0])

    def test_truncation_reports_omitted_file_count_and_handles_malformed_file_summaries(self) -> None:
        files = [
            {
                "filename": f"crates/pkg/src/f{idx:02d}.rs",
                "summary": {
                    "lines": {"count": 10, "covered": 9},
                    "regions": {"count": 10, "covered": 9},
                },
            }
            for idx in range(28)
        ]
        files.append({"filename": "bad-summary.rs", "summary": {"lines": "invalid", "regions": None}})
        _summary, failures = floor.check_coverage_data(
            make_payload(lines_covered=980, regions_covered=980, files=files),
            fail_under_lines=99.0,
            fail_under_regions=99.0,
        )
        self.assertIn("  ... and 3 more files", failures)

    def test_rejects_rounded_up_percent_when_computed_ratio_is_below_floor(self) -> None:
        payload = make_payload(
            lines_covered=9899996,
            lines_count=10000000,
            regions_covered=1000,
            regions_count=1000,
        )
        payload["data"][0]["totals"]["lines"]["percent"] = 99.0
        _summary, failures = floor.check_coverage_data(
            payload, fail_under_lines=99.0, fail_under_regions=99.0
        )
        self.assertTrue(
            any("line coverage 98.99996% is below threshold 99.00%" in msg for msg in failures),
            failures,
        )
        self.assertFalse(any("99.0000%" in msg for msg in failures), failures)

    def test_fails_closed_on_invalid_thresholds(self) -> None:
        payload = make_payload()
        for bad in (float("nan"), float("inf"), float("-inf"), -0.1, 100.1, True):
            with self.subTest(bad_lines=bad), self.assertRaises(floor.CoverageExportError):
                floor.check_coverage_data(
                    payload, fail_under_lines=bad, fail_under_regions=99.0
                )
            with self.subTest(bad_regions=bad), self.assertRaises(floor.CoverageExportError):
                floor.check_coverage_data(
                    payload, fail_under_lines=99.0, fail_under_regions=bad
                )

    def test_fails_closed_on_malformed_or_tampered_payloads(self) -> None:
        bad_payloads = [
            [],
            {},
            {"data": []},
            {"data": [{}, {}]},
            {"data": [{}]},
            {"data": [{"totals": {"lines": {"count": 0, "covered": 0, "percent": 100.0},
                                  "regions": {"count": 10, "covered": 10, "percent": 100.0}}}]},
            {"data": [{"totals": {"lines": {"count": 10, "covered": -1, "percent": 0.0},
                                  "regions": {"count": 10, "covered": 10, "percent": 100.0}}}]},
            {"data": [{"totals": {"lines": {"count": 10, "covered": 11, "percent": 100.0},
                                  "regions": {"count": 10, "covered": 10, "percent": 100.0}}}]},
            {"data": [{"totals": {"lines": {"count": 100, "covered": 50, "percent": 99.5},
                                  "regions": {"count": 100, "covered": 100, "percent": 100.0}}}]},
            {"data": [{"totals": {"lines": {"count": 100, "covered": 100, "percent": float("nan")},
                                  "regions": {"count": 100, "covered": 100, "percent": 100.0}}}]},
            {"data": [{"totals": {"lines": {"count": 100, "covered": 100, "percent": float("inf")},
                                  "regions": {"count": 100, "covered": 100, "percent": 100.0}}}]},
            {"data": [{"totals": {"lines": {"count": True, "covered": 1, "percent": 100.0},
                                  "regions": {"count": 1, "covered": 1, "percent": 100.0}}}]},
        ]
        for payload in bad_payloads:
            with self.subTest(payload=payload), self.assertRaises(floor.CoverageExportError):
                floor.check_coverage_data(
                    payload, fail_under_lines=99.0, fail_under_regions=99.0
                )

    def test_cli_exit_codes_for_passing_failing_nan_and_missing_files(self) -> None:
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

            nan_res = subprocess.run(
                [sys.executable, str(script), "--fail-under-lines", "nan",
                 "--fail-under-regions", "99", str(passing)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(nan_res.returncode, 1)

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
