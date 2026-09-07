#!/usr/bin/env python3
"""Adversarial contract tests for the Rust LLVM coverage presence guard."""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts" / "check-rust-coverage-report.sh"


def run(command: list[str], cwd: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, check=False, text=True, capture_output=True)


class RustCoverageReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.temp_dir.name)
        run(["git", "init", "-q"], self.repo)
        run(["git", "config", "user.email", "coverage-test@example.invalid"], self.repo)
        run(["git", "config", "user.name", "coverage-test"], self.repo)
        source = self.repo / "src" / "lib.rs"
        source.parent.mkdir()
        source.write_text("pub fn value() -> u8 { 1 }\n", encoding="utf-8")
        run(["git", "add", "src/lib.rs"], self.repo)
        self.assertEqual(run(["git", "commit", "-qm", "base"], self.repo).returncode, 0)
        source.write_text("pub fn value() -> u8 { 2 }\n", encoding="utf-8")
        run(["git", "add", "src/lib.rs"], self.repo)
        self.assertEqual(run(["git", "commit", "-qm", "change"], self.repo).returncode, 0)
        self.base = run(["git", "rev-parse", "HEAD^"], self.repo).stdout.strip()
        self.report = self.repo / "coverage.json"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def write_report(self, segments: list[list[object]], path: pathlib.Path | None = None) -> None:
        report_path = path or (self.repo / "src" / "lib.rs")
        self.report.write_text(
            json.dumps(
                {
                    "data": [
                        {
                            "files": [
                                {
                                    "filename": str(report_path),
                                    "segments": segments,
                                }
                            ]
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

    def check(self) -> subprocess.CompletedProcess[str]:
        return run([str(CHECKER), str(self.report), self.base], self.repo)

    def test_missing_file_fails_closed(self) -> None:
        self.report.write_text('{"data": []}\n', encoding="utf-8")
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("src/lib.rs", result.stderr)

    def test_non_total_segment_entry_fails_closed(self) -> None:
        self.write_report([[1, 1, 0, True, True, False]])
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("src/lib.rs", result.stderr)

    def test_positive_line_and_region_totals_pass(self) -> None:
        self.write_report(
            [
                [1, 1, 1, True, True, False],
                [2, 1, 1, True, True, False],
            ]
        )
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unstaged_change_is_checked_against_current_head(self) -> None:
        source = self.repo / "src" / "lib.rs"
        source.write_text("pub fn value() -> u8 { 3 }\n", encoding="utf-8")
        self.base = run(["git", "rev-parse", "HEAD"], self.repo).stdout.strip()
        self.report.write_text('{"data": []}\n', encoding="utf-8")
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("src/lib.rs", result.stderr)

    def test_staged_change_is_checked_against_current_head(self) -> None:
        source = self.repo / "src" / "lib.rs"
        source.write_text("pub fn value() -> u8 { 4 }\n", encoding="utf-8")
        run(["git", "add", "src/lib.rs"], self.repo)
        self.base = run(["git", "rev-parse", "HEAD"], self.repo).stdout.strip()
        self.report.write_text('{"data": []}\n', encoding="utf-8")
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("src/lib.rs", result.stderr)

    def test_similarly_named_path_does_not_satisfy_changed_file(self) -> None:
        self.write_report(
            [
                [1, 1, 1, True, True, False],
                [2, 1, 1, True, True, False],
            ],
            self.repo / "other" / "src" / "lib.rs",
        )
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("src/lib.rs", result.stderr)


if __name__ == "__main__":
    unittest.main()
