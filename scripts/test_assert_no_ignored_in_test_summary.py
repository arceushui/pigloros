#!/usr/bin/env python3
"""Contract tests for scripts/assert-no-ignored-in-test-summary.sh."""

from __future__ import annotations

import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent / "assert-no-ignored-in-test-summary.sh"

LIBTEST_CLEAN = "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
LIBTEST_IGNORED = "test result: ok. 3 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out\n"
NEXTEST_CLEAN = "     Summary [  12.3s] 4510 tests run: 4510 passed (6 slow)\n"
NEXTEST_SKIPPED = "     Summary [  12.3s] 45 tests run: 45 passed, 10 skipped\n"
NEXTEST_SKIPPED_COLOURED = (
    "\x1b[1m     Summary\x1b[0m [  12.3s] \x1b[1m45\x1b[0m tests run: "
    "\x1b[1m45\x1b[0m passed, \x1b[1m1\x1b[0m skipped\n"
)
PROSE_ONLY = "note: the word ignored; 2 ignored; appears in prose only\n"


class AssertNoIgnoredTests(unittest.TestCase):
    def run_script(self, *contents: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for index, content in enumerate(contents):
                path = pathlib.Path(directory) / f"{index}.log"
                path.write_text(content, encoding="utf-8")
                paths.append(str(path))
            return subprocess.run(
                ["bash", str(SCRIPT), *paths],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_clean_libtest_and_nextest_logs_pass(self) -> None:
        self.assertEqual(self.run_script(LIBTEST_CLEAN, NEXTEST_CLEAN).returncode, 0)

    def test_libtest_ignored_fails(self) -> None:
        result = self.run_script(LIBTEST_IGNORED)
        self.assertEqual(result.returncode, 1)
        self.assertIn("reports ignored tests", result.stderr)

    def test_nextest_skipped_fails(self) -> None:
        result = self.run_script(NEXTEST_SKIPPED)
        self.assertEqual(result.returncode, 1)
        self.assertIn("reports skipped tests", result.stderr)

    def test_coloured_nextest_skipped_fails(self) -> None:
        self.assertEqual(self.run_script(NEXTEST_SKIPPED_COLOURED).returncode, 1)

    def test_any_failing_log_fails_the_set(self) -> None:
        self.assertEqual(self.run_script(NEXTEST_CLEAN, LIBTEST_IGNORED).returncode, 1)

    def test_missing_summary_fails_closed(self) -> None:
        for content in ("", PROSE_ONLY):
            with self.subTest(content=content):
                result = self.run_script(content)
                self.assertEqual(result.returncode, 1)
                self.assertIn("no libtest or nextest summary", result.stderr)

    def test_missing_log_file_fails(self) -> None:
        result = subprocess.run(
            ["bash", str(SCRIPT), "/nonexistent/test.log"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_no_arguments_is_a_usage_error(self) -> None:
        result = subprocess.run(
            ["bash", str(SCRIPT)], capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage", result.stderr)


if __name__ == "__main__":
    unittest.main()
