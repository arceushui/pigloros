#!/usr/bin/env python3
"""Adversarial tests for the pinned covgate policy checker."""

from __future__ import annotations

import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts" / "check-covgate-policy.sh"


class CovgatePolicyTests(unittest.TestCase):
    def run_checker(self, version: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = pathlib.Path(directory) / "bin"
            bin_dir.mkdir()
            fake_covgate = bin_dir / "covgate"
            fake_covgate.write_text(
                f"#!/usr/bin/env bash\nprintf '%s\\n' {version!r}\n", encoding="utf-8"
            )
            fake_covgate.chmod(0o755)
            environment = os.environ.copy()
            environment["PATH"] = f"{bin_dir}:{environment['PATH']}"
            base = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            return subprocess.run(
                [str(CHECKER), base],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

    def test_exact_version_passes(self) -> None:
        result = self.run_checker("covgate 0.2.0")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_different_version_fails_closed(self) -> None:
        result = self.run_checker("covgate 0.2.1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("covgate 0.2.0", result.stderr)


if __name__ == "__main__":
    unittest.main()
