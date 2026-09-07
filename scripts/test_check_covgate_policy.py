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
    def run_checker(
        self, version: str, repository: pathlib.Path = ROOT, base: str | None = None
    ) -> subprocess.CompletedProcess[str]:
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
            if base is None:
                base = self.git_output(repository, "rev-parse", "HEAD")
            return subprocess.run(
                [str(CHECKER), base],
                cwd=repository,
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

    def test_malformed_current_policy_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository, base = self.policy_repository(pathlib.Path(directory))
            (repository / "covgate.toml").write_text("not a policy\n", encoding="utf-8")

            result = self.run_checker("covgate 0.2.0", repository, base)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("immutable 99%", result.stderr)

    def test_policy_changed_since_base_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = pathlib.Path(directory)
            self.run_git(repository, "init", "-q")
            self.run_git(repository, "config", "user.email", "coverage-test@example.invalid")
            self.run_git(repository, "config", "user.name", "coverage-test")
            (repository / "covgate.toml").write_text(
                "[[gates]]\n"
                'name = "new-rust-code"\n'
                "fail-under-lines = 98\n"
                "fail-under-regions = 99",
                encoding="utf-8",
            )
            self.run_git(repository, "add", "covgate.toml")
            self.run_git(repository, "commit", "-qm", "old policy")
            base = self.git_output(repository, "rev-parse", "HEAD")
            (repository / "covgate.toml").write_text(
                (ROOT / "covgate.toml").read_text(encoding="utf-8"), encoding="utf-8"
            )
            self.run_git(repository, "add", "covgate.toml")
            self.run_git(repository, "commit", "-qm", "current policy")

            result = self.run_checker("covgate 0.2.0", repository, base)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("changed after the policy was established", result.stderr)

    def policy_repository(self, repository: pathlib.Path) -> tuple[pathlib.Path, str]:
        self.run_git(repository, "init", "-q")
        self.run_git(repository, "config", "user.email", "coverage-test@example.invalid")
        self.run_git(repository, "config", "user.name", "coverage-test")
        (repository / "covgate.toml").write_text(
            (ROOT / "covgate.toml").read_text(encoding="utf-8"), encoding="utf-8"
        )
        self.run_git(repository, "add", "covgate.toml")
        self.run_git(repository, "commit", "-qm", "policy")
        return repository, self.git_output(repository, "rev-parse", "HEAD")

    @staticmethod
    def run_git(repository: pathlib.Path, *arguments: str) -> None:
        result = subprocess.run(
            ["git", *arguments], cwd=repository, capture_output=True, text=True, check=False
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr)

    @staticmethod
    def git_output(repository: pathlib.Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", *arguments], cwd=repository, capture_output=True, text=True, check=False
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr)
        return result.stdout.strip()


if __name__ == "__main__":
    unittest.main()
