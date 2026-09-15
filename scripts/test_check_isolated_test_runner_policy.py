#!/usr/bin/env python3
"""Adversarial tests for the generic isolated-runner policy checker."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts/check_isolated_test_runner_policy.py"
FIXTURES = (
    Path(".github/workflows/ci.yml"),
    Path(".github/workflows/mutation.yml"),
    Path("crates/pos-reference/src/root_selector.rs"),
    Path("scripts/run-isolated-root-selector-test.sh"),
)


def invoke(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--root", str(root)],
        check=False,
        capture_output=True,
        text=True,
    )


def copy_fixture(root: Path) -> None:
    for relative in FIXTURES:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)


def main() -> None:
    baseline = invoke(ROOT)
    if baseline.returncode != 0:
        raise SystemExit(baseline.stderr or baseline.stdout)

    mutations = (
        (
            Path(".github/workflows/ci.yml"),
            "name: cargo test with ASan",
            "name: reduced sanitizer test",
        ),
        (
            Path(".github/workflows/mutation.yml"),
            "cargo mutants",
            "cargo test",
        ),
        (
            Path("crates/pos-reference/src/root_selector.rs"),
            "run-isolated-root-selector-test.sh",
            "missing-isolated-runner.sh",
        ),
        (
            Path("scripts/run-isolated-root-selector-test.sh"),
            "unshare --user --map-root-user --mount --fork --propagation private",
            "unshare --mount --fork --propagation private",
        ),
        (
            Path("scripts/run-isolated-root-selector-test.sh"),
            "timeout --signal=TERM --kill-after=5s 30s",
            "timeout 30s",
        ),
        (
            Path("scripts/run-isolated-root-selector-test.sh"),
            "exec timeout",
            "sudo -n timeout",
        ),
        (
            Path("scripts/run-isolated-root-selector-test.sh"),
            "mount --make-rprivate /",
            "rm -rf /run",
        ),
    )
    with tempfile.TemporaryDirectory() as directory:
        temporary = Path(directory)
        for index, (relative, old, new) in enumerate(mutations):
            fixture_root = temporary / str(index)
            copy_fixture(fixture_root)
            target = fixture_root / relative
            text = target.read_text(encoding="utf-8")
            if old not in text:
                raise SystemExit(f"fixture fragment missing in {relative}: {old}")
            target.write_text(text.replace(old, new, 1), encoding="utf-8")
            if invoke(fixture_root).returncode == 0:
                raise SystemExit(f"checker accepted invalid {relative}: {old}")


if __name__ == "__main__":
    main()
