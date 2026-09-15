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
RUNNERS = tuple(sorted((ROOT / "scripts").glob("run-isolated*-test.sh")))
if not RUNNERS:
    raise SystemExit("no delegated isolated test runners were discovered")
RUNNER_PATHS = tuple(path.relative_to(ROOT) for path in RUNNERS)
OWNER_PATHS = tuple(
    source.relative_to(ROOT)
    for source in sorted((ROOT / "crates").glob("**/*.rs"))
    if any(runner.name in source.read_text(encoding="utf-8") for runner in RUNNERS)
)
if not OWNER_PATHS:
    raise SystemExit("no Rust owners of delegated isolated test runners were discovered")
FIXTURES = (
    Path(".github/workflows/ci.yml"),
    Path(".github/workflows/mutation.yml"),
    *OWNER_PATHS,
    *RUNNER_PATHS,
)
PRIMARY_OWNER = OWNER_PATHS[0]
PRIMARY_RUNNER = RUNNER_PATHS[0]


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
            PRIMARY_OWNER,
            PRIMARY_RUNNER.name,
            "missing-isolated-runner.sh",
        ),
        (
            PRIMARY_RUNNER,
            "--network none",
            "--network host",
        ),
        (
            PRIMARY_RUNNER,
            "timeout --signal=TERM --kill-after=5s 30s",
            "timeout 30s",
        ),
        (
            PRIMARY_RUNNER,
            "exec timeout",
            "sudo -n timeout",
        ),
        (
            PRIMARY_RUNNER,
            "--tmpfs /run:rw,nosuid,nodev,mode=0755",
            "rm -rf /run",
        ),
        (
            PRIMARY_RUNNER,
            "--read-only",
            "--read-write",
        ),
        (
            PRIMARY_RUNNER,
            "--cap-drop ALL",
            "--cap-drop NET_ADMIN",
        ),
        (
            PRIMARY_RUNNER,
            "@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254",
            ":latest",
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
