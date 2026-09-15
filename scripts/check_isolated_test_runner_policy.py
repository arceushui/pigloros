#!/usr/bin/env python3
"""Enforce the repository contract for delegated isolated test runners."""

from __future__ import annotations

import argparse
import re
import stat
from pathlib import Path


def require(text: str, fragment: str, source: Path) -> None:
    if fragment not in text:
        raise SystemExit(f"{source}: missing required policy fragment: {fragment}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    root = args.root.resolve()
    workflow_path = root / ".github/workflows/ci.yml"
    mutation_path = root / ".github/workflows/mutation.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    mutation_workflow = mutation_path.read_text(encoding="utf-8")

    for fragment in (
        "python scripts/check_isolated_test_runner_policy.py",
        "python scripts/test_check_isolated_test_runner_policy.py",
        "cargo test --workspace --all-features --locked -- --include-ignored",
        "cargo llvm-cov --workspace --all-features --locked",
        "name: cargo test with ASan",
        "uses: ./.github/workflows/mutation.yml",
    ):
        require(workflow, fragment, workflow_path)
    require(mutation_workflow, "cargo mutants", mutation_path)

    runners = sorted((root / "scripts").glob("run-isolated*-test.sh"))
    if not runners:
        raise SystemExit("no delegated isolated test runners were discovered")
    rust_sources = {
        source: source.read_text(encoding="utf-8")
        for source in (root / "crates").glob("**/*.rs")
    }

    for runner_path in runners:
        runner = runner_path.read_text(encoding="utf-8")
        if not runner_path.stat().st_mode & stat.S_IXUSR:
            raise SystemExit(f"{runner_path}: isolated test runner must be executable")
        if re.search(r"\bsudo\b", runner):
            raise SystemExit(f"{runner_path}: ambient sudo is forbidden")
        if re.search(r"\brm\s+-[^\n]*r", runner):
            raise SystemExit(f"{runner_path}: recursive host-path deletion is forbidden")
        for fragment in (
            "set -euo pipefail",
            "[[ $# -ne 2 ]]",
            "timeout --signal=TERM --kill-after=5s 30s",
            "unshare --user --map-root-user --mount --fork --propagation private",
            "mount --make-rprivate /",
            "export PIGLOROS_TEST_BINARY=$1",
            "export PIGLOROS_TEST_NAME=$2",
            'exec "$PIGLOROS_TEST_BINARY" --exact "$PIGLOROS_TEST_NAME" --nocapture',
        ):
            require(runner, fragment, runner_path)

        owners = [
            (source, text)
            for source, text in rust_sources.items()
            if runner_path.name in text
        ]
        if not owners:
            raise SystemExit(f"{runner_path}: no Rust test self-locates this runner")
        for source, text in owners:
            require(text, 'env!("CARGO_MANIFEST_DIR")', source)
            require(text, f'join("../../scripts/{runner_path.name}")', source)
            require(text, '.arg(std::env::current_exe()?)', source)
            if re.search(r"PIGLOROS_[A-Z0-9_]*RUNNER", text):
                raise SystemExit(f"{source}: isolated runner selection must not be optional")


if __name__ == "__main__":
    main()
