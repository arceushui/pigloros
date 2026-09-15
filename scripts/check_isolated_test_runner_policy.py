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
        if re.search(r"(?m)(?:^[ \t]*|[;&|][ \t]*)rm[ \t]+-[^\n]*r", runner):
            raise SystemExit(f"{runner_path}: recursive host-path deletion is forbidden")
        if not re.search(
            r"readonly ISOLATION_IMAGE='[^']+@sha256:[0-9a-f]{64}'", runner
        ):
            raise SystemExit(f"{runner_path}: isolation image must be digest-pinned")
        for fragment in (
            "set -euo pipefail",
            "[[ $# -ne 2 ]]",
            "timeout --signal=TERM --kill-after=5s 30s",
            "docker run",
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--pids-limit 256",
            "--tmpfs /tmp:rw,nosuid,nodev,mode=1777",
            "--tmpfs /var/lib:rw,nosuid,nodev,mode=0755",
            "--tmpfs /run:rw,nosuid,nodev,mode=0755",
            'source=$REPOSITORY_ROOT,target=$REPOSITORY_ROOT,readonly',
            '"$REPOSITORY_ROOT"/target/*',
            '"$TEST_BINARY" --exact "$TEST_NAME" --nocapture',
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
