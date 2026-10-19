#!/usr/bin/env python3
"""Validate that the diff mutation gate runs mutants on its pinned nightly."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOLCHAIN_ACTION = "dtolnay/rust-toolchain@"
DATED_NIGHTLY = re.compile(r"nightly-\d{4}-\d{2}-\d{2}")
HARNESS_ARGUMENTS = ("-Zunstable-options", "--fail-fast")


class PolicyError(RuntimeError):
    """The mutation workflow can report mutants as caught without testing them."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def mapping(value: object) -> dict:
    """Read an optional YAML mapping; an empty key (`env:`) is None."""
    if value is None:
        return {}
    require(isinstance(value, dict), "mutation workflow keys must be mappings")
    return value


def live_lines(run: str) -> list[str]:
    """Return the stripped shell lines that execute, without comments or blanks."""
    lines = (line.strip() for line in run.splitlines())
    return [line for line in lines if line and not line.startswith("#")]


def guard_lines(toolchain: str) -> list[str]:
    return [
        "set -euo pipefail",
        'active="$(rustup show active-toolchain)"',
        'echo "$active"',
        f'[[ "$active" == {toolchain}-* ]]',
        "rustc --version | grep -q -- '-nightly '",
    ]


def check_workflow(path: pathlib.Path) -> None:
    workflow = mapping(yaml.safe_load(path.read_text(encoding="utf-8")))
    job = mapping(workflow.get("jobs")).get("mutation")
    require(isinstance(job, dict), "mutation workflow must define the mutation job")
    steps = job.get("steps") or []
    require(isinstance(steps, list), "mutation job steps must be a list")
    steps = [mapping(step) for step in steps]

    toolchains = [
        mapping(step.get("with")).get("toolchain")
        for step in steps
        if str(step.get("uses", "")).startswith(TOOLCHAIN_ACTION)
    ]
    require(len(toolchains) == 1, "mutation job must install exactly one toolchain")
    toolchain = toolchains[0]
    require(
        isinstance(toolchain, str) and DATED_NIGHTLY.fullmatch(toolchain) is not None,
        "mutation job must install a dated nightly for the -Z harness arguments",
    )
    # rust-toolchain.toml outranks `rustup default`; only the environment
    # variable makes the installed nightly the one cargo-mutants runs.
    require(
        mapping(job.get("env")).get("RUSTUP_TOOLCHAIN") == toolchain,
        "mutation job must set RUSTUP_TOOLCHAIN to its installed nightly",
    )
    for step in steps:
        require(
            "RUSTUP_TOOLCHAIN" not in mapping(step.get("env")),
            "mutation steps must not override the job RUSTUP_TOOLCHAIN",
        )

    runs = [live_lines(str(step.get("run", ""))) for step in steps]
    mutants = [
        index
        for index, lines in enumerate(runs)
        if any("cargo mutants" in line for line in lines)
    ]
    require(len(mutants) == 1, "mutation job must run cargo mutants exactly once")
    mutant_lines = runs[mutants[0]]
    require(
        not any(re.search(r"\bcargo \+", line) for line in mutant_lines),
        "cargo mutants must not select a toolchain with +toolchain",
    )
    guards = [index for index, lines in enumerate(runs) if lines == guard_lines(toolchain)]
    require(
        len(guards) == 1 and guards[0] < mutants[0],
        "mutation job must prove the active nightly before running mutants",
    )
    for argument in HARNESS_ARGUMENTS:
        require(
            any(argument in line.split() for line in mutant_lines),
            "mutation harness arguments changed; review this policy with them",
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--workflow", type=pathlib.Path, default=ROOT / ".github/workflows/mutation.yml"
    )
    args = parser.parse_args()
    try:
        check_workflow(args.workflow)
    except PolicyError as error:
        print(f"{args.workflow}: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
