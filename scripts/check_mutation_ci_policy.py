#!/usr/bin/env python3
"""Validate that the diff mutation gate runs mutants on its pinned nightly."""

from __future__ import annotations

import argparse
import pathlib
import sys

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOLCHAIN_ACTION = "dtolnay/rust-toolchain@"


class PolicyError(RuntimeError):
    """The mutation workflow can report mutants as caught without testing them."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def check_workflow(path: pathlib.Path) -> None:
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    job = workflow.get("jobs", {}).get("mutation")
    require(isinstance(job, dict), "mutation workflow must define the mutation job")
    steps = job.get("steps", [])

    toolchains = [
        step.get("with", {}).get("toolchain")
        for step in steps
        if str(step.get("uses", "")).startswith(TOOLCHAIN_ACTION)
    ]
    require(len(toolchains) == 1, "mutation job must install exactly one toolchain")
    toolchain = toolchains[0]
    require(
        isinstance(toolchain, str) and toolchain.startswith("nightly-"),
        "mutation job must install a dated nightly for the -Z harness arguments",
    )
    # rust-toolchain.toml outranks `rustup default`; only the environment
    # variable makes the installed nightly the one cargo-mutants runs.
    require(
        job.get("env", {}).get("RUSTUP_TOOLCHAIN") == toolchain,
        "mutation job must set RUSTUP_TOOLCHAIN to its installed nightly",
    )

    runs = [str(step.get("run", "")) for step in steps]
    mutants = [index for index, run in enumerate(runs) if "cargo mutants" in run]
    require(len(mutants) == 1, "mutation job must run cargo mutants exactly once")
    guards = [
        index
        for index, run in enumerate(runs)
        if "rustup show active-toolchain" in run
        and f'[[ "$active" == {toolchain}-* ]]' in run
        and "rustc --version | grep -q -- '-nightly '" in run
    ]
    require(
        len(guards) == 1 and guards[0] < mutants[0],
        "mutation job must prove the active nightly before running mutants",
    )
    require(
        "-Zunstable-options" in runs[mutants[0]],
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
