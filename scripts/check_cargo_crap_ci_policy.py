#!/usr/bin/env python3
"""Validate that the hosted coverage job enforces the cargo-crap policy."""

from __future__ import annotations

import pathlib
import sys

import yaml


INSTALL_ACTION = "taiki-e/install-action@288e746965032cfcc232e09af2daf5f23c14d780"
UPLOAD_ACTION = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
REQUIRED_ANALYSIS_ARGUMENTS = {
    "cargo crap --workspace",
    '--lcov "${{ runner.temp }}/coverage.lcov"',
    "--missing pessimistic",
    "--jobs 2",
    "--exclude 'tests/**'",
    "--exclude 'benches/**'",
    "--exclude 'examples/**'",
    '--baseline "${{ runner.temp }}/cargo-crap-baseline.json"',
    "--epsilon 0.01",
    "--format json",
    '--output "${{ runner.temp }}/cargo-crap-report.json"',
}


class PolicyError(RuntimeError):
    """The workflow does not provide the required cargo-crap gate."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def named_step(steps: list[object], name: str) -> dict:
    matches = [
        step for step in steps if isinstance(step, dict) and step.get("name") == name
    ]
    require(len(matches) == 1, f"expected exactly one {name!r} step")
    return matches[0]


def check_workflow(workflow_path: pathlib.Path) -> None:
    with workflow_path.open(encoding="utf-8") as stream:
        workflow = yaml.safe_load(stream)

    require(isinstance(workflow, dict), "workflow root must be a mapping")
    jobs = workflow.get("jobs")
    require(isinstance(jobs, dict), "workflow jobs must be a mapping")
    coverage = jobs.get("coverage")
    require(isinstance(coverage, dict), "missing required coverage job")
    require("continue-on-error" not in coverage, "coverage job must be blocking")
    require("if" not in coverage, "coverage job must be unconditional")

    steps = coverage.get("steps")
    require(isinstance(steps, list), "coverage steps must be an array")
    checkout = steps[0] if steps else None
    require(isinstance(checkout, dict), "coverage must start with checkout")
    require(
        checkout.get("with", {}).get("fetch-depth") == 0,
        "coverage checkout must fetch the pull-request base baseline",
    )

    install = named_step(steps, "Install cargo-crap")
    require(install.get("uses") == INSTALL_ACTION, "cargo-crap installer must be pinned")
    require(
        install.get("with") == {"tool": "cargo-crap@0.2.2"},
        "cargo-crap version or installer inputs changed",
    )

    export = named_step(steps, "Export LCOV for cargo-crap")
    require(
        export.get("run")
        == 'cargo llvm-cov report --lcov --output-path "${{ runner.temp }}/coverage.lcov"',
        "cargo-crap must reuse the completed hosted LCOV instrumentation",
    )

    baseline = named_step(steps, "Select trusted cargo-crap baseline")
    baseline_command = baseline.get("run")
    require(isinstance(baseline_command, str), "baseline selection must be a command")
    for fragment in (
        'git cat-file -e "${BASE_SHA}:.cargo-crap-baseline.json"',
        'git show "${BASE_SHA}:.cargo-crap-baseline.json"',
        'git diff --quiet "${BASE_SHA}...HEAD"',
        "'*.rs' Cargo.toml Cargo.lock rust-toolchain.toml",
        'cp .cargo-crap-baseline.json "${baseline}"',
    ):
        require(fragment in baseline_command, f"baseline selection is missing {fragment!r}")
    require(
        baseline.get("env")
        == {
            "BASE_SHA": "${{ github.event.pull_request.base.sha }}",
            "EVENT_NAME": "${{ github.event_name }}",
        },
        "baseline selection event inputs changed",
    )

    analyze = named_step(steps, "Analyze CRAP score changes")
    command = analyze.get("run")
    require(isinstance(command, str), "cargo-crap analysis must be a command")
    for argument in REQUIRED_ANALYSIS_ARGUMENTS:
        require(argument in command, f"cargo-crap analysis is missing {argument!r}")
    require("continue-on-error" not in analyze, "cargo-crap analysis must be blocking")
    require("if" not in analyze, "cargo-crap analysis must be unconditional")

    gate = named_step(steps, "Enforce cargo-crap policy")
    require(
        gate == {
            "name": "Enforce cargo-crap policy",
            "run": (
                "python scripts/check_cargo_crap_report.py "
                '"${{ runner.temp }}/cargo-crap-report.json"'
            ),
        },
        "cargo-crap policy verdict must be an unconditional blocking step",
    )

    upload = named_step(steps, "Upload cargo-crap report")
    require(upload.get("if") == "${{ always() }}", "cargo-crap report must always upload")
    require(upload.get("uses") == UPLOAD_ACTION, "report upload Action must be pinned")
    require(
        upload.get("with", {}).get("path")
        == "${{ runner.temp }}/cargo-crap-report.json",
        "report artifact path changed",
    )


def main() -> int:
    root = pathlib.Path(__file__).resolve().parent.parent
    path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else root / ".github/workflows/ci.yml"
    try:
        check_workflow(path)
    except (OSError, yaml.YAMLError, PolicyError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("==> cargo-crap CI policy OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
