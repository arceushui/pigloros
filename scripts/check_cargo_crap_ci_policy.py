#!/usr/bin/env python3
"""Validate the executable semantics of the required cargo-crap CI gate."""

from __future__ import annotations

import pathlib
import sys

import yaml


CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
INSTALL_ACTION = "taiki-e/install-action@288e746965032cfcc232e09af2daf5f23c14d780"
UPLOAD_ACTION = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
DOWNLOAD_ACTION = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
BOOTSTRAP_BASE_SHA = "45bdac85b29d273573583f846ba7acd2b3a12573"
BASELINE_RESOLVER = "scripts/resolve_cargo_crap_baseline.sh"
SCOPED_JOB_IF = (
    "${{ needs.ci_change_scope.outputs.rust == 'true' || "
    "github.event_name != 'pull_request' }}"
)
SCOPED_CARGO_CRAP_JOB_IF = (
    "${{ needs.coverage.result == 'success' && (needs.ci_change_scope.outputs.rust == 'true' || "
    "github.event_name != 'pull_request') }}"
)
GENERATE_BASELINE_COMMAND = (
    "cargo crap --workspace "
    '--lcov "${{ runner.temp }}/coverage.lcov" '
    "--missing pessimistic --jobs 2 "
    "--exclude 'tests/**' --exclude 'benches/**' --exclude 'examples/**' "
    "--format json "
    '--output "${{ runner.temp }}/cargo-crap-baseline.json"\n'
)
ANALYZE_COMMAND = (
    "cargo crap --workspace "
    '--lcov "${{ runner.temp }}/coverage.lcov" '
    "--missing pessimistic --jobs 2 "
    "--exclude 'tests/**' --exclude 'benches/**' --exclude 'examples/**' "
    '--baseline "${{ runner.temp }}/cargo-crap-baseline.json" '
    "--epsilon 0 --format json "
    '--output "${{ runner.temp }}/cargo-crap-report.json"\n'
)


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


def check_baseline_resolver() -> None:
    path = pathlib.Path(__file__).with_name("resolve_cargo_crap_baseline.sh")
    resolver = path.read_text(encoding="utf-8")
    required_fragments = (
        ("#!/usr/bin/env bash\n", "baseline resolver must be an executable Bash script"),
        ("set -euo pipefail\n", "baseline resolver must fail closed"),
        ("BASELINE_RETRY_ATTEMPTS=30\n", "baseline retry attempts changed"),
        ("BASELINE_RETRY_DELAY_SECONDS=10\n", "baseline retry delay changed"),
        (
            "for ((attempt = 1; attempt <= BASELINE_RETRY_ATTEMPTS; attempt++)); do",
            "baseline resolver must use bounded retries",
        ),
        (
            "if (( attempt < BASELINE_RETRY_ATTEMPTS )); then",
            "baseline resolver must not sleep after the final attempt",
        ),
        (
            'sleep "${BASELINE_RETRY_DELAY_SECONDS}"',
            "baseline resolver retry delay is not enforced",
        ),
        (
            'test "${BASE_SHA}" = "45bdac85b29d273573583f846ba7acd2b3a12573"',
            "baseline bootstrap is not restricted to the approved base",
        ),
        (
            'git diff --quiet "${BASE_SHA}...HEAD"',
            "baseline bootstrap must reject Rust-affecting changes",
        ),
    )
    for fragment, message in required_fragments:
        require(fragment in resolver, message)


def check_workflow(workflow_path: pathlib.Path) -> None:
    check_baseline_resolver()
    with workflow_path.open(encoding="utf-8") as stream:
        workflow = yaml.safe_load(stream)

    require(isinstance(workflow, dict), "workflow root must be a mapping")
    require(
        workflow.get("permissions") == {"actions": "read", "contents": "read"},
        "workflow must grant only the reads needed for trusted baseline artifacts",
    )
    jobs = workflow.get("jobs")
    require(isinstance(jobs, dict), "workflow jobs must be a mapping")
    coverage = jobs.get("coverage")
    require(isinstance(coverage, dict), "missing required coverage job")
    require("continue-on-error" not in coverage, "coverage job must be blocking")
    require(
        coverage.get("needs") == "ci_change_scope",
        "coverage must depend on the trusted Rust scope result",
    )
    require(
        coverage.get("if") == SCOPED_JOB_IF,
        "coverage must skip documentation-only pull requests",
    )

    coverage_steps = coverage.get("steps")
    require(isinstance(coverage_steps, list), "coverage steps must be an array")
    export = named_step(coverage_steps, "Export LCOV for cargo-crap")
    require(
        export.get("run")
        == 'cargo llvm-cov report --lcov --output-path "${{ runner.temp }}/coverage.lcov"',
        "cargo-crap must reuse the completed hosted LCOV instrumentation",
    )
    lcov_upload = named_step(coverage_steps, "Upload LCOV for cargo-crap")
    require(
        lcov_upload
        == {
            "name": "Upload LCOV for cargo-crap",
            "uses": UPLOAD_ACTION,
            "with": {
                "name": "coverage-lcov-${{ github.sha }}",
                "path": "${{ runner.temp }}/coverage.lcov",
                "retention-days": 1,
                "if-no-files-found": "error",
            },
        },
        "coverage must publish the exact required LCOV artifact",
    )

    job = jobs.get("cargo-crap")
    require(isinstance(job, dict), "missing visible cargo-crap job")
    require(
        set(job)
        == {"name", "needs", "if", "runs-on", "timeout-minutes", "steps"},
        "cargo-crap job metadata or execution controls changed",
    )
    require(job.get("name") == "cargo-crap", "cargo-crap check name changed")
    require(
        job.get("needs") == ["ci_change_scope", "coverage"],
        "cargo-crap must depend on the trusted scope result and coverage",
    )
    require(
        job.get("if") == SCOPED_CARGO_CRAP_JOB_IF,
        "cargo-crap must skip documentation-only pull requests",
    )
    require(job.get("runs-on") == "ubuntu-latest", "cargo-crap runner changed")
    require(job.get("timeout-minutes") == 10, "cargo-crap timeout changed")
    steps = job.get("steps")
    require(isinstance(steps, list), "cargo-crap steps must be an array")
    require(len(steps) == 12, "cargo-crap must contain the exact trusted step sequence")

    require(
        steps[0] == {"uses": CHECKOUT_ACTION, "with": {"fetch-depth": 0}},
        "cargo-crap must start with a full pinned checkout",
    )
    install = named_step(steps, "Install cargo-crap")
    require(
        install
        == {
            "name": "Install cargo-crap",
            "uses": INSTALL_ACTION,
            "with": {"tool": "cargo-crap@0.2.2"},
        },
        "cargo-crap installation changed",
    )
    require(
        named_step(steps, "Download hosted LCOV")
        == {
            "name": "Download hosted LCOV",
            "uses": DOWNLOAD_ACTION,
            "with": {
                "name": "coverage-lcov-${{ github.sha }}",
                "path": "${{ runner.temp }}",
            },
        },
        "cargo-crap must download the exact hosted LCOV artifact",
    )
    require(
        named_step(steps, "Reject repository cargo-crap configuration")
        == {
            "name": "Reject repository cargo-crap configuration",
            "run": "test ! -e .cargo-crap.toml",
        },
        "repository cargo-crap configuration must be rejected",
    )

    require(
        named_step(steps, "Resolve trusted cargo-crap baseline")
        == {
            "name": "Resolve trusted cargo-crap baseline",
            "id": "baseline",
            "env": {
                "BASE_SHA": "${{ github.event.pull_request.base.sha }}",
                "EVENT_NAME": "${{ github.event_name }}",
                "GH_TOKEN": "${{ github.token }}",
            },
            "run": BASELINE_RESOLVER,
        },
        "trusted baseline resolution changed",
    )
    require(
        named_step(steps, "Download trusted base baseline")
        == {
            "name": "Download trusted base baseline",
            "if": "${{ steps.baseline.outputs.run-id != '' }}",
            "uses": DOWNLOAD_ACTION,
            "with": {
                "name": "cargo-crap-baseline-${{ github.event.pull_request.base.sha }}",
                "path": "${{ runner.temp }}",
                "github-token": "${{ github.token }}",
                "repository": "${{ github.repository }}",
                "run-id": "${{ steps.baseline.outputs.run-id }}",
            },
        },
        "trusted base artifact download changed",
    )
    require(
        named_step(steps, "Generate trusted current baseline")
        == {
            "name": "Generate trusted current baseline",
            "if": "${{ steps.baseline.outputs.bootstrap == 'true' }}",
            "run": GENERATE_BASELINE_COMMAND,
        },
        "trusted current baseline generation changed",
    )
    require(
        named_step(steps, "Analyze CRAP score changes")
        == {"name": "Analyze CRAP score changes", "run": ANALYZE_COMMAND},
        "cargo-crap analysis command changed",
    )
    require(
        named_step(steps, "Enforce cargo-crap policy")
        == {
            "name": "Enforce cargo-crap policy",
            "run": (
                "python scripts/check_cargo_crap_report.py "
                '"${{ runner.temp }}/cargo-crap-report.json"'
            ),
        },
        "cargo-crap policy verdict must be an unconditional blocking step",
    )
    report_upload = named_step(steps, "Upload cargo-crap report")
    require(
        report_upload.get("if") == "${{ always() }}"
        and report_upload.get("uses") == UPLOAD_ACTION
        and report_upload.get("with", {}).get("path")
        == "${{ runner.temp }}/cargo-crap-report.json",
        "cargo-crap report must always upload through the pinned Action",
    )
    require(
        named_step(steps, "Publish trusted main baseline")
        == {
            "name": "Publish trusted main baseline",
            "if": (
                "${{ github.event_name != 'pull_request' && "
                "github.ref == 'refs/heads/main' }}"
            ),
            "uses": UPLOAD_ACTION,
            "with": {
                "name": "cargo-crap-baseline-${{ github.sha }}",
                "path": "${{ runner.temp }}/cargo-crap-baseline.json",
                "retention-days": 90,
                "if-no-files-found": "error",
            },
        },
        "green main must publish the next trusted baseline",
    )

    aggregate = jobs.get("ci-gate")
    require(isinstance(aggregate, dict), "missing aggregate ci-gate")
    require("cargo-crap" in aggregate.get("needs", []), "ci-gate must need cargo-crap")
    aggregate_steps = aggregate.get("steps")
    require(isinstance(aggregate_steps, list), "ci-gate steps must be an array")
    verdict = named_step(aggregate_steps, "Require every blocking CI job to pass")
    require(
        verdict.get("env", {}).get("CARGO_CRAP_RESULT")
        == "${{ needs.cargo-crap.result }}",
        "ci-gate must read the cargo-crap result",
    )
    require(
        "CARGO_CRAP_RESULT" in verdict.get("run", ""),
        "ci-gate must reject a non-success cargo-crap result",
    )


def main() -> int:
    root = pathlib.Path(__file__).resolve().parent.parent
    path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else root / ".github/workflows/ci.yml"
    try:
        check_workflow(path)
        require(
            not (root / ".cargo-crap-baseline.json").exists(),
            "static repository cargo-crap baseline is not allowed",
        )
    except (OSError, yaml.YAMLError, PolicyError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("==> cargo-crap CI policy OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
