#!/usr/bin/env python3
"""Validate the blocking GitHub Actions new-code coverage policy."""

from __future__ import annotations

import pathlib
import sys

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
INSTALL_ACTION = "taiki-e/install-action@288e746965032cfcc232e09af2daf5f23c14d780"
SETUP_PYTHON_ACTION = "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1"
SCOPED_JOB_IF = (
    "${{ needs.ci_change_scope.outputs.rust == 'true' || "
    "github.event_name != 'pull_request' }}"
)
BASE_REF = (
    "${{ github.event_name == 'pull_request' && "
    "github.event.pull_request.base.sha || github.event.before }}"
)


class PolicyError(RuntimeError):
    """The workflow does not provide the required new-code coverage policy."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def named_step(steps: list[object], name: str) -> dict:
    matches = [
        step for step in steps if isinstance(step, dict) and step.get("name") == name
    ]
    require(len(matches) == 1, f"expected exactly one {name!r} step")
    return matches[0]


def check_workflow(workflow_path: pathlib.Path = ROOT / ".github/workflows/ci.yml") -> None:
    with workflow_path.open(encoding="utf-8") as stream:
        workflow = yaml.safe_load(stream)

    require(isinstance(workflow, dict), "workflow root must be a mapping")
    jobs = workflow.get("jobs")
    require(isinstance(jobs, dict), "workflow jobs must be a mapping")

    coverage = jobs.get("coverage")
    require(isinstance(coverage, dict), "missing coverage job")
    require("continue-on-error" not in coverage, "coverage job must be blocking")
    require(coverage.get("needs") == "ci_change_scope", "coverage scope dependency changed")
    require(coverage.get("if") == SCOPED_JOB_IF, "coverage scope condition changed")
    coverage_steps = coverage.get("steps")
    require(isinstance(coverage_steps, list), "coverage steps must be a list")

    require(
        coverage_steps[0]
        == {
            "uses": CHECKOUT_ACTION,
            "with": {"fetch-depth": 0, "persist-credentials": False},
        },
        "coverage must use a full checkout without persisted credentials",
    )
    require(
        named_step(coverage_steps, "Install covgate")
        == {
            "name": "Install covgate",
            "uses": INSTALL_ACTION,
            "with": {"tool": "covgate@0.2.0"},
        },
        "covgate must remain pinned to 0.2.0",
    )
    require(
        named_step(coverage_steps, "Resolve new-code coverage base")
        == {
            "name": "Resolve new-code coverage base",
            "id": "coverage-base",
            "env": {"BASE_REF": BASE_REF},
            "run": (
                'set -euo pipefail\n'
                'base_ref="${BASE_REF}"\n'
                'resolved_base_ref="$(bash scripts/resolve-coverage-base.sh "${base_ref}")"\n'
                'echo "base_ref=${resolved_base_ref}" >> "${GITHUB_OUTPUT}"\n'
            ),
        },
        "coverage base must be resolved once through the shared script",
    )
    require(
        named_step(coverage_steps, "Enforce immutable new-code coverage policy")
        == {
            "name": "Enforce immutable new-code coverage policy",
            "run": "bash scripts/check-covgate-policy.sh \"${{ steps.coverage-base.outputs.base_ref }}\"",
        },
        "coverage policy must use the shared immutable policy checker",
    )
    require(
        named_step(coverage_steps, "cargo llvm-cov (lines ≥99%, regions ≥99%)")["run"]
        == (
            "cargo llvm-cov --workspace --all-features --locked --summary-only "
            "--show-missing-lines --fail-under-lines 99 --fail-under-regions 99 "
            "-- --include-ignored\n"
        ),
        "repository-wide coverage gate changed",
    )
    require(
        named_step(coverage_steps, "Export coverage details for new-code gate")
        == {
            "name": "Export coverage details for new-code gate",
            "if": "always()",
            "continue-on-error": True,
            "run": 'cargo llvm-cov report --json --output-path "${{ runner.temp }}/coverage.json"',
        },
        "coverage JSON export must remain diagnostic and always attempted",
    )
    require(
        named_step(coverage_steps, "Reject changed Rust files missing from coverage")
        == {
            "name": "Reject changed Rust files missing from coverage",
            "if": "${{ success() }}",
            "run": 'bash scripts/check-rust-coverage-report.sh "${RUNNER_TEMP}/coverage.json" "${{ steps.coverage-base.outputs.base_ref }}"',
        },
        "changed-file coverage guard must be a blocking shared-script step",
    )
    require(
        named_step(coverage_steps, "Enforce new Rust code coverage (lines ≥99%, regions ≥99%)")
        == {
            "name": "Enforce new Rust code coverage (lines ≥99%, regions ≥99%)",
            "if": "${{ success() }}",
            "run": 'covgate check "${RUNNER_TEMP}/coverage.json" --base "${{ steps.coverage-base.outputs.base_ref }}" --no-github-summary',
        },
        "covgate must remain a blocking step using the resolved base",
    )
    require(
        named_step(coverage_steps, "Upload coverage details")
        == {
            "name": "Upload coverage details",
            "if": "always()",
            "uses": "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            "with": {
                "name": "coverage-details",
                "path": "${{ runner.temp }}/coverage.json",
                "if-no-files-found": "ignore",
            },
        },
        "coverage diagnostics must remain available",
    )

    policy_job = jobs.get("new-code-coverage-policy")
    require(isinstance(policy_job, dict), "missing blocking coverage policy job")
    require("continue-on-error" not in policy_job, "coverage policy job must be blocking")
    require(policy_job.get("needs") == "ci_change_scope", "policy job scope dependency changed")
    require(policy_job.get("if") == SCOPED_JOB_IF, "policy job scope condition changed")
    policy_steps = policy_job.get("steps")
    require(isinstance(policy_steps, list), "policy job steps must be a list")
    require(
        policy_steps[0] == {"uses": CHECKOUT_ACTION},
        "policy job checkout changed",
    )
    require(
        policy_steps[1]
        == {
            "uses": SETUP_PYTHON_ACTION,
            "with": {"python-version": 3.12},
        },
        "policy job Python setup changed",
    )
    require(
        policy_steps[2]
        == {
            "name": "Install pinned dependency checker",
            "run": (
                "python -m pip install --require-hashes --only-binary=:all: "
                "--requirement requirements-pinned-dependencies.txt\n"
            ),
        },
        "policy job dependency installation changed",
    )
    require(
        named_step(policy_steps, "Check new-code coverage CI policy")
        == {
            "name": "Check new-code coverage CI policy",
            "run": "python scripts/check_new_code_coverage_ci_policy.py",
        },
        "policy checker invocation changed",
    )
    require(
        named_step(policy_steps, "Test new-code coverage CI policy")
        == {
            "name": "Test new-code coverage CI policy",
            "run": (
                "python scripts/test_check_new_code_coverage_ci_policy.py\n"
                "python scripts/test_check_covgate_policy.py\n"
                "python scripts/test_check_rust_coverage_report.py\n"
            ),
        },
        "policy adversarial tests changed",
    )

    gate = jobs.get("ci-gate")
    require(isinstance(gate, dict), "missing ci-gate")
    require(
        "new-code-coverage-policy" in gate.get("needs", []),
        "new-code coverage policy must be required by ci-gate",
    )


if __name__ == "__main__":
    path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / ".github/workflows/ci.yml"
    try:
        check_workflow(path)
    except (OSError, PolicyError, yaml.YAMLError) as error:
        print(f"new-code coverage CI policy error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    print("==> new-code coverage CI policy OK")
