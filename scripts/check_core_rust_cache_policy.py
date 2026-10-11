#!/usr/bin/env python3
"""Keep core Rust cache writes on the trusted main branch."""

from __future__ import annotations

import pathlib
import sys

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
RUST_CACHE_ACTION = "Swatinem/rust-cache@f0d9c3887740aee45f6153b24b3a6b815192ec16"
TRUSTED_MAIN_SAVE_IF = "${{ github.ref == 'refs/heads/main' }}"
CORE_CACHE_KEYS = {
    "test": "test",
    "clippy": "clippy",
    "coverage": "coverage",
}


class PolicyError(RuntimeError):
    """The workflow does not preserve the core Rust cache contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def check_workflow(workflow_path: pathlib.Path = WORKFLOW_PATH) -> None:
    """Require PR restore-only caches and a durable trusted-main writer."""
    with workflow_path.open(encoding="utf-8") as stream:
        workflow = yaml.safe_load(stream)

    require(isinstance(workflow, dict), "workflow root must be a mapping")
    jobs = workflow.get("jobs")
    require(isinstance(jobs, dict), "workflow jobs must be a mapping")

    for job_name, shared_key in CORE_CACHE_KEYS.items():
        job = jobs.get(job_name)
        require(isinstance(job, dict), f"missing required {job_name!r} job")
        steps = job.get("steps")
        require(isinstance(steps, list), f"{job_name} steps must be an array")
        cache_steps = [
            step
            for step in steps
            if isinstance(step, dict) and step.get("uses") == RUST_CACHE_ACTION
        ]
        require(
            len(cache_steps) == 1,
            f"{job_name} must contain exactly one pinned rust-cache step",
        )
        require(
            cache_steps[0].get("with")
            == {
                "shared-key": shared_key,
                "save-if": TRUSTED_MAIN_SAVE_IF,
            },
            f"{job_name} must restore {shared_key!r} and save it only from main",
        )


def main() -> int:
    try:
        check_workflow()
    except PolicyError as error:
        print(f"core Rust cache policy error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
