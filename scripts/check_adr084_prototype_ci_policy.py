#!/usr/bin/env python3
"""Fail closed if the throwaway ADR-084 workflow stops producing full evidence."""

from __future__ import annotations

import pathlib
import sys

import yaml


WORKFLOW = pathlib.Path(".github/workflows/adr084-podman-feasibility.yml")
RUNNER_MATRIX = {
    ("x86_64", "ubuntu-24.04"),
    ("aarch64", "ubuntu-24.04-arm"),
}
UPLOAD_ACTION = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"


class PolicyError(RuntimeError):
    """The hosted prototype no longer has the required execution semantics."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def named_step(steps: list[object], name: str) -> dict[str, object]:
    matches = [
        step for step in steps if isinstance(step, dict) and step.get("name") == name
    ]
    require(len(matches) == 1, f"expected exactly one workflow step named {name!r}")
    return matches[0]


def ordered(source: str, fragments: tuple[str, ...], label: str) -> None:
    cursor = -1
    for fragment in fragments:
        position = source.find(fragment, cursor + 1)
        require(position >= 0, f"{label} is missing {fragment!r}")
        require(position > cursor, f"{label} reordered {fragment!r}")
        cursor = position


def check(root: pathlib.Path) -> None:
    workflow_path = root / WORKFLOW
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    require(isinstance(workflow, dict), "prototype workflow root must be a mapping")
    jobs = workflow.get("jobs")
    require(isinstance(jobs, dict) and set(jobs) == {"probe"}, "only probe job admitted")
    probe = jobs["probe"]
    require(isinstance(probe, dict), "probe job must be a mapping")
    strategy = probe.get("strategy")
    require(isinstance(strategy, dict), "probe strategy must be a mapping")
    require(strategy.get("fail-fast") is False, "both architectures must finish")
    matrix = strategy.get("matrix")
    require(isinstance(matrix, dict), "probe matrix must be a mapping")
    include = matrix.get("include")
    require(isinstance(include, list), "probe matrix include must be a list")
    actual_matrix = {
        (entry.get("architecture"), entry.get("runner"))
        for entry in include
        if isinstance(entry, dict)
    }
    require(actual_matrix == RUNNER_MATRIX, "probe must run on hosted x86_64 and aarch64")
    require(probe.get("timeout-minutes") == 30, "probe timeout must remain bounded")
    steps = probe.get("steps")
    require(isinstance(steps, list), "probe steps must be a list")
    run_step = named_step(steps, "Run throwaway Podman feasibility probe")
    require(
        run_step.get("run")
        == "bash prototypes/adr084-podman-feasibility/run.sh",
        "workflow must invoke the audited driver exactly",
    )
    upload = named_step(steps, "Upload durable raw evidence")
    require(upload.get("if") == "always()", "evidence upload must run after failures")
    require(upload.get("uses") == UPLOAD_ACTION, "evidence upload action must stay pinned")
    upload_with = upload.get("with")
    require(isinstance(upload_with, dict), "evidence upload inputs must be a mapping")
    require(
        upload_with.get("path") == "artifacts/adr084-podman-feasibility/",
        "evidence upload path changed",
    )
    require(upload_with.get("if-no-files-found") == "error", "missing evidence must fail")

    prototype_dir = root / "prototypes/adr084-podman-feasibility"
    run_source = (prototype_dir / "run.sh").read_text(encoding="utf-8")
    require(run_source.startswith("#!/usr/bin/env bash\nset -euo pipefail\n"), "run.sh must fail closed")
    ordered(
        run_source,
        (
            'python3 "${prototype_dir}/driver.py"',
            'python3 "${prototype_dir}/lifecycle_crash_matrix.py"',
            'bash "${prototype_dir}/run_coverage_probe.sh"',
            'python3 "${prototype_dir}/write_evidence_manifest.py"',
            'printf \'ADR-084 prototype completed',
            'find "${artifact_dir}" -type f ! -name SHA256SUMS',
        ),
        "run.sh evidence stages",
    )
    coverage_source = (prototype_dir / "run_coverage_probe.sh").read_text(
        encoding="utf-8"
    )
    require(
        coverage_source.startswith("#!/usr/bin/env bash\nset -euo pipefail\n"),
        "coverage probe must fail closed",
    )
    ordered(
        coverage_source,
        (
            "clean_status=$?",
            "if [[ ${clean_status} -ne 0 ]]; then",
            '"failed_acceptance_criterion": 3',
            "exit 0",
            "unexpectedly preserved an empty adapter environment",
            "exit 1",
        ),
        "ADR-079 stop rule",
    )


def main() -> None:
    try:
        check(pathlib.Path.cwd())
    except (OSError, PolicyError, yaml.YAMLError) as error:
        print(f"ADR-084 prototype CI policy error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    print("ADR-084 prototype CI policy OK")


if __name__ == "__main__":
    main()
