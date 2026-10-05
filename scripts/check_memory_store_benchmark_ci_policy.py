#!/usr/bin/env python3
"""Validate executable CI policy for MemoryStore benchmark evidence."""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys
from typing import Any

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
BENCHMARK_WORKFLOW = ROOT / ".github" / "workflows" / "memory-store-benchmark.yml"
COMPARATOR_PATH = ROOT / "scripts" / "compare_memory_store_benchmarks.py"
CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
UPLOAD_ACTION = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
COMPARATOR_STEP_NAME = "Test advisory benchmark comparator"
COMPARATOR_COMMAND = "python3 scripts/test_compare_memory_store_benchmarks.py"
REQUIRED_COMPARATOR_JOBS = frozenset({"test", "coverage"})
SCOPED_JOB_IF = (
    "${{ !cancelled() && needs.preflight-gate.result == 'success' && "
    "(needs.ci_change_scope.outputs.rust == 'true' || github.event_name != 'pull_request') }}"
)
BENCHMARK_SOURCE_REF = "${{ github.event.pull_request.head.sha || github.sha }}"
TRUSTED_EVENT_ORDER = ("push", "schedule")
TRUSTED_BASELINE_CONDITION = (
    "${{ success() && (github.event_name == 'push' || github.event_name == 'schedule') }}"
)
UNTRUSTED_EVIDENCE_CONDITION = (
    "${{ always() && (github.event_name == 'pull_request' || "
    "github.event_name == 'workflow_dispatch') }}"
)
WRITE_MANIFEST_STEP_NAME = "Validate current benchmark evidence and write manifest"
WRITE_MANIFEST_COMMAND = """set -euo pipefail
toolchain="$(rustc --version --verbose)"
python3 scripts/compare_memory_store_benchmarks.py write-manifest \\
  --csv "$PIGLOROS_BENCH_OUTPUT" \\
  --output "artifacts/memory-erasure-benchmark-manifest.json" \\
  --architecture "$(uname -m)" \\
  --event "$GITHUB_EVENT_NAME" \\
  --head-branch "$HEAD_BRANCH" \\
  --head-repository-id "$HEAD_REPOSITORY_ID" \\
  --head-sha "$HEAD_SHA" \\
  --repository "$GITHUB_REPOSITORY" \\
  --repository-id "$GITHUB_REPOSITORY_ID" \\
  --run-attempt "$GITHUB_RUN_ATTEMPT" \\
  --runner-image "$ImageOS-$ImageVersion" \\
  --toolchain "$toolchain" \\
  --workflow-id "$BENCHMARK_WORKFLOW_ID" \\
  --workflow-path "$BENCHMARK_WORKFLOW_PATH" \\
  --workflow-run-id "$GITHUB_RUN_ID"
"""
COMPARE_EVIDENCE_STEP_NAME = "Compare PR evidence with the latest trusted main baseline"
COMPARE_EVIDENCE_CONDITION = "${{ github.event_name == 'pull_request' }}"
COMPARE_EVIDENCE_COMMAND = """set -euo pipefail
python3 scripts/compare_memory_store_benchmarks.py compare \\
  --csv "$PIGLOROS_BENCH_OUTPUT" \\
  --manifest "artifacts/memory-erasure-benchmark-manifest.json" \\
  --summary "$GITHUB_STEP_SUMMARY" \\
  --token "$GITHUB_TOKEN" \\
  --repository "$GITHUB_REPOSITORY" \\
  --repository-id "$GITHUB_REPOSITORY_ID" \\
  --workflow-id "$BENCHMARK_WORKFLOW_ID" \\
  --workflow-path "$BENCHMARK_WORKFLOW_PATH"
"""
BENCHMARK_PATHS = [
    ".github/workflows/memory-store-benchmark.yml",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "crates/pos-conformance/**",
    "crates/pos-core/**",
    "crates/pos-crypto/**",
    "crates/pos-reference/**",
    "crates/pos-store/Cargo.toml",
    "crates/pos-store/benches/**",
    "crates/pos-store/src/**",
    "scripts/compare_memory_store_benchmarks.py",
    "scripts/test_compare_memory_store_benchmarks.py",
]
BENCHMARK_TRIGGERS = {
    "push": {"branches": ["main"], "paths": BENCHMARK_PATHS},
    "pull_request": {"paths": BENCHMARK_PATHS},
    "schedule": [{"cron": "17 4 * * 1"}],
    "workflow_dispatch": None,
}
TOOLCHAIN_ACTION = "dtolnay/rust-toolchain@02cb101ec7c40f2c49e1d9714d64511d8e1b74de"
RUST_CACHE_ACTION = "Swatinem/rust-cache@f0d9c3887740aee45f6153b24b3a6b815192ec16"
BENCHMARK_WORKFLOW_ID = "350682006"
BENCHMARK_JOB_ENVIRONMENT = {
    "CARGO_BUILD_JOBS": "2",
    "CARGO_INCREMENTAL": "0",
    "HEAD_BRANCH": "${{ github.head_ref || github.ref_name }}",
    "HEAD_REPOSITORY_ID": "${{ github.event.pull_request.head.repo.id || github.repository_id }}",
    "HEAD_SHA": BENCHMARK_SOURCE_REF,
    "PIGLOROS_BENCH_OUTPUT": "${{ github.workspace }}/artifacts/memory-erasure-benchmark.csv",
    "PIGLOROS_BENCH_SAMPLES": "10",
    "RUSTFLAGS": "-D warnings",
}
METADATA_STEP_NAME = "Record runner and toolchain metadata"
METADATA_COMMAND = r"""mkdir -p artifacts
{
  printf 'runner_image=%s\n' "$ImageOS-$ImageVersion"
  printf 'architecture=%s\n' "$(uname -m)"
  rustc --version --verbose
  cargo --version --verbose
} | tee artifacts/environment.txt
"""
MEASUREMENT_STEP_NAME = "Measure MemoryStore erasure persistence paths"
MEASUREMENT_COMMAND = """set -o pipefail
cargo bench --locked -p pos-store --bench memory_erasure 2>&1 |
  tee artifacts/benchmark.log
"""
CHECKOUT_STEP = {
    "uses": CHECKOUT_ACTION,
    "with": {"ref": BENCHMARK_SOURCE_REF},
}
TOOLCHAIN_STEP = {
    "uses": TOOLCHAIN_ACTION,
    "with": {"toolchain": "1.97.1"},
}
RUST_CACHE_STEP = {
    "uses": RUST_CACHE_ACTION,
    "with": {"shared-key": "memory-store-benchmark"},
}
METADATA_STEP = {"name": METADATA_STEP_NAME, "run": METADATA_COMMAND}
MEASUREMENT_STEP = {"name": MEASUREMENT_STEP_NAME, "run": MEASUREMENT_COMMAND}
WRITE_MANIFEST_STEP = {
    "name": WRITE_MANIFEST_STEP_NAME,
    "run": WRITE_MANIFEST_COMMAND,
}
COMPARE_EVIDENCE_STEP = {
    "name": COMPARE_EVIDENCE_STEP_NAME,
    "if": COMPARE_EVIDENCE_CONDITION,
    "env": {"GITHUB_TOKEN": "${{ github.token }}"},
    "run": COMPARE_EVIDENCE_COMMAND,
}
TRUSTED_BASELINE_STEP = {
    "name": "Upload trusted main benchmark baseline",
    "if": TRUSTED_BASELINE_CONDITION,
    "uses": UPLOAD_ACTION,
    "with": {
        "name": "${{ env.BASELINE_ARTIFACT_NAME }}",
        "path": "artifacts/",
        "retention-days": 90,
        "overwrite": True,
        "if-no-files-found": "error",
    },
}
UNTRUSTED_EVIDENCE_STEP = {
    "name": "Upload untrusted pull-request or manual benchmark evidence",
    "if": UNTRUSTED_EVIDENCE_CONDITION,
    "uses": UPLOAD_ACTION,
    "with": {
        "name": (
            "memory-store-benchmark-evidence-${{ github.event_name }}-"
            "${{ github.run_id }}-${{ github.run_attempt }}"
        ),
        "path": "artifacts/",
        "retention-days": 14,
        "if-no-files-found": "error",
    },
}
EXPECTED_BENCHMARK_JOB = {
    "name": "MemoryStore erasure benchmark",
    "runs-on": "ubuntu-24.04",
    "timeout-minutes": 30,
    "env": BENCHMARK_JOB_ENVIRONMENT,
    "steps": [
        CHECKOUT_STEP,
        TOOLCHAIN_STEP,
        RUST_CACHE_STEP,
        METADATA_STEP,
        MEASUREMENT_STEP,
        WRITE_MANIFEST_STEP,
        COMPARE_EVIDENCE_STEP,
        TRUSTED_BASELINE_STEP,
        UNTRUSTED_EVIDENCE_STEP,
    ],
}


class GithubActionsLoader(yaml.SafeLoader):
    """Safely load Actions YAML using its YAML 1.2 boolean spelling."""


# PyYAML implements YAML 1.1, where an unquoted ``on`` becomes ``True``. GitHub
# Actions uses ``on`` as the trigger key, so retain it as a string while keeping
# ordinary true/false values (for example artifact ``overwrite``) as booleans.
GithubActionsLoader.yaml_implicit_resolvers = {
    first_character: [
        (tag, pattern)
        for tag, pattern in resolvers
        if tag != "tag:yaml.org,2002:bool"
    ]
    for first_character, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
GithubActionsLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


class PolicyError(RuntimeError):
    """A workflow no longer proves the required benchmark evidence policy."""


def require(condition: bool, message: str) -> None:
    """Raise one stable error when a required workflow property is absent."""

    if not condition:
        raise PolicyError(message)


def load_comparator() -> Any:
    """Load the executable comparator so policy constants have one owner."""

    spec = importlib.util.spec_from_file_location(
        "memory_store_comparator", COMPARATOR_PATH
    )
    if spec is None or spec.loader is None:
        raise PolicyError(f"cannot load comparator policy source {COMPARATOR_PATH}")
    comparator = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = comparator
    spec.loader.exec_module(comparator)
    return comparator


COMPARATOR = load_comparator()


def expected_benchmark_workflow() -> dict[str, Any]:
    """Return the complete executable policy for producing benchmark evidence."""

    return {
        "name": "memory-store-benchmark",
        "on": BENCHMARK_TRIGGERS,
        "permissions": {"actions": "read", "contents": "read"},
        "concurrency": {
            "group": "memory-store-benchmark-${{ github.workflow }}-${{ github.ref }}",
            "cancel-in-progress": True,
        },
        "env": {
            "BASELINE_ARTIFACT_NAME": COMPARATOR.ARTIFACT_NAME,
            "BENCHMARK_WORKFLOW_ID": BENCHMARK_WORKFLOW_ID,
            "BENCHMARK_WORKFLOW_PATH": COMPARATOR.WORKFLOW_PATH,
        },
        "jobs": {"benchmark": EXPECTED_BENCHMARK_JOB},
    }


def require_mapping(value: object, label: str) -> dict[str, Any]:
    """Return a YAML mapping or fail with a policy-oriented diagnostic."""

    require(isinstance(value, dict), f"{label} must be a mapping")
    return value


def require_steps(job: dict[str, Any], label: str) -> list[dict[str, Any]]:
    """Return a job's executable steps after rejecting malformed entries."""

    steps = job.get("steps")
    require(isinstance(steps, list), f"{label} steps must be a list")
    require(
        all(isinstance(step, dict) for step in steps), f"{label} has a malformed step"
    )
    return steps


def named_step(steps: list[dict[str, Any]], name: str) -> dict[str, Any]:
    """Return exactly one named executable step."""

    matches = [step for step in steps if step.get("name") == name]
    require(len(matches) == 1, f"expected exactly one {name!r} step")
    return matches[0]


def load_workflow(path: pathlib.Path) -> dict[str, Any]:
    """Decode one Actions workflow before checking its executable structure."""

    with path.open(encoding="utf-8") as stream:
        workflow = yaml.load(stream, Loader=GithubActionsLoader)
    return require_mapping(workflow, f"workflow {path}")


def check_ci_workflow(workflow_path: pathlib.Path) -> None:
    """Require unconditional comparator fixtures in both normal required gates."""

    workflow = load_workflow(workflow_path)
    jobs = require_mapping(workflow.get("jobs"), "CI workflow jobs")
    locations: list[tuple[str, dict[str, Any]]] = []
    for job_name, candidate in jobs.items():
        if not isinstance(job_name, str) or not isinstance(candidate, dict):
            continue
        steps = candidate.get("steps")
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            if (
                step.get("name") == COMPARATOR_STEP_NAME
                or step.get("run") == COMPARATOR_COMMAND
            ):
                locations.append((job_name, step))

    require(
        {job_name for job_name, _step in locations} == REQUIRED_COMPARATOR_JOBS
        and len(locations) == len(REQUIRED_COMPARATOR_JOBS),
        "comparator fixtures must run exactly once in test and coverage only",
    )
    expected_step = {"name": COMPARATOR_STEP_NAME, "run": COMPARATOR_COMMAND}
    for job_name in sorted(REQUIRED_COMPARATOR_JOBS):
        job = require_mapping(jobs.get(job_name), f"missing {job_name!r} job")
        require(
            job.get("needs") == ["ci_change_scope", "preflight-gate"],
            f"{job_name} must retain required preflight dependencies",
        )
        require(
            job.get("if") == SCOPED_JOB_IF,
            f"{job_name} must retain the executable Rust-scope condition",
        )
        require(
            "continue-on-error" not in job,
            f"{job_name} must remain a blocking required gate",
        )
        require("defaults" not in job, f"{job_name} must use the standard failing shell")
        step = named_step(require_steps(job, job_name), COMPARATOR_STEP_NAME)
        require(
            step == expected_step,
            f"{job_name} comparator step must be unconditional and fail closed",
        )


def check_benchmark_workflow(workflow_path: pathlib.Path) -> None:
    """Require the complete, fail-closed benchmark evidence producer policy."""

    require(
        frozenset(COMPARATOR.TRUSTED_EVENTS) == frozenset(TRUSTED_EVENT_ORDER),
        "comparator trusted-event policy diverged from the benchmark contract",
    )
    workflow = load_workflow(workflow_path)
    require(
        workflow == expected_benchmark_workflow(),
        "benchmark workflow must retain the complete fail-closed evidence policy",
    )


def check_workflows(ci_workflow: pathlib.Path, benchmark_workflow: pathlib.Path) -> None:
    """Validate the coupled CI and benchmark workflow policy surface."""

    check_ci_workflow(ci_workflow)
    check_benchmark_workflow(benchmark_workflow)


def main() -> int:
    """Run the policy checker over canonical or supplied workflow files."""

    paths = sys.argv[1:]
    if len(paths) > 2:
        print("ERROR: expected at most CI and benchmark workflow paths", file=sys.stderr)
        return 2
    ci_workflow = pathlib.Path(paths[0]) if paths else CI_WORKFLOW
    benchmark_workflow = (
        pathlib.Path(paths[1]) if len(paths) == 2 else BENCHMARK_WORKFLOW
    )
    try:
        check_workflows(ci_workflow, benchmark_workflow)
    except (OSError, yaml.YAMLError, PolicyError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("==> MemoryStore benchmark CI policy OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
