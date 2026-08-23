#!/usr/bin/env python3
"""Validate the executable semantics of the required ASan CI gate."""

from __future__ import annotations

import pathlib
import sys

import yaml


EXPECTED_SUPPRESSION = (
    "leak:^<bevy_reflect::utility::GenericTypeCell<"
    "bevy_reflect::type_info::TypeInfo>>::get_or_insert_by_type_id::*$\n"
    "leak:^<bevy_reflect::utility::GenericTypeCell<"
    "bevy_reflect::utility::TypePathComponent>>::get_or_insert_by_type_id::*$\n"
).encode()
EXPECTED_COMMAND = """set -euo pipefail
test -x "/usr/bin/llvm-symbolizer-18"
ASAN_SYMBOLIZER_PATH="/usr/bin/llvm-symbolizer-18" \\
  RUSTFLAGS="-Z sanitizer=address" \\
  cargo +nightly-2026-07-01 test --all-features --locked -Z build-std \\
    --target x86_64-unknown-linux-gnu --workspace --tests 2>&1 | \\
  tee "${RUNNER_TEMP}/asan.log"
python scripts/check_lsan_suppression_report.py "${RUNNER_TEMP}/asan.log"
"""
EXPECTED_WORKFLOW_ENV = {
    "CARGO_TERM_COLOR": "always",
    "RUSTFLAGS": "-D warnings",
}
EXPECTED_STEP_ENV = {
    "RUSTC_BOOTSTRAP": "1",
    "ASAN_OPTIONS": "detect_leaks=1:detect_odr_violation=0",
    "LSAN_OPTIONS": (
        "suppressions=${{ github.workspace }}/scripts/asan/bevy-reflect.lsan:"
        "print_suppressions=1"
    ),
    "CARGO_BUILD_JOBS": "1",
    "CARGO_INCREMENTAL": "0",
    "CARGO_PROFILE_TEST_DEBUG": "line-tables-only",
}
EXPECTED_JOB_KEYS = {"name", "runs-on", "timeout-minutes", "steps"}
EXPECTED_SETUP_STEPS = [
    {"uses": "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"},
    {"run": "rm -f rust-toolchain.toml"},
    {
        "uses": "dtolnay/rust-toolchain@6c977a6ca4077a0ceb28ffbe03f59d46e9ac8772",
        "with": {"toolchain": "nightly-2026-07-01", "components": "rust-src"},
    },
    {
        "name": "Verify ASan symbolizer",
        "run": """symbolizer="/usr/bin/llvm-symbolizer-18"
test -x "${symbolizer}"
symbolizer_version="$("${symbolizer}" --version)"
grep -Fqx "Ubuntu LLVM version 18.1.3" <<<"${symbolizer_version}"
""",
    },
    {
        "uses": "Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32",
        "with": {"shared-key": "asan-nightly-2026-07-01"},
    },
]
EXPECTED_NEGATIVE_CONTROL_STEP = {
    "name": "Prove unrelated leaks still fail LSan",
    "env": {
        "ASAN_OPTIONS": "detect_leaks=1:detect_odr_violation=0",
        "LSAN_OPTIONS": (
            "suppressions=${{ github.workspace }}/scripts/asan/bevy-reflect.lsan:"
            "print_suppressions=1"
        ),
    },
    "run": """set -euo pipefail
binary="${RUNNER_TEMP}/asan-intentional-leak"
log="${RUNNER_TEMP}/asan-intentional-leak.log"
trap 'rm -f "${binary}" "${log}"' EXIT
rustc +nightly-2026-07-01 -Z sanitizer=address -C debuginfo=1 \\
  --target x86_64-unknown-linux-gnu \\
  scripts/asan/intentional-leak.rs -o "${binary}"
set +e
ASAN_SYMBOLIZER_PATH="/usr/bin/llvm-symbolizer-18" \\
  "${binary}" 2>&1 | tee "${log}"
status=${PIPESTATUS[0]}
set -e
test "${status}" -ne 0
grep -Fqx "SUMMARY: AddressSanitizer: 1234 byte(s) leaked in 1 allocation(s)." "${log}"
! grep -F "Suppressions used:" "${log}"
! grep -F "bevy_reflect::utility::GenericTypeCell" "${log}"
""",
}


class PolicyError(RuntimeError):
    """The workflow does not provide the required non-waived ASan gate."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def check_suppression_file(suppression_path: pathlib.Path) -> None:
    require(
        suppression_path.read_bytes() == EXPECTED_SUPPRESSION,
        "LSan suppression file must contain exactly the two approved anchored lines",
    )


def check_workflow(workflow_path: pathlib.Path) -> None:
    check_suppression_file(
        pathlib.Path(__file__).resolve().parent / "asan" / "bevy-reflect.lsan"
    )
    with workflow_path.open(encoding="utf-8") as stream:
        workflow = yaml.safe_load(stream)

    require(isinstance(workflow, dict), "workflow root must be a mapping")
    require("defaults" not in workflow, "workflow-level shell defaults are not allowed")
    require(
        workflow.get("env") == EXPECTED_WORKFLOW_ENV,
        "workflow environment changed and could alter ASan execution",
    )

    jobs = workflow.get("jobs")
    require(isinstance(jobs, dict), "workflow jobs must be a mapping")
    job = jobs.get("asan")
    require(isinstance(job, dict), "missing ASan job")
    require(set(job) == EXPECTED_JOB_KEYS, "ASan job graph or metadata changed")
    require(job.get("name") == "asan (address sanitizer)", "ASan check name changed")
    require(job.get("runs-on") == "ubuntu-24.04", "ASan runner changed")
    require(job.get("timeout-minutes") == 60, "ASan timeout changed")
    require("if" not in job, "ASan job must be unconditional")
    require("continue-on-error" not in job, "ASan job must fail the workflow")
    require("defaults" not in job, "ASan job must use the standard failing shell")
    require("env" not in job, "ASan job-level environment is not allowed")

    steps = job.get("steps")
    require(isinstance(steps, list), "ASan job steps must be a list")
    require(len(steps) == 7, "ASan job must contain the exact trusted step sequence")
    require(
        steps[:5] == EXPECTED_SETUP_STEPS,
        "ASan setup steps must match the exact pinned trusted sequence",
    )
    require(
        steps[5] == EXPECTED_NEGATIVE_CONTROL_STEP,
        "ASan negative control must match the exact trusted step",
    )
    test_steps = [
        step
        for step in steps
        if isinstance(step, dict) and step.get("name") == "cargo test with ASan"
    ]
    require(len(test_steps) == 1, "ASan job must contain exactly one named test step")
    step = test_steps[0]
    require(step is steps[6], "ASan test must be the final trusted step")
    require(
        set(step) == {"name", "env", "run"},
        "ASan test step must contain exactly name, env, and run",
    )
    require("if" not in step, "ASan test step must be unconditional")
    require("continue-on-error" not in step, "ASan test step must fail the workflow")
    require("shell" not in step, "ASan test step must use the standard failing shell")

    env = step.get("env")
    require(
        env == EXPECTED_STEP_ENV,
        "ASan test environment must match the exact allowlist",
    )

    command = step.get("run")
    require(isinstance(command, str), "ASan test step must have a run command")
    require(command == EXPECTED_COMMAND, "ASan test command changed")


def main() -> int:
    root = pathlib.Path(__file__).resolve().parent.parent
    workflow = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else root / ".github/workflows/ci.yml"
    try:
        check_workflow(workflow)
    except (OSError, yaml.YAMLError, PolicyError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("==> ASan CI policy OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
