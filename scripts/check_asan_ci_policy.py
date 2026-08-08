#!/usr/bin/env python3
"""Validate the executable semantics of the required ASan CI gate."""

from __future__ import annotations

import pathlib
import sys

import yaml


EXPECTED_COMMAND = " ".join(
    (
        'test -x "${RUNNER_TEMP}/llvm-symbolizer/llvm-symbolizer" &&',
        'ASAN_SYMBOLIZER_PATH="${RUNNER_TEMP}/llvm-symbolizer/llvm-symbolizer"',
        'RUSTFLAGS="-Z sanitizer=address"',
        "cargo +nightly-2026-07-01 test --all-features --locked -Z build-std",
        "--target x86_64-unknown-linux-gnu --workspace --tests",
    )
)
EXPECTED_WORKFLOW_ENV = {
    "CARGO_TERM_COLOR": "always",
    "RUSTFLAGS": "-D warnings",
}
EXPECTED_STEP_ENV = {
    "RUSTC_BOOTSTRAP": "1",
    "ASAN_OPTIONS": "detect_leaks=1:detect_odr_violation=0",
    "CARGO_BUILD_JOBS": "1",
    "CARGO_INCREMENTAL": "0",
    "CARGO_PROFILE_TEST_DEBUG": "line-tables-only",
}
EXPECTED_JOB_KEYS = {"name", "runs-on", "timeout-minutes", "steps"}
EXPECTED_SETUP_STEPS = [
    {"uses": "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"},
    {"run": "rm -f rust-toolchain.toml"},
    {
        "uses": "dtolnay/rust-toolchain@2c7215f132e9ebf062739d9130488b56d53c060c",
        "with": {"toolchain": "nightly-2026-07-01", "components": "rust-src"},
    },
    {
        "name": "Install ASan symbolizer",
        "env": {
            "LLVM_ARCHIVE_SHA256": (
                "54ec30358afcc9fb8aa74307db3046f5187f9fb89fb37064cdde906e062ebf36"
            )
        },
        "run": """archive="${RUNNER_TEMP}/llvm-18.1.8.tar.xz"
symbolizer_dir="${RUNNER_TEMP}/llvm-symbolizer"
curl --fail --location --retry 3 --output "${archive}" \\
  "https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.8/clang%2Bllvm-18.1.8-x86_64-linux-gnu-ubuntu-18.04.tar.xz"
echo "${LLVM_ARCHIVE_SHA256}  ${archive}" | sha256sum --check -
mkdir -p "${symbolizer_dir}"
tar -xJf "${archive}" --strip-components=2 -C "${symbolizer_dir}" \\
  "clang+llvm-18.1.8-x86_64-linux-gnu-ubuntu-18.04/bin/llvm-symbolizer"
rm -f "${archive}"
test -x "${symbolizer_dir}/llvm-symbolizer"
""",
    },
    {
        "uses": "Swatinem/rust-cache@e18b497796c12c097a38f9edb9d0641fb99eee32",
        "with": {"shared-key": "asan-nightly-2026-07-01"},
    },
]


class PolicyError(RuntimeError):
    """The workflow does not provide the required non-waived ASan gate."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def check_workflow(workflow_path: pathlib.Path) -> None:
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
    require(job.get("runs-on") == "ubuntu-latest", "ASan runner changed")
    require(job.get("timeout-minutes") == 60, "ASan timeout changed")
    require("if" not in job, "ASan job must be unconditional")
    require("continue-on-error" not in job, "ASan job must fail the workflow")
    require("defaults" not in job, "ASan job must use the standard failing shell")
    require("env" not in job, "ASan job-level environment is not allowed")

    steps = job.get("steps")
    require(isinstance(steps, list), "ASan job steps must be a list")
    require(len(steps) == 6, "ASan job must contain the exact trusted step sequence")
    require(
        steps[:5] == EXPECTED_SETUP_STEPS,
        "ASan setup steps must match the exact pinned trusted sequence",
    )
    test_steps = [
        step
        for step in steps
        if isinstance(step, dict) and step.get("name") == "cargo test with ASan"
    ]
    require(len(test_steps) == 1, "ASan job must contain exactly one named test step")
    step = test_steps[0]
    require(step is steps[5], "ASan test must be the final trusted step")
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
    require(command == f"{EXPECTED_COMMAND}\n", "ASan test command changed")


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
