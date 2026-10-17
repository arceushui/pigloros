#!/usr/bin/env python3
"""Validate the executable semantics of the required ASan CI gate."""

from __future__ import annotations

import pathlib
import sys

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
EXPECTED_SUPPRESSION = (
    "leak:^<bevy_reflect::utility::GenericTypeCell<"
    "bevy_reflect::type_info::TypeInfo>>::get_or_insert_by_type_id::*$\n"
    "leak:^<bevy_reflect::utility::GenericTypeCell<"
    "bevy_reflect::utility::TypePathComponent>>::get_or_insert_by_type_id::*$\n"
).encode()
EXPECTED_COMMAND = """set -euo pipefail
test -x "/usr/bin/llvm-symbolizer-18"
nextest_args=(
  +nightly-2026-07-01 nextest run
  --archive-file "${RUNNER_TEMP}/asan-archive/asan-tests.tar.zst"
  --extract-to "${GITHUB_WORKSPACE}"
  --extract-overwrite
  --workspace-remap "${GITHUB_WORKSPACE}"
  --user-config-file none
  --ignore-default-filter
  --success-output final
  --no-output-indent
  --test-threads 2
)
run_asan_partition() {
  ASAN_SYMBOLIZER_PATH="/usr/bin/llvm-symbolizer-18" \\
    cargo "${nextest_args[@]}" "$@"
}
case "${ASAN_SHARD}" in
  bundle-coverage)
    run_asan_partition \\
      -E 'binary_id(pos-conformance::bundle_contract_coverage_public)'
    ;;
  bundle-public-1)
    run_asan_partition \\
      -E 'binary_id(pos-conformance::bundle_contract_public)' \\
      --partition slice:1/2 --run-ignored all
    ;;
  bundle-public-2)
    run_asan_partition \\
      -E 'binary_id(pos-conformance::bundle_contract_public)' \\
      --partition slice:2/2 --run-ignored all
    ;;
  moat-proof)
    run_asan_partition \\
      -E 'binary_id(pos-conformance::moat_proof_public)'
    ;;
  remainder-1)
    run_asan_partition -E 'not package(pos-conformance)' \\
      --partition slice:1/2
    run_asan_partition \\
      -E 'package(pos-conformance) & (kind(lib) | kind(bin) | binary_id(pos-conformance::profile_contract_public) | binary_id(pos-conformance::provider_contract_public))'
    ;;
  remainder-2)
    run_asan_partition -E 'not package(pos-conformance)' \\
      --partition slice:2/2
    ;;
  *)
    printf 'unknown ASan shard: %s\\n' "${ASAN_SHARD}" >&2
    exit 2
    ;;
esac 2>&1 | tee "${RUNNER_TEMP}/asan.log"
python scripts/check_lsan_suppression_report.py "${RUNNER_TEMP}/asan.log"
"""
ARCHIVE_ARTIFACT = "asan-nextest-archive"
EXPECTED_BUILD_COMMAND = """set -euo pipefail
RUSTFLAGS="-Z sanitizer=address" \\
  cargo +nightly-2026-07-01 nextest archive --workspace --all-features \\
  --locked -Z build-std --target x86_64-unknown-linux-gnu --tests \\
  --archive-file "${RUNNER_TEMP}/asan-tests.tar.zst"
"""
EXPECTED_BUILD_ENV = {
    "RUSTC_BOOTSTRAP": "1",
    "CARGO_BUILD_JOBS": "1",
    "CARGO_INCREMENTAL": "0",
    "CARGO_PROFILE_TEST_DEBUG": "line-tables-only",
}
EXPECTED_BUILD_JOB = {
    "name": "asan build (nextest archive)",
    "needs": ["ci_change_scope", "cargo-crap"],
    "if": (
        "${{ !cancelled() && needs.ci_change_scope.result == 'success' && "
        "needs.cargo-crap.result == 'success' && "
        "(needs.ci_change_scope.outputs.rust == 'true' || github.event_name != 'pull_request') }}"
    ),
    "runs-on": "ubuntu-24.04",
    "timeout-minutes": 60,
    "steps": [
        {"uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"},
        {"run": "rm -f rust-toolchain.toml"},
        {
            "uses": "dtolnay/rust-toolchain@02cb101ec7c40f2c49e1d9714d64511d8e1b74de",
            "with": {"toolchain": "nightly-2026-07-01", "components": "rust-src"},
        },
        {
            "name": "Install cargo-nextest for the ASan archive",
            "uses": "taiki-e/install-action@4cef1412cce204788f482e778a0b9187f9626a29",
            "with": {"tool": "cargo-nextest@0.9.146", "fallback": "none"},
        },
        {
            "uses": "Swatinem/rust-cache@f0d9c3887740aee45f6153b24b3a6b815192ec16",
            "with": {
                "shared-key": "asan-nightly-2026-07-01",
                "save-if": "${{ github.ref == 'refs/heads/main' }}",
            },
        },
        {
            "name": "cargo nextest archive with ASan",
            "env": EXPECTED_BUILD_ENV,
            "run": EXPECTED_BUILD_COMMAND,
        },
        {
            "name": "Upload ASan test archive",
            "uses": "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            "with": {
                "name": ARCHIVE_ARTIFACT,
                "path": "${{ runner.temp }}/asan-tests.tar.zst",
                "retention-days": 3,
                "if-no-files-found": "error",
                "overwrite": True,
                "compression-level": 0,
            },
        },
    ],
}
EXPECTED_WORKFLOW_ENV = {
    "CARGO_TERM_COLOR": "always",
    "RUSTFLAGS": "-D warnings",
}
EXPECTED_STEP_ENV = {
    "ASAN_SHARD": "${{ matrix.shard }}",
    "ASAN_OPTIONS": "detect_leaks=1:detect_odr_violation=0",
    "LSAN_OPTIONS": (
        "suppressions=${{ github.workspace }}/scripts/asan/bevy-reflect.lsan:"
        "print_suppressions=1"
    ),
}
EXPECTED_SCOPE_JOB = [
    "ci_change_scope",
    "standard-gate",
    "mutation-checks",
    "asan-build",
]
EXPECTED_SCOPE_IF = (
    "${{ !cancelled() && needs.standard-gate.result == 'success' && "
    "(needs.mutation-checks.result == 'success' || needs.mutation-checks.result == 'skipped') && "
    "needs.asan-build.result == 'success' && "
    "(needs.ci_change_scope.outputs.rust == 'true' || github.event_name != 'pull_request') }}"
)
EXPECTED_JOB_KEYS = {
    "name",
    "needs",
    "if",
    "runs-on",
    "timeout-minutes",
    "strategy",
    "steps",
}
EXPECTED_STRATEGY = {
    "fail-fast": False,
    "max-parallel": 5,
    "matrix": {
        "shard": [
            "remainder-1",
            "remainder-2",
            "bundle-coverage",
            "bundle-public-1",
            "bundle-public-2",
            "moat-proof",
        ]
    },
}
EXPECTED_GATE_JOB = {
    "name": "asan (address sanitizer)",
    "if": "${{ always() }}",
    "needs": ["ci_change_scope", "asan-build", "asan"],
    "runs-on": "ubuntu-24.04",
    "timeout-minutes": 5,
    "steps": [
        {
            "name": "Require every ASan shard",
            "env": {
                "SCOPE_JOB_RESULT": "${{ needs.ci_change_scope.result }}",
                "RUST_SCOPE_RESULT": "${{ needs.ci_change_scope.outputs.rust }}",
                "ASAN_BUILD_RESULT": "${{ needs.asan-build.result }}",
                "ASAN_SHARDS_RESULT": "${{ needs.asan.result }}",
            },
            "run": (
                "set -euo pipefail\n"
                'if [[ "${SCOPE_JOB_RESULT}" == "success" \\\n'
                '  && "${RUST_SCOPE_RESULT}" == "false" \\\n'
                '  && "${ASAN_BUILD_RESULT}" == "skipped" \\\n'
                '  && "${ASAN_SHARDS_RESULT}" == "skipped" ]]; then\n'
                "  exit 0\n"
                "fi\n"
                'test "${ASAN_BUILD_RESULT}" = success\n'
                'test "${ASAN_SHARDS_RESULT}" = success\n'
            ),
        }
    ],
}
EXPECTED_SETUP_STEPS = [
    {"uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"},
    {"run": "rm -f rust-toolchain.toml"},
    {
        "uses": "dtolnay/rust-toolchain@02cb101ec7c40f2c49e1d9714d64511d8e1b74de",
        "with": {"toolchain": "nightly-2026-07-01"},
    },
    {
        "name": "Install cargo-nextest for partitioned ASan tests",
        "uses": "taiki-e/install-action@4cef1412cce204788f482e778a0b9187f9626a29",
        "with": {"tool": "cargo-nextest@0.9.146", "fallback": "none"},
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
        "name": "Download ASan test archive",
        "uses": "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "with": {"name": ARCHIVE_ARTIFACT, "path": "${{ runner.temp }}/asan-archive"},
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


def check_repository_nextest_configuration(workspace_root: pathlib.Path) -> None:
    repository_config = workspace_root / ".config" / "nextest.toml"
    require(
        not repository_config.exists(),
        "ASan nextest runs require no repository configuration",
    )


def check_workflow(
    workflow_path: pathlib.Path, workspace_root: pathlib.Path | None = None
) -> None:
    check_suppression_file(ROOT / "scripts" / "asan" / "bevy-reflect.lsan")
    check_repository_nextest_configuration(workspace_root or ROOT)
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
    build = jobs.get("asan-build")
    require(isinstance(build, dict), "missing ASan archive build job")
    require(
        build == EXPECTED_BUILD_JOB,
        "ASan archive build job must match the exact trusted job",
    )
    job = jobs.get("asan")
    require(isinstance(job, dict), "missing ASan shard job")
    require(set(job) == EXPECTED_JOB_KEYS, "ASan shard graph or metadata changed")
    require(job.get("needs") == EXPECTED_SCOPE_JOB, "ASan scope prerequisite changed")
    require(job.get("if") == EXPECTED_SCOPE_IF, "ASan scope condition changed")
    require(
        job.get("name") == "asan shard (${{ matrix.shard }})",
        "ASan shard check name changed",
    )
    require(job.get("runs-on") == "ubuntu-24.04", "ASan runner changed")
    require(job.get("timeout-minutes") == 60, "ASan timeout changed")
    require(
        job.get("strategy") == EXPECTED_STRATEGY,
        "ASan shard matrix must contain the exact complete partition",
    )
    require("continue-on-error" not in job, "ASan job must fail the workflow")
    require("defaults" not in job, "ASan job must use the standard failing shell")
    require("env" not in job, "ASan job-level environment is not allowed")

    steps = job.get("steps")
    require(isinstance(steps, list), "ASan job steps must be a list")
    require(len(steps) == 8, "ASan job must contain the exact trusted step sequence")
    require(
        steps[:6] == EXPECTED_SETUP_STEPS,
        "ASan setup steps must match the exact pinned trusted sequence",
    )
    require(
        steps[6] == EXPECTED_NEGATIVE_CONTROL_STEP,
        "ASan negative control must match the exact trusted step",
    )
    test_steps = [
        step
        for step in steps
        if isinstance(step, dict) and step.get("name") == "cargo test with ASan"
    ]
    require(len(test_steps) == 1, "ASan job must contain exactly one named test step")
    step = test_steps[0]
    require(step is steps[7], "ASan test must be the final trusted step")
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

    gate = jobs.get("asan-gate")
    require(isinstance(gate, dict), "missing aggregate ASan gate")
    require(
        gate == EXPECTED_GATE_JOB,
        "aggregate ASan gate must fail unless every shard succeeds",
    )


def main() -> int:
    workflow = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / ".github/workflows/ci.yml"
    try:
        check_workflow(workflow, ROOT)
    except (OSError, yaml.YAMLError, PolicyError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("==> ASan CI policy OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
