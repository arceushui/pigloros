#!/usr/bin/env python3
"""Validate the executable semantics of the required cargo-crap CI gate."""

from __future__ import annotations

import pathlib
import hashlib
import sys

import yaml


CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
INSTALL_ACTION = "taiki-e/install-action@86f7a0ffb25f40114606501a311ebcfaf882ea32"
UPLOAD_ACTION = "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9"
DOWNLOAD_ACTION = "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333"
BASELINE_RESOLVER = "scripts/resolve_cargo_crap_baseline.sh"
COVERAGE_MERGER = "scripts/merge_owner_bridge_lcov.py"
COVERAGE_MERGER_SHA256 = '5aded2c2efd208194ac002c902ea86773e95b75dddbd2323c8f5e4303768a99d'
MERGE_COVERAGE_COMMAND = 'python scripts/merge_owner_bridge_lcov.py --linux "${{ runner.temp }}/coverage.lcov" --native "${{ runner.temp }}/owner-windows-lcov/owner-windows.lcov" --receipt "${{ runner.temp }}/owner-windows-lcov/owner-windows-lcov-receipt.json" --workspace "${{ github.workspace }}" --checkout "${{ github.sha }}" --output "${{ runner.temp }}/cargo-crap-coverage.lcov"\n'
SCOPED_JOB_IF = (
    "${{ !cancelled() && needs.preflight-gate.result == 'success' && "
    "(needs.ci_change_scope.outputs.rust == 'true' || "
    "github.event_name != 'pull_request') }}"
)
SCOPED_CARGO_CRAP_JOB_IF = (
    "${{ !cancelled() && needs.core-gate.result == 'success' && needs.coverage.result == 'success' && "
    "(needs.owner-bridge-windows.result == 'success' || "
    "(needs.ci_change_scope.outputs.owner_windows == 'false' && needs.owner-bridge-windows.result == 'skipped')) && "
    "(needs.ci_change_scope.outputs.rust == 'true' || "
    "github.event_name != 'pull_request') }}"
)
# The native lane ran unless the trusted scope explicitly said 'false'. Every
# native-only step uses NATIVE_MEASURED and every Linux-only step uses
# NATIVE_SKIPPED, so an empty or unknown scope fails closed to the merge.
NATIVE_MEASURED = "${{ needs.ci_change_scope.outputs.owner_windows != 'false' }}"
NATIVE_SKIPPED = "${{ needs.ci_change_scope.outputs.owner_windows == 'false' }}"
SHIM_ALLOW_ENV = {
    "NATIVE_SHIM_ALLOW": (
        "${{ needs.ci_change_scope.outputs.owner_windows == 'false' && "
        "'crates/pos-owner-bridge-windows/**' || '' }}"
    ),
}
SHIM_ALLOW_ARG = '${NATIVE_SHIM_ALLOW:+--allow "${NATIVE_SHIM_ALLOW}"} '
LINUX_ONLY_COVERAGE_COMMAND = (
    'cp "${{ runner.temp }}/coverage.lcov" "${{ runner.temp }}/cargo-crap-coverage.lcov"'
)
DROP_SHIM_BASELINE_COMMAND = (
    "set -euo pipefail\n"
    'baseline="${RUNNER_TEMP}/cargo-crap-baseline.json"\n'
    "jq -e '.entries |= map(select(.file | gsub(\"\\\\\\\\\"; \"/\") | "
    "test(\"(^|/)crates/pos-owner-bridge-windows/\") | not))' \\\n"
    '  "${baseline}" > "${baseline}.scoped"\n'
    'mv "${baseline}.scoped" "${baseline}"\n'
)
TEST_ONLY_EXCLUSIONS = (
    "tests/**",
    "benches/**",
    "examples/**",
    "src/selector/installation/tests/**",
    "src/erasure_tests.rs",
    "src/system_bus/tests.rs",
    "src/image_activator/tests.rs",
    "src/root_attachment/tests.rs",
    "src/root_selector/tests/admission_bounds.rs",
    "src/selector/installation/fixture.rs",
    "src/provider_admission/test_support.rs",
    "src/e2e_determinism.rs",
    "src/action_admission_tests.rs",
    "src/fork_event_authority/tests/local_replay.rs",
    "src/sqlite/tests/protected_interval_cleanup.rs",
    "src/sqlite/fork_replay/interval_tests.rs",
    "src/imported_fork_replay_tests.rs",
    "src/imported_fork_replay_tests/lifecycle.rs",
    "src/imported_fork_replay_tests/lifecycle/begin.rs",
    "src/imported_fork_replay_tests/cumulative_budget.rs",
    "src/imported_fork_replay_tests/cumulative_budget/compare.rs",
    "src/imported_fork_replay_tests/cumulative_budget/read_bounds.rs",
    "src/imported_fork_replay_tests/cumulative_budget/sqlite.rs",
    "src/imported_fork_replay_tests/cumulative_budget/sqlite/compare.rs",
    "src/imported_fork_replay_tests/runtime_budget.rs",
    "src/imported_fork_replay_tests/runtime_budget/deadline.rs",
    "src/imported_fork_replay_tests/runtime_budget/repeat.rs",
    "src/nested_imported_fork_replay_tests.rs",
    "src/nested_imported_fork_replay_tests/intermediate_privacy.rs",
    "src/ordinary_fork_lineage_tests.rs",
    "src/execute/tests/ownership.rs",
    "src/provider_barrier/tests.rs",
    "src/execute/tests/ownership/abandonment.rs",
    "src/revision/tests.rs",
    "src/provider_lifecycle/tests.rs",
    "src/provider_runtime/tests.rs",
    "src/provider_runtime/endpoint/tests.rs",
    "src/provider_runtime/serving/tests.rs",
    "src/scenario_room/tests.rs",
    "src/executor/scenario_room/tests.rs",
    # The Windows owner bridge's #[cfg(test)] native harness; its fixtures
    # (for example Fixture::consuming_step) see run-dependent native coverage.
    "src/adapter/native_tests.rs",
    "src/adapter/native_tests/**",
)
EXCLUSION_ARGS = "".join(f"--exclude '{path}' " for path in TEST_ONLY_EXCLUSIONS)
GENERATE_BASELINE_COMMAND = (
    "cargo crap --workspace "
    '--lcov "${{ runner.temp }}/cargo-crap-coverage.lcov" '
    "--missing pessimistic --jobs 2 "
    + EXCLUSION_ARGS
    + SHIM_ALLOW_ARG
    + "--format json "
    '--output "${{ runner.temp }}/cargo-crap-baseline.json"\n'
)
ANALYZE_COMMAND = (
    "cargo crap --workspace "
    '--lcov "${{ runner.temp }}/cargo-crap-coverage.lcov" '
    "--missing pessimistic --jobs 2 "
    + EXCLUSION_ARGS
    + SHIM_ALLOW_ARG
    + '--baseline "${{ runner.temp }}/cargo-crap-baseline.json" '
    "--epsilon 0 --format json "
    '--output "${{ runner.temp }}/cargo-crap-report.json"\n'
)
# Standard-stage jobs start from core-gate, beside cargo-crap: none consumes
# cargo-crap output, so the native Windows lane that cargo-crap waits for never
# delays or hides their findings. ci-gate requires cargo-crap directly.
STAGED_MAIN_JOBS = {
    "rustdoc": ["ci_change_scope", "core-gate"],
    "reference-evaluator-release": ["ci_change_scope", "core-gate"],
    "materialize-conformance-bundles": [
        "ci_change_scope",
        "conformance-fixtures",
        "core-gate",
    ],
    "audit": ["ci_change_scope", "core-gate"],
    "docker-build": ["ci_change_scope", "core-gate", "third-party-notices"],
    "world-client-wasm": ["ci_change_scope", "core-gate"],
    "world-client-browser-parity": ["ci_change_scope", "world-client-wasm"],
    "asan-build": ["ci_change_scope", "core-gate"],
}


CI_GATE_CARGO_CRAP_CHECK = (
    "expected_cargo_crap=success\n"
    'if [[ "${RUST_SCOPE_RESULT}" = false ]]; then\n'
    "  expected_cargo_crap=skipped\n"
    "fi\n"
    'if [[ "${CARGO_CRAP_RESULT}" != "${expected_cargo_crap}" ]]; then\n'
    '  echo "CARGO_CRAP_RESULT=${CARGO_CRAP_RESULT}" >&2\n'
    "  failed=1\n"
    "fi\n"
)
MAIN_REPORT_JOBS = ("modules-structure", "depgraph")


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


def check_staged_main_job(jobs: dict, name: str, needs: list[str]) -> None:
    job = jobs.get(name)
    require(isinstance(job, dict), f"missing staged main job {name!r}")
    require(job.get("needs") == needs, f"{name} direct dependencies changed")
    condition = job.get("if")
    require(isinstance(condition, str), f"{name} must have a job condition")
    require(
        condition.startswith("${{ !cancelled() && "),
        f"{name} must opt into evaluation after optional skipped ancestors",
    )
    for dependency in needs:
        require(
            f"needs.{dependency}.result == 'success'" in condition,
            f"{name} must require successful {dependency}",
        )
    require(
        "needs.ci_change_scope.outputs.rust == 'true' || "
        "github.event_name != 'pull_request'" in condition,
        f"{name} must retain Rust-scope filtering",
    )


# Deliberate tripwire: this mirrors the `codeql` job `if` in ci.yml, so an
# edit to that condition must be made in both places.
CODEQL_CONDITION = (
    "${{ !cancelled() && needs.ci_change_scope.result == 'success' && "
    "(needs.core-gate.result == 'success' || "
    "needs.ci_change_scope.outputs.rust == 'false') }}"
)


def check_codeql_job(jobs: dict) -> None:
    """CodeQL waits for core-gate on Rust PRs but always runs for docs-only PRs.

    The main ruleset's code_scanning rule needs an uploaded analysis for every
    pull-request head, so a Rust-scope skip would make documentation-only pull
    requests unmergeable.
    """
    job = jobs.get("codeql")
    require(isinstance(job, dict), "missing codeql job")
    require(
        job.get("needs") == ["ci_change_scope", "core-gate"],
        "codeql direct dependencies changed",
    )
    condition = job.get("if")
    require(isinstance(condition, str), "codeql must have a job condition")
    require(
        " ".join(condition.split()) == CODEQL_CONDITION,
        "codeql must run once core-gate succeeds, and always for documentation-only pull requests",
    )


def check_baseline_resolver(path: pathlib.Path | None = None) -> None:
    path = path or pathlib.Path(__file__).with_name("resolve_cargo_crap_baseline.sh")
    resolver = path.read_text(encoding="utf-8")
    required_fragments = (
        ("#!/usr/bin/env bash\n", "baseline resolver must be an executable Bash script"),
        ("set -euo pipefail\n", "baseline resolver must fail closed"),
        ("BASELINE_RETRY_ATTEMPTS=30\n", "baseline retry attempts changed"),
        ("BASELINE_RETRY_DELAY_SECONDS=10\n", "baseline retry delay changed"),
        ("MAIN_RUN_POLL_DELAY_SECONDS=60\n", "main run poll delay changed"),
        ("BASELINE_WAIT_LIMIT_SECONDS=7200\n", "baseline wait bound changed"),
        ("MAIN_RUN_REGISTRATION_LIMIT_SECONDS=600\n", "main run registration window changed"),
        ("GH_API_ATTEMPTS=3\n", "GitHub API attempts changed"),
        ("GH_API_RETRY_DELAY_SECONDS=30\n", "GitHub API retry delay changed"),
        (
            "if ((elapsed + MAIN_RUN_POLL_DELAY_SECONDS > MAIN_RUN_REGISTRATION_LIMIT_SECONDS)); then\n"
            '      reason="no main ci.yml run exists for trusted base ${TRUSTED_BASE_SHA} after ${elapsed}s"\n'
            "      break\n",
            "baseline resolver must bound the main run registration window and record why it stopped",
        ),
        (
            '  if [[ "${main_run_status}" == "completed" ]]; then\n'
            "    publish_baseline_if_available\n"
            '    reason="main ci.yml run ${main_run_id} for trusted base ${TRUSTED_BASE_SHA} completed with conclusion ',
            "baseline resolver must recheck the artifact and record why it stopped after main's run completed",
        ),
        (
            '  if [[ "${crap_job_status}" == "completed" ]]; then\n'
            "    publish_baseline_if_available\n"
            '    reason="the cargo-crap job of main ci.yml run ${main_run_id} for trusted base ${TRUSTED_BASE_SHA} completed with conclusion ',
            "baseline resolver must recheck the artifact and record why it stopped after main's cargo-crap job completed",
        ),
        (
            '    reason="main ci.yml run ${main_run_id} for trusted base ${TRUSTED_BASE_SHA} is still ${main_run_status} after ${elapsed}s; ',
            "baseline resolver must record why it stopped at the wait bound",
        ),
        (
            '"repos/${GITHUB_REPOSITORY}/actions/runs/$1/jobs"',
            "baseline resolver must inspect main's cargo-crap job",
        ),
        (
            '-f filter=latest -f per_page=100',
            "baseline resolver must read the latest main run attempt",
        ),
        (
            'select(.name == \\"cargo-crap\\")',
            "baseline resolver must wait for main's cargo-crap job only",
        ),
        (
            '    if GH_API_OUTPUT="$(gh api "$@")"; then\n',
            "baseline resolver must route GitHub API calls through its retry wrapper",
        ),
        (
            "for ((failure = 1; failure <= GH_API_ATTEMPTS; failure++)); do",
            "baseline resolver must bound GitHub API retries",
        ),
        (
            "  echo \"::error::GitHub API request $4 failed ${GH_API_ATTEMPTS} consecutive times; "
            "failing closed without a trusted main baseline\"\n  exit 1\n}\n",
            "persistent GitHub API failures must fail closed before the bootstrap decision",
        ),
        (
            "if ((elapsed + MAIN_RUN_POLL_DELAY_SECONDS > BASELINE_WAIT_LIMIT_SECONDS)); then",
            "baseline resolver must bound its wait for main",
        ),
        (
            'sleep "${MAIN_RUN_POLL_DELAY_SECONDS}"',
            "baseline resolver main run poll delay is not enforced",
        ),
        (
            '"repos/${GITHUB_REPOSITORY}/actions/workflows/ci.yml/runs"',
            "baseline resolver must wait only for main's ci.yml run",
        ),
        (
            '-f branch=main -f head_sha="${TRUSTED_BASE_SHA}" -f per_page=100',
            "baseline resolver must query main's run of the trusted commit",
        ),
        (
            'select(.head_branch == \\"main\\")',
            "baseline resolver must wait only for a main-branch run",
        ),
        (
            'select(.head_sha == \\"${TRUSTED_BASE_SHA}\\")',
            "baseline resolver must wait only for the trusted main commit",
        ),
        (
            "select(.head_repository.id == .repository.id)",
            "baseline resolver must not wait for fork runs",
        ),
        (
            'if [[ "${main_run_status}" == "completed" ]]; then',
            "baseline resolver must stop waiting once main's run completed",
        ),
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
            '"repos/${GITHUB_REPOSITORY}/actions/artifacts"',
            "baseline resolver must inspect repository artifacts directly",
        ),
        (
            '-f name="cargo-crap-baseline-${sha}"',
            "baseline resolver must request the exact baseline artifact",
        ),
        (
            "select(.expired == false)",
            "baseline resolver must reject expired artifacts",
        ),
        (
            'select(.workflow_run.head_branch == \\"main\\")',
            "baseline resolver must require a main-branch artifact",
        ),
        (
            'TRUSTED_BASE_SHA="$(git merge-base "${BASE_SHA}" origin/main)"',
            "baseline resolver must derive the trusted main merge-base",
        ),
        (
            'BASELINE_ARTIFACT_NAME="cargo-crap-baseline-${TRUSTED_BASE_SHA}"',
            "baseline resolver must name the trusted main artifact",
        ),
        (
            'select(.workflow_run.head_sha == \\"${sha}\\")',
            "baseline resolver must require the exact main commit of the artifact",
        ),
        (
            "select(.workflow_run.head_repository_id == .workflow_run.repository_id)",
            "baseline resolver must reject fork artifacts",
        ),
        (
            'git diff --quiet "${BASE_SHA}...HEAD"',
            "baseline bootstrap must reject Rust or Cargo-policy changes",
        ),
        (
            'echo "baseline-sha=${sha}" >> "${GITHUB_OUTPUT}"',
            "baseline resolver must publish the artifact commit",
        ),
        (
            'publish_baseline_if_available() {\n  publish_baseline_of "${TRUSTED_BASE_SHA}"\n}\n',
            "baseline resolver must look up the trusted main commit first",
        ),
        ("ANCESTOR_BASELINE_WALK_LIMIT=30\n", "ancestor baseline walk bound changed"),
        (
            'ancestors="$(git rev-list --first-parent --skip=1 \\\n'
            '    --max-count="${ANCESTOR_BASELINE_WALK_LIMIT}" "${TRUSTED_BASE_SHA}")"',
            "ancestor baseline fallback must walk a bounded first-parent main history",
        ),
        (
            '    publish_baseline_of "${ancestor}" \\\n',
            "ancestor baseline fallback must look up each ancestor's exact artifact",
        ),
        (
            "  publish_baseline_if_available\ndone\n\npublish_ancestor_baseline\n",
            "ancestor baseline fallback must run only after the wait for main's trusted-base run",
        ),
    )
    for fragment, message in required_fragments:
        require(fragment in resolver, message)
    require(
        resolver.count("publish_ancestor_baseline\n") == 1,
        "ancestor baseline fallback must run exactly once, after the wait",
    )
    require(
        resolver.count("gh api") == 1,
        "baseline resolver must issue every GitHub API call through its retry wrapper",
    )
    require(
        resolver.endswith(
            "  .cargo/config.toml .cargo-crap.toml; then\n"
            '  echo "::notice::Trusted main baseline unavailable: ${reason}; bootstrapping because '
            'this pull request changes no Rust or Cargo policy inputs"\n'
            "  echo 'bootstrap=true' >> \"${GITHUB_OUTPUT}\"\n"
            "  exit 0\n"
            "fi\n"
            'echo "::error::Trusted main baseline unavailable: ${reason}; failing closed because '
            'this pull request changes Rust or Cargo policy inputs"\n'
            "exit 1\n"
        ),
        "baseline resolver must end with the restricted bootstrap and fail-closed decision",
    )
    require(
        "-f status=success" not in resolver,
        "baseline resolver must not require whole-workflow completion",
    )


def check_coverage_merger(path: pathlib.Path | None = None) -> None:
    path = path or pathlib.Path(__file__).with_name("merge_owner_bridge_lcov.py")
    try:
        digest = hashlib.sha256(path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
    except (OSError, UnicodeError) as error:
        raise PolicyError(f"native coverage merger is unavailable: {error}") from error
    require(digest == COVERAGE_MERGER_SHA256, "native coverage merger differs from its reviewed program")


def check_workflow(
    workflow_path: pathlib.Path,
    baseline_resolver_path: pathlib.Path | None = None,
    coverage_merger_path: pathlib.Path | None = None,
) -> None:
    check_baseline_resolver(baseline_resolver_path)
    check_coverage_merger(coverage_merger_path)
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
        coverage.get("needs") == ["ci_change_scope", "preflight-gate"],
        "coverage must wait for the trusted scope and fast preflight",
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
        job.get("needs") == ["ci_change_scope", "coverage", "core-gate", "owner-bridge-windows"],
        "cargo-crap must wait for every core gate, hosted coverage and the native lane",
    )
    require(
        job.get("if") == SCOPED_CARGO_CRAP_JOB_IF,
        "cargo-crap must skip documentation-only pull requests",
    )
    require(job.get("runs-on") == "ubuntu-24.04", "cargo-crap runner changed")
    require(job.get("timeout-minutes") == 150, "cargo-crap timeout changed")
    steps = job.get("steps")
    require(isinstance(steps, list), "cargo-crap steps must be an array")
    require(len(steps) == 16, "cargo-crap must contain the exact trusted step sequence")
    require([step.get("name") for step in steps] == [
        None, None, "Install cargo-crap", "Download hosted LCOV", "Download hosted native LCOV",
        "Bind native and Linux coverage to this checkout",
        "Use Linux coverage without the unmeasured native shim",
        "Reject repository cargo-crap configuration",
        "Resolve trusted cargo-crap baseline", "Download trusted base baseline",
        "Drop the unmeasured native shim from the trusted baseline",
        "Generate trusted current baseline", "Analyze CRAP score changes", "Enforce cargo-crap policy",
        "Upload cargo-crap report", "Publish trusted main baseline",
    ], "cargo-crap evidence steps must retain their reviewed order")
    require(steps[1] == {"uses": "dtolnay/rust-toolchain@683b588c487a69d01f6c6ddf40f036ff682cc2c8",
                         "with": {"toolchain": "1.97.1"}}, "cargo-crap toolchain changed")

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
    require(named_step(steps, "Download hosted native LCOV") == {
        "name": "Download hosted native LCOV", "if": NATIVE_MEASURED, "uses": DOWNLOAD_ACTION,
        "with": {"name": "owner-windows-lcov-${{ github.sha }}", "path": "${{ runner.temp }}/owner-windows-lcov"},
    }, "cargo-crap must download native LCOV for this checkout")
    require(named_step(steps, "Bind native and Linux coverage to this checkout") == {
        "name": "Bind native and Linux coverage to this checkout", "if": NATIVE_MEASURED,
        "run": MERGE_COVERAGE_COMMAND,
    }, "cargo-crap must bind actual hosted counters before scoring")
    require(named_step(steps, "Use Linux coverage without the unmeasured native shim") == {
        "name": "Use Linux coverage without the unmeasured native shim", "if": NATIVE_SKIPPED,
        "run": LINUX_ONLY_COVERAGE_COMMAND,
    }, "cargo-crap may score Linux LCOV alone only when the native lane is out of scope")
    require(named_step(steps, "Drop the unmeasured native shim from the trusted baseline") == {
        "name": "Drop the unmeasured native shim from the trusted baseline",
        "if": "${{ steps.baseline.outputs.run-id != '' && "
              "needs.ci_change_scope.outputs.owner_windows == 'false' }}",
        "run": DROP_SHIM_BASELINE_COMMAND,
    }, "only an out-of-scope native lane may drop shim entries from the trusted baseline")
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
            "timeout-minutes": 130,
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
                "name": "cargo-crap-baseline-${{ steps.baseline.outputs.baseline-sha }}",
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
            "env": SHIM_ALLOW_ENV,
            "run": GENERATE_BASELINE_COMMAND,
        },
        "trusted current baseline generation changed",
    )
    require(
        named_step(steps, "Analyze CRAP score changes")
        == {"name": "Analyze CRAP score changes", "env": SHIM_ALLOW_ENV, "run": ANALYZE_COMMAND},
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

    # cargo-crap waits for the native Windows lane. ci-gate requires it, so
    # standard-gate (which mutation and ASan follow) must not wait for it.
    standard = jobs.get("standard-gate")
    require(isinstance(standard, dict), "missing aggregate standard-gate")
    require("cargo-crap" not in standard.get("needs", []),
            "standard-gate must not delay mutation and ASan behind cargo-crap")
    aggregate = jobs.get("ci-gate")
    require(isinstance(aggregate, dict), "missing aggregate ci-gate")
    require(aggregate.get("if") == "${{ always() }}", "ci-gate must always evaluate cargo-crap")
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
        verdict.get("env", {}).get("RUST_SCOPE_RESULT")
        == "${{ needs.ci_change_scope.outputs.rust }}",
        "ci-gate must read the trusted Rust scope",
    )
    require(
        CI_GATE_CARGO_CRAP_CHECK in verdict.get("run", ""),
        "ci-gate must reject a non-success cargo-crap result in Rust scope",
    )
    for name in MAIN_REPORT_JOBS:
        report = jobs.get(name)
        require(isinstance(report, dict), f"missing main report job {name!r}")
        require(report.get("needs") == ["standard-gate", "cargo-crap"],
                f"{name} must wait for standard-gate and cargo-crap")
        require(
            report.get("if") == "${{ github.event_name != 'pull_request' && "
            "needs.standard-gate.result == 'success' && needs.cargo-crap.result == 'success' }}",
            f"{name} must run only after successful standard checks and cargo-crap",
        )

    for name, needs in STAGED_MAIN_JOBS.items():
        check_staged_main_job(jobs, name, needs)
    check_codeql_job(jobs)


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
