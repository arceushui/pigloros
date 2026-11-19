#!/usr/bin/env python3
"""Contract tests for CI change scope and the core Rust gate policy."""

from __future__ import annotations

import ast
import copy
import hashlib
import os
import pathlib
import re
import shlex
import subprocess
import tempfile
import tomllib
import unittest

import yaml

import test_check_owner_runtime_custody_policy as custody_policy_tests
import test_merge_owner_bridge_lcov as native_lcov_tests
import owner_bridge_windows_workflow_policy as native_policy
from check_owner_runtime_custody_policy import UniqueKeys
from check_asan_ci_policy import EXPECTED_SDK_HEADROOM_STEP


ROOT = pathlib.Path(__file__).resolve().parent.parent
FILTER_PATH = ROOT / ".github" / "rust-scope.yml"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
CODEQL_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "codeql.yml"
RUST_CACHE_ACTION = "Swatinem/rust-cache@f0d9c3887740aee45f6153b24b3a6b815192ec16"
TRUSTED_MAIN_SAVE_IF = "${{ github.ref == 'refs/heads/main' }}"
# Workflows that run on main (push or schedule) own main-written caches. The
# pull-request-only mutation and sim1 proof-risk workflows keep PR-scoped keys.
MAIN_WRITER_WORKFLOW_PATHS = (
    CI_WORKFLOW_PATH,
    ROOT / ".github" / "workflows" / "fuzz.yml",
    ROOT / ".github" / "workflows" / "memory-store-benchmark.yml",
    ROOT / ".github" / "workflows" / "thread-sanitizer.yml",
)
TRUSTED_MAIN_DOCKER_CACHE_TO = (
    "${{ github.ref == 'refs/heads/main' && 'type=gha,mode=max' || '' }}"
)
CORE_CACHE_KEYS = {
    "feature-matrix": "feature-matrix",
    "test": "test",
    "test-shard": "test-nextest",
    "clippy": "clippy",
    "coverage": "coverage",
}
CORE_JOB_NAMES = ("fmt", "feature-matrix", "test", "test-shard", "clippy", "coverage")
CORE_GATE_JOB_NAMES = ("fmt", "feature-matrix", "test", "test-shards", "clippy", "coverage")
# Phase-1 package scope: on a pull request these jobs build, lint and test only
# the packages ci_change_scope resolved with scripts/affected_packages.py. Any
# other event, and a missing output, selects the whole workspace.
SCOPED_PACKAGES = (
    "${{ github.event_name == 'pull_request' && "
    "needs.ci_change_scope.outputs.rust_packages || '--workspace' }}"
)
SCOPED_DOC_PACKAGES = (
    "${{ github.event_name == 'pull_request' && "
    "needs.ci_change_scope.outputs.rust_doc_packages || '--workspace' }}"
)
SCOPED_PACKAGE_JOBS = frozenset(
    {"feature-matrix", "test", "test-shard", "clippy", "rustdoc", "asan-build", "asan"}
)
READ_SCOPED_PACKAGES = 'read -ra packages <<<"${CARGO_PACKAGES}"\n'
FEATURE_MATRIX_STEPS = (
    {
        "name": "cargo check (no default features)",
        "env": {"CARGO_PACKAGES": SCOPED_PACKAGES},
        "run": READ_SCOPED_PACKAGES
        + 'cargo check "${packages[@]}" --all-targets --no-default-features --locked\n',
    },
    {
        "name": "Plugin trust registry Memory vectors (no default features)",
        "run": "cargo test -p pos-store --no-default-features "
        "--test plugin_trust_registry_memory_public "
        "--test plugin_trust_registry_memory_policy_public "
        "--test plugin_trust_registry_memory_evaluation_public --locked\n",
    },
    {
        "name": "cargo check (all features, all targets)",
        "env": {"CARGO_PACKAGES": SCOPED_PACKAGES},
        "run": READ_SCOPED_PACKAGES
        + 'cargo check "${packages[@]}" --all-targets --all-features --locked\n',
    },
    {
        "name": "Prove reference evaluator implementation independence",
        "run": "bash scripts/check-reference-evaluator-independence.sh",
    },
    {
        "name": "Prove the conformance adapter dependency graph",
        "run": "bash scripts/check-adapter-graph.sh",
    },
)
WORKSPACE_DOCTEST_STEP = {
    "name": "cargo test doctests (all features, ignored included)",
    "env": {"CARGO_DOC_PACKAGES": SCOPED_DOC_PACKAGES},
    "run": "set -euo pipefail\n"
    'if [[ "${CARGO_DOC_PACKAGES}" == none ]]; then\n'
    "  echo 'No affected package has a library target; no doctest is in scope.'\n"
    "  exit 0\n"
    "fi\n"
    'read -ra packages <<<"${CARGO_DOC_PACKAGES}"\n'
    'cargo test "${packages[@]}" --all-features --locked --doc -- --include-ignored '
    "2>&1 | tee /tmp/cargo-doctest.log\n",
}
WORKSPACE_DOCTEST_SUMMARY_STEP = {
    "name": "Require no ignored test in the doctest summary",
    "env": {"CARGO_DOC_PACKAGES": SCOPED_DOC_PACKAGES},
    "run": "set -euo pipefail\n"
    'if [[ "${CARGO_DOC_PACKAGES}" != none ]]; then\n'
    "  bash scripts/assert-no-ignored-in-test-summary.sh /tmp/cargo-doctest.log\n"
    "fi\n",
}
WORKSPACE_RUSTDOC_STEP = {
    "name": "cargo doc (warnings denied)",
    "env": {
        "CARGO_INCREMENTAL": "0",
        "RUSTDOCFLAGS": "-D warnings",
        "CARGO_PACKAGES": SCOPED_PACKAGES,
    },
    "run": READ_SCOPED_PACKAGES
    + 'cargo doc "${packages[@]}" --all-features --no-deps --locked\n',
}
TEST_SHARD_STEP = {
    "name": "cargo nextest partition (all features, ignored included)",
    "env": {"SHARD": "${{ matrix.shard }}", "CARGO_PACKAGES": SCOPED_PACKAGES},
    "run": "set -euo pipefail\n"
    'log="${RUNNER_TEMP}/nextest-shard.log"\n'
    + READ_SCOPED_PACKAGES
    + "no_tests=fail\n"
    'if [[ "${CARGO_PACKAGES}" != --workspace ]]; then\n'
    "  no_tests=pass\n"
    "fi\n"
    "printf 'nextest partition: slice:%s/3\\n' \"${SHARD}\" >\"${log}\"\n"
    'cargo nextest run "${packages[@]}" --all-features --locked \\\n'
    "  --user-config-file none --ignore-default-filter \\\n"
    '  --run-ignored all --no-fail-fast --no-tests="${no_tests}" \\\n'
    '  --partition "slice:${SHARD}/3" 2>&1 | tee -a "${log}"\n',
}
CLIPPY_WORKSPACE_STEP = {
    "name": "cargo clippy (workspace lint policy, pedantic, deny warnings)",
    "env": {"CARGO_PACKAGES": SCOPED_PACKAGES},
    "run": READ_SCOPED_PACKAGES
    + 'cargo clippy "${packages[@]}" --all-features --all-targets --locked -- \\\n'
    "  -D warnings -W clippy::pedantic\n",
}
RUSTDOC_JOB_IF = (
    "${{ !cancelled() && needs.ci_change_scope.result == 'success' && "
    "needs.core-gate.result == 'success' && "
    "(needs.ci_change_scope.outputs.rust == 'true' || "
    "github.event_name != 'pull_request') }}"
)
MAIN_PUSH_TRIGGER = {"branches": ["main"]}
PREFLIGHT_GATE_IF = "${{ always() }}"
REQUIRED_PREFLIGHT_NEEDS = (
    "ci_change_scope",
    "pinned-dependencies",
    "source-policies",
    "owner-bridge-policies",
)
PINNED_DEPENDENCIES_NEEDS = "ci_change_scope"
PINNED_DEPENDENCIES_IF = (
    "${{ needs.ci_change_scope.outputs.rust == 'true' || "
    "github.event_name != 'pull_request' }}"
)
CI_WORKFLOW_POLICY_TEST_STEP = {
    "name": "Test CI workflow policy",
    "run": "python scripts/test_ci_workflow_policy.py",
}
# The preflight policy checks run as parallel jobs so each one finishes well
# inside its timeout. Every job shares the reachability, setup and result
# contract of pinned-dependencies, including its runner, checkout, pinned
# Python and hash-pinned install steps; each check runs exactly once, in the
# job listed here, in this order, with exactly this step body.
PREFLIGHT_POLICY_JOB_TIMEOUT = 10
PREFLIGHT_POLICY_RUNNER = "ubuntu-24.04"
PREFLIGHT_POLICY_JOB_KEYS = {"name", "needs", "if", "runs-on", "timeout-minutes", "steps"}
LOST_POLICY_CHECK = (
    "exactly its policy checks|must run exactly once|run the CI workflow policy test"
)
PREFLIGHT_POLICY_SETUP = [
    {"uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"},
    {
        "uses": "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
        "with": {"python-version": "3.12.11"},
    },
    {
        "name": "Install pinned dependency checker",
        "run": "python -m pip install --require-hashes --only-binary=:all: "
        "--requirement requirements-pinned-dependencies.txt\n",
    },
]
PREFLIGHT_POLICY_SETUP_STEPS = len(PREFLIGHT_POLICY_SETUP)
PREFLIGHT_POLICY_RESULT_ENV = {
    "pinned-dependencies": "POLICY_RESULT",
    "source-policies": "SOURCE_POLICY_RESULT",
    "owner-bridge-policies": "OWNER_POLICY_RESULT",
}
PREFLIGHT_POLICY_STEPS = {
    "pinned-dependencies": (
        {
            "name": "Check immutable Action and Docker references",
            "run": "bash scripts/check-pinned-dependencies.sh",
        },
        {
            "name": "Test pinned dependency checker",
            "run": "bash scripts/test-check-pinned-dependencies.sh",
        },
        {
            "name": "Test CI workflow policy",
            "run": "python scripts/test_ci_workflow_policy.py",
        },
        {
            "name": "Test the affected-package resolver",
            "run": "python scripts/test_affected_packages.py",
        },
        {
            "name": "Test mutation workflow policy",
            "run": "python scripts/test_mutation_workflow_policy.py",
        },
        {
            "name": "Test deploy workflow policy",
            "run": "python scripts/test_deploy_workflow_policy.py",
        },
        {
            "name": "Test ignored-test summary checker",
            "run": "python scripts/test_assert_no_ignored_in_test_summary.py",
        },
        {
            "name": "Test agent command guard",
            "run": "python scripts/test_agent_command_guard.py",
        },
        {
            "name": "Check ASan CI policy",
            "run": "bash scripts/check-asan-ci-policy.sh",
        },
        {
            "name": "Test ASan CI policy checker",
            "run": (
                "python scripts/test_check_asan_ci_policy.py\n"
                "python scripts/test_check_lsan_suppression_report.py\n"
            ),
        },
        {
            "name": "Check MemoryStore benchmark CI policy",
            "run": "python scripts/check_memory_store_benchmark_ci_policy.py",
        },
        {
            "name": "Test MemoryStore benchmark CI policy checker",
            "run": "python scripts/test_check_memory_store_benchmark_ci_policy.py",
        },
        {
            "name": "Check delegated isolated-test policy",
            "run": (
                "python scripts/check_isolated_test_runner_policy.py\n"
                "python scripts/test_check_isolated_test_runner_policy.py\n"
            ),
        },
        {
            "name": "Check cargo-crap CI policy",
            "run": "python scripts/check_cargo_crap_ci_policy.py",
        },
        {
            "name": "Test cargo-crap policy checkers",
            "run": (
                "python scripts/test_check_cargo_crap_ci_policy.py\n"
                "python scripts/test_check_cargo_crap_report.py\n"
            ),
        },
        {
            "name": "Check test-support feature policy",
            "run": (
                "python scripts/check_test_support_features.py\n"
                "python scripts/test_check_test_support_features.py\n"
            ),
        },
        {
            "name": "Test rust-test-policy test-code classification",
            "run": "python scripts/test_rust_test_policy.py",
        },
        {
            "name": "Test the Air-Gapped test namespace helpers",
            "run": "python scripts/test_air_gapped_seccomp_exec.py",
        },
        {
            "name": "Check the community Plugin handoff READMEs",
            "run": (
                "python scripts/check_handoff_readme.py\n"
                "python scripts/test_check_handoff_readme.py\n"
            ),
        },
        {
            "name": "Check PMF1 golden vectors match their generator",
            "run": "python scripts/generate_pmf1_golden_vectors.py --check",
        },
        {
            "name": "Check independent owner-bridge codec vectors",
            "run": (
                "python scripts/owner_bridge_vectors.py --check\n"
                "python scripts/test_owner_bridge_vectors.py\n"
            ),
        },
        {
            "name": "Check independent owner-bridge WebAuthn fixture",
            "run": "python scripts/owner_bridge_webauthn_fixtures.py --check",
        },
        {
            "name": "Test Wasmtime pin checker",
            "run": "python scripts/test_check_wasmtime_feature_pin.py",
        },
        {
            "name": "Check and test the third-party notice generator",
            "run": (
                "python scripts/third_party_notices.py check\n"
                "python scripts/test_third_party_notices.py\n"
            ),
        },
    ),
    "source-policies": (
        {
            "name": "Check counterfactual adapter seal policy",
            "run": (
                "python scripts/check_counterfactual_adapter_seal.py\n"
                "python scripts/test_check_counterfactual_adapter_seal.py\n"
            ),
        },
        {
            "name": "Check authority trust-root seal policy",
            "run": (
                "python scripts/check_authority_trust_root_seal.py\n"
                "python scripts/test_check_authority_trust_root_seal.py\n"
            ),
        },
        {
            "name": "Check trusted-clock port implementation policy",
            "run": (
                "python scripts/check_trusted_clock_port_impls.py\n"
                "python scripts/test_check_trusted_clock_port_impls.py\n"
            ),
        },
        {
            "name": "Check Plugin trust registry confinement policy",
            "run": (
                "python scripts/check_plugin_trust_registry_impls.py\n"
                "python scripts/test_check_plugin_trust_registry_impls.py\n"
            ),
        },
        {
            "name": "Check composition fallback registry confinement policy",
            "run": (
                "python scripts/check_composition_fallback_registry_impls.py\n"
                "python scripts/test_check_composition_fallback_registry_impls.py\n"
            ),
        },
        {
            "name": "Check fixture evaluation instant and admission host confinement policy",
            "run": (
                "python scripts/check_fixture_instant_confinement.py\n"
                "python scripts/test_check_fixture_instant_confinement.py\n"
            ),
        },
    ),
    "owner-bridge-policies": (
        {
            "name": "Check owner-bridge Windows unsafe policy",
            "run": (
                "python scripts/check_owner_bridge_unsafe_policy.py\n"
                "python scripts/test_check_owner_bridge_unsafe_policy.py\n"
            ),
        },
        {
            "name": "Check owner-bridge encryptor-lock dependency pin",
            "run": (
                "python scripts/check_owner_bridge_lock.py\n"
                "python scripts/test_check_owner_bridge_lock.py\n"
            ),
        },
        {
            "name": "Check subject-encryption activation boundary",
            "run": (
                "python scripts/check_subject_encryption_activation.py\n"
                "python scripts/test_check_subject_encryption_activation.py\n"
            ),
        },
        {
            "name": "Test Windows shim coverage exclusions",
            "run": "python scripts/test_owner_bridge_windows_cov_ignore.py",
        },
    ),
}
EXPECTED_EXCLUDES = {
    "!**/*.md",
    "!**/*.mdx",
    "!**/*.adoc",
    "!**/*.rst",
    "!.agents/**",
    "!docs/**",
}
# Every path the native Windows owner lane builds, lints, tests or executes,
# plus the gates that consume its evidence. Keep this a subset check: the
# filter may grow, it must never lose one of these.
REQUIRED_OWNER_WINDOWS_PATTERNS = (
    "crates/pos-owner-bridge-windows/**",
    "crates/pos-owner-bridge/**",
    "crates/pos-owner-bridge-codec/**",
    "apps/piglor-owner/**",
    "crates/pos-crypto/**",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".cargo/**",
    ".config/**",
    "clippy.toml",
    ".clippy.toml",
    "rustfmt.toml",
    ".rustfmt.toml",
    "covgate.toml",
    ".gitattributes",
    "fixtures/owner-bridge/**",
    ".github/workflows/owner-bridge-windows.yml",
    ".github/workflows/ci.yml",
    ".github/rust-scope.yml",
    "scripts/*owner*",
    "scripts/*cargo_crap*",
)
OWNER_WINDOWS_LANE_IF = (
    "${{ needs.ci_change_scope.outputs.rust == 'true' && "
    "needs.ci_change_scope.outputs.owner_windows == 'true' }}"
)
OWNER_WINDOWS_SCOPE_STEP = {
    "name": "Resolve the Windows-owner scope",
    "id": "owner_windows",
    "env": {
        "DETECTED": "${{ github.event_name == 'pull_request' && "
        "steps.scope.outcome == 'success' && steps.scope.outputs.owner_windows || '' }}",
        "CHANGED_FILES": "${{ github.event.pull_request.changed_files }}",
        "PULL_NUMBER": "${{ github.event.pull_request.number }}",
        "GH_TOKEN": "${{ github.token }}",
    },
    "run": (
        'scope=true\n'
        'if [[ "${DETECTED}" = false ]]; then\n'
        '  if [[ ! "${CHANGED_FILES}" =~ ^[0-9]+$ ]] || (( 10#${CHANGED_FILES} >= 3000 )); then\n'
        "    echo '::warning::The changed-file list may be truncated; running the Windows owner lane.'\n"
        '  elif [[ ! "${PULL_NUMBER}" =~ ^[0-9]+$ ]]; then\n'
        "    echo '::warning::The pull request number is unavailable; running the Windows owner lane.'\n"
        '  elif ! renamed="$(gh api --method GET --paginate -f per_page=100 \\\n'
        '    "repos/${GITHUB_REPOSITORY}/pulls/${PULL_NUMBER}/files" \\\n'
        '    --jq \'.[] | select(.status == "renamed") | .filename\')"; then\n'
        "    echo '::warning::Renamed files could not be listed; running the Windows owner lane.'\n"
        '  elif [[ -n "${renamed}" ]]; then\n'
        "    echo 'A renamed file may move a lane input; running the Windows owner lane.'\n"
        '  else\n'
        '    scope=false\n'
        '  fi\n'
        'fi\n'
        'printf \'owner_windows=%s\\n\' "${scope}" >> "$GITHUB_OUTPUT"\n'
    ),
}
RUST_PACKAGES_SCOPE_STEP = {
    "name": "Resolve the affected Rust packages",
    "id": "rust_packages",
    "env": {
        "EVENT_NAME": "${{ github.event_name }}",
        "DETECTED": "${{ github.event_name == 'pull_request' && steps.scope.outcome == 'success' && steps.scope.outputs.rust || '' }}",
        "HEAD_REF": "${{ github.head_ref }}",
        "CHANGED_FILES": "${{ github.event.pull_request.changed_files }}",
        "PULL_NUMBER": "${{ github.event.pull_request.number }}",
        "GH_TOKEN": "${{ github.token }}",
    },
    "run": (
        'packages=--workspace\n'
        'doc_packages=--workspace\n'
        "selection='^(--workspace|-p [A-Za-z0-9_-]+( -p [A-Za-z0-9_-]+)*)$'\n"
        'listing="${RUNNER_TEMP}/pull-request-files.jsonl"\n'
        'if [[ "${EVENT_NAME}" != pull_request || "${DETECTED}" != true ]]; then\n'
        "  echo 'Not a scoped pull request; running the whole workspace.'\n"
        'elif [[ "${HEAD_REF}" == trunk-merge/* ]]; then\n'
        "  echo 'Merge-queue test pull request; running the whole workspace.'\n"
        'elif [[ ! "${CHANGED_FILES}" =~ ^[0-9]+$ ]] || (( 10#${CHANGED_FILES} >= 3000 )); then\n'
        "  echo '::warning::The changed-file list may be truncated; running the whole workspace.'\n"
        'elif [[ ! "${PULL_NUMBER}" =~ ^[0-9]+$ ]]; then\n'
        "  echo '::warning::The pull request number is unavailable; running the whole workspace.'\n"
        'elif ! gh api --method GET --paginate -f per_page=100 \\\n'
        '  "repos/${GITHUB_REPOSITORY}/pulls/${PULL_NUMBER}/files" \\\n'
        '  --jq \'.[] | {filename, previous_filename}\' >"${listing}"; then\n'
        "  echo '::warning::Changed files could not be listed; running the whole workspace.'\n"
        'elif ! resolved="$(python3 scripts/affected_packages.py \\\n'
        '  --expected-files "$((10#${CHANGED_FILES}))" "${listing}")"; then\n'
        "  echo '::warning::The affected packages could not be resolved; running the whole workspace.'\n"
        'else\n'
        '  mapfile -t lines <<<"${resolved}"\n'
        '  candidate="${lines[0]-}"\n'
        '  candidate="${candidate#rust_packages=}"\n'
        '  doc_candidate="${lines[1]-}"\n'
        '  doc_candidate="${doc_candidate#rust_doc_packages=}"\n'
        '  if (( ${#lines[@]} == 2 )) \\\n'
        '    && [[ "${lines[0]-}" == rust_packages=* && "${lines[1]-}" == rust_doc_packages=* ]] \\\n'
        '    && [[ "${candidate}" =~ ${selection} ]] \\\n'
        '    && [[ "${doc_candidate}" == none || "${doc_candidate}" =~ ${selection} ]] \\\n'
        '    && [[ "${candidate}" != --workspace || "${doc_candidate}" == --workspace ]]; then\n'
        '    packages="${candidate}"\n'
        '    doc_packages="${doc_candidate}"\n'
        '  else\n'
        "    echo '::warning::The affected-package output is malformed; running the whole workspace.'\n"
        '  fi\n'
        'fi\n'
        'printf \'Rust packages: %s\\nDoctest packages: %s\\n\' "${packages}" "${doc_packages}"\n'
        'printf \'rust_packages=%s\\n\' "${packages}" >> "$GITHUB_OUTPUT"\n'
        'printf \'rust_doc_packages=%s\\n\' "${doc_packages}" >> "$GITHUB_OUTPUT"\n'
    ),
}
RUST_PACKAGES_OUTPUTS = {
    "rust_packages": "${{ steps.rust_packages.outputs.rust_packages }}",
    "rust_doc_packages": "${{ steps.rust_packages.outputs.rust_doc_packages }}",
}
CORE_JOB_NEEDS = ["ci_change_scope", "preflight-gate"]
CORE_JOB_IF = (
    "${{ !cancelled() && needs.preflight-gate.result == 'success' && "
    "(needs.ci_change_scope.outputs.rust == 'true' || "
    "github.event_name != 'pull_request') }}"
)


def assert_core_sdk_headroom(workflow: dict) -> None:
    """Protect the two workers observed exhausting disk during compilation."""
    for job_name in ("test-shard", "coverage"):
        steps = workflow["jobs"][job_name]["steps"]
        if (
            len(steps) < 2
            or steps[0].get("uses")
            != "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
            or steps[1] != EXPECTED_SDK_HEADROOM_STEP
            or sum(
                step.get("name") == EXPECTED_SDK_HEADROOM_STEP["name"]
                for step in steps
            )
            != 1
        ):
            raise AssertionError(
                f"{job_name} must reclaim bounded SDK headroom immediately after checkout"
            )


def load_patterns(key: str = "rust") -> list[str]:
    with FILTER_PATH.open(encoding="utf-8") as stream:
        filters = yaml.load(stream, Loader=UniqueKeys)
    if not isinstance(filters, dict) or not isinstance(filters.get(key), list):
        raise AssertionError(f"rust-scope.yml must define a {key} pattern list")
    patterns = filters[key]
    if not all(isinstance(pattern, str) for pattern in patterns):
        raise AssertionError("rust-scope.yml patterns must be strings")
    return patterns


def assert_owner_windows_filter(patterns: list[str]) -> None:
    """The owner filter is positive-only and keeps every lane input."""
    if any(pattern.startswith("!") for pattern in patterns):
        raise AssertionError("owner_windows must not exclude paths")
    missing = [pattern for pattern in REQUIRED_OWNER_WINDOWS_PATTERNS if pattern not in patterns]
    if missing:
        raise AssertionError(f"owner_windows lost required lane inputs: {missing}")


def picomatch_regex(pattern: str) -> re.Pattern[str]:
    """Translate the picomatch subset paths-filter uses (with ``dot: true``).

    ``*`` and ``?`` stay within one path segment; a whole ``**`` segment spans
    zero or more segments. Brace, extglob and class syntax is rejected so a
    filter cannot silently rely on a construct this model does not reproduce.
    """
    if any(character in pattern for character in "{}[]()+@") or pattern.startswith("!"):
        raise AssertionError(f"unsupported scope pattern: {pattern}")
    segments = pattern.split("/")
    regex = ""
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        if segment == "**":
            regex += ".*" if last else "(?:[^/]+/)*"
            continue
        if "**" in segment:
            raise AssertionError(f"unsupported scope pattern: {pattern}")
        regex += "".join(
            "[^/]*" if character == "*" else "[^/]" if character == "?" else re.escape(character)
            for character in segment
        )
        if not last:
            regex += "/"
    return re.compile(regex)


def picomatch(path: str, pattern: str) -> bool:
    return picomatch_regex(pattern).fullmatch(path) is not None


def scope_matches(path: str, patterns: list[str]) -> bool:
    """paths-filter's ``some-with-excludes``: any include and no exclude."""
    includes = [pattern for pattern in patterns if not pattern.startswith("!")]
    excludes = [pattern[1:] for pattern in patterns if pattern.startswith("!")]
    return (any(picomatch(path, pattern) for pattern in includes)
            and not any(picomatch(path, pattern) for pattern in excludes))


def owner_windows_lane_required(paths: list[str], patterns: list[str]) -> bool:
    return any(scope_matches(path, patterns) for path in paths)


def load_workflow(workflow_path: pathlib.Path) -> dict:
    with workflow_path.open(encoding="utf-8") as stream:
        workflow = yaml.load(stream, Loader=UniqueKeys)
    if not isinstance(workflow, dict):
        raise AssertionError(f"{workflow_path} must contain a mapping")
    return workflow


def workflow_triggers(workflow: dict) -> dict:
    """Return the top-level event mapping across PyYAML's YAML 1.1 key forms."""
    triggers = workflow.get("on")
    if triggers is None:
        triggers = workflow.get(True)
    if not isinstance(triggers, dict):
        raise AssertionError("ci.yml must define an event mapping")
    return triggers


def assert_core_jobs_run_on_main_push(workflow: dict) -> None:
    """Require the core Rust gates to remain reachable after a trusted main push."""
    for job_name in CORE_JOB_NAMES:
        job = workflow["jobs"].get(job_name)
        if not isinstance(job, dict):
            raise AssertionError(f"missing core Rust job: {job_name}")
        if job.get("needs") != CORE_JOB_NEEDS:
            raise AssertionError(f"{job_name} must wait for successful preflight")
        if job.get("if") != CORE_JOB_IF:
            raise AssertionError(f"{job_name} must remain reachable on a main push")


def assert_main_push_prerequisites(workflow: dict) -> None:
    """Keep the scope and preflight path available to every main push."""
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        raise AssertionError("ci.yml must define a jobs mapping")

    scope = jobs.get("ci_change_scope")
    if not isinstance(scope, dict):
        raise AssertionError("ci.yml must define ci_change_scope")
    if "needs" in scope:
        raise AssertionError("ci_change_scope must have no prerequisites")
    if "if" in scope:
        raise AssertionError("ci_change_scope must remain unconditional")

    for policy_name in PREFLIGHT_POLICY_STEPS:
        policy_job = jobs.get(policy_name)
        if not isinstance(policy_job, dict):
            raise AssertionError(f"ci.yml must define {policy_name}")
        if policy_job.get("needs") != PINNED_DEPENDENCIES_NEEDS:
            raise AssertionError(f"{policy_name} must wait for ci_change_scope")
        if policy_job.get("if") != PINNED_DEPENDENCIES_IF:
            raise AssertionError(f"{policy_name} must remain reachable on a main push")
    pinned_steps = jobs["pinned-dependencies"].get("steps")
    if (
        not isinstance(pinned_steps, list)
        or CI_WORKFLOW_POLICY_TEST_STEP not in pinned_steps
    ):
        raise AssertionError("pinned-dependencies must run the CI workflow policy test")

    preflight = jobs.get("preflight-gate")
    if not isinstance(preflight, dict):
        raise AssertionError("ci.yml must define preflight-gate")
    if preflight.get("if") != PREFLIGHT_GATE_IF:
        raise AssertionError("preflight-gate must remain reachable on a main push")
    preflight_needs = preflight.get("needs")
    if not isinstance(preflight_needs, list) or not set(REQUIRED_PREFLIGHT_NEEDS).issubset(
        preflight_needs
    ):
        raise AssertionError("preflight-gate must retain scope and policy dependencies")


def assert_preflight_policy_split(workflow: dict) -> None:
    """Each preflight policy job keeps its checks, setup and gate result."""
    assert_main_push_prerequisites(workflow)
    jobs = workflow["jobs"]
    for policy_name, expected_steps in PREFLIGHT_POLICY_STEPS.items():
        expected_names = tuple(step["name"] for step in expected_steps)
        job = jobs[policy_name]
        if job.get("name") != policy_name:
            raise AssertionError(f"{policy_name} must keep its check name")
        if job.get("runs-on") != PREFLIGHT_POLICY_RUNNER:
            raise AssertionError(f"{policy_name} must keep its pinned runner")
        if (job.get("timeout-minutes") != PREFLIGHT_POLICY_JOB_TIMEOUT
                or "continue-on-error" in job):
            raise AssertionError(f"{policy_name} must keep its blocking 10-minute limit")
        steps = job.get("steps", [])
        if steps[:PREFLIGHT_POLICY_SETUP_STEPS] != PREFLIGHT_POLICY_SETUP:
            raise AssertionError(f"{policy_name} must use the shared pinned Python setup")
        checks = steps[PREFLIGHT_POLICY_SETUP_STEPS:]
        if tuple(step.get("name") for step in checks) != expected_names:
            raise AssertionError(f"{policy_name} must run exactly its policy checks")
        if any("if" in step or "continue-on-error" in step for step in steps):
            raise AssertionError(f"{policy_name} steps must remain unconditional and blocking")
        if tuple(checks) != expected_steps:
            raise AssertionError(f"{policy_name} must run its pinned policy step bodies")
        if set(job) != PREFLIGHT_POLICY_JOB_KEYS:
            raise AssertionError(f"{policy_name} must keep exactly its reviewed job keys")
        for name in expected_names:
            owners = [
                owner
                for owner, candidate in jobs.items()
                for step in candidate.get("steps", [])
                if step.get("name") == name
            ]
            if owners != [policy_name]:
                raise AssertionError(f"{name} must run exactly once, in {policy_name}")

    preflight = jobs["preflight-gate"]
    if not set(PREFLIGHT_POLICY_STEPS).issubset(job_needs(preflight)):
        raise AssertionError("preflight-gate must wait for every preflight policy job")
    step = preflight["steps"][0]
    for policy_name, variable in PREFLIGHT_POLICY_RESULT_ENV.items():
        if step["env"].get(variable) != "${{ needs." + policy_name + ".result }}":
            raise AssertionError(f"preflight-gate must read the actual {policy_name} result")
        for expected in ("success", "skipped"):
            if f'test "${{{variable}}}" = {expected}' not in step["run"]:
                raise AssertionError(f"preflight-gate must enforce the {policy_name} result")


def assert_core_rust_cache_contract(workflow: dict) -> None:
    """Require the trusted writer and PR restore paths for core Rust caches."""
    triggers = workflow_triggers(workflow)
    if "pull_request" not in triggers or triggers["pull_request"] is not None:
        raise AssertionError("ci.yml must retain an unfiltered pull_request trigger for cache restores")

    push = triggers.get("push")
    if push != MAIN_PUSH_TRIGGER:
        raise AssertionError("ci.yml must retain a main push trigger for trusted cache writers")

    assert_main_push_prerequisites(workflow)
    assert_core_jobs_run_on_main_push(workflow)
    for job_name, shared_key in CORE_CACHE_KEYS.items():
        steps = workflow["jobs"][job_name]["steps"]
        cache_steps = [
            step
            for step in steps
            if isinstance(step, dict)
            and isinstance(step.get("uses"), str)
            and step["uses"].startswith("Swatinem/rust-cache@")
        ]
        if len(cache_steps) != 1:
            raise AssertionError(f"{job_name} must contain exactly one Rust cache step")
        cache_step = cache_steps[0]
        if cache_step["uses"] != RUST_CACHE_ACTION:
            raise AssertionError(f"{job_name} must use the pinned Rust cache action")
        if cache_step.get("with") != {
            "shared-key": shared_key,
            "save-if": TRUSTED_MAIN_SAVE_IF,
        }:
            raise AssertionError(f"{job_name} cache must use the trusted-main policy")
        if "if" in cache_step:
            raise AssertionError(f"{job_name} cache must remain reachable on pull requests")


TEST_SHARDS_NEEDS = ["test-shard"]
TEST_SHARDS_IF = "${{ !cancelled() && needs.test-shard.result == 'success' }}"
TEST_SHARDS_CORE_CHECK = 'test "${TEST_SHARDS_RESULT}" = "${expected}"'
TEST_SHARD_COUNT = 3


def step_runs(job: dict) -> str:
    return "\n".join(str(step.get("run", "")) for step in job.get("steps", []))


def assert_test_shards_gate(workflow: dict) -> None:
    """Require the shard aggregate to run only on all-shard success and block core-gate."""
    jobs = workflow["jobs"]
    aggregate = jobs.get("test-shards")
    if not isinstance(aggregate, dict):
        raise AssertionError("ci.yml must define the test-shards aggregate")
    if aggregate.get("needs") != TEST_SHARDS_NEEDS:
        raise AssertionError("test-shards must wait for every test shard")
    if aggregate.get("if") != TEST_SHARDS_IF:
        raise AssertionError("test-shards must run only after every shard succeeded")
    shard = jobs.get("test-shard", {})
    strategy = shard.get("strategy", {})
    expected = list(range(1, TEST_SHARD_COUNT + 1))
    if strategy.get("matrix", {}).get("shard") != expected:
        raise AssertionError(f"test-shard matrix must be shards {expected}")
    if strategy.get("fail-fast") is not False:
        raise AssertionError("test-shard must not cancel sibling shards on failure")
    count = str(TEST_SHARD_COUNT)
    shard_runs = step_runs(shard)
    aggregate_runs = step_runs(aggregate)
    for fragment, runs in (
        (f'--partition "slice:${{SHARD}}/{count}"', shard_runs),
        (f"nextest partition: slice:%s/{count}", shard_runs),
        (f"for shard in {' '.join(map(str, expected))}; do", aggregate_runs),
        (f"slice:${{shard}}/{count}", aggregate_runs),
        (f"--partitioned={count}", aggregate_runs),
    ):
        if fragment not in runs:
            raise AssertionError(f"shard count must agree everywhere: missing {fragment}")
    core = jobs["core-gate"]
    if "test-shards" not in core.get("needs", []):
        raise AssertionError("core-gate must wait for test-shards")
    steps = core.get("steps", [])
    if not any(
        step.get("env", {}).get("TEST_SHARDS_RESULT") == "${{ needs.test-shards.result }}"
        and TEST_SHARDS_CORE_CHECK in step.get("run", "")
        for step in steps
    ):
        raise AssertionError("core-gate must require the test-shards result")


def assert_pull_requests_never_write_caches(workflow: dict) -> None:
    """Keep every cache write on main so pull requests cannot evict main's caches.

    The repository cache budget is shared; per-PR writes previously pushed it
    past the limit and evicted the trusted main caches every PR restores.
    """
    for job_name, job in workflow["jobs"].items():
        for step in job.get("steps", []):
            uses = step.get("uses", "") if isinstance(step, dict) else ""
            if uses.startswith("Swatinem/rust-cache@"):
                if step.get("with", {}).get("save-if") != TRUSTED_MAIN_SAVE_IF:
                    raise AssertionError(f"{job_name} Rust cache must save only from main")
            if uses.startswith("docker/build-push-action@"):
                cache_to = step.get("with", {}).get("cache-to")
                if cache_to is not None and cache_to != TRUSTED_MAIN_DOCKER_CACHE_TO:
                    raise AssertionError(f"{job_name} Docker cache must save only from main")


STANDARD_STAGE_RUNNER_CAP = 8
LIGHTWEIGHT_CORE_GATE_CONSUMERS = frozenset({"standard-gate", "ci-gate"})
CARGO_CRAP_CONSUMERS = ["ci-gate", "depgraph", "modules-structure"]
# Heavy jobs released by core-gate. Browser parity follows WASM packaging on
# the same budget. cargo-crap starts earlier, from coverage, and compiles
# nothing (pinned binary, cargo metadata and LCOV parsing in a 10-minute budget,
# plus a bounded idle wait for main's trusted baseline), and standard-gate and
# ci-gate are lightweight fan-ins.
STANDARD_STAGE_JOBS = frozenset(
    {
        "rustdoc",
        "reference-evaluator-release",
        "materialize-conformance-bundles",
        "audit",
        "codeql",
        "docker-build",
        "world-client-wasm",
        "asan-build",
    }
)


def job_needs(job: dict) -> list[str]:
    needs = job.get("needs", [])
    return [needs] if isinstance(needs, str) else list(needs)


def assert_standard_stage_runner_cap(workflow: dict) -> None:
    """Keep the normal stage within its documented concurrent-runner cap."""
    jobs = workflow["jobs"]
    started = {
        name
        for name, job in jobs.items()
        if name not in LIGHTWEIGHT_CORE_GATE_CONSUMERS and "core-gate" in job_needs(job)
    }
    crap = jobs.get("cargo-crap", {})
    if (
        "strategy" in crap
        or crap.get("timeout-minutes") != 70
        or "core-gate" in job_needs(crap)
        or "coverage" not in job_needs(crap)
    ):
        raise AssertionError("cargo-crap must stay one lightweight runner released by coverage")
    if sorted(name for name, job in jobs.items() if "cargo-crap" in job_needs(job)) != CARGO_CRAP_CONSUMERS:
        raise AssertionError("only ci-gate and the main-only reports may wait for cargo-crap")
    if started != STANDARD_STAGE_JOBS:
        raise AssertionError("standard stage must start exactly the counted jobs")
    if len(started) > STANDARD_STAGE_RUNNER_CAP:
        raise AssertionError("standard stage must start at most eight runners")
    for name in sorted(started):
        if "strategy" in jobs[name]:
            raise AssertionError(f"standard stage job {name} must use one runner")
    gate_needs = job_needs(jobs.get("standard-gate", {}))
    missing = sorted(started - set(gate_needs))
    if missing:
        raise AssertionError(f"standard-gate must wait for every standard-stage job: {missing}")


# cargo-crap consumes the native LCOV and ci-gate requires both results. The
# main-only reports keep requiring cargo-crap. Mutation, ASan and every
# standard-stage job never wait for the lane.
OWNER_WINDOWS_DOWNSTREAM = sorted((
    "cargo-crap", "ci-gate", "modules-structure", "depgraph",
))


def transitive_needs(jobs: dict, name: str) -> set[str]:
    seen: set[str] = set()
    pending = job_needs(jobs[name])
    while pending:
        dependency = pending.pop()
        if dependency not in seen:
            seen.add(dependency)
            pending.extend(job_needs(jobs.get(dependency, {})))
    return seen


def assert_owner_windows_lane(workflow: dict, native: dict) -> None:
    """The Windows lane runs beside core CI and blocks its direct consumers."""
    jobs = workflow["jobs"]
    expected = {
        "name": "owner-bridge-windows",
        "needs": ["ci_change_scope", "ledger-windows"],
        "if": OWNER_WINDOWS_LANE_IF,
        "uses": "./.github/workflows/owner-bridge-windows.yml",
        "permissions": {"contents": "read"},
    }
    if jobs.get("owner-bridge-windows") != expected:
        raise AssertionError("owner Windows lane must follow the completed ledger runner")
    scope = jobs["ci_change_scope"]
    if scope.get("outputs", {}).get("owner_windows") != (
        "${{ steps.owner_windows.outputs.owner_windows }}"
    ):
        raise AssertionError("owner Windows scope must come only from its resolving step")
    resolving = [step for step in scope["steps"] if step.get("id") == "owner_windows"]
    if resolving != [OWNER_WINDOWS_SCOPE_STEP] or scope["steps"][-1] != OWNER_WINDOWS_SCOPE_STEP:
        raise AssertionError("owner Windows scope must default to the full lane")
    preflight = jobs["preflight-gate"]
    if "owner-bridge-windows" in job_needs(preflight) or "owner-bridge-windows" in str(preflight):
        raise AssertionError("owner Windows lane must not delay the core stage")
    consumers = sorted(name for name, job in jobs.items()
                       if "owner-bridge-windows" in job_needs(job))
    if consumers != ["cargo-crap", "ci-gate"]:
        raise AssertionError("only cargo-crap and ci-gate may wait for the owner Windows lane")
    behind_lane = sorted(name for name in jobs
                         if "owner-bridge-windows" in transitive_needs(jobs, name))
    if behind_lane != OWNER_WINDOWS_DOWNSTREAM:
        raise AssertionError(f"a failed owner Windows lane must not hide other findings: {behind_lane}")
    gate = jobs["ci-gate"]
    step = gate["steps"][0]
    if step["env"].get("OWNER_WINDOWS_RESULT") != "${{ needs.owner-bridge-windows.result }}":
        raise AssertionError("ci-gate must use the actual owner Windows result")
    if step["env"].get("OWNER_WINDOWS_SCOPE") != "${{ needs.ci_change_scope.outputs.owner_windows }}":
        raise AssertionError("ci-gate must use the trusted owner Windows scope")
    for fragment in (
        "expected_owner_windows=skipped",
        'if [[ "${EVENT_NAME}" != pull_request \\\n'
        '  || ( "${RUST_SCOPE_RESULT}" = true && "${OWNER_WINDOWS_SCOPE}" != false ) ]]; then\n'
        "  expected_owner_windows=success\n",
        'if [[ "${OWNER_WINDOWS_RESULT}" != "${expected_owner_windows}" ]]; then',
    ):
        if fragment not in step["run"]:
            raise AssertionError("ci-gate must enforce the owner Windows scope result")
    try:
        native_policy.check(native)
    except native_policy.PolicyError as error:
        raise AssertionError(str(error)) from error


def assert_parallel_validation_contract(workflow: dict) -> None:
    """Moving checks may change scheduling, never scope or failure semantics."""
    assert_core_jobs_run_on_main_push(workflow)
    jobs = workflow["jobs"]
    for owner, required in (
        ("feature-matrix", FEATURE_MATRIX_STEPS),
        ("test", (WORKSPACE_DOCTEST_STEP,)),
        ("rustdoc", (WORKSPACE_RUSTDOC_STEP,)),
    ):
        job = jobs[owner]
        if job.get("timeout-minutes") != 30 or "continue-on-error" in job:
            raise AssertionError(f"{owner} must keep its blocking 30-minute limit")
        for expected in required:
            occurrences = [
                (name, step)
                for name, candidate in jobs.items()
                for step in candidate.get("steps", [])
                if step.get("name") == expected["name"]
                or step.get("run") == expected["run"]
            ]
            if occurrences != [(owner, expected)]:
                raise AssertionError(f"{owner} must run the exact required step once")
    rustdoc = jobs["rustdoc"]
    if (rustdoc.get("needs") != ["ci_change_scope", "core-gate"]
            or rustdoc.get("if") != RUSTDOC_JOB_IF):
        raise AssertionError("rustdoc must retain its successful standard-stage prerequisites")
    if any(
        str(step.get("uses", "")).startswith("Swatinem/rust-cache@")
        for step in rustdoc["steps"]
    ):
        raise AssertionError("rustdoc must not restore the broken documentation target cache")
    gate = jobs["core-gate"]
    if gate.get("needs") != ["ci_change_scope", "preflight-gate", *CORE_GATE_JOB_NAMES]:
        raise AssertionError("core-gate must require every parallel core job")
    if gate.get("if") != "${{ always() }}" or "continue-on-error" in gate:
        raise AssertionError("core-gate must remain unconditional and blocking")
    step = gate["steps"][0]
    if "if" in step or "continue-on-error" in step:
        raise AssertionError("core-gate result check must remain blocking")
    for name in CORE_GATE_JOB_NAMES:
        variable = name.upper().replace("-", "_") + "_RESULT"
        if step["env"].get(variable) != "${{ needs." + name + ".result }}":
            raise AssertionError("core-gate must read every actual job result")
        if f'test "${{{variable}}}" = "${{expected}}"' not in step["run"]:
            raise AssertionError("core-gate must enforce every actual job result")


def rust_gate_required(paths: list[str], patterns: list[str]) -> bool:
    return any(scope_matches(path, patterns) for path in paths)


def mentions_package_scope(value: object) -> bool:
    return "rust_packages" in str(value) or "rust_doc_packages" in str(value)


def assert_rust_package_scope(workflow: dict) -> None:
    """Phase-1 package scope: resolved once, from the trusted base, fail-safe.

    Only the plain test and lint jobs read it, only through the exact step
    environment that ignores it outside pull requests and defaults a missing
    value to the whole workspace.
    """
    jobs = workflow["jobs"]
    scope = jobs["ci_change_scope"]
    outputs = scope.get("outputs", {})
    for key, value in RUST_PACKAGES_OUTPUTS.items():
        if outputs.get(key) != value:
            raise AssertionError("package scope must come only from its resolving step")
    steps = scope["steps"]
    if [step for step in steps if step.get("id") == "rust_packages"] != [RUST_PACKAGES_SCOPE_STEP]:
        raise AssertionError("package scope must default to the whole workspace")
    ids = [step.get("id") for step in steps]
    if ids.index("rust_packages") < ids.index("scope"):
        raise AssertionError("package scope must follow change detection")
    for step in steps:
        if step.get("id") != "rust_packages" and mentions_package_scope(step):
            raise AssertionError("only the resolving step may produce the package scope")
    expected_env = {"CARGO_PACKAGES": SCOPED_PACKAGES, "CARGO_DOC_PACKAGES": SCOPED_DOC_PACKAGES}
    readers = set()
    for name, job in jobs.items():
        if name == "ci_change_scope":
            continue
        if mentions_package_scope({key: value for key, value in job.items() if key != "steps"}):
            raise AssertionError(f"{name} may read the package scope only in a step environment")
        for step in job.get("steps", []):
            env = step.get("env", {})
            if mentions_package_scope({key: value for key, value in step.items() if key != "env"}):
                raise AssertionError(f"{name} may read the package scope only in a step environment")
            for key, value in env.items():
                if key in expected_env and value != expected_env[key]:
                    raise AssertionError(f"{name} must default {key} to the whole workspace")
                if key not in expected_env and mentions_package_scope(value):
                    raise AssertionError(f"{name} may read the package scope only as {sorted(expected_env)}")
                if key in expected_env:
                    readers.add(name)
    if readers != SCOPED_PACKAGE_JOBS:
        raise AssertionError(
            f"only the phase-1 jobs may use the package scope: {sorted(readers ^ SCOPED_PACKAGE_JOBS)}"
        )
    for owner, step in (
        ("test", WORKSPACE_DOCTEST_SUMMARY_STEP),
        ("test-shard", TEST_SHARD_STEP),
        ("clippy", CLIPPY_WORKSPACE_STEP),
    ):
        if [candidate for candidate in jobs[owner]["steps"]
                if candidate.get("name") == step["name"]] != [step]:
            raise AssertionError(f"{owner} must run the exact scoped step")


def assert_codeql_preparation_contract(workflow: dict) -> None:
    """Prepare real missing inputs without narrowing the native analysis."""
    job = workflow["jobs"]["analyze"]
    steps = job["steps"]
    if job["timeout-minutes"] != 30 or len(steps) != 5:
        raise AssertionError("retain the analysis deadline and complete step inventory")
    if steps[3:] != [
        {"uses": "github/codeql-action/init@9b3254085494b55a0f7c4c2b3d2d52cc712ce370",
         "with": {"languages": "rust", "build-mode": "none"}},
        {"uses": "github/codeql-action/analyze@9b3254085494b55a0f7c4c2b3d2d52cc712ce370",
         "with": {"category": "/language:rust"}},
    ]:
        raise AssertionError("retain the unchanged full CodeQL initialization and analysis")
    # Exact reviewed-program snapshots, not a shell semantics oracle. Preserve
    # every byte, including heredoc data; update only with reviewed setup changes.
    required = (
        (5, "28c278b217fbafce26f3940be27c2dea987e012b986564110dbccb1ad7e21e0c"),
        (1, "8ff9e3fadf283e88daefd380c1de1bdcf915e9ee321bcc8dd9b850c9e6382978"),
    )
    for step, (deadline, digest) in zip(steps[1:3], required):
        if set(step) != {"name", "run", "timeout-minutes"} or step["timeout-minutes"] != deadline:
            raise AssertionError("source preparation must remain bounded, unconditional and blocking")
        if hashlib.sha256(step["run"].encode()).hexdigest() != digest:
            raise AssertionError("source preparation must retain its real inputs and refusal checks")


class CiWorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.patterns = load_patterns()

    AZURE_MIRROR = "http://azure.archive.ubuntu.com/ubuntu"
    AZURE_LIST = {"apt-mirrors.txt": "http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\n"}
    SIMPLE_SOURCES = "Types: deb\nURIs: mirror+file:/etc/apt/apt-mirrors.txt\nSuites: noble\n"
    THIRD_PARTY_SOURCE = "deb [arch=amd64] https://packages.microsoft.com/ubuntu/24.04/prod noble main\n"

    @staticmethod
    def apt_command(apt_dir: pathlib.Path, arguments: str, *, bounded: bool = True) -> str:
        """The recorded apt-get call, scoped to the rewritten Ubuntu sources."""
        scope = (
            "-o Dir::Etc::sourcelist=/dev/null "
            f"-o Dir::Etc::sourceparts={apt_dir}/pigloros-sources.d"
        )
        bound = "timeout --kill-after=10 120 " if bounded else ""
        return f"{bound}apt-get {scope} {arguments}"

    def run_ubuntu_mirror_preparation(
        self, sources: str, runner_lists: dict[str, str],
        packages: tuple[str, ...] = ("b3sum", "jq"), apt_results: tuple[int, ...] = (),
        extra_sources: dict[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], pathlib.Path, dict[str, str], list[tuple[str, str]]]:
        """Run the installer against a sandboxed apt directory.

        ``sudo`` runs its command, ``timeout`` records its bound and runs the
        command, and ``apt-get`` records each call with the mirror list it saw
        and exits with the next of ``apt_results`` (0 once they run out).
        """
        with tempfile.TemporaryDirectory() as directory:
            fixture = pathlib.Path(directory)
            apt_dir = fixture / "apt"
            (apt_dir / "sources.list.d").mkdir(parents=True)
            (apt_dir / "apt.conf.d").mkdir()
            (apt_dir / "sources.list.d/ubuntu.sources").write_text(sources)
            for name, contents in (extra_sources or {}).items():
                (apt_dir / "sources.list.d" / name).write_text(contents)
            for name, contents in runner_lists.items():
                (apt_dir / name).write_text(contents)
            tools = fixture / "bin"
            tools.mkdir()
            calls = fixture / "calls"
            calls.mkdir()
            (calls / "log").write_text("")
            stubs = {
                "sudo": 'exec "$@"\n',
                "timeout": (
                    'printf "timeout %s " "$1 $2" >> "${APT_CALLS}/log"\n'
                    'shift 2\nexec "$@"\n'
                ),
                "apt-get": (
                    'n=$(($(wc -l < "${APT_CALLS}/log") + 1))\n'
                    'cp "${PIGLOROS_APT_DIR}/pigloros-mirrors.txt" "${APT_CALLS}/list.${n}"\n'
                    'printf "apt-get %s\\n" "$*" >> "${APT_CALLS}/log"\n'
                    'results=(${APT_RESULTS})\n'
                    'exit "${results[$((n - 1))]:-0}"\n'
                ),
            }
            for name, body in stubs.items():
                (tools / name).write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body)
                (tools / name).chmod(0o755)
            completed = subprocess.run(
                ["bash", str(ROOT / "scripts/prepare-ubuntu-package-mirror.sh"), *packages],
                env={
                    **os.environ,
                    "PATH": f"{tools}:{os.environ['PATH']}",
                    "PIGLOROS_APT_DIR": str(apt_dir),
                    "APT_CALLS": str(calls),
                    "APT_RESULTS": " ".join(str(result) for result in apt_results),
                },
                text=True, capture_output=True, check=False,
            )
            written = {
                str(path.relative_to(apt_dir)): path.read_text()
                for path in sorted(apt_dir.rglob("*")) if path.is_file()
            }
            log = (calls / "log").read_text().splitlines()
            apt_calls = [
                (line, (calls / f"list.{index}").read_text())
                for index, line in enumerate(log, start=1)
            ]
            return completed, apt_dir, written, apt_calls

    def test_ubuntu_mirror_lists_only_runner_and_ubuntu_hosts(self) -> None:
        # Hosted runners have no IPv6 route to mirrors.edge.kernel.org and its
        # IPv4 address timed out on 2026-11-16; no attempt may list a mirror
        # that neither the runner image nor Ubuntu runs.
        for runner_lists, apt_results in (({}, (124,)), (self.AZURE_LIST, (0, 100))):
            with self.subTest(runner_lists=runner_lists):
                completed, _, _, apt_calls = self.run_ubuntu_mirror_preparation(
                    self.SIMPLE_SOURCES, runner_lists, apt_results=apt_results,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                hosts = {
                    entry.split("\t", 1)[0]
                    for _, mirror_list in apt_calls
                    for entry in mirror_list.splitlines()
                }
                self.assertLessEqual(hosts, {
                    self.AZURE_MIRROR,
                    "http://archive.ubuntu.com/ubuntu",
                    "http://security.ubuntu.com/ubuntu",
                })

    def test_ubuntu_mirror_lists_runner_mirrors_first_then_ubuntu_fallbacks(self) -> None:
        # The GitHub-hosted image's own list (actions/runner-images
        # configure-apt-sources.sh) and the deb822 stanzas it redirects to it.
        runner_list = (
            "http://azure.archive.ubuntu.com/ubuntu/\tpriority:1\n"
            "https://archive.ubuntu.com/ubuntu/\tpriority:2\n"
            "https://security.ubuntu.com/ubuntu/\tpriority:3\n"
        )
        original = (
            "Types: deb\nURIs: mirror+file:/etc/apt/apt-mirrors.txt\n"
            "Suites: noble noble-updates noble-backports\nComponents: main universe\n"
            "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\n"
            "Types: deb\nURIs: mirror+file:/etc/apt/apt-security-mirrors.txt\n"
            "Suites: noble-security\nComponents: main universe\n"
            "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\n"
            "URIs: https://packages.microsoft.com/ubuntu/24.04/prod\n"
            "# URIs: mirror+file:/etc/apt/apt-mirrors.txt\n"
            "X-Notes: mirror+file:/etc/apt/apt-security-mirrors.txt\n"
            "URIs: mirror+file:/etc/apt/apt-mirrorsXtxt\n"
            "URIs: mirror+file:/etc/apt/apt-mirrors.txt.backup\n"
        )
        completed, apt_dir, written, apt_calls = self.run_ubuntu_mirror_preparation(
            original,
            {
                "apt-mirrors.txt": runner_list,
                "apt-security-mirrors.txt": "https://security.ubuntu.com/ubuntu/\tpriority:1\n# note\n",
            },
            extra_sources={"microsoft-prod.list": self.THIRD_PARTY_SOURCE},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        redirected = f"\nURIs: mirror+file:{apt_dir}/pigloros-mirrors.txt\n"
        rewritten = original.replace(
            "\nURIs: mirror+file:/etc/apt/apt-mirrors.txt\n", redirected,
        ).replace(
            "\nURIs: mirror+file:/etc/apt/apt-security-mirrors.txt\n", redirected,
        )
        mirror_list = (
            "http://azure.archive.ubuntu.com/ubuntu\tpriority:1\n"
            "https://archive.ubuntu.com/ubuntu\tpriority:2\n"
            "https://security.ubuntu.com/ubuntu\tpriority:3\n"
            "http://archive.ubuntu.com/ubuntu\tpriority:4\n"
            "http://security.ubuntu.com/ubuntu\tpriority:5\n"
        )
        self.assertEqual(written, {
            "apt-mirrors.txt": runner_list,
            "apt-security-mirrors.txt": "https://security.ubuntu.com/ubuntu/\tpriority:1\n# note\n",
            "pigloros-mirrors.txt": mirror_list,
            # No retries, so the mirror method fails over to the next entry at
            # once; a short connect/read timeout bounds each attempt.
            "apt.conf.d/80pigloros-mirror-retries": (
                'Acquire::Retries "0";\n'
                'Acquire::http::Timeout "10";\n'
                'Acquire::https::Timeout "10";\n'
            ),
            "sources.list.d/ubuntu.sources": rewritten,
            # The third-party source stays as it was and outside every apt call:
            # the scoped parts directory holds only the Ubuntu sources.
            "sources.list.d/microsoft-prod.list": self.THIRD_PARTY_SOURCE,
            "pigloros-sources.d/ubuntu.sources": rewritten,
        })
        # Both network phases are bounded; installation reads only the
        # downloaded packages from the same Ubuntu-only indices.
        self.assertEqual(apt_calls, [
            (self.apt_command(apt_dir, "update --error-on=any"), mirror_list),
            (self.apt_command(apt_dir, "install --yes --download-only b3sum jq"), mirror_list),
            (self.apt_command(apt_dir, "install --yes --no-download b3sum jq", bounded=False), mirror_list),
        ])

    def test_ubuntu_mirror_keeps_the_ubuntu_fallbacks_without_a_runner_list(self) -> None:
        completed, apt_dir, written, _ = self.run_ubuntu_mirror_preparation(self.SIMPLE_SOURCES, {})
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(written["pigloros-mirrors.txt"], (
            "http://archive.ubuntu.com/ubuntu\tpriority:1\n"
            "http://security.ubuntu.com/ubuntu\tpriority:2\n"
        ))
        self.assertEqual(
            written["sources.list.d/ubuntu.sources"],
            f"Types: deb\nURIs: mirror+file:{apt_dir}/pigloros-mirrors.txt\nSuites: noble\n",
        )

    def test_ubuntu_mirror_leaves_a_direct_host_security_stanza_untouched(self) -> None:
        # The EC2-hosted image points its security stanza straight at the host.
        security = (
            "Types: deb\nURIs: http://security.ubuntu.com/ubuntu\nSuites: noble-security\n"
        )
        completed, apt_dir, written, _ = self.run_ubuntu_mirror_preparation(
            self.SIMPLE_SOURCES + "\n" + security, {},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        rewritten = (
            f"Types: deb\nURIs: mirror+file:{apt_dir}/pigloros-mirrors.txt\nSuites: noble\n"
            "\n" + security
        )
        self.assertEqual(written["sources.list.d/ubuntu.sources"], rewritten)
        self.assertEqual(written["pigloros-sources.d/ubuntu.sources"], rewritten)

    def test_ubuntu_mirror_keeps_a_runner_entry_without_a_trailing_newline(self) -> None:
        completed, _, written, _ = self.run_ubuntu_mirror_preparation(self.SIMPLE_SOURCES, {
            "apt-mirrors.txt": "http://azure.archive.ubuntu.com/ubuntu/\tpriority:1",
        })
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(written["pigloros-mirrors.txt"], (
            "http://azure.archive.ubuntu.com/ubuntu\tpriority:1\n"
            "http://archive.ubuntu.com/ubuntu\tpriority:2\n"
            "http://security.ubuntu.com/ubuntu\tpriority:3\n"
        ))

    def test_ubuntu_mirror_fails_when_the_runner_sources_have_no_mirror_list(self) -> None:
        original = "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu\nSuites: noble\n"
        completed, _, written, apt_calls = self.run_ubuntu_mirror_preparation(original, {})
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("has no mirror+file Ubuntu archive source to redirect", completed.stdout)
        self.assertEqual(written["sources.list.d/ubuntu.sources"], original)
        self.assertEqual(apt_calls, [])

    def test_ubuntu_mirror_requires_packages_to_install(self) -> None:
        completed, _, _, apt_calls = self.run_ubuntu_mirror_preparation(
            self.SIMPLE_SOURCES, {}, packages=(),
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("::error::usage:", completed.stdout)
        self.assertEqual(apt_calls, [])

    def assert_runner_mirror_free_retry(
        self, apt_results: tuple[int, ...], failed_calls: int, failure: str,
    ) -> None:
        completed, apt_dir, _, apt_calls = self.run_ubuntu_mirror_preparation(
            self.SIMPLE_SOURCES, self.AZURE_LIST,
            packages=("--no-install-recommends", "valgrind"), apt_results=apt_results,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(
            f"::warning::apt {failure} on the Ubuntu sources; retrying once with the mirror "
            f"list without {self.AZURE_MIRROR}\n",
            completed.stdout,
        )
        with_first = (
            f"{self.AZURE_MIRROR}\tpriority:1\n"
            "http://archive.ubuntu.com/ubuntu\tpriority:2\n"
            "http://security.ubuntu.com/ubuntu\tpriority:3\n"
        )
        without_first = (
            "http://archive.ubuntu.com/ubuntu\tpriority:1\n"
            "http://security.ubuntu.com/ubuntu\tpriority:2\n"
        )
        update = self.apt_command(apt_dir, "update --error-on=any")
        download = self.apt_command(
            apt_dir, "install --yes --download-only --no-install-recommends valgrind",
        )
        install = self.apt_command(
            apt_dir, "install --yes --no-download --no-install-recommends valgrind", bounded=False,
        )
        first_attempt = [(update, with_first), (download, with_first)][:failed_calls]
        self.assertEqual(apt_calls, first_attempt + [
            (update, without_first), (download, without_first), (install, without_first),
        ])

    def test_ubuntu_mirror_retries_without_the_runner_mirror_when_the_refresh_times_out(self) -> None:
        # 124 is timeout's status once the 120 s bound expires; 137 is the
        # SIGKILL it sends when apt ignores SIGTERM for the 10 s grace.
        for status in (124, 137):
            with self.subTest(status=status):
                self.assert_runner_mirror_free_retry(
                    (status,), failed_calls=1,
                    failure=f"index refresh timed out after 120s (status {status})",
                )

    def test_ubuntu_mirror_retries_without_the_runner_mirror_when_a_package_download_fails(
        self,
    ) -> None:
        # apt-get exits 100 when a mirror is unreachable.
        self.assert_runner_mirror_free_retry(
            (0, 100), failed_calls=2, failure="package download failed with status 100",
        )

    def test_ubuntu_mirror_retries_with_the_full_list_without_a_runner_mirror(self) -> None:
        completed, apt_dir, _, apt_calls = self.run_ubuntu_mirror_preparation(
            self.SIMPLE_SOURCES, {}, apt_results=(124,),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(
            "::warning::apt index refresh timed out after 120s (status 124) on the Ubuntu "
            "sources; retrying once with the mirror list\n",
            completed.stdout,
        )
        fallbacks = (
            "http://archive.ubuntu.com/ubuntu\tpriority:1\n"
            "http://security.ubuntu.com/ubuntu\tpriority:2\n"
        )
        self.assertEqual([mirror_list for _, mirror_list in apt_calls], [fallbacks] * 4)
        self.assertEqual(apt_calls[1][0], self.apt_command(apt_dir, "update --error-on=any"))

    def test_ubuntu_mirror_keeps_the_archive_when_the_runner_lists_it_first(self) -> None:
        # A runner list that starts with the Ubuntu archive has no in-region
        # mirror to skip; dropping the archive would leave no main-suite mirror.
        completed, _, written, apt_calls = self.run_ubuntu_mirror_preparation(
            self.SIMPLE_SOURCES,
            {"apt-mirrors.txt": "http://archive.ubuntu.com/ubuntu/\tpriority:1\n"},
            apt_results=(124,),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("; retrying once with the mirror list\n", completed.stdout)
        fallbacks = (
            "http://archive.ubuntu.com/ubuntu\tpriority:1\n"
            "http://security.ubuntu.com/ubuntu\tpriority:2\n"
        )
        self.assertEqual(written["pigloros-mirrors.txt"], fallbacks)
        self.assertEqual([mirror_list for _, mirror_list in apt_calls], [fallbacks] * 4)

    def test_ubuntu_mirror_fails_closed_when_the_retry_fails(self) -> None:
        cases = {
            (124, 124): "index refresh timed out after 120s (status 124)",
            (0, 100, 0, 100): "package download failed with status 100",
            (100, 0, 137): "package download timed out after 120s (status 137)",
        }
        for apt_results, failure in cases.items():
            with self.subTest(apt_results=apt_results):
                completed, _, _, apt_calls = self.run_ubuntu_mirror_preparation(
                    self.SIMPLE_SOURCES, self.AZURE_LIST, apt_results=apt_results,
                )
                self.assertEqual(completed.returncode, 1)
                self.assertIn(
                    f"::error::apt {failure} on the Ubuntu sources again with the mirror list "
                    f"without {self.AZURE_MIRROR}; failing closed\n",
                    completed.stdout,
                )
                self.assertEqual(len(apt_calls), len(apt_results))
                self.assertNotIn("--no-download", apt_calls[-1][0])

    def test_ubuntu_mirror_fails_closed_when_the_offline_install_fails(self) -> None:
        completed, _, _, apt_calls = self.run_ubuntu_mirror_preparation(
            self.SIMPLE_SOURCES, {}, apt_results=(0, 0, 100),
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn(
            "::error::apt could not install the downloaded packages; failing closed\n",
            completed.stdout,
        )
        self.assertEqual(len(apt_calls), 3)
        self.assertIn("--no-download", apt_calls[-1][0])
        self.assertNotIn("::warning::", completed.stdout)

    def test_ubuntu_dependency_installers_use_only_the_bounded_installer(self) -> None:
        installers = {}
        for path in (CI_WORKFLOW_PATH, CI_WORKFLOW_PATH.with_name("sim1-proof-risk.yml")):
            for job in load_workflow(path)["jobs"].values():
                for step in job.get("steps", []):
                    run = step.get("run", "")
                    # No caller refreshes or installs outside the bounded script.
                    self.assertNotIn("apt-get", run)
                    self.assertNotIn("apt install", run)
                    lines = [line.strip() for line in run.splitlines()]
                    for line in lines:
                        if "prepare-ubuntu-package-mirror.sh" in line:
                            installers.setdefault(step["name"], []).append(line)
        prepare = "bash scripts/prepare-ubuntu-package-mirror.sh "
        self.assertEqual(installers, {
            "Install evaluator packaging tools": [prepare + "b3sum jq"],
            "Install fixture verification tools": [prepare + "b3sum jq"] * 2,
            "Install the musl and aarch64 cross toolchains": [
                prepare + "--no-install-recommends musl-tools gcc-aarch64-linux-gnu "
                "libc6-dev-arm64-cross",
            ],
            "Install graphviz": [prepare + "graphviz"],
            "Install heap profiler": [prepare + "--no-install-recommends valgrind"],
        })
        paths = workflow_triggers(load_workflow(
            CI_WORKFLOW_PATH.with_name("sim1-proof-risk.yml"),
        ))["pull_request"]["paths"]
        self.assertIn("scripts/prepare-ubuntu-package-mirror.sh", paths)

    def test_filter_has_conservative_positive_default(self) -> None:
        self.assertEqual(self.patterns[0], "**")
        self.assertEqual(set(self.patterns[1:]), EXPECTED_EXCLUDES)

    def test_owner_windows_filter_keeps_every_lane_input(self) -> None:
        patterns = load_patterns("owner_windows")
        assert_owner_windows_filter(patterns)
        for pattern in REQUIRED_OWNER_WINDOWS_PATTERNS:
            with self.subTest(removed=pattern), self.assertRaises(AssertionError):
                assert_owner_windows_filter([p for p in patterns if p != pattern])
        with self.assertRaises(AssertionError):
            assert_owner_windows_filter(patterns + ["!crates/pos-owner-bridge-windows/README.md"])

    def test_owner_windows_filter_covers_every_lane_input_path(self) -> None:
        patterns = load_patterns("owner_windows")
        native = (ROOT / ".github/workflows/owner-bridge-windows.yml").read_text(encoding="utf-8")
        scripts = sorted(set(re.findall(r"scripts/[A-Za-z0-9_.-]+\.(?:py|ps1|sh)", native)))
        self.assertEqual(scripts, [
            "scripts/check_owner_bridge_unsafe_policy.py",
            "scripts/observe-owner-desktop.ps1",
            "scripts/owner_bridge_windows_cov_ignore.py",
            "scripts/prepare-owner-runtime.ps1",
        ])
        for path in (*scripts,
                     "scripts/owner_bridge_runtime.py",
                     "scripts/merge_owner_bridge_lcov.py",
                     "scripts/owner_bridge_windows_workflow_policy.py",
                     "scripts/check_cargo_crap_report.py",
                     "scripts/resolve_cargo_crap_baseline.sh",
                     "crates/pos-owner-bridge-windows/unsafe-inventory.toml",
                     "crates/pos-owner-bridge-windows/runtime-manifest.v1",
                     "crates/pos-owner-bridge-windows/covgate.toml",
                     "crates/pos-owner-bridge-windows/README.md",
                     "crates/pos-owner-bridge/src/lib.rs",
                     "crates/pos-owner-bridge-codec/Cargo.toml",
                     "apps/piglor-owner/src/main.rs",
                     "crates/pos-crypto/src/lib.rs",
                     "Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
                     ".cargo/audit.toml",
                     ".cargo/config.toml",
                     ".config/nextest.toml",
                     "clippy.toml", ".clippy.toml", "rustfmt.toml", ".rustfmt.toml",
                     "covgate.toml", ".gitattributes",
                     "fixtures/owner-bridge/webauthn-es256-v1.fixture",
                     ".github/workflows/ci.yml",
                     ".github/workflows/owner-bridge-windows.yml",
                     ".github/rust-scope.yml"):
            with self.subTest(path=path):
                self.assertTrue(owner_windows_lane_required([path], patterns))
        for path in ("crates/pos-core/src/lib.rs", "crates/pos-store/Cargo.toml",
                     "scripts/check_asan_ci_policy.py", "crates/Cargo.toml",
                     "scripts/asan/owner.sh", "crates/pos-core/Cargo.toml",
                     "crates/pos-owner-bridge-windows-extra/src/lib.rs",
                     "fixtures/other/owner-bridge.fixture", "docs/test-policy.md"):
            with self.subTest(path=path):
                self.assertFalse(owner_windows_lane_required([path], patterns))

    def resolve_owner_windows_scope(self, *, detected: str, changed: str = "12",
                                    number: str = "848", gh_status: int = 0,
                                    gh_output: str = "") -> tuple[str, list[str]]:
        step = OWNER_WINDOWS_SCOPE_STEP
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            tools = root / "bin"
            tools.mkdir()
            calls = root / "gh-calls"
            (tools / "gh").write_text(
                "#!/usr/bin/env bash\n"
                'printf \'%s\\0\' "$@" >> "${GH_CALLS}"\n'
                'printf \'%s\' "${GH_FAKE_OUTPUT}"\n'
                'exit "${GH_FAKE_STATUS}"\n',
                encoding="utf-8",
            )
            (tools / "gh").chmod(0o755)
            output = root / "output"
            subprocess.run(
                ["bash", "-e", "-c", step["run"]], check=True, capture_output=True,
                env=dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}",
                         DETECTED=detected, CHANGED_FILES=changed, PULL_NUMBER=number,
                         GITHUB_REPOSITORY="owner/repository", GITHUB_OUTPUT=str(output),
                         GH_CALLS=str(calls), GH_FAKE_STATUS=str(gh_status),
                         GH_FAKE_OUTPUT=gh_output),
            )
            arguments = calls.read_text(encoding="utf-8").split("\0")[:-1] if calls.exists() else []
            return output.read_text(encoding="utf-8"), arguments

    def test_owner_windows_scope_resolves_only_explicit_false_to_a_skip(self) -> None:
        # Absent filter key, failed or skipped detection and non-pull-request
        # events all reach the step as an empty value.
        for detected in ("true", "", "False", "0", "unknown"):
            with self.subTest(detected=detected):
                output, calls = self.resolve_owner_windows_scope(detected=detected)
                self.assertEqual(output, "owner_windows=true\n")
                self.assertEqual(calls, [])
        output, calls = self.resolve_owner_windows_scope(detected="false")
        self.assertEqual(output, "owner_windows=false\n")
        self.assertEqual(calls, [
            "api", "--method", "GET", "--paginate", "-f", "per_page=100",
            "repos/owner/repository/pulls/848/files",
            "--jq", '.[] | select(.status == "renamed") | .filename',
        ])
        detected = OWNER_WINDOWS_SCOPE_STEP["env"]["DETECTED"]
        for guard in ("github.event_name == 'pull_request'", "steps.scope.outcome == 'success'"):
            self.assertIn(guard, detected)

    def test_owner_windows_scope_runs_the_lane_when_the_file_list_is_uncertain(self) -> None:
        for label, overrides in (
            ("api limit", {"changed": "3000"}),
            ("over api limit", {"changed": "3001"}),
            ("zero-padded api limit", {"changed": "03000"}),
            ("unknown count", {"changed": ""}),
            ("malformed count", {"changed": "12; true"}),
            ("unknown pull request", {"number": ""}),
            ("api failure", {"gh_status": 1}),
            ("api failure with partial output", {"gh_status": 22, "gh_output": ""}),
            ("renamed file", {"gh_output": "crates/pos-owner-bridge-windows/src/moved.rs\n"}),
            ("renamed elsewhere", {"gh_output": "docs/moved.md"}),
        ):
            with self.subTest(label=label):
                output, _ = self.resolve_owner_windows_scope(detected="false", **overrides)
                self.assertEqual(output, "owner_windows=true\n")
        for changed in ("2999", "0999", "08"):
            with self.subTest(changed=changed):
                output, calls = self.resolve_owner_windows_scope(detected="false", changed=changed)
                self.assertEqual(output, "owner_windows=false\n")
                self.assertTrue(calls)
        output, calls = self.resolve_owner_windows_scope(detected="false", changed="3000")
        self.assertEqual(calls, [])

    def test_scope_matcher_follows_picomatch_segments(self) -> None:
        for path, pattern, expected in (
            ("scripts/owner_bridge_runtime.py", "scripts/*owner*", True),
            ("scripts/asan/owner.sh", "scripts/*owner*", False),
            ("README.md", "**/*.md", True),
            ("a/b/c.md", "**/*.md", True),
            (".agents/x.md", "**/*.md", True),
            ("docs/a/b.txt", "docs/**", True),
            ("docs", "docs/**", False),
            ("crates/pos-owner-bridge-windows/src/a.rs", "crates/pos-owner-bridge-windows/**", True),
            ("crates/pos-owner-bridge-windows-extra/a.rs", "crates/pos-owner-bridge-windows/**", False),
            ("x/Cargo.toml", "Cargo.toml", False),
            ("Cargo.toml", "Cargo.toml", True),
            ("src/a.rs", "**", True),
            ("ab", "a?", True),
            ("a/b", "a?b", False),
        ):
            with self.subTest(path=path, pattern=pattern):
                self.assertEqual(picomatch(path, pattern), expected)
        for pattern in ("{a,b}", "a/[bc]", "!a", "a**b", "+(a)"):
            with self.subTest(pattern=pattern), self.assertRaises(AssertionError):
                picomatch_regex(pattern)
        self.assertFalse(scope_matches("docs/a.rs", ["**", "!docs/**"]))
        self.assertTrue(scope_matches("src/a.rs", ["**", "!docs/**"]))

    def test_owner_windows_scope_rejects_weakened_resolution(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        native = load_workflow(ROOT / ".github/workflows/owner-bridge-windows.yml")

        def step(w):
            return next(s for s in w["jobs"]["ci_change_scope"]["steps"] if s.get("id") == "owner_windows")

        for change in (
            lambda w: w["jobs"]["ci_change_scope"]["outputs"].update(
                owner_windows="${{ steps.scope.outputs.owner_windows }}"),
            lambda w: w["jobs"]["ci_change_scope"]["outputs"].update(
                owner_windows="${{ steps.owner_windows.outputs.owner_windows || 'false' }}"),
            lambda w: w["jobs"]["ci_change_scope"]["outputs"].pop("owner_windows"),
            lambda w: step(w).update(run=step(w)["run"].replace(
                '"${DETECTED}" = false', '"${DETECTED}" != true')),
            lambda w: step(w)["env"].update(DETECTED="${{ steps.scope.outputs.owner_windows }}"),
            lambda w: step(w).update(**{"if": "steps.scope.outcome == 'success'"}),
            lambda w: step(w).update(run=step(w)["run"].replace("10#${CHANGED_FILES} >= 3000", "10#${CHANGED_FILES} > 3000")),
            lambda w: step(w).update(run=step(w)["run"].replace("10#${CHANGED_FILES}", "CHANGED_FILES")),
            lambda w: step(w).update(run=step(w)["run"].replace(" -f per_page=100", "")),
            lambda w: step(w).update(run=step(w)["run"].replace("--method GET ", "")),
            lambda w: step(w).update(run=step(w)["run"].replace('select(.status == "renamed")', 'select(.status == "moved")')),
            lambda w: step(w).update(run=step(w)["run"].replace("elif ! renamed=", "elif renamed=")),
            lambda w: step(w)["env"].pop("GH_TOKEN"),
            lambda w: step(w).update(**{"continue-on-error": True}),
            lambda w: w["jobs"]["ci_change_scope"]["steps"].remove(step(w)),
        ):
            mutated = copy.deepcopy(workflow)
            change(mutated)
            with self.subTest(change=change), self.assertRaises(AssertionError):
                assert_owner_windows_lane(mutated, native)

    def test_codeql_prepares_inputs_before_unchanged_analysis(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH.with_name("codeql.yml"))
        assert_codeql_preparation_contract(workflow)
        steps = workflow["jobs"]["analyze"]["steps"]
        installer = (ROOT / "plugins/community/examples/compatibility-prototype/install-tools.sh").read_text()
        for prefix in ("url=", "digest="):
            value = next(line[len(prefix):] for line in steps[1]["run"].splitlines()
                         if line.startswith(prefix))
            self.assertIn(value, installer)
        for step in steps[1:3]:
            subprocess.run(["bash", "-n"], input=step["run"], text=True, check=True)
        source = steps[2]["run"].split("python3 - <<'PY'\n")[1].split("\nPY\n")[0]
        tree = ast.parse(source)
        self.assertEqual(len(tree.body), 2)
        call = tree.body[1].value
        self.assertEqual(call.func.attr, "write_text")
        self.assertEqual(ast.literal_eval(call.func.value.args[0]), "scripts/asan/Cargo.toml")
        self.assertEqual(tomllib.loads(ast.literal_eval(call.args[0])), {
            "package": {"name": "pigloros-asan-extraction-canary", "version": "0.0.0", "edition": "2021"},
            "bin": [{"name": "intentional-leak", "path": "intentional-leak.rs"}],
            "workspace": {},
        })

    def test_codeql_preparation_refuses_missing_or_weakened_inputs(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH.with_name("codeql.yml"))
        for index in (1, 2):
            for key, value in (("if", "false"), ("continue-on-error", True), ("env", {})):
                changed = copy.deepcopy(workflow)
                changed["jobs"]["analyze"]["steps"][index][key] = value
                with self.assertRaises(AssertionError):
                    assert_codeql_preparation_contract(changed)
            changed = copy.deepcopy(workflow)
            del changed["jobs"]["analyze"]["steps"][index]
            with self.assertRaises(AssertionError):
                assert_codeql_preparation_contract(changed)
        for original, replacement in (("sha256sum --check --strict -", "true"),
                                      ("test ! -e scripts/asan/Cargo.toml", "true"),
                                      ("test -s", "test -e")):
            changed = copy.deepcopy(workflow)
            for step in changed["jobs"]["analyze"]["steps"][1:3]:
                step["run"] = step["run"].replace(original, replacement)
            with self.assertRaises(AssertionError):
                assert_codeql_preparation_contract(changed)
        changed = copy.deepcopy(workflow)
        changed["jobs"]["analyze"]["steps"][3]["with"]["config"] = "paths-ignore: [scripts]"
        with self.assertRaises(AssertionError):
            assert_codeql_preparation_contract(changed)
        changed = copy.deepcopy(workflow)
        changed["jobs"]["analyze"]["steps"][1]["run"] += "true || true\n"
        with self.assertRaises(AssertionError):
            assert_codeql_preparation_contract(changed)

    def test_codeql_preparation_refuses_non_executing_checksum_text(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH.with_name("codeql.yml"))
        run = workflow["jobs"]["analyze"]["steps"][1]["run"]
        checksum = next(line for line in run.splitlines()
                        if line.startswith("printf ") and "sha256sum --check" in line)
        quoted = "'" + checksum.replace("'", "'\\''") + "'"
        for replacement in ("# " + checksum, ": " + quoted, "echo " + quoted,
                            "if false; then\n" + checksum + "\nfi",
                            "unused_checksum() {\n" + checksum + "\n}"):
            changed = copy.deepcopy(workflow)
            changed["jobs"]["analyze"]["steps"][1]["run"] = run.replace(checksum, replacement)
            with self.assertRaises(AssertionError):
                assert_codeql_preparation_contract(changed)

    def test_codeql_generates_bindings_for_each_declared_rust_guest_owner(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH.with_name("codeql.yml"))
        run = workflow["jobs"]["analyze"]["steps"][1]["run"]
        # Execute the real owner-selection/generation section, not downloads.
        program = run.split('"$tools_dir/wit-bindgen" --version\n', 1)[1]
        program = program.rsplit('test -z "$(git diff --name-only HEAD)"', 1)[0]
        prototype = pathlib.Path("plugins/community/examples/compatibility-prototype")
        cases = (
            ("legacy", False, True),
            ("both", True, True),
            ("partial-probe", True, False),
            ("missing-required-source", False, False),
            ("preexisting-output", False, False),
            ("generator-failure", True, False),
            ("empty-output", True, False),
            ("dangling-probe", False, False),
            ("probe-is-file", False, False),
            ("linked-probe", False, False),
        )
        for case, has_probe, success in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(
                prefix="pigloros-codeql-owners-",
                dir="/dev/shm" if pathlib.Path("/dev/shm").is_dir() else None,
            ) as temporary:
                root = pathlib.Path(temporary)
                tools = root / "tools"
                tools.mkdir()
                generator = tools / "wit-bindgen"
                generator.write_text(
                    '#!/bin/sh\nset -eu\n'
                    'test "$#" -eq 6\n'
                    'test "$1" = rust\n'
                    'test "$2" = --world\n'
                    'test "$3" = community-plugin\n'
                    'test "$4" = --out-dir\n'
                    'test "$6" = plugins/community/wit\n'
                    'test -d "$6"\n'
                    'printf "%s\\n" "$5" >> "$PIGLOROS_CODEQL_OWNER_TRACE"\n'
                    'case "$PIGLOROS_CODEQL_STUB_MODE" in\n'
                    '  generator-failure) exit 37 ;;\n'
                    '  empty-output) : > "$5/community_plugin.rs" ;;\n'
                    '  *) printf "generated\\n" > "$5/community_plugin.rs" ;;\n'
                    'esac\n',
                    encoding="utf-8",
                )
                generator.chmod(0o755)
                (root / "plugins/community/wit").mkdir(parents=True)
                guests = ["rust-guest", "probe-guest"] if has_probe else ["rust-guest"]
                for guest in guests:
                    directory = root / prototype / guest
                    (directory / "src").mkdir(parents=True)
                    if case != "partial-probe" or guest != "probe-guest":
                        (directory / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
                    if case != "missing-required-source":
                        (directory / "src/lib.rs").write_text("// owner\n", encoding="utf-8")
                if case == "preexisting-output":
                    (root / prototype / "rust-guest/generated").mkdir()
                elif case == "dangling-probe":
                    (root / prototype / "probe-guest").symlink_to("absent-owner")
                elif case == "probe-is-file":
                    (root / prototype / "probe-guest").write_text("not a directory\n", encoding="utf-8")
                elif case == "linked-probe":
                    other = root / "separate-owner"
                    (other / "src").mkdir(parents=True)
                    (other / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
                    (other / "src/lib.rs").write_text("// owner\n", encoding="utf-8")
                    (root / prototype / "probe-guest").symlink_to(other, target_is_directory=True)
                trace = root / "owner-trace"
                result = subprocess.run(
                    ["bash", "-c", "set -euo pipefail\n"
                     + "tools_dir=" + shlex.quote(str(tools)) + "\n" + program],
                    cwd=root,
                    env=dict(os.environ, PIGLOROS_CODEQL_OWNER_TRACE=str(trace),
                             PIGLOROS_CODEQL_STUB_MODE=case),
                    capture_output=True, text=True, check=False, timeout=10,
                )
                self.assertEqual(result.returncode == 0, success, result.stderr)
                if success:
                    self.assertEqual(
                        trace.read_text(encoding="utf-8").splitlines(),
                        [str(prototype / guest / "generated") for guest in guests],
                    )
                    for guest in guests:
                        self.assertEqual(
                            (root / prototype / guest / "generated/community_plugin.rs")
                            .read_text(encoding="utf-8"), "generated\n",
                        )

    def test_package_scope_is_trusted_and_defaults_to_the_workspace(self) -> None:
        assert_rust_package_scope(load_workflow(CI_WORKFLOW_PATH))

    def test_package_scope_rejects_weakened_resolution_or_consumers(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)

        def step(w: dict) -> dict:
            return next(s for s in w["jobs"]["ci_change_scope"]["steps"]
                        if s.get("id") == "rust_packages")

        def env_of(job: str, name: str):
            def find(w: dict) -> dict:
                return next(s for s in w["jobs"][job]["steps"] if s.get("name") == name)["env"]
            return find

        shard_env = env_of("test-shard", TEST_SHARD_STEP["name"])
        clippy_env = env_of("clippy", CLIPPY_WORKSPACE_STEP["name"])
        doc_env = env_of("test", WORKSPACE_DOCTEST_SUMMARY_STEP["name"])
        coverage_step = lambda w: next(  # noqa: E731
            s for s in w["jobs"]["coverage"]["steps"] if "run" in s)
        for label, change in (
            ("output from paths-filter", lambda w: w["jobs"]["ci_change_scope"]["outputs"].update(
                rust_packages="${{ steps.scope.outputs.rust_packages }}")),
            ("output default narrowed", lambda w: w["jobs"]["ci_change_scope"]["outputs"].update(
                rust_packages="${{ steps.rust_packages.outputs.rust_packages || '-p pos-core' }}")),
            ("doc output dropped", lambda w: w["jobs"]["ci_change_scope"]["outputs"].pop(
                "rust_doc_packages")),
            ("step removed", lambda w: w["jobs"]["ci_change_scope"]["steps"].remove(step(w))),
            ("step conditional", lambda w: step(w).update(**{"if": "always()"})),
            ("step tolerant", lambda w: step(w).update(**{"continue-on-error": True})),
            ("push scoped", lambda w: step(w)["env"].update(DETECTED="${{ steps.scope.outputs.rust }}")),
            ("queue scoped", lambda w: step(w).update(run=step(w)["run"].replace(
                "trunk-merge/*", "trunk-queue/*"))),
            ("truncated list", lambda w: step(w).update(run=step(w)["run"].replace(
                ">= 3000", "> 3000"))),
            ("unchecked output", lambda w: step(w).update(run=step(w)["run"].replace(
                '&& [[ "${candidate}" =~ ${selection} ]] \\\n', ""))),
            ("default narrowed", lambda w: step(w).update(run=step(w)["run"].replace(
                "packages=--workspace\n", "packages='-p pos-core'\n", 1))),
            ("moved before detection", lambda w: w["jobs"]["ci_change_scope"]["steps"].insert(
                1, w["jobs"]["ci_change_scope"]["steps"].pop(
                    w["jobs"]["ci_change_scope"]["steps"].index(step(w))))),
            ("second producer", lambda w: w["jobs"]["ci_change_scope"]["steps"].insert(
                -1, {"name": "x", "run": "echo rust_packages=-p a >> \"$GITHUB_OUTPUT\""})),
            ("scoped on push", lambda w: shard_env(w).update(
                CARGO_PACKAGES="${{ needs.ci_change_scope.outputs.rust_packages }}")),
            ("missing output narrowed", lambda w: clippy_env(w).update(
                CARGO_PACKAGES="${{ github.event_name == 'pull_request' && "
                "needs.ci_change_scope.outputs.rust_packages || '-p pos-core' }}")),
            ("hard-coded selection", lambda w: clippy_env(w).update(CARGO_PACKAGES="-p pos-core")),
            ("doc scope on push", lambda w: doc_env(w).update(
                CARGO_DOC_PACKAGES="${{ needs.ci_change_scope.outputs.rust_doc_packages }}")),
            ("phase-1 job unscoped", lambda w: shard_env(w).pop("CARGO_PACKAGES")),
            ("scope in run text", lambda w: shard_env(w).update(
                SCOPE="${{ needs.ci_change_scope.outputs.rust_packages }}")),
            ("scope in job env", lambda w: w["jobs"]["test-shard"].update(
                env={"CARGO_PACKAGES": SCOPED_PACKAGES})),
            ("coverage scoped", lambda w: coverage_step(w).setdefault("env", {}).update(
                CARGO_PACKAGES=SCOPED_PACKAGES)),
            ("cargo-crap scoped", lambda w: w["jobs"]["cargo-crap"]["steps"][-1].setdefault(
                "env", {}).update(CARGO_PACKAGES=SCOPED_PACKAGES)),
            ("shard runs every package", lambda w: next(
                s for s in w["jobs"]["test-shard"]["steps"]
                if s.get("name") == TEST_SHARD_STEP["name"]).update(
                run=TEST_SHARD_STEP["run"].replace('"${packages[@]}"', "--workspace"))),
            ("shard passes empty workspace", lambda w: next(
                s for s in w["jobs"]["test-shard"]["steps"]
                if s.get("name") == TEST_SHARD_STEP["name"]).update(
                run=TEST_SHARD_STEP["run"].replace("no_tests=fail", "no_tests=pass"))),
            ("doctest summary skipped", lambda w: next(
                s for s in w["jobs"]["test"]["steps"]
                if s.get("name") == WORKSPACE_DOCTEST_SUMMARY_STEP["name"]).update(
                run="true\n")),
        ):
            mutated = copy.deepcopy(workflow)
            change(mutated)
            with self.subTest(change=label), self.assertRaises(AssertionError):
                assert_rust_package_scope(mutated)

    def resolve_package_scope(
        self, *, event: str = "pull_request", detected: str = "true",
        head_ref: str = "feature/scope", changed: str = "1", number: str = "848",
        gh_status: int = 0, listing: str | None = None, python_stub: str | None = None,
        with_script: bool = True,
    ) -> tuple[dict[str, str], list[str], str]:
        """Run the resolving step against a small workspace with a fake gh."""
        if listing is None:
            listing = '{"filename":"crates/a/src/lib.rs","previous_filename":null}\n'
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for member, manifest in (
                ("crates/a", '[package]\nname = "a"\n'),
                ("crates/b", '[package]\nname = "b"\n[dependencies]\na = { path = "../a" }\n'),
                ("apps/c", '[package]\nname = "c"\n[dev-dependencies]\nb = { path = "../../crates/b" }\n'),
            ):
                (root / member / "src").mkdir(parents=True)
                (root / member / "Cargo.toml").write_text(manifest, encoding="utf-8")
                entry = "main.rs" if member == "apps/c" else "lib.rs"
                (root / member / "src" / entry).write_text("\n", encoding="utf-8")
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["crates/*", "apps/c"]\n', encoding="utf-8")
            (root / ".github").mkdir()
            (root / ".github/rust-scope.yml").write_bytes(FILTER_PATH.read_bytes())
            if with_script:
                (root / "scripts").mkdir()
                (root / "scripts/affected_packages.py").write_bytes(
                    (ROOT / "scripts/affected_packages.py").read_bytes())
            tools = root / "bin"
            tools.mkdir()
            calls = root / "gh-calls"
            (tools / "gh").write_text(
                "#!/usr/bin/env bash\n"
                'printf \'%s\\0\' "$@" >> "${GH_CALLS}"\n'
                'printf \'%s\' "${GH_FAKE_OUTPUT}"\n'
                'exit "${GH_FAKE_STATUS}"\n',
                encoding="utf-8",
            )
            (tools / "gh").chmod(0o755)
            if python_stub is not None:
                (tools / "python3").write_text(
                    "#!/usr/bin/env bash\n" + python_stub, encoding="utf-8")
                (tools / "python3").chmod(0o755)
            output = root / "output"
            temp = root / "runner-temp"
            temp.mkdir()
            env = RUST_PACKAGES_SCOPE_STEP["env"]
            self.assertEqual(set(env), {"EVENT_NAME", "DETECTED", "HEAD_REF", "CHANGED_FILES",
                                        "PULL_NUMBER", "GH_TOKEN"})
            completed = subprocess.run(
                ["bash", "-e", "-c", RUST_PACKAGES_SCOPE_STEP["run"]], check=True,
                capture_output=True, text=True, cwd=root,
                env=dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}",
                         EVENT_NAME=event, DETECTED=detected, HEAD_REF=head_ref,
                         CHANGED_FILES=changed, PULL_NUMBER=number, RUNNER_TEMP=str(temp),
                         GITHUB_REPOSITORY="owner/repository", GITHUB_OUTPUT=str(output),
                         GH_CALLS=str(calls), GH_FAKE_STATUS=str(gh_status),
                         GH_FAKE_OUTPUT=listing),
            )
            values = dict(
                line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
            arguments = calls.read_text(encoding="utf-8").split("\0")[:-1] if calls.exists() else []
            return values, arguments, completed.stdout

    FULL_SCOPE = {"rust_packages": "--workspace", "rust_doc_packages": "--workspace"}

    def test_package_scope_selects_affected_members_on_a_pull_request(self) -> None:
        values, calls, _ = self.resolve_package_scope()
        self.assertEqual(values, {"rust_packages": "-p a -p b -p c",
                                  "rust_doc_packages": "-p a -p b"})
        self.assertEqual(calls, [
            "api", "--method", "GET", "--paginate", "-f", "per_page=100",
            "repos/owner/repository/pulls/848/files",
            "--jq", ".[] | {filename, previous_filename}",
        ])
        values, _, _ = self.resolve_package_scope(
            listing='{"filename":"apps/c/src/main.rs"}\n')
        self.assertEqual(values, {"rust_packages": "-p c", "rust_doc_packages": "none"})

    def test_package_scope_runs_the_workspace_whenever_unsure(self) -> None:
        for label, overrides in (
            ("push", {"event": "push"}),
            ("dispatch", {"event": "workflow_dispatch"}),
            ("failed detection", {"detected": ""}),
            ("documentation only", {"detected": "false"}),
            ("merge queue", {"head_ref": "trunk-merge/main/1"}),
            ("api limit", {"changed": "3000"}),
            ("zero-padded api limit", {"changed": "03000"}),
            ("unknown count", {"changed": ""}),
            ("malformed count", {"changed": "1; true"}),
            ("count mismatch", {"changed": "2"}),
            ("unknown pull request", {"number": ""}),
            ("api failure", {"gh_status": 1}),
            ("empty listing", {"listing": ""}),
            ("root manifest", {"listing": '{"filename":"Cargo.toml"}\n'}),
            ("lockfile", {"listing": '{"filename":"Cargo.lock"}\n'}),
            ("rename out of a member", {"listing":
                '{"filename":"crates/a/x.rs","previous_filename":"scripts/x.rs"}\n'}),
            ("base without the script", {"with_script": False}),
            ("script failure", {"python_stub": "exit 1\n"}),
            ("one line", {"python_stub": "echo rust_packages=-p a\n"}),
            ("extra line", {"python_stub":
                "printf 'rust_packages=-p a\\nrust_doc_packages=-p a\\nx=y\\n'\n"}),
            ("swapped lines", {"python_stub":
                "printf 'rust_doc_packages=-p a\\nrust_packages=-p a\\n'\n"}),
            ("injected arguments", {"python_stub":
                "printf 'rust_packages=-p a --exclude b\\nrust_doc_packages=-p a\\n'\n"}),
            ("shell text", {"python_stub":
                "printf 'rust_packages=-p a;true\\nrust_doc_packages=-p a\\n'\n"}),
            ("empty selection", {"python_stub":
                "printf 'rust_packages=\\nrust_doc_packages=none\\n'\n"}),
            ("workspace without doctests", {"python_stub":
                "printf 'rust_packages=--workspace\\nrust_doc_packages=none\\n'\n"}),
            ("malformed doc selection", {"python_stub":
                "printf 'rust_packages=-p a\\nrust_doc_packages=-p\\n'\n"}),
        ):
            with self.subTest(label=label):
                values, calls, _ = self.resolve_package_scope(**overrides)
                self.assertEqual(values, self.FULL_SCOPE)
                if label in ("push", "dispatch", "failed detection", "documentation only",
                             "merge queue", "api limit", "zero-padded api limit"):
                    self.assertEqual(calls, [])

    def test_scope_jobs_use_trusted_base_and_fail_closed(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        scope = workflow["jobs"]["ci_change_scope"]
        steps = scope["steps"]
        self.assertEqual(
            steps[0]["with"]["ref"],
            "${{ github.event.pull_request.base.sha }}",
        )
        filter_step = next(step for step in steps if step.get("id") == "scope")
        self.assertEqual(filter_step["with"]["filters"], ".github/rust-scope.yml")
        self.assertIn("hashFiles('.github/rust-scope.yml') != ''", filter_step["if"])
        self.assertIs(filter_step["continue-on-error"], True)
        fallback_step = next(step for step in steps if step.get("id") == "fallback")
        self.assertEqual(fallback_step["if"], "steps.scope.outcome == 'failure'")
        self.assertIn("printf 'rust=true\\n' >> \"$GITHUB_OUTPUT\"", fallback_step["run"])
        full_step = next(step for step in steps if step.get("id") == "full")
        self.assertIn("hashFiles('.github/rust-scope.yml') == ''", full_step["if"])
        self.assertEqual(
            scope["outputs"]["rust"],
            "${{ steps.fallback.outputs.rust || steps.scope.outputs.rust || "
            "steps.full.outputs.rust }}",
        )

    def test_codeql_runs_for_documentation_only_pull_requests(self) -> None:
        # The main ruleset's code_scanning rule needs an uploaded analysis for
        # every PR head, so a Rust-scope skip would leave docs-only PRs unmergeable.
        workflow = load_workflow(CI_WORKFLOW_PATH)
        jobs = workflow["jobs"]
        condition = " ".join(jobs["codeql"]["if"].split())
        self.assertEqual(jobs["codeql"]["needs"], ["ci_change_scope", "core-gate"])
        self.assertEqual(condition, "${{ !cancelled() && needs.ci_change_scope.result == 'success' && "
                         "(needs.core-gate.result == 'success' || "
                         "needs.ci_change_scope.outputs.rust == 'false') }}")
        self.assertNotIn("cargo-crap", condition)
        required = jobs["codeql-required"]
        self.assertEqual(required["name"], "CodeQL (Rust)")
        self.assertEqual(required["needs"], ["codeql"])
        self.assertIn('test "${CODEQL_RESULT}" = success', required["steps"][0]["run"])
        standard = jobs["standard-gate"]["steps"][0]["run"]
        self.assertIn('test "${CODEQL_RESULT}" = success', standard)
        self.assertNotIn('"${CODEQL_RESULT}"', standard.split("for result in")[1])
        codeql = load_workflow(CODEQL_WORKFLOW_PATH)
        self.assertEqual(list(codeql["jobs"]), ["analyze"])
        self.assertNotIn("if", codeql["jobs"]["analyze"])

    def test_documentation_only_paths_skip_rust_gate(self) -> None:
        paths = [
            "README.md",
            "guide/topic.mdx",
            "adr/decision.adoc",
            "notes/history.rst",
            ".agents/skills/example.md",
            "docs/reference.txt",
        ]
        self.assertFalse(rust_gate_required(paths, self.patterns))

    def test_unknown_and_build_inputs_require_rust_gate(self) -> None:
        paths = ("src/lib.rs", "Cargo.toml", "plugin.wit", ".github/workflows/ci.yml")
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(rust_gate_required([path], self.patterns))

    def test_deleted_and_renamed_rust_inputs_require_rust_gate(self) -> None:
        self.assertTrue(rust_gate_required(["old.rs"], self.patterns))
        self.assertTrue(rust_gate_required(["old.rs", "moved.md"], self.patterns))

    def test_ci_gate_distinguishes_scope_skips_from_unconditional_jobs(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        gate = workflow["jobs"]["ci-gate"]
        self.assertIn("ci_change_scope", gate["needs"])
        self.assertEqual(
            gate["steps"][0]["env"]["SCOPE_JOB_RESULT"],
            "${{ needs.ci_change_scope.result }}",
        )
        self.assertEqual(
            gate["steps"][0]["env"]["RUST_SCOPE_RESULT"],
            "${{ needs.ci_change_scope.outputs.rust }}",
        )
        run = gate["steps"][0]["run"]
        normalized_run = " ".join(run.replace("\\\n", " ").split())
        self.assertIn(
            "for result_name in PREFLIGHT_RESULT CORE_RESULT STANDARD_RESULT ASAN_RESULT",
            normalized_run,
        )
        self.assertIn('expected_mutation=skipped', run)
        self.assertIn('expected_mutation=success', run)
        self.assertIn('"${RUST_SCOPE_RESULT}" = true', run)
        self.assertIn('"${SCOPE_JOB_RESULT}" != "success"', run)

    def test_core_gates_run_after_successful_preflight_on_push(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        assert_core_jobs_run_on_main_push(workflow)

    def test_windows_owner_lane_is_blocking_and_runs_beside_core(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        native = load_workflow(ROOT / ".github/workflows/owner-bridge-windows.yml")
        assert_owner_windows_lane(workflow, native)
        assert_standard_stage_runner_cap(workflow)

    def test_every_native_evidence_step_is_mandatory_and_ordered(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        native = load_workflow(ROOT / ".github/workflows/owner-bridge-windows.yml")
        assert_owner_windows_lane(workflow, native)
        steps = native["jobs"]["owner-bridge-windows"]["steps"]
        for index, _ in enumerate(steps):
            for action in ("remove", "skip", "ignore", "fabricate", "duplicate"):
                changed = copy.deepcopy(native)
                candidates = changed["jobs"]["owner-bridge-windows"]["steps"]
                if action == "remove": candidates.pop(index)
                elif action == "skip": candidates[index]["if"] = "false"
                elif action == "ignore": candidates[index]["continue-on-error"] = True
                elif action == "fabricate": candidates[index] = {"run": "echo fabricated > coverage.json"}
                else: candidates.insert(index, copy.deepcopy(candidates[index]))
                with self.subTest(index=index, action=action), self.assertRaises(AssertionError):
                    assert_owner_windows_lane(workflow, changed)
        changed = copy.deepcopy(native)
        changed["jobs"]["owner-bridge-windows"]["steps"].reverse()
        with self.assertRaises(AssertionError):
            assert_owner_windows_lane(workflow, changed)

    def test_native_graph_controls_types_and_producer_indirection_fail_closed(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        native = load_workflow(ROOT / ".github/workflows/owner-bridge-windows.yml")
        for mutate in (
            lambda w: w.update(permissions={"contents": "write"}),
            lambda w: w.update(env={"FAKE_COVERAGE": "1"}),
            lambda w: w[True].update(pull_request_target={}),
            lambda w: w["jobs"].update(fabricate={"runs-on": "ubuntu-latest"}),
            lambda w: w["jobs"]["owner-bridge-windows"].update(**{"timeout-minutes": 90.0}),
            lambda w: w["jobs"]["owner-bridge-windows"].update(**{"if": "false"}),
            lambda w: w["jobs"]["owner-bridge-windows"]["steps"][0]["with"].update(**{"persist-credentials": 0}),
        ):
            changed = copy.deepcopy(native); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(AssertionError):
                assert_owner_windows_lane(workflow, changed)
        native_policy.check_repository()
        original = native_policy.producer_sources()
        for name, source in original.items():
            for changed in ("", source + "\n# unreviewed producer\n", "print('fabricated')\n"):
                sources = dict(original, **{name: changed})
                with self.subTest(name=name), self.assertRaises(native_policy.PolicyError):
                    native_policy.check(native, sources)
        with self.assertRaises(native_policy.PolicyError):
            native_policy.check(native, {})

    def test_desktop_observer_cannot_change_native_evidence_or_control_processes(self) -> None:
        native = load_workflow(ROOT / ".github/workflows/owner-bridge-windows.yml")
        coverage = native["jobs"]["owner-bridge-windows"]["steps"][9]
        for before, after in (
            ("--include-ignored", "--include-ignored --skip native"),
            (" --nocapture", ""),
            ("$nativeResult = $LASTEXITCODE", "$nativeResult = 0"),
            ("[System.IO.File]::WriteAllText($marker, 'stop')", "Write-Output 'not stopped'"),
        ):
            changed = copy.deepcopy(native)
            run = changed["jobs"]["owner-bridge-windows"]["steps"][9]["run"]
            self.assertEqual(run.count(before), 1)
            changed["jobs"]["owner-bridge-windows"]["steps"][9]["run"] = run.replace(before, after)
            with self.assertRaises(native_policy.PolicyError):
                native_policy.check(changed)
        self.assertIn("cargo llvm-cov", coverage["run"])
        # A hang must fail this step (so failure-only diagnostics run) and the
        # observer must stream live rather than only after the step returns.
        self.assertEqual(coverage["timeout-minutes"], 65)
        self.assertIn("-NoNewWindow -PassThru", coverage["run"])
        self.assertNotIn("Receive-Job", coverage["run"])
        for change in (
            lambda step: step.pop("timeout-minutes"),
            lambda step: step.update(**{"timeout-minutes": 90}),
            lambda step: step.update(run=step["run"].replace(
                "-NoNewWindow -PassThru", "-NoNewWindow -PassThru -RedirectStandardOutput observer.log")),
        ):
            changed = copy.deepcopy(native)
            change(changed["jobs"]["owner-bridge-windows"]["steps"][9])
            with self.assertRaises(native_policy.PolicyError):
                native_policy.check(changed)
        for name in ("Export failed native coverage diagnostics", "Retain failed native coverage diagnostics"):
            step = next(s for s in native["jobs"]["owner-bridge-windows"]["steps"] if s.get("name") == name)
            self.assertEqual(step["if"], "${{ failure() && !cancelled() && steps.coverage.outcome == 'failure' }}")
        sources = native_policy.producer_sources()
        name = "scripts/observe-owner-desktop.ps1"
        for payload in ("Stop-Process -Id 1", "Get-CimInstance Win32_Process | Select-Object CommandLine"):
            altered = dict(sources, **{name: sources[name] + "\n" + payload})
            with self.assertRaises(native_policy.PolicyError):
                native_policy.check(native, altered)

    def test_windows_owner_lane_rejects_missing_or_weakened_gates(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        native = load_workflow(ROOT / ".github/workflows/owner-bridge-windows.yml")
        for change in (
            lambda w: w["jobs"].pop("owner-bridge-windows"),
            lambda w: w["jobs"]["owner-bridge-windows"].update(needs=["ci_change_scope"]),
            lambda w: w["jobs"]["owner-bridge-windows"].update(**{"continue-on-error": True}),
            lambda w: w["jobs"]["owner-bridge-windows"].update(
                **{"if": "${{ needs.ci_change_scope.outputs.owner_windows == 'true' }}"}),
            lambda w: w["jobs"]["owner-bridge-windows"].update(
                **{"if": "${{ needs.ci_change_scope.outputs.rust == 'true' && "
                         "needs.ci_change_scope.outputs.owner_windows != 'false' && false }}"}),
            lambda w: w["jobs"]["owner-bridge-windows"].update(
                **{"if": "${{ needs.ci_change_scope.outputs.rust == 'true' && "
                         "github.event_name == 'pull_request' && "
                         "needs.ci_change_scope.outputs.owner_windows == 'true' }}"}),
            lambda w: w["jobs"]["preflight-gate"]["needs"].append("owner-bridge-windows"),
            lambda w: w["jobs"]["ci-gate"]["needs"].remove("owner-bridge-windows"),
            lambda w: w["jobs"]["cargo-crap"]["needs"].remove("owner-bridge-windows"),
            lambda w: w["jobs"]["standard-gate"]["needs"].append("owner-bridge-windows"),
            lambda w: w["jobs"]["rustdoc"]["needs"].append("cargo-crap"),
            lambda w: w["jobs"]["codeql"].update(needs=["ci_change_scope", "cargo-crap"]),
            lambda w: w["jobs"]["asan-build"]["needs"].append("cargo-crap"),
            lambda w: w["jobs"]["standard-gate"]["needs"].append("cargo-crap"),
            lambda w: w["jobs"]["mutation-checks"]["needs"].append("cargo-crap"),
            lambda w: w["jobs"]["asan"]["needs"].append("cargo-crap"),
            lambda w: w["jobs"]["ci-gate"]["steps"][0]["env"].update(OWNER_WINDOWS_RESULT="success"),
            lambda w: w["jobs"]["ci-gate"]["steps"][0]["env"].update(OWNER_WINDOWS_SCOPE="false"),
            lambda w: w["jobs"]["ci-gate"]["steps"][0].update(run="true"),
            lambda w: w["jobs"]["ci-gate"]["steps"][0].update(
                run=w["jobs"]["ci-gate"]["steps"][0]["run"].replace(
                    '"${OWNER_WINDOWS_SCOPE}" != false', '"${OWNER_WINDOWS_SCOPE}" = true')),
        ):
            mutated = copy.deepcopy(workflow)
            change(mutated)
            with self.assertRaises(AssertionError):
                assert_owner_windows_lane(mutated, native)

    def test_preflight_no_longer_waits_for_the_windows_owner_lane(self) -> None:
        gate = load_workflow(CI_WORKFLOW_PATH)["jobs"]["preflight-gate"]
        self.assertNotIn("owner-bridge-windows", gate["needs"])
        self.assertNotIn("OWNER_WINDOWS", gate["steps"][0]["run"])
        self.assertNotIn("OWNER_WINDOWS_RESULT", gate["steps"][0]["env"])

    def run_ci_gate(self, **overrides: str) -> bool:
        gate = load_workflow(CI_WORKFLOW_PATH)["jobs"]["ci-gate"]["steps"][0]
        env = dict(os.environ, **{name: "success" for name in gate["env"]})
        env.update(EVENT_NAME="pull_request", RUST_SCOPE_RESULT="true",
                   OWNER_WINDOWS_SCOPE="true")
        env.update(overrides)
        return subprocess.run(["bash", "-c", gate["run"]], env=env,
                              capture_output=True, check=False).returncode == 0

    def test_ci_gate_requires_the_windows_owner_result_exactly_when_in_scope(self) -> None:
        cases = (
            # event, rust scope, owner scope, required owner result
            ("pull_request", "true", "true", "success"),
            ("pull_request", "true", "", "success"),
            ("pull_request", "true", "unknown", "success"),
            ("pull_request", "true", "false", "skipped"),
            ("pull_request", "false", "true", "skipped"),
            ("pull_request", "false", "false", "skipped"),
            ("push", "true", "true", "success"),
            ("push", "true", "false", "success"),
            ("workflow_dispatch", "true", "false", "success"),
        )
        for event, rust, owner, expected in cases:
            mutation = "success" if event == "pull_request" and rust == "true" else "skipped"
            for result in ("success", "failure", "cancelled", "skipped", ""):
                with self.subTest(event=event, rust=rust, owner=owner, result=result):
                    self.assertEqual(
                        self.run_ci_gate(EVENT_NAME=event, RUST_SCOPE_RESULT=rust,
                                         OWNER_WINDOWS_SCOPE=owner, MUTATION_RESULT=mutation,
                                         CARGO_CRAP_RESULT="skipped" if rust == "false" else "success",
                                         OWNER_WINDOWS_RESULT=result),
                        result == expected,
                    )

    def test_asan_runs_beside_mutation_and_ci_gate_still_requires_both(self) -> None:
        jobs = load_workflow(CI_WORKFLOW_PATH)["jobs"]
        asan = jobs["asan"]
        self.assertEqual(asan["needs"], ["ci_change_scope", "standard-gate", "asan-build"])
        self.assertNotIn("mutation", asan["if"])
        self.assertIn("needs.standard-gate.result == 'success'", asan["if"])
        self.assertIn("needs.asan-build.result == 'success'", asan["if"])
        self.assertEqual(jobs["mutation-checks"]["needs"], ["ci_change_scope", "standard-gate"])
        for name in ("mutation-checks", "asan-gate"):
            self.assertIn(name, jobs["ci-gate"]["needs"])
        for mutation in ("failure", "cancelled", "skipped", ""):
            with self.subTest(mutation=mutation):
                self.assertFalse(self.run_ci_gate(MUTATION_RESULT=mutation))
        for asan in ("failure", "cancelled", "skipped", ""):
            with self.subTest(asan=asan):
                self.assertFalse(self.run_ci_gate(ASAN_RESULT=asan))
        self.assertTrue(self.run_ci_gate())
        self.assertFalse(self.run_ci_gate(EVENT_NAME="push", MUTATION_RESULT="success"))
        self.assertTrue(self.run_ci_gate(EVENT_NAME="push", MUTATION_RESULT="skipped"))

    def test_failed_native_diagnostics_cannot_qualify_or_weaken_measurement(self) -> None:
        native = load_workflow(ROOT / ".github/workflows/owner-bridge-windows.yml")
        for name, field, before, after in (
            ("Export failed native coverage diagnostics", "if", "steps.coverage.outcome == 'failure'", "steps.coverage.outcome == 'success'"),
            ("Export failed native coverage diagnostics", "run", "cargo llvm-cov report -p", "cargo llvm-cov -p"),
            ("Export failed native coverage diagnostics", "run", "failed-measurement-diagnostic-only", "qualified"),
            ("Export failed native coverage diagnostics", "run", "Get-ChildItem -LiteralPath $profileDirectory", "Get-ChildItem -LiteralPath $metadata.target_directory"),
            ("Export failed native coverage diagnostics", "run", "Join-Path $metadata.target_directory 'llvm-cov-target'", "$metadata.target_directory"),
            ("Export failed native coverage diagnostics", "run", "CARGO_LLVM_COV_TARGET_DIR", "CARGO_TARGET_DIR"),
            ("Retain failed native coverage diagnostics", "name", "owner-windows-failed-diagnostic-", "owner-windows-lcov-"),
            ("Retain failed native coverage diagnostics", "path", "owner-windows-failed-diagnostic/", "owner-windows.lcov"),
        ):
            changed = copy.deepcopy(native)
            step = next(s for s in changed["jobs"]["owner-bridge-windows"]["steps"] if s.get("name") == name)
            target = step["with"] if field in ("name", "path") else step
            self.assertIn(before, target[field])
            target[field] = target[field].replace(before, after)
            with self.subTest(name=name, field=field), self.assertRaises(native_policy.PolicyError):
                native_policy.check(changed)
        steps = native["jobs"]["owner-bridge-windows"]["steps"]
        measurement = next(s for s in steps if s.get("id") == "coverage")
        self.assertNotIn("continue-on-error", measurement)
        report = next(s for s in steps if s.get("name") == "Export failed native coverage diagnostics")
        self.assertIn("profile unavailable", report["run"])
        self.assertIn("failure()", report["if"])
        self.assertNotIn("--fail-under", report["run"])

    def test_windows_single_native_run_keeps_fixtures_and_documentation_required(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        native = load_workflow(ROOT / ".github/workflows/owner-bridge-windows.yml")
        steps = native["jobs"]["owner-bridge-windows"]["steps"]
        self.assertFalse(any("--skip" in step.get("run", "") for step in steps))
        commands = [step.get("run", "") for step in steps]
        self.assertEqual(sum("cargo llvm-cov -p pos-owner-bridge-windows" in run for run in commands), 1)
        runtime_at = next(index for index, step in enumerate(steps) if step.get("id") == "runtime")
        native_tests_at = next(index for index, step in enumerate(steps) if step.get("id") == "coverage")
        self.assertLess(runtime_at, native_tests_at)
        for name, before, after in (
            (
                "Measure only shim source coverage",
                "--no-fail-fast",
                "",
            ),
            (
                "Measure only shim source coverage",
                "-- --include-ignored",
                "-- --include-ignored --skip tests::native_window_environment_and_buffers_lifecycle",
            ),
            (
                "Measure only shim source coverage",
                "cargo llvm-cov -p",
                "cargo llvm-cov report -p",
            ),
            (
                "Test portable bridge, owner executable and native docs",
                "-p pos-owner-bridge -p piglor-owner",
                "-p pos-owner-bridge",
            ),
            (
                "Test portable bridge, owner executable and native docs",
                "--doc -- --include-ignored",
                "--no-run -- --include-ignored",
            ),
        ):
            mutated = copy.deepcopy(native)
            step = next(s for s in mutated["jobs"]["owner-bridge-windows"]["steps"] if s.get("name") == name)
            self.assertIn(before, step["run"])
            step["run"] = step["run"].replace(before, after)
            with self.subTest(name=name, before=before), self.assertRaises(AssertionError):
                assert_owner_windows_lane(workflow, mutated)

    def test_windows_full_file_coverage_rejects_weakened_or_missing_scopes(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        native = load_workflow(ROOT / ".github/workflows/owner-bridge-windows.yml")
        name = "Enforce both full-file Windows coverage floors"
        for before, after in (
            ("--fail-under-lines 99", "--fail-under-lines 98"),
            ("--fail-under-regions 99", "--fail-under-regions 98"),
            ("--fail-under-lines 95", "--fail-under-lines 94"),
            ("--fail-under-regions 80", "--fail-under-regions 79"),
            ("--scope safe", "--scope ffi"),
            ("--list-report", "--scope all"),
            ("$ffiResult = $LASTEXITCODE", "$ffiResult = 0"),
        ):
            mutated = copy.deepcopy(native)
            step = next(s for s in mutated["jobs"]["owner-bridge-windows"]["steps"] if s.get("name") == name)
            step["run"] = step["run"].replace(before, after)
            with self.subTest(before=before), self.assertRaises(AssertionError):
                assert_owner_windows_lane(workflow, mutated)
        for replacement in (None, "${{ success() }}"):
            mutated = copy.deepcopy(native)
            steps = mutated["jobs"]["owner-bridge-windows"]["steps"]
            step = next(s for s in steps if s.get("name") == name)
            if replacement is None:
                steps.remove(step)
            else:
                step["if"] = replacement
            with self.subTest(replacement=replacement), self.assertRaises(AssertionError):
                assert_owner_windows_lane(workflow, mutated)

    def test_parallel_validation_preserves_every_required_command(self) -> None:
        assert_parallel_validation_contract(load_workflow(CI_WORKFLOW_PATH))

    def test_owner_bridge_coverage_scope_runs_with_fixtures_and_real_metadata(self) -> None:
        jobs = load_workflow(CI_WORKFLOW_PATH)["jobs"]
        expected = (
            ("owner-bridge-policies", {
                "name": "Test Windows shim coverage exclusions",
                "run": "python scripts/test_owner_bridge_windows_cov_ignore.py",
            }),
            ("clippy", {
                "name": "Exercise Windows shim coverage exclusions with real metadata",
                "run": "set -euo pipefail\n"
                "cargo metadata --locked --no-deps --format-version 1 |\n"
                "  python scripts/owner_bridge_windows_cov_ignore.py > "
                '"${RUNNER_TEMP}/owner-bridge-windows-cov-ignore.txt"\n'
                'test -s "${RUNNER_TEMP}/owner-bridge-windows-cov-ignore.txt"\n',
            }),
        )
        for owner, step in expected:
            with self.subTest(job=owner):
                self.assertEqual(
                    [candidate for candidate in jobs[owner]["steps"]
                     if candidate.get("name") == step["name"]],
                    [step],
                )

    def test_native_width_counter_runs_on_the_actual_narrower_target(self) -> None:
        expected = {
            "name": "Exercise native-width canonical length arithmetic",
            "run": "cargo test -p pos-core --target i686-pc-windows-msvc --lib --locked "
            "canonical_length_tests -- --include-ignored",
        }
        steps = load_workflow(CI_WORKFLOW_PATH)["jobs"]["ledger-windows"]["steps"]
        self.assertEqual(
            [step for step in steps if step.get("name") == expected["name"]],
            [expected],
        )

    def test_parallel_validation_rejects_missing_or_weakened_commands(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        for owner, required in (
            ("feature-matrix", FEATURE_MATRIX_STEPS),
            ("test", (WORKSPACE_DOCTEST_STEP,)),
            ("rustdoc", (WORKSPACE_RUSTDOC_STEP,)),
        ):
            for expected in required:
                for change in ("remove", "if", "continue-on-error", "run"):
                    with self.subTest(owner=owner, step=expected["name"], change=change):
                        mutated = copy.deepcopy(workflow)
                        steps = mutated["jobs"][owner]["steps"]
                        step = next(s for s in steps if s.get("name") == expected["name"])
                        if change == "remove":
                            steps.remove(step)
                        else:
                            step[change] = True if change == "continue-on-error" else "false"
                        with self.assertRaisesRegex(AssertionError, "exact required step"):
                            assert_parallel_validation_contract(mutated)

    def test_rustdoc_contract_rejects_broken_cache_and_weakened_job(self) -> None:
        changes = (
            (
                "steps",
                [{"uses": RUST_CACHE_ACTION}, WORKSPACE_RUSTDOC_STEP],
                "broken documentation target cache",
            ),
            ("needs", ["ci_change_scope"], "standard-stage prerequisites"),
            ("if", "${{ always() }}", "standard-stage prerequisites"),
            ("timeout-minutes", 60, "blocking 30-minute limit"),
            ("continue-on-error", True, "blocking 30-minute limit"),
        )
        for field, value, message in changes:
            with self.subTest(field=field):
                mutated = copy.deepcopy(load_workflow(CI_WORKFLOW_PATH))
                mutated["jobs"]["rustdoc"][field] = value
                with self.assertRaisesRegex(AssertionError, message):
                    assert_parallel_validation_contract(mutated)

    def test_rustdoc_contract_rejects_weakened_environment(self) -> None:
        for variable, value in (("RUSTDOCFLAGS", ""), ("CARGO_INCREMENTAL", "1")):
            with self.subTest(variable=variable):
                mutated = copy.deepcopy(load_workflow(CI_WORKFLOW_PATH))
                step = next(
                    step for step in mutated["jobs"]["rustdoc"]["steps"]
                    if step.get("name") == WORKSPACE_RUSTDOC_STEP["name"]
                )
                step["env"][variable] = value
                with self.assertRaisesRegex(AssertionError, "exact required step"):
                    assert_parallel_validation_contract(mutated)

    def test_parallel_validation_rejects_an_omitted_feature_result(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        for change in ("needs", "env", "run"):
            with self.subTest(change=change):
                mutated = copy.deepcopy(workflow)
                gate = mutated["jobs"]["core-gate"]
                if change == "needs":
                    gate["needs"].remove("feature-matrix")
                elif change == "env":
                    gate["steps"][0]["env"]["FEATURE_MATRIX_RESULT"] = "success"
                else:
                    gate["steps"][0]["run"] = gate["steps"][0]["run"].replace(
                        'test "${FEATURE_MATRIX_RESULT}" = "${expected}"', "true"
                    )
                with self.assertRaisesRegex(AssertionError, "core-gate must"):
                    assert_parallel_validation_contract(mutated)

    def test_parallel_core_gate_executes_fail_closed_for_every_result(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        assert_parallel_validation_contract(workflow)
        # Execute only the inspected shell result checker, never Cargo commands.
        run = workflow["jobs"]["core-gate"]["steps"][0]["run"]
        results = {
            name.upper().replace("-", "_") + "_RESULT": "success"
            for name in CORE_GATE_JOB_NAMES
        }
        environment = dict(
            results, SCOPE_RESULT="success", PREFLIGHT_RESULT="success", RUST_SCOPE="true"
        )

        def verdict(env: dict[str, str]) -> int:
            return subprocess.run(
                ["/bin/bash", "-c", run], env=env, capture_output=True, check=False
            ).returncode

        self.assertEqual(verdict(environment), 0)
        for result in results:
            for state in ("failure", "cancelled", "skipped", ""):
                with self.subTest(result=result, state=state):
                    self.assertNotEqual(verdict(dict(environment, **{result: state})), 0)
        scoped = dict(environment, RUST_SCOPE="false")
        scoped.update(dict.fromkeys(results, "skipped"))
        self.assertEqual(verdict(scoped), 0)

    def test_core_workers_reclaim_sdk_headroom_before_cache_and_build(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        assert_core_sdk_headroom(workflow)
        program = workflow["jobs"]["test-shard"]["steps"][1]["run"]
        result = subprocess.run(
            ["bash", "-n"], input=program, text=True, capture_output=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_core_headroom_rejects_missing_duplicate_or_late_setup(self) -> None:
        for job_name in ("test-shard", "coverage"):
            for change in ("missing", "duplicate", "before-checkout", "after-cache"):
                with self.subTest(job=job_name, change=change):
                    workflow = copy.deepcopy(load_workflow(CI_WORKFLOW_PATH))
                    steps = workflow["jobs"][job_name]["steps"]
                    headroom = steps.pop(1)
                    if change == "duplicate":
                        steps[1:1] = [headroom, copy.deepcopy(headroom)]
                    elif change == "before-checkout":
                        steps.insert(0, headroom)
                    elif change == "after-cache":
                        steps.append(headroom)
                    with self.assertRaisesRegex(AssertionError, "SDK headroom"):
                        assert_core_sdk_headroom(workflow)

    def test_core_headroom_rejects_unsafe_cleanup_or_missing_receipts(self) -> None:
        edits = (
            ("/usr/share/dotnet/sdk", "/usr/share/dotnet"),
            ("/usr/local/lib/android/sdk", "/usr/local"),
            ("test ! -L", "true #"),
            ("readlink -e", "printf"),
            ("--one-file-system", ""),
            ("sudo du -sx -B1", "true #"),
            ("df -B1", "true #"),
            ("df -i", "true #"),
            ("set -euo pipefail", "set +e"),
        )
        for job_name in ("test-shard", "coverage"):
            for old, new in edits:
                with self.subTest(job=job_name, edit=old):
                    workflow = copy.deepcopy(load_workflow(CI_WORKFLOW_PATH))
                    steps = workflow["jobs"][job_name]["steps"]
                    # Mutate one consumer independently of the parsed YAML alias.
                    steps[1] = copy.deepcopy(steps[1])
                    self.assertIn(old, steps[1]["run"])
                    steps[1]["run"] = steps[1]["run"].replace(old, new)
                    with self.assertRaisesRegex(AssertionError, "SDK headroom"):
                        assert_core_sdk_headroom(workflow)

    def test_core_headroom_rejects_guard_bypasses_and_permissive_steps(self) -> None:
        for job_name in ("test-shard", "coverage"):
            for extra in (
                {"if": "${{ true }}"},
                {"if": "${{ runner.os == 'Linux' }}"},
                {"continue-on-error": True},
                {"shell": "bash {0} || true"},
                {"working-directory": "/tmp"},
            ):
                with self.subTest(job=job_name, extra=extra):
                    workflow = copy.deepcopy(load_workflow(CI_WORKFLOW_PATH))
                    steps = workflow["jobs"][job_name]["steps"]
                    steps[1] = copy.deepcopy(steps[1])
                    steps[1].update(extra)
                    with self.assertRaisesRegex(AssertionError, "SDK headroom"):
                        assert_core_sdk_headroom(workflow)

    def test_core_rust_caches_restore_on_prs_and_save_only_from_main(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        assert_core_rust_cache_contract(workflow)

    def test_core_cache_contract_rejects_missing_pull_request_trigger(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        mutated = copy.deepcopy(workflow)
        del workflow_triggers(mutated)["pull_request"]
        with self.assertRaisesRegex(AssertionError, "pull_request"):
            assert_core_rust_cache_contract(mutated)

    def test_core_cache_contract_rejects_filtered_pull_request_trigger(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        mutated = copy.deepcopy(workflow)
        workflow_triggers(mutated)["pull_request"] = {"branches": ["release"]}
        with self.assertRaisesRegex(AssertionError, "unfiltered pull_request"):
            assert_core_rust_cache_contract(mutated)

    def test_core_cache_contract_rejects_missing_main_push_trigger(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        mutated = copy.deepcopy(workflow)
        workflow_triggers(mutated)["push"]["branches"] = ["release"]
        with self.assertRaisesRegex(AssertionError, "main push"):
            assert_core_rust_cache_contract(mutated)

    def test_core_cache_contract_rejects_excluded_main_push_trigger(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        mutated = copy.deepcopy(workflow)
        workflow_triggers(mutated)["push"]["branches"] = ["main", "!main"]
        with self.assertRaisesRegex(AssertionError, "main push"):
            assert_core_rust_cache_contract(mutated)

    def test_core_cache_contract_rejects_path_filtered_main_push_trigger(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        for field, patterns in (
            ("paths", ["crates/**"]),
            ("paths-ignore", ["**"]),
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(workflow)
                workflow_triggers(mutated)["push"][field] = patterns
                with self.assertRaisesRegex(AssertionError, "main push"):
                    assert_core_rust_cache_contract(mutated)

    def test_core_cache_contract_rejects_unreachable_main_core_job(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        mutated = copy.deepcopy(workflow)
        mutated["jobs"]["fmt"]["if"] = "${{ github.event_name == 'pull_request' }}"
        with self.assertRaisesRegex(AssertionError, "reachable on a main push"):
            assert_core_rust_cache_contract(mutated)

    def test_core_cache_contract_rejects_unreachable_main_prerequisites(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        for job_name, field, value, message in (
            (
                "ci_change_scope",
                "if",
                "${{ github.event_name == 'pull_request' }}",
                "ci_change_scope must remain unconditional",
            ),
            (
                "ci_change_scope",
                "needs",
                ["trunk-pr"],
                "ci_change_scope must have no prerequisites",
            ),
            (
                "pinned-dependencies",
                "if",
                "${{ github.event_name == 'pull_request' }}",
                "pinned-dependencies must remain reachable on a main push",
            ),
            (
                "pinned-dependencies",
                "needs",
                "trunk-pr",
                "pinned-dependencies must wait for ci_change_scope",
            ),
            (
                "preflight-gate",
                "if",
                "${{ github.event_name == 'pull_request' }}",
                "preflight-gate must remain reachable on a main push",
            ),
            (
                "preflight-gate",
                "needs",
                ["trunk-pr"],
                "preflight-gate must retain scope and policy dependencies",
            ),
        ):
            with self.subTest(job=job_name):
                mutated = copy.deepcopy(workflow)
                mutated["jobs"][job_name][field] = value
                with self.assertRaisesRegex(AssertionError, message):
                    assert_core_rust_cache_contract(mutated)

    def test_core_cache_contract_requires_pinned_preflight_dependency(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        for policy_name in PREFLIGHT_POLICY_STEPS:
            with self.subTest(job=policy_name):
                mutated = copy.deepcopy(workflow)
                mutated["jobs"]["preflight-gate"]["needs"].remove(policy_name)
                with self.assertRaisesRegex(
                    AssertionError, "preflight-gate must retain scope and policy dependencies"
                ):
                    assert_core_rust_cache_contract(mutated)

    def test_split_policy_jobs_remain_reachable_preflight_inputs(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        for policy_name in ("source-policies", "owner-bridge-policies"):
            for field, value, message in (
                ("if", "${{ github.event_name == 'pull_request' }}",
                 f"{policy_name} must remain reachable on a main push"),
                ("needs", "trunk-pr", f"{policy_name} must wait for ci_change_scope"),
                (None, None, f"ci.yml must define {policy_name}"),
            ):
                with self.subTest(job=policy_name, field=field):
                    mutated = copy.deepcopy(workflow)
                    if field is None:
                        del mutated["jobs"][policy_name]
                    else:
                        mutated["jobs"][policy_name][field] = value
                    with self.assertRaisesRegex(AssertionError, message):
                        assert_core_rust_cache_contract(mutated)

    def test_preflight_policy_split_contract(self) -> None:
        assert_preflight_policy_split(load_workflow(CI_WORKFLOW_PATH))

    def test_preflight_policy_split_keeps_every_check_in_its_job(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        for policy_name, expected_steps in PREFLIGHT_POLICY_STEPS.items():
            for name in (step["name"] for step in expected_steps):
                with self.subTest(job=policy_name, step=name, change="missing"):
                    mutated = copy.deepcopy(workflow)
                    steps = mutated["jobs"][policy_name]["steps"]
                    steps.remove(next(s for s in steps if s.get("name") == name))
                    with self.assertRaisesRegex(AssertionError, LOST_POLICY_CHECK):
                        assert_preflight_policy_split(mutated)
                for other in (*PREFLIGHT_POLICY_STEPS, "fmt"):
                    if other == policy_name:
                        continue
                    for moved in (False, True):
                        change = f"{'moved' if moved else 'duplicated'} to {other}"
                        with self.subTest(job=policy_name, step=name, change=change):
                            mutated = copy.deepcopy(workflow)
                            steps = mutated["jobs"][policy_name]["steps"]
                            step = next(s for s in steps if s.get("name") == name)
                            if moved:
                                steps.remove(step)
                            mutated["jobs"][other]["steps"].append(copy.deepcopy(step))
                            with self.assertRaisesRegex(AssertionError, LOST_POLICY_CHECK):
                                assert_preflight_policy_split(mutated)

    def test_preflight_policy_split_rejects_weakened_jobs(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)

        def drop_one_command(job: dict) -> None:
            step = next(s for s in job["steps"][PREFLIGHT_POLICY_SETUP_STEPS:]
                        if len(s["run"].splitlines()) > 1)
            step["run"] = "".join(step["run"].splitlines(keepends=True)[1:])

        for policy_name in PREFLIGHT_POLICY_STEPS:
            variable = PREFLIGHT_POLICY_RESULT_ENV[policy_name]
            for label, change, message in (
                ("renamed check", lambda job: job.update(name="renamed"), "keep its check name"),
                ("longer timeout", lambda job: job.update({"timeout-minutes": 30}),
                 "blocking 10-minute limit"),
                ("nonblocking", lambda job: job.update({"continue-on-error": True}),
                 "blocking 10-minute limit"),
                ("unpinned setup", lambda job: job["steps"][1]["with"].update(
                    {"python-version": "3.12"}), "shared pinned Python setup"),
                ("missing install", lambda job: job["steps"].pop(2),
                 "shared pinned Python setup"),
                ("reordered checks", lambda job: job["steps"].insert(
                    PREFLIGHT_POLICY_SETUP_STEPS, job["steps"].pop()),
                 "exactly its policy checks"),
                ("changed runner", lambda job: job.update({"runs-on": "self-hosted"}),
                 "pinned runner"),
                ("job env", lambda job: job.update(env={"PYTHONPATH": "/tmp"}),
                 "reviewed job keys"),
                ("job permissions", lambda job: job.update(permissions="write-all"),
                 "reviewed job keys"),
                ("job strategy", lambda job: job.update(
                    strategy={"matrix": {"python": ["3.11"]}}), "reviewed job keys"),
                ("job defaults", lambda job: job.update(
                    defaults={"run": {"shell": "true {0}"}}), "reviewed job keys"),
                ("no-op step", lambda job: job["steps"][-1].update(run="true"),
                 "pinned policy step bodies"),
                ("dropped command", drop_one_command, "pinned policy step bodies"),
                ("step env", lambda job: job["steps"][-1].update(env={"PYTHONPATH": "/tmp"}),
                 "pinned policy step bodies"),
                ("step shell", lambda job: job["steps"][-1].update(shell="true {0}"),
                 "pinned policy step bodies"),
                ("conditional step", lambda job: job["steps"][-1].update({"if": "false"}),
                 "unconditional and blocking"),
                ("nonblocking step", lambda job: job["steps"][-1].update(
                    {"continue-on-error": True}), "unconditional and blocking"),
            ):
                with self.subTest(job=policy_name, change=label):
                    mutated = copy.deepcopy(workflow)
                    change(mutated["jobs"][policy_name])
                    with self.assertRaisesRegex(AssertionError, message):
                        assert_preflight_policy_split(mutated)
            for label, change, message in (
                ("missing need", lambda gate: gate["needs"].remove(policy_name),
                 "scope and policy dependencies"),
                ("forged result", lambda gate: gate["steps"][0]["env"].update(
                    {variable: "success"}), f"actual {policy_name} result"),
                ("missing result", lambda gate: gate["steps"][0]["env"].pop(variable),
                 f"actual {policy_name} result"),
                ("unchecked result", lambda gate: gate["steps"][0].update(
                    run=gate["steps"][0]["run"].replace(
                        f'test "${{{variable}}}" = success', "true")),
                 f"enforce the {policy_name} result"),
                ("unchecked skip", lambda gate: gate["steps"][0].update(
                    run=gate["steps"][0]["run"].replace(
                        f'test "${{{variable}}}" = skipped', "true")),
                 f"enforce the {policy_name} result"),
            ):
                with self.subTest(job=policy_name, change=label):
                    mutated = copy.deepcopy(workflow)
                    change(mutated["jobs"]["preflight-gate"])
                    with self.assertRaisesRegex(AssertionError, message):
                        assert_preflight_policy_split(mutated)

    def run_preflight_gate(self, rust_scope: str, **results: str) -> bool:
        step = load_workflow(CI_WORKFLOW_PATH)["jobs"]["preflight-gate"]["steps"][0]
        in_scope = "success" if rust_scope == "true" else "skipped"
        env = dict(os.environ, **{name: in_scope for name in step["env"]})
        env.update(EVENT_NAME="pull_request", RUST_SCOPE=rust_scope, SCOPE_RESULT="success",
                   TRUNK_RESULT="success", FIXTURES_RESULT="success",
                   NON_LINUX_RESULT="success")
        env.update(results)
        return subprocess.run(["bash", "-c", step["run"]], env=env,
                              capture_output=True, check=False).returncode == 0

    def test_preflight_gate_requires_each_policy_job_result_exactly_when_in_scope(self) -> None:
        self.assertTrue(self.run_preflight_gate("true"))
        self.assertTrue(self.run_preflight_gate("false"))
        for variable in PREFLIGHT_POLICY_RESULT_ENV.values():
            for rust_scope, required in (("true", "success"), ("false", "skipped")):
                for result in ("success", "failure", "cancelled", "skipped", ""):
                    with self.subTest(variable=variable, rust_scope=rust_scope, result=result):
                        self.assertEqual(
                            self.run_preflight_gate(rust_scope, **{variable: result}),
                            result == required,
                        )

    def test_core_cache_contract_requires_its_pinned_workflow_invocation(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        mutated = copy.deepcopy(workflow)
        mutated["jobs"]["pinned-dependencies"]["steps"].remove(
            CI_WORKFLOW_POLICY_TEST_STEP
        )
        with self.assertRaisesRegex(
            AssertionError, "run the CI workflow policy test"
        ):
            assert_core_rust_cache_contract(mutated)

    def test_core_cache_contract_rejects_conditional_pr_restore(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        mutated = copy.deepcopy(workflow)
        cache_step = next(
            step
            for step in mutated["jobs"]["test"]["steps"]
            if str(step.get("uses", "")).startswith("Swatinem/rust-cache@")
        )
        cache_step["if"] = "${{ github.event_name == 'push' }}"
        with self.assertRaisesRegex(AssertionError, "reachable on pull requests"):
            assert_core_rust_cache_contract(mutated)

    def test_test_shards_gate_blocks_core_gate(self) -> None:
        assert_test_shards_gate(load_workflow(CI_WORKFLOW_PATH))

    def test_test_shards_gate_rejects_mutations(self) -> None:
        mutations = {
            "core-gate must wait for test-shards": lambda w: w["jobs"]["core-gate"][
                "needs"
            ].remove("test-shards"),
            "core-gate must require the test-shards result": lambda w: w["jobs"][
                "core-gate"
            ]["steps"][0].update(
                run=w["jobs"]["core-gate"]["steps"][0]["run"].replace(
                    TEST_SHARDS_CORE_CHECK, ""
                )
            ),
            "only after every shard succeeded": lambda w: w["jobs"]["test-shards"].update(
                {"if": "${{ always() }}"}
            ),
            "wait for every test shard": lambda w: w["jobs"]["test-shards"].update(
                needs=["test"]
            ),
            "must define the test-shards aggregate": lambda w: w["jobs"].pop("test-shards"),
            "matrix must be shards": lambda w: w["jobs"]["test-shard"]["strategy"].update(
                matrix={"shard": [1, 2]}
            ),
            "must not cancel sibling shards": lambda w: w["jobs"]["test-shard"][
                "strategy"
            ].update({"fail-fast": True}),
            "shard count must agree everywhere": lambda w: w["jobs"]["test-shards"][
                "steps"
            ][-1].update(
                run=w["jobs"]["test-shards"]["steps"][-1]["run"].replace(
                    "--partitioned=3", "--partitioned=2"
                )
            ),
        }
        for message, mutate in mutations.items():
            with self.subTest(message=message):
                mutated = copy.deepcopy(load_workflow(CI_WORKFLOW_PATH))
                mutate(mutated)
                with self.assertRaisesRegex(AssertionError, message):
                    assert_test_shards_gate(mutated)

    def test_standard_stage_stays_within_runner_cap(self) -> None:
        assert_standard_stage_runner_cap(load_workflow(CI_WORKFLOW_PATH))

    def test_standard_stage_cap_rejects_mutations(self) -> None:
        mutations = {
            "start exactly the counted jobs": lambda w: w["jobs"].update(
                {
                    "ninth-heavy-job": {
                        "needs": ["ci_change_scope", "core-gate"],
                        "runs-on": "ubuntu-24.04",
                        "steps": [{"run": "true"}],
                    }
                }
            ),
            "must use one runner": lambda w: w["jobs"]["asan-build"].update(
                {"strategy": {"matrix": {"part": [1, 2]}}}
            ),
            "wait for every standard-stage job": lambda w: w["jobs"]["standard-gate"][
                "needs"
            ].remove("asan-build"),
            "only ci-gate and the main-only reports may wait for cargo-crap": lambda w: w["jobs"]["audit"][
                "needs"
            ].append("cargo-crap"),
            "one lightweight runner released by coverage": lambda w: w["jobs"]["cargo-crap"].update(
                {"timeout-minutes": 90}
            ),
            "lightweight runner released by coverage": lambda w: w["jobs"]["cargo-crap"][
                "needs"
            ].append("core-gate"),
        }
        for message, mutate in mutations.items():
            with self.subTest(message=message):
                mutated = copy.deepcopy(load_workflow(CI_WORKFLOW_PATH))
                mutate(mutated)
                with self.assertRaisesRegex(AssertionError, message):
                    assert_standard_stage_runner_cap(mutated)

    def test_pull_requests_never_write_caches(self) -> None:
        for workflow_path in MAIN_WRITER_WORKFLOW_PATHS:
            with self.subTest(workflow=workflow_path.name):
                assert_pull_requests_never_write_caches(load_workflow(workflow_path))

    def test_cache_write_contract_rejects_pull_request_rust_cache_write(self) -> None:
        mutated = copy.deepcopy(load_workflow(CI_WORKFLOW_PATH))
        cache_step = next(
            step
            for step in mutated["jobs"]["clippy"]["steps"]
            if str(step.get("uses", "")).startswith("Swatinem/rust-cache@")
        )
        del cache_step["with"]["save-if"]
        with self.assertRaisesRegex(AssertionError, "clippy Rust cache must save only from main"):
            assert_pull_requests_never_write_caches(mutated)

    def test_cache_write_contract_rejects_pull_request_docker_cache_write(self) -> None:
        mutated = copy.deepcopy(load_workflow(CI_WORKFLOW_PATH))
        build_step = next(
            step
            for step in mutated["jobs"]["docker-build"]["steps"]
            if str(step.get("uses", "")).startswith("docker/build-push-action@")
        )
        build_step["with"]["cache-to"] = "type=gha,mode=max"
        with self.assertRaisesRegex(AssertionError, "docker-build Docker cache must save only from main"):
            assert_pull_requests_never_write_caches(mutated)

    def test_conformance_materialization_honors_rust_scope(self) -> None:
        workflow = load_workflow(CI_WORKFLOW_PATH)
        materialization = workflow["jobs"]["materialize-conformance-bundles"]
        self.assertIn("ci_change_scope", materialization["needs"])
        self.assertEqual(
            materialization["if"],
            "${{ !cancelled() && needs.ci_change_scope.result == 'success' && "
            "needs.conformance-fixtures.result == 'success' && "
            "needs.core-gate.result == 'success' && "
            "(needs.ci_change_scope.outputs.rust == 'true' || "
            "github.event_name != 'pull_request') }}",
        )




# Accepted ADR-069's two-architecture static launcher evidence is a blocking
# contract. Keep the executable recipe, its graph and its fan-in explicit so
# changing the producer cannot silently turn acceptance evidence into a no-op.
STATIC_LAUNCHER_JOB = {'name': 'static-launcher',
 'needs': ['ci_change_scope', 'preflight-gate'],
 'if': "${{ !cancelled() && needs.preflight-gate.result == 'success' && "
       "(needs.ci_change_scope.outputs.rust == 'true' || github.event_name != "
       "'pull_request') }}",
 'runs-on': 'ubuntu-24.04',
 'timeout-minutes': 45,
 'env': {'RUSTFLAGS': '-D warnings -C target-feature=+crt-static -C '
                      'relocation-model=static',
         'CC_x86_64_unknown_linux_musl': 'musl-gcc',
         'CC_aarch64_unknown_linux_musl': 'aarch64-linux-gnu-gcc',
         'CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER': 'musl-gcc',
         'CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER': 'aarch64-linux-gnu-gcc'},
 'steps': [{'uses': 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
            'with': {'fetch-depth': 0, 'persist-credentials': False}},
           {'uses': 'dtolnay/rust-toolchain@683b588c487a69d01f6c6ddf40f036ff682cc2c8',
            'with': {'toolchain': '1.97.1',
                     'targets': 'x86_64-unknown-linux-musl,aarch64-unknown-linux-musl'}},
           {'uses': 'Swatinem/rust-cache@f0d9c3887740aee45f6153b24b3a6b815192ec16',
            'with': {'shared-key': 'static-launcher',
                     'save-if': "${{ github.ref == 'refs/heads/main' }}"}},
           {'name': 'Install the musl and aarch64 cross toolchains',
            'run': 'set -euo pipefail\n'
                   'bash scripts/prepare-ubuntu-package-mirror.sh '
                   '--no-install-recommends musl-tools gcc-aarch64-linux-gnu '
                   'libc6-dev-arm64-cross\n'},
           {'name': 'Build the provider binary as a static ELF for each architecture',
            'run': 'set -euo pipefail\n'
                   'for target in x86_64-unknown-linux-musl '
                   'aarch64-unknown-linux-musl; do\n'
                   '  cargo build --locked --release --package pos-sandboxd --bin '
                   'pos-sandboxd --target "${target}"\n'
                   'done\n'},
           {'name': 'Require no interpreter, no dynamic section and no shared '
                    'dependency',
            'run': 'set -euo pipefail\n'
                   'for target in x86_64-unknown-linux-musl '
                   'aarch64-unknown-linux-musl; do\n'
                   '  binary="target/${target}/release/pos-sandboxd"\n'
                   '  file "${binary}"\n'
                   '  file "${binary}" | grep -q \'statically linked\'\n'
                   '  if file "${binary}" | grep -qi \'interpreter\\|dynamically '
                   "linked'; then\n"
                   '    echo "${binary} names an interpreter or is dynamically linked" '
                   '>&2\n'
                   '    exit 1\n'
                   '  fi\n'
                   '  if readelf --program-headers --wide "${binary}" | grep -q '
                   "'INTERP'; then\n"
                   '    echo "${binary} has a PT_INTERP program header" >&2\n'
                   '    exit 1\n'
                   '  fi\n'
                   '  readelf --dynamic "${binary}" 2>&1 | grep -q \'There is no '
                   "dynamic section in this file'\n"
                   '  if readelf --section-headers --wide "${binary}" | grep -Eq '
                   "'\\.interp|\\.dynamic|\\.dynsym'; then\n"
                   '    echo "${binary} has dynamic-linking sections" >&2\n'
                   '    exit 1\n'
                   '  fi\n'
                   'done\n'},
           {'name': 'Run the x86_64 binary and require its launcher mode to refuse '
                    'invalid LPV1 input',
            'run': 'set -euo pipefail\n'
                   'binary=target/x86_64-unknown-linux-musl/release/pos-sandboxd\n'
                   'set +e\n'
                   '"${binary}" launch-barrier zz 2> launcher.err\n'
                   'status=$?\n'
                   'set -e\n'
                   'test "${status}" = 1\n'
                   "grep -q 'launch parameters are not a valid LPV1' launcher.err\n"}]}

STATIC_LAUNCHER_FAN_IN = {'name': 'standard-gate',
 'if': '${{ always() }}',
 'needs': ['ci_change_scope',
           'core-gate',
           'rustdoc',
           'reference-evaluator-release',
           'materialize-conformance-bundles',
           'audit',
           'codeql',
           'ledger-windows',
           'docker-build',
           'world-client-wasm',
           'world-client-browser-parity',
           'asan-build',
           'static-launcher'],
 'runs-on': 'ubuntu-24.04',
 'timeout-minutes': 5,
 'steps': [{'name': 'Require normal blocking checks',
            'env': {'RUST_SCOPE': '${{ needs.ci_change_scope.outputs.rust }}',
                    'CORE_RESULT': '${{ needs.core-gate.result }}',
                    'RUSTDOC_RESULT': '${{ needs.rustdoc.result }}',
                    'REFERENCE_RESULT': '${{ needs.reference-evaluator-release.result '
                                        '}}',
                    'MATERIALIZE_RESULT': '${{ '
                                          'needs.materialize-conformance-bundles.result '
                                          '}}',
                    'DEPENDENCY_RESULT': '${{ needs.audit.result }}',
                    'CODEQL_RESULT': '${{ needs.codeql.result }}',
                    'LEDGER_WINDOWS_RESULT': '${{ needs.ledger-windows.result }}',
                    'DOCKER_RESULT': '${{ needs.docker-build.result }}',
                    'WASM_RESULT': '${{ needs.world-client-wasm.result }}',
                    'BROWSER_RESULT': '${{ needs.world-client-browser-parity.result }}',
                    'ASAN_BUILD_RESULT': '${{ needs.asan-build.result }}',
                    'STATIC_LAUNCHER_RESULT': '${{ needs.static-launcher.result }}'},
            'run': 'set -euo pipefail\n'
                   'test "${CORE_RESULT}" = success\n'
                   'test "${CODEQL_RESULT}" = success\n'
                   'expected=success\n'
                   'if [[ "${RUST_SCOPE}" = false ]]; then\n'
                   '  expected=skipped\n'
                   'fi\n'
                   'for result in \\\n'
                   '  "${RUSTDOC_RESULT}" "${REFERENCE_RESULT}" \\\n'
                   '  "${MATERIALIZE_RESULT}" "${DEPENDENCY_RESULT}" \\\n'
                   '  "${LEDGER_WINDOWS_RESULT}" "${DOCKER_RESULT}" \\\n'
                   '  "${WASM_RESULT}" "${BROWSER_RESULT}" "${ASAN_BUILD_RESULT}" \\\n'
                   '  "${STATIC_LAUNCHER_RESULT}"; do\n'
                   '  test "${result}" = "${expected}"\n'
                   'done\n'}]}

STATIC_LAUNCHER_JOB_SET = ['asan',
 'asan-build',
 'asan-gate',
 'audit',
 'cargo-crap',
 'ci-gate',
 'ci_change_scope',
 'clippy',
 'codeql',
 'codeql-required',
 'conformance-fixtures',
 'conformance-non-linux',
 'core-gate',
 'coverage',
 'depgraph',
 'docker-build',
 'feature-matrix',
 'fmt',
 'ledger-windows',
 'materialize-conformance-bundles',
 'modules-structure',
 'mutation-checks',
 'mutation-required',
 'owner-bridge-policies',
 'owner-bridge-windows',
 'pinned-dependencies',
 'plugin-component-fixtures',
 'preflight-gate',
 'reference-evaluator-release',
 'rustdoc',
 'source-policies',
 'standard-gate',
 'static-launcher',
 'test',
 'test-shard',
 'test-shards',
 'third-party-notices',
 'trunk-pr',
 'world-client-browser-parity',
 'world-client-wasm']


def assert_static_launcher_contract(workflow: dict) -> None:
    trigger_key = "on" if "on" in workflow else True
    if set(workflow) != {"name", trigger_key, "concurrency", "permissions", "env", "jobs"}:
        raise AssertionError("static-launcher requires the reviewed workflow root envelope")
    if workflow["name"] != "ci" or workflow["concurrency"] != {
        "group": "ci-${{ github.workflow }}-${{ github.event_name == 'push' && github.sha || github.ref }}",
        "cancel-in-progress": True,
    }:
        raise AssertionError("static-launcher requires the reviewed workflow controls")
    if set(workflow_triggers(workflow)) != {"push", "pull_request", "workflow_dispatch"}:
        raise AssertionError("static-launcher requires the reviewed workflow triggers")
    if workflow_triggers(workflow).get("push") != MAIN_PUSH_TRIGGER:
        raise AssertionError("static-launcher must execute on main pushes")
    if any(workflow_triggers(workflow)[trigger] is not None for trigger in ("pull_request", "workflow_dispatch")):
        raise AssertionError("static-launcher requires unfiltered pull-request and manual triggers")
    if workflow.get("permissions") != {"actions": "read", "contents": "read"}:
        raise AssertionError("static-launcher requires read-only workflow permissions")
    if workflow.get("env") != {"CARGO_TERM_COLOR": "always", "RUSTFLAGS": "-D warnings"}:
        raise AssertionError("static-launcher requires the reviewed workflow environment")
    jobs = workflow.get("jobs", {})
    if sorted(jobs) != STATIC_LAUNCHER_JOB_SET:
        raise AssertionError("static-launcher requires the reviewed complete job set")
    if jobs.get("static-launcher") != STATIC_LAUNCHER_JOB:
        raise AssertionError("static-launcher evidence producer differs from its reviewed contract")
    if jobs.get("standard-gate") != STATIC_LAUNCHER_FAN_IN:
        raise AssertionError("static-launcher evidence must block the reviewed fan-in")


class StaticLauncherPolicyTests(unittest.TestCase):
    def test_checked_in_static_launcher_contract(self) -> None:
        assert_static_launcher_contract(load_workflow(CI_WORKFLOW_PATH))

    def test_static_launcher_rejects_weakening(self) -> None:
        original = load_workflow(CI_WORKFLOW_PATH)
        cases = []

        def changed(label, mutate):
            workflow = copy.deepcopy(original)
            mutate(workflow)
            cases.append((label, workflow))

        changed("fabricated success", lambda w: w["jobs"]["static-launcher"].update(steps=[{"run": "true"}]))
        changed("skipped producer", lambda w: w["jobs"]["static-launcher"].update({"if": False}))
        changed("nonblocking producer", lambda w: w["jobs"]["static-launcher"].update({"continue-on-error": True}))
        changed("producer permission escalation", lambda w: w["jobs"]["static-launcher"].update(permissions={"contents": "write"}))
        changed("workflow permission escalation", lambda w: w.update(permissions="write-all"))
        changed("inherited no-op shell", lambda w: w.update(defaults={"run": {"shell": "true {0}"}}))
        changed("inherited working directory", lambda w: w.update(defaults={"run": {"working-directory": "/tmp"}}))
        changed("altered workflow name", lambda w: w.update(name="fabricated-ci"))
        changed("altered concurrency", lambda w: w["concurrency"].update(group="all-branches"))
        changed("disabled cancellation", lambda w: w["concurrency"].update({"cancel-in-progress": False}))
        changed("filtered pull request", lambda w: w["on" if "on" in w else True].update(pull_request={"types": ["opened"]}))
        changed("manual input injection", lambda w: w["on" if "on" in w else True].update(workflow_dispatch={"inputs": {"skip": {"default": True}}}))
        changed("detached trigger", lambda w: w["on" if "on" in w else True].pop("pull_request"))
        changed("injected environment", lambda w: w["env"].update(CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUNNER="true"))
        changed("injected job", lambda w: w["jobs"].update({"fabricate": {"runs-on": "ubuntu-24.04", "steps": [{"run": "true"}]}}))
        changed("reordered checks", lambda w: w["jobs"]["static-launcher"]["steps"].reverse())
        changed("missing architecture", lambda w: w["jobs"]["static-launcher"]["steps"][1]["with"].update(targets="x86_64-unknown-linux-musl"))
        changed("missing ELF inspection", lambda w: w["jobs"]["static-launcher"]["steps"].pop(5))
        changed("missing smoke check", lambda w: w["jobs"]["static-launcher"]["steps"].pop())
        changed("removed producer", lambda w: w["jobs"].pop("static-launcher"))
        changed("removed fan-in dependency", lambda w: w["jobs"]["standard-gate"]["needs"].remove("static-launcher"))
        changed("removed fan-in result", lambda w: w["jobs"]["standard-gate"]["steps"][0]["env"].pop("STATIC_LAUNCHER_RESULT"))
        changed("fabricated fan-in", lambda w: w["jobs"]["standard-gate"]["steps"][0].update(run="true"))
        for label, workflow in cases:
            with self.subTest(label=label), self.assertRaises(AssertionError):
                assert_static_launcher_contract(workflow)

    def test_failed_or_missing_launcher_result_cannot_pass_fan_in(self) -> None:
        gate = STATIC_LAUNCHER_FAN_IN["steps"][0]
        for result in ("failure", "cancelled", "skipped", "", "success"):
            with self.subTest(result=result):
                environment = {name: "success" for name in gate["env"]}
                environment["RUST_SCOPE"] = "true"
                environment["STATIC_LAUNCHER_RESULT"] = result
                completed = subprocess.run(["bash", "-c", gate["run"]], env=environment, capture_output=True, check=False)
                self.assertEqual(completed.returncode == 0, result == "success")


def load_tests(loader, tests, pattern):
    # The required central CI policy step also exercises the separately
    # triggered custody workflow, including its producer indirection.
    tests.addTests(loader.loadTestsFromModule(custody_policy_tests))
    tests.addTests(loader.loadTestsFromModule(native_lcov_tests))
    return tests


if __name__ == "__main__":
    unittest.main()
