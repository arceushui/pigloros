"""Canonical stage prerequisites of .github/workflows/ci.yml.

The preflight-gate, core-gate and standard-gate jobs only report a stage
verdict to ci-gate. Each later stage waits for the gate's underlying jobs
directly and repeats the gate's pass rule as its job condition, so starting
a stage never costs an extra runner-queue hop. These constants are that pass
rule written as GitHub expressions; the workflow, the CI policy test and the
per-job checkers (ASan, cargo-crap, Memory benchmark) all compare against
them, so the copies in ci.yml cannot drift apart.

Every stage condition starts with ``!cancelled()`` so a skipped dependency is
judged by the explicit result checks below rather than by implicit success().
"""

from __future__ import annotations

RUST_SCOPE = "needs.ci_change_scope.outputs.rust"
IN_RUST_SCOPE = f"({RUST_SCOPE} == 'true' || github.event_name != 'pull_request')"

# preflight-gate: always-required jobs, Trunk (pull requests only) and the
# Rust-scoped policy jobs, in the order preflight-gate lists them.
PREFLIGHT_ALWAYS_JOBS = ("conformance-fixtures", "conformance-non-linux")
PREFLIGHT_SCOPED_JOBS = (
    "pinned-dependencies",
    "source-policies",
    "owner-bridge-policies",
    "plugin-component-fixtures",
    "third-party-notices",
)
PREFLIGHT_STAGE_NEEDS = [
    "ci_change_scope",
    "trunk-pr",
    "pinned-dependencies",
    "source-policies",
    "owner-bridge-policies",
    "conformance-fixtures",
    "conformance-non-linux",
    "plugin-component-fixtures",
    "third-party-notices",
]
# core-gate: the preflight set plus the core jobs it reads.
CORE_JOBS = ("fmt", "feature-matrix", "test", "test-shards", "clippy", "coverage")
CORE_STAGE_NEEDS = [*PREFLIGHT_STAGE_NEEDS, *CORE_JOBS]
# standard-gate: the core set plus CodeQL and the normal checks it reads.
STANDARD_JOBS = (
    "rustdoc",
    "reference-evaluator-release",
    "materialize-conformance-bundles",
    "audit",
    "ledger-windows",
    "docker-build",
    "world-client-wasm",
    "world-client-browser-parity",
    "asan-build",
    "static-launcher",
)
STANDARD_STAGE_NEEDS = [*CORE_STAGE_NEEDS, "codeql", *STANDARD_JOBS]
MAIN_REPORT_NEEDS = [*STANDARD_STAGE_NEEDS, "cargo-crap"]

STAGE_GATES = {
    "preflight-gate": PREFLIGHT_STAGE_NEEDS,
    "core-gate": CORE_STAGE_NEEDS,
    "standard-gate": STANDARD_STAGE_NEEDS,
}


def _results(jobs: tuple[str, ...], value: str) -> str:
    return " && ".join(f"needs.{job}.result == '{value}'" for job in jobs)


# preflight-gate passes exactly when this holds.
PREFLIGHT_PASSED = (
    "needs.ci_change_scope.result == 'success' && "
    f"{_results(PREFLIGHT_ALWAYS_JOBS, 'success')} && "
    "((github.event_name == 'pull_request' && needs.trunk-pr.result == 'success') || "
    "(github.event_name != 'pull_request' && needs.trunk-pr.result == 'skipped')) && "
    f"(({RUST_SCOPE} == 'true' && {_results(PREFLIGHT_SCOPED_JOBS, 'success')}) || "
    f"({RUST_SCOPE} != 'true' && {_results(PREFLIGHT_SCOPED_JOBS, 'skipped')}))"
)
# core-gate passes exactly when this holds.
CORE_PASSED = (
    f"{PREFLIGHT_PASSED} && "
    f"(({RUST_SCOPE} != 'false' && {_results(CORE_JOBS, 'success')}) || "
    f"({RUST_SCOPE} == 'false' && {_results(CORE_JOBS, 'skipped')}))"
)
# standard-gate passes exactly when this holds.
STANDARD_PASSED = (
    f"{CORE_PASSED} && needs.codeql.result == 'success' && "
    f"(({RUST_SCOPE} != 'false' && {_results(STANDARD_JOBS, 'success')}) || "
    f"({RUST_SCOPE} == 'false' && {_results(STANDARD_JOBS, 'skipped')}))"
)


def _condition(*terms: str) -> str:
    return "${{ !cancelled() && " + " && ".join(terms) + " }}"


PREFLIGHT_STAGE_IF = _condition(PREFLIGHT_PASSED, IN_RUST_SCOPE)
CORE_STAGE_IF = _condition(CORE_PASSED, IN_RUST_SCOPE)
DOCKER_BUILD_IF = _condition(
    CORE_PASSED, "needs.third-party-notices.result == 'success'", IN_RUST_SCOPE
)
# The ruleset's code_scanning rule needs an analysis for every pull-request
# head, so documentation-only pull requests run CodeQL whatever core reports.
CODEQL_IF = _condition(
    "needs.ci_change_scope.result == 'success'",
    f"(({CORE_PASSED}) || {RUST_SCOPE} == 'false')",
)
MUTATION_IF = _condition(
    STANDARD_PASSED, "github.event_name == 'pull_request'", f"{RUST_SCOPE} == 'true'"
)
ASAN_IF = _condition(STANDARD_PASSED, "needs.asan-build.result == 'success'", IN_RUST_SCOPE)
MAIN_REPORT_IF = _condition(
    "github.event_name != 'pull_request'",
    STANDARD_PASSED,
    "needs.cargo-crap.result == 'success'",
)

# Every job that starts once a stage passes: name -> (gate, needs, condition).
STAGE_CONSUMERS = {
    **{
        name: ("preflight-gate", PREFLIGHT_STAGE_NEEDS, PREFLIGHT_STAGE_IF)
        for name in (
            "fmt",
            "feature-matrix",
            "test",
            "test-shard",
            "clippy",
            "static-launcher",
            "coverage",
        )
    },
    **{
        name: ("core-gate", CORE_STAGE_NEEDS, CORE_STAGE_IF)
        for name in (
            "rustdoc",
            "reference-evaluator-release",
            "materialize-conformance-bundles",
            "audit",
            "asan-build",
            "world-client-wasm",
        )
    },
    "docker-build": ("core-gate", CORE_STAGE_NEEDS, DOCKER_BUILD_IF),
    "codeql": ("core-gate", CORE_STAGE_NEEDS, CODEQL_IF),
    "mutation-checks": ("standard-gate", STANDARD_STAGE_NEEDS, MUTATION_IF),
    "asan": ("standard-gate", STANDARD_STAGE_NEEDS, ASAN_IF),
    "modules-structure": ("standard-gate", MAIN_REPORT_NEEDS, MAIN_REPORT_IF),
    "depgraph": ("standard-gate", MAIN_REPORT_NEEDS, MAIN_REPORT_IF),
}
# Only these reporters may wait for a stage gate; nothing else may queue
# behind one.
GATE_REPORTERS = {
    "preflight-gate": ("core-gate", "ci-gate"),
    "core-gate": ("standard-gate", "ci-gate"),
    "standard-gate": ("ci-gate",),
}
