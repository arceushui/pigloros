#!/usr/bin/env python3
"""Keep mutation evidence dependent on a passing, identical test harness."""

from __future__ import annotations

import copy
import pathlib
import subprocess
import unittest

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
NIGHTLY = "nightly-2026-07-01"
BASELINE_RUN = """set -euo pipefail
cargo test --workspace --all-features --locked -- \\
  -Zunstable-options --fail-fast --include-ignored --test-threads=2 \\
  2>&1 | tee "${RUNNER_TEMP}/mutation-baseline.log"
bash scripts/assert-no-ignored-in-test-summary.sh "${RUNNER_TEMP}/mutation-baseline.log"
"""
MUTATION_IF = (
    "needs.mutation-changes.outputs.relevant == 'true' && "
    "needs.mutation-baseline.result == 'success'"
)
GATE_RUN = """test "${{ needs.mutation-changes.result }}" = success
if [[ "${{ needs.mutation-changes.outputs.relevant }}" = true ]]; then
  test "${{ needs.mutation-baseline.result }}" = success
  test "${{ needs.mutation.result }}" = success
else
  test "${{ needs.mutation-baseline.result }}" = skipped
  test "${{ needs.mutation.result }}" = skipped
fi
"""


def check_contract(workflow: dict) -> None:
    """Reject toolchain drift, baseline bypasses, and permissive fan-in."""
    if workflow.get("env") != {
        "RUSTUP_TOOLCHAIN": NIGHTLY,
        "CARGO_PROFILE_TEST_DEBUG": "line-tables-only",
        "CARGO_BUILD_JOBS": "1",
    }:
        raise AssertionError(
            "baseline and mutants must share the pinned nightly and serial compiler jobs"
        )
    jobs = workflow["jobs"]
    for name in ("mutation-baseline", "mutation"):
        job = jobs[name]
        if "env" in job or "continue-on-error" in job:
            raise AssertionError("mutation jobs must not override or suppress failures")
        toolchains = [
            step for step in job["steps"]
            if step.get("uses", "").startswith("dtolnay/rust-toolchain@")
        ]
        if len(toolchains) != 1 or toolchains[0].get("with") != {
            "toolchain": "${{ env.RUSTUP_TOOLCHAIN }}"
        }:
            raise AssertionError("install the selected nightly in both jobs")
        for step in job["steps"]:
            if "continue-on-error" in step or "env" in step:
                raise AssertionError("steps must not override or suppress failures")
    baseline = jobs["mutation-baseline"]
    if (
        baseline.get("needs") != "mutation-changes"
        or baseline.get("if") != "needs.mutation-changes.outputs.relevant == 'true'"
        or baseline.get("timeout-minutes") != 30
    ):
        raise AssertionError("baseline must run for every relevant change")
    runs = [step for step in baseline["steps"] if "run" in step]
    if runs != [{"name": "Prove the mutation test harness", "run": BASELINE_RUN}]:
        raise AssertionError("baseline must execute the complete mutation harness")
    mutation = jobs["mutation"]
    if (
        mutation.get("needs") != ["mutation-changes", "mutation-baseline"]
        or mutation.get("if") != MUTATION_IF
    ):
        raise AssertionError("mutants require a successful same-harness baseline")
    if mutation["strategy"] != {
        "fail-fast": False,
        "max-parallel": 8,
        "matrix": {"shard": list(range(8))},
    }:
        raise AssertionError("retain all eight blocking shards")
    mutation_step = next(
        step for step in mutation["steps"]
        if step.get("name") == "Run mutants in changed lines"
    )
    if "if" in mutation_step:
        raise AssertionError("mutation execution must be unconditional")
    command = " ".join(mutation_step["run"].replace("\\\n", " ").split())
    required = (
        "timeout --foreground 60m cargo mutants --workspace --all-features "
        '--in-diff "${{ runner.temp }}/changes.diff" --no-shuffle '
        '--shard "${{ matrix.shard }}/8" --baseline skip --jobs 4 '
        "--timeout 120 --build-timeout 600 --cap-lints true --cargo-arg=--locked "
        "-- -- -Zunstable-options --fail-fast --include-ignored --test-threads=2 "
        "mutation_status=$? set -e"
    )
    if required not in command or not command.endswith('exit "$mutation_status"'):
        raise AssertionError("preserve mutation scope, limits, harness and exit status")
    gate = jobs["mutation-gate"]
    if (
        gate.get("needs") != ["mutation-changes", "mutation-baseline", "mutation"]
        or gate.get("if") != "always()"
        or "continue-on-error" in gate
        or gate["steps"] != [{
            "name": "Require every relevant mutation shard to pass",
            "run": GATE_RUN,
        }]
    ):
        raise AssertionError("fan-in must require the baseline and every shard")


class MutationWorkflowPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = yaml.safe_load(
            (ROOT / ".github/workflows/mutation.yml").read_text(encoding="utf-8")
        )

    def test_repository_contract(self) -> None:
        check_contract(self.workflow)
        ci = yaml.safe_load(
            (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        )
        self.assertIn(
            {"name": "Test mutation workflow policy",
             "run": "python scripts/test_mutation_workflow_policy.py"},
            ci["jobs"]["pinned-dependencies"]["steps"],
        )

    def test_rejects_wrong_or_missing_toolchain(self) -> None:
        for value in (
            {},
            {"RUSTUP_TOOLCHAIN": "1.97.1"},
            dict(self.workflow["env"], RUSTUP_TOOLCHAIN="nightly-2026-08-28"),
        ):
            with self.subTest(value=value):
                changed = copy.deepcopy(self.workflow)
                changed["env"] = value
                with self.assertRaisesRegex(AssertionError, "pinned nightly"):
                    check_contract(changed)

    def test_rejects_bypasses_and_harness_drift(self) -> None:
        for name, field, value in (
            ("mutation-baseline", "if", "false"),
            ("mutation-baseline", "continue-on-error", True),
            ("mutation", "needs", ["mutation-changes"]),
            ("mutation", "if", "always()"),
            ("mutation", "env", {"RUSTUP_TOOLCHAIN": "stable"}),
            ("mutation-gate", "needs", ["mutation-changes", "mutation"]),
            ("mutation-gate", "continue-on-error", True),
        ):
            with self.subTest(job=name, field=field):
                changed = copy.deepcopy(self.workflow)
                changed["jobs"][name][field] = value
                with self.assertRaises(AssertionError):
                    check_contract(changed)
        for name in ("mutation-baseline", "mutation"):
            changed = copy.deepcopy(self.workflow)
            run = next(step for step in changed["jobs"][name]["steps"]
                       if "--include-ignored" in step.get("run", ""))
            run["run"] = run["run"].replace("--include-ignored", "")
            with self.subTest(job=name), self.assertRaises(AssertionError):
                check_contract(changed)

    def test_rejects_missing_or_nonserial_compiler_jobs(self) -> None:
        for value in (None, "", "auto", "2", "4", 1):
            with self.subTest(value=value):
                changed = copy.deepcopy(self.workflow)
                if value is None:
                    changed["env"].pop("CARGO_BUILD_JOBS")
                else:
                    changed["env"]["CARGO_BUILD_JOBS"] = value
                with self.assertRaisesRegex(AssertionError, "serial compiler jobs"):
                    check_contract(changed)

    def test_real_fan_in_rejects_unsuccessful_baseline_and_shards(self) -> None:
        run = self.workflow["jobs"]["mutation-gate"]["steps"][0]["run"]

        def verdict(relevant: bool, changes: str, baseline: str, shards: str) -> int:
            script = run
            for key, value in {
                "mutation-changes.result": changes,
                "mutation-changes.outputs.relevant": str(relevant).lower(),
                "mutation-baseline.result": baseline,
                "mutation.result": shards,
            }.items():
                script = script.replace("${{ needs." + key + " }}", value)
            return subprocess.run(
                ["bash", "-euo", "pipefail", "-c", script],
                capture_output=True, check=False,
            ).returncode

        self.assertEqual(verdict(True, "success", "success", "success"), 0)
        self.assertEqual(verdict(False, "success", "skipped", "skipped"), 0)
        for state in ("failure", "cancelled", "skipped", ""):
            with self.subTest(state=state):
                self.assertNotEqual(verdict(True, state, "success", "success"), 0)
                self.assertNotEqual(verdict(True, "success", state, "success"), 0)
                self.assertNotEqual(verdict(True, "success", "success", state), 0)
        self.assertNotEqual(verdict(False, "success", "success", "skipped"), 0)
        self.assertNotEqual(verdict(False, "success", "skipped", "failure"), 0)

    def test_timeout_log_selector_preserves_the_timeout_status(self) -> None:
        run = next(
            step["run"] for step in self.workflow["jobs"]["mutation"]["steps"]
            if step.get("name") == "Run mutants in changed lines"
        )
        self.assertEqual(run.count("| sort -nr | "), 1)
        selector = "sort -nr | " + run.split("| sort -nr | ", 1)[1].split(')"', 1)[0]
        # Exercise the real pipeline, not Cargo or filesystem fixture creation.
        # Exceed pipe capacity so an early-closing consumer exposes SIGPIPE.
        many = "".join(f"{index}.0 mutants.out/log/case {index}.log\n"
                       for index in range(20_000))
        for listing, expected in (
            ("", ""),
            ("1.0 mutants.out/log/only.log\n", "mutants.out/log/only.log"),
            (many, "mutants.out/log/case 19999.log"),
        ):
            with self.subTest(entries=listing.count("\n")):
                result = subprocess.run(
                    ["bash", "-euo", "pipefail", "-c",
                     'mutation_status=124\nlatest_log="$(' + selector + ')"\n'
                     'printf "%s\\n" "$latest_log"\nexit "$mutation_status"'],
                    input=listing, capture_output=True, text=True, check=False,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 124, result.stderr)
                self.assertEqual(result.stdout, expected + "\n")
                self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
