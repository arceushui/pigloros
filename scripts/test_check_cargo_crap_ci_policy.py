#!/usr/bin/env python3
"""Adversarial tests for the cargo-crap GitHub Actions policy checker."""

from __future__ import annotations

import copy
import importlib.util
import os
import pathlib
import subprocess
import tempfile
import unittest

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKER_PATH = ROOT / "scripts" / "check_cargo_crap_ci_policy.py"
RESOLVER_PATH = ROOT / "scripts" / "resolve_cargo_crap_baseline.sh"
BOOTSTRAP_BASE_SHA = "45bdac85b29d273573583f846ba7acd2b3a12573"
EXAMPLE_BASE_SHA = "a" * 40
SPEC = importlib.util.spec_from_file_location("check_cargo_crap_ci_policy", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class CargoCrapCiPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        with (ROOT / ".github/workflows/ci.yml").open(encoding="utf-8") as stream:
            self.workflow = yaml.safe_load(stream)

    def assert_rejected(self, mutate) -> None:
        workflow = copy.deepcopy(self.workflow)
        mutate(workflow)
        with tempfile.TemporaryDirectory() as directory:
            fixture = pathlib.Path(directory) / "ci.yml"
            fixture.write_text(yaml.safe_dump(workflow, sort_keys=False), encoding="utf-8")
            with self.assertRaises(CHECKER.PolicyError):
                CHECKER.check_workflow(fixture)

    def assert_resolver_rejected(self, mutate) -> None:
        resolver = RESOLVER_PATH.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            fixture = pathlib.Path(directory) / "resolve_cargo_crap_baseline.sh"
            fixture.write_text(mutate(resolver), encoding="utf-8")
            with self.assertRaises(CHECKER.PolicyError):
                CHECKER.check_workflow(
                    ROOT / ".github" / "workflows" / "ci.yml", fixture
                )

    def run_resolver(
        self,
        gh_response: str,
        *,
        base_sha: str = EXAMPLE_BASE_SHA,
        git_status: int = 1,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
        with tempfile.TemporaryDirectory() as directory:
            fixture = pathlib.Path(directory)
            tools = fixture / "bin"
            tools.mkdir()
            logs = {
                "output": str(fixture / "github-output"),
                "gh_args": str(fixture / "gh-args"),
                "gh_calls": str(fixture / "gh-calls"),
                "sleep_calls": str(fixture / "sleep-calls"),
                "git_calls": str(fixture / "git-calls"),
            }
            self.write_executable(
                tools / "gh",
                "printf '%s\\n' \"$@\" >> \"${GH_ARGS}\"\n"
                "printf 'call\\n' >> \"${GH_CALLS}\"\n"
                "printf '%s' \"${GH_RESPONSE}\"\n",
            )
            self.write_executable(
                tools / "sleep", "printf '%s\\n' \"$@\" >> \"${SLEEP_CALLS}\"\n"
            )
            self.write_executable(
                tools / "git",
                "printf '%s\\n' \"$@\" >> \"${GIT_CALLS}\"\n"
                "exit \"${FAKE_GIT_STATUS}\"\n",
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{tools}:{environment['PATH']}",
                    "EVENT_NAME": "pull_request",
                    "BASE_SHA": base_sha,
                    "GITHUB_OUTPUT": logs["output"],
                    "GITHUB_REPOSITORY": "owner/repository",
                    "GH_ARGS": logs["gh_args"],
                    "GH_CALLS": logs["gh_calls"],
                    "GH_RESPONSE": gh_response,
                    "SLEEP_CALLS": logs["sleep_calls"],
                    "GIT_CALLS": logs["git_calls"],
                    "FAKE_GIT_STATUS": str(git_status),
                }
            )
            result = subprocess.run(
                [str(RESOLVER_PATH)],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            contents = {
                name: pathlib.Path(path).read_text(encoding="utf-8")
                if pathlib.Path(path).exists()
                else ""
                for name, path in logs.items()
            }
            return result, contents

    @staticmethod
    def write_executable(path: pathlib.Path, body: str) -> None:
        path.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n" + body,
            encoding="utf-8",
        )
        path.chmod(0o755)

    def cargo_crap_step(self, workflow: dict, name: str) -> dict:
        return next(
            step
            for step in workflow["jobs"]["cargo-crap"]["steps"]
            if step.get("name") == name
        )

    def test_repository_workflow_passes(self) -> None:
        CHECKER.check_workflow(ROOT / ".github/workflows/ci.yml")

    def test_resolver_executes_the_exact_trusted_artifact_query(self) -> None:
        result, logs = self.run_resolver("4242\n")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(logs["output"], "run-id=4242\nbootstrap=false\n")
        self.assertEqual(logs["gh_calls"], "call\n")
        self.assertEqual(logs["sleep_calls"], "")
        self.assertEqual(logs["git_calls"], "")
        for argument in (
            "repos/owner/repository/actions/artifacts",
            f"name=cargo-crap-baseline-{EXAMPLE_BASE_SHA}",
            "select(.expired == false)",
            'select(.workflow_run.head_branch == "main")',
            f'select(.workflow_run.head_sha == "{EXAMPLE_BASE_SHA}")',
            "select(.workflow_run.head_repository_id == .workflow_run.repository_id)",
        ):
            with self.subTest(argument=argument):
                self.assertIn(argument, logs["gh_args"])

    def test_resolver_fails_closed_after_the_bounded_retry_window(self) -> None:
        result, logs = self.run_resolver("")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(logs["output"], "")
        self.assertEqual(logs["gh_calls"].count("call\n"), 30)
        self.assertEqual(logs["sleep_calls"].count("10\n"), 29)
        self.assertEqual(logs["git_calls"], "")

    def test_resolver_executes_only_the_approved_bootstrap(self) -> None:
        result, logs = self.run_resolver(
            "", base_sha=BOOTSTRAP_BASE_SHA, git_status=0
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(logs["output"], "bootstrap=true\n")
        self.assertIn(f"{BOOTSTRAP_BASE_SHA}...HEAD", logs["git_calls"])

    def test_rejects_unpinned_cargo_crap(self) -> None:
        self.assert_rejected(
            lambda workflow: self.cargo_crap_step(workflow, "Install cargo-crap")[
                "with"
            ].update({"tool": "cargo-crap"})
        )

    def test_rejects_optimistic_missing_coverage(self) -> None:
        self.assert_rejected(
            lambda workflow: self.cargo_crap_step(
                workflow, "Analyze CRAP score changes"
            ).update(
                {
                    "run": self.cargo_crap_step(
                        workflow, "Analyze CRAP score changes"
                    )["run"].replace("--missing pessimistic", "--missing optimistic")
                }
            )
        )

    def test_rejects_missing_baseline(self) -> None:
        self.assert_rejected(
            lambda workflow: self.cargo_crap_step(
                workflow, "Analyze CRAP score changes"
            ).update(
                {
                    "run": self.cargo_crap_step(
                        workflow, "Analyze CRAP score changes"
                    )["run"].replace(
                        '--baseline "${{ runner.temp }}/cargo-crap-baseline.json"',
                        "",
                    )
                }
            )
        )

    def test_rejects_required_arguments_hidden_in_a_comment(self) -> None:
        def replace_analysis(workflow: dict) -> None:
            step = self.cargo_crap_step(workflow, "Analyze CRAP score changes")
            original = step["run"]
            step["run"] = (
                "python -c 'import json; "
                'json.dump({\"version\":\"0.2.2\",\"entries\":[],\"removed\":[]}, '
                'open(\"${RUNNER_TEMP}/cargo-crap-report.json\",\"w\"))\'\n'
                f"# {original}"
            )

        self.assert_rejected(replace_analysis)

    def test_rejects_nonzero_regression_epsilon(self) -> None:
        def weaken_epsilon(workflow: dict) -> None:
            step = self.cargo_crap_step(workflow, "Analyze CRAP score changes")
            step["run"] = step["run"].replace("--epsilon 0 ", "--epsilon 0.01 ")

        self.assert_rejected(weaken_epsilon)

    def test_rejects_repository_configuration(self) -> None:
        self.assert_rejected(
            lambda workflow: self.cargo_crap_step(
                workflow, "Reject repository cargo-crap configuration"
            ).update({"run": "true"})
        )

    def test_rejects_unpinned_bootstrap_base(self) -> None:
        self.assert_resolver_rejected(
            lambda resolver: resolver.replace(
                'test "${BASE_SHA}" = "45bdac85b29d273573583f846ba7acd2b3a12573"',
                "true",
            )
        )

    def test_requires_centralized_baseline_resolver(self) -> None:
        self.assert_rejected(
            lambda workflow: self.cargo_crap_step(
                workflow, "Resolve trusted cargo-crap baseline"
            ).update({"run": "inline-baseline-resolver.sh"})
        )

    def test_requires_scoped_coverage(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["coverage"].update(
                {"if": "${{ always() }}"}
            )
        )

    def test_requires_scoped_cargo_crap(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["cargo-crap"].update(
                {"if": "${{ always() }}"}
            )
        )

    def test_requires_successful_coverage_for_cargo_crap(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["cargo-crap"].update(
                {
                    "if": (
                        "${{ needs.ci_change_scope.outputs.rust == 'true' || "
                        "github.event_name != 'pull_request' }}"
                    )
                }
            )
        )

    def test_requires_baseline_retry_delay(self) -> None:
        self.assert_resolver_rejected(
            lambda resolver: resolver.replace(
                "BASELINE_RETRY_DELAY_SECONDS=10",
                "BASELINE_RETRY_DELAY_SECONDS=1",
            )
        )

    def test_requires_artifact_based_baseline_resolution(self) -> None:
        self.assert_resolver_rejected(
            lambda resolver: resolver.replace(
                '"repos/${GITHUB_REPOSITORY}/actions/artifacts"',
                '"repos/${GITHUB_REPOSITORY}/actions/workflows/ci.yml/runs"',
            )
        )

    def test_rejects_whole_workflow_completion_dependency(self) -> None:
        self.assert_resolver_rejected(
            lambda resolver: resolver.replace(
                'BASELINE_ARTIFACT_NAME="cargo-crap-baseline-${BASE_SHA}"',
                'BASELINE_ARTIFACT_NAME="cargo-crap-baseline-${BASE_SHA}"\n'
                'LEGACY_LOOKUP="-f status=success"',
            )
        )

    def test_requires_main_baseline_publication(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["cargo-crap"]["steps"].pop()
        )

    def test_rejects_nonblocking_verdict(self) -> None:
        self.assert_rejected(
            lambda workflow: self.cargo_crap_step(
                workflow, "Enforce cargo-crap policy"
            ).update({"continue-on-error": True})
        )

    def test_rejects_shallow_checkout(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["cargo-crap"]["steps"][0].update(
                {"with": {"fetch-depth": 1}}
            )
        )

    def test_requires_visible_job_after_coverage(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["cargo-crap"].update(
                {"needs": "test"}
            )
        )

    def test_requires_cargo_crap_in_aggregate_gate(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["ci-gate"]["needs"].remove(
                "cargo-crap"
            )
        )

    def test_requires_aggregate_verdict_to_read_cargo_crap(self) -> None:
        def remove_result(workflow: dict) -> None:
            step = workflow["jobs"]["ci-gate"]["steps"][0]
            step["env"].pop("CARGO_CRAP_RESULT")

        self.assert_rejected(remove_result)


if __name__ == "__main__":
    unittest.main()
