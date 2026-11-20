#!/usr/bin/env python3
"""Adversarial tests for the cargo-crap GitHub Actions policy checker."""

from __future__ import annotations

import copy
import fnmatch
import importlib.util
import json
import os
import pathlib
import shlex
import subprocess
import tempfile
import unittest

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKER_PATH = ROOT / "scripts" / "check_cargo_crap_ci_policy.py"
RESOLVER_PATH = ROOT / "scripts" / "resolve_cargo_crap_baseline.sh"
EXAMPLE_BASE_SHA = "a" * 40
# The 30-attempt artifact window, then five one-minute polls of the 600 s main
# run registration window (elapsed 290 s to 530 s) before the final lookup.
NO_MAIN_RUN_CALLS = ["artifacts"] * 30 + ["runs", "artifacts"] * 5 + ["runs"]
REV_LIST_CALL = (
    f"rev-list\n--first-parent\n--skip=1\n--max-count=30\n{EXAMPLE_BASE_SHA}\n"
)
NO_ANCESTOR_REASON = (
    ", and none of its 30 nearest first-parent main ancestors has a baseline; failing closed"
)
EXPECTED_FORK_REPLAY_TEST_EXCLUSIONS = (
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
)
EXPECTED_SANDBOX_EXECUTION_TEST_EXCLUSIONS = (
    "src/execute/tests/ownership.rs",
    "src/provider_barrier/tests.rs",
    "src/execute/tests/ownership/abandonment.rs",
    "src/revision/tests.rs",
    "src/provider_lifecycle/tests.rs",
    "src/provider_runtime/tests.rs",
    "src/provider_runtime/endpoint/tests.rs",
    "src/provider_runtime/serving/tests.rs",
    "src/provider_runtime/revocation/tests.rs",
    "src/scenario_room/tests.rs",
    "src/executor/scenario_room/tests.rs",
    "src/local_erasure_provision/tests.rs",
    "src/mode_profile/tests.rs",
    "src/community/memory_domain/tests.rs",
    "src/community/initialize/tests.rs",
)
EXPECTED_OWNER_NATIVE_TEST_EXCLUSIONS = (
    "src/adapter/native_tests.rs",
    "src/adapter/native_tests/**",
)
EXPECTED_TEST_ONLY_EXCLUSIONS = (
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
    *EXPECTED_FORK_REPLAY_TEST_EXCLUSIONS,
    *EXPECTED_SANDBOX_EXECUTION_TEST_EXCLUSIONS,
    *EXPECTED_OWNER_NATIVE_TEST_EXCLUSIONS,
)
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
        artifact_responses: str | list[str],
        run_responses: str | list[str] = "",
        job_responses: str | list[str] = "",
        *,
        base_sha: str = EXAMPLE_BASE_SHA,
        trusted_base_sha: str = EXAMPLE_BASE_SHA,
        git_status: int = 1,
        ancestors: tuple[str, ...] = (),
        ancestor_artifacts: dict[str, str | None] | None = None,
        rev_list_status: int = 0,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
        """Run the resolver against a stubbed ``gh``, ``git``, ``sleep`` and clock.

        Each list holds the stdout of successive ``gh api`` calls to the
        artifacts, main-run or run-jobs endpoint; the last entry repeats and
        an entry of ``FAIL`` makes that call exit non-zero. ``sleep``
        advances the fake ``date +%s`` clock instead of waiting.
        ``git rev-list`` prints ``ancestors``; an artifact query for an
        ancestor prints its ``ancestor_artifacts`` entry (none by default),
        and a ``None`` entry makes that ``gh`` call fail.
        """
        responses = {
            "artifacts": [artifact_responses] if isinstance(artifact_responses, str) else artifact_responses,
            "runs": [run_responses] if isinstance(run_responses, str) else run_responses,
            "jobs": [job_responses] if isinstance(job_responses, str) else job_responses,
        }
        with tempfile.TemporaryDirectory() as directory:
            fixture = pathlib.Path(directory)
            tools = fixture / "bin"
            tools.mkdir()
            replies = fixture / "replies"
            replies.mkdir()
            for kind, outputs in responses.items():
                for index, output in enumerate(outputs, start=1):
                    (replies / f"{kind}.{index}").write_text(output, encoding="utf-8")
            for ancestor, output in (ancestor_artifacts or {}).items():
                if output is None:
                    (replies / f"ancestor-{ancestor}.fail").write_text("", encoding="utf-8")
                else:
                    (replies / f"ancestor-{ancestor}").write_text(output, encoding="utf-8")
            (fixture / "ancestors").write_text(
                "".join(f"{ancestor}\n" for ancestor in ancestors), encoding="utf-8"
            )
            clock = fixture / "clock"
            clock.write_text("1000000\n", encoding="utf-8")
            logs = {
                "output": str(fixture / "github-output"),
                "gh_args": str(fixture / "gh-args"),
                "gh_calls": str(fixture / "gh-calls"),
                "sleep_calls": str(fixture / "sleep-calls"),
                "git_calls": str(fixture / "git-calls"),
            }
            self.write_executable(
                tools / "gh",
                "printf '%s\\0' \"$@\" >> \"${GH_ARGS}\"\n"
                "case \"$5\" in\n"
                "  */actions/artifacts)\n"
                "    kind=artifacts\n"
                "    if [[ \"$7\" != \"name=cargo-crap-baseline-${TRUSTED_BASE_SHA}\" ]]; then\n"
                "      ancestor=\"${7#name=cargo-crap-baseline-}\"\n"
                "      printf 'ancestor:%s\\n' \"${ancestor}\" >> \"${GH_CALLS}\"\n"
                "      [[ ! -e \"${GH_REPLIES}/ancestor-${ancestor}.fail\" ]] || exit 1\n"
                "      cat \"${GH_REPLIES}/ancestor-${ancestor}\" 2>/dev/null || true\n"
                "      exit 0\n"
                "    fi\n"
                "    ;;\n"
                "  */actions/workflows/ci.yml/runs) kind=runs ;;\n"
                "  */actions/runs/*/jobs) kind=jobs ;;\n"
                "  *) exit 97 ;;\n"
                "esac\n"
                "printf '%s\\n' \"${kind}\" >> \"${GH_CALLS}\"\n"
                "reply=\"$(grep -cx \"${kind}\" \"${GH_CALLS}\")\"\n"
                "while ((reply > 1)) && [[ ! -e \"${GH_REPLIES}/${kind}.${reply}\" ]]; do\n"
                "  reply=$((reply - 1))\n"
                "done\n"
                "[[ \"$(cat \"${GH_REPLIES}/${kind}.${reply}\")\" != FAIL ]] || exit 1\n"
                "cat \"${GH_REPLIES}/${kind}.${reply}\"\n",
            )
            self.write_executable(
                tools / "sleep",
                "printf '%s\\n' \"$@\" >> \"${SLEEP_CALLS}\"\n"
                "printf '%s\\n' \"$(($(cat \"${FAKE_CLOCK}\") + $1))\" > \"${FAKE_CLOCK}\"\n",
            )
            self.write_executable(
                tools / "date",
                "[[ \"$*\" == \"+%s\" ]] || exit 98\n"
                "cat \"${FAKE_CLOCK}\"\n",
            )
            self.write_executable(
                tools / "git",
                "printf '%s\\n' \"$@\" >> \"${GIT_CALLS}\"\n"
                "if [[ \"$1\" == \"merge-base\" ]]; then\n"
                "  printf '%s\\n' \"${TRUSTED_BASE_SHA}\"\n"
                "  exit 0\n"
                "fi\n"
                "if [[ \"$1\" == \"rev-list\" ]]; then\n"
                "  cat \"${FAKE_ANCESTORS}\"\n"
                "  exit \"${FAKE_REV_LIST_STATUS}\"\n"
                "fi\n"
                "exit \"${FAKE_GIT_STATUS}\"\n",
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{tools}:{environment['PATH']}",
                    "EVENT_NAME": "pull_request",
                    "BASE_SHA": base_sha,
                    "TRUSTED_BASE_SHA": trusted_base_sha,
                    "GITHUB_OUTPUT": logs["output"],
                    "GITHUB_REPOSITORY": "owner/repository",
                    "GH_ARGS": logs["gh_args"],
                    "GH_CALLS": logs["gh_calls"],
                    "GH_REPLIES": str(replies),
                    "SLEEP_CALLS": logs["sleep_calls"],
                    "FAKE_CLOCK": str(clock),
                    "GIT_CALLS": logs["git_calls"],
                    "FAKE_GIT_STATUS": str(git_status),
                    "FAKE_ANCESTORS": str(fixture / "ancestors"),
                    "FAKE_REV_LIST_STATUS": str(rev_list_status),
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
    def gh_calls(logs: dict[str, str]) -> list[str]:
        return logs["gh_calls"].splitlines()

    @staticmethod
    def gh_invocations(logs: dict[str, str]) -> list[list[str]]:
        """Split the NUL-separated gh argument log into one list per call."""
        invocations: list[list[str]] = []
        for argument in logs["gh_args"].split("\0")[:-1]:
            if argument == "api":
                invocations.append([])
            invocations[-1].append(argument)
        return invocations

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

    def cargo_crap_exclusions(self, step_name: str) -> tuple[str, ...]:
        tokens = shlex.split(self.cargo_crap_step(self.workflow, step_name)["run"])
        return tuple(
            tokens[index + 1]
            for index, token in enumerate(tokens[:-1])
            if token == "--exclude"
        )

    def test_repository_workflow_passes(self) -> None:
        CHECKER.check_workflow(ROOT / ".github/workflows/ci.yml")

    def test_native_coverage_download_and_toolchain_pins_cannot_be_substituted(self) -> None:
        for index, action in (
            (1, "dtolnay/rust-toolchain@02cb101ec7c40f2c49e1d9714d64511d8e1b74de"),
            (4, "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"),
        ):
            with self.subTest(step=index):
                self.assert_rejected(
                    lambda workflow: workflow["jobs"]["cargo-crap"]["steps"][index].update(
                        {"uses": action}
                    )
                )

    def test_native_coverage_steps_cannot_skip_ignore_or_substitute_evidence(self) -> None:
        for name in (
            "Download hosted native LCOV",
            "Bind native and Linux coverage to this checkout",
        ):
            for key, value in (
                ("if", "${{ false }}"),
                ("continue-on-error", True),
                ("run", "echo fabricated coverage"),
                ("env", {"PYTHONPATH": "/tmp/substituted-program"}),
                ("with", {"name": "owner-windows-lcov-another-checkout"}),
            ):
                with self.subTest(step=name, control=key):
                    self.assert_rejected(
                        lambda workflow: self.cargo_crap_step(workflow, name).update(
                            {key: value}
                        )
                    )

    def test_native_coverage_steps_cannot_be_removed_duplicated_or_reordered(self) -> None:
        for name in (
            "Download hosted native LCOV",
            "Bind native and Linux coverage to this checkout",
        ):
            def remove(workflow: dict) -> None:
                steps = workflow["jobs"]["cargo-crap"]["steps"]
                steps.remove(self.cargo_crap_step(workflow, name))

            def duplicate(workflow: dict) -> None:
                steps = workflow["jobs"]["cargo-crap"]["steps"]
                steps.append(copy.deepcopy(self.cargo_crap_step(workflow, name)))

            def reorder(workflow: dict) -> None:
                steps = workflow["jobs"]["cargo-crap"]["steps"]
                step = self.cargo_crap_step(workflow, name)
                steps.remove(step)
                steps.append(step)

            for mutation in (remove, duplicate, reorder):
                with self.subTest(step=name, mutation=mutation.__name__):
                    self.assert_rejected(mutation)

    def test_both_scoring_paths_require_the_joined_coverage(self) -> None:
        for name in ("Generate trusted current baseline", "Analyze CRAP score changes"):
            with self.subTest(step=name):
                def replace_input(workflow: dict) -> None:
                    step = self.cargo_crap_step(workflow, name)
                    step["run"] = step["run"].replace(
                        "/cargo-crap-coverage.lcov", "/coverage.lcov"
                    )

                self.assert_rejected(replace_input)

    def test_native_steps_run_unless_the_scope_explicitly_skipped_the_lane(self) -> None:
        for name in (
            "Download hosted native LCOV",
            "Bind native and Linux coverage to this checkout",
        ):
            for condition in (
                "${{ needs.ci_change_scope.outputs.owner_windows == 'true' }}",
                "${{ needs.ci_change_scope.outputs.rust == 'true' }}",
                CHECKER.NATIVE_SKIPPED,
            ):
                with self.subTest(step=name, condition=condition):
                    self.assert_rejected(
                        lambda workflow: self.cargo_crap_step(workflow, name).update(
                            {"if": condition}
                        )
                    )
            with self.subTest(step=name, condition="removed"):
                self.assert_rejected(
                    lambda workflow: self.cargo_crap_step(workflow, name).pop("if")
                )

    def test_linux_only_scoring_requires_an_explicitly_skipped_lane(self) -> None:
        for name in (
            "Use Linux coverage without the unmeasured native shim",
            "Drop the unmeasured native shim from the trusted baseline",
        ):
            for key, value in (
                ("if", CHECKER.NATIVE_MEASURED),
                ("if", "${{ needs.ci_change_scope.outputs.owner_windows != 'true' }}"),
                ("if", "${{ true }}"),
                ("continue-on-error", True),
                ("run", "true"),
            ):
                with self.subTest(step=name, control=key, value=value):
                    self.assert_rejected(
                        lambda workflow: self.cargo_crap_step(workflow, name).update(
                            {key: value}
                        )
                    )
            with self.subTest(step=name, control="unconditional"):
                self.assert_rejected(
                    lambda workflow: self.cargo_crap_step(workflow, name).pop("if")
                )

    def test_shim_is_hidden_from_scoring_only_when_the_lane_is_skipped(self) -> None:
        for name in ("Generate trusted current baseline", "Analyze CRAP score changes"):
            for env in (
                {"NATIVE_SHIM_ALLOW": "crates/pos-owner-bridge-windows/**"},
                {"NATIVE_SHIM_ALLOW": (
                    "${{ needs.ci_change_scope.outputs.owner_windows != 'true' && "
                    "'crates/pos-owner-bridge-windows/**' || '' }}")},
                {"NATIVE_SHIM_ALLOW": (
                    "${{ needs.ci_change_scope.outputs.owner_windows == 'false' && "
                    "'crates/**' || '' }}")},
                {},
            ):
                with self.subTest(step=name, env=env):
                    self.assert_rejected(
                        lambda workflow: self.cargo_crap_step(workflow, name).update(
                            {"env": env}
                        )
                    )
            with self.subTest(step=name, change="unconditional allow"):
                def allow_always(workflow: dict) -> None:
                    step = self.cargo_crap_step(workflow, name)
                    step["run"] = step["run"].replace(
                        CHECKER.SHIM_ALLOW_ARG,
                        "--allow 'crates/pos-owner-bridge-windows/**' ",
                    )

                self.assert_rejected(allow_always)

    def test_shim_allow_expands_only_for_a_skipped_lane(self) -> None:
        for value, expected in (
            ("crates/pos-owner-bridge-windows/**",
             ["--allow", "crates/pos-owner-bridge-windows/**"]),
            ("", []),
        ):
            with self.subTest(value=value):
                result = subprocess.run(
                    ["bash", "-c", "printf '%s\\n' " + CHECKER.SHIM_ALLOW_ARG],
                    env=dict(os.environ, NATIVE_SHIM_ALLOW=value),
                    capture_output=True, text=True, check=True, cwd=ROOT,
                )
                self.assertEqual([line for line in result.stdout.split("\n") if line], expected)

    def test_baseline_shim_filter_keeps_every_other_entry_and_fails_closed(self) -> None:
        entries = [
            {"file": "/w/crates/pos-owner-bridge-windows/src/ffi/a.rs", "function": "a"},
            {"file": "C:\\w\\crates\\pos-owner-bridge-windows\\src\\b.rs", "function": "b"},
            {"file": "crates/pos-owner-bridge-windows/src/c.rs", "function": "c"},
            {"file": "/w/crates/pos-owner-bridge/src/d.rs", "function": "d"},
            {"file": "/w/crates/pos-owner-bridge-windows-extra/src/e.rs", "function": "e"},
            {"file": "/w/apps/piglor-owner/src/f.rs", "function": "f"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            baseline = pathlib.Path(directory) / "cargo-crap-baseline.json"
            baseline.write_text(json.dumps({"version": "0.2.2", "entries": entries}), encoding="utf-8")
            subprocess.run(["bash", "-c", CHECKER.DROP_SHIM_BASELINE_COMMAND],
                           env=dict(os.environ, RUNNER_TEMP=directory), check=True)
            kept = json.loads(baseline.read_text(encoding="utf-8"))
            self.assertEqual(kept["version"], "0.2.2")
            self.assertEqual([entry["function"] for entry in kept["entries"]], ["d", "e", "f"])
            baseline.write_text("not json", encoding="utf-8")
            result = subprocess.run(["bash", "-c", CHECKER.DROP_SHIM_BASELINE_COMMAND],
                                    env=dict(os.environ, RUNNER_TEMP=directory),
                                    capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            baseline.unlink()
            result = subprocess.run(["bash", "-c", CHECKER.DROP_SHIM_BASELINE_COMMAND],
                                    env=dict(os.environ, RUNNER_TEMP=directory),
                                    capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)

    def test_cargo_crap_requires_the_native_lane_whenever_it_is_in_scope(self) -> None:
        condition = self.workflow["jobs"]["cargo-crap"]["if"]
        for before, after in (
            ("needs.owner-bridge-windows.result == 'success' || ", ""),
            ("needs.ci_change_scope.outputs.owner_windows == 'false' && ", ""),
            ("outputs.owner_windows == 'false'", "outputs.owner_windows != 'true'"),
            ("needs.owner-bridge-windows.result == 'skipped'",
             "needs.owner-bridge-windows.result != 'failure'"),
        ):
            with self.subTest(before=before):
                self.assertIn(before, condition)
                self.assert_rejected(
                    lambda workflow: workflow["jobs"]["cargo-crap"].update(
                        {"if": condition.replace(before, after)}
                    )
                )
        with self.subTest(change="dependency removed"):
            self.assert_rejected(
                lambda workflow: workflow["jobs"]["cargo-crap"]["needs"].remove(
                    "owner-bridge-windows"
                )
            )

    def test_coverage_merger_is_pinned_as_a_complete_program(self) -> None:
        source = (ROOT / CHECKER.COVERAGE_MERGER).read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "merge_owner_bridge_lcov.py"
            path.write_bytes(source.replace("\n", "\r\n").encode("utf-8"))
            CHECKER.check_workflow(
                ROOT / ".github/workflows/ci.yml", coverage_merger_path=path
            )
            path.write_text(source + "\nraise SystemExit(0)\n", encoding="utf-8")
            with self.assertRaises(CHECKER.PolicyError):
                CHECKER.check_workflow(
                    ROOT / ".github/workflows/ci.yml", coverage_merger_path=path
                )
            path.unlink()
            with self.assertRaises(CHECKER.PolicyError):
                CHECKER.check_coverage_merger(path)

    def test_exclusions_are_the_literal_test_owned_allowlist(self) -> None:
        for step_name in (
            "Generate trusted current baseline",
            "Analyze CRAP score changes",
        ):
            with self.subTest(step=step_name):
                self.assertEqual(
                    self.cargo_crap_exclusions(step_name),
                    EXPECTED_TEST_ONLY_EXCLUSIONS,
                )
                self.assertNotIn("**/src/**", self.cargo_crap_exclusions(step_name))

    def test_test_allowlist_does_not_match_adversarial_production_paths(self) -> None:
        production_paths = (
            "src/tests/engine.rs",
            "src/protocol_tests.rs",
            "src/examples/production.rs",
            "src/system_bus/transport.rs",
            "src/root_selector.rs",
            "src/provider_admission.rs",
            "src/root_selector/tests/admission_bounds_production.rs",
            "src/fork_event_authority/tests/production.rs",
            "src/sqlite/tests/production.rs",
            "src/sqlite/fork_replay/production.rs",
            "src/imported_fork_replay_tests/production.rs",
            "src/imported_fork_replay_tests/lifecycle/production.rs",
            "src/imported_fork_replay_tests/cumulative_budget/production.rs",
            "src/imported_fork_replay_tests/runtime_budget/production.rs",
            "src/nested_imported_fork_replay_tests/production.rs",
            "src/ordinary_fork_lineage_tests/production.rs",
            "src/execute.rs",
            "src/execute/tests/production.rs",
            "src/execute/tests/ownership/production.rs",
            "src/provider_barrier.rs",
            "src/provider_barrier/production.rs",
            "src/provider_lifecycle.rs",
            "src/provider_lifecycle/production.rs",
            "src/adapter.rs",
            "src/adapter/native.rs",
            "src/adapter/native_tests_production.rs",
            "src/adapter/surface/native_tests/production.rs",
        )
        for path in production_paths:
            with self.subTest(path=path):
                self.assertFalse(
                    any(
                        fnmatch.fnmatchcase(path, pattern)
                        for pattern in EXPECTED_TEST_ONLY_EXCLUSIONS
                    )
                )

    def test_internal_test_allowlist_paths_are_exact(self) -> None:
        for path in (
            *EXPECTED_FORK_REPLAY_TEST_EXCLUSIONS,
            *EXPECTED_SANDBOX_EXECUTION_TEST_EXCLUSIONS,
        ):
            with self.subTest(path=path):
                self.assertTrue(
                    any(
                        fnmatch.fnmatchcase(path, pattern)
                        for pattern in self.cargo_crap_exclusions(
                            "Analyze CRAP score changes"
                        )
                    )
                )
                production_neighbor = path.removesuffix(".rs") + "_production.rs"
                self.assertFalse(
                    any(
                        fnmatch.fnmatchcase(production_neighbor, pattern)
                        for pattern in EXPECTED_TEST_ONLY_EXCLUSIONS
                    )
                )

    def test_rejects_internal_test_allowlist_scope_changes(self) -> None:
        for step_name in (
            "Generate trusted current baseline",
            "Analyze CRAP score changes",
        ):
            for path in (
                *EXPECTED_FORK_REPLAY_TEST_EXCLUSIONS,
                *EXPECTED_SANDBOX_EXECUTION_TEST_EXCLUSIONS,
            ):
                parent = str(pathlib.PurePosixPath(path).parent)
                neighbor = path.removesuffix(".rs") + "_production.rs"
                scope_changes = {
                    "broadened": f"--exclude '{parent}/**'",
                    "missing": "",
                    "extra-production": f"--exclude '{path}' --exclude '{neighbor}'",
                }
                for change, replacement in scope_changes.items():
                    with self.subTest(step=step_name, path=path, change=change):
                        def change_scope(
                            workflow, *, step_name=step_name, path=path,
                            replacement=replacement,
                        ):
                            step = self.cargo_crap_step(workflow, step_name)
                            step["run"] = step["run"].replace(
                                f"--exclude '{path}'", replacement
                            )

                        self.assert_rejected(change_scope)

    def test_rejects_admission_bounds_allowlist_scope_changes(self) -> None:
        path = "src/root_selector/tests/admission_bounds.rs"
        scope_changes = (
            "",
            "--exclude 'src/root_selector/tests/**'",
            "--exclude 'src/root_selector/**'",
            "--exclude 'src/root_selector.rs'",
            "--exclude 'src/provider_admission.rs'",
            f"--exclude '{path}' "
            "--exclude 'src/root_selector/tests/admission_bounds_production.rs'",
        )
        for step_name in (
            "Generate trusted current baseline",
            "Analyze CRAP score changes",
        ):
            for replacement in scope_changes:
                with self.subTest(step=step_name, replacement=replacement):
                    def change_scope(
                        workflow, *, step_name=step_name, replacement=replacement,
                    ):
                        step = self.cargo_crap_step(workflow, step_name)
                        step["run"] = step["run"].replace(
                            f"--exclude '{path}'", replacement
                        )

                    self.assert_rejected(change_scope)

    def test_rejects_excluding_production_source(self) -> None:
        def exclude_production(workflow: dict) -> None:
            step = self.cargo_crap_step(workflow, "Analyze CRAP score changes")
            step["run"] = step["run"].replace(
                "--format json", "--exclude '**/src/**' --format json"
            )

        self.assert_rejected(exclude_production)

    def test_resolver_executes_the_exact_trusted_artifact_query(self) -> None:
        result, logs = self.run_resolver("4242\n")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            logs["output"],
            f"run-id=4242\nbaseline-sha={EXAMPLE_BASE_SHA}\nbootstrap=false\n",
        )
        self.assertEqual(self.gh_calls(logs), ["artifacts"])
        self.assertEqual(logs["sleep_calls"], "")
        self.assertEqual(
            logs["git_calls"],
            f"merge-base\n{EXAMPLE_BASE_SHA}\norigin/main\n",
        )
        expected_query = (
            ".artifacts[] |\n"
            "      select(.expired == false) |\n"
            '      select(.workflow_run.head_branch == "main") |\n'
            f'      select(.workflow_run.head_sha == "{EXAMPLE_BASE_SHA}") |\n'
            "      select(.workflow_run.head_repository_id == "
            ".workflow_run.repository_id) |\n"
            "      .workflow_run.id"
        )
        self.assertEqual(
            logs["gh_args"].split("\0")[:-1],
            [
                "api",
                "--method",
                "GET",
                "--paginate",
                "repos/owner/repository/actions/artifacts",
                "-f",
                f"name=cargo-crap-baseline-{EXAMPLE_BASE_SHA}",
                "-f",
                "per_page=100",
                "--jq",
                expected_query,
            ],
        )

    def test_resolver_fails_closed_after_the_bounded_retry_window(self) -> None:
        result, logs = self.run_resolver("")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(logs["output"], "")
        self.assertEqual(self.gh_calls(logs), NO_MAIN_RUN_CALLS)
        self.assertEqual(logs["sleep_calls"], "10\n" * 29 + "60\n" * 5)
        self.assertIn(
            f"Trusted main baseline {EXAMPLE_BASE_SHA} for base {EXAMPLE_BASE_SHA} "
            "is not available yet (attempt 29/30); retrying in 10s\n",
            result.stdout,
        )
        self.assertEqual(
            logs["git_calls"],
            f"merge-base\n{EXAMPLE_BASE_SHA}\norigin/main\n"
            f"{REV_LIST_CALL}"
            f"diff\n--quiet\n{EXAMPLE_BASE_SHA}...HEAD\n--\n"
            "*.rs\n**/Cargo.toml\nCargo.toml\n**/Cargo.lock\nCargo.lock\n"
            "rust-toolchain\nrust-toolchain.toml\n.cargo/config.toml\n.cargo-crap.toml\n",
        )

    def test_resolver_uses_the_trusted_main_merge_base_for_stacked_pull_requests(self) -> None:
        stacked_base = "b" * 40
        result, logs = self.run_resolver(
            "4242\n", base_sha=stacked_base, trusted_base_sha=EXAMPLE_BASE_SHA
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            logs["output"],
            f"run-id=4242\nbaseline-sha={EXAMPLE_BASE_SHA}\nbootstrap=false\n",
        )
        self.assertIn(f"name=cargo-crap-baseline-{EXAMPLE_BASE_SHA}", logs["gh_args"])
        self.assertEqual(
            logs["git_calls"],
            f"merge-base\n{stacked_base}\norigin/main\n",
        )

    def test_resolver_fails_closed_when_the_stacked_main_baseline_is_missing(self) -> None:
        stacked_base = "b" * 40
        result, logs = self.run_resolver(
            "", base_sha=stacked_base, trusted_base_sha=EXAMPLE_BASE_SHA
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(logs["output"], "")
        self.assertEqual(self.gh_calls(logs), NO_MAIN_RUN_CALLS)
        self.assertIn(f"name=cargo-crap-baseline-{EXAMPLE_BASE_SHA}", logs["gh_args"])
        self.assertEqual(
            logs["git_calls"],
            f"merge-base\n{stacked_base}\norigin/main\n"
            f"{REV_LIST_CALL}"
            f"diff\n--quiet\n{stacked_base}...HEAD\n--\n"
            "*.rs\n**/Cargo.toml\nCargo.toml\n**/Cargo.lock\nCargo.lock\n"
            "rust-toolchain\nrust-toolchain.toml\n.cargo/config.toml\n.cargo-crap.toml\n",
        )

    def test_resolver_bootstraps_when_only_the_trusted_artifact_is_missing(self) -> None:
        result, logs = self.run_resolver(
            "",
            base_sha=EXAMPLE_BASE_SHA,
            trusted_base_sha=EXAMPLE_BASE_SHA,
            git_status=0,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(logs["output"], "bootstrap=true\n")
        self.assertIn(f"{EXAMPLE_BASE_SHA}...HEAD", logs["git_calls"])

    def test_resolver_rejects_bootstrap_when_policy_inputs_changed(self) -> None:
        result, logs = self.run_resolver(
            "",
            base_sha=EXAMPLE_BASE_SHA,
            trusted_base_sha=EXAMPLE_BASE_SHA,
            git_status=1,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(logs["output"], "")
        self.assertIn(f"{EXAMPLE_BASE_SHA}...HEAD", logs["git_calls"])

    def test_resolver_waits_for_an_in_progress_main_run_to_publish_the_baseline(self) -> None:
        # 30 short-window misses, one miss after the first main-run poll, then
        # the artifact appears after the second poll.
        result, logs = self.run_resolver(
            [""] * 31 + ["4242\n"],
            ["777 queued none\n", "777 in_progress none\n"],
            ["", "queued none\n"],
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            logs["output"],
            f"run-id=4242\nbaseline-sha={EXAMPLE_BASE_SHA}\nbootstrap=false\n",
        )
        self.assertEqual(
            self.gh_calls(logs),
            ["artifacts"] * 30 + ["runs", "jobs", "artifacts"] * 2,
        )
        self.assertEqual(logs["sleep_calls"], "10\n" * 29 + "60\n" * 2)
        self.assertIn("Waiting for main ci.yml run 777 (queued, cargo-crap job pending)", result.stdout)
        self.assertIn(
            "Waiting for main ci.yml run 777 (in_progress, cargo-crap job queued)", result.stdout
        )
        self.assertNotIn("diff", logs["git_calls"])
        expected_runs_query = (
            ".workflow_runs[] |\n"
            '      select(.head_branch == "main") |\n'
            f'      select(.head_sha == "{EXAMPLE_BASE_SHA}") |\n'
            "      select(.head_repository.id == .repository.id) |\n"
            '      "\\(.id) \\(.status) \\(.conclusion // "none")"'
        )
        self.assertEqual(
            self.gh_invocations(logs)[30],
            [
                "api",
                "--method",
                "GET",
                "--paginate",
                "repos/owner/repository/actions/workflows/ci.yml/runs",
                "-f",
                "branch=main",
                "-f",
                f"head_sha={EXAMPLE_BASE_SHA}",
                "-f",
                "per_page=100",
                "--jq",
                expected_runs_query,
            ],
        )

    def test_resolver_main_run_query_keeps_only_same_repository_main_runs(self) -> None:
        _, logs = self.run_resolver("")
        query = self.gh_invocations(logs)[30][-1]
        same = {"id": 1}
        other = {"id": 2}
        runs = [
            {"id": 10, "status": "in_progress", "conclusion": None, "head_branch": "main",
             "head_sha": EXAMPLE_BASE_SHA, "head_repository": same, "repository": same},
            {"id": 11, "status": "completed", "conclusion": "failure", "head_branch": "main",
             "head_sha": EXAMPLE_BASE_SHA, "head_repository": same, "repository": same},
            {"id": 12, "status": "queued", "conclusion": None, "head_branch": "main",
             "head_sha": EXAMPLE_BASE_SHA, "head_repository": other, "repository": same},
            {"id": 13, "status": "queued", "conclusion": None, "head_branch": "feature",
             "head_sha": EXAMPLE_BASE_SHA, "head_repository": same, "repository": same},
            {"id": 14, "status": "queued", "conclusion": None, "head_branch": "main",
             "head_sha": "b" * 40, "head_repository": same, "repository": same},
        ]
        selected = subprocess.run(
            ["jq", "-r", query],
            input=json.dumps({"workflow_runs": runs}),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(selected.stdout, "10 in_progress none\n11 completed failure\n")

    def test_resolver_prefers_an_unfinished_main_run_over_a_completed_attempt(self) -> None:
        result, logs = self.run_resolver(
            [""] * 31 + ["4242\n"], "900 completed failure\n901 in_progress none\n"
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("run-id=4242\n", logs["output"])
        self.assertIn("Waiting for main ci.yml run 901 (in_progress, cargo-crap job pending)", result.stdout)

    def test_resolver_accepts_a_baseline_listed_once_the_main_run_completed(self) -> None:
        result, logs = self.run_resolver([""] * 30 + ["4242\n"], "777 completed success\n")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("run-id=4242\n", logs["output"])
        self.assertEqual(self.gh_calls(logs), ["artifacts"] * 30 + ["runs", "artifacts"])
        self.assertEqual(logs["sleep_calls"], "10\n" * 29)

    def test_resolver_fails_closed_when_the_main_run_failed_without_a_baseline(self) -> None:
        result, logs = self.run_resolver("", "777 completed failure\n")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(logs["output"], "")
        self.assertEqual(self.gh_calls(logs), ["artifacts"] * 30 + ["runs", "artifacts"])
        self.assertEqual(logs["sleep_calls"], "10\n" * 29)
        self.assertIn(
            f"::error::Trusted main baseline unavailable: main ci.yml run 777 for trusted base "
            f"{EXAMPLE_BASE_SHA} completed with conclusion failure without publishing "
            f"cargo-crap-baseline-{EXAMPLE_BASE_SHA}{NO_ANCESTOR_REASON}",
            result.stdout,
        )
        self.assertIn(f"{EXAMPLE_BASE_SHA}...HEAD", logs["git_calls"])

    def test_resolver_bootstraps_non_rust_changes_after_a_cancelled_main_run(self) -> None:
        result, logs = self.run_resolver("", "777 completed cancelled\n", git_status=0)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(logs["output"], "bootstrap=true\n")
        self.assertIn("completed with conclusion cancelled", result.stdout)
        self.assertIn("::notice::", result.stdout)

    def test_resolver_fails_closed_when_main_has_no_run_for_the_trusted_base(self) -> None:
        result, logs = self.run_resolver("", "")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(logs["output"], "")
        self.assertEqual(self.gh_calls(logs), NO_MAIN_RUN_CALLS)
        self.assertIn(
            f"::error::Trusted main baseline unavailable: no main ci.yml run exists for "
            f"trusted base {EXAMPLE_BASE_SHA} after 590s{NO_ANCESTOR_REASON}",
            result.stdout,
        )

    def test_resolver_fails_closed_when_the_wait_bound_expires(self) -> None:
        result, logs = self.run_resolver("", "777 in_progress none\n")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(logs["output"], "")
        delays = [int(delay) for delay in logs["sleep_calls"].split()]
        # The 290 s short window plus 25 one-minute polls stays inside 1800 s;
        # one more poll would exceed the bound, so the resolver stops.
        self.assertEqual(delays, [10] * 29 + [60] * 25)
        self.assertLessEqual(sum(delays), 1800)
        self.assertEqual(
            self.gh_calls(logs),
            ["artifacts"] * 30 + ["runs", "jobs", "artifacts"] * 25 + ["runs", "jobs"],
        )
        self.assertIn(
            f"::error::Trusted main baseline unavailable: main ci.yml run 777 for trusted base "
            f"{EXAMPLE_BASE_SHA} is still in_progress after 1790s; the 1800s wait bound "
            f"expired without cargo-crap-baseline-{EXAMPLE_BASE_SHA}{NO_ANCESTOR_REASON}",
            result.stdout,
        )
        self.assertIn(f"{EXAMPLE_BASE_SHA}...HEAD", logs["git_calls"])

    def test_resolver_retries_a_transient_github_api_failure(self) -> None:
        result, logs = self.run_resolver(["FAIL", "FAIL", "4242\n"])

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            logs["output"],
            f"run-id=4242\nbaseline-sha={EXAMPLE_BASE_SHA}\nbootstrap=false\n",
        )
        self.assertEqual(self.gh_calls(logs), ["artifacts"] * 3)
        self.assertEqual(logs["sleep_calls"], "30\n30\n")
        self.assertIn(
            "GitHub API request repos/owner/repository/actions/artifacts failed "
            "(attempt 2/3); retrying in 30s\n",
            result.stdout,
        )

    def test_resolver_fails_closed_on_persistent_github_api_failures(self) -> None:
        # git_status=0 would allow bootstrap; an API failure must never reach it.
        result, logs = self.run_resolver("FAIL", git_status=0)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(logs["output"], "")
        self.assertEqual(self.gh_calls(logs), ["artifacts"] * 3)
        self.assertEqual(logs["sleep_calls"], "30\n30\n")
        self.assertEqual(logs["git_calls"], f"merge-base\n{EXAMPLE_BASE_SHA}\norigin/main\n")
        self.assertIn(
            "::error::GitHub API request repos/owner/repository/actions/artifacts failed 3 "
            "consecutive times; failing closed without a trusted main baseline\n",
            result.stdout,
        )

    def test_resolver_fails_closed_on_persistent_failures_while_waiting_for_main(self) -> None:
        result, logs = self.run_resolver("", "FAIL", git_status=0)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(logs["output"], "")
        self.assertEqual(self.gh_calls(logs), ["artifacts"] * 30 + ["runs"] * 3)
        self.assertNotIn("diff", logs["git_calls"])
        self.assertIn(
            "::error::GitHub API request repos/owner/repository/actions/workflows/ci.yml/runs "
            "failed 3 consecutive times",
            result.stdout,
        )

    def test_resolver_stops_once_mains_cargo_crap_job_completed(self) -> None:
        result, logs = self.run_resolver("", "777 in_progress none\n", "completed failure\n")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(logs["output"], "")
        self.assertEqual(self.gh_calls(logs), ["artifacts"] * 30 + ["runs", "jobs", "artifacts"])
        self.assertEqual(logs["sleep_calls"], "10\n" * 29)
        self.assertEqual(
            self.gh_invocations(logs)[31][:9],
            [
                "api",
                "--method",
                "GET",
                "--paginate",
                "repos/owner/repository/actions/runs/777/jobs",
                "-f",
                "filter=latest",
                "-f",
                "per_page=100",
            ],
        )
        self.assertIn(
            f"::error::Trusted main baseline unavailable: the cargo-crap job of main ci.yml run "
            f"777 for trusted base {EXAMPLE_BASE_SHA} completed with conclusion failure without "
            f"publishing cargo-crap-baseline-{EXAMPLE_BASE_SHA}{NO_ANCESTOR_REASON}",
            result.stdout,
        )

    def test_resolver_accepts_a_baseline_listed_once_mains_cargo_crap_job_completed(self) -> None:
        result, logs = self.run_resolver(
            [""] * 30 + ["4242\n"], "777 in_progress none\n", "completed success\n"
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("run-id=4242\n", logs["output"])
        self.assertEqual(self.gh_calls(logs), ["artifacts"] * 30 + ["runs", "jobs", "artifacts"])

    def test_resolver_reports_the_newest_of_several_completed_main_runs(self) -> None:
        # GitHub lists the newest run first; it decides the reason.
        result, _ = self.run_resolver("", "902 completed cancelled\n901 completed failure\n")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            f"main ci.yml run 902 for trusted base {EXAMPLE_BASE_SHA} completed with "
            "conclusion cancelled without publishing",
            result.stdout,
        )
        self.assertNotIn("run 901", result.stdout)

    def test_resolver_uses_the_first_listed_cargo_crap_job(self) -> None:
        result, logs = self.run_resolver(
            "", "777 in_progress none\n", "completed failure\nin_progress none\n"
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.gh_calls(logs), ["artifacts"] * 30 + ["runs", "jobs", "artifacts"])
        self.assertIn(
            "the cargo-crap job of main ci.yml run 777 for trusted base "
            f"{EXAMPLE_BASE_SHA} completed with conclusion failure",
            result.stdout,
        )

    def test_resolver_job_query_selects_only_the_cargo_crap_job(self) -> None:
        _, logs = self.run_resolver("", "777 in_progress none\n", "completed failure\n")
        query = self.gh_invocations(logs)[31][-1]
        jobs = [
            {"name": "coverage", "status": "completed", "conclusion": "success"},
            {"name": "cargo-crap", "status": "in_progress", "conclusion": None},
            {"name": "cargo-crap-report", "status": "completed", "conclusion": "failure"},
        ]
        selected = subprocess.run(
            ["jq", "-r", query],
            input=json.dumps({"jobs": jobs}),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(selected.stdout, "in_progress none\n")

    def test_resolver_waits_for_a_main_run_to_register(self) -> None:
        result, logs = self.run_resolver(
            [""] * 32 + ["4242\n"], ["", "", "777 queued none\n"]
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("run-id=4242\n", logs["output"])
        self.assertEqual(
            self.gh_calls(logs),
            ["artifacts"] * 30 + ["runs", "artifacts"] * 2 + ["runs", "jobs", "artifacts"],
        )
        self.assertEqual(logs["sleep_calls"], "10\n" * 29 + "60\n" * 3)
        self.assertIn(
            f"No main ci.yml run for trusted base {EXAMPLE_BASE_SHA} yet "
            "(290s of 600s registration window elapsed); checking again in 60s\n",
            result.stdout,
        )

    ANCESTORS = ("c" * 40, "d" * 40, "e" * 40)

    def assert_ancestor_baseline(self, result, logs, ancestor: str, run_id: str) -> None:
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            logs["output"],
            f"run-id={run_id}\nbaseline-sha={ancestor}\nbootstrap=false\n",
        )
        self.assertIn(f"::notice::Using the cargo-crap baseline of main ancestor {ancestor} because ", result.stdout)
        self.assertIn(REV_LIST_CALL, logs["git_calls"])
        # An ancestor baseline is a trusted baseline: the bootstrap check never runs.
        self.assertNotIn("diff", logs["git_calls"])

    def test_resolver_falls_back_to_the_nearest_ancestor_after_a_failed_main_run(self) -> None:
        result, logs = self.run_resolver(
            "",
            "777 completed failure\n",
            ancestors=self.ANCESTORS,
            ancestor_artifacts={"d" * 40: "5151\n5150\n", "e" * 40: "4949\n"},
        )

        self.assert_ancestor_baseline(result, logs, "d" * 40, "5151")
        self.assertEqual(
            self.gh_calls(logs),
            ["artifacts"] * 30 + ["runs", "artifacts", f"ancestor:{'c' * 40}", f"ancestor:{'d' * 40}"],
        )
        self.assertIn(
            f"::notice::Using the cargo-crap baseline of main ancestor {'d' * 40} because "
            f"main ci.yml run 777 for trusted base {EXAMPLE_BASE_SHA} completed with conclusion "
            f"failure without publishing cargo-crap-baseline-{EXAMPLE_BASE_SHA}\n",
            result.stdout,
        )
        self.assertEqual(logs["sleep_calls"], "10\n" * 29)

    def test_resolver_falls_back_to_an_ancestor_when_main_has_no_run(self) -> None:
        result, logs = self.run_resolver(
            "", "", ancestors=self.ANCESTORS, ancestor_artifacts={"c" * 40: "6060\n"}
        )

        self.assert_ancestor_baseline(result, logs, "c" * 40, "6060")
        self.assertIn(f"because no main ci.yml run exists for trusted base {EXAMPLE_BASE_SHA}", result.stdout)

    def test_resolver_falls_back_to_an_ancestor_once_the_wait_bound_expires(self) -> None:
        result, logs = self.run_resolver(
            "",
            "777 in_progress none\n",
            ancestors=self.ANCESTORS,
            ancestor_artifacts={"e" * 40: "4949\n"},
        )

        self.assert_ancestor_baseline(result, logs, "e" * 40, "4949")
        delays = [int(delay) for delay in logs["sleep_calls"].split()]
        self.assertEqual(delays, [10] * 29 + [60] * 25)
        self.assertIn("the 1800s wait bound expired", result.stdout)

    def test_resolver_waits_for_main_before_using_an_ancestor_baseline(self) -> None:
        result, logs = self.run_resolver(
            [""] * 31 + ["4242\n"],
            "777 in_progress none\n",
            ancestors=self.ANCESTORS,
            ancestor_artifacts={"c" * 40: "6060\n"},
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            logs["output"],
            f"run-id=4242\nbaseline-sha={EXAMPLE_BASE_SHA}\nbootstrap=false\n",
        )
        self.assertNotIn("ancestor:", logs["gh_calls"])
        self.assertNotIn("rev-list", logs["git_calls"])

    def test_resolver_fails_closed_when_no_ancestor_within_the_bound_has_a_baseline(self) -> None:
        result, logs = self.run_resolver("", "777 completed failure\n", ancestors=self.ANCESTORS)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(logs["output"], "")
        self.assertEqual(
            self.gh_calls(logs)[-3:],
            [f"ancestor:{ancestor}" for ancestor in self.ANCESTORS],
        )
        self.assertIn(f"::error::Trusted main baseline unavailable: ", result.stdout)
        self.assertIn(NO_ANCESTOR_REASON, result.stdout)
        self.assertEqual(
            logs["git_calls"],
            f"merge-base\n{EXAMPLE_BASE_SHA}\norigin/main\n{REV_LIST_CALL}"
            f"diff\n--quiet\n{EXAMPLE_BASE_SHA}...HEAD\n--\n"
            "*.rs\n**/Cargo.toml\nCargo.toml\n**/Cargo.lock\nCargo.lock\n"
            "rust-toolchain\nrust-toolchain.toml\n.cargo/config.toml\n.cargo-crap.toml\n",
        )

    def test_resolver_bootstraps_non_rust_changes_when_no_ancestor_has_a_baseline(self) -> None:
        result, logs = self.run_resolver(
            "", "777 completed failure\n", ancestors=self.ANCESTORS, git_status=0
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(logs["output"], "bootstrap=true\n")
        self.assertIn(NO_ANCESTOR_REASON.removesuffix("; failing closed"), result.stdout)
        self.assertIn("bootstrapping because this pull request changes no Rust", result.stdout)

    def test_resolver_aborts_when_the_ancestor_walk_fails(self) -> None:
        for name, options in {
            "git rev-list": {"rev_list_status": 128},
            "gh artifact query": {"ancestor_artifacts": {"c" * 40: None, "d" * 40: "5151\n"}},
        }.items():
            with self.subTest(name):
                result, logs = self.run_resolver(
                    "", "777 completed failure\n", ancestors=self.ANCESTORS, git_status=0, **options
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(logs["output"], "")
                self.assertNotIn("diff", logs["git_calls"])

    def test_resolver_ancestor_query_keeps_only_same_repository_main_artifacts(self) -> None:
        ancestor = "c" * 40
        _, logs = self.run_resolver("", "", ancestors=(ancestor,))
        invocation = self.gh_invocations(logs)[-1]
        self.assertEqual(
            invocation[:-1],
            [
                "api",
                "--method",
                "GET",
                "--paginate",
                "repos/owner/repository/actions/artifacts",
                "-f",
                f"name=cargo-crap-baseline-{ancestor}",
                "-f",
                "per_page=100",
                "--jq",
            ],
        )
        same, other = 1, 2

        def artifact(run_id: int, **changes) -> dict:
            run = {"id": run_id, "head_branch": "main", "head_sha": ancestor,
                   "head_repository_id": same, "repository_id": same}
            expired = changes.pop("expired", False)
            run.update(changes)
            return {"expired": expired, "workflow_run": run}

        artifacts = [
            artifact(10),
            artifact(11, expired=True),
            artifact(12, head_repository_id=other),
            artifact(13, head_branch="feature"),
            artifact(14, head_sha=EXAMPLE_BASE_SHA),
            artifact(15),
        ]
        selected = subprocess.run(
            ["jq", "-r", invocation[-1]],
            input=json.dumps({"artifacts": artifacts}),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(selected.stdout, "10\n15\n")

    def test_rejects_weakened_ancestor_baseline_fallback(self) -> None:
        resolver = RESOLVER_PATH.read_text(encoding="utf-8")
        mutations = {
            "longer walk": ("ANCESTOR_BASELINE_WALK_LIMIT=30", "ANCESTOR_BASELINE_WALK_LIMIT=300"),
            "any parent": ("git rev-list --first-parent --skip=1", "git rev-list --skip=1"),
            "unbounded walk": ('--max-count="${ANCESTOR_BASELINE_WALK_LIMIT}" ', ""),
            "other history": (
                '--max-count="${ANCESTOR_BASELINE_WALK_LIMIT}" "${TRUSTED_BASE_SHA}")"',
                '--max-count="${ANCESTOR_BASELINE_WALK_LIMIT}" HEAD)"',
            ),
            "any artifact name": ('-f name="cargo-crap-baseline-${sha}"', '-f name="cargo-crap-baseline"'),
            "any commit": ('select(.workflow_run.head_sha == \\"${sha}\\") |', ""),
            "wrong baseline commit": (
                'echo "baseline-sha=${sha}" >> "${GITHUB_OUTPUT}"',
                'echo "baseline-sha=${TRUSTED_BASE_SHA}" >> "${GITHUB_OUTPUT}"',
            ),
            "ancestor looked up as the trusted base": (
                '    publish_baseline_of "${ancestor}" \\\n',
                '    publish_baseline_of "${TRUSTED_BASE_SHA}" \\\n',
            ),
            "trusted base looked up as something else": (
                '  publish_baseline_of "${TRUSTED_BASE_SHA}"\n}',
                '  publish_baseline_of "${BASE_SHA}"\n}',
            ),
            "skips the wait": (
                "for ((attempt = 1; attempt <= BASELINE_RETRY_ATTEMPTS; attempt++)); do\n",
                "publish_ancestor_baseline\n"
                "for ((attempt = 1; attempt <= BASELINE_RETRY_ATTEMPTS; attempt++)); do\n",
            ),
            "no fallback": ("\npublish_ancestor_baseline\nreason=", "\nreason="),
            "expired artifacts": ("      select(.expired == false) |\n", ""),
            "other branches": ('      select(.workflow_run.head_branch == \\"main\\") |\n', ""),
            "fork artifacts": (
                "      select(.workflow_run.head_repository_id == .workflow_run.repository_id) |\n",
                "",
            ),
        }
        for name, (old, new) in mutations.items():
            with self.subTest(name):
                self.assertEqual(resolver.count(old), 1, old)
                self.assert_resolver_rejected(lambda text: text.replace(old, new))

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

    def test_rejects_unrestricted_bootstrap(self) -> None:
        self.assert_resolver_rejected(
            lambda resolver: resolver.replace(
                'git diff --quiet "${BASE_SHA}...HEAD" --',
                "true # unrestricted bootstrap",
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

    def test_codeql_waits_for_core_gate_except_on_documentation_only_prs(self) -> None:
        condition = self.workflow["jobs"]["codeql"]["if"]
        for before, after in (
            (" || needs.ci_change_scope.outputs.rust == 'false')", ")"),
            ("|| needs.ci_change_scope.outputs.rust == 'false'", "|| needs.ci_change_scope.outputs.rust != 'true'"),
            ("needs.coverage.result == 'success') ||", "needs.coverage.result != 'failure') ||"),
            ("${{ !cancelled() && needs.ci_change_scope.result == 'success' && ", "${{ !cancelled() && "),
        ):
            with self.subTest(before=before):
                self.assertIn(before, condition)
                self.assert_rejected(
                    lambda workflow, before=before, after=after: workflow["jobs"]["codeql"].update(
                        {"if": condition.replace(before, after)}
                    )
                )

    def test_requires_scoped_cargo_crap(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["cargo-crap"].update(
                {"if": "${{ always() }}"}
            )
        )

    def test_cargo_crap_ignores_accepted_skipped_ancestors(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["cargo-crap"].update(
                {
                    "if": workflow["jobs"]["cargo-crap"]["if"].replace(
                        "!cancelled() && ", ""
                    )
                }
            )
        )

    def test_staged_main_jobs_ignore_accepted_skipped_ancestors(self) -> None:
        for job_name in CHECKER.STAGED_MAIN_JOBS:
            with self.subTest(job=job_name):
                def remove_status_check(workflow, *, job_name=job_name):
                    workflow["jobs"][job_name]["if"] = workflow["jobs"][job_name][
                        "if"
                    ].replace("!cancelled() && ", "")

                self.assert_rejected(remove_status_check)

    def test_staged_main_jobs_require_successful_direct_dependencies(self) -> None:
        for job_name, (needs, condition) in CHECKER.STAGED_MAIN_JOBS.items():
            for dependency in needs:
                check = f"needs.{dependency}.result == 'success'"
                if check not in condition:
                    continue
                with self.subTest(job=job_name, dependency=dependency):
                    def accept_failure(workflow, *, job_name=job_name, check=check):
                        workflow["jobs"][job_name]["if"] = workflow["jobs"][job_name][
                            "if"
                        ].replace(check, check.replace("== 'success'", "!= 'cancelled'"), 1)

                    self.assert_rejected(accept_failure)

    def test_staged_main_jobs_wait_for_the_complete_core_set(self) -> None:
        for job_name, (needs, _) in CHECKER.STAGED_MAIN_JOBS.items():
            for dependency in ("trunk-pr", "test-shards", "coverage", "world-client-wasm"):
                if dependency not in needs:
                    continue
                with self.subTest(job=job_name, dependency=dependency):
                    self.assert_rejected(
                        lambda workflow, job_name=job_name, dependency=dependency: workflow[
                            "jobs"
                        ][job_name].update(
                            needs=[need for need in needs if need != dependency]
                        )
                    )
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["rustdoc"].update(
                needs=["ci_change_scope", "core-gate"]
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

    def test_rejects_weakened_main_run_wait(self) -> None:
        mutations = {
            "longer bound": ("BASELINE_WAIT_LIMIT_SECONDS=1800", "BASELINE_WAIT_LIMIT_SECONDS=7200"),
            "shorter bound": ("BASELINE_WAIT_LIMIT_SECONDS=1800", "BASELINE_WAIT_LIMIT_SECONDS=300"),
            "faster poll": ("MAIN_RUN_POLL_DELAY_SECONDS=60", "MAIN_RUN_POLL_DELAY_SECONDS=1"),
            "unbounded wait": (
                "if ((elapsed + MAIN_RUN_POLL_DELAY_SECONDS > BASELINE_WAIT_LIMIT_SECONDS)); then",
                "if false; then",
            ),
            "fork runs": ("select(.head_repository.id == .repository.id) |", ""),
            "any branch": ('-f branch=main -f head_sha', '-f head_sha'),
            "keeps waiting after completion": (
                'if [[ "${main_run_status}" == "completed" ]]; then',
                'if [[ "${main_run_status}" == "never" ]]; then',
            ),
        }
        for name, (old, new) in mutations.items():
            with self.subTest(name):
                self.assertIn(old, RESOLVER_PATH.read_text(encoding="utf-8"))
                self.assert_resolver_rejected(lambda resolver: resolver.replace(old, new))

    def test_cargo_crap_timeouts_cover_the_bounded_wait(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["cargo-crap"].update({"timeout-minutes": 60})
        )
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["cargo-crap"].update({"timeout-minutes": 150})
        )
        self.assert_rejected(
            lambda workflow: self.cargo_crap_step(
                workflow, "Resolve trusted cargo-crap baseline"
            ).pop("timeout-minutes")
        )
        self.assert_rejected(
            lambda workflow: self.cargo_crap_step(
                workflow, "Resolve trusted cargo-crap baseline"
            ).update({"timeout-minutes": 40})
        )

    def test_cargo_crap_timeouts_leave_room_beyond_the_wait_bound(self) -> None:
        resolver = RESOLVER_PATH.read_text(encoding="utf-8")
        wait = next(
            int(line.split("=", 1)[1])
            for line in resolver.splitlines()
            if line.startswith("BASELINE_WAIT_LIMIT_SECONDS=")
        )
        job = self.workflow["jobs"]["cargo-crap"]
        step = self.cargo_crap_step(self.workflow, "Resolve trusted cargo-crap baseline")
        # The step must outlast the wait by the ancestor walk and API retries,
        # and the job must leave the pre-steps and scoring their own budget.
        self.assertGreaterEqual(step["timeout-minutes"] * 60, wait + 15 * 60)
        self.assertGreaterEqual(job["timeout-minutes"], step["timeout-minutes"] + 20)

    def test_rejects_resolver_give_up_paths_that_skip_the_recheck_or_reason(self) -> None:
        mutations = {
            "no recheck after the run completed": (
                '  if [[ "${main_run_status}" == "completed" ]]; then\n'
                "    publish_baseline_if_available\n",
                '  if [[ "${main_run_status}" == "completed" ]]; then\n',
            ),
            "no recheck after the cargo-crap job completed": (
                '  if [[ "${crap_job_status}" == "completed" ]]; then\n'
                "    publish_baseline_if_available\n",
                '  if [[ "${crap_job_status}" == "completed" ]]; then\n',
            ),
            "no reason without a run": (
                '      reason="no main ci.yml run exists for trusted base ${TRUSTED_BASE_SHA} after ${elapsed}s"\n',
                "",
            ),
            "no reason at the bound": (
                '    reason="main ci.yml run ${main_run_id} for trusted base ${TRUSTED_BASE_SHA} is still ',
                '    unused="main ci.yml run ${main_run_id} for trusted base ${TRUSTED_BASE_SHA} is still ',
            ),
            "unbounded registration window": (
                "if ((elapsed + MAIN_RUN_POLL_DELAY_SECONDS > MAIN_RUN_REGISTRATION_LIMIT_SECONDS)); then",
                "if false; then",
            ),
            "ignores the cargo-crap job": (
                'select(.name == \\"cargo-crap\\")', 'select(.name == \\"coverage\\")',
            ),
            "fail-open final decision": (
                "policy inputs\"\nexit 1\n", "policy inputs\"\nexit 0\n",
            ),
            "unconditional bootstrap": (
                "  exit 0\nfi\necho \"::error::Trusted main baseline unavailable",
                "  exit 0\nfi\necho 'bootstrap=true' >> \"${GITHUB_OUTPUT}\"\n"
                "echo \"::error::Trusted main baseline unavailable",
            ),
            "API failure falls through": (
                "failing closed without a trusted main baseline\"\n  exit 1\n}\n",
                "failing closed without a trusted main baseline\"\n  return 1\n}\n",
            ),
            "unretried API call": (
                "  read_main_run\n",
                "  read_main_run\n  gh api repos/x/y >/dev/null\n",
            ),
            "more API retries": ("GH_API_ATTEMPTS=3", "GH_API_ATTEMPTS=30"),
        }
        for name, (old, new) in mutations.items():
            with self.subTest(name):
                self.assertIn(old, RESOLVER_PATH.read_text(encoding="utf-8"))
                self.assert_resolver_rejected(lambda resolver: resolver.replace(old, new))

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
                'BASELINE_ARTIFACT_NAME="cargo-crap-baseline-${TRUSTED_BASE_SHA}"',
                'BASELINE_ARTIFACT_NAME="cargo-crap-baseline-${TRUSTED_BASE_SHA}"\n'
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

    def test_ci_gate_cargo_crap_verdict_cannot_be_weakened(self) -> None:
        for before, after in (
            ('[[ "${RUST_SCOPE_RESULT}" = false ]]', '[[ "${RUST_SCOPE_RESULT}" != true ]]'),
            ("expected_cargo_crap=success\n", "expected_cargo_crap=skipped\n"),
            ("  failed=1\n", "  :\n"),
        ):
            with self.subTest(before=before):
                def weaken(workflow: dict, before=before, after=after) -> None:
                    step = workflow["jobs"]["ci-gate"]["steps"][0]
                    step["run"] = step["run"].replace(CHECKER.CI_GATE_CARGO_CRAP_CHECK,
                                                      CHECKER.CI_GATE_CARGO_CRAP_CHECK.replace(before, after), 1)

                self.assert_rejected(weaken)
        self.assert_rejected(lambda workflow: workflow["jobs"]["ci-gate"].update({"if": "${{ success() }}"}))
        self.assert_rejected(lambda workflow: workflow["jobs"]["ci-gate"]["steps"][0]["env"].update(
            RUST_SCOPE_RESULT="false"))

    def test_ci_gate_rejects_missing_failed_or_skipped_in_scope_cargo_crap(self) -> None:
        step = self.workflow["jobs"]["ci-gate"]["steps"][0]
        for rust, event, expected in (("true", "pull_request", "success"),
                                      ("true", "push", "success"),
                                      ("", "pull_request", "success"),
                                      ("false", "pull_request", "skipped")):
            for result in ("success", "failure", "cancelled", "skipped", ""):
                with self.subTest(rust=rust, event=event, result=result):
                    env = dict(os.environ, **{name: "success" for name in step["env"]})
                    mutation = "success" if event == "pull_request" and rust == "true" else "skipped"
                    owner = "success" if event != "pull_request" or rust == "true" else "skipped"
                    env.update(EVENT_NAME=event, RUST_SCOPE_RESULT=rust, OWNER_WINDOWS_SCOPE="true",
                               MUTATION_RESULT=mutation, OWNER_WINDOWS_RESULT=owner,
                               CARGO_CRAP_RESULT=result)
                    completed = subprocess.run(["bash", "-c", step["run"]], env=env,
                                               capture_output=True, check=False)
                    self.assertEqual(completed.returncode == 0, result == expected, completed.stderr)

    def test_standard_gate_and_reports_keep_their_cargo_crap_contract(self) -> None:
        self.assert_rejected(lambda workflow: workflow["jobs"]["standard-gate"]["needs"].append("cargo-crap"))
        for name in CHECKER.STANDARD_STAGE_JOBS:
            with self.subTest(job=name):
                self.assert_rejected(lambda workflow, name=name: workflow["jobs"][name].update(
                    needs=[*workflow["jobs"][name]["needs"], "cargo-crap"]))
        for name in CHECKER.MAIN_REPORT_JOBS:
            with self.subTest(job=name):
                self.assert_rejected(lambda workflow, name=name: workflow["jobs"][name].update(needs="standard-gate"))
                self.assert_rejected(lambda workflow, name=name: workflow["jobs"][name].update(
                    {"if": "${{ github.event_name != 'pull_request' && needs.standard-gate.result == 'success' }}"}))


if __name__ == "__main__":
    unittest.main()
