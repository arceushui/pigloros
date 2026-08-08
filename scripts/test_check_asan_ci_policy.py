#!/usr/bin/env python3
"""Adversarial tests for the ASan GitHub Actions policy checker."""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import tempfile
import unittest

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKER_PATH = ROOT / "scripts" / "check_asan_ci_policy.py"
SPEC = importlib.util.spec_from_file_location("check_asan_ci_policy", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class AsanCiPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        with (ROOT / ".github" / "workflows" / "ci.yml").open(encoding="utf-8") as stream:
            self.workflow = yaml.safe_load(stream)

    def assert_rejected(self, mutate) -> None:
        workflow = copy.deepcopy(self.workflow)
        mutate(workflow)
        with tempfile.TemporaryDirectory() as directory:
            fixture = pathlib.Path(directory) / "ci.yml"
            with fixture.open("w", encoding="utf-8") as stream:
                yaml.safe_dump(workflow, stream, sort_keys=False)
            with self.assertRaises(CHECKER.PolicyError):
                CHECKER.check_workflow(fixture)

    def test_repository_workflow_passes(self) -> None:
        CHECKER.check_workflow(ROOT / ".github" / "workflows" / "ci.yml")

    def test_rejects_missing_serialization(self) -> None:
        self.assert_rejected(
            lambda workflow: self.asan_step(workflow)["env"].pop("CARGO_BUILD_JOBS")
        )

    def test_rejects_commented_serialization(self) -> None:
        source = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        source = source.replace(
            '          CARGO_BUILD_JOBS: "1"',
            '          # CARGO_BUILD_JOBS: "1"',
        )
        with tempfile.TemporaryDirectory() as directory:
            fixture = pathlib.Path(directory) / "ci.yml"
            fixture.write_text(source, encoding="utf-8")
            with self.assertRaises(CHECKER.PolicyError):
                CHECKER.check_workflow(fixture)

    def test_rejects_disabled_job(self) -> None:
        self.assert_rejected(lambda workflow: workflow["jobs"]["asan"].update({"if": False}))

    def test_rejects_disabled_step(self) -> None:
        self.assert_rejected(
            lambda workflow: self.asan_step(workflow).update({"if": False})
        )

    def test_rejects_job_continue_on_error(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["asan"].update(
                {"continue-on-error": True}
            )
        )

    def test_rejects_step_continue_on_error(self) -> None:
        self.assert_rejected(
            lambda workflow: self.asan_step(workflow).update({"continue-on-error": True})
        )

    def test_rejects_custom_shell(self) -> None:
        self.assert_rejected(
            lambda workflow: self.asan_step(workflow).update({"shell": "bash {0}"})
        )

    def test_rejects_newline_between_rustflags_and_cargo(self) -> None:
        def insert_newline(workflow: dict) -> None:
            step = self.asan_step(workflow)
            step["run"] = step["run"].replace('" cargo +nightly', '"\ncargo +nightly')

        self.assert_rejected(insert_newline)

    def test_rejects_workflow_level_target_runner(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["env"].update(
                {"CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER": "/bin/true"}
            )
        )

    def test_rejects_job_level_environment(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["asan"].update(
                {
                    "env": {
                        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER": "/bin/true"
                    }
                }
            )
        )

    def test_rejects_extra_step_environment(self) -> None:
        self.assert_rejected(
            lambda workflow: self.asan_step(workflow)["env"].update(
                {"CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER": "/bin/true"}
            )
        )

    def test_rejects_preceding_github_env_injection(self) -> None:
        def inject_step(workflow: dict) -> None:
            workflow["jobs"]["asan"]["steps"].insert(
                -1,
                {
                    "name": "replace test runner",
                    "run": (
                        "echo 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=/bin/true' "
                        '>> "$GITHUB_ENV"'
                    ),
                },
            )

        self.assert_rejected(inject_step)

    def test_rejects_skipped_prerequisite(self) -> None:
        def add_skipped_prerequisite(workflow: dict) -> None:
            workflow["jobs"]["skip-asan"] = {
                "if": False,
                "runs-on": "ubuntu-latest",
                "steps": [{"run": "true"}],
            }
            workflow["jobs"]["asan"]["needs"] = "skip-asan"

        self.assert_rejected(add_skipped_prerequisite)

    def test_rejects_test_working_directory(self) -> None:
        self.assert_rejected(
            lambda workflow: self.asan_step(workflow).update(
                {"working-directory": "nested"}
            )
        )

    def test_rejects_floating_installer_toolchain(self) -> None:
        def float_installer(workflow: dict) -> None:
            toolchain_step = workflow["jobs"]["asan"]["steps"][2]
            toolchain_step["with"]["toolchain"] = "nightly"

        self.assert_rejected(float_installer)

    def test_rejects_floating_cargo_selector(self) -> None:
        def float_cargo_selector(workflow: dict) -> None:
            test_step = self.asan_step(workflow)
            test_step["run"] = test_step["run"].replace(
                "+nightly-2026-07-01", "+nightly"
            )

        self.assert_rejected(float_cargo_selector)

    def test_requires_pinned_symbolizer_archive(self) -> None:
        def change_symbolizer_digest(workflow: dict) -> None:
            symbolizer_step = workflow["jobs"]["asan"]["steps"][3]
            symbolizer_step["env"]["LLVM_ARCHIVE_SHA256"] = "0" * 64

        self.assert_rejected(change_symbolizer_digest)

    def test_requires_symbolizer_archive_cleanup(self) -> None:
        def remove_archive_cleanup(workflow: dict) -> None:
            symbolizer_step = workflow["jobs"]["asan"]["steps"][3]
            symbolizer_step["run"] = symbolizer_step["run"].replace(
                'rm -f "${archive}"\n',
                "",
            )

        self.assert_rejected(remove_archive_cleanup)

    def test_requires_symbolizer_executable_preflight(self) -> None:
        def remove_symbolizer_preflight(workflow: dict) -> None:
            test_step = self.asan_step(workflow)
            test_step["run"] = test_step["run"].replace(
                'test -x "${RUNNER_TEMP}/llvm-symbolizer/llvm-symbolizer" && ',
                "",
            )

        self.assert_rejected(remove_symbolizer_preflight)

    def test_requires_pinned_symbolizer_path(self) -> None:
        def change_symbolizer_path(workflow: dict) -> None:
            test_step = self.asan_step(workflow)
            test_step["run"] = test_step["run"].replace(
                'ASAN_SYMBOLIZER_PATH="${RUNNER_TEMP}/llvm-symbolizer/llvm-symbolizer"',
                'ASAN_SYMBOLIZER_PATH="/usr/bin/llvm-symbolizer"',
            )

        self.assert_rejected(change_symbolizer_path)

    def test_rejects_undated_cache_key(self) -> None:
        def remove_cache_date(workflow: dict) -> None:
            cache_step = workflow["jobs"]["asan"]["steps"][4]
            cache_step["with"]["shared-key"] = "asan"

        self.assert_rejected(remove_cache_date)

    def test_requires_incremental_artifacts_disabled(self) -> None:
        self.assert_rejected(
            lambda workflow: self.asan_step(workflow)["env"].pop(
                "CARGO_INCREMENTAL", None
            )
        )

    def test_requires_line_table_debuginfo(self) -> None:
        self.assert_rejected(
            lambda workflow: self.asan_step(workflow)["env"].pop(
                "CARGO_PROFILE_TEST_DEBUG", None
            )
        )

    def test_rejects_no_run(self) -> None:
        self.assert_rejected(
            lambda workflow: self.append_to_command(workflow, " --no-run")
        )

    def test_rejects_shell_success_override(self) -> None:
        self.assert_rejected(
            lambda workflow: self.append_to_command(workflow, " || true")
        )

    def test_rejects_test_skip_argument(self) -> None:
        self.assert_rejected(
            lambda workflow: self.append_to_command(workflow, " -- --skip anything")
        )

    @staticmethod
    def asan_step(workflow: dict) -> dict:
        return next(
            step
            for step in workflow["jobs"]["asan"]["steps"]
            if step.get("name") == "cargo test with ASan"
        )

    @classmethod
    def append_to_command(cls, workflow: dict, suffix: str) -> None:
        step = cls.asan_step(workflow)
        step["run"] = step["run"].rstrip() + suffix


if __name__ == "__main__":
    unittest.main()
