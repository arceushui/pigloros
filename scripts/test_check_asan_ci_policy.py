#!/usr/bin/env python3
"""Adversarial tests for the ASan GitHub Actions policy checker."""

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
CHECKER_PATH = ROOT / "scripts" / "check_asan_ci_policy.py"
SUPPRESSION_PATH = ROOT / "scripts" / "asan" / "bevy-reflect.lsan"
SERIAL_LINKER_PATH = ROOT / "scripts" / "asan" / "serial-link.sh"
NEGATIVE_CONTROL_PATH = ROOT / "scripts" / "asan" / "intentional-leak.rs"
EXPECTED_SUPPRESSION = (
    "leak:^<bevy_reflect::utility::GenericTypeCell<"
    "bevy_reflect::type_info::TypeInfo>>::get_or_insert_by_type_id::*$\n"
    "leak:^<bevy_reflect::utility::GenericTypeCell<"
    "bevy_reflect::utility::TypePathComponent>>::get_or_insert_by_type_id::*$\n"
)
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

    def test_rejects_repository_nextest_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace_root = pathlib.Path(directory)
            config_directory = workspace_root / ".config"
            config_directory.mkdir()
            (config_directory / "nextest.toml").write_text(
                '[profile.default]\ndefault-filter = "none()"\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(
                CHECKER.PolicyError, "no repository configuration"
            ):
                CHECKER.check_workflow(
                    ROOT / ".github" / "workflows" / "ci.yml", workspace_root
                )

    def test_repository_has_only_the_two_approved_suppressions(self) -> None:
        CHECKER.check_suppression_file(SUPPRESSION_PATH)

    def test_policy_checker_rejects_changed_suppression_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            suppression = pathlib.Path(directory) / "bevy-reflect.lsan"
            suppression.write_text(
                EXPECTED_SUPPRESSION + "leak:GenericTypeCell*\n", encoding="utf-8"
            )
            with self.assertRaises(CHECKER.PolicyError):
                CHECKER.check_suppression_file(suppression)

    def test_repository_has_the_intentional_leak_fixture(self) -> None:
        self.assertEqual(
            NEGATIVE_CONTROL_PATH.read_text(encoding="utf-8"),
            "fn main() {\n"
            "    let leaked = Box::leak(Box::new([0_u8; 1_234]));\n"
            "    std::hint::black_box(leaked);\n"
            "}\n",
        )

    def test_requires_leak_detection_and_suppression_reporting(self) -> None:
        self.assert_rejected(
            lambda workflow: self.asan_step(workflow)["env"].pop("LSAN_OPTIONS")
        )

    def test_requires_exact_suppression_path(self) -> None:
        def change_suppression_path(workflow: dict) -> None:
            env = self.asan_step(workflow)["env"]
            env["LSAN_OPTIONS"] = env["LSAN_OPTIONS"].replace(
                "scripts/asan/bevy-reflect.lsan",
                "scripts/asan/other.lsan",
            )

        self.assert_rejected(change_suppression_path)

    def test_requires_canonical_suppression_report_validation(self) -> None:
        def remove_report_validation(workflow: dict) -> None:
            step = self.asan_step(workflow)
            step["run"] = step["run"].replace(
                'python scripts/check_lsan_suppression_report.py "${RUNNER_TEMP}/asan.log"',
                "true",
            )

        self.assert_rejected(remove_report_validation)

    def test_canonical_step_requires_pipefail(self) -> None:
        def remove_pipefail(workflow: dict) -> None:
            step = self.asan_step(workflow)
            step["run"] = step["run"].replace("set -euo pipefail\n", "")

        self.assert_rejected(remove_pipefail)

    def test_requires_intentional_leak_negative_control(self) -> None:
        def remove_negative_control(workflow: dict) -> None:
            steps = workflow["jobs"]["asan"]["steps"]
            steps.remove(self.negative_control_step(workflow))

        self.assert_rejected(remove_negative_control)

    def test_negative_control_must_use_the_same_lsan_options(self) -> None:
        self.assert_rejected(
            lambda workflow: self.negative_control_step(workflow)["env"].update(
                {"LSAN_OPTIONS": "print_suppressions=1"}
            )
        )

    def test_negative_control_must_require_nonzero_exit(self) -> None:
        def remove_failure_assertion(workflow: dict) -> None:
            step = self.negative_control_step(workflow)
            step["run"] = step["run"].replace(
                'test "${status}" -ne 0',
                "true",
            )

        self.assert_rejected(remove_failure_assertion)

    def test_negative_control_must_require_exact_leak_summary(self) -> None:
        def weaken_summary(workflow: dict) -> None:
            step = self.negative_control_step(workflow)
            step["run"] = step["run"].replace(
                'grep -Fqx "SUMMARY: AddressSanitizer: 1234 byte(s) leaked in 1 allocation(s)."',
                'grep -F "AddressSanitizer"',
            )

        self.assert_rejected(weaken_summary)

    def test_negative_control_must_reject_bevy_suppression_match(self) -> None:
        def remove_match_assertion(workflow: dict) -> None:
            step = self.negative_control_step(workflow)
            step["run"] = step["run"].replace(
                '! grep -F "bevy_reflect::utility::GenericTypeCell" "${log}"\n',
                "",
            )

        self.assert_rejected(remove_match_assertion)

    def test_rejects_unbounded_build_concurrency(self) -> None:
        self.assert_rejected(
            lambda workflow: self.build_step(workflow)["env"].pop("CARGO_BUILD_JOBS")
        )

    def test_rejects_missing_serial_linker(self) -> None:
        self.assert_rejected(
            lambda workflow: self.build_step(workflow)["env"].pop(
                "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER"
            )
        )

    def test_rejects_rustflags_linker_override(self) -> None:
        def override_linker(workflow: dict) -> None:
            step = self.build_step(workflow)
            step["run"] = step["run"].replace(
                '-Z sanitizer=address"', '-Z sanitizer=address -C linker=cc"'
            )

        self.assert_rejected(override_linker)

    def test_requires_runtime_proof_of_serial_linking(self) -> None:
        def drop_lock_assertion(workflow: dict) -> None:
            step = self.build_step(workflow)
            step["run"] = step["run"].replace(
                'test -f "${RUNNER_TEMP}/asan-link.lock"\n', ""
            )

        self.assert_rejected(drop_lock_assertion)

    def test_repository_serial_linker_passes(self) -> None:
        CHECKER.check_serial_linker(SERIAL_LINKER_PATH)

    def test_rejects_unserialized_linker_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            linker = pathlib.Path(directory) / "serial-link.sh"
            linker.write_text('#!/bin/sh\nexec cc "$@"\n', encoding="utf-8")
            linker.chmod(0o755)
            with self.assertRaises(CHECKER.PolicyError):
                CHECKER.check_serial_linker(linker)

    def test_rejects_non_executable_linker_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            linker = pathlib.Path(directory) / "serial-link.sh"
            linker.write_bytes(SERIAL_LINKER_PATH.read_bytes())
            linker.chmod(0o644)
            with self.assertRaises(CHECKER.PolicyError):
                CHECKER.check_serial_linker(linker)

    def test_requires_bounded_test_concurrency(self) -> None:
        def remove_test_threads(workflow: dict) -> None:
            step = self.asan_step(workflow)
            step["run"] = step["run"].replace("  --test-threads 2\n", "")

        self.assert_rejected(remove_test_threads)

    def test_requires_archive_build_job(self) -> None:
        self.assert_rejected(lambda workflow: workflow["jobs"].pop("asan-build"))

    def test_shards_require_archive_build_dependency(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["asan"]["needs"].remove("asan-build")
        )

    def test_shards_require_archive_build_success(self) -> None:
        def drop_build_condition(workflow: dict) -> None:
            job = workflow["jobs"]["asan"]
            job["if"] = job["if"].replace(
                "needs.asan-build.result == 'success' && ", ""
            )

        self.assert_rejected(drop_build_condition)

    def test_archive_build_must_run_in_the_standard_stage(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["asan-build"].update(
                {"needs": ["ci_change_scope", "preflight-gate"]}
            )
        )

    def test_archive_build_must_require_cargo_crap_success(self) -> None:
        def drop_cargo_crap_condition(workflow: dict) -> None:
            job = workflow["jobs"]["asan-build"]
            job["if"] = job["if"].replace(
                "needs.cargo-crap.result == 'success' && ", ""
            )

        self.assert_rejected(drop_cargo_crap_condition)

    def test_archive_build_requires_instrumented_complete_scope(self) -> None:
        for fragment in (
            'RUSTFLAGS="-Z sanitizer=address" \\\n  ',
            " -Z build-std",
            " --all-features",
            " --tests",
            " --workspace",
        ):
            with self.subTest(fragment=fragment):
                def weaken_build(workflow: dict, removed: str = fragment) -> None:
                    step = self.build_step(workflow)
                    step["run"] = step["run"].replace(removed, "", 1)

                self.assert_rejected(weaken_build)

    def test_archive_build_rejects_extra_environment(self) -> None:
        self.assert_rejected(
            lambda workflow: self.build_step(workflow)["env"].update(
                {"RUSTFLAGS": "-C opt-level=0"}
            )
        )

    def test_archive_build_rejects_continue_on_error(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["asan-build"].update(
                {"continue-on-error": True}
            )
        )

    def test_archive_build_rejects_github_env_injection(self) -> None:
        def inject_step(workflow: dict) -> None:
            workflow["jobs"]["asan-build"]["steps"].insert(
                -2,
                {
                    "name": "drop instrumentation",
                    "run": "echo 'RUSTFLAGS=' >> \"$GITHUB_ENV\"",
                },
            )

        self.assert_rejected(inject_step)

    def test_rejects_archive_artifact_name_mismatch(self) -> None:
        def rename_download(workflow: dict) -> None:
            download = next(
                step
                for step in workflow["jobs"]["asan"]["steps"]
                if step.get("name") == "Download ASan test archive"
            )
            download["with"]["name"] = "asan-nextest-archive-other"

        self.assert_rejected(rename_download)

    def test_rejects_ignored_missing_archive_upload(self) -> None:
        def ignore_missing_archive(workflow: dict) -> None:
            upload = workflow["jobs"]["asan-build"]["steps"][-1]
            upload["with"]["if-no-files-found"] = "ignore"

        self.assert_rejected(ignore_missing_archive)

    def test_requires_exact_archive_retention(self) -> None:
        def shorten_retention(workflow: dict) -> None:
            upload = workflow["jobs"]["asan-build"]["steps"][-1]
            upload["with"]["retention-days"] = 1

        self.assert_rejected(shorten_retention)

    def test_requires_archive_overwrite_on_rerun(self) -> None:
        def keep_stale_archive(workflow: dict) -> None:
            upload = workflow["jobs"]["asan-build"]["steps"][-1]
            upload["with"]["overwrite"] = False

        self.assert_rejected(keep_stale_archive)

    def test_requires_extraction_into_workspace(self) -> None:
        for fragment in (
            '  --extract-to "${GITHUB_WORKSPACE}"\n',
            "  --extract-overwrite\n",
            '  --workspace-remap "${GITHUB_WORKSPACE}"\n',
        ):
            with self.subTest(fragment=fragment):
                def move_extraction(workflow: dict, removed: str = fragment) -> None:
                    step = self.asan_step(workflow)
                    step["run"] = step["run"].replace(removed, "")

                self.assert_rejected(move_extraction)

    def test_requires_archive_reuse_in_shards(self) -> None:
        def rebuild_in_shard(workflow: dict) -> None:
            step = self.asan_step(workflow)
            step["run"] = step["run"].replace(
                '  --archive-file "${RUNNER_TEMP}/asan-archive/asan-tests.tar.zst"\n',
                "  --workspace --all-features --locked\n",
            )

        self.assert_rejected(rebuild_in_shard)

    def test_requires_exact_shard_filtersets(self) -> None:
        for old, new in (
            ("not package(pos-conformance)", "all()"),
            (
                "binary_id(pos-conformance::moat_proof_public)",
                "binary_id(pos-conformance::moat_proof_public) & test(=none)",
            ),
            ("--partition slice:1/2 --run-ignored all", "--partition slice:1/2"),
            (" | kind(bin)", ""),
            (" | binary_id(pos-conformance::provider_contract_public)", ""),
            (
                "binary_id(pos-conformance::bundle_contract_coverage_public)",
                "binary_id(pos-conformance::bundle_contract_public)",
            ),
        ):
            with self.subTest(old=old):
                def change_filter(
                    workflow: dict, before: str = old, after: str = new
                ) -> None:
                    step = self.asan_step(workflow)
                    step["run"] = step["run"].replace(before, after, 1)

                self.assert_rejected(change_filter)

    def test_requires_all_asan_shards(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["asan"]["strategy"]["matrix"][
                "shard"
            ].pop()
        )

    def test_requires_aggregate_asan_gate(self) -> None:
        self.assert_rejected(lambda workflow: workflow["jobs"].pop("asan-gate"))

    def test_aggregate_gate_must_run_after_shard_failure(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["asan-gate"].pop("if")
        )

    def test_aggregate_gate_must_need_archive_build(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["asan-gate"]["needs"].remove(
                "asan-build"
            )
        )

    def test_aggregate_gate_must_check_archive_build(self) -> None:
        def remove_build_check(workflow: dict) -> None:
            step = workflow["jobs"]["asan-gate"]["steps"][0]
            step["run"] = step["run"].replace(
                'test "${ASAN_BUILD_RESULT}" = success\n', ""
            )

        self.assert_rejected(remove_build_check)

    def test_aggregate_gate_verdicts(self) -> None:
        script = self.workflow["jobs"]["asan-gate"]["steps"][0]["run"]
        cases = (
            (("success", "true", "success", "success"), True),
            (("success", "false", "skipped", "skipped"), True),
            (("success", "true", "failure", "skipped"), False),
            (("success", "true", "skipped", "skipped"), False),
            (("success", "true", "cancelled", "skipped"), False),
            (("success", "true", "success", "failure"), False),
            (("success", "true", "success", "skipped"), False),
            (("success", "false", "success", "skipped"), False),
            (("success", "false", "skipped", "success"), False),
            (("failure", "false", "skipped", "skipped"), False),
        )
        for (scope, rust, build, shards), passes in cases:
            with self.subTest(scope=scope, rust=rust, build=build, shards=shards):
                env = {
                    **os.environ,
                    "SCOPE_JOB_RESULT": scope,
                    "RUST_SCOPE_RESULT": rust,
                    "ASAN_BUILD_RESULT": build,
                    "ASAN_SHARDS_RESULT": shards,
                }
                result = subprocess.run(
                    ["bash", "-c", script],
                    env=env,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, passes)

    def test_aggregate_gate_must_require_shard_success(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["asan-gate"]["steps"][0].update(
                {"run": "true"}
            )
        )

    def test_rejects_commented_serialization(self) -> None:
        source = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        source = source.replace(
            "          CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER:",
            "          # CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER:",
        )
        with tempfile.TemporaryDirectory() as directory:
            fixture = pathlib.Path(directory) / "ci.yml"
            fixture.write_text(source, encoding="utf-8")
            with self.assertRaises(CHECKER.PolicyError):
                CHECKER.check_workflow(fixture)

    def test_rejects_disabled_job(self) -> None:
        self.assert_rejected(lambda workflow: workflow["jobs"]["asan"].update({"if": False}))

    def test_requires_pinned_ubuntu_2404_runner(self) -> None:
        self.assert_rejected(
            lambda workflow: workflow["jobs"]["asan"].update(
                {"runs-on": "ubuntu-latest"}
            )
        )

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
            step = self.build_step(workflow)
            step["run"] = step["run"].replace(
                'RUSTFLAGS="-Z sanitizer=address" \\\n  cargo',
                'RUSTFLAGS="-Z sanitizer=address"\n  cargo',
            )

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
            toolchain_step = next(
                step
                for step in workflow["jobs"]["asan"]["steps"]
                if str(step.get("uses", "")).startswith("dtolnay/rust-toolchain@")
            )
            toolchain_step["with"]["toolchain"] = "nightly"

        self.assert_rejected(float_installer)

    def test_rejects_floating_cargo_selector(self) -> None:
        def float_cargo_selector(workflow: dict) -> None:
            test_step = self.asan_step(workflow)
            test_step["run"] = test_step["run"].replace(
                "+nightly-2026-07-01", "+nightly"
            )

        self.assert_rejected(float_cargo_selector)

    def test_requires_pinned_nextest_version_and_no_fallback(self) -> None:
        def float_nextest_installer(workflow: dict) -> None:
            installer = self.nextest_installer_step(workflow)
            installer["with"]["tool"] = "cargo-nextest"
            installer["with"].pop("fallback")

        self.assert_rejected(float_nextest_installer)

    def test_requires_nextest_default_filter_bypass(self) -> None:
        def remove_default_filter_bypass(workflow: dict) -> None:
            test_step = self.asan_step(workflow)
            test_step["run"] = test_step["run"].replace(
                "  --ignore-default-filter\n", ""
            )

        self.assert_rejected(remove_default_filter_bypass)

    def test_requires_nextest_user_configuration_disabled(self) -> None:
        def enable_user_configuration(workflow: dict) -> None:
            test_step = self.asan_step(workflow)
            test_step["run"] = test_step["run"].replace(
                "  --user-config-file none\n", ""
            )

        self.assert_rejected(enable_user_configuration)

    def test_requires_visible_unindented_nextest_success_output(self) -> None:
        for option in ("--success-output final", "--no-output-indent"):
            with self.subTest(option=option):
                def hide_passing_lsan_reports(
                    workflow: dict, output_option: str = option
                ) -> None:
                    test_step = self.asan_step(workflow)
                    test_step["run"] = test_step["run"].replace(
                        f"  {output_option}\n", ""
                    )

                self.assert_rejected(hide_passing_lsan_reports)

    def test_requires_setup_symbolizer_executable_check(self) -> None:
        def remove_symbolizer_executable_check(workflow: dict) -> None:
            symbolizer_step = self.symbolizer_step(workflow)
            symbolizer_step["run"] = symbolizer_step["run"].replace(
                'test -x "${symbolizer}"\n',
                "",
            )

        self.assert_rejected(remove_symbolizer_executable_check)

    def test_requires_setup_symbolizer_execution(self) -> None:
        def remove_symbolizer_execution(workflow: dict) -> None:
            symbolizer_step = self.symbolizer_step(workflow)
            symbolizer_step["run"] = symbolizer_step["run"].replace(
                'symbolizer_version="$("${symbolizer}" --version)"\n',
                "",
            )

        self.assert_rejected(remove_symbolizer_execution)

    def test_requires_exact_symbolizer_version(self) -> None:
        def change_symbolizer_version(workflow: dict) -> None:
            symbolizer_step = self.symbolizer_step(workflow)
            symbolizer_step["run"] = symbolizer_step["run"].replace(
                "Ubuntu LLVM version 18.1.3",
                "Ubuntu LLVM version 18",
            )

        self.assert_rejected(change_symbolizer_version)

    def test_requires_exact_setup_symbolizer_path(self) -> None:
        def change_setup_symbolizer_path(workflow: dict) -> None:
            symbolizer_step = self.symbolizer_step(workflow)
            symbolizer_step["run"] = symbolizer_step["run"].replace(
                "/usr/bin/llvm-symbolizer-18",
                "/usr/bin/llvm-symbolizer",
            )

        self.assert_rejected(change_setup_symbolizer_path)

    def test_requires_symbolizer_executable_preflight(self) -> None:
        def remove_symbolizer_preflight(workflow: dict) -> None:
            test_step = self.asan_step(workflow)
            test_step["run"] = test_step["run"].replace(
                'test -x "/usr/bin/llvm-symbolizer-18"\n',
                "",
            )

        self.assert_rejected(remove_symbolizer_preflight)

    def test_requires_pinned_symbolizer_path(self) -> None:
        def change_symbolizer_path(workflow: dict) -> None:
            test_step = self.asan_step(workflow)
            test_step["run"] = test_step["run"].replace(
                'ASAN_SYMBOLIZER_PATH="/usr/bin/llvm-symbolizer-18"',
                'ASAN_SYMBOLIZER_PATH="/usr/bin/llvm-symbolizer"',
            )

        self.assert_rejected(change_symbolizer_path)

    def test_rejects_undated_cache_key(self) -> None:
        def remove_cache_date(workflow: dict) -> None:
            cache_step = next(
                step
                for step in workflow["jobs"]["asan-build"]["steps"]
                if str(step.get("uses", "")).startswith("Swatinem/rust-cache@")
            )
            cache_step["with"]["shared-key"] = "asan"

        self.assert_rejected(remove_cache_date)

    def test_requires_incremental_artifacts_disabled(self) -> None:
        self.assert_rejected(
            lambda workflow: self.build_step(workflow)["env"].pop(
                "CARGO_INCREMENTAL", None
            )
        )

    def test_requires_line_table_debuginfo(self) -> None:
        self.assert_rejected(
            lambda workflow: self.build_step(workflow)["env"].pop(
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

    @staticmethod
    def build_step(workflow: dict) -> dict:
        return next(
            step
            for step in workflow["jobs"]["asan-build"]["steps"]
            if step.get("name") == "cargo nextest archive with ASan"
        )

    @staticmethod
    def negative_control_step(workflow: dict) -> dict:
        return next(
            step
            for step in workflow["jobs"]["asan"]["steps"]
            if step.get("name") == "Prove unrelated leaks still fail LSan"
        )

    @staticmethod
    def symbolizer_step(workflow: dict) -> dict:
        return next(
            step
            for step in workflow["jobs"]["asan"]["steps"]
            if step.get("name") == "Verify ASan symbolizer"
        )

    @staticmethod
    def nextest_installer_step(workflow: dict) -> dict:
        return next(
            step
            for step in workflow["jobs"]["asan"]["steps"]
            if step.get("name") == "Install cargo-nextest for partitioned ASan tests"
        )

    @classmethod
    def append_to_command(cls, workflow: dict, suffix: str) -> None:
        step = cls.asan_step(workflow)
        step["run"] = step["run"].rstrip() + suffix


if __name__ == "__main__":
    unittest.main()
