"""Independent adversarial safety-policy fixtures; never inspect KVM or execute guests."""

import copy
import json
from pathlib import Path
import unittest

import yaml

from check_native_profiling_ci_policy import check_preflight_config, check_workflow


class NativeProfilingPolicyTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parent.parent
        self.workflow = yaml.safe_load((root / ".github/workflows/native-profiling-preflight.yml").read_text())
        self.config = json.loads((root / "docs/research/native-profiling-probe-preflight.json").read_text())

    def test_current_workflow_is_accepted(self):
        check_workflow(self.workflow)

    def test_current_configuration_and_intersecting_budgets_are_accepted(self):
        check_preflight_config(self.config)
        # Independent invariants, not the invalid count * per-file capacity rule.
        limits = self.config["limits"]
        self.assertEqual(limits["host_build_vcpus"], 2)
        self.assertLessEqual(limits["max_individual_artifact_bytes"], limits["max_aggregate_artifact_bytes"])
        self.assertLessEqual(limits["max_aggregate_artifact_bytes"], limits["max_expanded_artifact_bytes"])
        self.assertLessEqual(sum(limits[key] for key in (
            "host_build_timeout_seconds", "probe_timeout_seconds",
            "reporter_timeout_seconds", "external_cleanup_timeout_seconds",
        )), limits["job_timeout_seconds"])

    def test_every_ceiling_rejects_changes_and_wrong_types(self):
        for key, current in self.config["limits"].items():
            for changed in (current * 2, current + 1, 0, -1, True, str(current), float(current), None):
                with self.subTest(limit=key, value=changed):
                    config = copy.deepcopy(self.config)
                    config["limits"][key] = changed
                    with self.assertRaises(ValueError):
                        check_preflight_config(config)

    def test_every_artifact_rejection_policy_is_fixed(self):
        for key, current in self.config["artifact_policy"].items():
            for changed in (not current, int(current), str(current), None):
                with self.subTest(policy=key, value=changed):
                    config = copy.deepcopy(self.config)
                    config["artifact_policy"][key] = changed
                    with self.assertRaises(ValueError):
                        check_preflight_config(config)

    def test_activation_requirements_and_failure_actions_are_fixed(self):
        requirements = self.config["activation_requirements"]
        fixtures = [
            ("scope", "production"),
            ("native_classes", ["x86_64"]),
            ("native_classes", ["aarch64", "x86_64", "emulated"]),
            ("native_classes", list(reversed(self.config["native_classes"]))),
            ("activation_requirements", requirements + ["unreviewed"]),
            ("activation_requirements", list(reversed(requirements))),
            ("activation_requirements", []),
            ("on_unproved_requirement", "start-anyway"),
            ("on_limit_exceeded", "continue"),
            ("on_unverified_destruction", "report-success"),
        ]
        fixtures.extend(("activation_requirements", requirements[:index] + requirements[index + 1:])
                        for index in range(len(requirements)))
        for key, changed in fixtures:
            with self.subTest(field=key, value=changed):
                config = copy.deepcopy(self.config)
                config[key] = changed
                with self.assertRaises(ValueError):
                    check_preflight_config(config)

    def test_missing_and_unknown_configuration_fields_are_rejected(self):
        for section in (None, "limits", "artifact_policy"):
            current = self.config if section is None else self.config[section]
            for key in (*current, "unreviewed"):
                with self.subTest(section=section, key=key):
                    config = copy.deepcopy(self.config)
                    target = config if section is None else config[section]
                    if key == "unreviewed":
                        target[key] = "ignore"
                    else:
                        del target[key]
                    with self.assertRaises(ValueError):
                        check_preflight_config(config)

    def test_invalid_configuration_shapes_and_non_finite_numbers_are_rejected(self):
        for changed in (None, [], "not-an-object", True, 1):
            with self.subTest(config=changed):
                with self.assertRaises(ValueError):
                    check_preflight_config(changed)
        for changed in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=changed):
                config = copy.deepcopy(self.config)
                config["limits"]["guest_vcpus"] = changed
                with self.assertRaises(ValueError):
                    check_preflight_config(config)

    def test_adversarial_workflow_changes_are_rejected(self):
        # Each fixture mutates the executable YAML object, not comments or text fragments.
        fixtures = [
            ((), "permissions", {"contents": "write"}),
            ((), "env", {"LLVM_PROFILE_FILE": "unapproved"}),
            (("concurrency",), "cancel-in-progress", False),
            ((True, "pull_request"), "paths", []),
            (("jobs", "host-prerequisites"), "timeout-minutes", 90),
            (("jobs", "host-prerequisites"), "if", "false"),
            (("jobs", "host-prerequisites"), "continue-on-error", True),
            (("jobs", "host-prerequisites"), "container", {"options": "--privileged"}),
            (("jobs", "host-prerequisites", "strategy"), "fail-fast", True),
            (("jobs", "host-prerequisites", "strategy"), "max-parallel", 3),
            (("jobs", "host-prerequisites", "strategy", "matrix"), "include", [
                {"arch": "x86_64", "runner": "ubuntu-24.04"}]),
            (("jobs", "host-prerequisites", "strategy", "matrix", "include", 1), "runner", "ubuntu-24.04"),
            (("jobs", "host-prerequisites", "steps", 0, "with"), "persist-credentials", True),
            (("jobs", "host-prerequisites", "steps", 1), "run", "true"),
            (("jobs", "host-prerequisites", "steps", 2, "env"), "EXPECTED_ARCH", "x86_64"),
            (("jobs", "host-prerequisites", "steps", 2, "env"), "SOURCE_SHA", "${{ github.event.pull_request.head.sha }}"),
            (("jobs", "host-prerequisites", "steps", 2), "if", "false"),
            (("jobs", "host-prerequisites", "steps", 2), "continue-on-error", True),
            (("jobs", "host-prerequisites", "steps", 3), "if", "success()"),
            (("jobs", "host-prerequisites", "steps", 3), "uses", "actions/upload-artifact@main"),
            (("jobs", "host-prerequisites", "steps", 3, "with"), "path", "."),
            (("jobs", "host-prerequisites", "steps", 3, "with"), "if-no-files-found", "ignore"),
            (("jobs", "host-prerequisites", "steps", 3, "with"), "retention-days", 90),
        ]
        command = self.workflow["jobs"]["host-prerequisites"]["steps"][2]["run"]
        for changed in (
            command.replace("set -euo pipefail", "set -eu"),
            command.replace('test "$(git rev-parse HEAD)" = "$SOURCE_SHA"\n', ""),
            command + "true\n",
            command.replace("python3 scripts/", "sudo python3 scripts/"),
            command.replace("--source-sha", "--wrong-source-sha"),
        ):
            fixtures.append((("jobs", "host-prerequisites", "steps", 2), "run", changed))
        for path, key, value in fixtures:
            with self.subTest(path=path, key=key, value=value):
                workflow = copy.deepcopy(self.workflow)
                target = workflow
                for component in path:
                    target = target[component]
                target[key] = value
                with self.assertRaises(ValueError):
                    check_workflow(workflow)

    def test_added_removed_and_reordered_steps_are_rejected(self):
        steps = self.workflow["jobs"]["host-prerequisites"]["steps"]
        for changed in (steps + [{"run": "sudo qemu-system-x86_64"}], steps[:-1], list(reversed(steps))):
            with self.subTest(steps=changed):
                workflow = copy.deepcopy(self.workflow)
                workflow["jobs"]["host-prerequisites"]["steps"] = changed
                with self.assertRaises(ValueError):
                    check_workflow(workflow)


if __name__ == "__main__":
    unittest.main()
