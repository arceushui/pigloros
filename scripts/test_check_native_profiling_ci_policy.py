"""Independent adversarial workflow fixtures; never inspect KVM or execute guests."""

import copy
import json
from pathlib import Path
import unittest

import yaml

from check_native_profiling_ci_policy import check_workflow


class NativeProfilingPolicyTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parent.parent
        self.workflow = yaml.safe_load((root / ".github/workflows/native-profiling-preflight.yml").read_text())

    def test_current_workflow_is_accepted(self):
        check_workflow(self.workflow)

    def test_host_build_cpu_budget_is_explicit(self):
        root = Path(__file__).resolve().parent.parent
        config = json.loads((root / "docs/research/native-profiling-probe-preflight.json").read_text())
        self.assertEqual(config["limits"]["host_build_vcpus"], 2)

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
