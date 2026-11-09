#!/usr/bin/env python3
"""Adversarial checks for the actual custody workflow and producer programs."""

from __future__ import annotations

import copy
import pathlib
import subprocess
import sys
import tempfile
import unittest

import check_owner_runtime_custody_policy as policy


class OwnerRuntimeCustodyPolicyTests(unittest.TestCase):
    def setUp(self):
        self.workflow = policy.load_workflow((policy.ROOT / policy.WORKFLOW).read_text())
        self.producers = {name: (policy.ROOT / name).read_text() for name in policy.PRODUCER_SHA256}

    def test_current_programs_and_complete_graph_are_reviewed(self):
        policy.check(self.workflow, self.producers)
        policy.check_repository()

    def test_privilege_trigger_environment_and_job_changes_fail_closed(self):
        mutations = [
            lambda w: w.update(permissions={"contents": "write"}),
            lambda w: w.update(env={"PIGLOR_FAKE_RUNTIME": "true"}),
            lambda w: w[True].update(pull_request_target={}),
            lambda w: w[True]["pull_request"].update(paths=["README.md"]),
            lambda w: w[True].update(workflow_dispatch={"inputs": {"mode": {"default": "PrepareCustody"}}}),
            lambda w: w["jobs"].update(fabricate={"runs-on": "ubuntu-latest", "steps": [{"run": "true"}]}),
            lambda w: w["jobs"]["verify-runtime"].update(needs=[]),
            lambda w: w["jobs"]["verify-runtime"].update(**{"continue-on-error": True}),
            lambda w: w["jobs"]["verify-runtime"].update(**{"if": "false"}),
            lambda w: w["jobs"]["verify-runtime"].update(permissions={"contents": "write"}),
            lambda w: w["jobs"]["verify-runtime"].update(env={"GH_TOKEN": "untrusted"}),
            lambda w: w["jobs"]["verify-runtime"].update(**{"runs-on": "self-hosted"}),
            lambda w: w["jobs"]["verify-runtime"].update(**{"timeout-minutes": 1}),
            lambda w: w["jobs"]["verify-runtime"]["steps"][0]["with"].update(**{"persist-credentials": 0}),
            lambda w: w["jobs"]["verify-runtime"].update(**{"timeout-minutes": 20.0}),
        ]
        policy.check(self.workflow, self.producers)
        for mutate in mutations:
            changed = copy.deepcopy(self.workflow)
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(policy.PolicyError):
                policy.check(changed, self.producers)

    def test_every_step_is_mandatory_ordered_and_blocking(self):
        policy.check(self.workflow, self.producers)
        for job, data in self.workflow["jobs"].items():
            for index, _ in enumerate(data["steps"]):
                for action in ("remove", "skip", "ignore", "fabricate", "duplicate"):
                    changed = copy.deepcopy(self.workflow)
                    steps = changed["jobs"][job]["steps"]
                    if action == "remove": steps.pop(index)
                    elif action == "skip": steps[index]["if"] = "false"
                    elif action == "ignore": steps[index]["continue-on-error"] = True
                    elif action == "fabricate": steps[index] = {"run": "echo fabricated > runtime-custody.json"}
                    else: steps.insert(index, copy.deepcopy(steps[index]))
                    with self.subTest(job=job, index=index, action=action), self.assertRaises(policy.PolicyError):
                        policy.check(changed, self.producers)
            changed = copy.deepcopy(self.workflow)
            changed["jobs"][job]["steps"].reverse()
            with self.subTest(job=job), self.assertRaises(policy.PolicyError):
                policy.check(changed, self.producers)

    def test_script_indirection_cannot_skip_checks_or_fabricate_receipts(self):
        policy.check(self.workflow, self.producers)
        for name, original in self.producers.items():
            for changed in ("", original + "\n# changed program\n", original.replace("sha256", "sha512"),
                            original.replace("throw", "Write-Output"), "print('fabricated')\n"):
                if changed == original: continue
                sources = dict(self.producers, **{name: changed})
                with self.subTest(name=name), self.assertRaises(policy.PolicyError):
                    policy.check(self.workflow, sources)
        with self.assertRaises(policy.PolicyError):
            policy.check(self.workflow, {})

    def test_duplicate_keys_malformed_yaml_and_non_mapping_are_refused(self):
        for text in ("jobs: {}\njobs: {}\n", "jobs: {x: {run: a, run: b}}", "[not, a, mapping]", "[unterminated"):
            with self.subTest(text=text), self.assertRaises(policy.PolicyError):
                policy.load_workflow(text)

    def test_cli_and_crlf_checkout_use_the_same_reviewed_program(self):
        policy.check(self.workflow, self.producers)
        result = subprocess.run([sys.executable, str(pathlib.Path(policy.__file__))], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            files = {policy.WORKFLOW: (policy.ROOT / policy.WORKFLOW).read_text(), **self.producers}
            for name, text in files.items():
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(text.replace("\n", "\r\n").encode())
            policy.check_repository(root)


if __name__ == "__main__":
    unittest.main()
