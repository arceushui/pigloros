#!/usr/bin/env python3
"""Adversarial checks for the actual QEMU closure evidence workflow and producers."""

from __future__ import annotations

import copy
import pathlib
import subprocess
import sys
import tempfile
import unittest

import check_qemu_closure_workflow_policy as policy


class QemuClosureWorkflowPolicyTests(unittest.TestCase):
    def setUp(self):
        self.workflow = policy.load_workflow((policy.ROOT / policy.WORKFLOW).read_text())
        self.producers = {name: (policy.ROOT / name).read_text() for name in policy.PRODUCER_SHA256}

    def refuses(self, workflow=None, producers=None):
        with self.assertRaises(policy.PolicyError):
            policy.check(workflow or self.workflow, self.producers if producers is None else producers)

    def test_current_programs_and_complete_graph_are_reviewed(self):
        policy.check(self.workflow, self.producers)
        policy.check_repository()

    def test_privilege_trigger_runner_and_job_changes_fail_closed(self):
        evidence = lambda w: w["jobs"]["evidence"]
        kernel = lambda w: w["jobs"]["kernel-cache"]

        def step(job, name):
            return next(s for s in job["steps"] if name in (s.get("name"), s.get("id")))
        matrix = lambda w: evidence(w)["strategy"]["matrix"]["include"]
        mutations = [
            lambda w: w.update(permissions={"contents": "write"}),
            lambda w: w.update(permissions="write-all"),
            lambda w: w.update(env={"NIX_CONFIG": "substituters = https://example.org"}),
            lambda w: w[True].update(pull_request_target={}),
            lambda w: w[True].update(push={"branches": ["main"]}),
            lambda w: w[True]["pull_request"].update(paths=["README.md"]),
            lambda w: w[True].update(workflow_dispatch={"inputs": {"skip": {"default": "true"}}}),
            lambda w: w["concurrency"].update(group="shared"),
            lambda w: w["jobs"].update(fabricate={"runs-on": "ubuntu-24.04", "steps": [{"run": "true"}]}),
            lambda w: evidence(w).update(needs=[]),
            lambda w: evidence(w).update(**{"continue-on-error": True}),
            lambda w: evidence(w).update(**{"if": "false"}),
            lambda w: evidence(w).update(permissions={"contents": "write"}),
            lambda w: evidence(w).update(env={"EVIDENCE_ARCHITECTURE": "x86_64"}),
            lambda w: evidence(w)["env"].update(NIX_CONFIG="require-sigs = false"),
            lambda w: evidence(w).update(**{"runs-on": "self-hosted"}),
            lambda w: evidence(w).update(**{"timeout-minutes": 345.0}),
            lambda w: evidence(w)["strategy"].update(**{"fail-fast": True}),
            lambda w: matrix(w).pop(),
            lambda w: matrix(w)[1].update(runner="ubuntu-24.04"),
            lambda w: matrix(w)[0].update(runner="ubuntu-latest"),
            lambda w: matrix(w).append({"architecture": "riscv64", "runner": "ubuntu-24.04"}),
            lambda w: evidence(w)["steps"][0]["with"].update(**{"persist-credentials": 0}),
            lambda w: evidence(w)["steps"][-2]["with"].update(**{"retention-days": 1}),
            lambda w: evidence(w)["steps"][-2]["with"].update(**{"if-no-files-found": "ignore"}),
            lambda w: evidence(w)["steps"][-1].update(**{"if": "${{ always() }}"}),
            # The kernel cache: main-only signing, exact-key restore, signed import.
            lambda w: evidence(w).pop("if"),
            lambda w: evidence(w).update(**{"if": "${{ always() }}"}),
            lambda w: step(evidence(w), "kernel-cache")["with"].update(**{"restore-keys": "qemu-kernel-"}),
            lambda w: step(evidence(w), "kernel-cache")["with"].update(key="qemu-kernel"),
            lambda w: step(evidence(w), "Import the signed kernel").update(
                run='nix copy --no-check-sigs --from "file://${RUNNER_TEMP}/qemu-kernel-cache"'),
            lambda w: step(evidence(w), "Import the signed kernel").pop("if"),
            lambda w: evidence(w)["steps"].append(copy.deepcopy(step(kernel(w), "Save the signed kernel"))),
            lambda w: kernel(w).pop("environment"),
            lambda w: kernel(w).update(environment="production"),
            lambda w: kernel(w).pop("if"),
            lambda w: kernel(w).update(**{"if": "${{ always() }}"}),
            lambda w: kernel(w).update(**{"continue-on-error": True}),
            lambda w: kernel(w).update(permissions={"contents": "write"}),
            lambda w: kernel(w)["env"].update(QEMU_KERNEL_CACHE_SIGNING_KEY="${{ secrets.QEMU_KERNEL_CACHE_SIGNING_KEY }}"),
            lambda w: step(kernel(w), "Build and sign the kernel")["env"].update(
                QEMU_KERNEL_CACHE_SIGNING_KEY="${{ secrets.OTHER }}"),
            lambda w: step(kernel(w), "Look up the kernel cache entry")["with"].pop("lookup-only"),
            lambda w: step(kernel(w), "Save the signed kernel").update(**{"if": "${{ always() }}"}),
            lambda w: w["concurrency"].update(**{"cancel-in-progress": True}),
            lambda w: w[True]["push"].update(branches=["**"]),
            lambda w: w[True]["push"]["paths"].pop(),
            lambda w: w[True].pop("schedule"),
        ]
        policy.check(self.workflow, self.producers)
        for mutate in mutations:
            changed = copy.deepcopy(self.workflow)
            mutate(changed)
            with self.subTest(mutate=mutate):
                self.refuses(changed)

    def test_every_step_is_mandatory_ordered_and_blocking(self):
        policy.check(self.workflow, self.producers)
        for job, data in self.workflow["jobs"].items():
            for index, _ in enumerate(data["steps"]):
                for action in ("remove", "skip", "ignore", "fabricate", "duplicate"):
                    changed = copy.deepcopy(self.workflow)
                    steps = changed["jobs"][job]["steps"]
                    if action == "remove":
                        steps.pop(index)
                    elif action == "skip":
                        steps[index]["if"] = "false"
                    elif action == "ignore":
                        steps[index]["continue-on-error"] = True
                    elif action == "fabricate":
                        steps[index] = {"run": "echo complete > guest/status"}
                    else:
                        steps.insert(index, copy.deepcopy(steps[index]))
                    with self.subTest(job=job, index=index, action=action):
                        self.refuses(changed)
            changed = copy.deepcopy(self.workflow)
            changed["jobs"][job]["steps"].reverse()
            with self.subTest(job=job):
                self.refuses(changed)

    def test_producer_indirection_cannot_skip_checks_or_fabricate_evidence(self):
        policy.check(self.workflow, self.producers)
        for name, original in self.producers.items():
            for changed in ("", original + "\n# changed program\n", original.replace("tcg", "kvm"),
                            original.replace("allow_userspace_verity=0", "allow_userspace_verity=1"),
                            "printf 'complete\\n' >status\n"):
                if changed == original:
                    continue
                with self.subTest(name=name, changed=changed[:30]):
                    self.refuses(producers=dict(self.producers, **{name: changed}))
        self.refuses(producers={})
        self.refuses(producers=dict(self.producers, extra="x"))

    def test_duplicate_keys_malformed_yaml_and_non_mapping_are_refused(self):
        for text in ("jobs: {}\njobs: {}\n", "jobs: {x: {run: a, run: b}}", "[not, a, mapping]",
                     "[unterminated"):
            with self.subTest(text=text), self.assertRaises(policy.PolicyError):
                policy.load_workflow(text)

    def test_cli_and_crlf_checkout_use_the_same_reviewed_program(self):
        result = subprocess.run([sys.executable, str(pathlib.Path(policy.__file__))],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            files = {policy.WORKFLOW: (policy.ROOT / policy.WORKFLOW).read_text(), **self.producers}
            for name, text in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(text.replace("\n", "\r\n").encode())
            policy.check_repository(root)
            (root / policy.WORKFLOW).write_text("[unterminated")
            with self.assertRaises(policy.PolicyError):
                policy.check_repository(root)


if __name__ == "__main__":
    unittest.main()
