#!/usr/bin/env python3
"""Allowlist the #444 QEMU closure evidence workflow and pin its producers.

The workflow graph must equal the reviewed one exactly: triggers, read-only
permissions, jobs, matrix, ordered steps and the producer commands. Every
program the evidence steps reach, including the guest definition and its
collector, is pinned by SHA-256 so that changing a producer also changes
this reviewed checker.
"""

from __future__ import annotations

import hashlib
import pathlib
import sys

import yaml

from check_asan_ci_policy import EXPECTED_SDK_HEADROOM_STEP
from check_owner_runtime_custody_policy import PolicyError as CustodyPolicyError
from check_owner_runtime_custody_policy import UniqueKeys, same_graph


ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ".github/workflows/qemu-closure-evidence.yml"
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
UPLOAD = "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9"
EVIDENCE = '"${RUNNER_TEMP}/qemu-closure-evidence"'
ARTIFACT_SUFFIX = "${{ matrix.architecture }}-${{ github.event.pull_request.head.sha || github.sha }}"
# Universal newlines keep the same program across LF and CRLF checkouts.
PRODUCER_SHA256 = {
    "scripts/install-pinned-nix.sh": "8473cf9d96a25b6fb4a16427e2554ad1d3e1991ce3068cd07864d0d80983e14d",
    "scripts/qemu-closure-evidence.sh": "6720b38b6e0d5d9dc061d28b68234ff114aada14d02acc4c882ee0f4cf4c185d",
    "scripts/check_qemu_closure_evidence.py": "16683bfbc823519db213e575c1f7f170c5aef8d7df1f4a1a79e34857dc03e9b5",
    "deploy/nixos/flake.nix": "4a67c05abc63cc21cdcfd0c22c156a813320d0b4dca6c9dfcf98eaa08372d8c0",
    "deploy/nixos/flake.lock": "2e002544ff613a1b05d8f6a1a0d936a93278196c79ccd75f1f4fba58f28737c7",
    "deploy/nixos/modules/mountfsd-activation.nix": "8e354c20c711e100cd6b512cb45cc999a3cd06a81e1352f9412277f4787120e6",
    "deploy/nixos/qemu-evidence/guest.nix": "092f64b7702959d985890d39b138b05a68d714edb6e2fe1fe107fcad32b51562",
    "deploy/nixos/qemu-evidence/collect-evidence.sh": "ff9cf51f671cdc774f1b249baf2bf310ea1e0b8ca662a985c562792ee94250b9",
    "deploy/nixos/dev-trust/root-hash-dev-test.crt": "d755a5f97a8c7865bc3f5f73b731098df03382577f02ae7087a3596ef8f5a5a7",
}
CHECKOUT_STEP = {"uses": CHECKOUT, "with": {"persist-credentials": False}}
EXPECTED = {
    "name": "qemu-closure-evidence",
    True: {
        "pull_request": {"paths": [
            WORKFLOW,
            "deploy/nixos/**",
            "scripts/check_qemu_closure_evidence.py",
            "scripts/test_check_qemu_closure_evidence.py",
            "scripts/check_qemu_closure_workflow_policy.py",
            "scripts/test_check_qemu_closure_workflow_policy.py",
            "scripts/check_asan_ci_policy.py",
            "scripts/check_owner_runtime_custody_policy.py",
            "scripts/install-pinned-nix.sh",
            "scripts/qemu-closure-evidence.sh",
        ]},
        "workflow_dispatch": None,
    },
    "permissions": {"contents": "read"},
    "concurrency": {"group": "qemu-closure-evidence-${{ github.ref }}", "cancel-in-progress": True},
    "jobs": {
        "policy": {
            "runs-on": "ubuntu-24.04", "timeout-minutes": 5,
            "steps": [
                CHECKOUT_STEP,
                {"name": "Enforce the evidence workflow and producer pins",
                 "run": "python scripts/check_qemu_closure_workflow_policy.py"},
                {"name": "Test the evidence workflow policy",
                 "run": "python scripts/test_check_qemu_closure_workflow_policy.py"},
                {"name": "Test the evidence checker",
                 "run": "python scripts/test_check_qemu_closure_evidence.py"},
            ],
        },
        "evidence": {
            "name": "evidence (${{ matrix.architecture }})",
            "needs": "policy",
            "strategy": {"fail-fast": False, "matrix": {"include": [
                {"architecture": "x86_64", "runner": "ubuntu-24.04"},
                {"architecture": "aarch64", "runner": "ubuntu-24.04-arm"},
            ]}},
            "runs-on": "${{ matrix.runner }}",
            "timeout-minutes": 345,
            "env": {"EVIDENCE_ARCHITECTURE": "${{ matrix.architecture }}"},
            "steps": [
                CHECKOUT_STEP,
                EXPECTED_SDK_HEADROOM_STEP,
                {"name": "Install the hash-pinned Nix release",
                 "run": "bash scripts/install-pinned-nix.sh"},
                {"name": "Build the pinned guest and record its store identities",
                 "run": f'bash scripts/qemu-closure-evidence.sh build "${{EVIDENCE_ARCHITECTURE}}" {EVIDENCE}'},
                {"name": "Boot the guest under QEMU TCG without network",
                 "run": f'bash scripts/qemu-closure-evidence.sh boot "${{EVIDENCE_ARCHITECTURE}}" {EVIDENCE}'},
                {"name": "Check the recorded evidence",
                 "run": "python scripts/check_qemu_closure_evidence.py"
                        ' --architecture "${EVIDENCE_ARCHITECTURE}"'
                        " --certificate deploy/nixos/dev-trust/root-hash-dev-test.crt"
                        " --flake-lock deploy/nixos/flake.lock"
                        ' --verdict "${RUNNER_TEMP}/qemu-closure-evidence/checker-verdict.json"'
                        f" {EVIDENCE}\n"},
                {"name": "Hash every evidence file",
                 "run": f"bash scripts/qemu-closure-evidence.sh seal {EVIDENCE}"},
                {"name": "Publish the hashed evidence", "uses": UPLOAD, "with": {
                    "name": f"qemu-closure-evidence-{ARTIFACT_SUFFIX}",
                    "path": "${{ runner.temp }}/qemu-closure-evidence/",
                    "if-no-files-found": "error", "retention-days": 90,
                }},
                {"name": "Retain failed-run diagnostics, which are not evidence",
                 "if": "${{ failure() }}", "uses": UPLOAD, "with": {
                     "name": f"qemu-closure-diagnostics-{ARTIFACT_SUFFIX}",
                     "path": "${{ runner.temp }}/qemu-closure-evidence/",
                     "if-no-files-found": "ignore", "retention-days": 7,
                 }},
            ],
        },
    },
}


class PolicyError(ValueError):
    """The evidence workflow or a producer differs from the reviewed program."""


def load_workflow(text: str) -> dict:
    try:
        value = yaml.load(text, Loader=UniqueKeys)
    except (yaml.YAMLError, TypeError, CustodyPolicyError) as error:
        raise PolicyError(f"invalid evidence workflow: {error}") from error
    if not isinstance(value, dict):
        raise PolicyError("evidence workflow must be a mapping")
    return value


def check(workflow: dict, producers: dict[str, str]) -> None:
    if not same_graph(workflow, EXPECTED):
        raise PolicyError("evidence workflow differs from the reviewed execution graph")
    if producers.keys() != PRODUCER_SHA256.keys():
        raise PolicyError("evidence producer set changed")
    for name, expected in PRODUCER_SHA256.items():
        if hashlib.sha256(producers[name].encode("utf-8")).hexdigest() != expected:
            raise PolicyError(f"evidence producer differs from the reviewed program: {name}")


def check_repository(root: pathlib.Path = ROOT) -> None:
    check(load_workflow((root / WORKFLOW).read_text(encoding="utf-8")), {
        name: (root / name).read_text(encoding="utf-8") for name in PRODUCER_SHA256
    })


def main() -> int:
    try:
        check_repository()
    except (PolicyError, OSError, UnicodeError) as error:
        print(f"qemu closure evidence policy: {error}", file=sys.stderr)
        return 1
    print("qemu closure evidence graph and producer pins hold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
