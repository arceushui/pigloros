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
# Only the steps that read or write the kernel cache release get a token.
RELEASE_ENV = {"GH_TOKEN": "${{ github.token }}", "GH_REPO": "${{ github.repository }}"}
KERNEL_CACHE_DIR = '"${RUNNER_TEMP}/qemu-kernel-cache"'
EVIDENCE = '"${RUNNER_TEMP}/qemu-closure-evidence"'
# github.sha is the merge commit that the pull_request run actually tests.
ARTIFACT_SUFFIX = "${{ matrix.architecture }}-${{ github.sha }}"
# Universal newlines keep the same program across LF and CRLF checkouts. The
# imported policy modules are pinned too: they supply EXPECTED's headroom step
# (with the CI stage conditions that module imports) and the graph comparison.
PRODUCER_SHA256 = {
    "scripts/check_asan_ci_policy.py": "02553383756db91981d42745e2b005d7f73f10dc9c5c2ab30437df919f6fcb5b",
    "scripts/ci_stage_policy.py": "1ff0e611958501bfef1bfb54ea4016c129ed717d01de23a51cf8f7bf2cfd373e",
    "scripts/check_owner_runtime_custody_policy.py": "560aed1fd4634593a4027525642315740f7525a80cacb880249fd595e38fe02c",
    "scripts/install-pinned-nix.sh": "f8935b411c586d0fdebf1c24aca650459bd166593ab3025ed0df05e4e2012a72",
    "scripts/qemu_qmp_query_kvm.py": "e146d1aa17af33d65b530a663b9ee2396cd45323df169502dda058c56ef73fc6",
    "scripts/qemu-kernel-cache.sh": "9fabec0f9d07827bdf60ae6ea2ca245c24637929590c2256fb14a264aef78eb9",
    "scripts/qemu-closure-evidence.sh": "449dc07df784ccc7f5882e2189367cb90e2caf51f5f7b9ceeefdb0b5e0eb0dd4",
    "scripts/check_qemu_closure_evidence.py": "64990243f725786a25f82042b15f4f14c40e675e1f2372364422deeb55db7dc7",
    "deploy/nixos/flake.nix": "cfd9e71e22b18412dab4e3bc4d8a10ff702dcab3284f41c542a83947bce85e69",
    "deploy/nixos/flake.lock": "2e002544ff613a1b05d8f6a1a0d936a93278196c79ccd75f1f4fba58f28737c7",
    "deploy/nixos/modules/mountfsd-activation.nix": "5378ffda1f8f15c666091767e7fc346693e0b95f8715474235311dacc1e15c03",
    "deploy/nixos/qemu-evidence/guest.nix": "e7066879731d9f335a00b8d16a7a79fb320476d3b879962a0b6fc1e36e62c57a",
    "deploy/nixos/qemu-evidence/collect-evidence.sh": "afe15409386efce6792806890974105f0bbbf5cb1440d4a3910362ce5cf5c637",
    "deploy/nixos/qemu-evidence/build-images.sh": "a8be58ad9c58a3cd6ed4d4120aab8a632463c466dff385e1f038edb98e0b9672",
    "deploy/nixos/dev-trust/root-hash-dev-test.crt": "418702f8e3af31e90ec317776153beeeda4be61e489366379cab3a4a76455896",
    "deploy/nixos/dev-trust/root-hash-dev-test.key": "ca6cdbcf2f58cc20de6e45e63e387be37fc9d46e21d0e6e1212e6c9a0cd0dcd8",
    "deploy/nixos/dev-trust/root-hash-untrusted-dev-test.crt": "baf9bb141cf6c289964a6bf0e07cb5490be7ecc78bba27cdca484c3a73ba547d",
    "deploy/nixos/dev-trust/root-hash-untrusted-dev-test.key": "c1dd51e8357097ba31db0a1cc8c125cc3c7b95235c23ae49b82f74a76db61271",
    "deploy/sysctl.d/60-piglor-sandbox.conf": "b0c1bded474cb544f26bd1126c4b4397c6c776e8b9cc3b09be2708152295b026",
}
CHECKOUT_STEP = {"uses": CHECKOUT, "with": {"persist-credentials": False}}
INSTALL_NIX_STEP = {"name": "Install the hash-pinned Nix release",
                    "run": "bash scripts/install-pinned-nix.sh"}
ARCHITECTURES = {"fail-fast": False, "matrix": {"include": [
    {"architecture": "x86_64", "runner": "ubuntu-24.04"},
    {"architecture": "aarch64", "runner": "ubuntu-24.04-arm"},
]}}
EXPECTED = {
    "name": "qemu-closure-evidence",
    True: {
        "pull_request": {"paths": [
            WORKFLOW,
            "deploy/nixos/**",
            "deploy/sysctl.d/**",
            "Cargo.lock",
            "Cargo.toml",
            "apps/pos-sandbox-evidence-adapter/**",
            "apps/pos-sandboxd/**",
            "crates/pos-reference/**",
            "fixtures/conformance/**",
            "scripts/check_qemu_closure_evidence.py",
            "scripts/test_check_qemu_closure_evidence.py",
            "scripts/check_qemu_closure_workflow_policy.py",
            "scripts/test_check_qemu_closure_workflow_policy.py",
            "scripts/check_asan_ci_policy.py",
            "scripts/ci_stage_policy.py",
            "scripts/check_owner_runtime_custody_policy.py",
            "scripts/install-pinned-nix.sh",
            "scripts/qemu-closure-evidence.sh",
            "scripts/qemu_qmp_query_kvm.py",
            "scripts/test_qemu_closure_evidence_producer.py",
            "scripts/qemu-kernel-cache.sh",
        ]},
        "push": {"branches": ["main"], "paths": [
            WORKFLOW,
            "deploy/nixos/**",
            "scripts/install-pinned-nix.sh",
            "scripts/qemu-kernel-cache.sh",
        ]},
    },
    "permissions": {"contents": "read"},
    "concurrency": {"group": "qemu-closure-evidence-${{ github.ref }}", "cancel-in-progress": "${{ github.event_name == 'pull_request' }}"},
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
                {"name": "Test the evidence producer",
                 "run": "python scripts/test_qemu_closure_evidence_producer.py"},
            ],
        },
        "evidence": {
            "name": "evidence (${{ matrix.architecture }})",
            "needs": "policy",
            "if": "${{ github.event_name == 'pull_request' }}",
            "strategy": ARCHITECTURES,
            "runs-on": "${{ matrix.runner }}",
            "timeout-minutes": 345,
            "env": {"EVIDENCE_ARCHITECTURE": "${{ matrix.architecture }}",
                    "EVIDENCE_PR_HEAD_SHA": "${{ github.event.pull_request.head.sha }}"},
            "steps": [
                CHECKOUT_STEP,
                EXPECTED_SDK_HEADROOM_STEP,
                INSTALL_NIX_STEP,
                {"name": "Fetch the signed kernel built on main", "id": "kernel-cache", "env": RELEASE_ENV,
                 "run": 'if ! bash scripts/qemu-kernel-cache.sh fetch "${EVIDENCE_ARCHITECTURE}"'
                        f' {KERNEL_CACHE_DIR} >>"${{GITHUB_OUTPUT}}"; then\n'
                        "  echo '::warning::qemu-kernel-cache fetch failed: building the kernel from source.'\n"
                        "  echo 'hit=false' >>\"${GITHUB_OUTPUT}\"\n"
                        "fi\n"},
                {"name": "Note a kernel cache miss",
                 "if": "${{ steps.kernel-cache.outputs.hit != 'true' }}",
                 "run": "echo 'qemu-kernel-cache miss, so the kernel is built from source.'"
                        ' >>"${GITHUB_STEP_SUMMARY}"'},
                {"name": "Import the signed kernel",
                 "if": "${{ steps.kernel-cache.outputs.hit == 'true' }}",
                 "run": 'if ! bash scripts/qemu-kernel-cache.sh import "${EVIDENCE_ARCHITECTURE}"'
                        f' {KERNEL_CACHE_DIR}; then\n'
                        "  echo '::warning::qemu-kernel-cache refused: building the kernel from source.'\n"
                        "  echo 'qemu-kernel-cache refused: the kernel was built from source.'"
                        ' >>"${GITHUB_STEP_SUMMARY}"\n'
                        "fi\n"},
                {"name": "Build the pinned guest and record its store identities",
                 "run": f'bash scripts/qemu-closure-evidence.sh build "${{EVIDENCE_ARCHITECTURE}}" {EVIDENCE}'},
                {"name": "Boot the guest under QEMU TCG without network",
                 "run": f'bash scripts/qemu-closure-evidence.sh boot "${{EVIDENCE_ARCHITECTURE}}" {EVIDENCE}'},
                {"name": "Check the recorded evidence",
                 "run": "python scripts/check_qemu_closure_evidence.py"
                        ' --architecture "${EVIDENCE_ARCHITECTURE}"'
                        " --certificate deploy/nixos/dev-trust/root-hash-dev-test.crt"
                        " --untrusted-certificate deploy/nixos/dev-trust/root-hash-untrusted-dev-test.crt"
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
                 "if": "${{ !success() }}", "uses": UPLOAD, "with": {
                     "name": f"qemu-closure-diagnostics-{ARTIFACT_SUFFIX}",
                     "path": "${{ runner.temp }}/qemu-closure-evidence/",
                     "if-no-files-found": "ignore", "retention-days": 7,
                 }},
            ],
        },
        "kernel-cache-selftest": {
            "name": "kernel cache self-test",
            "needs": "policy",
            "if": "${{ github.event_name == 'pull_request' }}",
            "runs-on": "ubuntu-24.04",
            "timeout-minutes": 20,
            "steps": [
                CHECKOUT_STEP,
                INSTALL_NIX_STEP,
                {"name": "Sign, verify and import a throwaway path",
                 "run": 'bash scripts/qemu-kernel-cache.sh selftest "${RUNNER_TEMP}/qemu-kernel-cache-selftest"'},
            ],
        },
        "kernel-cache": {
            "name": "kernel cache",
            "needs": "policy",
            "if": "${{ github.event_name != 'pull_request' }}",
            "environment": "qemu-kernel-cache",
            "permissions": {"contents": "write"},
            "strategy": ARCHITECTURES,
            "runs-on": "${{ matrix.runner }}",
            "timeout-minutes": 345,
            "env": {"EVIDENCE_ARCHITECTURE": "${{ matrix.architecture }}"},
            "steps": [
                CHECKOUT_STEP,
                EXPECTED_SDK_HEADROOM_STEP,
                INSTALL_NIX_STEP,
                {"name": "Fetch the published kernel", "id": "kernel-fetch", "env": RELEASE_ENV,
                 "run": 'bash scripts/qemu-kernel-cache.sh fetch "${EVIDENCE_ARCHITECTURE}"'
                        f' {KERNEL_CACHE_DIR} >>"${{GITHUB_OUTPUT}}"'},
                {"name": "Verify the published kernel",
                 "if": "${{ steps.kernel-fetch.outputs.hit == 'true' }}",
                 "run": f'bash scripts/qemu-kernel-cache.sh verify "${{EVIDENCE_ARCHITECTURE}}" {KERNEL_CACHE_DIR}'},
                {"name": "Build the kernel",
                 "if": "${{ steps.kernel-fetch.outputs.hit != 'true' }}",
                 "run": 'bash scripts/qemu-kernel-cache.sh build "${EVIDENCE_ARCHITECTURE}"'},
                {"name": "Sign the kernel",
                 "if": "${{ steps.kernel-fetch.outputs.hit != 'true' }}",
                 "env": {"QEMU_KERNEL_CACHE_SIGNING_KEY": "${{ secrets.QEMU_KERNEL_CACHE_SIGNING_KEY }}"},
                 "run": f'bash scripts/qemu-kernel-cache.sh export "${{EVIDENCE_ARCHITECTURE}}" {KERNEL_CACHE_DIR}'},
                {"name": "Publish the signed kernel",
                 "if": "${{ steps.kernel-fetch.outputs.hit != 'true' }}", "env": RELEASE_ENV,
                 "run": f'bash scripts/qemu-kernel-cache.sh publish "${{EVIDENCE_ARCHITECTURE}}" {KERNEL_CACHE_DIR}'},
                {"name": "Prune week-old kernel assets", "env": RELEASE_ENV,
                 "run": 'bash scripts/qemu-kernel-cache.sh prune "${EVIDENCE_ARCHITECTURE}"'},
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
