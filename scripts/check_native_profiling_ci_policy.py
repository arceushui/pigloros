"""Closed safety configuration and advisory, non-activating KVM diagnostic policy."""

import json
from pathlib import Path

import yaml


def check_preflight_config(config):
    """Fix the complete reviewed safety budget; this does not enforce a VM run."""
    expected = {
        "scope": "adr079-probe-only",
        "native_classes": ["aarch64", "x86_64"],
        "limits": {
            "max_vms_per_job": 1,
            "max_parallel_native_jobs": 2,
            "guest_vcpus": 2,
            "guest_memory_bytes": 4294967296,
            "guest_writable_disk_bytes": 17179869184,
            "host_build_vcpus": 2,
            "host_build_memory_bytes": 12884901888,
            "host_build_disk_bytes": 85899345920,
            "host_build_timeout_seconds": 2700,
            "probe_timeout_seconds": 900,
            "job_timeout_seconds": 5400,
            "max_artifact_files": 128,
            "max_individual_artifact_bytes": 134217728,
            "max_aggregate_artifact_bytes": 536870912,
            "max_expanded_artifact_bytes": 536870912,
            "max_path_depth": 8,
            "max_path_bytes": 256,
            "reporter_vcpus": 2,
            "reporter_memory_bytes": 2147483648,
            "reporter_timeout_seconds": 300,
            "external_cleanup_timeout_seconds": 120,
        },
        "artifact_policy": {
            "allow_symlinks": False,
            "allow_hardlinks": False,
            "allow_special_files": False,
            "allow_sparse_files": False,
            "allow_absolute_paths": False,
            "allow_parent_components": False,
            "allow_duplicate_paths": False,
            "allow_nested_archives": False,
            "reject_missing_corrupt_mismatched_inventory": True,
        },
        "activation_requirements": [
            "exact-source-workflow-and-preflight-identities",
            "digest-pinned-complete-guest-image-and-runtime-closure",
            "exact-rust-llvm-runtime-tools-and-object-inventory",
            "verified-resource-enforcement-and-negative-controls",
            "read-only-source-and-unprivileged-secretless-build",
            "restricted-build-egress-and-disabled-privileged-test-egress",
            "outside-guest-destruction-owner-and-independent-verifier",
        ],
        "on_unproved_requirement": "do-not-start-privileged-execution",
        "on_limit_exceeded": "fail-and-destroy-guest",
        "on_unverified_destruction": "fail-with-retained-residual-state-evidence",
    }
    # JSON comparison also rejects Python's bool/int and int/float equality aliases.
    # Closed exact values preserve the reviewed cross-field budget, not just a schema.
    if json.dumps(config, sort_keys=True, allow_nan=False) != json.dumps(expected, sort_keys=True):
        raise ValueError("native profiling configuration differs from the reviewed safety policy")


def check_workflow(workflow):
    """Reject changes to the reviewed diagnostic contract, including extra steps."""
    expected = {
        "name": "native-profiling-preflight",
        # PyYAML's YAML 1.1 safe loader decodes the unquoted Actions 'on' key as True.
        True: {
            "pull_request": {"paths": [
                ".github/workflows/native-profiling-preflight.yml",
                "scripts/native_profiling_host_preflight.py",
                "scripts/test_native_profiling_host_preflight.py",
                "scripts/check_native_profiling_ci_policy.py",
                "scripts/test_check_native_profiling_ci_policy.py",
                ".github/workflows/ci.yml",
                "docs/research/native-profiling-probe-preflight.*",
            ]},
            "workflow_dispatch": None,
        },
        "permissions": {"contents": "read"},
        "concurrency": {
            "group": "native-profiling-preflight-${{ github.ref }}",
            "cancel-in-progress": True,
        },
        "jobs": {"host-prerequisites": {
            "name": "host-prerequisites-${{ matrix.arch }}",
            "runs-on": "${{ matrix.runner }}",
            "timeout-minutes": 5,
            "strategy": {
                "fail-fast": False,
                "max-parallel": 2,
                "matrix": {"include": [
                    {"arch": "x86_64", "runner": "ubuntu-24.04"},
                    {"arch": "aarch64", "runner": "ubuntu-24.04-arm"},
                ]},
            },
            "steps": [
                {"uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                 "with": {"persist-credentials": False}},
                {"name": "Test read-only prerequisite boundary",
                 "run": "python3 -m unittest discover -s scripts -p test_native_profiling_host_preflight.py -v"},
                {"name": "Inspect native KVM prerequisite without creating a VM",
                 "env": {"EXPECTED_ARCH": "${{ matrix.arch }}", "SOURCE_SHA": "${{ github.sha }}"},
                 "run": (
                     "set -euo pipefail\n"
                     'test "$(git rev-parse HEAD)" = "$SOURCE_SHA"\n'
                     "python3 scripts/native_profiling_host_preflight.py \\\n"
                     '  --expected-arch "$EXPECTED_ARCH" --source-sha "$SOURCE_SHA" | tee host-prerequisites.json\n'
                 )},
                {"name": "Retain bounded prerequisite evidence on either outcome",
                 "if": "always()",
                 "uses": "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
                 "with": {
                     "name": "native-profiling-host-prerequisites-${{ matrix.arch }}",
                     "path": "host-prerequisites.json",
                     "if-no-files-found": "error",
                     "retention-days": 7,
                 }},
            ],
        }},
    }
    if workflow != expected:
        raise ValueError("native profiling diagnostic differs from the reviewed read-only policy")


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    check_preflight_config(json.loads((root / "docs/research/native-profiling-probe-preflight.json").read_text(encoding="utf-8")))
    workflow_path = root / ".github/workflows/native-profiling-preflight.yml"
    check_workflow(yaml.safe_load(workflow_path.read_text(encoding="utf-8")))
