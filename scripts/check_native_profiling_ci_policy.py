"""Closed policy for the advisory, non-activating native KVM diagnostic."""

from pathlib import Path

import yaml


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
    workflow_path = Path(__file__).resolve().parent.parent / ".github/workflows/native-profiling-preflight.yml"
    check_workflow(yaml.safe_load(workflow_path.read_text(encoding="utf-8")))
