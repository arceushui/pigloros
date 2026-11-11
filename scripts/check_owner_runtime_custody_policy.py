#!/usr/bin/env python3
"""Allowlist the complete retained-runtime evidence graph and its producers."""

from __future__ import annotations

import hashlib
import pathlib
import sys

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
UPLOAD = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
WORKFLOW = ".github/workflows/owner-runtime-custody.yml"
# These pins bind the complete reviewed producer programs, including commands
# reached through the workflow's PowerShell indirection. Universal newlines
# preserve the same program across Git's LF and CRLF checkouts.
PRODUCER_SHA256 = {
    "scripts/prepare-owner-runtime.ps1": "4f06df3d95402416282ee304ce6ed1b0665ed12b589e198d5bdadcc7bf10fe7a",
    "scripts/owner_bridge_runtime.py": "ca9c0861a226d75dbfbbd233f3f56e30f5e73504e0c209e458260724cad5e43d",
}
EXPECTED = {
    "name": "owner-runtime-custody",
    True: {
        "pull_request": {"paths": [
            WORKFLOW,
            "scripts/check_owner_runtime_custody_policy.py",
            "scripts/test_check_owner_runtime_custody_policy.py",
            "scripts/test_ci_workflow_policy.py",
            "scripts/owner_bridge_runtime.py",
            "scripts/test_owner_bridge_runtime.py",
            "scripts/prepare-owner-runtime.ps1",
            "crates/pos-owner-bridge-windows/runtime-manifest.v1",
        ]},
        "workflow_dispatch": None,
    },
    "permissions": {"contents": "read"},
    "jobs": {
        "manifest-contract": {
            "runs-on": "ubuntu-24.04", "timeout-minutes": 5,
            "steps": [
                {"uses": CHECKOUT, "with": {"persist-credentials": False}},
                {"name": "Enforce retained runtime workflow policy",
                 "run": "python scripts/check_owner_runtime_custody_policy.py"},
                {"name": "Test retained runtime workflow policy",
                 "run": "python scripts/test_check_owner_runtime_custody_policy.py"},
                {"name": "Test retained runtime manifest contract",
                 "run": "python scripts/test_owner_bridge_runtime.py"},
            ],
        },
        "verify-runtime": {
            "needs": "manifest-contract", "runs-on": "windows-latest",
            "timeout-minutes": 20,
            "steps": [
                {"uses": CHECKOUT, "with": {"persist-credentials": False}},
                {"name": "Verify CAB, signer, timestamp, layout and every extracted file",
                 "shell": "pwsh", "env": {"GH_TOKEN": "${{ github.token }}"},
                 "run": './scripts/prepare-owner-runtime.ps1 -OutputRoot "$env:RUNNER_TEMP/owner-runtime-evidence"'},
                {"name": "Retain the verified custody candidate and public provenance",
                 "uses": UPLOAD, "with": {
                     "name": "owner-runtime-custody-${{ github.sha }}",
                     "path": "${{ runner.temp }}/owner-runtime-evidence/*.cab\n"
                             "${{ runner.temp }}/owner-runtime-evidence/*.json\n"
                             "${{ runner.temp }}/owner-runtime-evidence/*.signature.txt\n",
                     "if-no-files-found": "error", "retention-days": 7,
                     "compression-level": 0,
                 }},
            ],
        },
    },
}


class PolicyError(ValueError):
    """A producer or execution graph differs from the reviewed evidence path."""


class UniqueKeys(yaml.SafeLoader):
    """Reject duplicate mappings instead of silently keeping their last value."""


def unique_mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in result:
            raise PolicyError(f"duplicate workflow key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=True)
    return result


UniqueKeys.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def load_workflow(text: str) -> dict:
    try:
        value = yaml.load(text, Loader=UniqueKeys)
    except (yaml.YAMLError, TypeError) as error:
        raise PolicyError(f"invalid custody workflow: {error}") from error
    if not isinstance(value, dict):
        raise PolicyError("custody workflow must be a mapping")
    return value


def same_graph(actual, expected) -> bool:
    """Compare the parsed graph without bool/int or integer/float aliases."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return len(actual) == len(expected) and all(
            any(type(key) is type(other) and key == other and same_graph(value, actual[other])
                for other in actual)
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            same_graph(left, right) for left, right in zip(actual, expected)
        )
    return actual == expected


def check(workflow: dict, producers: dict[str, str]) -> None:
    if not same_graph(workflow, EXPECTED):
        raise PolicyError("custody workflow differs from the reviewed Release-only execution graph")
    if producers.keys() != PRODUCER_SHA256.keys():
        raise PolicyError("custody producer set changed")
    for name, expected in PRODUCER_SHA256.items():
        actual = hashlib.sha256(producers[name].encode("utf-8")).hexdigest()
        if actual != expected:
            raise PolicyError(f"custody producer differs from reviewed program: {name}")


def check_repository(root: pathlib.Path = ROOT) -> None:
    check(load_workflow((root / WORKFLOW).read_text(encoding="utf-8")), {
        name: (root / name).read_text(encoding="utf-8") for name in PRODUCER_SHA256
    })


def main() -> int:
    try:
        check_repository()
    except (PolicyError, OSError, UnicodeError) as error:
        print(f"owner-runtime custody policy: {error}", file=sys.stderr)
        return 1
    print("owner-runtime Release-only evidence graph and producer pins hold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
