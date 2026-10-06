#!/usr/bin/env python3
"""Adversarial tests for the Wasmtime pin and feature-set checker."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts/check_wasmtime_feature_pin.py"
WASMTIME_ID = "registry+https://github.com/rust-lang/crates.io-index#wasmtime@49.0.2"
HOST_ID = "path+file:///repo/crates/pos-plugin-host#0.1.0"
RESOLVED = [
    "component-model",
    "cranelift",
    "once_cell",
    "runtime",
    "std",
    "wasmtime-jit-icache-coherence",
]

VALID = {
    "packages": [
        {
            "name": "wasmtime",
            "version": "49.0.2",
            "id": WASMTIME_ID,
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "dependencies": [],
        },
        {
            "name": "pos-plugin-host",
            "version": "0.1.0",
            "id": HOST_ID,
            "source": None,
            "dependencies": [
                {
                    "name": "wasmtime",
                    "req": "=49.0.2",
                    "uses_default_features": False,
                    "features": ["component-model", "cranelift", "runtime"],
                }
            ],
        },
    ],
    "resolve": {
        "nodes": [
            {"id": WASMTIME_ID, "dependencies": [], "features": list(RESOLVED)},
            {"id": HOST_ID, "dependencies": [WASMTIME_ID], "features": []},
            # A declared but unresolved (dev) dependency is not a dependent.
            {"id": "wit-component", "dependencies": [], "features": []},
        ]
    },
}


def host_dependency(metadata: dict) -> dict:
    return metadata["packages"][1]["dependencies"][0]


def mutate(change) -> dict:
    metadata = copy.deepcopy(VALID)
    change(metadata)
    return metadata


REJECTED = {
    "extra resolved feature": mutate(
        lambda m: m["resolve"]["nodes"][0]["features"].append("wat")
    ),
    "missing resolved feature": mutate(
        lambda m: m["resolve"]["nodes"][0]["features"].remove("runtime")
    ),
    "other version": mutate(lambda m: m["packages"][0].update(version="49.0.1")),
    "other source": mutate(
        lambda m: m["packages"][0].update(source="git+https://example.invalid/wasmtime")
    ),
    "caret requirement": mutate(lambda m: host_dependency(m).update(req="^49.0.2")),
    "default features": mutate(
        lambda m: host_dependency(m).update(uses_default_features=True)
    ),
    "extra requested feature": mutate(
        lambda m: host_dependency(m)["features"].append("async")
    ),
    "second dependent": mutate(
        lambda m: m["resolve"]["nodes"].append(
            {"id": "pos-other", "dependencies": [WASMTIME_ID], "features": []}
        )
    ),
    "second wasmtime": mutate(
        lambda m: m["packages"].append(dict(m["packages"][0], version="48.0.5"))
    ),
    "unresolved": mutate(lambda m: m["resolve"]["nodes"].pop(0)),
    "no wasmtime": mutate(lambda m: m["packages"].pop(0)),
    "removed requested feature": mutate(
        lambda m: host_dependency(m)["features"].remove("runtime")
    ),
}

# The reason each case must be rejected for, so a case cannot pass by failing
# a different check.
REASONS = {
    "extra resolved feature": "resolved features",
    "missing resolved feature": "resolved features",
    "other version": "resolved to 49.0.1",
    "other source": "not crates.io",
    "caret requirement": "requirement ^49.0.2",
    "default features": "default features must be disabled",
    "extra requested feature": "requested features",
    "second dependent": "only pos-plugin-host may depend",
    "second wasmtime": "expected exactly one wasmtime package, found 2",
    "unresolved": "resolve nodes",
    "no wasmtime": "expected exactly one wasmtime package, found 0",
    "removed requested feature": "requested features",
}


def run_stdin(metadata: dict) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER)],
        input=json.dumps(metadata),
        capture_output=True,
        check=False,
        text=True,
    )


def run(metadata: dict) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "metadata.json"
        path.write_text(json.dumps(metadata), encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(CHECKER), str(path)],
            capture_output=True,
            check=False,
            text=True,
        )


def main() -> int:
    failures = []
    accepted = run(VALID)
    if accepted.returncode != 0:
        failures.append(f"valid metadata rejected: {accepted.stderr.strip()}")
    for name, metadata in REJECTED.items():
        result = run(metadata)
        rejected = result.returncode == 1 and "wasmtime pin:" in result.stderr
        if not rejected or REASONS[name] not in result.stderr:
            failures.append(f"{name} was not rejected for {REASONS[name]!r}")
    if run_stdin(VALID).returncode != 0:
        failures.append("valid metadata on stdin rejected")
    if run_stdin(REJECTED["other version"]).returncode != 1:
        failures.append("invalid metadata on stdin accepted")
    usage = subprocess.run(
        [sys.executable, str(CHECKER), "a", "b"],
        capture_output=True,
        check=False,
        text=True,
    )
    if usage.returncode != 2:
        failures.append("extra arguments were not refused")
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    print(f"wasmtime pin checker: {len(REJECTED) + 4} cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
