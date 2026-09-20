#!/usr/bin/env python3
"""Adversarial tests for the hosted ADR-084 prototype policy checker."""

from __future__ import annotations

import importlib.util
import pathlib
import shutil
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "scripts/check_adr084_prototype_ci_policy.py"
SPEC = importlib.util.spec_from_file_location("adr084_ci_policy", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load ADR-084 policy checker")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def fixture() -> pathlib.Path:
    root = pathlib.Path(tempfile.mkdtemp(prefix="adr084-policy-"))
    workflow = root / ".github/workflows/adr084-podman-feasibility.yml"
    workflow.parent.mkdir(parents=True)
    shutil.copy2(ROOT / CHECKER.WORKFLOW, workflow)
    prototype = root / "prototypes/adr084-podman-feasibility"
    prototype.mkdir(parents=True)
    for name in ("run.sh", "run_coverage_probe.sh"):
        shutil.copy2(ROOT / "prototypes/adr084-podman-feasibility" / name, prototype / name)
    return root


def replace(root: pathlib.Path, relative: str, old: str, new: str) -> None:
    path = root / relative
    source = path.read_text(encoding="utf-8")
    if source.count(old) != 1:
        raise AssertionError(f"mutation precondition failed for {relative}: {old!r}")
    path.write_text(source.replace(old, new), encoding="utf-8")


def rejected(relative: str, old: str, new: str) -> None:
    root = fixture()
    try:
        replace(root, relative, old, new)
        try:
            CHECKER.check(root)
        except CHECKER.PolicyError:
            return
        raise AssertionError(f"policy accepted mutation in {relative}: {old!r}")
    finally:
        shutil.rmtree(root)


def main() -> None:
    valid = fixture()
    try:
        CHECKER.check(valid)
    finally:
        shutil.rmtree(valid)
    rejected(
        ".github/workflows/adr084-podman-feasibility.yml",
        "          - architecture: aarch64\n            runner: ubuntu-24.04-arm\n",
        "",
    )
    rejected(
        ".github/workflows/adr084-podman-feasibility.yml",
        "        run: bash prototypes/adr084-podman-feasibility/run.sh",
        "        run: bash -x prototypes/adr084-podman-feasibility/run.sh",
    )
    rejected(
        ".github/workflows/adr084-podman-feasibility.yml",
        "        if: always()",
        "        if: success()",
    )
    rejected(
        "prototypes/adr084-podman-feasibility/run.sh",
        'bash "${prototype_dir}/run_coverage_probe.sh"',
        'true # coverage probe removed',
    )
    rejected(
        "prototypes/adr084-podman-feasibility/run.sh",
        'python3 "${prototype_dir}/write_evidence_manifest.py"',
        'true # provenance removed',
    )
    rejected(
        "prototypes/adr084-podman-feasibility/run.sh",
        'python3 "${workspace_dir}/scripts/check_spdx_sbom.py"',
        'true # SPDX validation removed',
    )
    rejected(
        "prototypes/adr084-podman-feasibility/run.sh",
        '"${artifact_dir}/fixture-sbom.spdx.json" "${SOURCE_DATE_EPOCH}"',
        '"${artifact_dir}/fixture-sbom.spdx.json" "0"',
    )
    rejected(
        "prototypes/adr084-podman-feasibility/run.sh",
        "find . -type f ! -name SHA256SUMS -printf '%P\\0'",
        "find . -type f -print0",
    )
    rejected(
        "prototypes/adr084-podman-feasibility/run_coverage_probe.sh",
        "set -euo pipefail",
        "set +e",
    )
    print("ADR-084 prototype CI policy adversarial tests passed")


if __name__ == "__main__":
    main()
