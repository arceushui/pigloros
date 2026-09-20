#!/usr/bin/env python3
"""Validate and inventory the throwaway ADR-079 profile evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import stat


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def covered_and_uncovered(path: pathlib.Path, source_suffix: str) -> tuple[bool, bool]:
    report = json.loads(path.read_text(encoding="utf-8"))
    files = [
        item
        for data in report["data"]
        for item in data["files"]
        if item["filename"].endswith(source_suffix)
    ]
    if len(files) != 1:
        raise ValueError(f"{path} did not retain exactly one {source_suffix}")
    counts = [segment[2] for segment in files[0]["segments"] if segment[3]]
    return any(count > 0 for count in counts), any(count == 0 for count in counts)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_dir", type=pathlib.Path)
    parser.add_argument("launcher", type=pathlib.Path)
    parser.add_argument("adapter", type=pathlib.Path)
    parser.add_argument("architecture")
    arguments = parser.parse_args()
    evidence_dir = arguments.evidence_dir.resolve()

    reports = {
        "launcher": covered_and_uncovered(
            evidence_dir / "launcher-only.json", "/launcher/src/main.rs"
        ),
        "adapter": covered_and_uncovered(
            evidence_dir / "adapter-only.json", "/adapter/src/main.rs"
        ),
    }
    if reports != {"launcher": (True, True), "adapter": (True, True)}:
        raise ValueError(f"covered/uncovered source closure failed: {reports!r}")
    combined = json.loads((evidence_dir / "official-combined.json").read_text())
    combined_sources = {
        item["filename"]
        for data in combined["data"]
        for item in data["files"]
        if item["filename"].endswith("/src/main.rs")
    }
    if len(combined_sources) != 2:
        raise ValueError(f"combined report source set is not closed: {combined_sources!r}")
    raw_profiles = sorted(evidence_dir.glob("*/*.profraw"))
    if len(raw_profiles) != 4 or any(path.stat().st_size == 0 for path in raw_profiles):
        raise ValueError("expected four nonempty per-process raw profiles")
    if stat.S_IMODE(arguments.launcher.stat().st_mode) & 0o111 == 0:
        raise ValueError("launcher object is not executable")
    if stat.S_IMODE(arguments.adapter.stat().st_mode) & 0o111 == 0:
        raise ValueError("adapter object is not executable")

    retained = sorted(path for path in evidence_dir.rglob("*") if path.is_file())
    inventory = {
        "architecture": arguments.architecture,
        "cargo_llvm_cov_report_present": (evidence_dir / "cargo-llvm-cov.json").is_file(),
        "clean_exit_launcher_profile_preserved": any(
            path.name.startswith("launcher-") for path in evidence_dir.glob("clean/*.profraw")
        ),
        "forced_kill_adapter_profile_preserved": any(
            path.name.startswith("adapter-") for path in evidence_dir.glob("kill/*.profraw")
        ),
        "instrumented_objects_are_not_release_conformance": True,
        "profile_sha256": {
            str(path.relative_to(evidence_dir)): sha256(path) for path in raw_profiles
        },
        "reports_retain_covered_and_uncovered_regions": True,
        "retained_sha256": {
            str(path.relative_to(evidence_dir)): sha256(path) for path in retained
        },
        "verdict": "throwaway profile preservation and official report composition passed",
    }
    (evidence_dir / "profile-evidence.json").write_text(
        json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
