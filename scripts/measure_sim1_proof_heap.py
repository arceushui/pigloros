#!/usr/bin/env python3
"""Measure the public SIM1 adversarial cases in the hosted risk workflow.

Massif records heap allocation, including fixture construction and the Rust
test harness. These measurements are not verifier-only RSS or a release limit.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


@dataclass(frozen=True)
class ProofCase:
    test: str
    lower_bound: int = 1024 * 1024 - 4096
    upper_bound: int = 1024 * 1024


MODULE = "image_proof_cases::envelope_cases::"
PREFIX = MODULE + "public_proof_verification_"
IDENTITY_PREFIX = MODULE + "identity_cases::public_proof_verification_"
CASES = {
    "digest-set": ProofCase(PREFIX + "bounds_near_limit_digest_set_before_decoding"),
    "certificate": ProofCase(PREFIX + "bounds_near_limit_certificate_before_decoding"),
    "attributes": ProofCase(PREFIX + "rejects_near_limit_attributes_before_decoding"),
    "near-limit-issuer": ProofCase(
        IDENTITY_PREFIX
        + "bounds_near_limit_issuer_before_decoding",
    ),
    "reversed-issuer": ProofCase(
        IDENTITY_PREFIX
        + "rejects_reverse_ordered_bounded_issuer",
        lower_bound=64 * 1024 - 4096,
        upper_bound=64 * 1024,
    ),
    "canonical-issuer": ProofCase(
        IDENTITY_PREFIX
        + "decodes_canonical_bounded_issuer",
        lower_bound=64 * 1024 - 4096,
        upper_bound=64 * 1024,
    ),
    "maximum-certificate-set": ProofCase(
        PREFIX + "decodes_eight_maximum_size_certificates",
        lower_bound=8 * 64 * 1024,
        upper_bound=8 * 64 * 1024 + 4096,
    ),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def executable_from_artifacts(path: Path) -> Path:
    candidates = set()
    for line in path.read_text().splitlines():
        artifact = json.loads(line)
        if (
            artifact.get("reason") == "compiler-artifact"
            and artifact.get("target", {}).get("name")
            == "sandbox_admission_contract_public"
            and artifact.get("profile", {}).get("test") is True
            and artifact.get("executable")
        ):
            candidates.add(artifact["executable"])
    require(len(candidates) == 1, "expected exactly one public admission executable")
    executable = Path(candidates.pop()).resolve(strict=True)
    require(executable.is_file(), "public admission executable is not a file")
    return executable


def peak_allocation(path: Path) -> dict[str, int]:
    snapshots = re.split(r"(?m)^snapshot=", path.read_text())[1:]
    peaks = [item for item in snapshots if re.search(r"(?m)^heap_tree=peak$", item)]
    require(len(peaks) == 1, "Massif must report exactly one peak snapshot")
    fields = dict(re.findall(r"(?m)^(mem_heap_B|mem_heap_extra_B|mem_stacks_B)=(\d+)$", peaks[0]))
    require(len(fields) == 3, "Massif peak is missing allocation fields")
    values = {key: int(value) for key, value in fields.items()}
    require(values["mem_heap_B"] > 0, "Massif reported no heap allocation")
    require(values["mem_stacks_B"] == 0, "unexpected stack measurement mode")
    return values


def measure(executable: Path, directory: Path, label: str, case: ProofCase) -> dict[str, object]:
    trace = directory / f"{label}.massif"
    result = subprocess.run(
        [
            "valgrind",
            "--tool=massif",
            "--stacks=no",
            "--time-unit=B",
            "--peak-inaccuracy=0.0",
            f"--massif-out-file={trace}",
            str(executable),
            case.test,
            "--exact",
            "--test-threads=1",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    (directory / f"{label}.stdout").write_text(result.stdout)
    (directory / f"{label}.stderr").write_text(result.stderr)
    require(result.returncode == 0, f"{label}: profiled public test failed")
    require(
        "test result: ok. 1 passed; 0 failed; 0 ignored;" in result.stdout,
        f"{label}: the exact public test did not execute successfully",
    )
    peak = peak_allocation(trace)
    rendered = subprocess.run(
        ["ms_print", str(trace)], capture_output=True, text=True, check=True
    )
    (directory / f"{label}.txt").write_text(rendered.stdout)
    return {
        "case": case.test,
        "proof_bytes_exclusive_lower_bound": case.lower_bound,
        "proof_bytes_inclusive_upper_bound": case.upper_bound,
        "peak": peak,
    }


def main() -> None:
    require(len(sys.argv) == 3, "usage: measure_sim1_proof_heap.py BUILD_JSON REPORT_DIR")
    executable = executable_from_artifacts(Path(sys.argv[1]))
    directory = Path(sys.argv[2])
    directory.mkdir(parents=True, exist_ok=True)
    source_head = os.environ["PROFILE_SOURCE_HEAD"]
    require(re.fullmatch(r"[0-9a-f]{40}", source_head) is not None, "invalid source head")
    checkout = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    version = subprocess.check_output(["valgrind", "--version"], text=True).strip()
    rust = subprocess.check_output(["rustc", "--version"], text=True).strip()
    digest = hashlib.sha256()
    with executable.open("rb") as binary:
        for block in iter(lambda: binary.read(1024 * 1024), b""):
            digest.update(block)
    metadata = {
        "source_head": source_head,
        "checkout": checkout,
        "executable_sha256": digest.hexdigest(),
        "profiler": version,
        "rustc": rust,
        "scope": "heap allocation including fixture construction and test harness; excludes stack and RSS",
        "peak_inaccuracy_percent": 0,
    }
    (directory / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    results = {label: measure(executable, directory, label, case) for label, case in CASES.items()}
    (directory / "measurements.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
