"""Read-only hosted KVM prerequisites; never creates a VM or authorizes activation."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sys


def inspect_kvm():
    """KVM's stable system ioctl requires API 12; close the descriptor on all paths."""
    try:
        descriptor = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
    except OSError as error:
        return {"api_version": None, "errno": error.errno}
    try:
        try:
            return {"api_version": fcntl.ioctl(descriptor, 0xAE00, 0), "errno": None}
        except OSError as error:
            return {"api_version": None, "errno": error.errno}
    finally:
        os.close(descriptor)


def prerequisite_failures(expected_arch, machine, uid, kvm):
    failures = []
    if machine != expected_arch:
        failures.append("native-architecture-mismatch")
    if uid == 0:
        failures.append("host-inspection-must-be-unprivileged")
    if kvm["api_version"] != 12:
        failures.append("usable-kvm-api-12-not-established")
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-arch", choices=("aarch64", "x86_64"), required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        parser.error("source SHA must be a full lowercase Git SHA")
    repository = Path(__file__).resolve().parent.parent
    identities = {}
    for relative in (
        "docs/research/native-profiling-probe-preflight.json",
        ".github/workflows/native-profiling-preflight.yml",
        "scripts/native_profiling_host_preflight.py",
        "scripts/test_native_profiling_host_preflight.py",
    ):
        identities[relative] = hashlib.sha256((repository / relative).read_bytes()).hexdigest()
    machine = platform.machine()
    uid = os.geteuid()
    kvm = inspect_kvm()
    failures = prerequisite_failures(args.expected_arch, machine, uid, kvm)
    print(json.dumps({
        "scope": "adr079-read-only-host-prerequisites",
        "source_sha": args.source_sha,
        "source_file_sha256": identities,
        "expected_arch": args.expected_arch,
        "observed_arch": machine,
        "host_kernel": platform.release(),
        "host_uid": uid,
        "kvm": kvm,
        "failures": failures,
        "kvm_prerequisite_pass": not failures,
        "privileged_activation_authorized": False,
        "vm_created": False,
        "remaining_prerequisites": [
            "exact-guest-and-tool-closure",
            "resource-and-artifact-enforcement-with-negative-controls",
            "read-only-source-secretless-build-and-egress-enforcement",
            "outside-guest-destruction-and-independent-verification",
        ],
    }, sort_keys=True))
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
