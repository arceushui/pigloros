#!/usr/bin/env python3
"""Materialize the throwaway ADR-084 revision-24 seccomp inputs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile

import cbor2


LIBSECCOMP_VERSION = "2.6.1"
LIBSECCOMP_SOURCE_SHA256 = (
    "501f66c667225d53791b97e1d7cf85ab764c297d04881f60f38f451c4b0ee1be"
)
LIBSECCOMP_SYSCALLS_SHA256 = (
    "ab64e55719254d44bc279d967845568ab9940e81ed7800e9d1066f664a9f5231"
)
SCS1_DOMAIN = b"PiglorOS.SCS1.v1\0"
PROFILE_DOMAIN = b"PiglorOS.OciSeccompProfile.v1\0"
ARCHITECTURES = {
    "x86_64": (0, "x86_64", "SCMP_ARCH_X86_64"),
    "aarch64": (1, "aarch64", "SCMP_ARCH_AARCH64"),
}
NAME = re.compile(r"[a-z0-9_]+\Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def blake3(value: bytes) -> bytes:
    result = subprocess.run(
        ["b3sum", "--raw"],
        input=value,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    if len(result.stdout) != 32:
        raise ValueError("b3sum returned a non-256-bit digest")
    return result.stdout


def load_table(archive_path: Path) -> tuple[dict[str, dict[str, str]], bytes]:
    archive_bytes = archive_path.read_bytes()
    if sha256_bytes(archive_bytes) != LIBSECCOMP_SOURCE_SHA256:
        raise ValueError("libseccomp source archive digest mismatch")
    member = f"libseccomp-{LIBSECCOMP_VERSION}/src/syscalls.csv"
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        entry = archive.getmember(member)
        source = archive.extractfile(entry)
        if source is None or not entry.isfile():
            raise ValueError("pinned libseccomp syscall table is not a regular file")
        table_bytes = source.read()
    if sha256_bytes(table_bytes) != LIBSECCOMP_SYSCALLS_SHA256:
        raise ValueError("pinned libseccomp syscall table digest mismatch")
    lines = table_bytes.decode("utf-8").splitlines()
    if not lines or not lines[0].startswith("#syscall"):
        raise ValueError("pinned libseccomp syscall table header mismatch")
    header = lines[0][1:].split(",")
    header[0] = "syscall"
    rows: dict[str, dict[str, str]] = {}
    for values in csv.reader(lines[1:]):
        if len(values) != len(header):
            raise ValueError("pinned libseccomp syscall table row width mismatch")
        row = dict(zip(header, values, strict=True))
        name = row["syscall"]
        if name in rows:
            raise ValueError("pinned libseccomp syscall table has duplicate name")
        rows[name] = row
    return rows, table_bytes


def validate_names(names: object, label: str) -> list[str]:
    if not isinstance(names, list) or not names:
        raise ValueError(f"{label} must be a nonempty array")
    if any(not isinstance(name, str) or NAME.fullmatch(name) is None for name in names):
        raise ValueError(f"{label} contains an invalid syscall name")
    if names != sorted(set(names)):
        raise ValueError(f"{label} must be strictly byte-sorted and unique")
    return names


def load_scs1(path: Path, architecture: str) -> tuple[list[str], list[str], bytes]:
    raw = path.read_bytes()
    value = cbor2.loads(raw)
    if cbor2.dumps(value, canonical=True) != raw:
        raise ValueError("SCS1 is not preferred deterministic CBOR")
    if not isinstance(value, list) or len(value) != 2:
        raise ValueError("SCS1 outer shape mismatch")
    unsigned, digest = value
    if not isinstance(unsigned, list) or len(unsigned) != 5:
        raise ValueError("SCS1 unsigned shape mismatch")
    expected_architecture = ARCHITECTURES[architecture][0]
    if unsigned[:3] != ["SCS1", 1, expected_architecture]:
        raise ValueError("SCS1 magic, version, or architecture mismatch")
    if not isinstance(digest, bytes) or len(digest) != 32:
        raise ValueError("SCS1 digest shape mismatch")
    if digest != blake3(SCS1_DOMAIN + cbor2.dumps(unsigned, canonical=True)):
        raise ValueError("SCS1 self-digest mismatch")
    requested = validate_names(unsigned[3], "requested_names")
    effective = validate_names(unsigned[4], "expected_effective_names")
    if not set(requested).issubset(effective):
        raise ValueError("requested_names is not a subset of expected_effective_names")
    return requested, effective, digest


def expected_mapping(
    requested: list[str],
    effective: list[str],
    table: dict[str, dict[str, str]],
    architecture: str,
) -> tuple[bytes, list[str], list[int]]:
    column = ARCHITECTURES[architecture][1]
    readback_only = sorted(set(effective) - set(requested))
    for name in readback_only:
        if name not in table or table[name][column] != "PNR":
            raise ValueError(f"readback-only name is not PNR: {name}")
    records: list[bytes] = []
    numeric: list[int] = []
    for name in requested:
        try:
            source_value = table[name][column]
        except KeyError as error:
            raise ValueError(f"requested name missing from pinned table: {name}") from error
        if architecture == "aarch64" and name == "poll":
            if source_value != "PNR":
                raise ValueError("aarch64 poll is not PNR in the pinned table")
            records.append(b"PNR:poll\n")
            continue
        if source_value == "PNR":
            raise ValueError(f"unapproved requested PNR name: {name}")
        if not source_value.isdecimal() or (
            len(source_value) > 1 and source_value.startswith("0")
        ):
            raise ValueError(f"requested name has no canonical native number: {name}")
        number = int(source_value)
        records.append(f"{number}:{name}\n".encode("ascii"))
        numeric.append(number)
    if len(set(numeric)) != len(numeric):
        raise ValueError("requested names resolve to a duplicate native number")
    return b"".join(sorted(records)), readback_only, sorted(numeric)


def validate_interface(
    interface: bytes,
    expected: bytes,
) -> None:
    if interface != expected:
        raise ValueError("LibseccompInterfaceV1 is not the exact canonical R mapping")


def profile_bytes(effective: list[str], architecture: str) -> bytes:
    profile = {
        "defaultAction": "SCMP_ACT_ERRNO",
        "defaultErrnoRet": 4094,
        "architectures": [ARCHITECTURES[architecture][2]],
        "syscalls": [{"names": effective, "action": "SCMP_ACT_ALLOW"}],
    }
    return json.dumps(profile, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def validate_profile(candidate: bytes, expected: bytes) -> None:
    if candidate != expected:
        raise ValueError("audit profile is not the exact canonical E mapping")


def rejected(action, message: str) -> str:
    try:
        action()
    except ValueError:
        return message
    raise AssertionError(f"mutation was accepted: {message}")


def mutation_report(
    requested: list[str],
    effective: list[str],
    table: dict[str, dict[str, str]],
    architecture: str,
    interface: bytes,
    profile: bytes,
) -> dict[str, object]:
    cases: list[str] = []
    if len(interface.splitlines()) < 2:
        raise ValueError("interface is too small for mutation evidence")
    lines = interface.splitlines(keepends=True)
    cases.append(rejected(lambda: validate_interface(b"".join(lines[1:]), interface), "missing interface row"))
    cases.append(rejected(lambda: validate_interface(interface + b"0:extra\n", interface), "extra interface row"))
    cases.append(rejected(lambda: validate_interface(b"".join(reversed(lines)), interface), "wrong interface order"))
    cases.append(rejected(lambda: validate_interface(interface[:-1], interface), "missing final newline"))
    cases.append(rejected(lambda: validate_interface(interface + b"\n", interface), "trailing empty record"))
    numeric_index = next(index for index, line in enumerate(lines) if not line.startswith(b"PNR:"))
    number, name = lines[numeric_index].split(b":", 1)
    changed = lines.copy()
    changed[numeric_index] = str(int(number) + 1).encode() + b":" + name
    cases.append(rejected(lambda: validate_interface(b"".join(changed), interface), "wrong native number"))
    changed = lines.copy()
    changed[numeric_index] = b"0" + number + b":" + name
    cases.append(rejected(lambda: validate_interface(b"".join(changed), interface), "noncanonical decimal"))
    if architecture == "aarch64":
        poll_index = lines.index(b"PNR:poll\n")
        changed = lines.copy()
        del changed[poll_index]
        cases.append(rejected(lambda: validate_interface(b"".join(changed), interface), "missing poll marker"))
        changed = lines.copy()
        changed[poll_index] = b"73:poll\n"
        cases.append(rejected(lambda: validate_interface(b"".join(changed), interface), "numeric poll alias"))
        changed = lines.copy()
        changed[poll_index] = b"PNR:ppoll\n"
        cases.append(rejected(lambda: validate_interface(b"".join(changed), interface), "poll-to-ppoll alias"))
    mutated_table = {name: row.copy() for name, row in table.items()}
    readback_only = sorted(set(effective) - set(requested))
    mutated_table[readback_only[0]][ARCHITECTURES[architecture][1]] = "0"
    cases.append(
        rejected(
            lambda: expected_mapping(requested, effective, mutated_table, architecture),
            "numeric readback-only token",
        )
    )
    if architecture == "x86_64":
        pnr_name = readback_only[0]
        mutated_requested = sorted(requested + [pnr_name])
        cases.append(
            rejected(
                lambda: expected_mapping(mutated_requested, effective, table, architecture),
                "unapproved requested PNR",
            )
        )
    parsed_profile = json.loads(profile)
    names = parsed_profile["syscalls"][0]["names"]
    for label, changed_names in (
        ("audit name removal", names[1:]),
        ("audit name substitution", ["zzzz_mutated_name"] + names[1:]),
        ("audit name reordering", list(reversed(names))),
        ("audit name addition", names + ["writev_extra"]),
    ):
        changed_profile = {
            **parsed_profile,
            "syscalls": [{"names": changed_names, "action": "SCMP_ACT_ALLOW"}],
        }
        candidate = json.dumps(changed_profile, separators=(",", ":")).encode()
        cases.append(rejected(lambda c=candidate: validate_profile(c, profile), label))
    if len(cases) < (14 if architecture == "aarch64" else 11):
        raise AssertionError("mutation matrix did not exercise the required cases")
    return {"architecture": architecture, "rejected_count": len(cases), "rejected": cases}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--architecture", choices=ARCHITECTURES, required=True)
    parser.add_argument("--scs1", type=Path, required=True)
    parser.add_argument("--libseccomp-archive", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args()
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    table, table_bytes = load_table(arguments.libseccomp_archive)
    requested, effective, scs1_digest = load_scs1(arguments.scs1, arguments.architecture)
    interface, readback_only, numeric = expected_mapping(
        requested, effective, table, arguments.architecture
    )
    validate_interface(interface, interface)
    profile = profile_bytes(effective, arguments.architecture)
    validate_profile(profile, profile)
    report = {
        "architecture": arguments.architecture,
        "requested_count": len(requested),
        "expected_effective_count": len(effective),
        "readback_only_count": len(readback_only),
        "readback_only_pnr": readback_only,
        "numeric_rule_count": len(numeric),
        "requested_pnr": ["poll"] if arguments.architecture == "aarch64" else [],
        "scs1_digest_blake3": scs1_digest.hex(),
        "libseccomp_source_sha256": LIBSECCOMP_SOURCE_SHA256,
        "libseccomp_syscalls_sha256": sha256_bytes(table_bytes),
        "interface_sha256": sha256_bytes(interface),
        "profile_blake3": blake3(PROFILE_DOMAIN + profile).hex(),
        "profile_sha256": sha256_bytes(profile),
    }
    (arguments.output_dir / "libseccomp-interface-v1.txt").write_bytes(interface)
    (arguments.output_dir / "readback-only-pnr.txt").write_text(
        "".join(f"{name}\n" for name in readback_only), encoding="ascii"
    )
    (arguments.output_dir / "oci-seccomp-profile.json").write_bytes(profile)
    (arguments.output_dir / "seccomp-mapping-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    mutations = mutation_report(
        requested, effective, table, arguments.architecture, interface, profile
    )
    (arguments.output_dir / "seccomp-mutation-report.json").write_text(
        json.dumps(mutations, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
