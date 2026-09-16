#!/usr/bin/env python3
"""Materialize the ADR-069 production SCS1 records from pinned sources."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile


SYSTEMD_REVISION = "f1d0952a125b96b7ab2f1ff29a87448ade8ac29b"
SYSTEMD_VERSION = "260.2"
SYSTEMD_SECCOMP_SHA256 = (
    "4242ae8aead8d2f0d9094449dfe039486edf0c0d8b32ba4cffc7991820590751"
)
LIBSECCOMP_VERSION = "2.6.1"
LIBSECCOMP_SOURCE_SHA256 = (
    "501f66c667225d53791b97e1d7cf85ab764c297d04881f60f38f451c4b0ee1be"
)
LIBSECCOMP_SYSCALLS_SHA256 = (
    "ab64e55719254d44bc279d967845568ab9940e81ed7800e9d1066f664a9f5231"
)
SCS1_DOMAIN = b"PiglorOS.SCS1.v1\0"
EXPECTED_EXPANDED_NAMES = 395
EXPECTED_REQUESTED_NAMES = {"x86_64": 315, "aarch64": 275}
EXPECTED_READBACK_NAMES = {"x86_64": 333, "aarch64": 300}
REQUIRED_NAMES = frozenset(
    {"execveat", "getsockopt", "poll", "recvmsg", "sendto", "socket"}
)
ARCHITECTURES = {"x86_64": 0, "aarch64": 1}
# ADR-069 expressly retains poll in the aarch64 D-Bus filter property even
# though libseccomp represents it as PNR, not a native kernel syscall.
PNR_RETENTION_EXCEPTIONS = {"x86_64": frozenset(), "aarch64": frozenset({"poll"})}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_source(path: Path, expected_digest: str, label: str) -> None:
    actual_digest = sha256(path)
    if actual_digest != expected_digest:
        raise ValueError(
            f"{label} is not the pinned source: expected {expected_digest}, "
            f"found {actual_digest}"
        )


def parse_systemd_groups(source: str) -> dict[str, tuple[str, ...]]:
    group_pattern = re.compile(
        r'\.name\s*=\s*"(?P<name>@[^"]+)"\s*,.*?'
        r"\.value\s*=\s*(?P<value>.*?)\n\s*},",
        re.DOTALL,
    )
    value_pattern = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)\\0"')
    groups = {
        match.group("name"): tuple(value_pattern.findall(match.group("value")))
        for match in group_pattern.finditer(source)
    }
    if "@system-service" not in groups:
        raise ValueError("pinned systemd source has no @system-service group")
    return groups


def expand_group(
    name: str,
    groups: dict[str, tuple[str, ...]],
    ancestors: tuple[str, ...] = (),
) -> list[str]:
    if name in ancestors:
        raise ValueError(f"recursive systemd syscall group: {name}")
    try:
        members = groups[name]
    except KeyError as error:
        raise ValueError(f"unknown systemd syscall group: {name}") from error

    expanded: list[str] = []
    for member in members:
        if member.startswith("@"):
            expanded.extend(expand_group(member, groups, ancestors + (name,)))
        else:
            expanded.append(member)
    return expanded


def parse_libseccomp_interface(source: str) -> dict[str, dict[str, str]]:
    lines = source.splitlines()
    if not lines or not lines[0].startswith("#syscall"):
        raise ValueError("pinned libseccomp syscall table has no expected header")
    header = lines[0][1:].split(",")
    header[0] = "syscall"
    if len(set(header)) != len(header) or not set(ARCHITECTURES).issubset(header):
        raise ValueError("pinned libseccomp syscall table has invalid architecture columns")
    rows: dict[str, dict[str, str]] = {}
    for row in csv.reader(lines[1:]):
        if len(row) != len(header):
            raise ValueError("pinned libseccomp syscall table has a malformed row")
        fields = dict(zip(header, row, strict=True))
        if fields["syscall"] in rows:
            raise ValueError("pinned libseccomp syscall table has a duplicate syscall")
        rows[fields["syscall"]] = fields
    return rows


def target_names(
    expanded: set[str], interface: dict[str, dict[str, str]], architecture: str
) -> list[str]:
    if architecture not in ARCHITECTURES:
        raise ValueError(f"unsupported architecture: {architecture}")
    names = sorted(
        name
        for name in expanded
        if name in interface
        and (
            interface[name][architecture].isdecimal()
            or (
                interface[name][architecture] == "PNR"
                and name in PNR_RETENTION_EXCEPTIONS[architecture]
            )
        )
    )
    missing = sorted(REQUIRED_NAMES.difference(names))
    if missing:
        raise ValueError(f"{architecture} omits required syscalls: {', '.join(missing)}")
    if any(name.startswith("@") for name in names):
        raise ValueError(f"{architecture} retained a systemd syscall group")
    return names


def systemd_readback_names(
    requested: list[str],
    defaults: set[str],
    interface: dict[str, dict[str, str]],
    architecture: str,
) -> list[str]:
    # The pinned transient-unit setter inserts @default before the caller's
    # allow-list. Its parser and getter preserve resolvable PNR names, even
    # though those names are not native kernel rules on this architecture.
    implicit = {
        name
        for name in defaults
        if name in interface
        and (
            interface[name][architecture].isdecimal()
            or interface[name][architecture] == "PNR"
        )
    }
    return sorted(set(requested) | implicit)


def cbor_head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFF_FFFF:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def cbor_uint(value: int) -> bytes:
    return cbor_head(0, value)


def cbor_bytes(value: bytes) -> bytes:
    return cbor_head(2, len(value)) + value


def cbor_text(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return cbor_head(3, len(encoded)) + encoded


def cbor_array(values: list[bytes]) -> bytes:
    return cbor_head(4, len(values)) + b"".join(values)


def blake3(preimage: bytes) -> bytes:
    completed = subprocess.run(
        ["b3sum", "--raw"],
        input=preimage,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    if len(completed.stdout) != 32:
        raise ValueError("b3sum returned a non-256-bit digest")
    return completed.stdout


def materialize_record(
    architecture: str, requested: list[str], expected: list[str]
) -> tuple[bytes, bytes]:
    unsigned = cbor_array(
        [
            cbor_text("SCS1"),
            cbor_uint(1),
            cbor_uint(ARCHITECTURES[architecture]),
            cbor_array([cbor_text(name) for name in requested]),
            cbor_array([cbor_text(name) for name in expected]),
        ]
    )
    digest = blake3(SCS1_DOMAIN + unsigned)
    return cbor_array([unsigned, cbor_bytes(digest)]), digest


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def materialize(
    systemd_root: Path, libseccomp_archive: Path, output_root: Path, check: bool = False
) -> None:
    revision = subprocess.run(
        ["git", "-C", str(systemd_root), "rev-parse", "--verify", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout.strip()
    if revision != SYSTEMD_REVISION:
        raise ValueError(f"systemd revision is not pinned: found {revision}")
    systemd_source = systemd_root / "src/shared/seccomp-util.c"
    require_source(systemd_source, SYSTEMD_SECCOMP_SHA256, "systemd seccomp-util.c")
    require_source(
        libseccomp_archive, LIBSECCOMP_SOURCE_SHA256, "libseccomp source archive"
    )
    with tarfile.open(libseccomp_archive, "r:gz") as archive:
        source = archive.extractfile(f"libseccomp-{LIBSECCOMP_VERSION}/src/syscalls.csv")
        if source is None:
            raise ValueError("libseccomp archive has no regular syscall table")
        with source:
            syscall_bytes = source.read()
    if hashlib.sha256(syscall_bytes).hexdigest() != LIBSECCOMP_SYSCALLS_SHA256:
        raise ValueError("libseccomp syscalls.csv is not the pinned source")

    groups = parse_systemd_groups(systemd_source.read_text(encoding="utf-8"))
    expanded = set(expand_group("@system-service", groups))
    if len(expanded) != EXPECTED_EXPANDED_NAMES:
        raise ValueError(
            f"@system-service expanded to {len(expanded)} names; "
            f"expected {EXPECTED_EXPANDED_NAMES}"
        )
    interface = parse_libseccomp_interface(syscall_bytes.decode("utf-8"))
    defaults = set(expand_group("@default", groups))

    records = []
    outputs = {}
    for architecture in ARCHITECTURES:
        names = target_names(expanded, interface, architecture)
        expected_count = EXPECTED_REQUESTED_NAMES[architecture]
        if len(names) != expected_count:
            raise ValueError(
                f"{architecture} materialized {len(names)} names; expected {expected_count}"
            )
        readback = systemd_readback_names(names, defaults, interface, architecture)
        readback_count = EXPECTED_READBACK_NAMES[architecture]
        if len(readback) != readback_count:
            raise ValueError(
                f"{architecture} readback has {len(readback)} names; expected {readback_count}"
            )
        encoded, record_digest = materialize_record(architecture, names, readback)
        filename = f"systemd-v{SYSTEMD_VERSION}-{architecture}.scs1.cbor"
        outputs[filename] = encoded
        records.append(
            {
                "architecture": architecture,
                "byte_length": len(encoded),
                "file": filename,
                "record_blake3": blake3(encoded).hex(),
                "requested_count": len(names),
                "expected_effective_count": len(readback),
                "syscall_set_digest": record_digest.hex(),
            }
        )

    metadata = {
        "libseccomp": {
            "source_archive_sha256": LIBSECCOMP_SOURCE_SHA256,
            "syscalls_csv_sha256": LIBSECCOMP_SYSCALLS_SHA256,
            "version": LIBSECCOMP_VERSION,
        },
        "records": records,
        "systemd": {
            "revision": SYSTEMD_REVISION,
            "seccomp_util_sha256": SYSTEMD_SECCOMP_SHA256,
            "version": SYSTEMD_VERSION,
        },
    }
    outputs["manifest.json"] = (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode()
    if check:
        for filename, content in outputs.items():
            if (output_root / filename).read_bytes() != content:
                raise ValueError(f"checked-in output differs from pinned derivation: {filename}")
    else:
        for filename, content in outputs.items():
            atomic_write(output_root / filename, content)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--systemd-source", type=Path, required=True)
    parser.add_argument("--libseccomp-archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true", help="verify outputs without writing")
    arguments = parser.parse_args()
    materialize(
        arguments.systemd_source.resolve(),
        arguments.libseccomp_archive.resolve(),
        arguments.output.resolve(),
        arguments.check,
    )


if __name__ == "__main__":
    main()
