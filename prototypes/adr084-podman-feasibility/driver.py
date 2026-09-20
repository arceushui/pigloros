#!/usr/bin/env python3
"""Throwaway ADR-084 release-barrier driver; never production code."""

from __future__ import annotations

import argparse
import base64
import binascii
import concurrent.futures
import errno
import hashlib
import json
import os
import pathlib
import select
import signal
import socket
import subprocess
import struct
import sys
import time
import uuid
from dataclasses import dataclass

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ATTEMPT_DOMAIN = b"PiglorOS.EvaluatorAttemptStream.v1\0"
OBSERVATION_DOMAIN = b"PiglorOS.EvaluatorObservationStream.v1\0"
RUNTIME_KEY_ID = "prototype-runtime-key-01"
WATCHDOG_NS = 60_000_000_000
MISSING_RELEASE_SECONDS = 30


@dataclass(frozen=True)
class BarrierFixture:
    architecture: int
    ois_digest: bytes
    ort_digest: bytes
    launcher_digest: bytes
    adapter_digest: bytes


@dataclass(frozen=True)
class BarrierAttempt:
    attempt_id: bytes
    nonce: bytes
    lpv: list[object]
    lpv_digest: bytes
    context_packet: bytes
    launch_anchor_ns: int
    deadline_ns: int
    fdl_digest: bytes


def run(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, check=check, text=True, capture_output=True)


def blake3(value: bytes) -> bytes:
    result = subprocess.run(
        ["/usr/bin/b3sum", "--raw"], input=value, check=True, capture_output=True
    ).stdout
    if len(result) != 32:
        raise AssertionError("b3sum returned a non-256-bit digest")
    return result


def canonical(value: object) -> bytes:
    return cbor2.dumps(value, canonical=True)


def record_digest(domain: str, unsigned: list[object]) -> bytes:
    return blake3(domain.encode("ascii") + b"\0" + canonical(unsigned))


def fixture_digest(label: str) -> bytes:
    return blake3(b"PiglorOS.ADR084PrototypeIdentity.v1\0" + label.encode("ascii"))


def load_barrier_fixture(path: pathlib.Path, architecture: str) -> BarrierFixture:
    document = json.loads(path.read_text(encoding="utf-8"))
    unsigned_bytes = bytes.fromhex(document["ois1"]["unsigned_cbor_hex"])
    unsigned = cbor2.loads(unsigned_bytes)
    if canonical(unsigned) != unsigned_bytes:
        raise ValueError("runtime OIS1 is not canonical CBOR")
    expected_architecture = {"x86_64": 0, "aarch64": 1}[architecture]
    if (
        not isinstance(unsigned, list)
        or len(unsigned) != 17
        or unsigned[0:2] != ["OIS1", 1]
        or unsigned[3] != expected_architecture
    ):
        raise ValueError("runtime OIS1 shape or architecture mismatch")
    ois_digest = bytes.fromhex(document["ois1"]["self_digest_hex"])
    if record_digest("PiglorOS.OciImageSubject.v1", unsigned) != ois_digest:
        raise ValueError("runtime OIS1 self-digest mismatch")
    launcher = unsigned[9]
    adapter = unsigned[10]
    if (
        not isinstance(launcher, list)
        or len(launcher) != 6
        or launcher[0] != "/launcher"
        or not isinstance(adapter, list)
        or len(adapter) != 6
        or adapter[0] != "/adapter"
        or unsigned[11] != []
    ):
        raise ValueError("runtime OIS1 executable contract mismatch")
    return BarrierFixture(
        architecture=expected_architecture,
        ois_digest=ois_digest,
        ort_digest=bytes.fromhex(document["ort1"]["self_digest_hex"]),
        launcher_digest=launcher[2],
        adapter_digest=adapter[2],
    )


def prepare_barrier_attempt(
    fixture: BarrierFixture, artifact_dir: pathlib.Path, scenario: str
) -> BarrierAttempt:
    attempt_id = uuid.uuid4().bytes
    nonce = os.urandom(32)
    fdl_unsigned = ["FDL1", 1, 1, [[3, 1]]]
    fdl_digest = record_digest("PiglorOS.FDL1.v1", fdl_unsigned)
    lpv_unsigned = [
        "LPV2",
        2,
        attempt_id,
        nonce,
        fixture.ois_digest,
        "/adapter",
        [],
        fdl_digest,
    ]
    lpv_digest = record_digest("PiglorOS.LPV2.v2", lpv_unsigned)
    lpv = [lpv_unsigned, lpv_digest]
    context = [
        "PBC1",
        1,
        lpv,
        fixture.ort_digest,
        fixture.launcher_digest,
        fixture.adapter_digest,
    ]
    anchor = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    deadline = anchor + WATCHDOG_NS
    state = {
        "attempt_id": attempt_id.hex(),
        "deadline_ns": deadline,
        "expected_fdl1_digest": fdl_digest.hex(),
        "launch_anchor_monotonic_ns": anchor,
        "lpv2_digest": lpv_digest.hex(),
        "nonce": nonce.hex(),
        "scenario": scenario,
        "state": "LauncherStarting",
    }
    context_packet = canonical(context)
    (artifact_dir / f"{scenario}.launch-context.cbor").write_bytes(context_packet)
    state_path = artifact_dir / f"{scenario}.launcher-starting.json"
    with state_path.open("w", encoding="utf-8") as stream:
        json.dump(state, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    directory_fd = os.open(artifact_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return BarrierAttempt(
        attempt_id=attempt_id,
        nonce=nonce,
        lpv=lpv,
        lpv_digest=lpv_digest,
        context_packet=context_packet,
        launch_anchor_ns=anchor,
        deadline_ns=deadline,
        fdl_digest=fdl_digest,
    )


def validate_ready(
    packet: bytes, attempt: BarrierAttempt, fixture: BarrierFixture
) -> tuple[list[object], bytes]:
    record = cbor2.loads(packet)
    if canonical(record) != packet or not isinstance(record, list) or len(record) != 2:
        raise ValueError("ReadyV2 is not one exact canonical record")
    unsigned, self_digest = record
    if (
        not isinstance(unsigned, list)
        or len(unsigned) != 14
        or unsigned[0:2] != ["RDY2", 2]
        or not isinstance(self_digest, bytes)
        or len(self_digest) != 32
        or record_digest("PiglorOS.RDY2.v2", unsigned) != self_digest
    ):
        raise ValueError("ReadyV2 shape or self-digest mismatch")
    expected = {
        2: attempt.attempt_id,
        3: attempt.nonce,
        5: fixture.launcher_digest,
        7: fixture.ois_digest,
        8: fixture.ort_digest,
        9: fixture.adapter_digest,
        11: attempt.lpv_digest,
        12: attempt.fdl_digest,
        13: attempt.fdl_digest,
    }
    for index, value in expected.items():
        if unsigned[index] != value:
            raise ValueError(f"ReadyV2 equality mismatch at ordinal {index}")
    for index in (4, 6, 10):
        identity = unsigned[index]
        if (
            not isinstance(identity, list)
            or len(identity) != 2
            or any(not isinstance(value, int) or value < 0 for value in identity)
        ):
            raise ValueError(f"ReadyV2 identity mismatch at ordinal {index}")
    return unsigned, self_digest


def build_rbs2(fixture: BarrierFixture, fdl_digest: bytes) -> tuple[list[object], bytes]:
    features = sorted(
        [
            "broker-lifecycle",
            "cgroup-kill",
            "cgroup-v2-cpu",
            "cgroup-v2-memory",
            "cgroup-v2-pids",
            "ipc-namespace",
            "limit-observation",
            "managed-attempt-exec",
            "mount-namespace",
            "network-namespace",
            "nftables-atomic",
            "pid-namespace",
            "process-isolation-controls",
            "signed-root-image",
            "user-namespace",
            "uts-namespace",
        ],
        key=canonical,
    )
    unsigned = [
        "RBS2",
        2,
        0,
        "podman-rootless",
        fixture_digest("spm1"),
        fixture_digest("provider-binary"),
        fixture_digest("provider-public-contract"),
        fixture_digest("hcp1"),
        fixture.architecture,
        RUNTIME_KEY_ID,
        ["pigloros.sandbox.air-gapped", 1, 1],
        1,
        fixture_digest("lps2"),
        fixture.ois_digest,
        fixture_digest("scs1"),
        fixture_digest("elm2"),
        fdl_digest,
        features,
        [],
    ]
    return unsigned, record_digest("PiglorOS.SandboxReadbackSet.v2", unsigned)


def build_and_verify_release(
    ready_digest: bytes, attempt: BarrierAttempt, fixture: BarrierFixture
) -> tuple[bytes, list[object], bytes]:
    _, rbs_digest = build_rbs2(fixture, attempt.fdl_digest)
    unsigned = [
        "RLS2",
        2,
        attempt.attempt_id,
        attempt.nonce,
        ready_digest,
        fixture_digest("trs1"),
        fixture_digest("rvs2"),
        fixture_digest("apt2"),
        1,
        1,
        1,
        rbs_digest,
        rbs_digest,
        attempt.launch_anchor_ns,
        attempt.deadline_ns,
        RUNTIME_KEY_ID,
    ]
    self_digest = record_digest("PiglorOS.RLS2.v2", unsigned)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    signature = key.sign(b"PiglorOS.RLS2.Signature.v2\0" + self_digest)
    packet = canonical([unsigned, self_digest, signature])

    decoded = cbor2.loads(packet)
    if canonical(decoded) != packet or decoded != [unsigned, self_digest, signature]:
        raise ValueError("ReleaseV2 independent canonical verification failed")
    if (
        record_digest("PiglorOS.RLS2.v2", decoded[0]) != decoded[1]
        or unsigned[2:5] != [attempt.attempt_id, attempt.nonce, ready_digest]
        or unsigned[11] != unsigned[12]
        or unsigned[13] != attempt.launch_anchor_ns
        or unsigned[14] != attempt.launch_anchor_ns + WATCHDOG_NS
        or unsigned[13] >= unsigned[14]
        or time.clock_gettime_ns(time.CLOCK_MONOTONIC) >= unsigned[14]
        or unsigned[15] != RUNTIME_KEY_ID
    ):
        raise ValueError("ReleaseV2 independent equality verification failed")
    try:
        key.public_key().verify(
            decoded[2], b"PiglorOS.RLS2.Signature.v2\0" + decoded[1]
        )
    except InvalidSignature as error:
        raise ValueError("ReleaseV2 independent signature verification failed") from error
    return packet, unsigned, self_digest


def signed_release_packet(unsigned: list[object]) -> bytes:
    self_digest = record_digest("PiglorOS.RLS2.v2", unsigned)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    signature = key.sign(b"PiglorOS.RLS2.Signature.v2\0" + self_digest)
    return canonical([unsigned, self_digest, signature])


def mutate_release_packet(label: str, packet: bytes) -> bytes:
    decoded = cbor2.loads(packet)
    unsigned = list(decoded[0])
    if label == "noncanonical-record-length":
        if packet[0] != 0x83:
            raise AssertionError("unexpected canonical ReleaseV2 array head")
        return b"\x98\x03" + packet[1:]
    if label == "trailing-byte":
        return packet + b"\x00"
    if label == "wrong-self-digest":
        changed = bytearray(decoded[1])
        changed[0] ^= 1
        return canonical([decoded[0], bytes(changed), decoded[2]])
    if label in {"wrong-attempt", "wrong-nonce", "wrong-ready-binding"}:
        ordinal = {"wrong-attempt": 2, "wrong-nonce": 3, "wrong-ready-binding": 4}[
            label
        ]
        changed = bytearray(unsigned[ordinal])
        changed[0] ^= 1
        unsigned[ordinal] = bytes(changed)
        return signed_release_packet(unsigned)
    if label == "invalid-anchor-order":
        unsigned[14] = unsigned[13]
        return signed_release_packet(unsigned)
    if label == "expired":
        unsigned[13] = 0
        unsigned[14] = 1
        return signed_release_packet(unsigned)
    if label == "invalid-runtime-key-utf8":
        unsigned_bytes = canonical(unsigned)
        encoded_key = canonical(RUNTIME_KEY_ID)
        if unsigned_bytes.count(encoded_key) != 1:
            raise AssertionError("runtime key is not unique in ReleaseV2")
        malformed_key = bytearray(encoded_key)
        malformed_key[-1] = 0xFF
        malformed_unsigned = unsigned_bytes.replace(encoded_key, bytes(malformed_key))
        self_digest = blake3(b"PiglorOS.RLS2.v2\0" + malformed_unsigned)
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        signature = key.sign(b"PiglorOS.RLS2.Signature.v2\0" + self_digest)
        return b"\x83" + malformed_unsigned + canonical(self_digest) + canonical(signature)
    raise ValueError(f"unknown ReleaseV2 mutation: {label}")


def transport_frames(stream: bytes) -> list[tuple[bytes, object]]:
    frames: list[tuple[bytes, object]] = []
    offset = 0
    while offset < len(stream):
        if len(stream) - offset < 4:
            raise ValueError("truncated transport frame prefix")
        length = int.from_bytes(stream[offset : offset + 4], "big")
        if length == 0 or length > 128 * 1024:
            raise ValueError("transport frame length is out of bounds")
        end = offset + 4 + length
        if end > len(stream):
            raise ValueError("truncated transport frame")
        framed = stream[offset:end]
        encoded = framed[4:]
        value = cbor2.loads(encoded)
        if cbor2.dumps(value, canonical=True) != encoded:
            raise ValueError("transport frame is not canonical CBOR")
        frames.append((framed, value))
        offset = end
    return frames


def validate_eai1(stream: bytes, expected_payload: bytes) -> dict[str, object]:
    frames = transport_frames(stream)
    values = [value for _, value in frames]
    if len(values) != 6:
        raise ValueError("unexpected EAI1 frame count")
    header = values[0]
    expected_header = [
        "EAI1",
        1,
        "adr084-probe",
        0,
        0,
        0,
        blake3(b"adr084-fixture"),
        [67108864, 1000, 1000, 1000, 65536, 65536, 1000, 1000000000],
        1000,
        False,
        0,
        2,
        65536,
        131072,
    ]
    if header != expected_header:
        raise ValueError("invalid EAI1 header")
    artifacts = ((0, b"opaque-schema-v1"), (1, expected_payload))
    for artifact_index, (role, expected) in enumerate(artifacts):
        member = values[1 + artifact_index * 2]
        chunk = values[2 + artifact_index * 2]
        if member != ["EIM1", 1, role, 0, len(expected), blake3(expected), 1]:
            raise ValueError("invalid EAI1 member header")
        if chunk != ["EIB1", 1, role, 0, 0, expected]:
            raise ValueError("invalid EAI1 member chunk")
    transcript = blake3(ATTEMPT_DOMAIN + b"".join(frame for frame, _ in frames[:-1]))
    if values[-1] != ["EIE1", 1, transcript]:
        raise ValueError("invalid EAI1 transcript")
    return {
        "bytes": len(stream),
        "frames": len(frames),
        "payload_sha256": hashlib.sha256(expected_payload).hexdigest(),
        "transcript_blake3": transcript.hex(),
    }


def validate_eao1(stream: bytes, expected_output: bytes) -> dict[str, object]:
    frames = transport_frames(stream)
    values = [value for _, value in frames]
    if len(values) != 3 or values[:2] != [["EAO1", 1], ["EOB1", 1, 0, expected_output]]:
        raise ValueError("invalid EAO1 start/output frames")
    transcript = blake3(
        OBSERVATION_DOMAIN + b"".join(frame for frame, _ in frames[:-1])
    )
    terminal = [
        "EOE1", 1, 0, len(expected_output), blake3(expected_output), None, None,
        [0] * 8, transcript,
    ]
    if values[-1] != terminal:
        raise ValueError("invalid EAO1 terminal/transcript")
    return {
        "bytes": len(stream),
        "frames": len(frames),
        "output_sha256": hashlib.sha256(expected_output).hexdigest(),
        "transcript_blake3": transcript.hex(),
    }


def wait_for_container(name: str, process: subprocess.Popen[bytes]) -> str:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        inspected = run("/usr/bin/podman", "inspect", name, check=False)
        if inspected.returncode == 0:
            value = json.loads(inspected.stdout)
            if len(value) == 1 and value[0].get("Id"):
                return str(value[0]["Id"])
        if process.poll() is not None:
            stderr = process.stderr.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"podman exited before identity acquisition: {process.returncode}: {stderr}"
            )
        time.sleep(0.05)
    raise TimeoutError("container identity was not acquired through provider-owned name")


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        return f"UNAVAILABLE: {error}\n"


def parse_cgroup_events(value: str) -> dict[str, int]:
    events: dict[str, int] = {}
    for line in value.splitlines():
        fields = line.split()
        if len(fields) != 2 or fields[0] in events:
            raise ValueError(f"invalid cgroup event record: {line!r}")
        count = int(fields[1])
        if count < 0:
            raise ValueError(f"negative cgroup event counter: {line!r}")
        events[fields[0]] = count
    if not events:
        raise ValueError("empty cgroup event record")
    return events


def process_snapshot(pid: int) -> dict[str, object]:
    proc = pathlib.Path("/proc") / str(pid)
    descriptors: list[dict[str, object]] = []
    descriptor_access_error: str | None = None
    try:
        descriptor_entries = sorted(
            (proc / "fd").iterdir(), key=lambda item: int(item.name)
        )
    except OSError as error:
        descriptor_entries = []
        descriptor_access_error = f"UNAVAILABLE: {error}"
    for entry in descriptor_entries:
        try:
            target = os.readlink(entry)
        except OSError as error:
            target = f"UNAVAILABLE: {error}"
        descriptors.append({"fd": int(entry.name), "target": target})
    namespaces: dict[str, str] = {}
    namespace_access_error: str | None = None
    try:
        namespace_entries = sorted((proc / "ns").iterdir())
    except OSError as error:
        namespace_entries = []
        namespace_access_error = f"UNAVAILABLE: {error}"
    for entry in namespace_entries:
        try:
            namespaces[entry.name] = os.readlink(entry)
        except OSError as error:
            namespaces[entry.name] = f"UNAVAILABLE: {error}"
    cgroup_text = read_text(proc / "cgroup")
    unified = next(
        (line.split("::", 1)[1] for line in cgroup_text.splitlines() if "::" in line),
        "",
    )
    cgroup_root = pathlib.Path("/sys/fs/cgroup") / unified.lstrip("/")
    cgroup_values = {
        name: read_text(cgroup_root / name).strip()
        for name in (
            "cgroup.controllers",
            "cgroup.events",
            "cgroup.procs",
            "cpu.max",
            "cpu.stat",
            "memory.max",
            "memory.events.local",
            "memory.swap.max",
            "memory.swap.events",
            "pids.max",
            "pids.events",
            "pids.events.local",
        )
    }
    cgroup_values["cgroup.kill_exists"] = str((cgroup_root / "cgroup.kill").exists())
    return {
        "pid": pid,
        "status": read_text(proc / "status"),
        "limits": read_text(proc / "limits"),
        "cgroup": cgroup_text,
        "cgroup_path": str(cgroup_root),
        "cgroup_values": cgroup_values,
        "descriptor_access_error": descriptor_access_error,
        "descriptors": descriptors,
        "mountinfo": read_text(proc / "mountinfo"),
        "namespace_access_error": namespace_access_error,
        "namespaces": namespaces,
    }


def assert_launcher_snapshot(
    snapshot: dict[str, object], expected_filter_count: int = 1
) -> None:
    status = str(snapshot["status"])
    required_status = (
        "NoNewPrivs:\t1",
        "Seccomp:\t2",
        f"Seccomp_filters:\t{expected_filter_count}",
        "CapEff:\t0000000000000000",
    )
    for expected in required_status:
        if expected not in status:
            raise AssertionError(f"missing launcher status evidence: {expected}")
    descriptor_numbers = [entry["fd"] for entry in snapshot["descriptors"]]  # type: ignore[index]
    if descriptor_numbers and descriptor_numbers != [0, 1, 2, 3]:
        raise AssertionError(f"launcher descriptor set is not 0..3: {descriptor_numbers}")
    if not descriptor_numbers and "Permission denied" not in str(snapshot["descriptor_access_error"]):
        raise AssertionError("launcher descriptor evidence was unavailable for an unknown reason")
    values = snapshot["cgroup_values"]  # type: ignore[assignment]
    if values["memory.max"] != "67108864":  # type: ignore[index]
        raise AssertionError(f"memory.max not enforced: {values['memory.max']}")  # type: ignore[index]
    if values["memory.swap.max"] != "0":  # type: ignore[index]
        raise AssertionError(f"memory.swap.max not enforced: {values['memory.swap.max']}")  # type: ignore[index]
    if values["pids.max"] != "16":  # type: ignore[index]
        raise AssertionError(f"pids.max not enforced: {values['pids.max']}")  # type: ignore[index]
    if not str(values["cpu.max"]).startswith("50000 100000"):  # type: ignore[index]
        raise AssertionError(f"cpu.max not enforced: {values['cpu.max']}")  # type: ignore[index]
    limits = str(snapshot["limits"])
    nofile = next(
        (line.split() for line in limits.splitlines() if line.startswith("Max open files")),
        None,
    )
    if nofile is None or nofile[-3:] != ["64", "64", "files"]:
        raise AssertionError(f"RLIMIT_NOFILE not enforced: {nofile}")
    fsize = next(
        (line.split() for line in limits.splitlines() if line.startswith("Max file size")),
        None,
    )
    if fsize is None or fsize[-3:] != ["32768", "32768", "bytes"]:
        raise AssertionError(f"RLIMIT_FSIZE not enforced: {fsize}")
    root_mounts = [
        line for line in str(snapshot["mountinfo"]).splitlines() if " / / " in line
    ]
    if len(root_mounts) != 1 or " ro," not in root_mounts[0]:
        raise AssertionError(f"container root is not uniquely read-only: {root_mounts}")
    work_mounts = [
        line for line in str(snapshot["mountinfo"]).splitlines() if " /work " in line
    ]
    if (
        len(work_mounts) != 1
        or " /work rw,nosuid,nodev,noexec" not in work_mounts[0]
        or " - tmpfs tmpfs rw,size=64k" not in work_mounts[0]
    ):
        raise AssertionError(f"/work is not the exact bounded tmpfs: {work_mounts}")


def expected_runtime_annotations(
    seccomp: pathlib.Path, seccomp_bpf_base64: str
) -> dict[str, str]:
    return {
        "io.container.manager": "libpod",
        "io.podman.annotations.seccomp": str(seccomp),
        "org.opencontainers.image.stopSignal": "15",
        "run.oci.seccomp_bpf_data": seccomp_bpf_base64,
    }


def validate_runtime_annotations(
    annotations: object, seccomp: pathlib.Path, seccomp_bpf_base64: str
) -> None:
    expected = expected_runtime_annotations(seccomp, seccomp_bpf_base64)
    if annotations != expected:
        raise ValueError(f"effective runtime annotations differ: {annotations!r}")


def validate_bpf_annotation(value: str, expected_bpf: bytes) -> None:
    if not value or any(character.isspace() for character in value):
        raise ValueError("seccomp BPF base64 is empty or contains whitespace")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("seccomp BPF base64 is malformed") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("seccomp BPF base64 is not canonical padded RFC 4648")
    if decoded != expected_bpf:
        raise ValueError("seccomp BPF annotation differs from exported bytes")


def validate_launch_arguments(
    annotations: list[str],
    seccomp_profiles: list[str],
    stop_signals: list[str],
    expected_annotation: str,
    expected_profile: str,
) -> None:
    if annotations != [expected_annotation]:
        raise ValueError("launch requires exactly one exact BPF annotation argument")
    if seccomp_profiles != [expected_profile]:
        raise ValueError("launch requires exactly one descriptor-resolved seccomp profile")
    if stop_signals != ["15"]:
        raise ValueError("launch requires exactly one decimal stop signal 15")


def annotation_mutation_report(
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
) -> dict[str, object]:
    expected_bpf = seccomp_bpf.read_bytes()
    expected = expected_runtime_annotations(seccomp, seccomp_bpf_base64)
    rejected: list[str] = []

    def rejects(action, label: str) -> None:
        try:
            action()
        except ValueError:
            rejected.append(label)
            return
        raise AssertionError(f"annotation mutation was accepted: {label}")

    for key in expected:
        missing = {name: value for name, value in expected.items() if name != key}
        rejects(
            lambda candidate=missing: validate_runtime_annotations(
                candidate, seccomp, seccomp_bpf_base64
            ),
            f"missing effective map member: {key}",
        )
        wrong = {**expected, key: expected[key] + ".mutated"}
        rejects(
            lambda candidate=wrong: validate_runtime_annotations(
                candidate, seccomp, seccomp_bpf_base64
            ),
            f"wrong effective map value: {key}",
        )
    for label, key in (
        ("configured-default injection", "io.containers.default.annotation"),
        ("caller annotation injection", "org.pigloros.caller"),
        ("image annotation forwarding", "org.opencontainers.image.title"),
        ("arbitrary extra annotation", "fixture.extra"),
        ("security-affecting run.oci annotation", "run.oci.hooks"),
        ("systemd annotation injection", "org.systemd.property.DeviceAllow"),
    ):
        injected = {**expected, key: "mutated"}
        rejects(
            lambda candidate=injected: validate_runtime_annotations(
                candidate, seccomp, seccomp_bpf_base64
            ),
            label,
        )

    annotation_argument = f"run.oci.seccomp_bpf_data={seccomp_bpf_base64}"
    profile_argument = f"seccomp={seccomp}"
    launch_cases = (
        ("missing BPF annotation argument", [], [profile_argument], ["15"]),
        (
            "duplicate BPF annotation argument",
            [annotation_argument, annotation_argument],
            [profile_argument],
            ["15"],
        ),
        ("missing seccomp profile argument", [annotation_argument], [], ["15"]),
        (
            "duplicate seccomp profile argument",
            [annotation_argument],
            [profile_argument, profile_argument],
            ["15"],
        ),
        ("missing stop signal argument", [annotation_argument], [profile_argument], []),
        (
            "duplicate stop signal argument",
            [annotation_argument],
            [profile_argument],
            ["15", "15"],
        ),
        ("wrong stop signal argument", [annotation_argument], [profile_argument], ["9"]),
    )
    for label, annotations, profiles, stop_signals in launch_cases:
        rejects(
            lambda a=annotations, p=profiles, s=stop_signals: validate_launch_arguments(
                a, p, s, annotation_argument, profile_argument
            ),
            label,
        )

    changed_first = (
        ("A" if seccomp_bpf_base64[0] != "A" else "B")
        + seccomp_bpf_base64[1:]
    )
    bpf_cases = (
        ("empty BPF base64", ""),
        ("BPF base64 whitespace", seccomp_bpf_base64 + "\n"),
        ("BPF base64 invalid alphabet", "*" + seccomp_bpf_base64[1:]),
        ("BPF base64 truncation", seccomp_bpf_base64[:-1]),
        ("BPF base64 byte mutation", changed_first),
    )
    for label, candidate in bpf_cases:
        rejects(
            lambda value=candidate: validate_bpf_annotation(value, expected_bpf),
            label,
        )
    if len(rejected) != 26:
        raise AssertionError(f"annotation mutation matrix is incomplete: {len(rejected)}")
    return {"rejected": rejected, "rejected_count": len(rejected), "verdict": "passed"}


def launch(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
    barrier_fixture: BarrierFixture,
    input_bytes: bytes,
    scenario: str,
    prefilter: pathlib.Path | None = None,
    expected_filter_count: int = 1,
    release: bool = True,
    containers_conf: pathlib.Path | None = None,
    expect_annotation_rejection: str | None = None,
    release_mutation: str | None = None,
    release_gate: tuple[pathlib.Path, pathlib.Path] | None = None,
    trace_seccomp_install: bool = True,
) -> tuple[subprocess.Popen[bytes], socket.socket, str] | None:
    parent_control, child_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    if parent_control.fileno() == 3:
        relocated_parent = socket.socket(fileno=os.dup(parent_control.fileno()))
        parent_control.close()
        parent_control = relocated_parent
    child_fd = child_control.fileno()
    child_control.set_inheritable(True)
    name = f"pigloros-adr084-{scenario}-{uuid.uuid4().hex[:12]}"
    barrier_attempt = prepare_barrier_attempt(barrier_fixture, artifact_dir, scenario)
    if parent_control.send(barrier_attempt.context_packet) != len(
        barrier_attempt.context_packet
    ):
        raise RuntimeError("provider-private launch context was not sent atomically")
    annotation_argument = f"run.oci.seccomp_bpf_data={seccomp_bpf_base64}"
    profile_argument = f"seccomp={seccomp}"
    validate_launch_arguments(
        [annotation_argument],
        [profile_argument],
        ["15"],
        annotation_argument,
        profile_argument,
    )
    podman_command = [
        "/usr/bin/podman",
        "run",
        "--runtime=/usr/bin/crun",
        "--pull=never",
        f"--name={name}",
        "--preserve-fds=1",
        "--network=none",
        "--no-hosts",
        "--hostname=pigloros-adapter",
        "--read-only",
        "--read-only-tmpfs=false",
        "--tmpfs=/work:rw,nosuid,nodev,noexec,size=65536",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        f"--security-opt={profile_argument}",
        f"--annotation={annotation_argument}",
        "--stop-signal=15",
        "--memory=64m",
        "--memory-swap=64m",
        "--pids-limit=16",
        "--cpus=0.5",
        "--ulimit=nofile=64:64",
        "--ulimit=fsize=32768:32768",
        "--user=65532:65532",
        "--label=io.pigloros.prototype=adr084",
        f"--label=io.pigloros.scenario={scenario}",
        "--rm=false",
        "-i",
        image,
    ]
    installed_bpf = artifact_dir / f"{scenario}.installed-seccomp.bpf"
    install_report = artifact_dir / f"{scenario}.seccomp-install.json"
    traced_command = (
        [str(prefilter), *podman_command] if prefilter is not None else podman_command
    )
    command = (
        [
            str(seccomp_tracer),
            str(seccomp_bpf),
            str(installed_bpf),
            str(install_report),
            "--",
            *traced_command,
        ]
        if trace_seccomp_install
        else traced_command
    )

    saved_fd3: int | None = None
    if child_fd != 3:
        try:
            saved_fd3 = os.dup(3)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
        os.dup2(child_fd, 3, inheritable=True)
    try:
        process_environment = os.environ.copy()
        if containers_conf is not None:
            process_environment["CONTAINERS_CONF"] = str(containers_conf)
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(3,),
            env=process_environment,
        )
    finally:
        if child_fd != 3:
            os.close(3)
            if saved_fd3 is not None:
                os.dup2(saved_fd3, 3)
                os.close(saved_fd3)
    child_control.close()
    container_id = wait_for_container(name, process)
    try:
        ready = parent_control.recv(4096)
    except ConnectionResetError:
        ready = b""
    try:
        ready_unsigned, ready_digest = validate_ready(
            ready, barrier_attempt, barrier_fixture
        )
    except (TypeError, ValueError, cbor2.CBORDecodeError) as ready_error:
        return_code = process.wait(timeout=10)
        stderr = process.stderr.read().decode("utf-8", errors="replace")
        (artifact_dir / f"{scenario}.pre-ready.stderr").write_text(
            stderr, encoding="utf-8"
        )
        if expect_annotation_rejection is not None:
            assert process.stdout is not None
            output = process.stdout.read()
            inspected = json.loads(
                run("/usr/bin/podman", "inspect", container_id).stdout
            )[0]
            annotations = inspected["Config"]["Annotations"]
            expected_key, separator, expected_value = (
                expect_annotation_rejection.partition("=")
            )
            run("/usr/bin/podman", "rm", "--force", container_id)
            parent_control.close()
            if (
                separator != "="
                or annotations.get(expected_key) != expected_value
                or output
                or "OCI runtime error" not in stderr
            ):
                raise AssertionError(
                    "configured security default did not fail closed before start: "
                    f"annotations={annotations!r} output={output!r} stderr={stderr!r}"
                )
            (artifact_dir / f"{scenario}.stdout").write_bytes(output)
            (artifact_dir / f"{scenario}.stderr").write_text(
                stderr, encoding="utf-8"
            )
            (artifact_dir / f"{scenario}.json").write_text(
                json.dumps(
                    {
                        "actual_annotations": annotations,
                        "injection": expect_annotation_rejection,
                        "launcher_ready": False,
                        "release_sent": False,
                        "return_code": return_code,
                        "verdict": "configured security default rejected by crun before start",
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            return None
        raise AssertionError(
            f"unexpected launcher readiness: {ready.hex()}; "
            f"exit={return_code}; stderr={stderr!r}; error={ready_error}"
        ) from ready_error
    (artifact_dir / f"{scenario}.ready2.cbor").write_bytes(ready)
    readable, _, _ = select.select([process.stdout], [], [], 0.2)
    if readable:
        premature = process.stdout.read1(64)
        raise AssertionError(f"adapter emitted before ReleaseV2: {premature!r}")
    inspect = run("/usr/bin/podman", "inspect", container_id).stdout
    (artifact_dir / f"{scenario}.inspect.json").write_text(inspect, encoding="utf-8")
    inspected = json.loads(inspect)[0]
    annotations = inspected["Config"]["Annotations"]
    (artifact_dir / f"{scenario}.runtime-annotations.json").write_text(
        json.dumps(annotations, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    annotation_error: ValueError | None = None
    try:
        validate_runtime_annotations(annotations, seccomp, seccomp_bpf_base64)
    except ValueError as error:
        annotation_error = error
    if expect_annotation_rejection is not None:
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        process.stdin.close()
        run("/usr/bin/podman", "kill", "--signal=KILL", container_id, check=False)
        return_code = process.wait(timeout=20)
        parent_control.close()
        output = process.stdout.read()
        errors = process.stderr.read()
        run("/usr/bin/podman", "rm", "--force", container_id)
        expected_key, separator, expected_value = (
            expect_annotation_rejection.partition("=")
        )
        if (
            separator != "="
            or annotations.get(expected_key) != expected_value
            or annotation_error is None
            or output
        ):
            raise AssertionError(
                f"runtime annotation injection was not rejected: {annotations!r}"
            )
        (artifact_dir / f"{scenario}.stdout").write_bytes(output)
        (artifact_dir / f"{scenario}.stderr").write_bytes(errors)
        (artifact_dir / f"{scenario}.json").write_text(
            json.dumps(
                {
                    "actual_annotations": annotations,
                    "injection": expect_annotation_rejection,
                    "launcher_ready": True,
                    "release_sent": False,
                    "return_code": return_code,
                    "validation_error": str(annotation_error),
                    "verdict": "configured default rejected before release",
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return None
    if annotation_error is not None:
        raise annotation_error
    pid = int(inspected["State"]["Pid"])
    snapshot = process_snapshot(pid)
    assert_launcher_snapshot(snapshot, expected_filter_count)
    (artifact_dir / f"{scenario}.launcher.json").write_text(
        json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if release_gate is not None:
        observed_path, release_path = release_gate
        observed_path.write_text(
            json.dumps(
                {
                    "container_id": container_id,
                    "launcher_pid": pid,
                    "monotonic_ns": time.clock_gettime_ns(time.CLOCK_MONOTONIC),
                    "scenario": scenario,
                    "state": "Observed",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        gate_deadline = time.monotonic() + 60
        while not release_path.exists() and time.monotonic() < gate_deadline:
            time.sleep(0.005)
        if not release_path.exists():
            raise TimeoutError(f"release gate did not open for {scenario}")
    if release:
        release_packet, release_unsigned, release_digest = build_and_verify_release(
            ready_digest, barrier_attempt, barrier_fixture
        )
        sent_packet = (
            mutate_release_packet(release_mutation, release_packet)
            if release_mutation is not None
            else release_packet
        )
        if parent_control.send(sent_packet) != len(sent_packet):
            raise RuntimeError("ReleaseV2 was not sent atomically")
        release_sent_monotonic_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        (artifact_dir / f"{scenario}.release2.cbor").write_bytes(sent_packet)
        (artifact_dir / f"{scenario}.release-barrier.json").write_text(
            json.dumps(
                {
                    "attempt_id": barrier_attempt.attempt_id.hex(),
                    "context_packet_sha256": hashlib.sha256(
                        barrier_attempt.context_packet
                    ).hexdigest(),
                    "deadline_ns": release_unsigned[14],
                    "launch_anchor_monotonic_ns": release_unsigned[13],
                    "lpv2_digest": barrier_attempt.lpv_digest.hex(),
                    "ready2_digest": ready_digest.hex(),
                    "ready2_mount_namespace": ready_unsigned[4],
                    "base_release2_digest": release_digest.hex(),
                    "release2_digest": (
                        release_digest.hex() if release_mutation is None else None
                    ),
                    "release_mutation": release_mutation,
                    "base_release_signature_verified_before_conformance_injection": True,
                    "release_signature_verified_before_send": release_mutation is None,
                    "runtime_key_id": release_unsigned[15],
                    "release_sent_monotonic_ns": release_sent_monotonic_ns,
                    "sent_packet_sha256": hashlib.sha256(sent_packet).hexdigest(),
                    "verdict": (
                        "canonical signed ReleaseV2 sent only after ReadyV2 and observations"
                        if release_mutation is None
                        else "conformance-injected ReleaseV2 sent after valid base verification"
                    ),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        assert process.stdin is not None
        process.stdin.write(input_bytes)
        process.stdin.flush()
    return process, parent_control, container_id


def release_rejection_scenarios(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
    barrier_fixture: BarrierFixture,
) -> None:
    mutations = {
        "noncanonical-record-length": b"cbor-noncanonical-integer",
        "trailing-byte": b"release-trailing",
        "wrong-self-digest": b"release-self-digest",
        "wrong-attempt": b"release-attempt",
        "wrong-nonce": b"release-nonce",
        "wrong-ready-binding": b"release-ready",
        "invalid-anchor-order": b"release-expired",
        "expired": b"release-expired",
        "invalid-runtime-key-utf8": b"cbor-text-utf8",
    }
    observations = []
    for mutation, expected_error in mutations.items():
        scenario = f"release-reject-{mutation}"
        process, control, container_id = launch(
            image,
            seccomp,
            seccomp_bpf_base64,
            seccomp_bpf,
            seccomp_tracer,
            artifact_dir,
            barrier_fixture,
            b"",
            scenario,
            release_mutation=mutation,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        process.stdin.close()
        return_code = process.wait(timeout=20)
        output = process.stdout.read()
        errors = process.stderr.read()
        control.close()
        run("/usr/bin/podman", "rm", "--force", container_id)
        (artifact_dir / f"{scenario}.stdout").write_bytes(output)
        (artifact_dir / f"{scenario}.stderr").write_bytes(errors)
        if return_code == 0 or output or expected_error not in errors:
            raise AssertionError(
                f"launcher accepted ReleaseV2 mutation {mutation}: "
                f"code={return_code} output={output!r} stderr={errors!r}"
            )
        observations.append(
            {
                "mutation": mutation,
                "return_code": return_code,
                "expected_error": expected_error.decode("ascii"),
                "stderr": errors.decode("utf-8", errors="replace").strip(),
            }
        )

    for scenario, close_control, timeout in (
        ("release-reject-revoked", True, 20),
        ("release-reject-missing", False, MISSING_RELEASE_SECONDS + 10),
    ):
        process, control, container_id = launch(
            image,
            seccomp,
            seccomp_bpf_base64,
            seccomp_bpf,
            seccomp_tracer,
            artifact_dir,
            barrier_fixture,
            b"",
            scenario,
            release=False,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        process.stdin.close()
        if close_control:
            control.close()
        return_code = process.wait(timeout=timeout)
        output = process.stdout.read()
        errors = process.stderr.read()
        if not close_control:
            control.close()
        run("/usr/bin/podman", "rm", "--force", container_id)
        (artifact_dir / f"{scenario}.stdout").write_bytes(output)
        (artifact_dir / f"{scenario}.stderr").write_bytes(errors)
        expected = (
            b"release-receive:Protocol error"
            if close_control
            else b"release-receive:Operation timed out"
        )
        if return_code == 0 or output or expected not in errors:
            raise AssertionError(
                f"launcher did not fail closed for {scenario}: "
                f"code={return_code} output={output!r} stderr={errors!r}"
            )
        observations.append(
            {
                "mutation": "provider-revocation" if close_control else "missing-release",
                "return_code": return_code,
                "stderr": errors.decode("utf-8", errors="replace").strip(),
            }
        )

    (artifact_dir / "release-barrier-runtime-rejections.json").write_text(
        json.dumps(
            {
                "cases": observations,
                "missing_release_bound_seconds": MISSING_RELEASE_SECONDS,
                "verdict": "all live ReleaseV2 conformance injections failed closed",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def configured_default_rejection_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
    barrier_fixture: BarrierFixture,
    containers_conf: pathlib.Path,
    scenario: str,
    injection: str,
) -> None:
    result = launch(
        image,
        seccomp,
        seccomp_bpf_base64,
        seccomp_bpf,
        seccomp_tracer,
        artifact_dir,
        barrier_fixture,
        b"",
        scenario,
        release=False,
        containers_conf=containers_conf,
        expect_annotation_rejection=injection,
    )
    if result is not None:
        raise AssertionError("configured-default injection unexpectedly returned a launch")


def normal_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
    barrier_fixture: BarrierFixture,
    eai1_hello: bytes,
    eao1_hello: bytes,
) -> None:
    process, control, container_id = launch(
        image,
        seccomp,
        seccomp_bpf_base64,
        seccomp_bpf,
        seccomp_tracer,
        artifact_dir,
        barrier_fixture,
        eai1_hello,
        "normal",
    )
    assert process.stdin is not None
    process.stdin.close()
    assert process.stdout is not None
    assert process.stderr is not None
    output = process.stdout.read()
    errors = process.stderr.read()
    return_code = process.wait(timeout=20)
    control.close()
    (artifact_dir / "normal.stdout").write_bytes(output)
    (artifact_dir / "normal.stderr").write_bytes(errors)
    validation = validate_eao1(output, b"hello\n")
    if output != eao1_hello:
        raise AssertionError("adapter EAO1 differs from independently validated vector")
    (artifact_dir / "normal-transport-validation.json").write_text(
        json.dumps(validation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if return_code != 0:
        raise AssertionError(
            f"normal adapter failed: code={return_code} output={output!r} stderr={errors!r}"
        )
    run("/usr/bin/podman", "rm", container_id)


def memory_limit_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
    barrier_fixture: BarrierFixture,
    eai1_memory: bytes,
) -> None:
    scenario = "elm-memory"
    process, control, container_id = launch(
        image,
        seccomp,
        seccomp_bpf_base64,
        seccomp_bpf,
        seccomp_tracer,
        artifact_dir,
        barrier_fixture,
        eai1_memory,
        scenario,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    snapshot = json.loads(
        (artifact_dir / f"{scenario}.launcher.json").read_text(encoding="utf-8")
    )
    cgroup_path = pathlib.Path(snapshot["cgroup_path"])
    baseline_text = snapshot["cgroup_values"]["memory.events.local"]
    baseline = parse_cgroup_events(baseline_text)
    process.stdin.close()
    final = baseline
    observation_deadline = time.monotonic() + 20
    while time.monotonic() < observation_deadline:
        current_text = read_text(cgroup_path / "memory.events.local").strip()
        if not current_text.startswith("UNAVAILABLE:"):
            final = parse_cgroup_events(current_text)
            if final.get("oom_kill", 0) > baseline.get("oom_kill", 0):
                break
        if process.poll() is not None:
            break
        time.sleep(0.01)
    return_code = process.wait(timeout=20)
    output = process.stdout.read()
    errors = process.stderr.read()
    control.close()
    inspected = json.loads(run("/usr/bin/podman", "inspect", container_id).stdout)[0]
    oom_delta = final.get("oom_kill", 0) - baseline.get("oom_kill", 0)
    oom_flag = inspected["State"]["OOMKilled"]
    (artifact_dir / f"{scenario}.stdout").write_bytes(output)
    (artifact_dir / f"{scenario}.stderr").write_bytes(errors)
    report = {
        "baseline_memory_events_local": baseline,
        "container_id": container_id,
        "final_memory_events_local": final,
        "memory_max": snapshot["cgroup_values"]["memory.max"],
        "oom_kill_delta": oom_delta,
        "podman_oom_killed": oom_flag,
        "return_code": return_code,
        "terminal_code": 3,
        "terminal_name": "OomKilled",
        "verdict": "forced memory allocation selected OomKilled",
    }
    (artifact_dir / f"{scenario}.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    run("/usr/bin/podman", "rm", "--force", container_id)
    if (
        return_code == 0
        or output
        or snapshot["cgroup_values"]["memory.max"] != "67108864"
        or (oom_delta <= 0 and oom_flag is not True)
    ):
        raise AssertionError(f"memory limit did not force OOM evidence: {report!r}")


def task_limit_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
    barrier_fixture: BarrierFixture,
    eai1_tasks: bytes,
) -> None:
    scenario = "elm-tasks"
    process, control, container_id = launch(
        image,
        seccomp,
        seccomp_bpf_base64,
        seccomp_bpf,
        seccomp_tracer,
        artifact_dir,
        barrier_fixture,
        eai1_tasks,
        scenario,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    snapshot = json.loads(
        (artifact_dir / f"{scenario}.launcher.json").read_text(encoding="utf-8")
    )
    cgroup_path = pathlib.Path(snapshot["cgroup_path"])
    baseline = parse_cgroup_events(snapshot["cgroup_values"]["pids.events.local"])
    process.stdin.close()
    final = baseline
    observation_deadline = time.monotonic() + 20
    while time.monotonic() < observation_deadline:
        current_text = read_text(cgroup_path / "pids.events.local").strip()
        if not current_text.startswith("UNAVAILABLE:"):
            final = parse_cgroup_events(current_text)
            if final.get("max", 0) > baseline.get("max", 0):
                break
        if process.poll() is not None:
            break
        time.sleep(0.01)
    run("/usr/bin/podman", "rm", "--force", container_id)
    return_code = process.wait(timeout=20)
    output = process.stdout.read()
    errors = process.stderr.read()
    control.close()
    max_delta = final.get("max", 0) - baseline.get("max", 0)
    (artifact_dir / f"{scenario}.stdout").write_bytes(output)
    (artifact_dir / f"{scenario}.stderr").write_bytes(errors)
    report = {
        "baseline_pids_events_local": baseline,
        "container_id": container_id,
        "final_pids_events_local": final,
        "pids_max": snapshot["cgroup_values"]["pids.max"],
        "pids_max_delta": max_delta,
        "return_code_after_cleanup": return_code,
        "terminal_code": 5,
        "terminal_name": "TaskLimit",
        "verdict": "forced fork exhaustion selected TaskLimit",
    }
    (artifact_dir / f"{scenario}.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if (
        output
        or snapshot["cgroup_values"]["pids.max"] != "16"
        or max_delta <= 0
        or b"TASK_LIMIT" not in errors
    ):
        raise AssertionError(f"task limit did not force pids evidence: {report!r}")


def cpu_throttling_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
    barrier_fixture: BarrierFixture,
    eai1_cpu: bytes,
) -> None:
    scenario = "elm-cpu-throttling"
    process, control, container_id = launch(
        image,
        seccomp,
        seccomp_bpf_base64,
        seccomp_bpf,
        seccomp_tracer,
        artifact_dir,
        barrier_fixture,
        eai1_cpu,
        scenario,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    snapshot = json.loads(
        (artifact_dir / f"{scenario}.launcher.json").read_text(encoding="utf-8")
    )
    cgroup_path = pathlib.Path(snapshot["cgroup_path"])
    baseline = parse_cgroup_events(snapshot["cgroup_values"]["cpu.stat"])
    process.stdin.close()
    final = baseline
    observation_deadline = time.monotonic() + 20
    while time.monotonic() < observation_deadline:
        current_text = read_text(cgroup_path / "cpu.stat").strip()
        if not current_text.startswith("UNAVAILABLE:"):
            final = parse_cgroup_events(current_text)
            if final.get("nr_throttled", 0) > baseline.get("nr_throttled", 0):
                break
        if process.poll() is not None:
            break
        time.sleep(0.01)
    run("/usr/bin/podman", "rm", "--force", container_id)
    return_code = process.wait(timeout=20)
    output = process.stdout.read()
    errors = process.stderr.read()
    control.close()
    throttled_delta = final.get("nr_throttled", 0) - baseline.get("nr_throttled", 0)
    (artifact_dir / f"{scenario}.stdout").write_bytes(output)
    (artifact_dir / f"{scenario}.stderr").write_bytes(errors)
    report = {
        "baseline_cpu_stat": baseline,
        "container_id": container_id,
        "cpu_max": snapshot["cgroup_values"]["cpu.max"],
        "final_cpu_stat": final,
        "nr_throttled_delta": throttled_delta,
        "return_code_after_cleanup": return_code,
        "terminal_selected": None,
        "verdict": "CPU quota throttling was observed without manufacturing a terminal",
    }
    (artifact_dir / f"{scenario}.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if (
        output
        or snapshot["cgroup_values"]["cpu.max"] != "50000 100000"
        or throttled_delta <= 0
    ):
        raise AssertionError(f"CPU quota did not produce throttling evidence: {report!r}")


def file_limit_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
    barrier_fixture: BarrierFixture,
    eai1_file: bytes,
) -> None:
    scenario = "elm-file"
    process, control, container_id = launch(
        image,
        seccomp,
        seccomp_bpf_base64,
        seccomp_bpf,
        seccomp_tracer,
        artifact_dir,
        barrier_fixture,
        eai1_file,
        scenario,
        trace_seccomp_install=False,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    snapshot = json.loads(
        (artifact_dir / f"{scenario}.launcher.json").read_text(encoding="utf-8")
    )
    process.stdin.close()
    return_code = process.wait(timeout=20)
    output = process.stdout.read()
    errors = process.stderr.read()
    control.close()
    inspected = json.loads(run("/usr/bin/podman", "inspect", container_id).stdout)[0]
    state = inspected["State"]
    (artifact_dir / f"{scenario}.stdout").write_bytes(output)
    (artifact_dir / f"{scenario}.stderr").write_bytes(errors)
    report = {
        "adr069_compatible": False,
        "container_id": container_id,
        "observed_errno": "EFBIG",
        "observed_signal": None,
        "observed_terminal_code": 8,
        "observed_terminal_name": "ProcessCrash",
        "podman_exit_code": state["ExitCode"],
        "podman_oom_killed": state["OOMKilled"],
        "process_limits": snapshot["limits"],
        "required_signal": "SIGXFSZ",
        "required_terminal_code": 7,
        "required_terminal_name": "FileOrOutputLimit",
        "return_code": return_code,
        "runtime_annotations": inspected["Config"]["Annotations"],
        "seccomp_install_observer": "untraced exact annotation after global install proof",
        "verdict": "candidate enforced RLIMIT_FSIZE but did not produce required SIGXFSZ evidence",
    }
    (artifact_dir / f"{scenario}.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    run("/usr/bin/podman", "rm", "--force", container_id)
    if (
        return_code != 71
        or state["ExitCode"] != 71
        or state["OOMKilled"] is not False
        or output
        or errors
        != b"adapter-error:file-limit-write-without-sigxfsz:File too large\n"
    ):
        raise AssertionError(f"file limit negative result changed: {report!r}")


def watchdog_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
    barrier_fixture: BarrierFixture,
    eai1_watchdog: bytes,
) -> None:
    scenario = "elm-watchdog"
    process, control, container_id = launch(
        image,
        seccomp,
        seccomp_bpf_base64,
        seccomp_bpf,
        seccomp_tracer,
        artifact_dir,
        barrier_fixture,
        eai1_watchdog,
        scenario,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    snapshot = json.loads(
        (artifact_dir / f"{scenario}.launcher.json").read_text(encoding="utf-8")
    )
    release_report = json.loads(
        (artifact_dir / f"{scenario}.release-barrier.json").read_text(
            encoding="utf-8"
        )
    )
    start_ns = int(release_report["release_sent_monotonic_ns"])
    deadline_ns = start_ns + 1_000_000_000
    process.stdin.close()
    while True:
        now_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        if now_ns >= deadline_ns:
            break
        if process.poll() is not None:
            raise AssertionError("watchdog workload exited before its deadline")
        time.sleep(min((deadline_ns - now_ns) / 1_000_000_000, 0.005))
    termination_requested_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    run("/usr/bin/podman", "kill", "--signal=TERM", container_id)
    kill_escalated = False
    kill_requested_ns = None
    try:
        return_code = process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        kill_escalated = True
        kill_requested_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        run("/usr/bin/podman", "kill", "--signal=KILL", container_id)
        return_code = process.wait(timeout=5)
    finish_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    output = process.stdout.read()
    errors = process.stderr.read()
    control.close()
    cgroup_path = pathlib.Path(snapshot["cgroup_path"])
    cgroup_procs = cgroup_path / "cgroup.procs"
    final_cgroup_procs = (
        read_text(cgroup_procs).strip() if cgroup_procs.exists() else ""
    )
    inspected = json.loads(run("/usr/bin/podman", "inspect", container_id).stdout)[0]
    (artifact_dir / f"{scenario}.stdout").write_bytes(output)
    (artifact_dir / f"{scenario}.stderr").write_bytes(errors)
    report = {
        "container_id": container_id,
        "deadline_ns": deadline_ns,
        "effective_watchdog_ms": 1000,
        "final_cgroup_procs": final_cgroup_procs,
        "finish_ns": finish_ns,
        "kill_escalated": kill_escalated,
        "kill_requested_ns": kill_requested_ns,
        "podman_exit_code": inspected["State"]["ExitCode"],
        "release_sent_start_ns": start_ns,
        "return_code": return_code,
        "terminal_code": 6,
        "terminal_name": "Watchdog",
        "termination_lateness_ns": termination_requested_ns - deadline_ns,
        "termination_requested_ns": termination_requested_ns,
        "termination_signal": "SIGTERM then SIGKILL",
        "verdict": "provider monotonic deadline selected Watchdog",
    }
    (artifact_dir / f"{scenario}.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    run("/usr/bin/podman", "rm", "--force", container_id)
    if (
        termination_requested_ns < deadline_ns
        or kill_escalated is not True
        or return_code != 137
        or inspected["State"]["ExitCode"] != 137
        or final_cgroup_procs != ""
        or output
        or errors
    ):
        raise AssertionError(f"watchdog evidence did not match: {report!r}")


def concurrent_lifecycle_worker(
    index: int,
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
    barrier_fixture: BarrierFixture,
    eai1_hello: bytes,
    eao1_hello: bytes,
    release_path: pathlib.Path,
) -> dict[str, object]:
    scenario = f"lifecycle-concurrent-{index}"
    observed_path = artifact_dir / f"{scenario}.observed.json"
    started_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    process, control, container_id = launch(
        image,
        seccomp,
        seccomp_bpf_base64,
        seccomp_bpf,
        seccomp_tracer,
        artifact_dir,
        barrier_fixture,
        eai1_hello,
        scenario,
        release_gate=(observed_path, release_path),
    )
    released_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    process.stdin.close()
    return_code = process.wait(timeout=20)
    output = process.stdout.read()
    errors = process.stderr.read()
    control.close()
    run("/usr/bin/podman", "rm", container_id)
    (artifact_dir / f"{scenario}.stdout").write_bytes(output)
    (artifact_dir / f"{scenario}.stderr").write_bytes(errors)
    validation = validate_eao1(output, b"hello\n")
    if return_code != 0 or output != eao1_hello or errors:
        raise AssertionError(
            f"concurrent lifecycle attempt failed: {scenario} code={return_code} "
            f"output={output!r} stderr={errors!r}"
        )
    starting = json.loads(
        (artifact_dir / f"{scenario}.launcher-starting.json").read_text(
            encoding="utf-8"
        )
    )
    launcher = json.loads(
        (artifact_dir / f"{scenario}.launcher.json").read_text(encoding="utf-8")
    )
    observed = json.loads(observed_path.read_text(encoding="utf-8"))
    return {
        "attempt_id": starting["attempt_id"],
        "cgroup_path": launcher["cgroup_path"],
        "container_id": container_id,
        "launcher_pid": launcher["pid"],
        "observed_monotonic_ns": observed["monotonic_ns"],
        "released_monotonic_ns": released_ns,
        "scenario": scenario,
        "started_monotonic_ns": started_ns,
        "transport_validation": validation,
    }


def concurrent_lifecycle_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
    barrier_fixture: BarrierFixture,
    eai1_hello: bytes,
    eao1_hello: bytes,
) -> None:
    release_path = artifact_dir / "lifecycle-concurrent.release"
    with concurrent.futures.ProcessPoolExecutor(max_workers=8) as executor:
        futures = [
            executor.submit(
                concurrent_lifecycle_worker,
                index,
                image,
                seccomp,
                seccomp_bpf_base64,
                seccomp_bpf,
                seccomp_tracer,
                artifact_dir,
                barrier_fixture,
                eai1_hello,
                eao1_hello,
                release_path,
            )
            for index in range(8)
        ]
        observed_paths = [
            artifact_dir / f"lifecycle-concurrent-{index}.observed.json"
            for index in range(8)
        ]
        observed_deadline = time.monotonic() + 60
        while (
            not all(path.exists() for path in observed_paths)
            and time.monotonic() < observed_deadline
        ):
            time.sleep(0.01)
        if not all(path.exists() for path in observed_paths):
            raise TimeoutError("eight lifecycle attempts did not all reach Observed")
        release_path.write_text("release all observed attempts\n", encoding="ascii")
        results = [future.result(timeout=60) for future in futures]

    identity_fields = ("attempt_id", "cgroup_path", "container_id", "launcher_pid")
    for field in identity_fields:
        values = [result[field] for result in results]
        if len(set(values)) != 8:
            raise AssertionError(f"concurrent lifecycle {field} is not unique")
    latest_observed = max(int(result["observed_monotonic_ns"]) for result in results)
    earliest_release = min(int(result["released_monotonic_ns"]) for result in results)
    if latest_observed >= earliest_release:
        raise AssertionError("a concurrent lifecycle attempt released before all observed")
    report = {
        "attempt_count": len(results),
        "attempts": sorted(results, key=lambda result: str(result["scenario"])),
        "earliest_release_monotonic_ns": earliest_release,
        "identity_fields_unique": list(identity_fields),
        "latest_observed_monotonic_ns": latest_observed,
        "verdict": "eight unique attempts were simultaneously Observed before release",
    }
    (artifact_dir / "lifecycle-concurrent.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def cancellation_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
    barrier_fixture: BarrierFixture,
    eai1_hold: bytes,
) -> None:
    process, control, container_id = launch(
        image,
        seccomp,
        seccomp_bpf_base64,
        seccomp_bpf,
        seccomp_tracer,
        artifact_dir,
        barrier_fixture,
        eai1_hold,
        "cancel",
    )
    assert process.stdin is not None
    process.stdin.close()
    assert process.stderr is not None
    readable, _, _ = select.select([process.stderr], [], [], 10)
    if not readable:
        raise TimeoutError("holding adapter did not report its descendant")
    holding = process.stderr.readline()
    if not holding.startswith(b"HOLDING child="):
        raise AssertionError(f"unexpected holding output: {holding!r}")
    (artifact_dir / "cancel.stderr").write_bytes(holding)
    before = json.loads((artifact_dir / "cancel.launcher.json").read_text(encoding="utf-8"))
    cgroup_path = pathlib.Path(before["cgroup_path"])
    run("/usr/bin/podman", "kill", "--signal=KILL", container_id)
    return_code = process.wait(timeout=20)
    control.close()
    deadline = time.monotonic() + 10
    cgroup_procs = cgroup_path / "cgroup.procs"
    while time.monotonic() < deadline and cgroup_procs.exists() and read_text(cgroup_procs).strip():
        time.sleep(0.05)
    residual = read_text(cgroup_procs).strip() if cgroup_procs.exists() else ""
    (artifact_dir / "cancel.cleanup.txt").write_text(
        f"return_code={return_code}\nresidual_cgroup_procs={residual}\n",
        encoding="utf-8",
    )
    if residual:
        raise AssertionError(f"descendants survived cancellation: {residual}")
    run("/usr/bin/podman", "rm", "--force", container_id)


def transport_rejection_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
    barrier_fixture: BarrierFixture,
    valid: bytes,
) -> None:
    magic_offset = valid.index(b"EAI1")
    mutations = {
        "changed-magic": valid[:magic_offset] + b"X" + valid[magic_offset + 1 :],
        "changed-transcript": valid[:-1] + bytes([valid[-1] ^ 1]),
        "truncated": valid[:-1],
        "trailing": valid + b"\x00",
    }
    observations = []
    for label, malformed in mutations.items():
        scenario = f"transport-reject-{label}"
        process, control, container_id = launch(
            image,
            seccomp,
            seccomp_bpf_base64,
            seccomp_bpf,
            seccomp_tracer,
            artifact_dir,
            barrier_fixture,
            malformed,
            scenario,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        process.stdin.close()
        output = process.stdout.read()
        errors = process.stderr.read()
        return_code = process.wait(timeout=20)
        control.close()
        run("/usr/bin/podman", "rm", "--force", container_id)
        (artifact_dir / f"{scenario}.stdout").write_bytes(output)
        (artifact_dir / f"{scenario}.stderr").write_bytes(errors)
        if return_code == 0 or output or b"adapter-error:input-" not in errors:
            raise AssertionError(
                f"adapter accepted malformed EAI1 {label}: "
                f"code={return_code} output={output!r} stderr={errors!r}"
            )
        observations.append(
            {
                "mutation": label,
                "return_code": return_code,
                "stderr": errors.decode("utf-8", errors="replace").strip(),
            }
        )
    (artifact_dir / "adapter-transport-runtime-rejections.json").write_text(
        json.dumps(
            {
                "cases": observations,
                "verdict": "all incomplete, changed, or trailing EAI1 streams rejected",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def installed_byte_mutation_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
) -> None:
    canonical = seccomp_bpf.read_bytes()
    mutated = bytearray(canonical)
    mutated[-1] ^= 1
    mutated_base64 = base64.b64encode(mutated).decode("ascii")
    name = f"pigloros-adr084-installed-byte-mutation-{uuid.uuid4().hex[:12]}"
    installed = artifact_dir / "installed-byte-mutation.installed-seccomp.bpf"
    install_report = artifact_dir / "installed-byte-mutation.seccomp-install.json"
    parent_control, child_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    if parent_control.fileno() == 3:
        relocated_parent = socket.socket(fileno=os.dup(parent_control.fileno()))
        parent_control.close()
        parent_control = relocated_parent
    child_fd = child_control.fileno()
    child_control.set_inheritable(True)
    podman_command = [
        "/usr/bin/podman",
        "run",
        "--runtime=/usr/bin/crun",
        "--pull=never",
        f"--name={name}",
        "--preserve-fds=1",
        "--network=none",
        "--no-hosts",
        "--hostname=pigloros-adapter",
        "--read-only",
        "--read-only-tmpfs=false",
        "--tmpfs=/work:rw,nosuid,nodev,noexec,size=65536",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        f"--security-opt=seccomp={seccomp}",
        f"--annotation=run.oci.seccomp_bpf_data={mutated_base64}",
        "--stop-signal=15",
        "--memory=64m",
        "--memory-swap=64m",
        "--pids-limit=16",
        "--cpus=0.5",
        "--ulimit=nofile=64:64",
        "--ulimit=fsize=32768:32768",
        "--user=65532:65532",
        "--label=io.pigloros.prototype=adr084",
        "--label=io.pigloros.scenario=installed-byte-mutation",
        "--rm=false",
        "-i",
        image,
    ]
    command = [
        str(seccomp_tracer),
        str(seccomp_bpf),
        str(installed),
        str(install_report),
        "--",
        *podman_command,
    ]
    saved_fd3: int | None = None
    if child_fd != 3:
        try:
            saved_fd3 = os.dup(3)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
        os.dup2(child_fd, 3, inheritable=True)
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(3,),
        )
    finally:
        if child_fd != 3:
            os.close(3)
            if saved_fd3 is not None:
                os.dup2(saved_fd3, 3)
                os.close(saved_fd3)
    child_control.close()
    stdout, stderr = process.communicate(input=b"", timeout=30)
    parent_control.close()
    completed = subprocess.CompletedProcess(
        command,
        process.returncode,
        stdout,
        stderr,
    )
    run("/usr/bin/podman", "rm", "--force", name, check=False)
    (artifact_dir / "installed-byte-mutation.stdout").write_bytes(completed.stdout)
    (artifact_dir / "installed-byte-mutation.stderr").write_bytes(completed.stderr)
    if (
        completed.returncode != 72
        or completed.stdout
        or b"seccomp-tracer-error:installed-byte-mismatch" not in completed.stderr
        or installed.exists()
        or install_report.exists()
    ):
        raise AssertionError(
            "mutated installed BPF was not stopped before seccomp continuation: "
            f"code={completed.returncode} stdout={completed.stdout!r} "
            f"stderr={completed.stderr!r} installed={installed.exists()} "
            f"report={install_report.exists()}"
        )
    (artifact_dir / "installed-byte-mutation.json").write_text(
        json.dumps(
            {
                "canonical_sha256": hashlib.sha256(canonical).hexdigest(),
                "mutation": "final byte xor 1 after canonical base64 decode",
                "mutated_sha256": hashlib.sha256(mutated).hexdigest(),
                "return_code": completed.returncode,
                "seccomp_syscall_continued": False,
                "verdict": "same-flags changed install bytes rejected before continuation",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def stacked_filter_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    prefilter: pathlib.Path,
    artifact_dir: pathlib.Path,
    barrier_fixture: BarrierFixture,
) -> None:
    process, control, container_id = launch(
        image,
        seccomp,
        seccomp_bpf_base64,
        seccomp_bpf,
        seccomp_tracer,
        artifact_dir,
        barrier_fixture,
        b"",
        "stacked",
        prefilter=prefilter,
        expected_filter_count=2,
        release=False,
    )
    assert process.stdin is not None
    process.stdin.close()
    run("/usr/bin/podman", "kill", "--signal=KILL", container_id)
    return_code = process.wait(timeout=20)
    control.close()
    assert process.stdout is not None
    assert process.stderr is not None
    output = process.stdout.read()
    errors = process.stderr.read()
    (artifact_dir / "stacked.stdout").write_bytes(output)
    (artifact_dir / "stacked.stderr").write_bytes(errors)
    if output or return_code == 0:
        raise AssertionError(
            f"stacked filter was not denied before release: code={return_code} "
            f"output={output!r} stderr={errors!r}"
        )
    run("/usr/bin/podman", "rm", "--force", container_id)
    (artifact_dir / "stacked-rejection.json").write_text(
        json.dumps(
            {
                "adapter_output_bytes": 0,
                "observed_filter_count": 2,
                "release_sent": False,
                "return_code": return_code,
                "verdict": "denied before release",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def seccomp_probe_scenario(
    architecture: str,
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    artifact_dir: pathlib.Path,
    scenario: str = "probe",
) -> None:
    name = f"pigloros-adr084-{scenario}-{uuid.uuid4().hex[:12]}"
    podman_command = [
        "/usr/bin/podman",
        "run",
        "--runtime=/usr/bin/crun",
        "--pull=never",
        f"--name={name}",
        "--network=none",
        "--no-hosts",
        "--hostname=pigloros-seccomp-probe",
        "--read-only",
        "--read-only-tmpfs=false",
        "--tmpfs=/work:rw,nosuid,nodev,noexec,size=65536",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        f"--security-opt=seccomp={seccomp}",
        f"--annotation=run.oci.seccomp_bpf_data={seccomp_bpf_base64}",
        "--stop-signal=15",
        "--memory=64m",
        "--memory-swap=64m",
        "--pids-limit=16",
        "--cpus=0.5",
        "--ulimit=nofile=64:64",
        "--ulimit=fsize=32768:32768",
        "--user=65532:65532",
        "--label=io.pigloros.prototype=adr084",
        f"--label=io.pigloros.scenario={scenario}",
        "--entrypoint=/seccomp-probe",
        "--rm=false",
        image,
    ]
    completed = subprocess.run(
        podman_command,
        check=False,
        capture_output=True,
        timeout=20,
    )
    (artifact_dir / f"{scenario}.stdout").write_bytes(completed.stdout)
    (artifact_dir / f"{scenario}.stderr").write_bytes(completed.stderr)
    inspect_text = run("/usr/bin/podman", "inspect", name).stdout
    (artifact_dir / f"{scenario}.inspect.json").write_text(
        inspect_text, encoding="utf-8"
    )
    inspected = json.loads(inspect_text)[0]
    validate_runtime_annotations(
        inspected["Config"]["Annotations"], seccomp, seccomp_bpf_base64
    )
    exported = seccomp_bpf.read_bytes()
    installed = (artifact_dir / "normal.installed-seccomp.bpf").read_bytes()
    if installed != exported:
        raise AssertionError("normal installed BPF differs from boundary probe input")
    (artifact_dir / f"{scenario}-filter-binding.json").write_text(
        json.dumps(
            {
                "annotation_bpf_sha256": hashlib.sha256(exported).hexdigest(),
                "installed_bpf_sha256": hashlib.sha256(installed).hexdigest(),
                "installed_capture": "normal.installed-seccomp.bpf",
                "install_report": "normal.seccomp-install.json",
                "runtime_annotation_map": f"{scenario}.inspect.json",
                "verdict": "boundary helper uses the independently captured exact filter",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    try:
        observed = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(
            f"seccomp probe emitted invalid JSON: {completed.stdout!r}"
        ) from error
    expected: dict[str, object] = {
        "architecture": architecture,
        "foreign_signal": signal.SIGSYS,
    }
    if architecture == "x86_64":
        expected.update({"high_bit_signal": signal.SIGSYS, "sentinel_raw": -4094})
    if completed.returncode != 0 or observed != expected:
        raise AssertionError(
            "seccomp boundary probe failed: "
            f"code={completed.returncode} observed={observed!r} "
            f"stderr={completed.stderr!r}"
        )
    run("/usr/bin/podman", "rm", name)


def cache_probe_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
    scenario: str,
) -> None:
    name = f"pigloros-adr084-{scenario}-{uuid.uuid4().hex[:12]}"
    podman_command = [
        "/usr/bin/podman",
        "run",
        "--runtime=/usr/bin/crun",
        "--pull=never",
        f"--name={name}",
        "--network=none",
        "--no-hosts",
        "--read-only",
        "--read-only-tmpfs=false",
        "--tmpfs=/work:rw,nosuid,nodev,noexec,size=65536",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        f"--security-opt=seccomp={seccomp}",
        f"--annotation=run.oci.seccomp_bpf_data={seccomp_bpf_base64}",
        "--stop-signal=15",
        "--memory=64m",
        "--memory-swap=64m",
        "--pids-limit=16",
        "--cpus=0.5",
        "--ulimit=nofile=64:64",
        "--ulimit=fsize=32768:32768",
        "--user=65532:65532",
        "--label=io.pigloros.prototype=adr084",
        f"--label=io.pigloros.scenario={scenario}",
        "--entrypoint=/cache-probe",
        "--rm=false",
        image,
    ]
    completed = subprocess.run(
        [
            str(seccomp_tracer),
            str(seccomp_bpf),
            str(artifact_dir / f"{scenario}.installed-seccomp.bpf"),
            str(artifact_dir / f"{scenario}.seccomp-install.json"),
            "--",
            *podman_command,
        ],
        check=False,
        capture_output=True,
        timeout=20,
    )
    (artifact_dir / f"{scenario}.stdout").write_bytes(completed.stdout)
    (artifact_dir / f"{scenario}.stderr").write_bytes(completed.stderr)
    inspect_text = run("/usr/bin/podman", "inspect", name).stdout
    (artifact_dir / f"{scenario}.inspect.json").write_text(
        inspect_text, encoding="utf-8"
    )
    inspected = json.loads(inspect_text)[0]
    validate_runtime_annotations(
        inspected["Config"]["Annotations"], seccomp, seccomp_bpf_base64
    )
    if completed.returncode != 0 or completed.stdout != b"CACHE-OK\n":
        raise AssertionError(
            "cache bypass probe failed: "
            f"code={completed.returncode} output={completed.stdout!r} "
            f"stderr={completed.stderr!r}"
        )
    run("/usr/bin/podman", "rm", name)


def native_matrix_scenario(
    architecture: str,
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_interface: pathlib.Path,
    artifact_dir: pathlib.Path,
) -> None:
    interface: dict[int, str] = {}
    for line in seccomp_interface.read_text(encoding="ascii").splitlines():
        encoded_number, name = line.split(":", 1)
        if encoded_number != "PNR":
            interface[int(encoded_number)] = name
    maximum = max(interface)
    name = f"pigloros-adr084-native-matrix-{uuid.uuid4().hex[:12]}"
    podman_command = [
        "/usr/bin/podman",
        "run",
        "--runtime=/usr/bin/crun",
        "--pull=never",
        f"--name={name}",
        "--network=none",
        "--no-hosts",
        "--hostname=pigloros-native-matrix",
        "--read-only",
        "--read-only-tmpfs=false",
        "--tmpfs=/work:rw,nosuid,nodev,noexec,size=65536",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        f"--security-opt=seccomp={seccomp}",
        f"--annotation=run.oci.seccomp_bpf_data={seccomp_bpf_base64}",
        "--stop-signal=15",
        "--memory=64m",
        "--memory-swap=64m",
        "--pids-limit=16",
        "--cpus=0.5",
        "--ulimit=nofile=64:64",
        "--ulimit=fsize=32768:32768",
        "--user=65532:65532",
        "--label=io.pigloros.prototype=adr084",
        "--label=io.pigloros.scenario=native-matrix",
        "--entrypoint=/native-matrix",
        "--rm=false",
        image,
    ]
    process = subprocess.Popen(
        podman_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    container_id = wait_for_container(name, process)
    running_inspect: dict[str, object] | None = None
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        inspected = json.loads(run("/usr/bin/podman", "inspect", container_id).stdout)[0]
        if inspected["State"]["Running"] and int(inspected["State"]["Pid"]) > 0:
            running_inspect = inspected
            break
        if process.poll() is not None:
            break
        time.sleep(0.01)
    if running_inspect is None:
        raise AssertionError("native matrix exited before running identity observation")
    (artifact_dir / "native-matrix.inspect.json").write_text(
        json.dumps([running_inspect], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    validate_runtime_annotations(
        running_inspect["Config"]["Annotations"],  # type: ignore[index]
        seccomp,
        seccomp_bpf_base64,
    )
    pid = int(running_inspect["State"]["Pid"])  # type: ignore[index]
    cgroup_path = pathlib.Path(process_snapshot(pid)["cgroup_path"])  # type: ignore[arg-type]
    output, errors = process.communicate(timeout=120)
    (artifact_dir / "native-matrix.stdout").write_bytes(output)
    (artifact_dir / "native-matrix.stderr").write_bytes(errors)
    if process.returncode != 0:
        raise AssertionError(
            f"native matrix helper failed: {process.returncode}: {errors!r}"
        )
    documents = [json.loads(line) for line in output.splitlines()]
    if len(documents) != maximum + 3:
        raise AssertionError("native matrix result count mismatch")
    results = documents[:-1]
    summary = documents[-1]
    blocking = {"pause", "select", "pselect6", "ppoll"}
    variable_blocking = {"sync"}
    terminating = {"exit", "exit_group"}
    for number, observed in enumerate(results):
        expected_name = interface.get(number, "")
        if observed.get("nr") != number or observed.get("name") != expected_name:
            raise AssertionError(f"native matrix identity mismatch at {number}")
        allowed = number in interface
        if observed.get("allowed") is not allowed:
            raise AssertionError(f"native matrix membership mismatch at {number}")
        outcome = observed.get("outcome")
        if not allowed:
            if outcome != "return" or observed.get("raw") != -4094:
                raise AssertionError(f"native hole was not denied at {number}: {observed}")
        elif expected_name in blocking:
            if outcome != "timeout":
                raise AssertionError(f"blocking syscall outcome mismatch: {observed}")
        elif expected_name in variable_blocking:
            if outcome not in {"return", "timeout"} or observed.get("raw") == -4094:
                raise AssertionError(
                    f"variable blocking syscall outcome mismatch: {observed}"
                )
        elif expected_name in terminating:
            if outcome != "exit" or observed.get("status") != 0:
                raise AssertionError(f"terminating syscall outcome mismatch: {observed}")
        elif expected_name == "rt_sigreturn" or (
            architecture == "x86_64" and expected_name == "uretprobe"
        ):
            expected_signal = (
                signal.SIGILL if expected_name == "uretprobe" else signal.SIGSEGV
            )
            if outcome == "timeout":
                continue
            if outcome != "signal" or observed.get("signal") != expected_signal:
                raise AssertionError(f"terminating signal mismatch: {observed}")
        elif outcome != "return" or observed.get("raw") == -4094:
            raise AssertionError(f"allowed syscall outcome mismatch: {observed}")
    if summary != {
        "summary": True,
        "case_count": maximum + 2,
        "maximum_interface_number": maximum,
        "residual_children": 0,
    }:
        raise AssertionError(f"native matrix summary mismatch: {summary}")
    deadline = time.monotonic() + 10
    while cgroup_path.exists() and time.monotonic() < deadline:
        if not read_text(cgroup_path / "cgroup.procs").strip():
            break
        time.sleep(0.01)
    residual = (
        read_text(cgroup_path / "cgroup.procs").strip()
        if cgroup_path.exists()
        else ""
    )
    if residual:
        raise AssertionError(f"native matrix cgroup is not empty: {residual}")
    exported = seccomp_bpf.read_bytes()
    installed = (artifact_dir / "normal.installed-seccomp.bpf").read_bytes()
    report = {
        "case_count": len(results),
        "deadline_nanoseconds_per_case": 100_000_000,
        "interface_sha256": hashlib.sha256(seccomp_interface.read_bytes()).hexdigest(),
        "maximum_interface_number": maximum,
        "results": results,
        "seccomp_bpf_sha256": hashlib.sha256(exported).hexdigest(),
        "installed_bpf_sha256": hashlib.sha256(installed).hexdigest(),
        "residual_cgroup_procs": residual,
        "verdict": "passed",
    }
    if exported != installed:
        raise AssertionError("native matrix filter binding differs from captured install")
    (artifact_dir / "native-matrix.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    run("/usr/bin/podman", "rm", container_id)


def crun_cache_checksum(profile: dict[str, object]) -> tuple[str, dict[str, object]]:
    package_version = "1.14.1"
    libseccomp_version = (2, 5, 5)
    installed_version = run(
        "/usr/bin/dpkg-query", "-W", "-f=${Version}", "libseccomp2"
    ).stdout
    if not installed_version.startswith("2.5.5-"):
        raise AssertionError(f"unexpected crun libseccomp package: {installed_version}")
    uname = os.uname()
    chunks = [package_version.encode("ascii")]
    chunks.extend(struct.pack("=I", value) for value in libseccomp_version)
    chunks.extend(
        value.encode("utf-8") for value in (uname.release, uname.version, uname.machine)
    )
    chunks.append(struct.pack("=I", 0))
    default_errno = profile.get("defaultErrnoRet")
    default_action = profile.get("defaultAction")
    architectures = profile.get("architectures")
    syscalls = profile.get("syscalls")
    if (
        not isinstance(default_errno, int)
        or not isinstance(default_action, str)
        or not isinstance(architectures, list)
        or not isinstance(syscalls, list)
    ):
        raise ValueError("seccomp profile cannot be checksummed")
    chunks.extend((struct.pack("=I", default_errno), default_action.encode("ascii")))
    for architecture in architectures:
        if not isinstance(architecture, str):
            raise ValueError("invalid seccomp architecture")
        chunks.append(architecture.encode("ascii"))
    for rule in syscalls:
        if not isinstance(rule, dict) or set(rule) != {"action", "names"}:
            raise ValueError("unsupported seccomp rule for checksum")
        action = rule["action"]
        names = rule["names"]
        if not isinstance(action, str) or not isinstance(names, list):
            raise ValueError("invalid seccomp rule for checksum")
        chunks.append(action.encode("ascii"))
        for name in names:
            if not isinstance(name, str):
                raise ValueError("invalid seccomp syscall name")
            chunks.append(name.encode("ascii"))
    result = subprocess.run(
        ["/usr/bin/b3sum"], input=b"".join(chunks), check=True, capture_output=True
    )
    checksum = result.stdout.decode("ascii").split()[0]
    return checksum, {
        "crun_package_version": package_version,
        "libseccomp_api_version": list(libseccomp_version),
        "libseccomp_package_version": installed_version,
        "seccomp_gen_options": 0,
        "uname": [uname.release, uname.version, uname.machine],
    }


def cache_snapshot(cache_dir: pathlib.Path) -> dict[str, object]:
    entries = []
    if cache_dir.exists():
        for entry in sorted(cache_dir.iterdir(), key=lambda item: item.name):
            if not entry.is_file() or entry.is_symlink():
                raise AssertionError(f"unexpected cache entry: {entry}")
            content = entry.read_bytes()
            metadata = entry.stat()
            entries.append(
                {
                    "name": entry.name,
                    "length": len(content),
                    "mode": metadata.st_mode & 0o7777,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "mtime_ns": metadata.st_mtime_ns,
                }
            )
    return {"directory": str(cache_dir), "entries": entries}


def cache_matrix_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
) -> None:
    profile = json.loads(seccomp.read_text(encoding="utf-8"))
    if not isinstance(profile, dict):
        raise ValueError("seccomp profile is not an object")
    candidate_checksum, checksum_inputs = crun_cache_checksum(profile)
    cache_dir = pathlib.Path(f"/run/user/{os.getuid()}/crun/.cache/seccomp")
    cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    exported = seccomp_bpf.read_bytes()
    if candidate_checksum in {"0" * 64, "1" * 64, "2" * 64}:
        raise AssertionError("candidate checksum collides with fixed cache fixture")
    states: list[tuple[str, str | None, bytes | None, int | None]] = [
        ("empty", None, None, None),
        ("valid", "0" * 64, exported, None),
        ("stale", "1" * 64, exported, 0),
        ("corrupt", "2" * 64, b"not-a-classic-bpf-program", None),
        ("adversarial", candidate_checksum, bytes(len(exported)), None),
    ]
    observations = []
    for state, filename, content, mtime_ns in states:
        for entry in cache_dir.iterdir():
            if not entry.is_file() or entry.is_symlink():
                raise AssertionError(f"refusing to clear unexpected cache entry: {entry}")
            entry.unlink()
        if filename is not None and content is not None:
            cache_file = cache_dir / filename
            cache_file.write_bytes(content)
            cache_file.chmod(0o700)
            if mtime_ns is not None:
                os.utime(cache_file, ns=(mtime_ns, mtime_ns))
        before = cache_snapshot(cache_dir)
        cache_probe_scenario(
            image,
            seccomp,
            seccomp_bpf_base64,
            seccomp_bpf,
            seccomp_tracer,
            artifact_dir,
            f"cache-{state}",
        )
        after = cache_snapshot(cache_dir)
        if after != before:
            raise AssertionError(f"crun checksum cache changed in {state} case")
        observations.append({"state": state, "before": before, "after": after})
    for entry in cache_dir.iterdir():
        entry.unlink()
    (artifact_dir / "cache-matrix.json").write_text(
        json.dumps(
            {
                "candidate_checksum": candidate_checksum,
                "checksum_inputs": checksum_inputs,
                "observations": observations,
                "verdict": "all states byte-identical before/after; tracer observed zero accesses",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def concurrent_identical_cache_scenario(
    image: str,
    seccomp: pathlib.Path,
    seccomp_bpf_base64: str,
    seccomp_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
) -> None:
    profile = json.loads(seccomp.read_text(encoding="utf-8"))
    if not isinstance(profile, dict):
        raise ValueError("seccomp profile is not an object")
    candidate_checksum, checksum_inputs = crun_cache_checksum(profile)
    cache_dir = pathlib.Path(f"/run/user/{os.getuid()}/crun/.cache/seccomp")
    cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    for entry in cache_dir.iterdir():
        if not entry.is_file() or entry.is_symlink():
            raise AssertionError(f"refusing to clear unexpected cache entry: {entry}")
        entry.unlink()
    adversarial = cache_dir / candidate_checksum
    adversarial.write_bytes(bytes(seccomp_bpf.stat().st_size))
    adversarial.chmod(0o700)
    before = cache_snapshot(cache_dir)
    scenarios = [f"cache-concurrent-identical-{index}" for index in range(8)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [
            executor.submit(
                cache_probe_scenario,
                image,
                seccomp,
                seccomp_bpf_base64,
                seccomp_bpf,
                seccomp_tracer,
                artifact_dir,
                scenario,
            )
            for scenario in scenarios
        ]
        for future in futures:
            future.result()
    after = cache_snapshot(cache_dir)
    if after != before:
        raise AssertionError("crun checksum cache changed under identical concurrency")
    install_reports = []
    for scenario in scenarios:
        report = json.loads(
            (artifact_dir / f"{scenario}.seccomp-install.json").read_text(
                encoding="utf-8"
            )
        )
        if report.get("checksum_cache_accesses") != 0:
            raise AssertionError(f"cache access under concurrency: {scenario}")
        install_reports.append(
            {
                "scenario": scenario,
                "installed_bpf_sha256": hashlib.sha256(
                    (artifact_dir / f"{scenario}.installed-seccomp.bpf").read_bytes()
                ).hexdigest(),
                "install_report": report,
            }
        )
    adversarial.unlink()
    (artifact_dir / "cache-concurrent-identical.json").write_text(
        json.dumps(
            {
                "attempt_count": len(scenarios),
                "before": before,
                "after": after,
                "candidate_checksum": candidate_checksum,
                "checksum_inputs": checksum_inputs,
                "install_reports": install_reports,
                "input_class": "identical SCS1/profile/BPF",
                "verdict": "eight concurrent installs bypassed the adversarial cache",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def concurrent_distinct_cache_scenario(
    image: str,
    primary_scs1: pathlib.Path,
    primary_seccomp: pathlib.Path,
    primary_base64: str,
    primary_bpf: pathlib.Path,
    distinct_scs1: pathlib.Path,
    distinct_seccomp: pathlib.Path,
    distinct_base64: str,
    distinct_bpf: pathlib.Path,
    seccomp_tracer: pathlib.Path,
    artifact_dir: pathlib.Path,
) -> None:
    tuples = (
        ("primary", primary_scs1, primary_seccomp, primary_base64, primary_bpf),
        ("derived-cachestat", distinct_scs1, distinct_seccomp, distinct_base64, distinct_bpf),
    )
    if primary_scs1.read_bytes() == distinct_scs1.read_bytes():
        raise AssertionError("distinct concurrency SCS1 inputs are identical")
    if primary_bpf.read_bytes() == distinct_bpf.read_bytes():
        raise AssertionError("distinct concurrency BPF inputs are identical")
    cache_dir = pathlib.Path(f"/run/user/{os.getuid()}/crun/.cache/seccomp")
    cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    for entry in cache_dir.iterdir():
        if not entry.is_file() or entry.is_symlink():
            raise AssertionError(f"refusing to clear unexpected cache entry: {entry}")
        entry.unlink()
    identities = []
    for label, scs1, profile_path, _, bpf_path in tuples:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        if not isinstance(profile, dict):
            raise ValueError("distinct seccomp profile is not an object")
        checksum, checksum_inputs = crun_cache_checksum(profile)
        cache_file = cache_dir / checksum
        if cache_file.exists():
            raise AssertionError("distinct profiles produced the same crun checksum")
        cache_file.write_bytes(bytes(bpf_path.stat().st_size))
        cache_file.chmod(0o700)
        identities.append(
            {
                "label": label,
                "scs1_sha256": hashlib.sha256(scs1.read_bytes()).hexdigest(),
                "profile_sha256": hashlib.sha256(profile_path.read_bytes()).hexdigest(),
                "bpf_sha256": hashlib.sha256(bpf_path.read_bytes()).hexdigest(),
                "candidate_checksum": checksum,
                "checksum_inputs": checksum_inputs,
            }
        )
    before = cache_snapshot(cache_dir)
    attempts = [
        (
            f"cache-concurrent-distinct-{index}",
            tuples[index % len(tuples)],
        )
        for index in range(8)
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [
            executor.submit(
                cache_probe_scenario,
                image,
                selected[2],
                selected[3],
                selected[4],
                seccomp_tracer,
                artifact_dir,
                scenario,
            )
            for scenario, selected in attempts
        ]
        for future in futures:
            future.result()
    after = cache_snapshot(cache_dir)
    if after != before:
        raise AssertionError("crun checksum cache changed under distinct concurrency")
    observations = []
    for scenario, selected in attempts:
        install_report = json.loads(
            (artifact_dir / f"{scenario}.seccomp-install.json").read_text(
                encoding="utf-8"
            )
        )
        installed_hash = hashlib.sha256(
            (artifact_dir / f"{scenario}.installed-seccomp.bpf").read_bytes()
        ).hexdigest()
        expected_hash = hashlib.sha256(selected[4].read_bytes()).hexdigest()
        if install_report.get("checksum_cache_accesses") != 0 or installed_hash != expected_hash:
            raise AssertionError(f"distinct cache attempt mismatch: {scenario}")
        observations.append(
            {
                "scenario": scenario,
                "input": selected[0],
                "installed_bpf_sha256": installed_hash,
                "install_report": install_report,
            }
        )
    for entry in cache_dir.iterdir():
        entry.unlink()
    (artifact_dir / "cache-concurrent-distinct.json").write_text(
        json.dumps(
            {
                "attempt_count": len(attempts),
                "before": before,
                "after": after,
                "input_identities": identities,
                "observations": observations,
                "verdict": (
                    "eight concurrent installs used two distinct SCS1/filter "
                    "tuples without cache access"
                ),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--architecture", required=True, choices=("x86_64", "aarch64"))
    parser.add_argument("--seccomp", required=True, type=pathlib.Path)
    parser.add_argument("--seccomp-bpf-base64", required=True, type=pathlib.Path)
    parser.add_argument("--seccomp-bpf", required=True, type=pathlib.Path)
    parser.add_argument("--seccomp-interface", required=True, type=pathlib.Path)
    parser.add_argument("--scs1", required=True, type=pathlib.Path)
    parser.add_argument("--distinct-seccomp", required=True, type=pathlib.Path)
    parser.add_argument(
        "--distinct-seccomp-bpf-base64", required=True, type=pathlib.Path
    )
    parser.add_argument("--distinct-seccomp-bpf", required=True, type=pathlib.Path)
    parser.add_argument("--distinct-scs1", required=True, type=pathlib.Path)
    parser.add_argument("--seccomp-tracer", required=True, type=pathlib.Path)
    parser.add_argument("--prefilter", required=True, type=pathlib.Path)
    parser.add_argument("--eai1-hello", required=True, type=pathlib.Path)
    parser.add_argument("--eai1-hold", required=True, type=pathlib.Path)
    parser.add_argument("--eai1-memory", required=True, type=pathlib.Path)
    parser.add_argument("--eai1-tasks", required=True, type=pathlib.Path)
    parser.add_argument("--eai1-cpu", required=True, type=pathlib.Path)
    parser.add_argument("--eai1-file", required=True, type=pathlib.Path)
    parser.add_argument("--eai1-watchdog", required=True, type=pathlib.Path)
    parser.add_argument("--eao1-hello", required=True, type=pathlib.Path)
    parser.add_argument("--runtime-subject", required=True, type=pathlib.Path)
    parser.add_argument("--configured-defaults", required=True, type=pathlib.Path)
    parser.add_argument(
        "--configured-security-defaults", required=True, type=pathlib.Path
    )
    parser.add_argument("--artifact-dir", required=True, type=pathlib.Path)
    arguments = parser.parse_args()
    arguments.artifact_dir.mkdir(parents=True, exist_ok=True)
    barrier_fixture = load_barrier_fixture(
        arguments.runtime_subject.resolve(), arguments.architecture
    )
    provider_status = read_text(pathlib.Path("/proc/self/status"))
    if "Seccomp:\t0" not in provider_status or "Seccomp_filters:\t0" not in provider_status:
        raise AssertionError("provider process did not begin with a clean seccomp baseline")
    (arguments.artifact_dir / "provider-seccomp-baseline.txt").write_text(
        "\n".join(
            line
            for line in provider_status.splitlines()
            if line.startswith(("NoNewPrivs:", "Seccomp:", "Seccomp_filters:"))
        )
        + "\n",
        encoding="utf-8",
    )
    eai1_hello = arguments.eai1_hello.read_bytes()
    eai1_hold = arguments.eai1_hold.read_bytes()
    eai1_memory = arguments.eai1_memory.read_bytes()
    eai1_tasks = arguments.eai1_tasks.read_bytes()
    eai1_cpu = arguments.eai1_cpu.read_bytes()
    eai1_file = arguments.eai1_file.read_bytes()
    eai1_watchdog = arguments.eai1_watchdog.read_bytes()
    eao1_hello = arguments.eao1_hello.read_bytes()
    (arguments.artifact_dir / "normal.eai1").write_bytes(eai1_hello)
    (arguments.artifact_dir / "cancel.eai1").write_bytes(eai1_hold)
    (arguments.artifact_dir / "elm-memory.eai1").write_bytes(eai1_memory)
    (arguments.artifact_dir / "elm-tasks.eai1").write_bytes(eai1_tasks)
    (arguments.artifact_dir / "elm-cpu-throttling.eai1").write_bytes(eai1_cpu)
    (arguments.artifact_dir / "elm-file.eai1").write_bytes(eai1_file)
    (arguments.artifact_dir / "elm-watchdog.eai1").write_bytes(eai1_watchdog)
    (arguments.artifact_dir / "expected.eao1").write_bytes(eao1_hello)
    transport_report = {
        "eai1_hello": validate_eai1(eai1_hello, b"hello\n"),
        "eai1_hold": validate_eai1(eai1_hold, b"HOLD\n"),
        "eai1_memory": validate_eai1(eai1_memory, b"MEMORY\n"),
        "eai1_tasks": validate_eai1(eai1_tasks, b"TASKS\n"),
        "eai1_cpu": validate_eai1(eai1_cpu, b"CPU\n"),
        "eai1_file": validate_eai1(eai1_file, b"FILE\n"),
        "eai1_watchdog": validate_eai1(eai1_watchdog, b"WATCHDOG\n"),
        "eao1_hello": validate_eao1(eao1_hello, b"hello\n"),
        "verdict": "canonical framed streams independently validated before launch",
    }
    (arguments.artifact_dir / "adapter-transport-validation.json").write_text(
        json.dumps(transport_report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    seccomp_bpf_base64 = arguments.seccomp_bpf_base64.read_text(
        encoding="ascii"
    )
    validate_bpf_annotation(
        seccomp_bpf_base64, arguments.seccomp_bpf.resolve().read_bytes()
    )
    distinct_seccomp_bpf_base64 = arguments.distinct_seccomp_bpf_base64.read_text(
        encoding="ascii"
    )
    validate_bpf_annotation(
        distinct_seccomp_bpf_base64,
        arguments.distinct_seccomp_bpf.resolve().read_bytes(),
    )
    mutation_report = annotation_mutation_report(
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
    )
    (arguments.artifact_dir / "annotation-mutation-report.json").write_text(
        json.dumps(mutation_report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    installed_byte_mutation_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.artifact_dir,
    )
    configured_default_rejection_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.artifact_dir,
        barrier_fixture,
        arguments.configured_defaults.resolve(),
        "configured-default-injection",
        "fixture.configured-default=injected",
    )
    configured_default_rejection_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.artifact_dir,
        barrier_fixture,
        arguments.configured_security_defaults.resolve(),
        "configured-security-default-injection",
        "org.systemd.property.DeviceAllow=injected",
    )
    normal_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.artifact_dir,
        barrier_fixture,
        eai1_hello,
        eao1_hello,
    )
    memory_limit_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.artifact_dir,
        barrier_fixture,
        eai1_memory,
    )
    task_limit_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.artifact_dir,
        barrier_fixture,
        eai1_tasks,
    )
    cpu_throttling_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.artifact_dir,
        barrier_fixture,
        eai1_cpu,
    )
    file_limit_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.artifact_dir,
        barrier_fixture,
        eai1_file,
    )
    watchdog_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.artifact_dir,
        barrier_fixture,
        eai1_watchdog,
    )
    concurrent_lifecycle_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.artifact_dir,
        barrier_fixture,
        eai1_hello,
        eao1_hello,
    )
    release_rejection_scenarios(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.artifact_dir,
        barrier_fixture,
    )
    cancellation_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.artifact_dir,
        barrier_fixture,
        eai1_hold,
    )
    transport_rejection_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.artifact_dir,
        barrier_fixture,
        eai1_hello,
    )
    stacked_filter_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.prefilter.resolve(),
        arguments.artifact_dir,
        barrier_fixture,
    )
    seccomp_probe_scenario(
        arguments.architecture,
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.artifact_dir,
    )
    native_matrix_scenario(
        arguments.architecture,
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_interface.resolve(),
        arguments.artifact_dir,
    )
    cache_matrix_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.artifact_dir,
    )
    concurrent_identical_cache_scenario(
        arguments.image,
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.artifact_dir,
    )
    concurrent_distinct_cache_scenario(
        arguments.image,
        arguments.scs1.resolve(),
        arguments.seccomp.resolve(),
        seccomp_bpf_base64,
        arguments.seccomp_bpf.resolve(),
        arguments.distinct_scs1.resolve(),
        arguments.distinct_seccomp.resolve(),
        distinct_seccomp_bpf_base64,
        arguments.distinct_seccomp_bpf.resolve(),
        arguments.seccomp_tracer.resolve(),
        arguments.artifact_dir,
    )
    print("ADR-084 Podman release-barrier prototype passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"prototype failed: {error}", file=sys.stderr)
        subprocess.run(
            ["/usr/bin/podman", "ps", "--all", "--no-trunc"], check=False
        )
        raise
