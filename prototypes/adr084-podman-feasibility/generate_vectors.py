#!/usr/bin/env python3
"""Emit deterministic ADR-085 vectors without using project production code."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import struct
import subprocess
import tarfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from oci_layer import MAX_UNCOMPRESSED_LAYER_BYTES, MAX_UNCOMPRESSED_TOTAL_BYTES


def head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def cbor(value: object) -> bytes:
    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int) and value >= 0:
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(item) for item in value)
    raise TypeError(f"unsupported canonical value: {value!r}")


def blake3(domain: str, encoded: bytes) -> bytes:
    result = subprocess.run(
        ["b3sum"],
        input=domain.encode("ascii") + b"\0" + encoded,
        check=True,
        capture_output=True,
    )
    return bytes.fromhex(result.stdout.decode("ascii").split()[0])


def sha256(content: bytes) -> bytes:
    return hashlib.sha256(content).digest()


def json_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def elf_fixture(exit_status: int) -> bytes:
    """Build a complete static x86_64 ELF that exits with the selected status."""
    identification = b"\x7fELF\x02\x01\x01" + bytes(9)
    code = b"\xbf" + exit_status.to_bytes(4, "little") + b"\xb8\x3c\x00\x00\x00\x0f\x05"
    entry_offset = 64 + 56
    file_size = entry_offset + len(code)
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        2,
        62,
        1,
        0x400000 + entry_offset,
        64,
        0,
        0,
        64,
        56,
        1,
        0,
        0,
        0,
    )
    program_header = struct.pack(
        "<IIQQQQQQ",
        1,
        5,
        0,
        0x400000,
        0x400000,
        file_size,
        file_size,
        0x1000,
    )
    return identification + header + program_header + code


def layer(path: str, content: bytes) -> tuple[bytes, bytes]:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.GNU_FORMAT) as archive:
        entry = tarfile.TarInfo(path.lstrip("/"))
        entry.size = len(content)
        entry.mode = 0o555
        entry.uid = 65532
        entry.gid = 65532
        entry.mtime = 0
        archive.addfile(entry, io.BytesIO(content))
    uncompressed = stream.getvalue()
    return gzip.compress(uncompressed, compresslevel=9, mtime=0), sha256(uncompressed)


def repeated_gzip(byte_count: int) -> bytes:
    """Create a deterministic compact gzip stream without retaining its input."""
    stream = io.BytesIO()
    block = bytes(1_048_576)
    with gzip.GzipFile(fileobj=stream, mode="wb", compresslevel=9, mtime=0) as archive:
        remaining = byte_count
        while remaining:
            portion = min(remaining, len(block))
            archive.write(block[:portion])
            remaining -= portion
    return stream.getvalue()


def digest(index: int) -> bytes:
    return bytes([index]) * 32


def identifier(index: int) -> bytes:
    return bytes([index]) * 16


def key_id(index: int) -> str:
    return f"test-key-{index:02d}"


def rejection(
    name: str,
    unsigned: list[object],
    expected: str,
    vector_name: str,
    signed: bool = False,
) -> dict[str, str]:
    result = vector(vector_name, unsigned, signed)
    result["record"] = name
    result["expected_rejection"] = expected
    return result


def vector(name: str, unsigned: list[object], signed: bool = False) -> dict[str, str]:
    encoded = cbor(unsigned)
    if name == "OciImageSubject":
        digest_domain = "PiglorOS.OciImageSubject.v1"
    elif name == "OciRootfsTree":
        digest_domain = "PiglorOS.OciRootfsTree.v1"
    elif unsigned[0] == "RBS2":
        digest_domain = "PiglorOS.SandboxReadbackSet.v2"
    else:
        digest_domain = f"PiglorOS.{unsigned[0]}.v{unsigned[1]}"
    self_digest = blake3(digest_domain, encoded)
    result = {
        "record": name,
        "unsigned_cbor_hex": encoded.hex(),
        "self_digest_hex": self_digest.hex(),
    }
    if signed:
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        signature_domain = (
            b"PiglorOS.OciImageSubjectSignature.v1\0"
            if name == "OciImageSubject"
            else f"PiglorOS.{unsigned[0]}.Signature.v{unsigned[1]}\0".encode("ascii")
        )
        result["signer_public_key_hex"] = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        result["signature_hex"] = key.sign(signature_domain + self_digest).hex()
    return result


def main() -> None:
    limits = [[index, 1000 + index] for index in range(17)]
    capability = ["pigloros.sandbox.air-gapped", 1, 1]
    host_features = sorted(
        [
            "cgroup-v2-cpu",
            "cgroup-v2-memory",
            "cgroup-v2-pids",
            "cgroup-kill",
            "managed-attempt-exec",
            "process-isolation-controls",
            "signed-root-image",
            "mount-namespace",
            "pid-namespace",
            "ipc-namespace",
            "uts-namespace",
            "user-namespace",
            "network-namespace",
            "nftables-atomic",
            "broker-lifecycle",
            "limit-observation",
        ],
        key=cbor,
    )
    request_common = [identifier(1), digest(1), 7, identifier(2)]
    payload = [6, digest(2)]
    descriptor = lambda media, content: [media, len(content), sha256(content)]
    launcher_bytes = elf_fixture(0)
    adapter_bytes = elf_fixture(1)
    launcher_layer, launcher_diff_id = layer("/launcher", launcher_bytes)
    adapter_layer, adapter_diff_id = layer("/adapter", adapter_bytes)
    diff_ids = [launcher_diff_id, adapter_diff_id]
    chain_id = sha256(
        f"sha256:{diff_ids[0].hex()} sha256:{diff_ids[1].hex()}".encode("ascii")
    )
    config_bytes = json_bytes(
        {
            "architecture": "amd64",
            "config": {
                "Entrypoint": ["/launcher"],
                "User": "65532:65532",
                "WorkingDir": "/",
            },
            "os": "linux",
            "rootfs": {
                "diff_ids": [f"sha256:{value.hex()}" for value in diff_ids],
                "type": "layers",
            },
        }
    )
    config_descriptor = descriptor(1, config_bytes)
    layer_descriptors = [descriptor(2, launcher_layer), descriptor(2, adapter_layer)]
    manifest_bytes = json_bytes(
        {
            "annotations": {
                "org.opencontainers.image.base.digest": "",
                "org.opencontainers.image.base.name": "",
            },
            "config": {
                "digest": f"sha256:{config_descriptor[2].hex()}",
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "size": config_descriptor[1],
            },
            "layers": [
                {
                    "digest": f"sha256:{item[2].hex()}",
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "size": item[1],
                }
                for item in layer_descriptors
            ],
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "schemaVersion": 2,
        }
    )
    executable = [
        "/launcher",
        len(launcher_bytes),
        blake3("PiglorOS.OciExecutable.v1", launcher_bytes),
        0,
        None,
        None,
    ]
    adapter = [
        "/adapter",
        len(adapter_bytes),
        blake3("PiglorOS.OciExecutable.v1", adapter_bytes),
        0,
        None,
        None,
    ]
    ort = [
        "ORT1",
        1,
        [
            ["/", 0, 365, 0, 0, 0, None, None],
            [
                "/adapter",
                1,
                365,
                65532,
                65532,
                len(adapter_bytes),
                blake3("PiglorOS.OciRootfsFile.v1", adapter_bytes),
                None,
            ],
            [
                "/launcher",
                1,
                365,
                65532,
                65532,
                len(launcher_bytes),
                blake3("PiglorOS.OciRootfsFile.v1", launcher_bytes),
                None,
            ],
        ],
    ]
    ort_vector = vector("OciRootfsTree", ort)
    ois = [
        "OIS1",
        1,
        "pigloros.adapter.fixture",
        0,
        descriptor(0, manifest_bytes),
        config_descriptor,
        [[layer_descriptors[0], diff_ids[0]], [layer_descriptors[1], diff_ids[1]]],
        chain_id,
        bytes.fromhex(ort_vector["self_digest_hex"]),
        executable,
        adapter,
        ["--fixture"],
        65532,
        65532,
        "/",
        11,
        key_id(3),
    ]
    vectors = [ort_vector, vector("OciImageSubject", ois, signed=True)]
    ois_digest = bytes.fromhex(vectors[1]["self_digest_hex"])
    rbs_vector = vector(
        "RBS",
        ["RBS2", 2, 0, "podman-rootless", digest(1), digest(2), digest(3),
         digest(4), 0, key_id(1), capability, 0, digest(5), ois_digest,
         digest(7), digest(8), digest(9), host_features, []],
    )
    rbs_digest = bytes.fromhex(rbs_vector["self_digest_hex"])
    lpv_unsigned = [
        "LPV2", 2, identifier(1), digest(1), ois_digest, "/adapter",
        ["--fixture"], digest(9),
    ]
    lpv_vector = vector("LPV", lpv_unsigned)
    lpv_digest = bytes.fromhex(lpv_vector["self_digest_hex"])
    ready_unsigned = [
        "RDY2", 2, identifier(1), digest(1), [11, 12], executable[2], [1, 2],
        ois_digest, bytes.fromhex(ort_vector["self_digest_hex"]), adapter[2], [3, 4],
        lpv_digest, digest(9), digest(9),
    ]
    ready_vector = vector("RDY", ready_unsigned)
    launch_anchor = 9
    watchdog_ms = limits[4][1]
    release_unsigned = [
        "RLS2", 2, identifier(1), digest(1),
        bytes.fromhex(ready_vector["self_digest_hex"]), digest(3), digest(4),
        digest(5), 6, 7, 8, rbs_digest, rbs_digest, launch_anchor,
        launch_anchor + watchdog_ms * 1_000_000, key_id(2),
    ]
    vectors.extend(
        [
            vector("RVS", ["RVS2", 2, digest(1), 9, [], [], [digest(2)], key_id(1)], True),
            vector(
                "APT",
                ["APT2", 2, 10, digest(1), digest(2), [digest(3)], [digest(4)],
                 digest(5), digest(6), digest(7), digest(8), digest(9), 11, 12,
                 digest(10), key_id(2)],
                True,
            ),
            vector(
                "SIC",
                ["SIC2", 2, key_id(1),
                 bytes.fromhex(vectors[1]["signer_public_key_hex"]), digest(1), digest(2),
                 digest(3), "/run/pigloros/provider-execute.sock",
                 "/run/pigloros/provider-control.sock", host_features,
                 [[9, digest(4), digest(5), 1024]]],
            ),
            vector("LPS", ["LPS2", 2, "pigloros.air-gapped", 0, digest(1), limits, []]),
            vector(
                "EVR",
                ["EVR2", 2, identifier(1), digest(1), digest(2), 0, digest(3),
                 ["org.pigloros.fixture", digest(4), digest(5), digest(6), digest(7), None],
                 digest(8), digest(9), [digest(10), 1048576, 65536], digest(11),
                 digest(12), [digest(13), digest(14), capability, digest(15), 7], None],
            ),
            vector(
                "ELM",
                 ["ELM2", 2, limits, digest(1), digest(2), digest(3), digest(4),
                 digest(5), key_id(1)],
                True,
            ),
            rbs_vector,
            lpv_vector,
            ready_vector,
            vector("RLS", release_unsigned, True),
            vector(
                "SPX",
                ["SPX2", 2, request_common, identifier(3)] + [digest(index) for index in range(1, 16)]
                + [[], payload, []],
            ),
            vector(
                "AGR",
                ["AGR2", 2, identifier(1), identifier(2)]
                + [digest(index) for index in range(1, 14)]
                + [7, 8, 9, digest(16), digest(17), [], digest(18), digest(19), key_id(3)],
                True,
            ),
            vector(
                "SPR",
                ["SPR2", 2, identifier(1)] + [digest(index) for index in range(1, 9)]
                + [7, 8, 9, digest(9), digest(10), [], digest(11), digest(12),
                   digest(13), digest(14), digest(15), digest(16), digest(17), key_id(2)],
                True,
            ),
        ]
    )
    wrong_architecture = [*ois]
    wrong_architecture[3] = 2
    wrong_layer_order = [*ois]
    wrong_layer_order[6] = list(reversed(ois[6]))
    wrong_diff_id = [*ois]
    wrong_diff_id[6] = [[[*subject[0]], subject[1]] for subject in ois[6]]
    wrong_diff_id[6][0][1] = digest(30)
    wrong_chain_id = [*ois]
    wrong_chain_id[7] = digest(30)
    wrong_rootfs = [*ois]
    wrong_rootfs[8] = digest(31)
    wrong_executable = [*ois]
    wrong_executable[10] = [*adapter]
    wrong_executable[10][0] = "/wrong-adapter"
    mixed_lps = ["LPS1", 1, "pigloros.air-gapped", 0, digest(1), limits, []]
    ready_mutations = (
        ("RDY2-wrong-attempt", 2, identifier(30), "ReadyV2 attempt ID mismatch"),
        ("RDY2-wrong-nonce", 3, digest(30), "ReadyV2 nonce mismatch"),
        ("RDY2-wrong-mount-namespace", 4, [30, 31], "ReadyV2 mount namespace mismatch"),
        ("RDY2-wrong-launcher-digest", 5, digest(30), "ReadyV2 launcher digest mismatch"),
        ("RDY2-wrong-launcher-FD", 6, [30, 31], "ReadyV2 launcher FD mismatch"),
        ("RDY2-wrong-OIS1", 7, digest(30), "ReadyV2 OIS1 mismatch"),
        ("RDY2-wrong-ORT1", 8, digest(30), "ReadyV2 ORT1 mismatch"),
        ("RDY2-wrong-adapter-digest", 9, digest(30), "ReadyV2 adapter digest mismatch"),
        ("RDY2-wrong-adapter-FD", 10, [30, 31], "ReadyV2 adapter FD mismatch"),
        ("RDY2-wrong-LPV2", 11, digest(30), "ReadyV2 LPV2 mismatch"),
        ("RDY2-wrong-expected-FDL1", 12, digest(30), "ReadyV2 expected FDL1 mismatch"),
        ("RDY2-wrong-observed-FDL1", 13, digest(30), "ReadyV2 observed FDL1 mismatch"),
    )
    lpv_mutations = (
        ("LPV2-wrong-attempt", 2, identifier(30), "LPV2 attempt ID mismatch"),
        ("LPV2-wrong-nonce", 3, digest(30), "LPV2 nonce mismatch"),
        ("LPV2-wrong-OIS1", 4, digest(30), "LPV2 OIS1 mismatch"),
        ("LPV2-wrong-path", 5, "/wrong-adapter", "LPV2 adapter path mismatch"),
        ("LPV2-wrong-arguments", 6, ["--wrong"], "LPV2 arguments mismatch"),
        ("LPV2-wrong-FDL1", 7, digest(30), "LPV2 expected FDL1 mismatch"),
    )
    release_mutations = (
        ("RLS2-wrong-attempt", 2, identifier(30), "ReleaseV2 attempt ID mismatch"),
        ("RLS2-wrong-nonce", 3, digest(30), "ReleaseV2 nonce mismatch"),
        ("RLS2-wrong-ReadyV2", 4, digest(30), "ReleaseV2 ReadyV2 mismatch"),
        ("RLS2-wrong-TRS1", 5, digest(30), "ReleaseV2 TRS1 mismatch"),
        ("RLS2-wrong-RVS2", 6, digest(30), "ReleaseV2 RVS2 mismatch"),
        ("RLS2-wrong-APT2", 7, digest(30), "ReleaseV2 APT2 mismatch"),
        ("RLS2-wrong-trust-epoch", 8, 30, "ReleaseV2 trust epoch mismatch"),
        ("RLS2-wrong-revocation-epoch", 9, 30, "ReleaseV2 revocation epoch mismatch"),
        ("RLS2-wrong-policy-epoch", 10, 30, "ReleaseV2 policy epoch mismatch"),
        ("RLS2-wrong-expected-RBS2", 11, digest(30), "ReleaseV2 expected RBS2 mismatch"),
        ("RLS2-wrong-observed-RBS2", 12, digest(30), "ReleaseV2 observed RBS2 mismatch"),
        ("RLS2-wrong-launch-anchor", 13, 30, "ReleaseV2 launch anchor mismatch"),
        ("RLS2-wrong-deadline", 14, 30, "ReleaseV2 deadline mismatch"),
        ("RLS2-wrong-runtime-key", 15, key_id(30), "ReleaseV2 runtime key mismatch"),
    )
    rejections = [
        rejection("OIS1-wrong-architecture", wrong_architecture,
                  "unsupported architecture", "OciImageSubject", True),
        rejection("OIS1-wrong-layer-order", wrong_layer_order,
                  "ordered layer closure mismatch", "OciImageSubject", True),
        rejection("OIS1-wrong-DiffID", wrong_diff_id,
                  "fixture DiffID mismatch", "OciImageSubject", True),
        rejection("OIS1-wrong-ChainID", wrong_chain_id,
                  "fixture ChainID mismatch", "OciImageSubject", True),
        rejection("OIS1-wrong-rootfs", wrong_rootfs,
                  "mounted ORT1 digest mismatch", "OciImageSubject", True),
        rejection("OIS1-wrong-executable", wrong_executable,
                  "adapter identity mismatch", "OciImageSubject", True),
        rejection(
            "RVS2-revoked-image",
             ["RVS2", 2, digest(1), 9, [], [],
             [bytes.fromhex(vectors[1]["self_digest_hex"])], key_id(1)],
            "OIS1 self-digest is revoked",
            "RVS",
            True,
        ),
        rejection(
            "mixed-version-closure",
            mixed_lps,
            "version-1 authority record in version-2 closure",
            "LPS",
        ),
    ]
    rejections.extend(
        rejection(name, [*lpv_unsigned[:index], value, *lpv_unsigned[index + 1:]], message, "LPV")
        for name, index, value, message in lpv_mutations
    )
    rejections.extend(
        rejection(name, [*ready_unsigned[:index], value, *ready_unsigned[index + 1:]], message, "RDY")
        for name, index, value, message in ready_mutations
    )
    rejections.extend(
        rejection(
            name,
            [*release_unsigned[:index], value, *release_unsigned[index + 1:]],
            message,
            "RLS",
            True,
        )
        for name, index, value, message in release_mutations
    )
    wrong_signature = rejection(
        "RLS2-wrong-signature",
        release_unsigned,
        "ReleaseV2 signature verification failed",
        "RLS",
        True,
    )
    corrupted_signature = bytearray.fromhex(wrong_signature["signature_hex"])
    corrupted_signature[0] ^= 1
    wrong_signature["signature_hex"] = corrupted_signature.hex()
    rejections.append(wrong_signature)
    mixed_lps_rejection = next(
        item for item in rejections if item["record"] == "mixed-version-closure"
    )
    mixed_lps_digest = bytes.fromhex(mixed_lps_rejection["self_digest_hex"])
    mixed_apt = [
        "APT2", 2, 10, digest(1), digest(2), [mixed_lps_digest],
        [bytes.fromhex(vectors[1]["self_digest_hex"])], digest(5), digest(6),
        digest(7), digest(8), digest(9), 11, 12, digest(10), key_id(2),
    ]
    mixed_apt_vector = vector("APT", mixed_apt, True)
    mixed_lps_rejection["referencing_apt2_unsigned_cbor_hex"] = mixed_apt_vector[
        "unsigned_cbor_hex"
    ]
    mixed_lps_rejection["referencing_apt2_self_digest_hex"] = mixed_apt_vector[
        "self_digest_hex"
    ]
    mixed_lps_rejection["referencing_apt2_signature_hex"] = mixed_apt_vector[
        "signature_hex"
    ]
    fixture_blobs = [
        ["application/vnd.oci.image.manifest.v1+json", sha256(manifest_bytes).hex(), manifest_bytes.hex()],
        ["application/vnd.oci.image.config.v1+json", sha256(config_bytes).hex(), config_bytes.hex()],
        ["application/vnd.oci.image.layer.v1.tar+gzip", sha256(launcher_layer).hex(), launcher_layer.hex()],
        ["application/vnd.oci.image.layer.v1.tar+gzip", sha256(adapter_layer).hex(), adapter_layer.hex()],
    ]
    noncanonical_ois = bytes.fromhex(vectors[1]["unsigned_cbor_hex"])
    noncanonical_ois = noncanonical_ois[:6] + b"\x18\x01" + noncanonical_ois[7:]
    malformed_cases = [
        {
            "record": "OIS1-noncanonical-CBOR",
            "expected_rejection": "noncanonical OIS1 CBOR",
            "input_hex": noncanonical_ois.hex(),
        },
        {
            "record": "manifest-duplicate-key",
            "expected_rejection": "duplicate JSON key",
            "input_hex": b'{"schemaVersion":2,"schemaVersion":2}'.hex(),
        },
        {
            "record": "manifest-extra-field",
            "expected_rejection": "unexpected manifest fields",
            "input_hex": json_bytes({**json.loads(manifest_bytes), "extra": 1}).hex(),
        },
        {
            "record": "config-DiffID-mismatch",
            "expected_rejection": "config DiffID mismatch",
            "input_hex": json_bytes(
                {
                    **json.loads(config_bytes),
                    "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "00" * 32]},
                }
            ).hex(),
        },
        {
            "record": "layer-uncompressed-limit",
            "expected_rejection": "layer exceeds uncompressed byte ceiling",
            "input_hex": repeated_gzip(MAX_UNCOMPRESSED_LAYER_BYTES + 1).hex(),
        },
        {
            "record": "layers-cumulative-limit",
            "expected_rejection": "layers exceed cumulative uncompressed byte ceiling",
            "inputs_hex": [
                repeated_gzip(MAX_UNCOMPRESSED_LAYER_BYTES).hex()
                for _ in range(
                    MAX_UNCOMPRESSED_TOTAL_BYTES // MAX_UNCOMPRESSED_LAYER_BYTES
                )
            ]
            + [
                repeated_gzip(
                    MAX_UNCOMPRESSED_TOTAL_BYTES % MAX_UNCOMPRESSED_LAYER_BYTES + 1
                ).hex()
            ],
        },
    ]
    print(
        json.dumps(
            {
                "fixture_blobs": fixture_blobs,
                "malformed_cases": malformed_cases,
                "rejection_vectors": rejections,
                "vectors": vectors,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
