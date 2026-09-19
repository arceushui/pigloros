#!/usr/bin/env python3
"""Emit deterministic ADR-085 vectors without using project production code."""

from __future__ import annotations

import json
import subprocess

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


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


def digest(index: int) -> bytes:
    return bytes([index]) * 32


def identifier(index: int) -> bytes:
    return bytes([index]) * 16


def rejection(name: str, record: list[object], expected: str) -> dict[str, str]:
    return {
        "expected_rejection": expected,
        "record": name,
        "record_cbor_hex": cbor(record).hex(),
    }


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
    request_common = [identifier(1), digest(1), 7, identifier(2)]
    payload = [6, digest(2)]
    descriptor = lambda media, size, value: [media, size, digest(value)]
    executable = ["/launcher", 4096, digest(8), 0, None, None]
    adapter = ["/adapter", 4096, digest(9), 0, None, None]
    ort = ["ORT1", 1, [["/", 0, 365, 0, 0, 0, None, None]]]
    ort_vector = vector("OciRootfsTree", ort)
    ois = [
        "OIS1",
        1,
        "pigloros.adapter.fixture",
        0,
        descriptor(0, 512, 3),
        descriptor(1, 256, 4),
        [[descriptor(3, 1024, 5), digest(6)], [descriptor(3, 2048, 16), digest(17)]],
        digest(7),
        bytes.fromhex(ort_vector["self_digest_hex"]),
        executable,
        adapter,
        ["--fixture"],
        65532,
        65532,
        "/",
        11,
        identifier(3),
    ]
    vectors = [ort_vector, vector("OciImageSubject", ois, signed=True)]
    vectors.extend(
        [
            vector("RVS", ["RVS2", 2, digest(1), 9, [], [], [digest(2)], identifier(1)], True),
            vector(
                "APT",
                ["APT2", 2, 10, digest(1), digest(2), [digest(3)], [digest(4)],
                 digest(5), digest(6), digest(7), digest(8), digest(9), 11, 12,
                 digest(10), identifier(2)],
                True,
            ),
            vector(
                "SIC",
                ["SIC2", 2, identifier(1), bytes(range(32)), digest(1), digest(2),
                 digest(3), "/run/pigloros/provider-execute.sock",
                 "/run/pigloros/provider-control.sock", ["cgroup-v2"],
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
                 digest(5), identifier(1)],
                True,
            ),
            vector(
                "RBS",
                ["RBS2", 2, 0, "podman-rootless", digest(1), digest(2), digest(3),
                 digest(4), 0, identifier(1), capability, 0, digest(5), digest(6),
                 digest(7), digest(8), digest(9), ["cgroup-v2"], []],
            ),
            vector(
                "LPV",
                ["LPV2", 2, identifier(1), digest(1), digest(2), "/adapter",
                 ["--fixture"], digest(3)],
            ),
            vector(
                "RDY",
                ["RDY2", 2, identifier(1), digest(1), identifier(2), digest(2), [1, 2],
                 digest(3), digest(4), digest(5), digest(6), digest(7), [3, 4], digest(8),
                 digest(9), digest(10)],
            ),
            vector(
                "RLS",
                ["RLS2", 2, identifier(1), digest(1), digest(2), digest(3), digest(4),
                 digest(5), 6, 7, 8, digest(6), digest(7), 9, identifier(2)],
                True,
            ),
            vector(
                "SPX",
                ["SPX2", 2, request_common, identifier(3)] + [digest(index) for index in range(1, 17)]
                + [[], payload, []],
            ),
            vector(
                "AGR",
                ["AGR2", 2, identifier(1), identifier(2)]
                + [digest(index) for index in range(1, 15)]
                + [7, 8, 9, digest(16), digest(17), [], digest(18), digest(19), identifier(3)],
                True,
            ),
            vector(
                "SPR",
                ["SPR2", 2, identifier(1)] + [digest(index) for index in range(1, 9)]
                + [7, 8, 9, digest(9), digest(10), [], digest(11), digest(12),
                   digest(13), digest(14), digest(15), digest(16), digest(17), identifier(2)],
                True,
            ),
        ]
    )
    wrong_architecture = [*ois]
    wrong_architecture[3] = 2
    wrong_layer_order = [*ois]
    wrong_layer_order[6] = list(reversed(ois[6]))
    wrong_rootfs = [*ois]
    wrong_rootfs[8] = digest(31)
    wrong_executable = [*ois]
    wrong_executable[10] = ["/wrong-adapter", 4096, digest(9), 0, None, None]
    rejections = [
        rejection("OIS1-wrong-architecture", wrong_architecture, "unsupported architecture"),
        rejection("OIS1-wrong-layer-order", wrong_layer_order, "ordered layer closure mismatch"),
        rejection("OIS1-wrong-rootfs", wrong_rootfs, "mounted ORT1 digest mismatch"),
        rejection("OIS1-wrong-executable", wrong_executable, "adapter identity mismatch"),
        rejection(
            "RVS2-revoked-image",
            ["RVS2", 2, digest(1), 9, [], [],
             [bytes.fromhex(vectors[1]["self_digest_hex"])], identifier(1)],
            "OIS1 self-digest is revoked",
        ),
        rejection(
            "mixed-version-closure",
            ["LPS1", 1, "pigloros.air-gapped", 0, digest(1), limits, []],
            "version-1 authority record in version-2 closure",
        ),
    ]
    print(json.dumps({"rejection_vectors": rejections, "vectors": vectors}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
