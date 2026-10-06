#!/usr/bin/env python3
"""Independently regenerate the portable ADR-110 owner-bridge vectors.

This script intentionally imports no Rust code or third-party package.  It
contains a minimal deterministic-CBOR encoder, builds every public #533 wire
fixture, and compares the resulting bytes with the accepted vectors consumed
by the public Rust seam.

Usage:
    python3 scripts/owner_bridge_vectors.py --check
"""

from __future__ import annotations

import argparse
import struct
from collections.abc import Sequence

CEREMONY_ID = bytes(range(0x00, 0x10))
SUBJECT_ID = bytes(range(0x10, 0x20))
CHALLENGE = bytes(range(0x20, 0x40))
USER_HANDLE = bytes(range(0x40, 0x60))
PRF_INPUT = bytes(range(0x60, 0x80))
CREDENTIAL_ID = bytes((0x80, 0x81))
PRF_RESULT = bytes(range(0xA0, 0xC0))
COSE_ES256_KEY = bytes.fromhex(
    "a50102032620012158206b17d1f2e12c4247f8bce6e563a440f277037d812deb"
    "33a0f4a13945d898c2962258204fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce335"
    "76b315ececbb6406837bf51f5"
)

EXPECTED = {
    "create_options": (
        "8b44574352310150000102030405060708090a0b0c0d0e0f582020212223242526"
        "2728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f582040414243444546"
        "4748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f696c6f63616c686f"
        "7374685069676c6f724f532600005820606162636465666768696a6b6c6d6e6f70"
        "7172737475767778797a7b7c7d7e7f"
    ),
    "get_options": (
        "8844574752310150000102030405060708090a0b0c0d0e0f582020212223242526"
        "2728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f696c6f63616c686f"
        "7374428081005820606162636465666768696a6b6c6d6e6f707172737475767778"
        "797a7b7c7d7e7f"
    ),
    "attestation_reply": (
        "8a44574152310150000102030405060708090a0b0c0d0e0f428081427b7d41a081"
        "00f55820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdb"
        "ebff6"
    ),
    "assertion_reply": (
        "8a44574153310150000102030405060708090a0b0c0d0e0f428081427b7d582500"
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021"
        "222324483031323334353637f65820a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2"
        "b3b4b5b6b7b8b9babbbcbdbebff6"
    ),
    "request_header": "50574231010040000000000001000000000102030405060708090a0b0c0d0e0f0010000094000000020000000000000000000000000000000000000000000000",
    "ready_reply_header": "50574231010040000101000001000000000102030405060708090a0b0c0d0e0f0020000072000000020000000000000000000000000000000000000000000000",
    "subject_credential_binding": (
        "90445343423101656f776e657250101112131415161718191a1b1c1d1e1f000169"
        "6c6f63616c686f737476687474703a2f2f6c6f63616c686f73743a343932393142"
        "80815820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d"
        "5e5f584da50102032620012158206b17d1f2e12c4247f8bce6e563a440f277037d"
        "812deb33a0f4a13945d898c2962258204fe342e2fe1a7f9b8ee7eb4a7c0f9e162b"
        "ce33576b315ececbb6406837bf51f500f4f4078100"
    ),
    "cleanup_record": (
        "8744504243520150000102030405060708090a0b0c0d0e0f6e6f776e65722d6272"
        "696467652d31071b01020304050607085820a0a1a2a3a4a5a6a7a8a9aaabacadaea"
        "fb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    ),
}


def _head(major: int, value: int) -> bytes:
    if not 0 <= major <= 7 or value < 0:
        raise ValueError("invalid deterministic-CBOR head")
    if value < 24:
        return bytes((major << 5 | value,))
    for width, additional in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if value < 1 << (width * 8):
            return bytes((major << 5 | additional,)) + value.to_bytes(width, "big")
    raise ValueError("deterministic-CBOR integer is too large")


def cbor(value: object) -> bytes:
    """Encode the strict definite-array CBOR subset used by #533 vectors."""
    if value is None:
        return b"\xf6"
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _head(3, len(encoded)) + encoded
    if isinstance(value, Sequence):
        return _head(4, len(value)) + b"".join(cbor(item) for item in value)
    raise TypeError(f"unsupported deterministic-CBOR vector value: {type(value)!r}")


def control_header(
    role: int, kind: int, capacity: int, payload_length: int, state: int
) -> bytes:
    """Encode the exact little-endian 64-byte `OwnerBridgeControlV1` image."""
    output = bytearray(b"PWB1")
    output.extend(struct.pack("<HH", 1, 64))
    output.extend(bytes((role, kind)))
    output.extend(b"\0\0")
    output.extend(struct.pack("<I", 1))
    output.extend(CEREMONY_ID)
    output.extend(struct.pack("<III", capacity, payload_length, state))
    output.extend(b"\0" * 20)
    if len(output) != 64:
        raise AssertionError("control header is not 64 bytes")
    return bytes(output)


def vectors() -> dict[str, bytes]:
    """Return all independently encoded public owner-bridge V1 fixtures."""
    authenticator_data = bytes(range(0x25))
    return {
        "create_options": cbor(
            [
                b"WCR1",
                1,
                CEREMONY_ID,
                CHALLENGE,
                USER_HANDLE,
                "localhost",
                "PiglorOS",
                -7,
                0,
                0,
                PRF_INPUT,
            ]
        ),
        "get_options": cbor(
            [
                b"WGR1",
                1,
                CEREMONY_ID,
                CHALLENGE,
                "localhost",
                CREDENTIAL_ID,
                0,
                PRF_INPUT,
            ]
        ),
        "attestation_reply": cbor(
            [
                b"WAR1",
                1,
                CEREMONY_ID,
                CREDENTIAL_ID,
                b"{}",
                b"\xa0",
                [0],
                True,
                PRF_RESULT,
                None,
            ]
        ),
        "assertion_reply": cbor(
            [
                b"WAS1",
                1,
                CEREMONY_ID,
                CREDENTIAL_ID,
                b"{}",
                authenticator_data,
                bytes(range(0x30, 0x38)),
                None,
                PRF_RESULT,
                None,
            ]
        ),
        "request_header": control_header(0, 0, 4096, 148, 2),
        "ready_reply_header": control_header(1, 1, 8192, 114, 2),
        "subject_credential_binding": cbor(
            [
                b"SCB1",
                1,
                "owner",
                SUBJECT_ID,
                0,
                1,
                "localhost",
                "http://localhost:49291",
                CREDENTIAL_ID,
                USER_HANDLE,
                COSE_ES256_KEY,
                0,
                False,
                False,
                7,
                [0],
            ]
        ),
        "cleanup_record": cbor(
            [
                b"PBCR",
                1,
                CEREMONY_ID,
                "owner-bridge-1",
                7,
                0x0102_0304_0506_0708,
                PRF_RESULT,
            ]
        ),
    }


def check() -> None:
    """Fail closed if an independently generated byte vector drifts."""
    actual = vectors()
    if set(actual) != set(EXPECTED):
        raise AssertionError("owner-bridge vector names drifted")
    for name, encoded in actual.items():
        expected = bytes.fromhex(EXPECTED[name])
        if encoded != expected:
            raise AssertionError(
                f"{name} mismatch: expected {expected.hex()}, got {encoded.hex()}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify all committed vectors")
    parser.parse_args()
    check()
    print("owner-bridge vectors: ALL MATCH")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
