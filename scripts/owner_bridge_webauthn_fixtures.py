#!/usr/bin/env python3
"""Generate the portable closed-ES256 WebAuthn fixture for ADR-110.

The generator is deliberately stdlib-only and does not invoke Rust.  It
implements the small P-256/RFC-6979 signing subset needed to produce a public
test fixture for the owner-bridge verifier.  The fixture private scalar is
``d = 1`` and is test data only; it is never a deployment credential.

Usage:
    python3 scripts/owner_bridge_webauthn_fixtures.py --check
    python3 scripts/owner_bridge_webauthn_fixtures.py --print
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_PATH = ROOT / "fixtures/owner-bridge/webauthn-es256-v1.fixture"

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
PRIVATE_SCALAR = 1

CEREMONY_ID = bytes(range(0x00, 0x10))
CHALLENGE = bytes(range(0x20, 0x40))
CREDENTIAL_ID = bytes((0x80, 0x81))
USER_HANDLE = bytes(range(0x40, 0x60))
PRF_FIRST = bytes(range(0xA0, 0xC0))
RP_ID_HASH = hashlib.sha256(b"localhost").digest()
CREATE_CLIENT_DATA = (
    b'{"type":"webauthn.create","challenge":"'
    + base64.urlsafe_b64encode(CHALLENGE).rstrip(b"=")
    + b'","origin":"http://localhost:49291"}'
)
ASSERTION_CLIENT_DATA = (
    b'{"type":"webauthn.get","challenge":"'
    + base64.urlsafe_b64encode(CHALLENGE).rstrip(b"=")
    + b'","origin":"http://localhost:49291"}'
)

Point = tuple[int, int] | None


def _point_add(left: Point, right: Point) -> Point:
    if left is None:
        return right
    if right is None:
        return left
    x_left, y_left = left
    x_right, y_right = right
    if x_left == x_right:
        if (y_left + y_right) % P == 0:
            return None
        slope = (3 * x_left * x_left + A) * pow(2 * y_left, -1, P) % P
    else:
        slope = (y_right - y_left) * pow(x_right - x_left, -1, P) % P
    x_result = (slope * slope - x_left - x_right) % P
    y_result = (slope * (x_left - x_result) - y_left) % P
    return x_result, y_result


def _scalar_multiply(scalar: int, point: Point) -> Point:
    result: Point = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _rfc6979_nonce(private_scalar: int, digest: bytes) -> int:
    """Return one RFC-6979 SHA-256 nonce for a P-256 scalar and digest."""
    if len(digest) != 32:
        raise ValueError("P-256 fixture digest must be exactly 32 bytes")
    private_bytes = private_scalar.to_bytes(32, "big")
    digest_value = int.from_bytes(digest, "big")
    digest_bytes = (digest_value % N).to_bytes(32, "big")
    value = b"\x01" * 32
    key = b"\x00" * 32
    key = hmac.new(key, value + b"\x00" + private_bytes + digest_bytes, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    key = hmac.new(key, value + b"\x01" + private_bytes + digest_bytes, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    while True:
        value = hmac.new(key, value, hashlib.sha256).digest()
        candidate = int.from_bytes(value, "big")
        if 1 <= candidate < N:
            return candidate
        key = hmac.new(key, value + b"\x00", hashlib.sha256).digest()
        value = hmac.new(key, value, hashlib.sha256).digest()


def _der_integer(value: int) -> bytes:
    encoded = value.to_bytes(32, "big").lstrip(b"\0") or b"\0"
    if encoded[0] & 0x80:
        encoded = b"\0" + encoded
    return b"\x02" + bytes((len(encoded),)) + encoded


def ecdsa_signature_values(message: bytes) -> tuple[int, int]:
    """Return deterministic P-256 ECDSA values for one fixture message."""
    digest = hashlib.sha256(message).digest()
    nonce = _rfc6979_nonce(PRIVATE_SCALAR, digest)
    point = _scalar_multiply(nonce, (GX, GY))
    if point is None:
        raise AssertionError("RFC-6979 nonce unexpectedly produced infinity")
    r_value = point[0] % N
    if r_value == 0:
        raise AssertionError("RFC-6979 nonce unexpectedly produced r = 0")
    digest_value = int.from_bytes(digest, "big")
    s_value = pow(nonce, -1, N) * (digest_value + r_value * PRIVATE_SCALAR) % N
    if s_value == 0:
        raise AssertionError("RFC-6979 nonce unexpectedly produced s = 0")
    return r_value, s_value


def ecdsa_der_signature(r_value: int, s_value: int) -> bytes:
    """Encode the supplied valid P-256 ECDSA values as strict DER."""
    if not 0 < r_value < N or not 0 < s_value < N:
        raise ValueError("P-256 ECDSA values must be in the scalar range")
    body = _der_integer(r_value) + _der_integer(s_value)
    return b"\x30" + bytes((len(body),)) + body


def canonical_cose_es256_key() -> bytes:
    """Return the closed canonical EC2/ES256 map for the published fixture key."""
    point = _scalar_multiply(PRIVATE_SCALAR, (GX, GY))
    if point != (GX, GY):
        raise AssertionError("fixture scalar does not derive P-256 generator")
    return (
        b"\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20"
        + GX.to_bytes(32, "big")
        + b"\x22\x58\x20"
        + GY.to_bytes(32, "big")
    )


def attestation_object(cose_key: bytes) -> bytes:
    """Construct the closed `none` attestation object for this fixture."""
    authenticator_data = (
        RP_ID_HASH
        + b"\x45"
        + (0).to_bytes(4, "big")
        + b"\0" * 16
        + len(CREDENTIAL_ID).to_bytes(2, "big")
        + CREDENTIAL_ID
        + cose_key
    )
    return (
        b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData\x58"
        + bytes((len(authenticator_data),))
        + authenticator_data
    )


def fixture_fields() -> dict[str, str]:
    """Build every textual field consumed by the public Rust fixture test."""
    cose_key = canonical_cose_es256_key()
    assertion_authenticator_data = RP_ID_HASH + b"\x05" + (1).to_bytes(4, "big")
    assertion_message = assertion_authenticator_data + hashlib.sha256(ASSERTION_CLIENT_DATA).digest()
    r_value, s_value = ecdsa_signature_values(assertion_message)
    signature = ecdsa_der_signature(r_value, s_value)
    high_s_signature = ecdsa_der_signature(r_value, N - s_value)
    return {
        "version": "1",
        "ceremony_id": CEREMONY_ID.hex(),
        "challenge": CHALLENGE.hex(),
        "credential_id": CREDENTIAL_ID.hex(),
        "user_handle": USER_HANDLE.hex(),
        "create_client_data_json": CREATE_CLIENT_DATA.hex(),
        "attestation_object": attestation_object(cose_key).hex(),
        "assertion_client_data_json": ASSERTION_CLIENT_DATA.hex(),
        "assertion_authenticator_data": assertion_authenticator_data.hex(),
        "assertion_signature_der": signature.hex(),
        "assertion_signature_high_s_der": high_s_signature.hex(),
        "public_key_cose": cose_key.hex(),
        "backup_eligible": "false",
        "backup_state": "false",
        "stored_sign_count": "0",
        "assertion_sign_count": "1",
        "prf_first": PRF_FIRST.hex(),
    }


def fixture_text() -> str:
    """Render the stable line-oriented fixture without a JSON dependency."""
    fields = fixture_fields()
    lines = [
        "# Generated by scripts/owner_bridge_webauthn_fixtures.py; do not edit.",
        "# Test-only P-256 scalar d = 1; never a deployment credential.",
    ]
    lines.extend(f"{name}={value}" for name, value in fields.items())
    return "\n".join(lines) + "\n"


def check() -> None:
    """Fail closed when the committed portable fixture drifts."""
    expected = fixture_text()
    actual = FIXTURE_PATH.read_text(encoding="utf-8")
    if actual != expected:
        raise AssertionError(
            "owner-bridge WebAuthn fixture drifted; regenerate from the independent script"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify the committed fixture")
    parser.add_argument("--print", action="store_true", help="print the generated fixture")
    arguments = parser.parse_args()
    if arguments.print:
        print(fixture_text(), end="")
    if arguments.check:
        check()
        print("owner-bridge WebAuthn fixture: ALL MATCH")
    if not arguments.check and not arguments.print:
        parser.error("choose --check or --print")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
