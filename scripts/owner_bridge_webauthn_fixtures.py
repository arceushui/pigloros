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

from owner_bridge_vectors import cbor

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_PATH = ROOT / "fixtures/owner-bridge/webauthn-es256-v1.fixture"
REASONS_PATH = ROOT / "fixtures/owner-bridge/webauthn-reasons-v1.fixture"

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


def cbor_map(pairs: list[tuple[object, object]]) -> bytes:
    """Encode a definite map of at most 23 entries from the vector encoder."""
    if len(pairs) > 23:
        raise ValueError("fixture maps are limited to 23 entries")
    body = b"".join(cbor(key) + cbor(value) for key, value in pairs)
    return bytes((0xA0 | len(pairs),)) + body


CHALLENGE_B64 = base64.urlsafe_b64encode(CHALLENGE).rstrip(b"=").decode("ascii")
ORIGIN = "http://localhost:49291"
GENERATOR_X = GX.to_bytes(32, "big")
GENERATOR_Y = GY.to_bytes(32, "big")
OTHER_HANDLE = bytes(range(0x60, 0x80))
OTHER_CREDENTIAL_ID = bytes((0x82, 0x83))
OTHER_CEREMONY_ID = bytes(range(0x10, 0x20))


def client_json(members: list[tuple[str, str]]) -> bytes:
    """Render clientDataJSON from already-JSON-encoded member values."""
    return ("{" + ",".join(f'"{key}":{value}' for key, value in members) + "}").encode()


def client_members(kind: str) -> dict[str, str]:
    """Return the baseline clientDataJSON members for one ceremony kind."""
    return {
        "type": f'"webauthn.{kind}"',
        "challenge": f'"{CHALLENGE_B64}"',
        "origin": f'"{ORIGIN}"',
    }


def client_variant(kind: str, change: dict[str, str | None], extra: str = "") -> bytes:
    """Return baseline client data with members replaced, removed or appended."""
    members = client_members(kind)
    for key, value in change.items():
        if value is None:
            del members[key]
        else:
            members[key] = value
    pairs = list(members.items())
    return client_json(pairs) if not extra else client_json(pairs)[:-1] + extra.encode() + b"}"


def cose_key(
    kty: int = 2,
    algorithm: int = -7,
    curve: int = 1,
    x_coordinate: bytes = GENERATOR_X,
    y_coordinate: bytes = GENERATOR_Y,
) -> bytes:
    """Encode a COSE EC2 key map with selectable (possibly wrong) members."""
    return cbor_map(
        [(1, kty), (3, algorithm), (-1, curve), (-2, x_coordinate), (-3, y_coordinate)]
    )


def create_auth_data(
    flags: int = 0x45,
    credential_id: bytes = CREDENTIAL_ID,
    key: bytes | None = None,
    suffix: bytes = b"",
    rp_id_hash: bytes = RP_ID_HASH,
    length: int | None = None,
) -> bytes:
    """Build Create authenticator data with attested credential data."""
    key = canonical_cose_es256_key() if key is None else key
    credential_length = len(credential_id) if length is None else length
    return (
        rp_id_hash
        + bytes((flags,))
        + (0).to_bytes(4, "big")
        + b"\0" * 16
        + credential_length.to_bytes(2, "big")
        + credential_id
        + key
        + suffix
    )


def attestation(
    auth_data: bytes,
    fmt: str = "none",
    statement: bytes = b"\xa0",
    field: str = "authData",
) -> bytes:
    """Build a three-member attestation object around authenticator data."""
    return (
        b"\xa3"
        + cbor("fmt")
        + cbor(fmt)
        + cbor("attStmt")
        + statement
        + cbor(field)
        + cbor(auth_data)
    )


def get_auth_data(
    flags: int = 0x05,
    counter: int = 1,
    suffix: bytes = b"",
    rp_id_hash: bytes = RP_ID_HASH,
) -> bytes:
    """Build Get authenticator data."""
    return rp_id_hash + bytes((flags,)) + counter.to_bytes(4, "big") + suffix


def sign(auth_data: bytes, client_data: bytes) -> bytes:
    """Sign authenticator data and client data with the fixture scalar."""
    message = auth_data + hashlib.sha256(client_data).digest()
    return ecdsa_der_signature(*ecdsa_signature_values(message))


def corrupted(signature: bytes) -> bytes:
    """Flip one bit inside the DER r integer so the signature stays well formed."""
    return signature[:10] + bytes((signature[10] ^ 1,)) + signature[11:]


def create_case(reason: str, **fields: bytes | str) -> dict[str, str]:
    """Return one Create case; omitted fields use the baseline fixture."""
    return {"kind": "create", "reason": reason} | _hex_fields(fields)


def get_case(reason: str, **fields: bytes | str) -> dict[str, str]:
    """Return one Get case whose signature is valid unless the field overrides it."""
    return {"kind": "get", "reason": reason} | _hex_fields(fields)


def get_signed_case(
    reason: str,
    auth_data: bytes,
    client_data: bytes | None = None,
    **fields: bytes | str,
) -> dict[str, str]:
    """Return a Get case re-signed over its own authenticator and client data."""
    signed_client = ASSERTION_CLIENT_DATA if client_data is None else client_data
    return get_case(
        reason,
        authenticator_data=auth_data,
        client_data_json=signed_client,
        signature=sign(auth_data, signed_client),
        **fields,
    )


def decode_case(reason: str, kind: str, payload: bytes) -> dict[str, str]:
    """Return one payload-decoding case, reported as a decode-time reason."""
    return {"kind": f"decode_{kind}", "reason": reason, "payload": payload.hex()}


def _hex_fields(fields: dict[str, bytes | str]) -> dict[str, str]:
    return {
        name: value.hex() if isinstance(value, bytes) else value
        for name, value in fields.items()
    }


def create_cases() -> dict[str, dict[str, str]]:
    """Return one Create case per verifier fault that is not Get specific."""
    base_flags = 0x45
    ext_flag = 0xC5
    return {
        "create_ceremony_id": create_case(
            "CeremonyIdMismatch", reply_ceremony_id=OTHER_CEREMONY_ID
        ),
        "create_prf_unsupported": create_case("PrfUnsupported", prf_enabled="false"),
        "create_origin_wrong": create_case(
            "Origin",
            client_data_json=client_variant("create", {"origin": '"http://localhost:49292"'}),
        ),
        "create_origin_missing": create_case(
            "Origin", client_data_json=client_variant("create", {"origin": None})
        ),
        "create_type_wrong": create_case(
            "ClientDataType",
            client_data_json=client_variant("create", {"type": '"webauthn.get"'}),
        ),
        "create_type_not_string": create_case(
            "ClientDataType", client_data_json=client_variant("create", {"type": "true"})
        ),
        "create_type_missing": create_case(
            "ClientDataType", client_data_json=client_variant("create", {"type": None})
        ),
        "create_challenge_wrong": create_case(
            "Challenge",
            client_data_json=client_variant(
                "create", {"challenge": '"' + "A" * 43 + '"'}
            ),
        ),
        "create_challenge_escaped": create_case(
            "Challenge",
            client_data_json=client_variant(
                "create", {"challenge": '"\\u0049' + CHALLENGE_B64[1:] + '"'}
            ),
        ),
        "create_challenge_missing": create_case(
            "Challenge", client_data_json=client_variant("create", {"challenge": None})
        ),
        "create_cross_origin_true": create_case(
            "CrossOrigin",
            client_data_json=client_variant("create", {}, extra=',"crossOrigin":true'),
        ),
        "create_top_origin_present": create_case(
            "CrossOrigin",
            client_data_json=client_variant(
                "create", {}, extra=',"topOrigin":"https://example.test"'
            ),
        ),
        "create_token_binding_present": create_case(
            "CrossOrigin",
            client_data_json=client_variant("create", {}, extra=',"tokenBinding":"present"'),
        ),
        "create_nested_member": create_case(
            "Malformed",
            client_data_json=client_variant(
                "create", {}, extra=',"tokenBinding":{"status":"present"}'
            ),
        ),
        "create_client_data_duplicate_key": create_case(
            "Malformed",
            client_data_json=client_variant("create", {}, extra=f',"origin":"{ORIGIN}"'),
        ),
        "create_client_data_not_object": create_case("Malformed", client_data_json=b"[]"),
        "create_rp_id_hash_wrong": create_case(
            "RpIdHash",
            attestation_object=attestation(
                create_auth_data(rp_id_hash=hashlib.sha256(b"example.test").digest())
            ),
        ),
        "create_user_presence_missing": create_case(
            "UserPresence", attestation_object=attestation(create_auth_data(flags=0x44))
        ),
        "create_user_verification_missing": create_case(
            "UserVerification", attestation_object=attestation(create_auth_data(flags=0x41))
        ),
        "create_reserved_flag": create_case(
            "Malformed", attestation_object=attestation(create_auth_data(flags=0x47))
        ),
        "create_backup_state_without_eligibility": create_case(
            "BackupFlags", attestation_object=attestation(create_auth_data(flags=0x55))
        ),
        "create_attested_data_flag_missing": create_case(
            "Malformed",
            attestation_object=attestation(get_auth_data(flags=0x05, counter=0)),
        ),
        "create_attestation_format_packed": create_case(
            "AttestationFormat",
            attestation_object=attestation(create_auth_data(), fmt="packed"),
        ),
        "create_attestation_statement_not_empty": create_case(
            "AttestationFormat",
            attestation_object=attestation(create_auth_data(), statement=b"\xa1\x61a\x01"),
        ),
        "create_attestation_unknown_member": create_case(
            "AttestationFormat",
            attestation_object=attestation(create_auth_data(), field="other"),
        ),
        "create_credential_id_mismatch": create_case(
            "CredentialMismatch",
            attestation_object=attestation(create_auth_data(credential_id=OTHER_CREDENTIAL_ID)),
        ),
        "create_credential_length_zero": create_case(
            "Malformed", attestation_object=attestation(create_auth_data(length=0))
        ),
        "create_algorithm_eddsa": create_case(
            "Algorithm",
            attestation_object=attestation(
                create_auth_data(
                    key=cbor_map([(1, 1), (3, -8), (-1, 6), (-2, GENERATOR_X)]),
                )
            ),
        ),
        "create_algorithm_rs256": create_case(
            "Algorithm",
            attestation_object=attestation(create_auth_data(key=cose_key(algorithm=-257))),
        ),
        "create_cose_key_type_wrong": create_case(
            "CoseKey", attestation_object=attestation(create_auth_data(key=cose_key(kty=1)))
        ),
        "create_cose_curve_wrong": create_case(
            "CoseKey", attestation_object=attestation(create_auth_data(key=cose_key(curve=2)))
        ),
        "create_cose_coordinate_short": create_case(
            "CoseKey",
            attestation_object=attestation(
                create_auth_data(key=cose_key(x_coordinate=GENERATOR_X[:31]))
            ),
        ),
        "create_cose_point_invalid": create_case(
            "CoseKey",
            attestation_object=attestation(
                create_auth_data(key=cose_key(x_coordinate=bytes(32), y_coordinate=bytes(32)))
            ),
        ),
        "create_extensions_trailing_bytes": create_case(
            "Extensions",
            attestation_object=attestation(create_auth_data(flags=base_flags, suffix=b"\x00")),
        ),
        "create_extensions_missing_map": create_case(
            "Extensions", attestation_object=attestation(create_auth_data(flags=ext_flag))
        ),
        "create_extensions_duplicate_key": create_case(
            "Extensions",
            attestation_object=attestation(
                create_auth_data(flags=ext_flag, suffix=b"\xa2\x61a\x01\x61a\x02")
            ),
        ),
        "create_extensions_integer_key": create_case(
            "Extensions",
            attestation_object=attestation(
                create_auth_data(flags=ext_flag, suffix=b"\xa1\x01\x01")
            ),
        ),
        "create_extensions_too_many_entries": create_case(
            "Extensions",
            attestation_object=attestation(
                create_auth_data(
                    flags=ext_flag,
                    suffix=bytes((0xB1,))
                    + b"".join(cbor(chr(0x61 + index)) + cbor(0) for index in range(17)),
                )
            ),
        ),
    }


def get_cases() -> dict[str, dict[str, str]]:
    """Return one Get case per verifier fault, each validly signed up to that fault."""
    return {
        "get_ceremony_id": get_case("CeremonyIdMismatch", reply_ceremony_id=OTHER_CEREMONY_ID),
        "get_credential_mismatch": get_case("CredentialMismatch", raw_id=OTHER_CREDENTIAL_ID),
        "get_origin_wrong": get_signed_case(
            "Origin",
            get_auth_data(),
            client_variant("get", {"origin": '"http://localhost:49292"'}),
        ),
        "get_type_wrong": get_signed_case(
            "ClientDataType",
            get_auth_data(),
            client_variant("get", {"type": '"webauthn.create"'}),
        ),
        "get_challenge_wrong": get_signed_case(
            "Challenge",
            get_auth_data(),
            client_variant("get", {"challenge": '"' + "B" * 43 + '"'}),
        ),
        "get_cross_origin_true": get_signed_case(
            "CrossOrigin",
            get_auth_data(),
            client_variant("get", {}, extra=',"crossOrigin":true'),
        ),
        "get_rp_id_hash_wrong": get_signed_case(
            "RpIdHash",
            get_auth_data(rp_id_hash=hashlib.sha256(b"example.test").digest()),
        ),
        "get_user_presence_missing": get_signed_case("UserPresence", get_auth_data(flags=0x04)),
        "get_user_verification_missing": get_signed_case(
            "UserVerification", get_auth_data(flags=0x01)
        ),
        "get_attested_data_flag_set": get_signed_case("Malformed", get_auth_data(flags=0x45)),
        "get_backup_state_without_eligibility": get_signed_case(
            "BackupFlags", get_auth_data(flags=0x15)
        ),
        "get_backup_eligibility_changed": get_signed_case(
            "BackupFlags", get_auth_data(flags=0x0D)
        ),
        "get_extensions_not_a_map": get_signed_case(
            "Extensions", get_auth_data(flags=0x85, suffix=b"\x01")
        ),
        "get_extensions_trailing_bytes": get_signed_case(
            "Extensions", get_auth_data(suffix=b"\x00")
        ),
        "get_user_handle_mismatch": get_case("UserHandleMismatch", user_handle=OTHER_HANDLE),
        "get_counter_equal": get_signed_case(
            "CounterRegression", get_auth_data(counter=5), stored_sign_count="5"
        ),
        "get_counter_lower": get_signed_case(
            "CounterRegression", get_auth_data(counter=4), stored_sign_count="5"
        ),
        "get_counter_zero_after_nonzero": get_signed_case(
            "CounterRegression", get_auth_data(counter=0), stored_sign_count="1"
        ),
        "get_signature_invalid": get_case(
            "Signature", signature=corrupted(sign(get_auth_data(), ASSERTION_CLIENT_DATA))
        ),
        "get_signature_not_der": get_case("Signature", signature=bytes(8)),
        "get_signature_other_message": get_case(
            "Signature", signature=sign(get_auth_data(counter=2), ASSERTION_CLIENT_DATA)
        ),
    }


def decode_cases() -> dict[str, dict[str, str]]:
    """Return reply payloads whose PRF or user-handle shape fails while decoding."""
    attestation_fields = [
        b"WAR1", 1, CEREMONY_ID, CREDENTIAL_ID, b"{}", b"\xa0", [0], True, PRF_FIRST, None
    ]
    assertion_fields = [
        b"WAS1", 1, CEREMONY_ID, CREDENTIAL_ID, b"{}", bytes(37), bytes(8), None, PRF_FIRST, None
    ]

    def replace(fields: list[object], index: int, value: object) -> bytes:
        return cbor(fields[:index] + [value] + fields[index + 1 :])

    return {
        "decode_create_prf_short": decode_case(
            "PrfMalformed", "attestation", replace(attestation_fields, 8, PRF_FIRST[:31])
        ),
        "decode_create_prf_not_bytes": decode_case(
            "PrfMalformed", "attestation", replace(attestation_fields, 8, 7)
        ),
        "decode_create_prf_second_present": decode_case(
            "PrfMalformed", "attestation", replace(attestation_fields, 9, PRF_FIRST)
        ),
        "decode_get_prf_short": decode_case(
            "PrfMalformed", "assertion", replace(assertion_fields, 8, PRF_FIRST[:31])
        ),
        "decode_get_prf_null": decode_case(
            "PrfAbsent", "assertion", replace(assertion_fields, 8, None)
        ),
        "decode_get_prf_second_present": decode_case(
            "PrfMalformed", "assertion", replace(assertion_fields, 9, PRF_FIRST)
        ),
        "decode_get_user_handle_short": decode_case(
            "UserHandleMismatch", "assertion", replace(assertion_fields, 7, USER_HANDLE[:31])
        ),
        "decode_get_user_handle_empty": decode_case(
            "UserHandleMismatch", "assertion", replace(assertion_fields, 7, b"")
        ),
        "decode_get_user_handle_not_bytes": decode_case(
            "UserHandleMismatch", "assertion", replace(assertion_fields, 7, 7)
        ),
    }


def reasons_text() -> str:
    """Render the line-oriented per-reason fixture cases."""
    cases = create_cases() | get_cases() | decode_cases()
    lines = [
        "# Generated by scripts/owner_bridge_webauthn_fixtures.py; do not edit.",
        "# Each case differs from the baseline fixture in exactly one verifier fault.",
        "version=1",
    ]
    for name, fields in cases.items():
        lines.append(f"case={name}")
        lines.extend(f"{name}.{field}={value}" for field, value in fields.items())
    return "\n".join(lines) + "\n"


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
    for path, expected in ((FIXTURE_PATH, fixture_text()), (REASONS_PATH, reasons_text())):
        actual = path.read_text(encoding="utf-8")
        if actual != expected:
            raise AssertionError(
                f"{path.name} drifted; regenerate from the independent script"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify the committed fixture")
    parser.add_argument("--print", action="store_true", help="print the generated fixture")
    arguments = parser.parse_args()
    if arguments.print:
        print(fixture_text(), end="")
        print(reasons_text(), end="")
    if arguments.check:
        check()
        print("owner-bridge WebAuthn fixture: ALL MATCH")
    if not arguments.check and not arguments.print:
        parser.error("choose --check or --print")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
