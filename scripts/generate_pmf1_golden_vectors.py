#!/usr/bin/env python3
"""Independently generate the golden PMF1 V1 release closure (ADR-061 r3).

This generator shares no code with `pos-crypto`. It encodes one complete
canonical 28-field PMF1 V1 manifest with its own deterministic CBOR encoder,
computes every inner BLAKE3 domain digest with a pure-Python BLAKE3, the raw
SHA-256 of every member with `hashlib`, the unsigned manifest and release
digests, the complete-PMF1 digest, the ADR-103 descriptor digest set, and the
ADR-102 JCS OCI manifest. It writes the Rust constants consumed by
`crates/pos-crypto/tests/plugin_manifest_public.rs`.

Usage:
    python3 scripts/generate_pmf1_golden_vectors.py          # rewrite
    python3 scripts/generate_pmf1_golden_vectors.py --check  # verify
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

OUTPUT = (
    Path(__file__).resolve().parent.parent
    / "crates/pos-crypto/tests/support/pmf1_golden_vectors.rs"
)

# --- Pure-Python BLAKE3 (unkeyed hash mode, 32-byte output) -----------------

IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
CHUNK_START = 1
CHUNK_END = 2
PARENT = 4
ROOT = 8
BLOCK_LEN = 64
CHUNK_LEN = 1024
MASK = 0xFFFFFFFF


def _rotr(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & MASK


def _g(state: list[int], a: int, b: int, c: int, d: int, mx: int, my: int) -> None:
    state[a] = (state[a] + state[b] + mx) & MASK
    state[d] = _rotr(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = _rotr(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + my) & MASK
    state[d] = _rotr(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = _rotr(state[b] ^ state[c], 7)


def _round(state: list[int], m: list[int]) -> None:
    _g(state, 0, 4, 8, 12, m[0], m[1])
    _g(state, 1, 5, 9, 13, m[2], m[3])
    _g(state, 2, 6, 10, 14, m[4], m[5])
    _g(state, 3, 7, 11, 15, m[6], m[7])
    _g(state, 0, 5, 10, 15, m[8], m[9])
    _g(state, 1, 6, 11, 12, m[10], m[11])
    _g(state, 2, 7, 8, 13, m[12], m[13])
    _g(state, 3, 4, 9, 14, m[14], m[15])


def _compress(cv, block_words, counter: int, block_len: int, flags: int) -> list[int]:
    state = list(cv) + list(IV[:4]) + [
        counter & MASK,
        (counter >> 32) & MASK,
        block_len,
        flags,
    ]
    m = list(block_words)
    for round_index in range(7):
        _round(state, m)
        if round_index < 6:
            m = [m[index] for index in MSG_PERMUTATION]
    for index in range(8):
        state[index] ^= state[index + 8]
        state[index + 8] ^= cv[index]
    return state


def _words(block: bytes) -> list[int]:
    return list(struct.unpack("<16I", block.ljust(BLOCK_LEN, b"\0")))


def _chunk_output(chunk: bytes, counter: int):
    """Return (cv, last block words, block length, flags) before finalization."""
    cv = list(IV)
    blocks = [chunk[i : i + BLOCK_LEN] for i in range(0, len(chunk), BLOCK_LEN)] or [b""]
    for index, block in enumerate(blocks):
        flags = (CHUNK_START if index == 0 else 0) | (
            CHUNK_END if index == len(blocks) - 1 else 0
        )
        if index == len(blocks) - 1:
            return cv, _words(block), counter, len(block), flags
        cv = _compress(cv, _words(block), counter, BLOCK_LEN, flags)[:8]
    raise AssertionError("unreachable")


def _parent_output(left: list[int], right: list[int]):
    return list(IV), left + right, 0, BLOCK_LEN, PARENT


def _cv(output) -> list[int]:
    cv, words, counter, block_len, flags = output
    return _compress(cv, words, counter, block_len, flags)[:8]


def blake3(data: bytes) -> bytes:
    chunks = [data[i : i + CHUNK_LEN] for i in range(0, len(data), CHUNK_LEN)] or [b""]
    stack: list[list[int]] = []
    for counter, chunk in enumerate(chunks[:-1]):
        cv = _cv(_chunk_output(chunk, counter))
        total = counter + 1
        while total & 1 == 0:
            cv = _cv(_parent_output(stack.pop(), cv))
            total >>= 1
        stack.append(cv)
    output = _chunk_output(chunks[-1], len(chunks) - 1)
    while stack:
        output = _parent_output(stack.pop(), _cv(output))
    cv, words, counter, block_len, flags = output
    state = _compress(cv, words, counter, block_len, flags | ROOT)
    return struct.pack("<8I", *state[:8])


# --- Strict deterministic CBOR encoder ---------------------------------------


def _head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([major << 5 | value])
    for width, code in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if value < 1 << (8 * width):
            return bytes([major << 5 | code]) + value.to_bytes(width, "big")
    raise ValueError("CBOR argument too large")


def cbor(value) -> bytes:
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
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(cbor(item) for item in value)
    raise TypeError(type(value))


# --- Golden release ----------------------------------------------------------

WORLD = "pigloros:plugin/community-plugin@0.1.0"
SCHEMA_MEDIA_TYPE = "application/vnd.pigloros.plugin.schema.v1+json"
# role: (ADR-102 media type, ADR-061 r3 inner BLAKE3 domain)
ROLES = {
    "component": (
        "application/vnd.pigloros.plugin.component.v1+wasm",
        b"PiglorOS.Plugin.Component.v1\0",
    ),
    "wit": ("application/vnd.pigloros.plugin.wit.v1+tar", b"PiglorOS.Plugin.WITArchive.v1\0"),
    "schema": (SCHEMA_MEDIA_TYPE, b"PiglorOS.Plugin.Schema.v1\0"),
    "provenance": ("application/vnd.in-toto+json", b"PiglorOS.Plugin.Provenance.v1\0"),
    "sbom": ("application/spdx+json", b"PiglorOS.Plugin.SBOM.v1\0"),
    "licence": ("text/plain; charset=utf-8", b"PiglorOS.Plugin.Licence.v1\0"),
}
PMF1_MEDIA_TYPE = "application/vnd.pigloros.plugin.manifest.v1+cbor"
EMPTY_CONFIG_DIGEST = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"

BLOBS = {
    "component": b"\0asm golden community-plugin component",
    "wit": b"golden WIT archive: package pigloros:plugin@0.1.0",
    "event-a": b'{"$id":"golden-event-a","type":"object"}',
    "event-b": b'{"$id":"golden-event-b","type":"object"}',
    "state": b'{"$id":"golden-state","type":"object"}',
    "configuration": b'{"$id":"golden-configuration","type":"object"}',
    "provenance": b'{"_type":"https://in-toto.io/Statement/v1","golden":true}',
    "sbom": b'{"spdxVersion":"SPDX-2.3","name":"golden"}',
    "licence-a": b"Apache-2.0 golden licence text",
    "licence-b": b"MIT golden licence text",
}
DEPENDENCY_RELEASE = bytes([0x42]) * 32
PREVIOUS_RELEASE = bytes([0x24]) * 32
SIGNATURE = bytes([0x5A]) * 64


def inner(role: str, data: bytes) -> bytes:
    domain = ROLES[role][1]
    return blake3(domain + len(data).to_bytes(8, "big") + data)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def descriptor(role: str, data: bytes) -> list:
    return [ROLES[role][0], len(data), inner(role, data), sha256(data)]


def schema(schema_id: int, version: int, name: str, max_bytes: int) -> list:
    return [schema_id, version, descriptor("schema", BLOBS[name]), max_bytes]


def golden_fields() -> list:
    licences = sorted(
        (descriptor("licence", BLOBS[name]) for name in ("licence-a", "licence-b")),
        key=lambda item: item[3],
    )
    return [
        "PMF1",
        1,
        "alpha/plugin",
        "1.2.3-rc.1",
        WORLD,
        0,
        1,
        3,
        ["clock.v1", "log"],
        descriptor("component", BLOBS["component"]),
        descriptor("wit", BLOBS["wit"]),
        [schema(1, 1, "event-a", 4096), schema(7, 2, "event-b", 4096)],
        schema(100, 1, "state", 65536),
        schema(200, 1, "configuration", 1024),
        [
            ["kv", "read", "state/*", "Read Plugin state", "plugin", True, 24, 1024, 2048],
            ["kv", "write", "state/*", "Write Plugin state", "plugin", False, 10, 2048, 0],
        ],
        [1_048_576, 1 << 40, 1000, 16, 4096, 65536, 24, 2048],
        [],
        [
            [
                "beta/lib",
                DEPENDENCY_RELEASE,
                WORLD,
                0,
                0,
                2,
                ["clock.v1"],
                ["kv"],
                1,
            ]
        ],
        descriptor("provenance", BLOBS["provenance"]),
        descriptor("sbom", BLOBS["sbom"]),
        licences,
        "publisher",
        -100,
        100,
        PREVIOUS_RELEASE,
    ]


def golden_release():
    fields = golden_fields()
    unsigned = cbor(fields)
    manifest_digest = blake3(
        b"PiglorOS.Plugin.Manifest.v1\0" + len(unsigned).to_bytes(8, "big") + unsigned
    )
    release_digest = blake3(
        b"PiglorOS.Plugin.Release.v1\0"
        + manifest_digest
        + fields[9][2]
        + fields[10][2]
    )
    complete = cbor(fields + [manifest_digest, [1, 3, 9, SIGNATURE], release_digest])
    return fields, complete, manifest_digest, release_digest


def oci_layers(complete: bytes) -> tuple[list[dict], dict[str, bytes]]:
    members = [
        ("component", "component", BLOBS["component"]),
        ("wit", "wit", BLOBS["wit"]),
    ]
    schema_blobs = sorted(
        (BLOBS[name] for name in ("event-a", "event-b", "state", "configuration")),
        key=sha256,
    )
    members += [("schema/" + sha256(blob).hex(), "schema", blob) for blob in schema_blobs]
    members += [
        ("provenance", "provenance", BLOBS["provenance"]),
        ("sbom", "sbom", BLOBS["sbom"]),
    ]
    licence_blobs = sorted((BLOBS["licence-a"], BLOBS["licence-b"]), key=sha256)
    members += [("licence/" + sha256(blob).hex(), "licence", blob) for blob in licence_blobs]
    layers = [
        {
            "annotations": {"org.pigloros.plugin.member": "pmf1"},
            "digest": "sha256:" + sha256(complete).hex(),
            "mediaType": PMF1_MEDIA_TYPE,
            "size": len(complete),
        }
    ]
    blobs = {"sha256:" + sha256(complete).hex(): complete, EMPTY_CONFIG_DIGEST: b"{}"}
    for annotation, role, blob in members:
        digest = "sha256:" + sha256(blob).hex()
        layers.append(
            {
                "annotations": {"org.pigloros.plugin.member": annotation},
                "digest": digest,
                "mediaType": ROLES[role][0],
                "size": len(blob),
            }
        )
        blobs[digest] = blob
    return layers, blobs


def jcs(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def rust_bytes(data: bytes) -> str:
    return '"' + data.hex() + '"'


def rust_const(name: str, ty: str, literal: str) -> list[str]:
    """Lay out one string constant the way rustfmt does at max_width 100."""
    single = f"const {name}: {ty} = {literal};"
    broken = f"    {literal};"
    if len(single) <= 100 or len(broken) > 100:
        return [single]
    return [f"const {name}: {ty} =", broken]


def render() -> str:
    fields, complete, manifest_digest, release_digest = golden_release()
    layers, blobs = oci_layers(complete)
    manifest = jcs(
        {
            "artifactType": "application/vnd.pigloros.plugin.release.v1",
            "config": {
                "digest": EMPTY_CONFIG_DIGEST,
                "mediaType": "application/vnd.oci.empty.v1+json",
                "size": 2,
            },
            "layers": layers,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "schemaVersion": 2,
        }
    )
    artifacts = [fields[9], fields[10]] + [item[2] for item in fields[11]]
    artifacts += [fields[12][2], fields[13][2], fields[18], fields[19]] + fields[20]
    descriptor_digests = sorted(
        {digest for item in artifacts for digest in (item[2], item[3])}
        | {dependency[1] for dependency in fields[17]}
    )
    lines = [
        "// @generated by scripts/generate_pmf1_golden_vectors.py; do not edit.",
        "//",
        "// Independent golden PMF1 V1 release closure (ADR-061 revision 3). Every",
        "// value below was computed by the Python generator, not by `pos-crypto`.",
        "",
        "/// Complete canonical PMF1 V1 bytes.",
        *rust_const("GOLDEN_PMF1_HEX", "&str", rust_bytes(complete)),
        "/// Unkeyed BLAKE3-256 of the complete PMF1 bytes.",
        *rust_const("GOLDEN_PMF1_DIGEST_HEX", "&str", rust_bytes(blake3(complete))),
        "/// Field 25: the unsigned manifest digest.",
        *rust_const(
            "GOLDEN_UNSIGNED_MANIFEST_DIGEST_HEX", "&str", rust_bytes(manifest_digest)
        ),
        "/// Field 27: the release digest.",
        *rust_const("GOLDEN_RELEASE_DIGEST_HEX", "&str", rust_bytes(release_digest)),
        "/// Field 24: the previous release digest (not a descriptor digest).",
        *rust_const("GOLDEN_PREVIOUS_RELEASE_HEX", "&str", rust_bytes(PREVIOUS_RELEASE)),
        "/// The strictly increasing ADR-103 descriptor digest set.",
        f"const GOLDEN_DESCRIPTOR_DIGESTS_HEX: [&str; {len(descriptor_digests)}] = [",
    ]
    lines += [f"    {rust_bytes(digest)}," for digest in descriptor_digests]
    lines += [
        "];",
        "/// The exact JCS OCI image manifest of the golden release closure.",
        *rust_const("GOLDEN_OCI_MANIFEST", "&str", json.dumps(manifest)),
        "/// The OCI digest of `GOLDEN_OCI_MANIFEST`.",
        *rust_const(
            "GOLDEN_OCI_MANIFEST_DIGEST",
            "&str",
            f'"sha256:{sha256(manifest.encode()).hex()}"',
        ),
        "/// Every closure blob as `(OCI digest, hex bytes)`, in digest order.",
        f"const GOLDEN_BLOBS_HEX: [(&str, &str); {len(blobs)}] = [",
    ]
    for digest in sorted(blobs):
        lines += ["    (", f'        "{digest}",', f"        {rust_bytes(blobs[digest])},"]
        lines += ["    ),"]
    lines += ["];", ""]
    return "\n".join(lines)


def self_test() -> None:
    """Check the BLAKE3 port against published BLAKE3 test-vector prefixes."""
    vectors = {
        0: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        1: "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        1023: "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
        1024: "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
        1025: "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
        2048: "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
        2049: "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030",
        3072: "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2",
        4097: "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995",
    }
    for length, expected in vectors.items():
        data = bytes(index % 251 for index in range(length))
        if blake3(data).hex() != expected:
            raise SystemExit(f"BLAKE3 self-test failed for length {length}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="verify the committed file")
    arguments = parser.parse_args()
    self_test()
    rendered = render()
    if arguments.check:
        if OUTPUT.read_text(encoding="utf-8") != rendered:
            print(f"{OUTPUT} is stale; rerun the generator", file=sys.stderr)
            return 1
        return 0
    OUTPUT.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
