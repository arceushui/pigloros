#!/usr/bin/env python3
"""Generate the Plugin conformance fixtures (ADR-061 revision 8 decisions 7, 8 and 11, #617).

This is the only writer of the composites, payloads, oracles and evidence-status records of
the `plugin-conformance` layer, and of the adapter's `src/schema_digests.rs`. It is called by
`scripts/conformance-fixture-adapters/plugin-signed-v1.sh render` (through the `render`
subcommand) and runs offline.

It does not use implementation output as an oracle: no Rust, no cargo and no binary of the
repository. Every expected value is computed here from the public specification (the guest
behaviour of `docs/evidence/adr-061-r4-prototype.md`, the PMF1, PTR1, PRV1, TPS1 and execution
profile formats) or is written by hand; the only checked-in vectors it reads are the
specification vectors it reproduces in `--check`. It imports the BLAKE3, Ed25519 and CBOR
primitives of
`generate_pmf1_golden_vectors.py` and adds keyed BLAKE3 with extendable output, a parameterized
PMF1 builder, the PTR1, PRV1 and TPS1 encoders and signers, the execution profile digest, and
the OCI closure and `PCW2` composite builders.

Usage:
    python3 scripts/generate_plugin_conformance_fixtures.py          # write every output
    python3 scripts/generate_plugin_conformance_fixtures.py --check  # self-test and verify
    python3 scripts/generate_plugin_conformance_fixtures.py render ...  # one family (adapter)

The fixture seeds below are public and used for fixtures only ("repository-test-fixture-only");
the signatures prove consistency, not publisher identity.

The slice S3b1 ships a real subset of each family (R8-F9): `positive` and
`independent-evaluation` in full, `den.01` and `den.02`, `mal.1a` and `mal.1b`, `res.1`,
`del.1` and `dgr.1`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import generate_pmf1_golden_vectors as golden  # noqa: E402

FIXTURES = ROOT / "fixtures/conformance"
COMPONENTS = ROOT / "plugins/community/examples/compatibility-prototype/fixtures"
WIT_PATH = ROOT / "plugins/community/wit/pigloros-plugin.wit"
BLAKE3_VECTORS = HERE / "data/blake3_test_vectors.json"
PMF1_GOLDEN_RUST = ROOT / "crates/pos-crypto/tests/support/pmf1_golden_vectors.rs"
TRUST_VECTORS_RUST = ROOT / "crates/pos-crypto/tests/plugin_trust_vectors.rs"
SCHEMA_DIGESTS_RUST = ROOT / "apps/pos-plugin-conformance-adapter/src/schema_digests.rs"

CLAIM_LAYER = "plugin-conformance"
SCHEMA_ID = "pigloros.plugin-conformance.case.v2"
FAMILIES = (
    "positive",
    "denied",
    "malformed",
    "resource-exhaustion",
    "deletion-redaction",
    "downgrade",
    "independent-evaluation",
)
CANONICAL_OUTPUT_FAMILIES = ("positive", "deletion-redaction", "independent-evaluation")
COMPOSITE_MEDIA_TYPE = "application/vnd.pigloros.plugin-world.v2+cbor"

# --- Keyed BLAKE3 and extendable output ---

KEYED_HASH = 16


def _key_words(key: bytes) -> list[int]:
    return list(struct.unpack("<8I", key))


B3Output = tuple[list[int], list[int], int, int, int]


def _chunk_output(chunk: bytes, counter: int, key_words: list[int], base_flags: int) -> B3Output:
    cv = list(key_words)
    blocks = [chunk[i : i + 64] for i in range(0, len(chunk), 64)] or [b""]
    for index, block in enumerate(blocks):
        flags = base_flags
        flags |= golden.CHUNK_START if index == 0 else 0
        flags |= golden.CHUNK_END if index == len(blocks) - 1 else 0
        if index == len(blocks) - 1:
            return cv, golden._words(block), counter, len(block), flags
        cv = golden._compress(cv, golden._words(block), counter, 64, flags)[:8]
    raise AssertionError("unreachable")


def _parent_output(
    left: list[int], right: list[int], key_words: list[int], base_flags: int
) -> B3Output:
    return list(key_words), left + right, 0, 64, base_flags | golden.PARENT


def _root_output(data: bytes, key_words: list[int], base_flags: int) -> B3Output:
    chunks = [data[i : i + 1024] for i in range(0, len(data), 1024)] or [b""]
    stack: list[list[int]] = []
    for counter, chunk in enumerate(chunks[:-1]):
        cv = golden._cv(_chunk_output(chunk, counter, key_words, base_flags))
        total = counter + 1
        while total & 1 == 0:
            cv = golden._cv(_parent_output(stack.pop(), cv, key_words, base_flags))
            total >>= 1
        stack.append(cv)
    output = _chunk_output(chunks[-1], len(chunks) - 1, key_words, base_flags)
    while stack:
        output = _parent_output(stack.pop(), golden._cv(output), key_words, base_flags)
    return output


def blake3_xof(data: bytes, key: bytes | None, offset: int, length: int) -> bytes:
    """`length` bytes of the (keyed) BLAKE3 extendable output of `data`, from byte `offset`.

    The offset need not be aligned to the 64-byte output block: this is the host's
    `blake3::Hasher::new_keyed(domain).finalize_xof()` followed by `set_position(offset)`.
    """
    words = _key_words(key) if key is not None else list(golden.IV)
    cv, block_words, _counter, block_len, flags = _root_output(
        data, words, KEYED_HASH if key is not None else 0
    )
    block = offset // 64
    skip = offset % 64
    produced = b""
    while len(produced) < skip + length:
        state = golden._compress(cv, block_words, block, block_len, flags | golden.ROOT)
        produced += struct.pack("<16I", *state)
        block += 1
    return produced[skip : skip + length]


# --- Strict CBOR decoding (self-tests only) ---


def cbor_decode(data: bytes) -> object:
    value, end = _decode(data, 0)
    if end != len(data):
        raise ValueError("trailing bytes")
    return value


def _decode(data: bytes, pos: int) -> tuple[object, int]:
    initial = data[pos]
    major, info = initial >> 5, initial & 31
    pos += 1
    if info < 24:
        argument = info
    elif info in (24, 25, 26, 27):
        width = {24: 1, 25: 2, 26: 4, 27: 8}[info]
        argument = int.from_bytes(data[pos : pos + width], "big")
        pos += width
    elif major == 7 and info in (20, 21, 22):
        argument = info
    else:
        raise ValueError("unsupported CBOR head")
    if major == 0:
        return argument, pos
    if major == 1:
        return -1 - argument, pos
    if major == 2:
        return bytes(data[pos : pos + argument]), pos + argument
    if major == 3:
        return data[pos : pos + argument].decode("utf-8"), pos + argument
    if major == 4:
        items = []
        for _ in range(argument):
            item, pos = _decode(data, pos)
            items.append(item)
        return items, pos
    if major == 7:
        return {20: False, 21: True, 22: None}[argument], pos
    raise ValueError("unsupported CBOR major type")


# --- PTR1, PRV1 and TPS1 ---

ROOT_SIGNATURE_DOMAIN = b"pigloros/plugin-trust-root/v1\0"
REVOCATION_SIGNATURE_DOMAIN = b"pigloros/plugin-revocation/v1\0"
ROOT_KEY_ID_DOMAIN = b"pigloros/plugin-root-key-id/v1\0"
TPS1_SIGNATURE_DOMAIN = b"PiglorOS.TPS1.operator-signature.v1\0"
PUBLISHER_KEY_ROLE = 3
TPS1_VALID_THROUGH = "2030-01-01T00:00:00Z"

ROOT_SEED = bytes([0x11]) * 32
PUBLISHER_SEED = bytes([0x22]) * 32
OPERATOR_SEED = bytes([0x33]) * 32


def root_key_id(public: bytes) -> bytes:
    return golden.blake3(ROOT_KEY_ID_DOMAIN + public)


def signed_record(fields: list, domain: bytes, root_seed: bytes) -> bytes:
    message = domain + golden.cbor(fields)
    signature = golden.ed25519_sign(root_seed, message)
    key_id = root_key_id(golden.ed25519_public(root_seed))
    return golden.cbor(fields + [[[key_id, signature]]])


def encode_ptr1(
    scope: str,
    version: int,
    not_before: int,
    not_after: int,
    previous: bytes | None,
    root_seed: bytes,
    publishers: list[tuple[str, int, bytes]],
    grants: list[tuple[str, str]],
) -> bytes:
    public = golden.ed25519_public(root_seed)
    fields = [
        "PTR1",
        1,
        scope,
        version,
        not_before,
        not_after,
        previous,
        1,
        [[root_key_id(public), public]],
        [[owner, PUBLISHER_KEY_ROLE, epoch, key] for owner, epoch, key in publishers],
        [[plugin, owner] for plugin, owner in sorted(grants)],
    ]
    return signed_record(fields, ROOT_SIGNATURE_DOMAIN, root_seed)


def encode_prv1(
    scope: str,
    epoch: int,
    not_before: int,
    not_after: int,
    root_digest: bytes,
    previous: bytes | None,
    tick: int,
    keys: list[list],
    artifacts: list[list],
    root_seed: bytes,
) -> bytes:
    fields = [
        "PRV1",
        1,
        scope,
        epoch,
        not_before,
        not_after,
        root_digest,
        previous,
        tick,
        keys,
        artifacts,
    ]
    return signed_record(fields, REVOCATION_SIGNATURE_DOMAIN, root_seed)


def encode_tps1(
    scope: str,
    epoch: int,
    position: int,
    roots: list,
    revoked_keys: list,
    revoked_artifacts: list,
    minimum_versions: list,
    valid_through: str,
    previous: bytes | None,
    operator_seed: bytes,
) -> bytes:
    """The operator-signed TPS1 whose fields 0 to 10 are signed under the TPS1 domain."""
    fields = [
        "TPS1",
        1,
        scope,
        epoch,
        position,
        roots,
        revoked_keys,
        revoked_artifacts,
        minimum_versions,
        valid_through,
        previous,
    ]
    message = TPS1_SIGNATURE_DOMAIN + golden.cbor(fields)
    return golden.cbor(fields + [golden.ed25519_sign(operator_seed, message)])


def plugin_tps1(scope: str, epoch: int, root_version: int, root_public: bytes) -> bytes:
    """The genesis Plugin TPS1 that maps one PTR1 root key and revokes nothing."""
    roots = [["ptr1-" + root_key_id(root_public).hex(), root_version, "Ed25519", root_public]]
    return encode_tps1(
        scope, epoch, 9, roots, [], [], [], TPS1_VALID_THROUGH, None, OPERATOR_SEED
    )


# --- The execution profile digest (EPF1) ---

PROFILE_DOMAIN = b"PiglorOS.Plugin.ExecutionProfile.v1\0"


def profile_digest(ceilings, version, features, engine, traps) -> bytes:
    """BLAKE3 of the domain, the big-endian body length and the CBOR `[ceilings, runtime]`."""
    body = golden.cbor(
        [
            list(ceilings),
            [
                version,
                sorted(features, key=lambda item: item.encode()),
                list(engine),
                [list(row) for row in sorted(traps, key=lambda row: row[0].encode())],
            ],
        ]
    )
    return golden.blake3(PROFILE_DOMAIN + len(body).to_bytes(8, "big") + body)


R7_D1 = {
    "ceilings": [67_108_864, 1_000_000_000, 1_000_000, 16_777_216, 16_384],
    "runtime": {
        "version": "fixture-1",
        "features": ["component-model", "cranelift", "runtime"],
        "engine": [524_288, True, True],
        "traps": [
            ["OutOfFuel", "FuelExhausted"],
            ["Interrupt", "OperationalWatchdogStop"],
            ["UnreachableCodeReached", "unreachable"],
        ],
    },
}
R7_D1_DIGEST = "9df81ceb0d029665c3317e72736385b21af951200babd30cbbfc7d0a8d11e100"


def r7_d1_digest() -> bytes:
    runtime = R7_D1["runtime"]
    return profile_digest(
        R7_D1["ceilings"],
        runtime["version"],
        runtime["features"],
        runtime["engine"],
        runtime["traps"],
    )


# --- PMF1 ---


@dataclass(frozen=True)
class SchemaDoc:
    schema_id: int
    version: int
    document: bytes
    max_bytes: int


@dataclass(frozen=True)
class Pmf1Spec:
    plugin_id: str
    release_version: str
    abi_major: int
    abi_min_minor: int
    abi_max_minor: int
    features: tuple
    component: bytes
    wit: bytes
    events: tuple
    state: SchemaDoc
    configuration: SchemaDoc | None
    capabilities: tuple
    budget: tuple
    dependencies: tuple
    provenance: bytes
    sbom: bytes
    licences: tuple
    owner: str
    not_before: int
    not_after: int
    previous: bytes | None
    signer_seed: bytes
    signer_epoch: int


def schema_field(schema: SchemaDoc) -> list:
    return [
        schema.schema_id,
        schema.version,
        golden.descriptor("schema", schema.document),
        schema.max_bytes,
    ]


def pmf1_fields(spec: Pmf1Spec) -> list:
    licences = sorted(
        (golden.descriptor("licence", text) for text in spec.licences),
        key=lambda item: item[3],
    )
    return [
        "PMF1",
        1,
        spec.plugin_id,
        spec.release_version,
        golden.WORLD,
        spec.abi_major,
        spec.abi_min_minor,
        spec.abi_max_minor,
        list(spec.features),
        golden.descriptor("component", spec.component),
        golden.descriptor("wit", spec.wit),
        [schema_field(event) for event in spec.events],
        schema_field(spec.state),
        None if spec.configuration is None else schema_field(spec.configuration),
        [list(capability) for capability in spec.capabilities],
        list(spec.budget),
        [],
        [list(dependency) for dependency in spec.dependencies],
        golden.descriptor("provenance", spec.provenance),
        golden.descriptor("sbom", spec.sbom),
        licences,
        spec.owner,
        spec.not_before,
        spec.not_after,
        spec.previous,
    ]


def build_pmf1(spec: Pmf1Spec) -> dict:
    """The complete PMF1 and its digests, as `pos-crypto`'s encoder defines them."""
    fields = pmf1_fields(spec)
    unsigned = golden.cbor(fields)
    manifest_digest = golden.blake3(
        b"PiglorOS.Plugin.Manifest.v1\0" + len(unsigned).to_bytes(8, "big") + unsigned
    )
    release_digest = golden.blake3(
        b"PiglorOS.Plugin.Release.v1\0" + manifest_digest + fields[9][2] + fields[10][2]
    )
    message = golden.role_message(spec.owner, spec.signer_epoch, release_digest)
    signature = golden.ed25519_sign(spec.signer_seed, message)
    complete = golden.cbor(
        fields + [manifest_digest, [1, 3, spec.signer_epoch, signature], release_digest]
    )
    return {
        "complete": complete,
        "manifest_digest": manifest_digest,
        "release_digest": release_digest,
        "pmf1_digest": golden.blake3(complete),
    }


# --- The OCI closure ---


def _addressed(prefix: str, role: str, blobs) -> list:
    entries = sorted(
        ((f"sha256:{golden.sha256(blob).hex()}", blob) for blob in blobs), key=lambda e: e[0]
    )
    return [(prefix + digest[len("sha256:") :], role, blob) for digest, blob in entries]


def oci_closure(pmf1: bytes, spec: Pmf1Spec) -> tuple[bytes, list[bytes]]:
    """The JCS OCI manifest and the layer blobs (in layer order) of a release."""
    schemas = [event.document for event in spec.events] + [spec.state.document]
    if spec.configuration is not None:
        schemas.append(spec.configuration.document)
    layers = [
        ("pmf1", None, pmf1),
        ("component", "component", spec.component),
        ("wit", "wit", spec.wit),
        *_addressed("schema/", "schema", schemas),
        ("provenance", "provenance", spec.provenance),
        ("sbom", "sbom", spec.sbom),
        *_addressed("licence/", "licence", spec.licences),
    ]
    descriptors = []
    for member, role, blob in layers:
        media_type = golden.PMF1_MEDIA_TYPE if role is None else golden.ROLES[role][0]
        descriptors.append(
            {
                "annotations": {"org.pigloros.plugin.member": member},
                "digest": f"sha256:{golden.sha256(blob).hex()}",
                "mediaType": media_type,
                "size": len(blob),
            }
        )
    manifest = golden.jcs(
        {
            "artifactType": "application/vnd.pigloros.plugin.release.v1",
            "config": {
                "digest": golden.EMPTY_CONFIG_DIGEST,
                "mediaType": "application/vnd.oci.empty.v1+json",
                "size": 2,
            },
            "layers": descriptors,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "schemaVersion": 2,
        }
    )
    return manifest.encode("utf-8"), [blob for _, _, blob in layers]


# --- Fixed public documents of the releases ---

PLUGIN_ID = "pigloros.compatibility-prototype"
OWNER = "publisher"
SCOPE = "plugin-conformance"
EVENT_TYPE = "prototype.driven"

EVENT_SCHEMA = b'{"$id":"pigloros.fixture.plugin-conformance.event","type":"object"}'
STATE_SCHEMA = b'{"$id":"pigloros.fixture.plugin-conformance.state","type":"object"}'
PROVENANCE = b'{"_type":"https://in-toto.io/Statement/v1","subject":"plugin-conformance-fixture"}'
SBOM = b'{"spdxVersion":"SPDX-2.3","name":"plugin-conformance-fixture"}'
LICENCE = b"MIT"

# Seconds, Ticks and instants of the sub-cases.
NOT_BEFORE = 40
NOT_AFTER = 60
INSTANT = 50_000_000
LATER_INSTANT = 51_000_000
TICK = 5
LATER_TICK = 6
ROOT_NOT_AFTER = 100

MEMORY_BYTES = 16 * 1_048_576
ROOMY_FUEL = 1 << 40


def tar_archive(name: str, data: bytes) -> bytes:
    """A deterministic one-member ustar archive (the media type of the WIT layer is a tar)."""
    header = bytearray(512)
    header[0 : len(name)] = name.encode("ascii")
    header[100:108] = b"0000644\0"
    header[108:116] = b"0000000\0"
    header[116:124] = b"0000000\0"
    header[124:136] = f"{len(data):011o}".encode("ascii") + b"\0"
    header[136:148] = b"00000000000\0"
    header[148:156] = b"        "
    header[156:157] = b"0"
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[148:156] = f"{sum(header):06o}".encode("ascii") + b"\0 "
    padding = (-len(data)) % 512
    return bytes(header) + data + bytes(padding) + bytes(1024)


@lru_cache(maxsize=None)
def component(name: str) -> bytes:
    data = (COMPONENTS / name).read_bytes()
    pinned = {}
    for line in (COMPONENTS / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, file = line.split("  ")
        pinned[file] = digest
    if hashlib.sha256(data).hexdigest() != pinned[name]:
        raise SystemExit(f"{name} does not match {COMPONENTS / 'SHA256SUMS'}")
    return data


@lru_cache(maxsize=None)
def wit_archive() -> bytes:
    return tar_archive("pigloros-plugin.wit", WIT_PATH.read_bytes())


def default_capability(required: bool) -> tuple:
    return ("kv", "read", "state/*", "Read Plugin state", "plugin", required, 10, 1024, 2048)


def default_budget(fuel: int = ROOMY_FUEL) -> tuple:
    return (MEMORY_BYTES, fuel, 256, 24, 4096, 4096, 24, 256)


def default_spec(**overrides) -> Pmf1Spec:
    """The release shape of the conformance world: the real worker's ABI 0.0, no feature."""
    spec = Pmf1Spec(
        plugin_id=PLUGIN_ID,
        release_version="1.0.0",
        abi_major=0,
        abi_min_minor=0,
        abi_max_minor=0,
        features=(),
        component=component("rust-guest.wasm"),
        wit=wit_archive(),
        events=(SchemaDoc(1, 1, EVENT_SCHEMA, 65_536),),
        state=SchemaDoc(2, 1, STATE_SCHEMA, 65_536),
        configuration=None,
        capabilities=(default_capability(False),),
        budget=default_budget(),
        # The `dep` row is kept as the publisher test world declares it (proven on the real
        # worker); nothing in the gate or the conformance cases reads it.
        dependencies=(("dep", bytes([0x42]) * 32, golden.WORLD, 0, 0, 0, ["clock"], [], 0),),
        provenance=PROVENANCE,
        sbom=SBOM,
        licences=(LICENCE,),
        owner=OWNER,
        not_before=NOT_BEFORE,
        not_after=NOT_AFTER,
        previous=None,
        signer_seed=PUBLISHER_SEED,
        signer_epoch=1,
    )
    return replace(spec, **overrides)


@dataclass(frozen=True)
class Release:
    """A release closure: its PMF1, OCI manifest and layer blobs, with the identities."""

    pmf1: bytes
    oci_manifest: bytes
    layers: tuple
    pmf1_digest: bytes
    release_digest: bytes
    manifest_digest: bytes

    def pieces(self) -> list[bytes]:
        return [self.oci_manifest, *self.layers]

    def reference(self) -> dict:
        """The payload `release` object."""
        return {
            "manifest": golden.blake3(self.oci_manifest).hex(),
            "blobs": [golden.blake3(layer).hex() for layer in self.layers],
        }


def make_release(spec: Pmf1Spec, mutate=None) -> Release:
    """The release of `spec`; `mutate` replaces the PMF1 bytes (the closure is built over them)."""
    built = build_pmf1(spec)
    pmf1 = built["complete"] if mutate is None else mutate(built["complete"])
    manifest, layers = oci_closure(pmf1, spec)
    return Release(
        pmf1=pmf1,
        oci_manifest=manifest,
        layers=tuple(layers),
        pmf1_digest=golden.blake3(pmf1),
        release_digest=built["release_digest"],
        manifest_digest=built["manifest_digest"],
    )


# --- The trust policy ---


@dataclass(frozen=True)
class Trust:
    anchor: bytes
    tps1: bytes
    ptr1: bytes
    prv1: bytes

    def pieces(self) -> list[bytes]:
        return [self.anchor, self.tps1, self.ptr1, self.prv1]

    def reference(self) -> dict:
        digest = lambda data: golden.blake3(data).hex()  # noqa: E731
        return {
            "anchor": digest(self.anchor),
            "tps1": digest(self.tps1),
            "ptr1": [digest(self.ptr1)],
            "prv1": [digest(self.prv1)],
        }


@lru_cache(maxsize=None)
def trust() -> Trust:
    """The genesis policy: one root, one publisher key and one grant, no revocation."""
    publisher = golden.ed25519_public(PUBLISHER_SEED)
    ptr1 = encode_ptr1(
        SCOPE, 1, 0, ROOT_NOT_AFTER, None, ROOT_SEED, [(OWNER, 1, publisher)], [(PLUGIN_ID, OWNER)]
    )
    prv1 = encode_prv1(
        SCOPE, 1, 0, ROOT_NOT_AFTER, golden.blake3(ptr1), None, TICK, [], [], ROOT_SEED
    )
    tps1 = plugin_tps1(SCOPE, 1, 1, golden.ed25519_public(ROOT_SEED))
    anchor = golden.cbor(
        [
            "PCA1",
            1,
            SCOPE,
            golden.blake3(ptr1),
            golden.ed25519_public(OPERATOR_SEED),
            golden.blake3(tps1),
        ]
    )
    return Trust(anchor=anchor, tps1=tps1, ptr1=ptr1, prv1=prv1)


# --- The prototype guests ---

FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
OUTPUT_DOMAIN = b"PiglorOS.Plugin.Output.v1\0"


def fnv1a(state: int, data: bytes) -> int:
    for byte in data:
        state ^= byte
        state = (state * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return state


def put_bytes(parts: list[bytes], data: bytes) -> None:
    parts.append(len(data).to_bytes(8, "big"))
    parts.append(data)


def guest_output(
    state_schema: bytes,
    prior_state: bytes,
    observation: bytes,
    simulation_time: int,
    domain: bytes,
    offset: int,
    invocation_id: bytes,
) -> tuple[bytes, bytes]:
    """The `drive` of both prototype guests: (V1 output digest, next state bytes)."""
    random = blake3_xof(b"", domain, offset, 16)
    state = FNV_OFFSET
    for part in (prior_state, observation, simulation_time.to_bytes(8, "little"), random):
        state = fnv1a(state, part)
    next_state = state.to_bytes(8, "little")
    parts = [OUTPUT_DOMAIN]
    put_bytes(parts, invocation_id)
    parts.append((1).to_bytes(8, "big"))
    parts.append((1).to_bytes(4, "big"))
    put_bytes(parts, invocation_id)
    put_bytes(parts, EVENT_TYPE.encode("ascii"))
    put_bytes(parts, next_state)
    parts.append((0).to_bytes(8, "big"))
    put_bytes(parts, state_schema)
    put_bytes(parts, next_state)
    parts.append((0).to_bytes(8, "big"))
    parts.append((0).to_bytes(8, "big"))
    return golden.blake3(b"".join(parts)), next_state


# --- Sub-cases ---

INITIAL_SCHEMA = bytes([9]) * 32
INITIAL_STATE = b"initial"
PRE_EXECUTION = "PreExecutionRejection"
IND1_INPUT = "PiglorOS independent fixture plugin-conformance"
IND1_DIGEST = "92adc8f0b327b091f85e847d3fa1f7cb46e16bdd74f389d79b2e61171c2715c3"


@dataclass
class SubCase:
    id: str
    steps: list
    expect: dict
    entry: dict | None
    releases: list


def install(release: Release, tick: int = TICK, instant: int = INSTANT) -> dict:
    return {
        "step": "install",
        "release": release.reference(),
        "material": trust().reference(),
        "instant_micros": instant,
        "tick": tick,
    }


def bind(release: Release, tick: int = TICK, instant: int = INSTANT) -> dict:
    return {
        "step": "bind",
        "release": release.reference(),
        "material": trust().reference(),
        "plugin_id": PLUGIN_ID,
        "instant_micros": instant,
        "tick": tick,
        "initial_state": {"schema": INITIAL_SCHEMA.hex(), "bytes": INITIAL_STATE.hex()},
        "event_type": EVENT_TYPE,
    }


@dataclass(frozen=True)
class PassInputs:
    invocation_id: bytes
    domain: bytes
    offset: int
    observation: bytes
    simulation_time: int
    tick: int
    instant: int


FIRST_PASS = PassInputs(
    invocation_id=bytes([1]) * 16,
    domain=bytes([4]) * 32,
    offset=37,
    observation=b"pos.1 observation",
    simulation_time=42,
    tick=TICK,
    instant=INSTANT,
)
SECOND_PASS = PassInputs(
    invocation_id=bytes([2]) * 16,
    domain=bytes([5]) * 32,
    offset=120,
    observation=b"pos.3 second observation",
    simulation_time=43,
    tick=LATER_TICK,
    instant=LATER_INSTANT,
)
REDACTION_PASS = PassInputs(
    invocation_id=bytes([0x0D]) * 16,
    domain=bytes([6]) * 32,
    offset=0,
    observation=b"del.1 observation synthetic-secret",
    simulation_time=44,
    tick=TICK,
    instant=INSTANT,
)


def run_pass(inputs: PassInputs) -> dict:
    return {
        "step": "pass",
        "members": [{"plugin_id": PLUGIN_ID}],
        "instant_micros": inputs.instant,
        "tick": inputs.tick,
        "invocation_id": inputs.invocation_id.hex(),
        "random_domain": inputs.domain.hex(),
        "timeline_seq": inputs.offset,
        "observation": inputs.observation.hex(),
        "simulation_time": inputs.simulation_time,
    }


def drive(inputs: PassInputs, prior_state: bytes) -> tuple[bytes, bytes]:
    return guest_output(
        INITIAL_SCHEMA,
        prior_state,
        inputs.observation,
        inputs.simulation_time,
        inputs.domain,
        inputs.offset,
        inputs.invocation_id,
    )


def refused(error: str, basis: str | None = None, index: int | None = None) -> dict:
    expect = {"kind": "refused", "error": error, "class": PRE_EXECUTION}
    if basis is not None:
        expect["basis"] = basis
    if index is not None:
        expect["index"] = index
    return expect


@lru_cache(maxsize=None)
def rust_release() -> Release:
    return make_release(default_spec())


@lru_cache(maxsize=None)
def c_release() -> Release:
    return make_release(default_spec(component=component("c-guest.wasm")))


def committed_subcase(sub_id: str, release: Release) -> SubCase:
    digest, _state = drive(FIRST_PASS, INITIAL_STATE)
    return SubCase(
        id=sub_id,
        steps=[install(release), bind(release), run_pass(FIRST_PASS)],
        expect={"kind": "committed", "output_digest": digest.hex()},
        entry={"id": sub_id, "kind": "committed", "output_digest": digest.hex()},
        releases=[release],
    )


def positive_subcases() -> list[SubCase]:
    first_digest, first_state = drive(FIRST_PASS, INITIAL_STATE)
    second_digest, _state = drive(SECOND_PASS, first_state)
    rust = rust_release()
    carried = SubCase(
        id="pos.3",
        steps=[
            install(rust),
            bind(rust),
            run_pass(FIRST_PASS),
            run_pass(SECOND_PASS),
        ],
        expect={"kind": "committed", "output_digest": second_digest.hex()},
        entry={"id": "pos.3", "kind": "committed", "output_digest": second_digest.hex()},
        releases=[rust],
    )
    assert first_digest != second_digest
    return [committed_subcase("pos.1", rust), committed_subcase("pos.2", c_release()), carried]


def digest_subcase(sub_id: str, steps: list, compute: dict, value: bytes, releases) -> SubCase:
    return SubCase(
        id=sub_id,
        steps=steps,
        expect={"kind": "digest", "compute": compute, "value": value.hex()},
        entry={"id": sub_id, "kind": "digest", "value": value.hex()},
        releases=releases,
    )


def independent_subcases() -> list[SubCase]:
    rust = rust_release()
    bound = [install(rust), bind(rust)]
    first_digest, _state = drive(FIRST_PASS, INITIAL_STATE)
    runtime = R7_D1["runtime"]
    ind1 = golden.blake3(IND1_INPUT.encode("ascii"))
    assert ind1.hex() == IND1_DIGEST
    return [
        digest_subcase(
            "ind.1", [], {"what": "blake3_of", "input": IND1_INPUT}, ind1, []
        ),
        digest_subcase(
            "ind.2a",
            bound,
            {"what": "release_identity", "field": "pmf1"},
            rust.pmf1_digest,
            [rust],
        ),
        digest_subcase(
            "ind.2b",
            bound,
            {"what": "release_identity", "field": "release"},
            rust.release_digest,
            [rust],
        ),
        digest_subcase(
            "ind.3",
            [install(rust), bind(rust), run_pass(FIRST_PASS)],
            {"what": "output_digest", "pass_index": 0},
            first_digest,
            [rust],
        ),
        digest_subcase(
            "ind.4",
            [],
            {
                "what": "profile_digest",
                "ceilings": R7_D1["ceilings"],
                "runtime": {
                    "version": runtime["version"],
                    "features": runtime["features"],
                    "engine": runtime["engine"],
                    "traps": runtime["traps"],
                },
            },
            r7_d1_digest(),
            [],
        ),
    ]


def refusal_subcase(sub_id: str, steps: list, expect: dict, releases: list) -> SubCase:
    return SubCase(id=sub_id, steps=steps, expect=expect, entry=None, releases=releases)


def denied_subcases() -> list[SubCase]:
    capability = make_release(default_spec(capabilities=(default_capability(True),)))
    feature = make_release(default_spec(features=("clock",)))
    return [
        refusal_subcase(
            "den.01",
            [install(capability), bind(capability)],
            refused("CapabilityDenied", index=0),
            [capability],
        ),
        refusal_subcase(
            "den.02",
            [install(feature), bind(feature)],
            refused("MissingFeature", index=0),
            [feature],
        ),
    ]


def trailing_byte(pmf1: bytes) -> bytes:
    return pmf1 + b"\x00"


def noncanonical_version(pmf1: bytes) -> bytes:
    """Field 1 (`1`) written as `0x18 0x01`, which is not the shortest form."""
    head = 2 + 5  # the array head and the text "PMF1"
    assert pmf1[head] == 0x01
    return pmf1[:head] + b"\x18\x01" + pmf1[head + 1 :]


def malformed_subcases() -> list[SubCase]:
    trailing = make_release(default_spec(), mutate=trailing_byte)
    noncanonical = make_release(default_spec(), mutate=noncanonical_version)
    invalid = refused("InvalidManifest")
    return [
        refusal_subcase("mal.1a", [install(trailing)], invalid, [trailing]),
        refusal_subcase("mal.1b", [install(noncanonical)], dict(invalid), [noncanonical]),
    ]


def resource_subcases() -> list[SubCase]:
    starved = make_release(
        default_spec(component=component("c-guest.wasm"), budget=default_budget(fuel=1))
    )
    expect = {"kind": "failed", "error": "FuelExhausted", "class": "Authoritative"}
    return [
        SubCase(
            id="res.1",
            steps=[install(starved), bind(starved), run_pass(FIRST_PASS)],
            expect=expect,
            entry=None,
            releases=[starved],
        )
    ]


def redaction_subcases() -> list[SubCase]:
    rust = rust_release()
    marker = "synthetic-secret"
    retained = {"plugin_id": PLUGIN_ID, "invocation_id_hex": REDACTION_PASS.invocation_id.hex()}
    scan = {
        "step": "scan",
        "marker": marker,
        "in": ["events", "state", "outcome"],
        "retained": retained,
    }
    return [
        SubCase(
            id="del.1",
            steps=[install(rust), bind(rust), run_pass(REDACTION_PASS), scan],
            expect={"kind": "absent", "marker": marker, "retained": retained},
            entry={
                "id": "del.1",
                "kind": "absent",
                "prohibited_data_present": False,
                "retained_metadata": {
                    "invocation_id_hex": retained["invocation_id_hex"],
                    "plugin_id": PLUGIN_ID,
                },
            },
            releases=[rust],
        )
    ]


def downgrade_subcases() -> list[SubCase]:
    first = rust_release()
    successor = make_release(
        default_spec(release_version="1.1.0", previous=first.release_digest)
    )
    return [
        refusal_subcase(
            "dgr.1",
            [install(first), install(successor), bind(first)],
            refused("ArtifactTrustDenied", basis="NotActive"),
            [first, successor],
        )
    ]


SUBCASES = {
    "positive": positive_subcases,
    "denied": denied_subcases,
    "malformed": malformed_subcases,
    "resource-exhaustion": resource_subcases,
    "deletion-redaction": redaction_subcases,
    "downgrade": downgrade_subcases,
    "independent-evaluation": independent_subcases,
}


# --- Outputs ---


def jcs(value) -> bytes:
    """RFC 8785 canonical JSON of ASCII text, integers and booleans, and no whitespace."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def composite(pieces: list[bytes]) -> bytes:
    """`["PCW2", 1, [[digest32, bytes], ...]]`, the pieces sorted by digest and deduplicated."""
    by_digest = {golden.blake3(piece): piece for piece in pieces}
    return golden.cbor(["PCW2", 1, [[d, by_digest[d]] for d in sorted(by_digest)]])


def composite_path(family: str) -> str:
    return f"inputs/{CLAIM_LAYER}/{family}.pcw2"


@dataclass(frozen=True)
class Context:
    case_id: str
    provider_id: str
    contract_version: str
    abi_major: int
    abi_minor: int
    oracle_kind: str
    code_id: str


@dataclass(frozen=True)
class Outputs:
    payload: bytes
    oracle: bytes
    evidence: bytes
    composite: bytes


def render_family(family: str, context: Context) -> Outputs:
    subcases = SUBCASES[family]()
    payload_object = {
        "schema": SCHEMA_ID,
        "family": family,
        "subcases": [
            {"id": sub.id, "steps": sub.steps, "expect": sub.expect} for sub in subcases
        ],
    }
    if family == "downgrade":
        payload_object["provider"] = {
            "provider_id": context.provider_id,
            "contract_version": context.contract_version,
            "abi_major": context.abi_major,
            "abi_minor": context.abi_minor,
            "from_abi_minor": context.abi_minor + 1,
        }
    payload = jcs(payload_object) + b"\n"
    pieces = trust().pieces()
    for sub in subcases:
        for release in sub.releases:
            pieces.extend(release.pieces())
    if context.oracle_kind == "canonical-output":
        oracle_object = {
            "case_id": context.case_id,
            "claim_layer": CLAIM_LAYER,
            "family": family,
            "oracle": {"kind": "canonical-output"},
            "output": {"subcases": [sub.entry for sub in subcases]},
        }
    else:
        oracle_object = {
            "case_id": context.case_id,
            "claim_layer": CLAIM_LAYER,
            "family": family,
            "oracle": {
                "kind": "namespaced-failure",
                "owner_id": context.provider_id,
                "contract_version": context.contract_version,
                "code_id": context.code_id,
            },
        }
    evidence_object = {
        "claim_layer": CLAIM_LAYER,
        "case_id": context.case_id,
        "family": family,
        "input_blake3_digest": golden.blake3(payload).hex(),
        "status": "pending",
        "execution_result": None,
        "executed_at": None,
    }
    return Outputs(
        payload=payload,
        oracle=jcs(oracle_object) + b"\n",
        evidence=(json.dumps(evidence_object, indent=2) + "\n").encode("ascii"),
        composite=composite(pieces),
    )


def schema_path(family: str) -> Path:
    return FIXTURES / f"providers/{CLAIM_LAYER}/schemas/{family}.schema.json"


def rust_digest_const(name: str, digest: bytes) -> list[str]:
    """A `[u8; 32]` constant, laid out as rustfmt does: 16 literals per line at max_width 100."""
    lines = [f"const {name}: [u8; 32] = ["]
    for start in range(0, 32, 16):
        lines.append("    " + " ".join(f"0x{byte:02x}," for byte in digest[start : start + 16]))
    lines.append("];")
    return lines


def schema_digests_rust() -> str:
    constants: list[str] = []
    for family in FAMILIES:
        name = family.upper().replace("-", "_")
        digest = golden.blake3(schema_path(family).read_bytes())
        constants.extend(rust_digest_const(name, digest))
    arms = "".join(
        f"        FixtureFamily::{''.join(word.title() for word in family.split('-'))}"
        f" => {family.upper().replace('-', '_')},\n"
        for family in FAMILIES
    )
    header = """\
// @generated by scripts/generate_plugin_conformance_fixtures.py; do not edit.

//! The pinned digests of the schema members of the seven families (ADR-061 revision 8
//! decision 2, interpretation I-12).
//!
//! The digest of the schema member (role 0) of an attempt must equal the digest pinned here for
//! its family; a mismatch is a non-executed outcome (ADR-068 section 3). The fixture generator
//! writes this file from the checked-in schema members and its `--check` verifies it (R8-F4).

use pos_reference::evaluator_domain::FixtureFamily;

"""
    footer = """\

/// The pinned digest of the schema member of `family`.
#[must_use]
pub const fn pinned_digest(family: FixtureFamily) -> [u8; 32] {
    match family {
"""
    tail = """\
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
"""
    return header + "\n".join(constants) + "\n" + footer + arms + tail


# --- Self-tests (--check) ---


def input_bytes(length: int) -> bytes:
    return bytes(index % 251 for index in range(length))


def check_blake3_vectors() -> None:
    """The official vectors for lengths 0, 1, 1024 and 1025: hash, keyed hash and the XOF."""
    vectors = json.loads(BLAKE3_VECTORS.read_text(encoding="utf-8"))
    key = vectors["key"].encode("ascii")
    seen = set()
    for case in vectors["cases"]:
        data = input_bytes(case["input_len"])
        seen.add(case["input_len"])
        expected = bytes.fromhex(case["hash"])
        keyed = bytes.fromhex(case["keyed_hash"])
        if blake3_xof(data, None, 0, 131) != expected:
            raise SystemExit(f"BLAKE3 hash vector failed for length {case['input_len']}")
        if blake3_xof(data, key, 0, 131) != keyed:
            raise SystemExit(f"keyed BLAKE3 vector failed for length {case['input_len']}")
        if golden.blake3(data) != expected[:32]:
            raise SystemExit(f"BLAKE3 hash failed for length {case['input_len']}")
        # The unaligned offsets of the guests' random stream.
        slices = ((0, 16), (37, 16), (63, 2), (115, 16), (64, 67), (130, 1), (120, 11))
        for offset, length in slices:
            if blake3_xof(data, key, offset, length) != keyed[offset : offset + length]:
                raise SystemExit(f"keyed XOF slice {offset}+{length} failed")
    if seen != {0, 1, 1024, 1025}:
        raise SystemExit("the BLAKE3 vectors must cover the lengths 0, 1, 1024 and 1025")


def rust_hex_constant(path: Path, name: str) -> bytes:
    match = re.search(rf'const {name}: &str = "([0-9a-f]+)";', path.read_text(encoding="utf-8"))
    if match is None:
        raise SystemExit(f"{name} is missing from {path}")
    return bytes.fromhex(match.group(1))


def check_trust_vectors() -> None:
    """Re-encode and re-sign `PTR1_HEX` and `PRV1_HEX` from their decoded fields."""
    ptr1 = rust_hex_constant(TRUST_VECTORS_RUST, "PTR1_HEX")
    prv1 = rust_hex_constant(TRUST_VECTORS_RUST, "PRV1_HEX")
    fields = cbor_decode(ptr1)
    scope, version, not_before, not_after, previous = fields[2:7]
    (publisher,) = fields[9]
    (grant,) = fields[10]
    again = encode_ptr1(
        scope,
        version,
        not_before,
        not_after,
        previous,
        bytes([0x11]) * 32,
        [(publisher[0], publisher[2], publisher[3])],
        [(grant[0], grant[1])],
    )
    if again != ptr1:
        raise SystemExit("PTR1_HEX is not reproduced")
    record = cbor_decode(prv1)
    if record[6] != golden.blake3(ptr1):
        raise SystemExit("PRV1_HEX does not name the digest of PTR1_HEX")
    rebuilt = encode_prv1(
        record[2], record[3], record[4], record[5], record[6], record[7], record[8],
        record[9], record[10], bytes([0x11]) * 32,
    )  # fmt: skip
    if rebuilt != prv1:
        raise SystemExit("PRV1_HEX is not reproduced")


def check_tps1_vector() -> None:
    """Re-sign the independent Plugin TPS1 vector of the pos-conformance bridge tests."""
    source = (ROOT / "crates/pos-conformance/tests/plugin_trust_bridge_public.rs").read_text()
    match = re.search(r'const GOLDEN_TPS1_HEX: &str = "([0-9a-f]+)";', source)
    if match is None:
        raise SystemExit("GOLDEN_TPS1_HEX is missing")
    golden_tps1 = bytes.fromhex(match.group(1))
    fields = cbor_decode(golden_tps1)
    again = encode_tps1(
        fields[2], fields[3], fields[4], fields[5], fields[6], fields[7], fields[8], fields[9],
        fields[10], bytes([0x11]) * 32,
    )  # fmt: skip
    if again != golden_tps1:
        raise SystemExit("the TPS1 vector is not reproduced")


def check_pmf1_golden() -> None:
    """The parameterized builder reproduces the golden release, and the golden files are fresh."""
    spec = Pmf1Spec(
        plugin_id="alpha/plugin",
        release_version="1.2.3-rc.1",
        abi_major=0,
        abi_min_minor=1,
        abi_max_minor=3,
        features=("clock.v1", "log"),
        component=golden.BLOBS["component"],
        wit=golden.BLOBS["wit"],
        events=(
            SchemaDoc(1, 1, golden.BLOBS["event-a"], 4096),
            SchemaDoc(7, 2, golden.BLOBS["event-b"], 4096),
        ),
        state=SchemaDoc(100, 1, golden.BLOBS["state"], 65536),
        configuration=SchemaDoc(200, 1, golden.BLOBS["configuration"], 1024),
        capabilities=(
            ("kv", "read", "state/*", "Read Plugin state", "plugin", True, 24, 1024, 2048),
            ("kv", "write", "state/*", "Write Plugin state", "plugin", False, 10, 2048, 0),
        ),
        budget=(1_048_576, 1 << 40, 1000, 16, 4096, 65536, 24, 2048),
        dependencies=(
            (
                "beta/lib",
                golden.DEPENDENCY_RELEASE,
                golden.WORLD,
                0,
                0,
                2,
                ["clock.v1"],
                ["kv"],
                1,
            ),
        ),
        provenance=golden.BLOBS["provenance"],
        sbom=golden.BLOBS["sbom"],
        licences=(golden.BLOBS["licence-a"], golden.BLOBS["licence-b"]),
        owner="publisher",
        not_before=-100,
        not_after=100,
        previous=golden.PREVIOUS_RELEASE,
        signer_seed=golden.SIGNING_SEED,
        signer_epoch=golden.SIGNER_EPOCH,
    )
    _fields, complete, manifest_digest, release_digest, _message, _signature, _unsigned = (
        golden.golden_release()
    )
    built = build_pmf1(spec)
    if (built["complete"], built["manifest_digest"], built["release_digest"]) != (
        complete,
        manifest_digest,
        release_digest,
    ):
        raise SystemExit("the parameterized PMF1 builder does not reproduce the golden release")
    layers, _blobs = golden.oci_layers(complete)
    manifest, _layer_blobs = oci_closure(complete, spec)
    if json.loads(manifest)["layers"] != layers:
        raise SystemExit("the OCI closure builder does not reproduce the golden layers")
    for path, rendered in (
        (PMF1_GOLDEN_RUST, golden.render()),
        (golden.SIGNED_OUTPUT, golden.render_signed()),
    ):
        if path.read_text(encoding="utf-8") != rendered:
            raise SystemExit(f"{path} is stale; rerun scripts/generate_pmf1_golden_vectors.py")


def check_profile_digest() -> None:
    if r7_d1_digest().hex() != R7_D1_DIGEST:
        raise SystemExit("the EPF1 encoder does not reproduce the R7-D1 digest")


def _type_ok(value: object, name: str) -> bool:
    if name == "null":
        return value is None
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    return {"string": str, "array": list, "object": dict}[name] is type(value)


def schema_errors(value: object, schema: dict, root: dict, where: str = "$") -> list[str]:
    """The violations of the JSON Schema subset the provider schemas use."""
    if "$ref" in schema:
        target: object = root
        for part in schema["$ref"].removeprefix("#/").split("/"):
            target = target[part]  # type: ignore[index]
        return schema_errors(value, target, root, where)  # type: ignore[arg-type]
    found: list[str] = []
    if "oneOf" in schema:
        matching = sum(not schema_errors(value, option, root, where) for option in schema["oneOf"])
        return [] if matching == 1 else [f"{where}: {matching} alternatives match"]
    types = schema.get("type")
    if types is not None:
        names = [types] if isinstance(types, str) else types
        if not any(_type_ok(value, name) for name in names):
            return [f"{where}: wrong type"]
    if "const" in schema and value != schema["const"]:
        found.append(f"{where}: not the constant")
    if "enum" in schema and value not in schema["enum"]:
        found.append(f"{where}: not in the enumeration")
    if isinstance(value, str) and "pattern" in schema:
        if re.search(schema["pattern"], value) is None:
            found.append(f"{where}: pattern")
    if isinstance(value, int) and not isinstance(value, bool):
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            found.append(f"{where}: out of range")
    if isinstance(value, list):
        found.extend(_array_errors(value, schema, root, where))
    if isinstance(value, dict):
        found.extend(_object_errors(value, schema, root, where))
    return found


def _array_errors(value: list, schema: dict, root: dict, where: str) -> list[str]:
    found: list[str] = []
    if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", len(value)):
        found.append(f"{where}: item count")
    for index, item in enumerate(value):
        prefix = schema.get("prefixItems", [])
        item_schema = prefix[index] if index < len(prefix) else schema.get("items")
        if item_schema is not None:
            found.extend(schema_errors(item, item_schema, root, f"{where}[{index}]"))
    return found


def _object_errors(value: dict, schema: dict, root: dict, where: str) -> list[str]:
    found = [f"{where}: missing {key}" for key in schema.get("required", []) if key not in value]
    properties = schema.get("properties", {})
    for key, item in value.items():
        if key in properties:
            found.extend(schema_errors(item, properties[key], root, f"{where}.{key}"))
        elif schema.get("additionalProperties", True) is False:
            found.append(f"{where}: unexpected {key}")
    return found


def check_payload_schemas() -> None:
    """Every generated payload satisfies its checked-in schema member."""
    for family in FAMILIES:
        schema = json.loads(schema_path(family).read_text(encoding="utf-8"))
        outputs = render_family(family, provider_context(family))
        errors = schema_errors(json.loads(outputs.payload), schema, schema)
        if errors:
            raise SystemExit(f"the {family} payload violates its schema: {errors[:3]}")


def self_test() -> None:
    golden.self_test()
    golden.ed25519_self_test()
    check_blake3_vectors()
    check_pmf1_golden()
    check_trust_vectors()
    check_tps1_vector()
    check_profile_digest()
    check_payload_schemas()


# --- Command line ---


def provider_context(family: str) -> Context:
    provider = json.loads((FIXTURES / f"providers/{CLAIM_LAYER}/provider.json").read_text())
    contract = json.loads((FIXTURES / "support/fixture-family-contract.json").read_text())
    entry = next(item for item in contract["families"] if item["name"] == family)
    return Context(
        case_id=f"{CLAIM_LAYER}-{family}",
        provider_id=provider["provider_id"],
        contract_version=provider["contract_version"],
        abi_major=provider["abi_major"],
        abi_minor=provider["abi_minor"],
        oracle_kind=entry["oracle"]["kind"],
        code_id=entry["oracle"].get("code_id", ""),
    )


def outputs_on_disk() -> dict[Path, bytes]:
    wanted: dict[Path, bytes] = {SCHEMA_DIGESTS_RUST: schema_digests_rust().encode("utf-8")}
    for family in FAMILIES:
        outputs = render_family(family, provider_context(family))
        wanted[FIXTURES / f"inputs/{CLAIM_LAYER}/{family}.json"] = outputs.payload
        wanted[FIXTURES / composite_path(family)] = outputs.composite
        wanted[FIXTURES / f"oracles/{CLAIM_LAYER}/{family}.json"] = outputs.oracle
        wanted[FIXTURES / f"expected/{CLAIM_LAYER}/{family}.json"] = outputs.evidence
    return wanted


def command_render(arguments: argparse.Namespace) -> int:
    context = Context(
        case_id=arguments.case_id,
        provider_id=arguments.provider_id,
        contract_version=arguments.contract_version,
        abi_major=arguments.abi_major,
        abi_minor=arguments.abi_minor,
        oracle_kind=arguments.oracle_kind,
        code_id=arguments.code_id,
    )
    outputs = render_family(arguments.family, context)
    for path, data in (
        (arguments.payload_out, outputs.payload),
        (arguments.oracle_out, outputs.oracle),
        (arguments.evidence_out, outputs.evidence),
        (arguments.composite_out, outputs.composite),
    ):
        Path(path).write_bytes(data)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="self-test and verify every output")
    sub = parser.add_subparsers(dest="command")
    render = sub.add_parser("render", help="render the outputs of one family")
    render.add_argument("--family", required=True, choices=FAMILIES)
    render.add_argument("--case-id", required=True)
    render.add_argument("--provider-id", required=True)
    render.add_argument("--contract-version", required=True)
    render.add_argument("--abi-major", type=int, required=True)
    render.add_argument("--abi-minor", type=int, required=True)
    render.add_argument("--oracle-kind", required=True)
    render.add_argument("--code-id", default="")
    render.add_argument("--payload-out", required=True)
    render.add_argument("--oracle-out", required=True)
    render.add_argument("--evidence-out", required=True)
    render.add_argument("--composite-out", required=True)
    arguments = parser.parse_args()
    if arguments.command == "render":
        return command_render(arguments)
    if arguments.check:
        self_test()
        stale = [
            path
            for path, data in outputs_on_disk().items()
            if not path.exists() or path.read_bytes() != data
        ]
        for path in stale:
            print(f"{path} is stale; rerun the generator", file=sys.stderr)
        return 1 if stale else 0
    for path, data in outputs_on_disk().items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
