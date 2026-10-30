#!/usr/bin/env python3
"""Generate the replay-conformance fixtures (ADR-062 Revision 8 slice R4, #1222).

This is the only writer of the payloads, `RCS1` composites, oracles and evidence-status records
of the `replay-conformance` layer, of its seven provider schemas and of the subject adapter's
`apps/pos-experiment/src/replay_conformance/schema_digests.rs`. It is called by
`scripts/conformance-fixture-adapters/replay-cbor-v1.sh render` (through the `render`
subcommand) and runs offline.

It does not use implementation output as an oracle (ADR-062 Revision 8, Q3 (a)): no Rust, no
cargo and no binary of the repository. Every expected stream, authoritative result digest,
closure digest and first divergence is derived here from the closure members it writes, with the
digest scheme of the ADR-062 Revision 8 note "Recorded Replay Digests" (the
`PiglorOS.RecordedReplay*.v1` domains) and the closure composition this slice proposes for that
note. The only primitive it imports is the BLAKE3 hash of `generate_pmf1_golden_vectors.py`; it
reuses the JSON Schema subset checker of `generate_metric_conformance_fixtures.py`.

Usage:
    python3 scripts/generate_replay_conformance_fixtures.py          # write every output
    python3 scripts/generate_replay_conformance_fixtures.py --check  # self-test and verify
    python3 scripts/generate_replay_conformance_fixtures.py render ...  # one family (adapter)

`--check` first runs the self-tests: the BLAKE3 vectors, the ULID text codec, the canonical CBOR
key order, the eleven W8H1 entries (each exactly in its family), every closure digest against the
members the payload names (and the one deliberate mismatch), a second derivation of every
expected stream from its closure member, and every payload against its schema. It then
regenerates every output and compares it with the checked-in file.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import generate_metric_conformance_fixtures as metric  # noqa: E402
import generate_pmf1_golden_vectors as golden  # noqa: E402

FIXTURES = ROOT / "fixtures/conformance"
BLAKE3_VECTORS = HERE / "data/blake3_test_vectors.json"
SCHEMA_DIGESTS_RUST = ROOT / "apps/pos-experiment/src/replay_conformance/schema_digests.rs"

CLAIM_LAYER = "replay-conformance"
SCHEMA_ID = "pigloros.replay-conformance.case.v2"
SUBJECT_SCHEMA_ID = "pigloros.replay-conformance.subject.v1"
FAMILIES = (
    "positive",
    "denied",
    "malformed",
    "resource-exhaustion",
    "deletion-redaction",
    "downgrade",
    "independent-evaluation",
)
ID_PREFIX = {
    "positive": "pos",
    "denied": "den",
    "malformed": "mal",
    "resource-exhaustion": "res",
    "deletion-redaction": "del",
    "downgrade": "dgr",
    "independent-evaluation": "ind",
}
COMPOSITE_MAGIC = "RCS1"
COMPOSITE_MEDIA_TYPE = "application/vnd.pigloros.replay-cases.v1+cbor"

# The W8H1 entries (fixtures/conformance/expected-authority/inventory.json) and the family whose
# payload and oracle carry each of them.
W8H1_FAMILIES = {
    "RPL-001": "positive",
    "PRF-001": "positive",
    "PRF-002": "positive",
    "DIV-001": "independent-evaluation",
    "INV-001": "malformed",
    "INV-002": "deletion-redaction",
    "INV-003": "downgrade",
    "RES-001": "resource-exhaustion",
    "LIVE-001": "denied",
    "ERA-001": "deletion-redaction",
    "SEC-001": "denied",
}

# --- The host composition the subject adapter declares (apps/pos-experiment) ---

LOCAL = "deterministic-local-v1"
AIR_GAPPED = "deterministic-air-gapped-v1"
REPLAY = "replay-v1"
LIVE = "live-local-v1"
PROFILES = (LOCAL, AIR_GAPPED, REPLAY, LIVE)
CLASSES = ("RecordedReplay", "ProfileRecomputation", "CrossProfileConformance", "LiveUnverified")
CLAIMS = (
    "Exact",
    "ExactAuthoritativeWithRedactedViews",
    "StructuralOnly",
    "UnverifiableArtifactsMissing",
    "IncompatibleProfile",
)
REDUCER = "replay-conformance.count"
EVENT_TYPE = "replay.count"
HOST_FAILURE_DRIVER = "experiment-host"
RECOMPUTED_TIMELINE = bytes(16)

# --- Digest scheme (ADR-062 Revision 8 note "Recorded Replay Digests") ---

EVENT_IDENTITY_DOMAIN = b"PiglorOS.RecordedReplayEventIdentity.v1"
EVENT_SCHEMA_DOMAIN = b"PiglorOS.RecordedReplayEventSchema.v1"
CHECKPOINT_DOMAIN = b"PiglorOS.RecordedReplayCheckpoint.v1"
RESULT_DOMAIN = b"PiglorOS.RecordedReplayResult.v1"
# Proposed by this slice for section 4 of the note: the closure composition.
CLOSURE_DOMAIN = b"PiglorOS.RecordedReplayClosure.v1"
ROLE_EXPORTED_TIMELINE = 1
ROLE_RECOMPUTATION_SUBJECT = 2
ROLE_LICENCE = 3


def b3(data: bytes) -> bytes:
    return golden.blake3(data)


def domain_digest(domain: bytes, *parts: bytes) -> bytes:
    return b3(domain + b"\0" + b"".join(parts))


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def closure_digest(role: int, primary: bytes, licence: bytes) -> bytes:
    """Section 4 of the note: the member count, then each member in role order, as its one-byte
    role and its 32-byte artifact digest (the BLAKE3 of the member bytes)."""
    return domain_digest(
        CLOSURE_DOMAIN,
        u64(2),
        bytes([role]),
        b3(primary),
        bytes([ROLE_LICENCE]),
        b3(licence),
    )


# --- ULID text (Crockford base32, 26 characters) ---

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid_text(value: int) -> str:
    return "".join(CROCKFORD[(value >> (5 * (25 - index))) & 31] for index in range(26))


def ulid_value(text: str) -> int:
    value = 0
    for char in text:
        value = value << 5 | CROCKFORD.index(char)
    if value >> 128:
        raise ValueError("a ULID exceeds 128 bits")
    return value


def ulid_bytes(value: int) -> bytes:
    return value.to_bytes(16, "big")


# --- CBOR ---


class Ordered:
    """A map encoded in the given key order (as ciborium writes a serde struct)."""

    def __init__(self, *pairs: tuple[str, object]) -> None:
        self.pairs = pairs


def head(major: int, value: int) -> bytes:
    return metric.head(major, value)


def cbor(value: object, canonical: bool = False) -> bytes:
    if isinstance(value, Ordered):
        return head(5, len(value.pairs)) + b"".join(
            cbor(key, canonical) + cbor(item, canonical) for key, item in value.pairs
        )
    if isinstance(value, dict):
        # RFC 8949 section 4.2.1: keys sorted by encoded length, then bytewise (as
        # `pos_crypto::canonical::encode`).
        encoded = sorted(
            ((cbor(key, canonical), cbor(item, canonical)) for key, item in value.items()),
            key=lambda pair: (len(pair[0]), pair[0]),
        )
        return head(5, len(encoded)) + b"".join(key + item for key, item in encoded)
    return metric.enc(value) if not isinstance(value, list) else head(4, len(value)) + b"".join(
        cbor(item, canonical) for item in value
    )


# --- Closure members ---

LICENCE = b"SPDX-License-Identifier: MIT\n"
OTHER_LICENCE = b"SPDX-License-Identifier: Apache-2.0\n"
ENTITY = 0x0123_4567_89AB_CDEF
RECORDED_TIMELINE = 0x0001_0000_0000_0000_0000_0000_0000_0001
FIRST_EVENT_ID = 0x0001_0000_0000_0000_0000_0000_0000_1001


@dataclass(frozen=True)
class Recorded:
    """One recorded Event of an export."""

    event_id: int
    seq: int
    payload: bytes


def export_member(events: list[Recorded]) -> bytes:
    """A `TimelineExport` as `ciborium` writes the serde form (struct fields in declaration
    order; ULIDs as text; `CanonicalBytes` and `Hash` as byte strings; `SchemaVersion` as 1)."""
    meta = Ordered(
        ("id", ulid_text(RECORDED_TIMELINE)),
        ("mode", "Live"),
        ("name", "replay-conformance"),
        ("owner", None),
        ("fork_point", None),
    )
    timeline = Ordered(("meta", meta), ("head", events[-1].seq if events else 0))
    encoded = [
        Ordered(
            ("id", ulid_text(event.event_id)),
            ("entity", ulid_text(ENTITY)),
            ("event_type", EVENT_TYPE),
            ("payload", event.payload),
            ("wall_time", event.seq),
            ("seq", event.seq),
            ("causation_id", None),
            ("correlation_id", None),
            ("schema_version", 1),
            ("signature", None),
            ("signature_identity", None),
            ("origin", None),
            ("payload_hash", b3(event.payload)),
        )
        for event in events
    ]
    return cbor(Ordered(("timeline", timeline), ("events", encoded)))


@dataclass(frozen=True)
class Script:
    """A frozen recomputation subject: the drafts its one Driver emits at each Tick, and an
    optional typed failure at one Tick."""

    drafts: tuple[tuple[bytes, ...], ...]
    failure_tick: int | None = None
    failure_reason: str = ""


def subject_member(script: Script) -> bytes:
    document = {
        "schema": SUBJECT_SCHEMA_ID,
        "entity": ulid_text(ENTITY),
        "event_type": EVENT_TYPE,
        "drafts": [[payload.hex() for payload in tick] for tick in script.drafts],
        "failure": None
        if script.failure_tick is None
        else {"tick": script.failure_tick, "reason": script.failure_reason},
    }
    return jcs(document) + b"\n"


# The closed host-failure code of a Driver or runtime failure (`HostFailureCodeV1::Runtime`,
# note section 6): the typed failure's canonical bytes are this code as a big-endian u16.
HOST_FAILURE_RUNTIME = 1


def run_script(script: Script, ticks: int) -> tuple[list[bytes], bytes | None]:
    """What the host commits for `script` over `ticks` Tick boundaries: the Event payloads in
    Timeline Order and the typed failure's canonical bytes, if the Driver failed."""
    payloads: list[bytes] = []
    for tick in range(1, ticks + 1):
        if script.failure_tick == tick:
            return payloads, HOST_FAILURE_RUNTIME.to_bytes(2, "big")
        if tick <= len(script.drafts):
            payloads.extend(script.drafts[tick - 1])
    return payloads, None


# --- Expected streams ---


@dataclass(frozen=True)
class StreamEvent:
    seq: int
    identity: bytes
    schema: bytes
    payload: bytes


@dataclass(frozen=True)
class Stream:
    timeline: bytes
    events: tuple[StreamEvent, ...]
    checkpoint_digest: bytes
    checkpoint_size: int
    failure: bytes | None

    @property
    def fold_cursor(self) -> int:
        return self.events[-1].seq if self.events else 0


def schema_digest() -> bytes:
    return domain_digest(EVENT_SCHEMA_DOMAIN, EVENT_TYPE.encode(), b"\0", (1).to_bytes(4, "big"))


def snapshot_bytes(count: int) -> bytes:
    states = {} if count == 0 else {ulid_text(ENTITY): {"fields": {"count": count}}}
    return cbor({REDUCER: {"states": states}}, canonical=True)


def stream(
    timeline: bytes, events: list[tuple[int, bytes, bytes]], failure: bytes | None
) -> Stream:
    """`events` holds (seq, Event id bytes, payload)."""
    snapshot = snapshot_bytes(len(events))
    return Stream(
        timeline=timeline,
        events=tuple(
            StreamEvent(
                seq=seq,
                identity=domain_digest(
                    EVENT_IDENTITY_DOMAIN, event_id, ulid_bytes(ENTITY), EVENT_TYPE.encode()
                ),
                schema=schema_digest(),
                payload=payload,
            )
            for seq, event_id, payload in events
        ),
        checkpoint_digest=domain_digest(CHECKPOINT_DOMAIN, snapshot),
        checkpoint_size=len(snapshot),
        failure=failure,
    )


def recorded_stream(events: list[Recorded]) -> Stream:
    return stream(
        ulid_bytes(RECORDED_TIMELINE),
        [(event.seq, ulid_bytes(event.event_id), event.payload) for event in events],
        None,
    )


def recomputed_stream(payloads: list[bytes], failure: bytes | None) -> Stream:
    return stream(
        RECOMPUTED_TIMELINE,
        [(seq, bytes(16), payload) for seq, payload in enumerate(payloads, start=1)],
        failure,
    )


def result_digest(value: Stream) -> bytes:
    """The authoritative result digest (note section 2): the Events, the one checkpoint (tick 0),
    then the count-prefixed typed failures at the host coordinate (tick 0, scheduler position 0,
    the length-prefixed Driver id, output ordinal 0, the canonical bytes). A recorded export has
    no typed failure, so its count is 0."""
    parts = [u64(len(value.events))]
    for event in value.events:
        parts += [value.timeline, u64(event.seq), event.identity, event.schema, b3(event.payload)]
    parts += [
        u64(1),
        value.timeline,
        u64(value.fold_cursor),
        u64(0),
        value.checkpoint_digest,
        u64(value.checkpoint_size),
    ]
    failures = [] if value.failure is None else [value.failure]
    parts.append(u64(len(failures)))
    for failure in failures:
        driver = HOST_FAILURE_DRIVER.encode()
        parts += [
            value.timeline,
            u64(value.fold_cursor),
            u64(0),
            (0).to_bytes(4, "big"),
            u64(len(driver)),
            driver,
            (0).to_bytes(4, "big"),
            failure,
        ]
    return domain_digest(RESULT_DOMAIN, *parts)


def stream_object(value: Stream) -> dict:
    return {
        "timeline": value.timeline.hex(),
        "events": [
            {
                "seq": event.seq,
                "identity": event.identity.hex(),
                "schema": event.schema.hex(),
                "payload": event.payload.hex(),
            }
            for event in value.events
        ],
        "checkpoint": {
            "fold_cursor": value.fold_cursor,
            "digest": value.checkpoint_digest.hex(),
            "size": value.checkpoint_size,
        },
        "failure": None
        if value.failure is None
        else {"fold_cursor": value.fold_cursor, "bytes": value.failure.hex()},
    }


# --- Expected results (one leg per profile run) ---


def leg(
    profile: str,
    outcome: str,
    claim: str,
    digest: bytes | None = None,
    error: tuple[str, str | None] | None = None,
    divergence: dict | None = None,
) -> dict:
    return {
        "profile": profile,
        "outcome": outcome,
        "replay_claim": claim,
        "authoritative_result_digest": None if digest is None else digest.hex(),
        "first_error": None if error is None else {"code": error[0], "coordinate": error[1]},
        "divergence": divergence,
    }


def digest_size(data: bytes) -> dict:
    return {"digest": b3(data).hex(), "size": len(data)}


# --- Sub-cases ---


@dataclass
class SubCase:
    id: str
    fixture_id: str | None
    title: str
    cls: str
    profiles: tuple[str, ...]
    primary: bytes | None
    licence: bytes | None
    expected: Stream
    expect: list[dict]
    role: int
    ticks: int | None = None
    evaluation: dict | None = None
    claim: str = "Exact"
    format_version: int = 1
    resource_limit: int = 16
    bound_licence: bytes | None = None
    members: list[bytes] = field(default_factory=list)

    def closure_digest(self) -> bytes:
        """The request's `artifact_closure_digest`: the composition of the bound members (the
        supplied ones unless `bound_licence` names another licence)."""
        primary = self.primary if self.primary is not None else b""
        licence = self.bound_licence or self.licence or LICENCE
        return closure_digest(self.role, primary, licence)


RECORDED = [
    Recorded(FIRST_EVENT_ID, 1, bytes([7])),
    Recorded(FIRST_EVENT_ID + 1, 2, bytes([9])),
]
COUNT = Script(drafts=((bytes([1]),), (bytes([2]),), (bytes([3]),)))
SECRET = Script(
    drafts=((bytes([1]),), (bytes([2]),), (bytes([3]),)),
    failure_tick=2,
    failure_reason="secret read denied",
)


def recorded_case(sub_id: str, fixture_id: str | None, title: str, **overrides) -> SubCase:
    export = export_member(RECORDED)
    expected = recorded_stream(RECORDED)
    case = SubCase(
        id=sub_id,
        fixture_id=fixture_id,
        title=title,
        cls="RecordedReplay",
        profiles=(REPLAY,),
        primary=export,
        licence=LICENCE,
        expected=expected,
        expect=[],
        role=ROLE_EXPORTED_TIMELINE,
        evaluation={"rule": "PreserveExact", "state": "Retained"},
    )
    for key, value in overrides.items():
        setattr(case, key, value)
    return case


def recomputed_case(
    sub_id: str,
    fixture_id: str | None,
    title: str,
    cls: str,
    profiles: tuple[str, ...],
    script: Script = COUNT,
    ticks: int = 3,
    **overrides,
) -> SubCase:
    payloads, failure = run_script(script, ticks)
    case = SubCase(
        id=sub_id,
        fixture_id=fixture_id,
        title=title,
        cls=cls,
        profiles=profiles,
        primary=subject_member(script),
        licence=LICENCE,
        expected=recomputed_stream(payloads, failure),
        expect=[],
        role=ROLE_RECOMPUTATION_SUBJECT,
        ticks=ticks,
    )
    for key, value in overrides.items():
        setattr(case, key, value)
    return case


def exact_legs(case: SubCase, claim: str = "Exact") -> list[dict]:
    digest = result_digest(case.expected)
    return [leg(profile, "VerifiedExact", claim, digest) for profile in case.profiles]


def positive_subcases() -> list[SubCase]:
    rpl = recorded_case("pos.1", "RPL-001", "a recorded export replays exactly")
    rpl.expect = exact_legs(rpl)
    prf = recomputed_case(
        "pos.2", "PRF-001", "a recomputation is exact", "ProfileRecomputation", (LOCAL,)
    )
    prf.expect = exact_legs(prf)
    cross = recomputed_case(
        "pos.3",
        "PRF-002",
        "Local and Air-Gapped recomputations match one expected record",
        "CrossProfileConformance",
        (LOCAL, AIR_GAPPED),
    )
    cross.expect = exact_legs(cross)
    return [rpl, prf, cross]


def denied_subcases() -> list[SubCase]:
    single = recomputed_case(
        "den.1a",
        "SEC-001",
        "a denied secret read is the expected typed failure",
        "ProfileRecomputation",
        (LOCAL,),
        script=SECRET,
    )
    single.expect = exact_legs(single)
    cross = recomputed_case(
        "den.1b",
        "SEC-001",
        "the denied secret read is the same typed failure in both profiles",
        "CrossProfileConformance",
        (LOCAL, AIR_GAPPED),
        script=SECRET,
    )
    cross.expect = exact_legs(cross)
    live = recomputed_case(
        "den.2",
        "LIVE-001",
        "a live run is recorded and never verified exact",
        "LiveUnverified",
        (LIVE,),
        claim="StructuralOnly",
    )
    payloads, failure = run_script(COUNT, 3)
    live.expect = [
        leg(
            LIVE,
            "UnverifiableArtifactsMissing",
            "StructuralOnly",
            result_digest(recomputed_stream(payloads, failure)),
            ("ProvenanceMissing", "replay_claim"),
        )
    ]
    return [single, cross, live]


def malformed_subcases() -> list[SubCase]:
    unsupported = ("UnsupportedVersion", "manifest")
    single = recomputed_case(
        "mal.1a",
        "INV-001",
        "a manifest of format version 2 is invalid",
        "ProfileRecomputation",
        (LOCAL,),
        format_version=2,
    )
    single.expect = [leg(LOCAL, "InvalidManifest", "Exact", error=unsupported)]
    cross = recomputed_case(
        "mal.1b",
        "INV-001",
        "a manifest of format version 2 is invalid in both profiles",
        "CrossProfileConformance",
        (LOCAL, AIR_GAPPED),
        format_version=2,
    )
    cross.expect = [
        leg(profile, "InvalidManifest", "Exact", error=unsupported) for profile in cross.profiles
    ]
    unbound = recorded_case(
        "mal.2",
        None,
        "closure members that do not compose the request's closure digest are refused",
        bound_licence=OTHER_LICENCE,
    )
    unbound.expect = [
        leg(REPLAY, "InvalidManifest", "Exact", error=("DigestMismatch", "artifact_closure"))
    ]
    return [single, cross, unbound]


def resource_subcases() -> list[SubCase]:
    over = recomputed_case(
        "res.1",
        "RES-001",
        "a recomputation of three Events under a limit of two",
        "ProfileRecomputation",
        (LOCAL,),
        resource_limit=2,
    )
    over.expect = [
        leg(LOCAL, "ResourceLimitExceeded", "Exact", error=("ResourceLimitExceeded", None))
    ]
    return [over]


def redaction_subcases() -> list[SubCase]:
    redacted = recorded_case(
        "del.1",
        "ERA-001",
        "redacted views keep an exact authoritative outcome with a degraded claim",
        evaluation={"rule": "RedactViews", "state": "TransitionApplied"},
    )
    redacted.expect = exact_legs(redacted, "ExactAuthoritativeWithRedactedViews")
    missing = ("ClosureIncomplete", "artifact_closure")
    no_licence = recomputed_case(
        "del.2a",
        "INV-002",
        "a recomputation whose licence member is missing",
        "ProfileRecomputation",
        (LOCAL,),
        licence=None,
    )
    no_licence.expect = [
        leg(LOCAL, "UnverifiableArtifactsMissing", "UnverifiableArtifactsMissing", error=missing)
    ]
    no_subject = recomputed_case(
        "del.2b",
        "INV-002",
        "a cross-profile run whose subject member is missing",
        "CrossProfileConformance",
        (LOCAL, AIR_GAPPED),
        primary=None,
    )
    no_subject.expect = [
        leg(profile, "UnverifiableArtifactsMissing", "UnverifiableArtifactsMissing", error=missing)
        for profile in no_subject.profiles
    ]
    return [redacted, no_licence, no_subject]


def downgrade_subcases() -> list[SubCase]:
    wrong_class = recomputed_case(
        "dgr.1a",
        "INV-003",
        "a recomputation under the live profile is an incompatible profile",
        "ProfileRecomputation",
        (LIVE,),
    )
    wrong_class.expect = [
        leg(
            LIVE,
            "IncompatibleProfile",
            "IncompatibleProfile",
            error=("ProfileClassMismatch", "profile_class"),
        )
    ]
    swapped = recomputed_case(
        "dgr.1b",
        "INV-003",
        "cross-profile legs under each other's profile are an incompatible profile",
        "CrossProfileConformance",
        (AIR_GAPPED, LOCAL),
    )
    swapped.expect = [
        leg(
            profile,
            "IncompatibleProfile",
            "IncompatibleProfile",
            error=("ProfileUnsupported", "execution_profile"),
        )
        for profile in swapped.profiles
    ]
    return [wrong_class, swapped]


def independent_subcases() -> list[SubCase]:
    case = recomputed_case(
        "ind.1",
        "DIV-001",
        "an expected record that differs at sequence 2 is the first divergence",
        "ProfileRecomputation",
        (LOCAL,),
    )
    payloads, failure = run_script(COUNT, 3)
    actual = recomputed_stream(payloads, failure)
    tampered = list(payloads)
    tampered[1] = bytes([0x2A])
    case.expected = recomputed_stream(tampered, failure)
    case.expect = [
        leg(
            LOCAL,
            "Diverged",
            "Exact",
            result_digest(actual),
            divergence={
                "location": "TimelineSeq",
                "mismatch": "CanonicalBytes",
                "timeline": RECOMPUTED_TIMELINE.hex(),
                "seq": 2,
                "expected": digest_size(tampered[1]),
                "actual": digest_size(payloads[1]),
            },
        )
    ]
    return [case]


def subcases_of(family: str) -> list[SubCase]:
    return {
        "positive": positive_subcases,
        "denied": denied_subcases,
        "malformed": malformed_subcases,
        "resource-exhaustion": resource_subcases,
        "deletion-redaction": redaction_subcases,
        "downgrade": downgrade_subcases,
        "independent-evaluation": independent_subcases,
    }[family]()


# --- Payload, composite, oracle, evidence ---


def jcs(value) -> bytes:
    return metric.jcs(value)


def label(text: str) -> str:
    return b3(f"PiglorOS.ReplayConformanceFixture.v1\0{text}".encode()).hex()


def manifest_object(sub: SubCase) -> dict:
    return {
        "format_version": sub.format_version,
        "seed": 11,
        "resource_limit": sub.resource_limit,
        "network_enabled": False,
        "replay_claim": sub.claim,
        "input_digest": label(f"{sub.id}/input"),
        "artifact_closure_digest": sub.closure_digest().hex(),
        "evaluator_digest": label("evaluator"),
        "scenario_room_digest": label(f"{sub.id}/scenario-room"),
        "scheduler_digest": label(f"{sub.id}/scheduler"),
        "budget_digest": label(f"{sub.id}/budget"),
        "request_digest": label(f"{sub.id}/request"),
        "report_bytes_limit": 1024,
    }


def subcase_object(sub: SubCase) -> dict:
    return {
        "id": sub.id,
        "fixture_id": sub.fixture_id,
        "title": sub.title,
        "class": sub.cls,
        "profiles": list(sub.profiles),
        "manifest": manifest_object(sub),
        "closure": {
            "primary": None if sub.primary is None else b3(sub.primary).hex(),
            "licence": None if sub.licence is None else b3(sub.licence).hex(),
        },
        "export_evaluation": sub.evaluation,
        "ticks": sub.ticks,
        "expected_stream": stream_object(sub.expected),
        "expect": sub.expect,
    }


def oracle_entry(sub: SubCase) -> dict:
    return {"id": sub.id, "fixture_id": sub.fixture_id, "legs": sub.expect}


def composite(subcases: list[SubCase]) -> bytes:
    """`["RCS1", 1, [[digest32, bytes], ...]]`: the closure members, sorted by digest, unique."""
    members = [member for sub in subcases for member in (sub.primary, sub.licence) if member]
    by_digest = {b3(member): member for member in members}
    return cbor([COMPOSITE_MAGIC, 1, [[digest, by_digest[digest]] for digest in sorted(by_digest)]])


@dataclass(frozen=True)
class Context:
    case_id: str
    provider_id: str
    contract_version: str
    oracle_kind: str
    code_id: str


@dataclass(frozen=True)
class Outputs:
    payload: bytes
    oracle: bytes
    evidence: bytes
    composite: bytes


def render_family(family: str, context: Context) -> Outputs:
    subcases = subcases_of(family)
    payload = (
        jcs(
            {
                "schema": SCHEMA_ID,
                "family": family,
                "subcases": [subcase_object(sub) for sub in subcases],
            }
        )
        + b"\n"
    )
    entries = [oracle_entry(sub) for sub in subcases]
    if context.oracle_kind == "canonical-output":
        oracle_object = {
            "case_id": context.case_id,
            "claim_layer": CLAIM_LAYER,
            "family": family,
            "oracle": {"kind": "canonical-output"},
            "output": {"subcases": entries},
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
            "subcases": entries,
        }
    evidence_object = {
        "claim_layer": CLAIM_LAYER,
        "case_id": context.case_id,
        "family": family,
        "input_blake3_digest": b3(payload).hex(),
        "status": "pending",
        "execution_result": None,
        "executed_at": None,
    }
    return Outputs(
        payload=payload,
        oracle=jcs(oracle_object) + b"\n",
        evidence=(json.dumps(evidence_object, indent=2) + "\n").encode("ascii"),
        composite=composite(subcases),
    )


# --- Provider schemas ---


def family_schema(family: str) -> dict:
    hex32 = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    hex16 = {"type": "string", "pattern": "^[0-9a-f]{32}$"}
    u64_schema = {"type": "integer", "minimum": 0, "maximum": 9007199254740991}
    nullable = lambda schema: {"oneOf": [schema, {"type": "null"}]}  # noqa: E731
    digest_size_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["digest", "size"],
        "properties": {"digest": nullable(hex32), "size": nullable(u64_schema)},
    }
    leg_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "profile",
            "outcome",
            "replay_claim",
            "authoritative_result_digest",
            "first_error",
            "divergence",
        ],
        "properties": {
            "profile": {"enum": list(PROFILES)},
            "outcome": {
                "enum": [
                    "VerifiedExact",
                    "Diverged",
                    "InvalidManifest",
                    "UnverifiableArtifactsMissing",
                    "IncompatibleProfile",
                    "ResourceLimitExceeded",
                ]
            },
            "replay_claim": {"enum": list(CLAIMS)},
            "authoritative_result_digest": nullable(hex32),
            "first_error": nullable(
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["code", "coordinate"],
                    "properties": {
                        "code": {"type": "string", "pattern": "^[A-Za-z]+$"},
                        "coordinate": nullable({"type": "string", "pattern": "^[a-z_]+$"}),
                    },
                }
            ),
            "divergence": nullable(
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "location",
                        "mismatch",
                        "timeline",
                        "seq",
                        "expected",
                        "actual",
                    ],
                    "properties": {
                        "location": {"type": "string", "pattern": "^[A-Za-z]+$"},
                        "mismatch": {"type": "string", "pattern": "^[A-Za-z]+$"},
                        "timeline": hex16,
                        "seq": u64_schema,
                        "expected": digest_size_schema,
                        "actual": digest_size_schema,
                    },
                }
            ),
        },
    }
    stream_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["timeline", "events", "checkpoint", "failure"],
        "properties": {
            "timeline": hex16,
            "events": {
                "type": "array",
                "maxItems": 1024,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["seq", "identity", "schema", "payload"],
                    "properties": {
                        "seq": u64_schema,
                        "identity": hex32,
                        "schema": hex32,
                        "payload": {"type": "string", "pattern": "^([0-9a-f]{2})*$"},
                    },
                },
            },
            "checkpoint": {
                "type": "object",
                "additionalProperties": False,
                "required": ["fold_cursor", "digest", "size"],
                "properties": {"fold_cursor": u64_schema, "digest": hex32, "size": u64_schema},
            },
            "failure": nullable(
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["fold_cursor", "bytes"],
                    "properties": {
                        "fold_cursor": u64_schema,
                        "bytes": {"type": "string", "pattern": "^([0-9a-f]{2})*$"},
                    },
                }
            ),
        },
    }
    manifest_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": list(manifest_object(subcases_of("positive")[0]).keys()),
        "properties": {
            "format_version": {"type": "integer", "minimum": 0, "maximum": 4294967295},
            "seed": u64_schema,
            "resource_limit": u64_schema,
            "network_enabled": {"type": "boolean"},
            "replay_claim": {"enum": list(CLAIMS)},
            "input_digest": hex32,
            "artifact_closure_digest": hex32,
            "evaluator_digest": hex32,
            "scenario_room_digest": hex32,
            "scheduler_digest": hex32,
            "budget_digest": hex32,
            "request_digest": hex32,
            "report_bytes_limit": u64_schema,
        },
    }
    subcase_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "id",
            "fixture_id",
            "title",
            "class",
            "profiles",
            "manifest",
            "closure",
            "export_evaluation",
            "ticks",
            "expected_stream",
            "expect",
        ],
        "properties": {
            "id": {"type": "string", "pattern": f"^{ID_PREFIX[family]}\\.[0-9]+[a-z]?$"},
            "fixture_id": nullable({"enum": sorted(W8H1_FAMILIES)}),
            "title": {"type": "string", "pattern": "^[ -~]+$"},
            "class": {"enum": list(CLASSES)},
            "profiles": {
                "type": "array",
                "minItems": 1,
                "maxItems": 2,
                "items": {"enum": list(PROFILES)},
            },
            "manifest": manifest_schema,
            "closure": {
                "type": "object",
                "additionalProperties": False,
                "required": ["primary", "licence"],
                "properties": {"primary": nullable(hex32), "licence": nullable(hex32)},
            },
            "export_evaluation": nullable(
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["rule", "state"],
                    "properties": {
                        "rule": {"enum": ["PreserveExact", "RedactViews"]},
                        "state": {"enum": ["Retained", "TransitionApplied"]},
                    },
                }
            ),
            "ticks": nullable({"type": "integer", "minimum": 0, "maximum": 1024}),
            "expected_stream": stream_schema,
            "expect": {"type": "array", "minItems": 1, "maxItems": 2, "items": leg_schema},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": ["schema", "family", "subcases"],
        "properties": {
            "schema": {"const": SCHEMA_ID},
            "family": {"const": family},
            "subcases": {"type": "array", "minItems": 1, "maxItems": 16, "items": subcase_schema},
        },
    }


def schema_path(family: str) -> Path:
    return FIXTURES / f"providers/{CLAIM_LAYER}/schemas/{family}.schema.json"


def rust_digest_const(name: str, digest: bytes) -> list[str]:
    lines = [f"const {name}: [u8; 32] = ["]
    for start in range(0, 32, 16):
        lines.append("    " + " ".join(f"0x{byte:02x}," for byte in digest[start : start + 16]))
    lines.append("];")
    return lines


def schema_digests_rust() -> str:
    constants: list[str] = []
    for family in FAMILIES:
        name = family.upper().replace("-", "_")
        constants.extend(rust_digest_const(name, b3(jcs(family_schema(family)) + b"\n")))
    names = "".join(f"    {family.upper().replace('-', '_')},\n" for family in FAMILIES)
    header = """\
// @generated by scripts/generate_replay_conformance_fixtures.py; do not edit.

//! The pinned digests of the replay-conformance schema members of the seven families
//! (provider contract 2.0.0, ADR-062 Revision 8 slice R4).
//!
//! The digest of the schema member of an attempt must equal the digest pinned here for its
//! family; a mismatch, such as the schema member of provider contract 1.0.0, is a non-executed
//! outcome: there is no reader for 1.0.0. The fixture generator writes this file from the
//! checked-in schema members and its `--check` verifies it.

use pos_reference::evaluator_domain::FixtureFamily;

"""
    footer = """\

/// The pinned digests, in the wire order of `FixtureFamily`.
const PINNED: [[u8; 32]; 7] = [
"""
    tail = """\
];

/// The pinned digest of the schema member of `family`.
#[must_use]
pub(super) fn pinned_digest(family: FixtureFamily) -> [u8; 32] {
    PINNED[usize::from(family.code())]
}
"""
    return header + "\n".join(constants) + "\n" + footer + names + tail


# --- Self-tests (--check) ---


def check_blake3_vectors() -> None:
    metric.check_blake3_vectors()


def decode(data: bytes, pos: int = 0) -> tuple[object, int]:
    """Decode the definite-length CBOR this generator writes, maps included (self-tests)."""
    initial = data[pos]
    major, info = initial >> 5, initial & 31
    pos += 1
    if major == 7:
        return {20: False, 21: True, 22: None}[info], pos
    if info < 24:
        argument = info
    else:
        width = 1 << (info - 24)
        argument = int.from_bytes(data[pos : pos + width], "big")
        pos += width
    if major == 0:
        return argument, pos
    if major == 2:
        return bytes(data[pos : pos + argument]), pos + argument
    if major == 3:
        return data[pos : pos + argument].decode("utf-8"), pos + argument
    if major == 4:
        items = []
        for _ in range(argument):
            item, pos = decode(data, pos)
            items.append(item)
        return items, pos
    if major == 5:
        pairs = {}
        for _ in range(argument):
            key, pos = decode(data, pos)
            pairs[key], pos = decode(data, pos)
        return pairs, pos
    raise ValueError("unsupported CBOR major type")


def decode_export(data: bytes) -> list[Recorded]:
    """The recorded Events of an export member, read back from its bytes."""
    export, end = decode(data)
    if end != len(data) or export["timeline"]["meta"]["id"] != ulid_text(RECORDED_TIMELINE):
        raise SystemExit("an export member does not decode")
    events = []
    for event in export["events"]:
        if event["payload_hash"] != b3(event["payload"]) or event["schema_version"] != 1:
            raise SystemExit("an exported Event is inconsistent")
        events.append(Recorded(ulid_value(event["id"]), event["seq"], event["payload"]))
    return events


def check_ulid_and_cbor() -> None:
    # The nil and the maximum ULID of the ULID specification.
    if ulid_text(0) != "0" * 26 or ulid_text((1 << 128) - 1) != "7" + "Z" * 25:
        raise SystemExit("the ULID text codec disagrees")
    for value in (0, 1, ENTITY, RECORDED_TIMELINE, (1 << 128) - 1):
        if ulid_value(ulid_text(value)) != value:
            raise SystemExit("the ULID text codec does not round-trip")
    # RFC 8949 section 4.2.1: shorter keys first, then bytewise.
    if cbor({"bb": 1, "a": 2, "c": 3}, canonical=True) != bytes.fromhex("a3616102616303626262" "01"):
        raise SystemExit("the canonical CBOR key order disagrees")


def every_subcase() -> list[tuple[str, SubCase]]:
    return [(family, sub) for family in FAMILIES for sub in subcases_of(family)]


def check_w8h1() -> None:
    seen: dict[str, set[str]] = {}
    for family, sub in every_subcase():
        if sub.fixture_id is not None:
            seen.setdefault(sub.fixture_id, set()).add(family)
    if sorted(seen) != sorted(W8H1_FAMILIES):
        raise SystemExit(f"the W8H1 entries are not all covered: {sorted(seen)}")
    for fixture_id, families in seen.items():
        if families != {W8H1_FAMILIES[fixture_id]}:
            raise SystemExit(f"{fixture_id} is not carried by {W8H1_FAMILIES[fixture_id]} alone")
    inventory = json.loads((FIXTURES / "expected-authority/inventory.json").read_text())
    if [entry["fixture_id"] for entry in inventory["entries"]] != list(W8H1_FAMILIES):
        raise SystemExit("the W8H1 inventory order changed")


def check_closures() -> None:
    """Every request binds the composition of the members the payload names, except the one
    sub-case that binds another licence on purpose."""
    for _family, sub in every_subcase():
        if sub.primary is None or sub.licence is None:
            continue
        supplied = closure_digest(sub.role, sub.primary, sub.licence)
        bound = sub.closure_digest() == supplied
        if bound == (sub.bound_licence is not None):
            raise SystemExit(f"{sub.id}: the closure binding is not what the sub-case claims")
        if sub.id == "mal.2" and sub.expect[0]["first_error"]["code"] != "DigestMismatch":
            raise SystemExit("mal.2 does not expect the closure refusal")


def check_streams() -> None:
    """A second derivation of each expected stream from the closure member it names."""
    for _family, sub in every_subcase():
        if sub.role == ROLE_EXPORTED_TIMELINE:
            again = recorded_stream(decode_export(sub.primary or b""))
        else:
            document = json.loads(sub.primary or subject_member(COUNT))
            script = Script(
                drafts=tuple(
                    tuple(bytes.fromhex(item) for item in tick) for tick in document["drafts"]
                ),
                failure_tick=(document["failure"] or {}).get("tick"),
                failure_reason=(document["failure"] or {}).get("reason", ""),
            )
            again = recomputed_stream(*run_script(script, sub.ticks or 0))
        if sub.id == "ind.1":
            if again == sub.expected or again.events[1].payload == sub.expected.events[1].payload:
                raise SystemExit("ind.1 does not diverge at sequence 2")
            continue
        if again != sub.expected:
            raise SystemExit(f"{sub.id}: the second derivation of the stream disagrees")
        if sub.expect[0]["outcome"] == "VerifiedExact" and sub.expect[0][
            "authoritative_result_digest"
        ] != result_digest(again).hex():
            raise SystemExit(f"{sub.id}: the exact result digest disagrees")


def check_payload_schemas() -> None:
    for family in FAMILIES:
        schema = family_schema(family)
        outputs = render_family(family, provider_context(family))
        errors = metric.schema_errors(json.loads(outputs.payload), schema, schema)
        if errors:
            raise SystemExit(f"the {family} payload violates its schema: {errors[:3]}")


def self_test() -> None:
    check_blake3_vectors()
    check_ulid_and_cbor()
    check_w8h1()
    check_closures()
    check_streams()
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
        oracle_kind=entry["oracle"]["kind"],
        code_id=entry["oracle"].get("code_id", ""),
    )


def composite_path(family: str) -> str:
    return f"inputs/{CLAIM_LAYER}/{family}.rcs1"


def outputs_on_disk() -> dict[Path, bytes]:
    wanted: dict[Path, bytes] = {SCHEMA_DIGESTS_RUST: schema_digests_rust().encode("utf-8")}
    for family in FAMILIES:
        wanted[schema_path(family)] = jcs(family_schema(family)) + b"\n"
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
