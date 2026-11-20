#!/usr/bin/env python3
"""Generate the gateway-client-conformance fixtures (provider contract 2.0.0, #1295).

This is the only writer of the payloads, oracles and evidence-status records of the
`gateway-client-conformance` layer, of its seven provider schemas and of the subject adapter's
`apps/pos-gateway-conformance-adapter/src/subject/schema_digests.rs`. It is called by
`scripts/conformance-fixture-adapters/gateway-http-v1.sh render` (through the `render`
subcommand) and runs offline.

It does not use implementation output as an oracle: no Rust, no cargo and no binary of the
repository. Every expected HTTP exchange is written here by hand from the published Gateway v1
contract (`contracts/gateway/v1/openapi.json` and its problem-type registry) and the exchange
grammar and normalization of `fixtures/conformance/profiles/gateway-client-conformance/
normative-requirements.md`. Every expected response body is also validated against the
contract by `scripts/check_gateway_contract.py`. The only computed values are the `society.signal` payload bytes
(the encoding the requirements text states), the independent-evaluation digests and the Session
provenance digest (the record the `Session` schema states), all derived here. The only primitive it imports is the BLAKE3 hash of
`generate_pmf1_golden_vectors.py`.

Usage:
    python3 scripts/generate_gateway_conformance_fixtures.py          # write every output
    python3 scripts/generate_gateway_conformance_fixtures.py --check  # self-test and verify
    python3 scripts/generate_gateway_conformance_fixtures.py render ...  # one family (adapter)

`--check` first runs the self-tests: the BLAKE3 vectors, a second derivation of every
`society.signal` payload by an independent CBOR decoder, the normalization rules on raw
response shapes, the route and capture rules of every exchange, the capability set and the
step and Event usage of every family against the provider declaration, and every payload
against its schema. It then regenerates every output and compares it with the checked-in file.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import generate_pmf1_golden_vectors as golden  # noqa: E402

FIXTURES = ROOT / "fixtures/conformance"
PROBLEM_TYPES = ROOT / "contracts/gateway/v1/problem-types.json"
BLAKE3_VECTORS = HERE / "data/blake3_test_vectors.json"
SCHEMA_DIGESTS_RUST = ROOT / "apps/pos-gateway-conformance-adapter/src/subject/schema_digests.rs"

CLAIM_LAYER = "gateway-client-conformance"
SCHEMA_ID = "pigloros.gateway-client-conformance.case.v2"
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
EXECUTION_MODES = ("local", "air-gapped")

# --- The fixture identities of the requirements text (section "Compositions") ---

# The actor of the `authorized` composition, sent as `x-piglor-actor-entity` when an exchange
# sets `actor`; the World body its fixture catalogue knows; the entity of every Society Signal.
ACTOR = "01JC0GATEWAYF1XTVREACT0R00"
BODY = "01JC0GATEWAYF1XTVREB0DY000"
ENTITY = "01JC0GATEWAYF1XTVRES1GNA10"
ULID_PATTERN = "[0-7][0-9A-HJKMNP-TV-Z]{25}"
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
# The Principal of the authorized compositions' fixture Local Principal document: 16 bytes 0x01.
PRINCIPAL_BYTES = bytes([1]) * 16
# The ADR-134 digest of each Gateway execution-mode profile's current revision: the head of its
# rotation chain in `scripts/check_gateway_contract.py` (`--check` verifies the two agree).
MODE_PROFILE_DIGESTS = {
    "gateway-mode-air-gapped-v1":
        "d1513a3395c47d6a9102f75b575daef58123c7d62306c7c0398709db8c0daebb",
    "gateway-mode-local-v1": "26d6c7e75b11df673a1ef2d3210733b4ca431648eab0b9ae93bf4a6f6e69da3f",
}
# The operations the fixture Local Principal is granted, sorted: what its Session discloses.
PRINCIPAL_GRANTS = ["session.read", "timeline.create", "timeline.events.read"]
# The operations the `authorized-consented` fixture Principal is granted (#309), sorted; its one
# consent governs `timeline.create`.
CONSENTED_GRANTS = ["consent.revoke", "session.read", "timeline.create", "timeline.events.read"]
# The operations the `authorized-rooms` fixture Principal is granted (#303), sorted; its one
# consent, export permitted, governs `timeline.create`, is named as a room's
# `privacy_export_ref` and may be revoked.
ROOM_GRANTS = [
    "consent.revoke",
    "scenario-room.create",
    "scenario-room.derive",
    "scenario-room.read",
    "session.read",
    "timeline.create",
]
# The single-participant governance record the `authorized-rooms` Principal document records.
GOVERNANCE = "01JC0GATEWAYW90G0VERN00001"
# The society participant of the fixture rooms, which the grant need not name.
SOCIETY = "01JC0GATEWAYW90S0C1ETY0001"
CURSOR_PATTERN = f"v1\\.[0-9a-f]{{64}}\\.{ULID_PATTERN}\\.[1-9][0-9]*"

# The route of a request path (query removed) and the capability it needs (section "Routes").
ROUTE_CAPABILITY = {
    "health": "gateway.health.read",
    "ledger": "gateway.ledger.read",
    "create": "timeline.create",
    "events": "timeline.events.read",
    "signals": "timeline.signals.append",
    "actions": "world.action.v1.submit",
    "session": "session.read",
    "revoke": "consent.revoke",
    "erasures": "erasure.request",
    "erasure": "erasure.read",
    "rooms": "scenario-room.create",
    "revisions": "scenario-room.derive",
    "revision": "scenario-room.read",
}
CAPABILITIES = tuple(sorted(ROUTE_CAPABILITY.values()))
# The Events a `201` response of a route commits (requirements section 5): a room create or
# derive appends its request claim and the revision.
COMMITTED_EVENTS = {"signals": 1, "actions": 1, "revoke": 1, "rooms": 2, "revisions": 2}
MAX_TIMELINES = 64  # README "Timeline bound"
EVENT_LIMIT = 100  # README "Polling": limit defaults to and may not exceed 100


def route_of(path: str) -> str | None:
    base = path.split("?", 1)[0]
    fixed = {
        "/health": "health",
        "/v1/ledger": "ledger",
        "/v1/timelines": "create",
        "/v1/session": "session",
        "/v1/me/consent-revocations": "revoke",
        "/v1/me/erasures": "erasures",
    }
    if base in fixed:
        return fixed[base]
    match = re.fullmatch(r"/v1/timelines/([^/]+)/(events|signals|actions)", base)
    if match:
        return match.group(2)
    if re.fullmatch(r"/v1/me/erasures/[^/]+", base):
        return "erasure"
    if re.fullmatch(r"/v1/scenario-rooms/[^/]+/revisions", base):
        return "revisions"
    if re.fullmatch(r"/v1/scenario-rooms/[^/]+/revisions/[1-9][0-9]*", base):
        return "revision"
    return "rooms" if base == "/v1/scenario-rooms" else None


# --- Deterministic CBOR (only what a `society.signal` payload uses) ---


def cbor_head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([major << 5 | value])
    if value < 0x100:
        return bytes([major << 5 | 24, value])
    return bytes([major << 5 | 25]) + value.to_bytes(2, "big")


def cbor_text(text: str) -> bytes:
    data = text.encode("utf-8")
    return cbor_head(3, len(data)) + data


def cbor_float(value: float) -> bytes:
    """The shortest IEEE 754 width that holds `value` exactly: half, single, then double."""
    half = struct.pack(">e", value)
    if struct.unpack(">e", half)[0] == value:
        return b"\xf9" + half
    single = struct.pack(">f", value)
    if struct.unpack(">f", single)[0] == value:
        return b"\xfa" + single
    return b"\xfb" + struct.pack(">d", value)


def signal_payload(dimension: str, value: float, subject: str | None) -> bytes:
    """A stored `society.signal` payload: a map of four text keys in declaration order."""
    fields = (
        ("dimension", cbor_text(dimension)),
        ("value", cbor_float(value)),
        ("subject", b"\xf6" if subject is None else cbor_text(subject)),
        ("object", b"\xf6"),
    )
    return cbor_head(5, len(fields)) + b"".join(cbor_text(k) + v for k, v in fields)


# --- Exchanges ---


@dataclass
class Exchange:
    router: str
    method: str
    path: str
    expect: dict
    actor: bool = False
    body: object = None
    has_body: bool = False
    # The slot this exchange's response fills: `timeline` or `room` (its `id`), `consent`
    # (the `consent_ref` of its first consent) or `erasure` (its `request_id`).
    capture: str | None = None

    def payload(self) -> dict:
        value: dict = {
            "router": self.router,
            "method": self.method,
            "path": self.path,
            "expect": self.expect,
        }
        if self.actor:
            value["actor"] = True
        if self.has_body:
            value["body"] = self.body
        if self.capture is not None:
            value["capture"] = self.capture
        return value


@dataclass
class SubCase:
    id: str
    title: str
    composition: str
    exchanges: list[Exchange]
    canary: str | None = None
    extra: dict = field(default_factory=dict)


def json_body(value: object) -> dict:
    return {"json": value}


def observed(status: int, body: object) -> dict:
    return {"status": status, "body": body}


def problem_titles() -> dict[str, str]:
    registry = json.loads(PROBLEM_TYPES.read_text(encoding="utf-8"))
    return {entry["code"]: entry["title"] for entry in registry["problem_types"]}


def route_template(path: str) -> str:
    """The problem `instance` of a routed request: its route template, never a run-local ID."""
    base = path.split("?", 1)[0]
    return re.sub(r"^/v1/timelines/[^/]+/", "/v1/timelines/{timeline_id}/", base)


def problem(status: int, code: str, instance: str, retryable: bool = False) -> dict:
    """An RFC 9457 problem of the v1 registry; its detail text is normalized away."""
    return observed(
        status,
        json_body(
            {
                "code": code,
                "detail": "<message>",
                "instance": instance,
                "retryable": retryable,
                "schema_id": "urn:pigloros:gateway:v1:schema:problem",
                "status": status,
                "title": problem_titles()[code],
                "type": f"urn:pigloros:gateway:v1:problem:{code}",
            }
        ),
    )


def routed_problem(status: int, code: str, path: str) -> dict:
    return problem(status, code, route_template(path))


def not_routed(path: str) -> dict:
    """The answer of a router that serves no such path: `instance` is the request path, whose
    captured Timeline ID the normalization turns into `<ulid>`."""
    return problem(404, "not-found-or-unavailable", path.replace("{timeline}", "<ulid>"))


def ulid_text(data: bytes) -> str:
    """The canonical Crockford base32 text of a 16-byte ULID."""
    value = int.from_bytes(data, "big")
    return "".join(CROCKFORD[(value >> (5 * (25 - index))) & 31] for index in range(26))


def session_body(
    mode_profile_id: str,
    mode: str,
    network: str,
    grants: list[str] | None = None,
    generation: int = 1,
    consents: list[dict] | None = None,
) -> dict:
    """The `Session` the contract prescribes for the fixture Local Principal: by default
    generation 1 (its one grant is issued at authority position 1 and binds no consent), binding
    epoch 1, no operator network grant, and the provenance digest of the `Session` schema
    description."""
    principal = ulid_text(PRINCIPAL_BYTES)
    digest = MODE_PROFILE_DIGESTS[mode_profile_id]
    record = (
        b"PiglorOS.GatewaySession.v1\x00"
        + PRINCIPAL_BYTES
        + generation.to_bytes(8, "big")
        + digest.encode("ascii")
        + (1).to_bytes(8, "big")
    )
    return {
        "availability": {"state": "available", "withheld": []},
        "consents": [] if consents is None else consents,
        "contract": {"api_major": "v1", "contract_version": "1.0.0-draft"},
        "execution_profile": {
            "profile_kind": "epf1",
            "reason": "not-installed",
            "state": "unavailable",
        },
        "generation": generation,
        "grants": PRINCIPAL_GRANTS if grants is None else grants,
        "id": "<ulid>",
        "mode_profile": {
            "binding_epoch": 1,
            "mode": mode,
            "mode_profile_digest": digest,
            "mode_profile_id": mode_profile_id,
            "network": network,
            "network_grants": [],
            "profile_kind": "gateway-mode-v1",
        },
        "principal": {"entity_ids": [ACTOR], "principal_id": principal},
        "provenance": {"digest": golden.blake3(record).hex(), "origin": "host-derived"},
        "schema_id": "urn:pigloros:gateway:v1:schema:session",
    }


def session(expect: dict, actor: bool = True, capture: str | None = None) -> Exchange:
    return Exchange("loopback", "GET", "/v1/session", expect, actor=actor, capture=capture)


def consent_revocation_body(generation: int) -> dict:
    """The `ConsentRevocation` the contract prescribes for the `authorized-consented` fixture
    Principal's one consent, revoked at consent Timeline sequence 2 (its `generation`), under the
    Local binding at epoch 1, with the provenance digest of the `ConsentRevocation` schema
    description."""
    digest = MODE_PROFILE_DIGESTS["gateway-mode-local-v1"]
    record = (
        b"PiglorOS.GatewayConsentRevocation.v1\x00"
        + PRINCIPAL_BYTES
        + generation.to_bytes(8, "big")
        + digest.encode("ascii")
        + (1).to_bytes(8, "big")
    )
    return {
        "availability": {"state": "available", "withheld": []},
        "consent_ref": "{consent}",
        "execution_profile": {
            "profile_kind": "epf1",
            "reason": "not-installed",
            "state": "unavailable",
        },
        "future_protected_work": "denied",
        "generation": generation,
        "id": "<ulid>",
        "mode_profile": {
            "binding_epoch": 1,
            "mode": "local",
            "mode_profile_digest": digest,
            "mode_profile_id": "gateway-mode-local-v1",
            "profile_kind": "gateway-mode-v1",
        },
        "provenance": {"digest": golden.blake3(record).hex(), "origin": "host-derived"},
        "schema_id": "urn:pigloros:gateway:v1:schema:consent-revocation",
        "state": "revoked",
    }


def revoke(expect: dict) -> Exchange:
    """Revoke the consent the last `consent` capture named, as the fixture actor."""
    return Exchange(
        "loopback",
        "POST",
        "/v1/me/consent-revocations",
        expect,
        actor=True,
        body={"consent_ref": "{consent}"},
        has_body=True,
    )


ROOMS_PATH = "/v1/scenario-rooms"
ROOM_REVISIONS_PATH = f"{ROOMS_PATH}/{{room}}/revisions"
# The problem `instance` of the derive route: its route template.
ROOM_REVISIONS_INSTANCE = f"{ROOMS_PATH}/{{room_id}}/revisions"
ROOM_REVISION_SCHEMA = "urn:pigloros:gateway:v1:schema:scenario-room-revision"
ROOM_PLUGIN = {"plugin_id": "gateway-world-actions", "version": "0.1.0"}
# The Event types the reviewed host catalogue entry of the room plugin owns.
ROOM_PLUGIN_EVENT_TYPES = ["world.action.v1"]
CAPABILITY_SET_TAG = b"PiglorOS.ScenarioRoom.CapabilitySet.v1\x00"
PLUGIN_COMPOSITION_TAG = b"PiglorOS.ScenarioRoom.PluginComposition.v1\x00"


def framed(data: bytes) -> bytes:
    return len(data).to_bytes(8, "little") + data


def plugin_composition_hash() -> str:
    """The ADR-041 amendment A4 hash of the fixture room's one plugin: its name, version and
    the hash of its sorted, distinct capability (owned Event type) names."""
    names = sorted(set(ROOM_PLUGIN_EVENT_TYPES))
    capabilities = golden.blake3(
        CAPABILITY_SET_TAG + len(names).to_bytes(8, "little") + b"".join(
            framed(name.encode("ascii")) for name in names
        )
    )
    return golden.blake3(
        PLUGIN_COMPOSITION_TAG
        + (1).to_bytes(8, "little")
        + framed(ROOM_PLUGIN["plugin_id"].encode("ascii"))
        + framed(ROOM_PLUGIN["version"].encode("ascii"))
        + capabilities
    ).hex()


def room_rules(value_micro: int) -> list[dict]:
    return [{"rule_id": "gateway-world-actions.nudge.scale", "value_micro": value_micro}]


def room_descriptor(
    value_micro: int,
    privacy_export_ref: str = "{consent}",
    governance_ref: str = GOVERNANCE,
    persona: str = ACTOR,
) -> dict:
    """The fixture room's `ScenarioRoomInput`: one persona (by default the fixture actor) and
    one society participant, the fixture plugin and one rule of it, the governance record (by
    default the recorded one) and the consent (by default the last `consent` capture)."""
    return {
        "governance_ref": governance_ref,
        "initial_conditions": [{"dimension": "trust", "entity_id": SOCIETY, "value_micro": 600000}],
        "intervention_policy": 1,
        "max_ticks": 600,
        "participants": [
            {"entity_id": persona, "kind": "persona"},
            {"entity_id": SOCIETY, "kind": "society"},
        ],
        "plugins": [ROOM_PLUGIN],
        "privacy_export_ref": privacy_export_ref,
        "rules": room_rules(value_micro),
        "schema_version": 1,
        "scheduler_policy": 0,
        "scheduler_seed": "04" * 32,
        "tick_duration_ms": 100,
    }


def room_revision_body(revision: int, value_micro: int, seq: int) -> dict:
    """The `ScenarioRoomRevision` the contract prescribes for a fixture room revision committed
    at `seq` of its room Timeline, under the Local binding at epoch 1. It echoes the captured
    room as its `id` and `room_id` and the captured consent as its `privacy_export_ref`; the
    Timeline and Event IDs, the correlation ID, the descriptor hash and the provenance digest
    (which covers the descriptor hash) are run-local and normalized."""
    descriptor = room_descriptor(value_micro)
    descriptor.update(
        {
            "correlation_id": "<correlation>",
            "descriptor_hash": "<hash>",
            "plugin_composition_hash": plugin_composition_hash(),
            "revision": revision,
            "room_id": "{room}",
            "rule_set_hash": golden.blake3(jcs(room_rules(value_micro))).hex(),
        }
    )
    return {
        "availability": {"state": "available", "withheld": []},
        "commit": {
            "event_id": "<ulid>",
            "event_schema_id": "room.revision.v1",
            "next_cursor": "<cursor>",
            "schema_id": "urn:pigloros:gateway:v1:schema:committed-event-receipt",
            "seq": seq,
            "timeline_id": "<ulid>",
        },
        "descriptor": descriptor,
        "execution_profile": {
            "profile_kind": "epf1",
            "reason": "not-installed",
            "state": "unavailable",
        },
        "id": "{room}",
        "mode_profile": {
            "binding_epoch": 1,
            "mode": "local",
            "mode_profile_digest": MODE_PROFILE_DIGESTS["gateway-mode-local-v1"],
            "mode_profile_id": "gateway-mode-local-v1",
            "profile_kind": "gateway-mode-v1",
        },
        "parent_revision": None if revision == 1 else revision - 1,
        "provenance": {"digest": "<hash>", "origin": "principal-authored"},
        "revision": revision,
        "schema_id": ROOM_REVISION_SCHEMA,
    }


def create_room(
    expect: dict, capture: bool = False, value_micro: int = 250000, **descriptor: str
) -> Exchange:
    return Exchange(
        "loopback",
        "POST",
        ROOMS_PATH,
        expect,
        actor=True,
        body={"descriptor": room_descriptor(value_micro, **descriptor)},
        has_body=True,
        capture="room" if capture else None,
    )


def derive_room(expect: dict, value_micro: int, parent_revision: int = 1) -> Exchange:
    return Exchange(
        "loopback",
        "POST",
        ROOM_REVISIONS_PATH,
        expect,
        actor=True,
        body={"descriptor": room_descriptor(value_micro), "parent_revision": parent_revision},
        has_body=True,
    )


def room_session(*consents: str) -> Exchange:
    """The `authorized-rooms` Principal's Session, capturing its consent: the capture is
    observed with the slot it fills, so the consent reads `{consent}`."""
    listed = [
        {"consent_ref": "{consent}", "export_permitted": True, "state": state}
        for state in consents
    ]
    body = session_body("gateway-mode-local-v1", "local", "denied", ROOM_GRANTS, 3, listed)
    return session(observed(200, json_body(body)), capture="consent")


def room_exchanges() -> list[Exchange]:
    """#303: a room is created (`201`), answered with its original on an exact retry (`200`),
    read back, and derived to revision 2, the third Event of its room Timeline after the
    derive's request claim."""
    created = room_revision_body(1, 250000, 1)
    return [
        room_session("granted"),
        create_room(observed(201, json_body(created)), capture=True),
        create_room(observed(200, json_body(created))),
        Exchange(
            "loopback",
            "GET",
            f"{ROOM_REVISIONS_PATH}/1",
            observed(200, json_body(created)),
            actor=True,
        ),
        derive_room(observed(201, json_body(room_revision_body(2, 500000, 3))), 500000),
    ]


def room_conflict_exchanges() -> list[Exchange]:
    """#303: the sub-case's one idempotency key used for a different create is
    `409 idempotency-conflict`; a derive repeated from the same parent hashes like the head and
    answers it (`200`, the ADR-041 section 7 duplicate), and a different derive from that
    non-head parent is `409 append-conflict`."""
    derived = observed(200, json_body(room_revision_body(2, 500000, 3)))
    return [
        room_session("granted"),
        create_room(observed(201, json_body(room_revision_body(1, 250000, 1))), capture=True),
        create_room(routed_problem(409, "idempotency-conflict", ROOMS_PATH), value_micro=1),
        derive_room(observed(201, json_body(room_revision_body(2, 500000, 3))), 500000),
        derive_room(derived, 500000),
        derive_room(problem(409, "append-conflict", ROOM_REVISIONS_INSTANCE), 750000),
    ]


REFUSED = {"refused": "capability-denied"}
EMPTY_PAGE = observed(
    200, json_body({"events": [], "next_cursor": None, "next_from_seq": None})
)
TIMELINE_PATH = "/v1/timelines/{timeline}"
EVENTS_PATH = f"{TIMELINE_PATH}/events"
ACTIONS_PATH = f"{TIMELINE_PATH}/actions"
SIGNALS_PATH = f"{TIMELINE_PATH}/signals"


def health(router: str = "loopback") -> Exchange:
    return Exchange(router, "GET", "/health", observed(200, json_body({"ok": True})))


def ledger(router: str = "loopback") -> Exchange:
    view = {"domain": "piglor.com", "ledger": [], "path": "/ledger"}
    return Exchange(router, "GET", "/v1/ledger", observed(200, json_body(view)))


def create(
    name: str, capture: bool = True, expect: dict | None = None, actor: bool = False
) -> Exchange:
    """Create a Timeline; on the `authorized` Gateway the fixture actor must send it (#1361)."""
    created = observed(201, json_body({"head": 0, "id": "<ulid>", "name": name}))
    return Exchange(
        "loopback",
        "POST",
        "/v1/timelines",
        created if expect is None else expect,
        actor=actor,
        body={"name": name},
        has_body=True,
        capture="timeline" if capture else None,
    )


def poll(expect: dict, query: str = "", actor: bool = False, router: str = "loopback") -> Exchange:
    return Exchange(router, "GET", f"{EVENTS_PATH}{query}", expect, actor=actor)


def signal_request(subject: str) -> dict:
    return {
        "entity_id": ENTITY,
        "dimension": "trust",
        "value": 0.5,
        "subject": subject,
        "object": None,
    }


def signal_view(subject: str, seq: int) -> dict:
    return {
        "entity": ENTITY,
        "event_type": "society.signal",
        "id": "<ulid>",
        "payload": {"dimension": "trust", "object": None, "subject": subject, "value": 0.5},
        "payload_hex": signal_payload("trust", 0.5, subject).hex(),
        "seq": seq,
    }


def signal(subject: str, expect: dict, router: str = "loopback") -> Exchange:
    return Exchange(
        router,
        "POST",
        SIGNALS_PATH,
        expect,
        body=signal_request(subject),
        has_body=True,
    )


def world_action(params: list) -> dict:
    return {
        "actor_entity_id": ACTOR,
        "body_entity_id": BODY,
        "action_kind": "impulse",
        "params": params,
        "action_scope": 0,
        "catalogue_version": 1,
        "tick": 1,
    }


def action(
    expect: dict,
    params: list | None = None,
    event_type: str = "world.action.v1",
    capability: str = "world.action.v1.submit",
) -> Exchange:
    body = {
        "entity_id": ACTOR,
        "event_type": event_type,
        "capability": capability,
        "payload": world_action([0.5, 0.25] if params is None else params),
    }
    return Exchange(
        "loopback", "POST", ACTIONS_PATH, expect, body=body, has_body=True
    )


ERASURES_PATH = "/v1/me/erasures"
ERASURE_PATH = f"{ERASURES_PATH}/{{erasure}}"
# The problem `instance` of the getErasure route: its route template.
ERASURE_INSTANCE = f"{ERASURES_PATH}/{{erasure_id}}"
# An erasure ID no fixture Gateway holds.
UNKNOWN_ERASURE = "01JC0GATEWAYW90ERASVRE0001"
# The compiled Local erasure policy (ELP1) every Local erasure request pins (ADR-136 §4): the
# digest pos-runtime pins as LOCAL_ERASURE_POLICY_REFERENCE_V1 and recomputes in its tests.
LOCAL_ERASURE_POLICY = "e12e33dfd34dade0faf2ce530a187226eaae154bf195c3ad9e30404f86b0b83d"
RETAINED_CLASSES = ["public-record", "aggregate", "structural-audit-metadata"]


def erasure_request(scope: str, impact: bool = True) -> dict:
    return {"scope": scope, "impact_acknowledged": impact}


def request_erasure(
    expect: dict, scope: str = "private-subject-data", impact: bool = True, actor: bool = True,
    capture: bool = False,
) -> Exchange:
    """`requestErasure` as the fixture actor; every request carries the sub-case ID as its
    Idempotency-Key."""
    return Exchange(
        "loopback",
        "POST",
        ERASURES_PATH,
        expect,
        actor=actor,
        body=erasure_request(scope, impact),
        has_body=True,
        capture="erasure" if capture else None,
    )


def read_erasure(expect: dict, path: str = ERASURE_PATH) -> Exchange:
    return Exchange("loopback", "GET", path, expect, actor=True)


def admission_receipt(key: str) -> dict:
    """The `202` admission receipt of the captured erasure under the Idempotency-Key `key`:
    BLAKE3 of the key, the pinned policy, the Local mode profile, and the bundle digest that
    covers the store's own erasure identity, normalized away (ADR-136 §7)."""
    return {
        "bound_inputs": {
            "mode_profile": MODE_PROFILE_DIGESTS["gateway-mode-local-v1"],
            "policy": LOCAL_ERASURE_POLICY,
            "trust": "<hash>",
        },
        "idempotency_key_digest": golden.blake3(key.encode("ascii")).hex(),
        "operation_id": "{erasure}",
        "operation_url": f"{ERASURES_PATH}/<ulid>",
        "request_id": "{erasure}",
        "schema_id": "urn:pigloros:gateway:v1:schema:admission-receipt",
        "state": "admitted",
    }


def submitted_erasure() -> dict:
    """The `Erasure` of a submitted private-subject-data request no driver advanced: generation
    0, no obligation yet, the exact claim, and the ERS1 state digest normalized away."""
    return {
        "acknowledgements": {"classes": [], "positive": 0, "required": 0},
        "availability": {"state": "available", "withheld": []},
        "execution_profile": {
            "profile_kind": "epf1",
            "reason": "not-installed",
            "state": "unavailable",
        },
        "external_copies": "not-covered",
        "generation": 0,
        "id": "{erasure}",
        "mode_profile": {
            "binding_epoch": 1,
            "mode": "local",
            "mode_profile_digest": MODE_PROFILE_DIGESTS["gateway-mode-local-v1"],
            "mode_profile_id": "gateway-mode-local-v1",
            "profile_kind": "gateway-mode-v1",
        },
        "provenance": {"digest": "<hash>", "origin": "host-derived"},
        "replay_claim": "exact",
        "retained_classes": RETAINED_CLASSES,
        "schema_id": "urn:pigloros:gateway:v1:schema:erasure",
        "scope": "private-subject-data",
        "state": "submitted",
    }


def erasure_exchanges() -> list[Exchange]:
    """#1449: a request is admitted (`202`), an exact retry answers the same receipt, the same
    key for another scope is the `409` `idempotency-conflict` problem, and the erasure reads
    back as submitted."""
    receipt = observed(202, json_body(admission_receipt("pos.10")))
    return [
        request_erasure(receipt, capture=True),
        request_erasure(receipt),
        request_erasure(
            problem(409, "idempotency-conflict", ERASURES_PATH), scope="consented-shared-data"
        ),
        read_erasure(observed(200, json_body(submitted_erasure()))),
    ]


# --- Sub-cases, one list per family ---


def positive_subcases() -> list[SubCase]:
    page = {"events": [signal_view("alice", 1)], "next_cursor": None, "next_from_seq": None}
    return [
        SubCase("pos.1", "the health route answers ok", "open", [health()]),
        SubCase(
            "pos.2",
            "a created Timeline polls an empty exhausted page",
            "open",
            [create("pos-2"), poll(EMPTY_PAGE)],
        ),
        SubCase(
            "pos.3",
            "a committed Society Signal is polled back with its canonical payload",
            "open",
            [
                create("pos-3"),
                signal("alice", observed(201, json_body(signal_view("alice", 1)))),
                poll(observed(200, json_body(page)), "?from_seq=0&limit=1"),
            ],
        ),
        SubCase("pos.4", "the public Prediction Ledger JSON is empty", "open", [ledger()]),
        SubCase(
            "pos.5",
            "the Local Principal's Session discloses its grants and the Local mode",
            "authorized",
            [
                session(
                    observed(
                        200, json_body(session_body("gateway-mode-local-v1", "local", "denied"))
                    )
                )
            ],
        ),
        SubCase(
            "pos.6",
            "on an Air-Gapped store the Session discloses the Air-Gapped mode and no network",
            "authorized-air-gapped",
            [
                session(
                    observed(
                        200,
                        json_body(
                            session_body("gateway-mode-air-gapped-v1", "air-gapped", "absent")
                        ),
                    )
                )
            ],
        ),
        SubCase(
            "pos.7",
            "a revoked consent stops the operation it governs and is revoked exactly once",
            "authorized-consented",
            consent_revocation_exchanges(),
        ),
        SubCase(
            "pos.8",
            "a Scenario Room is created, retried, read and derived to its next revision",
            "authorized-rooms",
            room_exchanges(),
        ),
        SubCase(
            "pos.9",
            "a reused key and a stale parent conflict, and a repeated derive answers the head",
            "authorized-rooms",
            room_conflict_exchanges(),
        ),
        SubCase(
            "pos.10",
            "an erasure is admitted, replayed, refused for another scope and read as submitted",
            "authorized-erasure",
            erasure_exchanges(),
        ),
    ]


def consent_revocation_exchanges() -> list[Exchange]:
    """#309: the consent governs Timeline creation until it is revoked; the revocation is
    recorded once (`201`), answered with its original on a retry (`200`), and the Session then
    discloses it revoked and no longer lists the operation."""
    # The capturing Session is observed with the slot it fills, so the consent reads `{consent}`.
    granted = [{"consent_ref": "{consent}", "export_permitted": False, "state": "granted"}]
    revoked = [{"consent_ref": "{consent}", "export_permitted": False, "state": "revoked"}]
    without_create = [grant for grant in CONSENTED_GRANTS if grant != "timeline.create"]
    local = ("gateway-mode-local-v1", "local", "denied")
    return [
        session(
            observed(200, json_body(session_body(*local, CONSENTED_GRANTS, 3, granted))),
            capture="consent",
        ),
        create("pos-7", capture=False, actor=True),
        revoke(observed(201, json_body(consent_revocation_body(2)))),
        revoke(observed(200, json_body(consent_revocation_body(2)))),
        create("pos-7", capture=False, actor=True, expect=routed_problem(403, "revoked", "/v1/timelines")),
        session(observed(200, json_body(session_body(*local, without_create, 4, revoked)))),
    ]


def denied_subcases() -> list[SubCase]:
    return [
        SubCase(
            "den.1",
            "an action without a host authorizer is unauthorized and commits nothing",
            "open",
            [
                create("den-1"),
                action(routed_problem(401, "unauthenticated", ACTIONS_PATH)),
                poll(EMPTY_PAGE),
            ],
        ),
        SubCase(
            "den.2",
            "an action the fixture authority does not grant is forbidden and commits nothing",
            "authorized",
            [
                create("den-2", actor=True),
                action(routed_problem(403, "unauthorized", ACTIONS_PATH)),
                poll(EMPTY_PAGE, actor=True),
            ],
        ),
        SubCase(
            "den.3",
            "a route whose capability the attempt does not hold is refused before any request",
            "open",
            [Exchange("loopback", "GET", "/v1/ledger", REFUSED)],
        ),
        SubCase(
            "den.4",
            "a read without the actor header on an authorized Gateway is unauthorized",
            "authorized",
            [create("den-4", actor=True), poll(routed_problem(401, "unauthenticated", EVENTS_PATH))],
        ),
        SubCase(
            "den.5",
            "a Session read without the actor header on an authorized Gateway is unauthenticated",
            "authorized",
            [session(routed_problem(401, "unauthenticated", "/v1/session"), actor=False)],
        ),
        SubCase(
            "den.6",
            "a Gateway without a host authorizer has no Principal and no Session to disclose",
            "open",
            [session(routed_problem(401, "unauthenticated", "/v1/session"))],
        ),
        SubCase(
            "den.7",
            "a room naming a consent the Principal does not hold is consent-invalid",
            "authorized-rooms",
            [
                create_room(
                    routed_problem(403, "consent-invalid", ROOMS_PATH),
                    privacy_export_ref=BODY,
                )
            ],
        ),
        SubCase(
            "den.8",
            "a room naming a revoked consent is refused as revoked",
            "authorized-rooms",
            [
                room_session("granted"),
                revoke(observed(201, json_body(consent_revocation_body(2)))),
                create_room(routed_problem(403, "revoked", ROOMS_PATH)),
            ],
        ),
        SubCase(
            "den.9",
            "a room whose persona the grant does not cover is unauthorized",
            "authorized-rooms",
            [
                room_session("granted"),
                create_room(routed_problem(403, "unauthorized", ROOMS_PATH), persona=BODY),
            ],
        ),
        SubCase(
            "den.10",
            "without the erasure grants a request is unauthorized and a read finds nothing",
            "authorized",
            [
                request_erasure(problem(403, "unauthorized", ERASURES_PATH)),
                read_erasure(
                    problem(404, "not-found-or-unavailable", ERASURE_INSTANCE),
                    path=f"{ERASURES_PATH}/{UNKNOWN_ERASURE}",
                ),
                request_erasure(problem(401, "unauthenticated", ERASURES_PATH), actor=False),
            ],
        ),
        SubCase(
            "den.11",
            "a Gateway without the Local erasure authority serves no erasure",
            "authorized-erasure-closed",
            [
                request_erasure(problem(503, "temporarily-unavailable", ERASURES_PATH)),
                read_erasure(
                    problem(404, "not-found-or-unavailable", ERASURE_INSTANCE),
                    path=f"{ERASURES_PATH}/{UNKNOWN_ERASURE}",
                ),
            ],
        ),
        SubCase(
            "den.12",
            "an expired erasure bundle closes new erasure admissions",
            "authorized-erasure-expired",
            [request_erasure(problem(503, "temporarily-unavailable", ERASURES_PATH))],
        ),
    ]


def malformed_subcases() -> list[SubCase]:
    return [
        SubCase(
            "mal.1",
            "cursor together with from_seq is a bad query",
            "open",
            [
                create("mal-1"),
                poll(routed_problem(400, "invalid-request", EVENTS_PATH), "?from_seq=0&cursor=v1"),
            ],
        ),
        SubCase(
            "mal.2",
            "a page limit above 100 is a bad query",
            "open",
            [
                create("mal-2"),
                poll(routed_problem(400, "invalid-request", EVENTS_PATH), f"?limit={EVENT_LIMIT + 1}"),
            ],
        ),
        SubCase(
            "mal.3",
            "a Timeline ID that is not a ULID is a bad ID",
            "open",
            [
                Exchange(
                    "loopback",
                    "GET",
                    "/v1/timelines/not-a-timeline/events",
                    routed_problem(400, "invalid-request", "/v1/timelines/not-a-timeline/events"),
                )
            ],
        ),
        SubCase(
            "mal.4",
            "integer action params are an invalid typed payload and commit nothing",
            "authorized",
            [
                create("mal-4", actor=True),
                action(routed_problem(422, "admission-rejected", ACTIONS_PATH), params=[1, 2]),
                poll(EMPTY_PAGE, actor=True),
            ],
        ),
        SubCase(
            "mal.5",
            "a room naming a governance record the host does not record is rejected",
            "authorized-rooms",
            [
                room_session("granted"),
                create_room(
                    routed_problem(422, "admission-rejected", ROOMS_PATH), governance_ref=BODY
                ),
            ],
        ),
        SubCase(
            "mal.6",
            "an unacknowledged impact, a retained-only scope and a malformed erasure ID",
            "authorized-erasure",
            [
                request_erasure(problem(400, "invalid-request", ERASURES_PATH), impact=False),
                request_erasure(
                    problem(400, "erasure-scope-retained", ERASURES_PATH), scope="public-record"
                ),
                read_erasure(
                    problem(400, "invalid-request", ERASURE_INSTANCE),
                    path=f"{ERASURES_PATH}/not-an-erasure",
                ),
            ],
        ),
    ]


def resource_subcases() -> list[SubCase]:
    creates = [create(f"res-1-{index:02d}", capture=False) for index in range(1, MAX_TIMELINES + 1)]
    over = create(
        f"res-1-{MAX_TIMELINES + 1}",
        capture=False,
        expect=routed_problem(429, "resource-limit-exceeded", "/v1/timelines"),
    )
    return [
        SubCase(
            "res.1",
            "the 65th root Timeline exceeds the Timeline bound",
            "open",
            creates + [over],
        ),
        SubCase(
            "res.2",
            "a subject with an erasure in progress is refused another until it settles",
            "authorized-erasure-held",
            [
                request_erasure(
                    problem(429, "resource-limit-exceeded", ERASURES_PATH, retryable=True)
                )
            ],
        ),
    ]


CANARY = "synthetic-canary-del-1"


def redaction_subcases() -> list[SubCase]:
    page = {"events": [signal_view(CANARY, 1)], "next_cursor": None, "next_from_seq": None}
    return [
        SubCase(
            "del.1",
            "the public listener serves no Timeline route and no committed payload",
            "open",
            [
                create("del-1"),
                signal(CANARY, observed(201, json_body(signal_view(CANARY, 1)))),
                poll(not_routed(EVENTS_PATH), router="spectator"),
                signal(CANARY, not_routed(SIGNALS_PATH), router="spectator"),
                health("spectator"),
                ledger("spectator"),
                poll(observed(200, json_body(page))),
            ],
            canary=CANARY,
        )
    ]


def downgrade_subcases() -> list[SubCase]:
    return [
        SubCase(
            "dgr.1",
            "the legacy world.action event type is refused with no fallback",
            "authorized",
            [
                create("dgr-1", actor=True),
                action(
                    routed_problem(400, "unsupported-version", ACTIONS_PATH), event_type="world.action"
                ),
                poll(EMPTY_PAGE, actor=True),
            ],
        ),
        SubCase(
            "dgr.2",
            "the legacy world.action.submit capability is refused with no fallback",
            "authorized",
            [
                create("dgr-2", actor=True),
                action(
                    routed_problem(403, "unauthorized", ACTIONS_PATH), capability="world.action.submit"
                ),
                poll(EMPTY_PAGE, actor=True),
            ],
        ),
    ]


def independent_subcases() -> list[SubCase]:
    return [
        SubCase("ind.1", "the digest of the health exchange", "open", [health()]),
        SubCase(
            "ind.2",
            "the digest of a created Timeline and its empty page",
            "open",
            [create("ind-2"), poll(EMPTY_PAGE)],
        ),
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


def jcs(value) -> bytes:
    """RFC 8785 canonical JSON of ASCII text, integers, 0.5-style floats, booleans and null."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def subcase_payload(sub: SubCase) -> dict:
    value: dict = {
        "id": sub.id,
        "title": sub.title,
        "composition": sub.composition,
        "exchanges": [exchange.payload() for exchange in sub.exchanges],
    }
    if sub.canary is not None:
        value["canary"] = sub.canary
    return value


def subcase_record(family: str, sub: SubCase) -> dict:
    """The record a subject outputs for a sub-case whose every exchange is as expected."""
    exchanges = [exchange.expect for exchange in sub.exchanges]
    record: dict = {"id": sub.id, "exchanges": exchanges}
    if sub.canary is not None:
        record["prohibited_data_present"] = False
    if family == "independent-evaluation":
        record["digest"] = golden.blake3(jcs(exchanges)).hex()
    return record


def execution_result(context: Context, oracle: bytes) -> dict[str, object]:
    """The verifier-accepted result of one family (ADR-062 R8 provider dispatch section 10).

    A family is `executed` when the evaluator passes its case in both the Local and the
    Air-Gapped ExecutionProfile run, both Local-relaxation engineering evidence. A pass means the
    subject output is the exact oracle member (the actual digest is its BLAKE3) or the subject
    failure is the oracle's (the actual error is its code): both follow from the oracle alone.
    `apps/pos-gateway-conformance-adapter/tests/provider_dispatch_public.rs` re-executes every
    family and requires this record.
    """
    if context.oracle_kind == "canonical-output":
        result = {"actual_digest": golden.blake3(oracle).hex()}
    else:
        result = {"actual_error": context.code_id}
    return {
        "evidence": "local-relaxation",
        "modes": [{"mode": mode, "outcome": "pass", **result} for mode in EXECUTION_MODES],
    }


def render_family(family: str, context: Context) -> Outputs:
    subcases = SUBCASES[family]()
    payload_object = {
        "schema": SCHEMA_ID,
        "family": family,
        "subcases": [subcase_payload(sub) for sub in subcases],
    }
    payload = jcs(payload_object) + b"\n"
    if context.oracle_kind == "canonical-output":
        oracle_object = {
            "case_id": context.case_id,
            "claim_layer": CLAIM_LAYER,
            "family": family,
            "oracle": {"kind": "canonical-output"},
            "output": {"subcases": [subcase_record(family, sub) for sub in subcases]},
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
    oracle = jcs(oracle_object) + b"\n"
    evidence_object = {
        "claim_layer": CLAIM_LAYER,
        "case_id": context.case_id,
        "family": family,
        "input_blake3_digest": golden.blake3(payload).hex(),
        "status": "executed",
        "execution_result": execution_result(context, oracle),
        "executed_at": None,
    }
    return Outputs(
        payload=payload,
        oracle=oracle,
        evidence=(json.dumps(evidence_object, indent=2) + "\n").encode("ascii"),
    )


# --- Provider schemas ---


def family_schema(family: str) -> dict:
    observation = {
        "oneOf": [
            {
                "type": "object",
                "additionalProperties": False,
                "required": ["refused"],
                "properties": {"refused": {"const": "capability-denied"}},
            },
            {
                "type": "object",
                "additionalProperties": False,
                "required": ["status", "body"],
                "properties": {
                    "status": {"type": "integer", "minimum": 100, "maximum": 599},
                    "body": {
                        "oneOf": [
                            {"const": "non-json"},
                            {
                                "type": "object",
                                "additionalProperties": False,
                                "required": ["json"],
                                "properties": {"json": {}},
                            },
                        ]
                    },
                },
            },
        ]
    }
    exchange = {
        "type": "object",
        "additionalProperties": False,
        "required": ["router", "method", "path", "expect"],
        "properties": {
            "router": {"enum": ["loopback", "spectator"]},
            "method": {"enum": ["GET", "POST"]},
            "path": {"type": "string", "pattern": "^/[!-~]{0,255}$"},
            "actor": {"const": True},
            "body": {},
            "capture": {"enum": ["timeline", "consent", "room", "erasure"]},
            "expect": {"$ref": "#/$defs/observation"},
        },
    }
    subcase = {
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "title", "composition", "exchanges"],
        "properties": {
            "id": {"type": "string", "pattern": f"^{ID_PREFIX[family]}\\.[0-9]+$"},
            "title": {"type": "string", "pattern": "^[ -~]{1,160}$"},
            "composition": {
                "enum": [
                    "open",
                    "authorized",
                    "authorized-air-gapped",
                    "authorized-consented",
                    "authorized-rooms",
                    "authorized-erasure",
                    "authorized-erasure-held",
                    "authorized-erasure-expired",
                    "authorized-erasure-closed",
                ]
            },
            "exchanges": {
                "type": "array",
                "minItems": 1,
                "maxItems": 128,
                "items": {"$ref": "#/$defs/exchange"},
            },
            "canary": {"type": "string", "pattern": "^[!-~]{1,64}$"},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"urn:pigloros:gateway-client-conformance:case:v2:{family}",
        "title": f"Gateway client conformance case payload, family {family}",
        "type": "object",
        "additionalProperties": False,
        "required": ["schema", "family", "subcases"],
        "properties": {
            "schema": {"const": SCHEMA_ID},
            "family": {"const": family},
            "subcases": {
                "type": "array",
                "minItems": 1,
                "maxItems": 64,
                "items": {"$ref": "#/$defs/subcase"},
            },
        },
        "$defs": {"observation": observation, "exchange": exchange, "subcase": subcase},
    }


def schema_path(family: str) -> Path:
    return FIXTURES / f"providers/{CLAIM_LAYER}/schemas/{family}.schema.json"


def _type_ok(value: object, name: str) -> bool:
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
    if "oneOf" in schema:
        matching = sum(not schema_errors(value, option, root, where) for option in schema["oneOf"])
        return [] if matching == 1 else [f"{where}: {matching} alternatives match"]
    if "type" in schema and not _type_ok(value, schema["type"]):
        return [f"{where}: wrong type"]
    found: list[str] = []
    if "const" in schema and (value != schema["const"] or type(value) is not type(schema["const"])):
        found.append(f"{where}: not the constant")
    if "enum" in schema and value not in schema["enum"]:
        found.append(f"{where}: not in the enumeration")
    if isinstance(value, str) and "pattern" in schema and not re.search(schema["pattern"], value):
        found.append(f"{where}: pattern")
    if isinstance(value, int) and not isinstance(value, bool):
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            found.append(f"{where}: out of range")
    if isinstance(value, list):
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", len(value)):
            found.append(f"{where}: item count")
        for index, item in enumerate(value):
            if "items" in schema:
                found.extend(schema_errors(item, schema["items"], root, f"{where}[{index}]"))
    if isinstance(value, dict):
        found.extend(f"{where}: missing {key}" for key in schema.get("required", []) if key not in value)
        properties = schema.get("properties", {})
        for key, item in value.items():
            if key in properties:
                found.extend(schema_errors(item, properties[key], root, f"{where}.{key}"))
            elif schema.get("additionalProperties", True) is False:
                found.append(f"{where}: unexpected {key}")
    return found


# --- Self-tests (--check) ---


def check_blake3_vectors() -> None:
    golden.self_test()
    vectors = json.loads(BLAKE3_VECTORS.read_text(encoding="utf-8"))
    for case in vectors["cases"]:
        data = bytes(index % 251 for index in range(case["input_len"]))
        if golden.blake3(data).hex() != case["hash"][:64]:
            raise SystemExit(f"BLAKE3 hash failed for length {case['input_len']}")


def cbor_decode(data: bytes) -> object:
    """An independent decoder of the CBOR subset of a signal payload (text, map, null, floats)."""

    def item(pos: int) -> tuple[object, int]:
        initial = data[pos]
        major, info = initial >> 5, initial & 0x1F
        if initial == 0xF6:
            return None, pos + 1
        if initial == 0xF9:
            return struct.unpack(">e", data[pos + 1 : pos + 3])[0], pos + 3
        if initial == 0xFA:
            return struct.unpack(">f", data[pos + 1 : pos + 5])[0], pos + 5
        if initial == 0xFB:
            return struct.unpack(">d", data[pos + 1 : pos + 9])[0], pos + 9
        if info < 24:
            length, pos = info, pos + 1
        elif info == 24:
            length, pos = data[pos + 1], pos + 2
        else:
            length, pos = int.from_bytes(data[pos + 1 : pos + 3], "big"), pos + 3
        if major == 3:
            return data[pos : pos + length].decode("utf-8"), pos + length
        if major == 5:
            value: dict = {}
            for _ in range(length):
                key, pos = item(pos)
                value[key], pos = item(pos)  # type: ignore[index]
            return value, pos
        raise SystemExit(f"unexpected CBOR major type {major}")

    value, end = item(0)
    if end != len(data):
        raise SystemExit("trailing CBOR bytes")
    return value


def every_subcase() -> list[tuple[str, SubCase]]:
    return [(family, sub) for family in FAMILIES for sub in SUBCASES[family]()]


def check_signal_payloads() -> None:
    """Each payload_hex decodes back to the polled `payload` view and to the request."""
    for family, sub in every_subcase():
        for exchange in sub.exchanges:
            body = exchange.expect.get("body")
            views = []
            if isinstance(body, dict) and isinstance(body.get("json"), dict):
                value = body["json"]
                views = value.get("events", [value]) if "events" in value else [value]
            for view in views:
                if not isinstance(view, dict) or "payload_hex" not in view:
                    continue
                decoded = cbor_decode(bytes.fromhex(view["payload_hex"]))
                if list(decoded) != ["dimension", "value", "subject", "object"]:
                    raise SystemExit(f"{sub.id}: the signal keys are not in declaration order")
                if decoded != view["payload"]:
                    raise SystemExit(f"{sub.id}: payload_hex does not decode to the payload view")
                if view["entity"] != ENTITY:
                    raise SystemExit(f"{sub.id}: the signal entity is not the fixture entity")
    if cbor_float(0.5) != b"\xf9\x38\x00" or cbor_float(0.1)[0] != 0xFB:
        raise SystemExit("the shortest-float rule is broken")


# The members whose ULID segments are permitted nondeterministic operational fields.
ULID_KEYS = (
    "id",
    "instance",
    "consent_ref",
    "timeline_id",
    "event_id",
    "request_id",
    "operation_id",
    "operation_url",
)
# The `(schema_id, member, field)` digests a placeholder replaces in an object of that schema:
# a room revision's provenance covers its run-local descriptor hash and Event ID, and an
# erasure's ERS1 state digest and an admission receipt's bundle digest cover the store's own
# erasure identity (#1449).
MASKED_DIGESTS = (
    (ROOM_REVISION_SCHEMA, "provenance", "digest"),
    ("urn:pigloros:gateway:v1:schema:erasure", "provenance", "digest"),
    ("urn:pigloros:gateway:v1:schema:admission-receipt", "bound_inputs", "trust"),
)
# `n` lowercase hex digits, not all zero (the contract's hash and correlation ID patterns).
NONZERO_HEX = "(?!0+$)[0-9a-f]{{{}}}"


def substitute(value: object, captured: dict[str, str]) -> object:
    """Every text value equal to a captured value becomes its slot literal (`{consent}`,
    `{room}`), before the normalization, so an echo of a captured value is pinned."""
    if isinstance(value, dict):
        return {name: substitute(item, captured) for name, item in value.items()}
    if isinstance(value, list):
        return [substitute(item, captured) for item in value]
    if isinstance(value, str):
        return next((slot for slot, text in captured.items() if text == value), value)
    return value


def normalize(value: object, key: str | None = None) -> object:
    """The normalization of the requirements text, on a parsed JSON response value."""
    if isinstance(value, dict):
        members = {name: normalize(item, name) for name, item in value.items()}
        for schema, member, field_name in MASKED_DIGESTS:
            masked = members.get(member)
            if (
                members.get("schema_id") == schema
                and isinstance(masked, dict)
                and isinstance(masked.get(field_name), str)
                and re.fullmatch(NONZERO_HEX.format(64), masked[field_name])
            ):
                members[member] = {**masked, field_name: "<hash>"}
        return members
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, str):
        if key == "next_cursor" and re.fullmatch(CURSOR_PATTERN, value):
            return "<cursor>"
        if key == "detail":
            return "<message>"
        if key in ULID_KEYS:
            return "/".join(
                "<ulid>" if re.fullmatch(ULID_PATTERN, part) else part for part in value.split("/")
            )
        if key == "correlation_id" and re.fullmatch(NONZERO_HEX.format(32), value):
            return "<correlation>"
        if key == "descriptor_hash" and re.fullmatch(NONZERO_HEX.format(64), value):
            return "<hash>"
    return value


def check_normalization() -> None:
    ulid = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    raw = {
        "events": [{"id": ulid, "entity": ulid, "seq": 1}],
        "next_cursor": f"v1.{'ab' * 32}.{ulid}.2",
        "next_from_seq": 2,
        "detail": "no such Timeline",
        "instance": f"/v1/timelines/{ulid}/events",
    }
    wanted = {
        "events": [{"id": "<ulid>", "entity": ulid, "seq": 1}],
        "next_cursor": "<cursor>",
        "next_from_seq": 2,
        "detail": "<message>",
        "instance": "/v1/timelines/<ulid>/events",
    }
    if normalize(raw) != wanted:
        raise SystemExit("the normalization rules are broken")
    # A value that is not a ULID or a cursor stays raw, so the exchange cannot match.
    if normalize({"id": "8ZZZZZZZZZZZZZZZZZZZZZZZZZ", "next_cursor": "v1.x"}) != {
        "id": "8ZZZZZZZZZZZZZZZZZZZZZZZZZ",
        "next_cursor": "v1.x",
    }:
        raise SystemExit("the normalization accepts a non-ULID")
    room_id, consent = "01ARZ3NDEKTSV4RRFFQ69G5FAW", "01ARZ3NDEKTSV4RRFFQ69G5FAX"
    captured = {"{consent}": consent, "{room}": room_id}
    room = {
        "schema_id": ROOM_REVISION_SCHEMA,
        "id": room_id,
        "descriptor": {
            "room_id": room_id,
            "privacy_export_ref": consent,
            "governance_ref": ulid,
            "correlation_id": "5f" * 16,
            "descriptor_hash": "ab" * 32,
            "rule_set_hash": "ab" * 32,
        },
        "commit": {"timeline_id": ulid, "event_id": ulid},
        "provenance": {"digest": "cd" * 32, "origin": "principal-authored"},
    }
    if normalize(substitute(room, captured)) != {
        "schema_id": ROOM_REVISION_SCHEMA,
        "id": "{room}",
        "descriptor": {
            "room_id": "{room}",
            "privacy_export_ref": "{consent}",
            "governance_ref": ulid,
            "correlation_id": "<correlation>",
            "descriptor_hash": "<hash>",
            "rule_set_hash": "ab" * 32,
        },
        "commit": {"timeline_id": "<ulid>", "event_id": "<ulid>"},
        "provenance": {"digest": "<hash>", "origin": "principal-authored"},
    }:
        raise SystemExit("the room normalization rules are broken")
    # An echo of another room or consent, an all-zero or malformed hash or correlation ID,
    # and a provenance digest outside a room revision stay raw.
    for kept in (
        {"room_id": ulid, "privacy_export_ref": ulid},
        {"correlation_id": "0" * 32, "descriptor_hash": "0" * 64},
        {"correlation_id": "5F" * 16, "descriptor_hash": "ab"},
        {"schema_id": ROOM_REVISION_SCHEMA, "provenance": {"digest": "0" * 64}},
        {"provenance": {"digest": "cd" * 32, "origin": "principal-authored"}},
    ):
        if normalize(substitute(kept, captured)) != kept:
            raise SystemExit(f"the room normalization changes {kept}")
    check_erasure_normalization(ulid)
    for constant in (ACTOR, BODY, ENTITY, ulid_text(PRINCIPAL_BYTES), UNKNOWN_ERASURE):
        if not re.fullmatch(ULID_PATTERN, constant):
            raise SystemExit(f"{constant} is not a ULID")
    if ulid_text(bytes(15) + bytes([33])) != "0" * 24 + "11":
        raise SystemExit("the ULID text encoding is broken")


def check_erasure_normalization(ulid: str) -> None:
    """A captured erasure is pinned, its operation URL and an uncaptured request ID lose their
    ULID, and only an erasure's provenance digest and a receipt's `trust` input are masked."""
    receipt = {
        "schema_id": "urn:pigloros:gateway:v1:schema:admission-receipt",
        "request_id": ulid,
        "operation_id": ulid,
        "operation_url": f"/v1/me/erasures/{ulid}",
        "bound_inputs": {"policy": "ab" * 32, "trust": "cd" * 32, "mode_profile": "ef" * 32},
    }
    if normalize(substitute(receipt, {"{erasure}": ulid})) != {
        **receipt,
        "request_id": "{erasure}",
        "operation_id": "{erasure}",
        "operation_url": "/v1/me/erasures/<ulid>",
        "bound_inputs": {"policy": "ab" * 32, "trust": "<hash>", "mode_profile": "ef" * 32},
    }:
        raise SystemExit("the admission receipt normalization rules are broken")
    erasure = {
        "schema_id": "urn:pigloros:gateway:v1:schema:erasure",
        "provenance": {"digest": "cd" * 32, "origin": "host-derived"},
    }
    if normalize(erasure)["provenance"]["digest"] != "<hash>":
        raise SystemExit("the erasure provenance normalization is broken")
    for kept in (
        {"bound_inputs": {"trust": "cd" * 32}},
        {"schema_id": "urn:pigloros:gateway:v1:schema:erasure", "bound_inputs": {"trust": "cd" * 32}},
        {"schema_id": "urn:pigloros:gateway:v1:schema:admission-receipt", "provenance": {"digest": "cd" * 32}},
    ):
        if normalize(kept) != kept:
            raise SystemExit(f"the erasure normalization changes {kept}")


def check_room_hashes() -> None:
    """The fixture room's plugin composition and rule set hashes, derived here, are the ones
    of the contract's golden `createScenarioRoom` example, which names the same plugin and
    rule."""
    example = json.loads(
        (ROOT / "contracts/gateway/v1/examples/scenario-room-create.json").read_text(
            encoding="utf-8"
        )
    )
    descriptor = example["response"]["body"]["descriptor"]
    if descriptor["plugins"] != [ROOM_PLUGIN] or descriptor["rules"] != room_rules(250000):
        raise SystemExit("the golden room example no longer names the fixture plugin and rule")
    if descriptor["plugin_composition_hash"] != plugin_composition_hash():
        raise SystemExit("the plugin composition hash is not the golden example's")
    if descriptor["rule_set_hash"] != golden.blake3(jcs(room_rules(250000))).hex():
        raise SystemExit("the rule set hash is not the golden example's")


def rotation_chain_heads(checker: str) -> dict[str, str]:
    """The head of each rotation chain the contract checker source declares."""
    for node in ast.parse(checker).body:
        if (
            isinstance(node, ast.Assign)
            and [getattr(target, "id", None) for target in node.targets]
            == ["MODE_PROFILE_ROTATION_CHAINS"]
        ):
            chains = ast.literal_eval(node.value)
            return {identifier: chain[-1] for identifier, chain in chains.items()}
    raise SystemExit("the contract checker declares no MODE_PROFILE_ROTATION_CHAINS")


def check_mode_profile_digests() -> None:
    """The mode-profile digests are the heads of the contract checker's rotation chains."""
    checker = (HERE / "check_gateway_contract.py").read_text(encoding="utf-8")
    if rotation_chain_heads(checker) != MODE_PROFILE_DIGESTS:
        raise SystemExit("the mode-profile digests are not the contract checker's chain heads")


def provider() -> dict:
    return json.loads((FIXTURES / f"providers/{CLAIM_LAYER}/provider.json").read_text())


def check_routes_and_usage() -> None:
    """Routes, captures, capability sets and step and Event usage against the provider."""
    contracts = provider()["fixture_contracts"]
    for family in FAMILIES:
        needed: set[str] = set()
        steps = events = 0
        for sub in SUBCASES[family]():
            captured = consent_captured = room_captured = erasure_captured = False
            for exchange in sub.exchanges:
                route = route_of(exchange.path)
                if route is None:
                    raise SystemExit(f"{sub.id}: {exchange.path} is no Gateway route")
                if "{timeline}" in exchange.path and not captured:
                    raise SystemExit(f"{sub.id}: a Timeline is used before it is captured")
                if "{consent}" in json.dumps(exchange.body) and not consent_captured:
                    raise SystemExit(f"{sub.id}: a consent is used before it is captured")
                if "{room}" in exchange.path and not room_captured:
                    raise SystemExit(f"{sub.id}: a room is used before it is captured")
                if "{erasure}" in exchange.path and not erasure_captured:
                    raise SystemExit(f"{sub.id}: an erasure is used before it is captured")
                erasure_captured = erasure_captured or exchange.capture == "erasure"
                captured = captured or exchange.capture == "timeline"
                room_captured = room_captured or exchange.capture == "room"
                consent_captured = consent_captured or exchange.capture == "consent"
                if exchange.expect == REFUSED:
                    continue
                needed.add(ROUTE_CAPABILITY[route])
                steps += 1
                if exchange.expect.get("status") == 201:
                    events += COMMITTED_EVENTS.get(route, 0)
            for exchange in sub.exchanges:
                if exchange.expect == REFUSED and ROUTE_CAPABILITY[route_of(exchange.path)] in needed:
                    raise SystemExit(f"{sub.id}: a refused route's capability is held")
        contract = contracts[family]
        if contract["minimum_capability_ids"] != sorted(needed):
            raise SystemExit(f"{family}: the provider capabilities are not {sorted(needed)}")
        budget = contract["deterministic_budget"]
        if steps > budget["execution_steps"] or events > budget["event_count"]:
            raise SystemExit(f"{family}: {steps} steps or {events} Events exceed the budget")
        if contract["network_allowed"] is not False:
            raise SystemExit(f"{family}: the Gateway subject uses no network")


def check_payload_schemas() -> None:
    for family in FAMILIES:
        schema = family_schema(family)
        payload = json.loads(render_family(family, provider_context(family)).payload)
        errors = schema_errors(payload, schema, schema)
        if errors:
            raise SystemExit(f"{family}: the payload violates its schema: {errors[:3]}")


def self_test() -> None:
    check_blake3_vectors()
    check_signal_payloads()
    check_normalization()
    check_room_hashes()
    check_mode_profile_digests()
    check_routes_and_usage()
    check_payload_schemas()


# --- Command line ---


def provider_context(family: str) -> Context:
    declaration = provider()
    contract = json.loads((FIXTURES / "support/fixture-family-contract.json").read_text())
    entry = next(item for item in contract["families"] if item["name"] == family)
    return Context(
        case_id=f"{CLAIM_LAYER}-{family}",
        provider_id=declaration["provider_id"],
        contract_version=declaration["contract_version"],
        oracle_kind=entry["oracle"]["kind"],
        code_id=entry["oracle"].get("code_id", ""),
    )


def rust_digest_const(name: str, digest: bytes) -> list[str]:
    lines = [f"const {name}: [u8; 32] = ["]
    for start in range(0, 32, 16):
        lines.append("    " + " ".join(f"0x{byte:02x}," for byte in digest[start : start + 16]))
    lines.append("];")
    return lines


def schema_digests_rust() -> str:
    """The subject adapter's pinned digest of each family's schema member."""
    constants: list[str] = []
    for family in FAMILIES:
        name = family.upper().replace("-", "_")
        constants.extend(rust_digest_const(name, golden.blake3(jcs(family_schema(family)) + b"\n")))
    names = "".join(f"    {family.upper().replace('-', '_')},\n" for family in FAMILIES)
    header = """\
// @generated by scripts/generate_gateway_conformance_fixtures.py; do not edit.

//! The pinned digests of the gateway-client-conformance schema members of the seven families
//! (provider contract 2.0.0, #1295).
//!
//! The digest of the schema member of an attempt must equal the digest pinned here for its
//! family; a mismatch, such as a schema member of the Draft provider contract 1.0.0, is a
//! non-executed outcome: there is no reader for 1.0.0. The fixture generator writes this file
//! from the checked-in schema members and its `--check` verifies it.

use pos_reference::evaluator_domain::FixtureFamily;

"""
    footer = """\

/// The pinned digests, in the wire order of `FixtureFamily`.
pub(super) const PINNED: [[u8; 32]; 7] = [
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


def outputs_on_disk() -> dict[Path, bytes]:
    wanted: dict[Path, bytes] = {SCHEMA_DIGESTS_RUST: schema_digests_rust().encode("utf-8")}
    for family in FAMILIES:
        wanted[schema_path(family)] = jcs(family_schema(family)) + b"\n"
        outputs = render_family(family, provider_context(family))
        wanted[FIXTURES / f"inputs/{CLAIM_LAYER}/{family}.json"] = outputs.payload
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
