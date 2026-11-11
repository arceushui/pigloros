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
(the encoding the requirements text states) and the independent-evaluation digests, both
derived here. The only primitive it imports is the BLAKE3 hash of
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
CURSOR_PATTERN = f"v1\\.[0-9a-f]{{64}}\\.{ULID_PATTERN}\\.[1-9][0-9]*"

# The route of a request path (query removed) and the capability it needs (section "Routes").
ROUTE_CAPABILITY = {
    "health": "gateway.health.read",
    "ledger": "gateway.ledger.read",
    "create": "timeline.create",
    "events": "timeline.events.read",
    "signals": "timeline.signals.append",
    "actions": "world.action.v1.submit",
}
CAPABILITIES = tuple(sorted(ROUTE_CAPABILITY.values()))
MAX_TIMELINES = 64  # README "Timeline bound"
EVENT_LIMIT = 100  # README "Polling": limit defaults to and may not exceed 100


def route_of(path: str) -> str | None:
    base = path.split("?", 1)[0]
    fixed = {"/health": "health", "/v1/ledger": "ledger", "/v1/timelines": "create"}
    if base in fixed:
        return fixed[base]
    match = re.fullmatch(r"/v1/timelines/([^/]+)/(events|signals|actions)", base)
    return match.group(2) if match else None


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
    capture: bool = False

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
        if self.capture:
            value["capture"] = "timeline"
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


def create(name: str, capture: bool = True, expect: dict | None = None) -> Exchange:
    created = observed(201, json_body({"head": 0, "id": "<ulid>", "name": name}))
    return Exchange(
        "loopback",
        "POST",
        "/v1/timelines",
        created if expect is None else expect,
        body={"name": name},
        has_body=True,
        capture=capture,
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
                create("den-2"),
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
            [create("den-4"), poll(routed_problem(401, "unauthenticated", EVENTS_PATH))],
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
                create("mal-4"),
                action(routed_problem(422, "admission-rejected", ACTIONS_PATH), params=[1, 2]),
                poll(EMPTY_PAGE, actor=True),
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
        )
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
                create("dgr-1"),
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
                create("dgr-2"),
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
            "capture": {"const": "timeline"},
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
            "composition": {"enum": ["open", "authorized"]},
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


def normalize(value: object, key: str | None = None) -> object:
    """The normalization of the requirements text, on a parsed JSON response value."""
    if isinstance(value, dict):
        return {name: normalize(item, name) for name, item in value.items()}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, str):
        if key == "next_cursor" and re.fullmatch(CURSOR_PATTERN, value):
            return "<cursor>"
        if key == "detail":
            return "<message>"
        if key in ("id", "instance"):
            return "/".join(
                "<ulid>" if re.fullmatch(ULID_PATTERN, part) else part for part in value.split("/")
            )
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
    for constant in (ACTOR, BODY, ENTITY):
        if not re.fullmatch(ULID_PATTERN, constant):
            raise SystemExit(f"{constant} is not a ULID")


def provider() -> dict:
    return json.loads((FIXTURES / f"providers/{CLAIM_LAYER}/provider.json").read_text())


def check_routes_and_usage() -> None:
    """Routes, captures, capability sets and step and Event usage against the provider."""
    contracts = provider()["fixture_contracts"]
    for family in FAMILIES:
        needed: set[str] = set()
        steps = events = 0
        for sub in SUBCASES[family]():
            captured = False
            for exchange in sub.exchanges:
                route = route_of(exchange.path)
                if route is None:
                    raise SystemExit(f"{sub.id}: {exchange.path} is no Gateway route")
                if "{timeline}" in exchange.path and not captured:
                    raise SystemExit(f"{sub.id}: a Timeline is used before it is captured")
                captured = captured or exchange.capture
                if exchange.expect == REFUSED:
                    continue
                needed.add(ROUTE_CAPABILITY[route])
                steps += 1
                if exchange.expect.get("status") == 201 and route in ("signals", "actions"):
                    events += 1
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
