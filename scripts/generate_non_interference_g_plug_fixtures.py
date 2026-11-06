"""The G-PLUG non-interference oracle (ADR-062 Revision 8 slice N2, #1230).

The owner note `ADR-062_R8_NonInterference_Plugin` has this oracle derive, independently, the
expected NIA1 `result_digest` of every executed case of NI-TOOL-001, NI-STATE-003 (state members,
`ADR-059_R9_State_Migration_Scoping`), NI-NET-010 and NI-SERVICE-011 (modes L, R and F;
ADR-062 Revision 8, Q3 (a)). It uses no Rust, no cargo and no binary of the repository, and
implementation output is never an oracle. Every surface is rebuilt from the documented capture
contract in `apps/pos-experiment/src/non_interference_harness/g_plug.rs`:
- the `drive` observation, which comes from the permitted input and the host-owned frozen
  records alone, and the `drive` draft payload;
- the position-relative Event stream;
- the fixture guest's descriptor record and its `reduce` rebuild (the state chain
  `BLAKE3(prior || observation)` from 32 zero bytes, and the `Denial` capability probe);
- each row's closed records (tool registry, migrate-state refusal, network absence, frozen
  request digests and projections).
The digests then follow the #181 capture profile and the harness result domain
(`non_interference_fixtures.py`). Air-Gapped stays non-executed until N7 (#1235), and the
NI-STATE-003 migration-only canary until PMF1 v2 (#621).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from non_interference_fixtures import b3, cbor, decode, result_digest  # noqa: E402

TOOL = "NI-TOOL-001"
STATE = "NI-STATE-003"
NET = "NI-NET-010"
SERVICE = "NI-SERVICE-011"
ROWS = (TOOL, STATE, NET, SERVICE)

# The #181 capture profiles of the four rows (ADR-059 surface order; normalization codes:
# CategoryCountDigest = 0, CategoryCount = 2, ByteExact = 5).
SURFACES = {
    TOOL: (
        ("Imported-service registry", 0),
        ("tool result handle", 0),
        ("Plugin imports", 0),
        ("staged EventDrafts", 0),
        ("public outcome", 0),
        ("audit record", 0),
    ),
    STATE: (
        ("Migration request/result", 2),
        ("activated state", 2),
        ("PluginInvocation", 2),
        ("PluginOutput", 2),
        ("EventDrafts", 2),
        ("quarantine/error", 2),
    ),
    NET: (
        ("Capability checks", 2),
        ("attempted-call records", 2),
        ("retry count", 2),
        ("Plugin output", 2),
        ("Timeline", 2),
        ("logs", 2),
        ("evaluator bundle", 2),
    ),
    SERVICE: (
        ("Exact request digest", 5),
        ("frozen response projection", 5),
        ("call ordinal", 5),
        ("PluginInvocation", 5),
        ("generated dependency edges", 5),
    ),
}

# The subject contract of g_plug.rs.
TICKS = 2
EVENT_TYPE = "ni.g-plug.output"
GUEST_PLUGIN_ID = "ni.g-plug"
WORLD = "pigloros:plugin/community-plugin"
STATE_SCHEMA_TEXT = b"pigloros.ni.g-plug.state.v1"
PROBE_PREFIX = b"ni.g-plug.probe:"
TOOL_ID = "ni.tool.lookup"
CAPABILITIES = {
    TOOL: "ni.cap.tool",
    STATE: "ni.cap.state-migrate",
    NET: "ni.cap.network",
    SERVICE: "ni.cap.service-live",
}
LOOKUP_KINDS = {NET: "network", SERVICE: "service"}
VARIANT_NAMES = ("success", "denial", "warm_cache", "cold_cache")


def permitted_input(row: str, variant: str) -> bytes:
    return f"g-plug permitted input v1/{row}/{variant}".encode()


def service_request(kind: str, permitted: bytes) -> bytes:
    return cbor(["ni.g-plug.request", kind, permitted])


def frozen_projection(row: str, kind: str, permitted: bytes) -> bytes | None:
    """The admitted records are those of the row's four permitted inputs."""
    wanted = b3(service_request(kind, permitted))
    admitted = {b3(service_request(kind, permitted_input(row, name))) for name in VARIANT_NAMES}
    return cbor(["admitted", kind, b3(permitted)]) if wanted in admitted else None


def channel(row: str, permitted: bytes) -> list:
    if row == TOOL:
        return ["tool", TOOL_ID, "capability-denied"]
    if row == STATE:
        return ["state"]
    kind = LOOKUP_KINDS[row]
    return [kind, b3(service_request(kind, permitted)), frozen_projection(row, kind, permitted)]


def drive_payload(row: str, permitted: bytes) -> bytes:
    """The guest's `drive` draft payload `["drive", observation]`."""
    return cbor(["drive", cbor([row, permitted, channel(row, permitted)])])


def descriptor_record() -> bytes:
    return cbor(
        [GUEST_PLUGIN_ID, "1.0.0", WORLD, 0, 0, 0, [], [b3(EVENT_TYPE.encode())], b3(STATE_SCHEMA_TEXT)]
    )


def rebuild(row: str, variant: str, payload: bytes, seqs: list[int]) -> dict:
    """The `reduce` rebuild over the Events, then the `Denial` probe."""
    calls = [(seq, payload) for seq in seqs]
    if variant == "denial":
        calls.append((seqs[-1], PROBE_PREFIX + CAPABILITIES[row].encode()))
    state = bytes(32)
    rebuilt: dict = {"invocations": [], "outputs": [], "edges": [], "errors": []}
    for ordinal, (seq, observation) in enumerate(calls, start=1):
        rebuilt["invocations"].append([ordinal, seq, b3(observation), b3(state)])
        if observation.startswith(PROBE_PREFIX):
            capability = observation[len(PROBE_PREFIX) :].decode()
            record = ["error", f'CapabilityRequired("{capability}")']
            rebuilt["outputs"].append(record)
            rebuilt["errors"].append(record)
        else:
            state = b3(state + observation)
            consumed = [b3(observation)]
            rebuilt["outputs"].append(["output", 0, state, consumed])
            rebuilt["edges"].append([ordinal, consumed])
    rebuilt["state"] = state
    return rebuilt


def row_surfaces(row: str, variant: str) -> list[bytes]:
    permitted = permitted_input(row, variant)
    payload = drive_payload(row, permitted)
    seqs = list(range(1, TICKS + 1))
    # `[seq, entity ordinal, type, schema version, cause, correlation, payload hash, payload]`;
    # the subject Timeline has no owner, so the guest's entity takes ordinal 0.
    stream = cbor([[seq, 0, EVENT_TYPE, 1, None, None, b3(payload), payload] for seq in seqs])
    rebuilt = rebuild(row, variant, payload, seqs)
    imports = cbor([descriptor_record(), rebuilt["invocations"]])
    outputs = cbor(rebuilt["outputs"])
    if row == TOOL:
        return [
            cbor([[TOOL_ID, CAPABILITIES[TOOL], False]]),
            cbor([[0, TOOL_ID, "capability-denied"]]),
            imports,
            stream,
            outputs,
            cbor([[TOOL_ID, CAPABILITIES[TOOL], "denied"]]),
        ]
    if row == STATE:
        return [
            cbor(["migrate-state refused", 0]),
            cbor(rebuilt["state"]),
            imports,
            outputs,
            stream,
            cbor(rebuilt["errors"]),
        ]
    if row == NET:
        return [
            cbor([[CAPABILITIES[NET], False]]),
            cbor([["network", "absent", 0]]),
            cbor(0),
            outputs,
            stream,
            cbor([]),
            cbor([b3(stream), rebuilt["state"]]),
        ]
    request = b3(service_request("service", permitted))
    projection = frozen_projection(row, "service", permitted)
    return [
        cbor([request for _ in seqs]),
        cbor([projection for _ in seqs]),
        cbor([[ordinal, seq] for ordinal, seq in enumerate(seqs)]),
        imports,
        cbor(rebuilt["edges"]),
    ]


def expected_result_digest(row: str, variant: str) -> bytes:
    surfaces = row_surfaces(row, variant)
    return result_digest(row, SURFACES[row], surfaces, surfaces)


def self_test() -> None:
    if frozen_projection(SERVICE, "service", b"unadmitted") is not None:
        raise SystemExit("an unadmitted request has a frozen record")
    if frozen_projection(NET, "network", permitted_input(NET, "denial")) is None:
        raise SystemExit("an admitted request has no frozen record")
    # A hand-derived state chain step: BLAKE3 over 32 zero bytes and one byte.
    if rebuild(STATE, "success", b"\x01", [1])["state"] != b3(bytes(32) + b"\x01"):
        raise SystemExit("the reduce state chain is wrong")
    denial = rebuild(TOOL, "denial", b"\x01", [1, 2])
    if denial["errors"] != [["error", 'CapabilityRequired("ni.cap.tool")']]:
        raise SystemExit("the Denial probe is wrong")
    if [item[0] for item in denial["invocations"]] != [1, 2, 3]:
        raise SystemExit("the invocation ordinals are wrong")
    stream = decode(row_surfaces(STATE, "success")[4])[0]
    if [event[0] for event in stream] != [1, 2] or stream[0][2] != EVENT_TYPE:
        raise SystemExit("the Event stream is wrong")
    for row in ROWS:
        if len(row_surfaces(row, "success")) != len(SURFACES[row]):
            raise SystemExit(f"{row} has the wrong surface count")
