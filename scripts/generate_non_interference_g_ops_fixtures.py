"""The G-OPS non-interference oracle (ADR-062 Revision 8 slice N3, #1231).

The owner note `ADR-062_R8_NonInterference_Operations` has this oracle derive the expected NIA1
`result_digest` of every executed case of NI-CACHE-002, NI-OBS-004, NI-TIME-005 and NI-CRASH-012
(modes L, R and F) independently (ADR-062 Revision 8, Q3 (a)). It uses no Rust, no cargo and no
binary of the repository, and implementation output is never an oracle. Every record is rebuilt
from the documented capture contract in
`apps/pos-experiment/src/non_interference_harness/g_ops.rs` and the documented guest
`g_ops_guest.wat`:
- the guest's one constant Event and the position-relative Event stream;
- the subject invocation's imports (observation, Simulation Time 0, Tick 3);
- the subject receipt (committed, one dropped trace annotation, its output usage);
- the host's closed categories and counts of the cache, log, crash and watchdog channels, and the
  rows' declared bounds.
The authoritative and public facets are the same records; the digests follow the #181 capture
profile and the harness result domain (`non_interference_fixtures.py`). Operational facets are
not part of the result digest.

Air-Gapped stays non-executed until N7 (#1235): none of its cases is ever flipped.
`scripts/generate_non_interference_fixtures.py` plugs this oracle into the evidence binder.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from non_interference_fixtures import b3, cbor, result_digest  # noqa: E402

CACHE = "NI-CACHE-002"
OBS = "NI-OBS-004"
TIME = "NI-TIME-005"
CRASH = "NI-CRASH-012"
ROWS = (CACHE, OBS, TIME, CRASH)

# The #181 capture profiles of the four rows (ADR-059 surface order; normalization codes:
# CountClass = 1, CategoryCount = 2, CategoryCountPaddedLength = 3, OmitOperational = 4,
# ByteExact = 5).
SURFACES = {
    CACHE: (
        ("Cache API return", 1),
        ("snapshot bytes", 1),
        ("Plugin inputs", 1),
        ("typed errors", 1),
        ("logs/metrics", 1),
        ("evaluator bundle", 1),
    ),
    OBS: (
        ("Structured logs", 3),
        ("metric names/labels/counts", 3),
        ("trace spans", 3),
        ("crash artifact", 3),
        ("public support bundle", 3),
    ),
    TIME: (
        ("Plugin imports", 5),
        ("deterministic deadline", 4),
        ("safe-stop record", 5),
        ("status/error", 2),
        ("logs/metrics", 2),
        ("evaluator input", 5),
    ),
    CRASH: (
        ("Guest error", 3),
        ("host error mapping", 3),
        ("quarantine", 3),
        ("crash report", 3),
        ("support archive", 3),
        ("next Tick status", 3),
    ),
}

# The subject and guest contract of g_ops.rs and g_ops_guest.wat.
EVENT_TYPE = "ni-g-ops.observed"
EVENT_PAYLOAD = b"\x82\x65g-ops\x01"  # the CBOR ["g-ops", 1]
NEXT_STATE = b"g-ops-state"
TICK = 3
SIMULATION_TIME = 0
FUEL = 1_000_000  # min(budget 1,000,000, V1 ceiling 1,000,000,000)
LOG_MESSAGE_BOUND = 256
COORDINATE_BOUND = 128
LOG_SCHEMA = "pigloros.operational-log.v1"
# Closed codes: the declaration ordinals of `ReceiptDispositionV1` (Staged, Committed, Discarded)
# and `PluginAvailabilityV1` (Available, Disabled, Unavailable, Revoked, Trapped,
# ResourceExhausted).
DISPOSITION = 1  # Committed
AVAILABLE = 0
TRAPPED = 4
NONE = "none"
# The guest logs under category Simulation Time + 1: 1 for the output, 2 for the declared
# failure; the declared failure is `guest-declared-failure(7)`.
OUTPUT_LOG_CATEGORY = 1
DECLARED_LOG_CATEGORY = 2
DECLARED_CODE = ["guest-declared-failure", 7, True]
TRAP_NAME = "ComponentTrap"
TRAP_TEXT = "community Plugin Component trapped: unreachable"


def permitted_input(row: str, variant: str) -> bytes:
    return f"g-ops permitted input v1/{row}/{variant}".encode()


def stream() -> bytes:
    """`[seq, entity ordinal, event type, schema version, causation seq, correlation ordinal,
    payload, payload hash]` (the ADR-127 Event record) of the one subject Event: seq 1; the
    subject Timeline has no owner, so the one entity has ordinal 0; no cause or correlation; the
    payload hash is the BLAKE3 digest of the payload."""
    return cbor([[1, 0, EVENT_TYPE, 1, None, None, EVENT_PAYLOAD, b3(EVENT_PAYLOAD)]])


def imports(row: str, variant: str) -> bytes:
    return cbor([permitted_input(row, variant), SIMULATION_TIME, TICK])


def padded(record: bytes) -> int:
    """The next power of two of a record's length."""
    return 1 << (len(record) - 1).bit_length()


def cache_records(row: str, variant: str) -> list[bytes]:
    return [
        cbor([True, True]),
        cbor(stream()),
        cbor(imports(row, variant)),
        cbor([NONE]),
        cbor([["authorization_cache.hits", 2], ["authorization_cache.misses", 0]]),
        cbor([row, variant, stream()]),
    ]


def observability_records(_row: str, _variant: str) -> list[bytes]:
    metrics = [
        ["receipts", 1],
        ["dropped_trace_annotations", 1],
        ["event_count", 1],
        ["event_payload_bytes", len(EVENT_PAYLOAD)],
        ["state_bytes", len(NEXT_STATE)],
    ]
    return [
        cbor([LOG_SCHEMA, [[DECLARED_LOG_CATEGORY, LOG_MESSAGE_BOUND]]]),
        cbor(metrics),
        cbor([["drive", DISPOSITION, 1]]),
        cbor([DECLARED_CODE, True, COORDINATE_BOUND]),
        cbor([["logs", 1], ["metrics", len(metrics)], ["traces", 1], ["crash", 1]]),
    ]


def time_records(row: str, variant: str) -> list[bytes]:
    return [
        cbor(imports(row, variant)),
        cbor(["fuel", FUEL, "simulation_time", SIMULATION_TIME]),
        cbor([NONE, NONE]),
        cbor([DISPOSITION, "output"]),
        cbor([[OUTPUT_LOG_CATEGORY, 1]]),
        cbor(stream()),
    ]


def crash_records(_row: str, _variant: str) -> list[bytes]:
    """Two denied sibling community Drivers: the declaring one stays `Available`; the trapping one
    is quarantined `Trapped`, so its next Tick is refused before the host runs it: it keeps its one
    receipt, and the refusal is no community host failure. The subject stays `Available`."""
    report = [
        ["guest-error", DECLARED_CODE],
        ["host-error", TRAP_NAME],
        ["quarantine", TRAPPED],
    ]
    return [
        cbor([DECLARED_CODE, True]),
        cbor([TRAP_NAME, TRAP_TEXT]),
        cbor([AVAILABLE, TRAPPED]),
        cbor(report),
        cbor([["crash-report.cbor", padded(cbor(report))]]),
        cbor([AVAILABLE, TRAPPED, 1, True]),
    ]


RECORDS = {
    CACHE: cache_records,
    OBS: observability_records,
    TIME: time_records,
    CRASH: crash_records,
}


def records(row: str, variant: str) -> list[bytes]:
    return RECORDS[row](row, variant)


def expected_result_digest(row: str, variant: str) -> bytes:
    values = records(row, variant)
    return result_digest(row, SURFACES[row], values, list(values))


def self_test() -> None:
    # A hand-derived stream: array(1) of array(8)
    # [1, 0, text(17), 1, null, null, bytes(8), bytes(32)].
    expected = bytes.fromhex(
        "8188010071"
        + EVENT_TYPE.encode().hex()
        + "01f6f648"
        + EVENT_PAYLOAD.hex()
        + "5820"
        + b3(EVENT_PAYLOAD).hex()
    )
    if stream() != expected:
        raise SystemExit("the G-OPS Event stream encoding is wrong")
    for length, power in ((5, 8), (8, 8), (9, 16)):
        if padded(bytes(length)) != power:
            raise SystemExit("the padded length is wrong")
    for row in ROWS:
        if len(records(row, "success")) != len(SURFACES[row]):
            raise SystemExit(f"{row} has a record per surface")
    if imports(TIME, "success")[:3] != b"\x83\x58\x2c":
        raise SystemExit("the G-OPS imports encoding is wrong")
