"""The G-PUB non-interference oracle (ADR-062 Revision 8 slice N1, #1229).

The owner note `ADR-062_R8_NonInterference_Executions` (decisions 4 and 5) has this oracle
derive the expected NIA1 `result_digest` of every executed case of NI-PUBLIC-006 and NI-EVAL-007
(modes L, R and F) independently (ADR-062 Revision 8, Q3 (a)). It uses no Rust, no cargo and no
binary of the repository, and implementation output is never an oracle. Every surface is rebuilt
from the documented capture contract in
`apps/pos-experiment/src/non_interference_harness/g_pub.rs`:
- the subject's Society Signals, which come from the permitted input alone;
- the position-relative Event stream;
- the Gateway's page JSON and closed error body;
- the export record, the evaluator member table, the fixture descriptor, the EAI1 member
  digests and the case outcomes.
The digests then follow the #181 capture profile and the harness result domain
(`non_interference_fixtures.py`).

NI-ARCHIVE-009 (slice N1b, #1284) shares this subject; its oracle is
`generate_non_interference_g_archive_fixtures.py`. Air-Gapped stays non-executed until N7
(#1235): none of its cases is ever flipped. `scripts/generate_non_interference_fixtures.py` plugs
this oracle into the evidence binder.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from non_interference_fixtures import (  # noqa: E402
    Half,
    Struct,
    b3,
    cbor,
    decode,
    result_digest,
    ulid_text,
)

PUBLIC = "NI-PUBLIC-006"
EVAL = "NI-EVAL-007"
ROWS = (PUBLIC, EVAL)
ULID_TEXT_LEN = 26
GENERATION_HEX_LEN = 64

# The #181 capture profiles of the two rows (ADR-059 surface order; normalization codes:
# CategoryCount = 2, ByteExact = 5).
SURFACES = {
    PUBLIC: (
        ("HTTP/Plugin error", 2),
        ("status transition", 2),
        ("cursor bytes", 2),
        ("page count", 2),
        ("response length/padding", 2),
    ),
    EVAL: (
        ("Export bundle", 5),
        ("manifest", 5),
        ("fixture descriptor", 5),
        ("evaluator stdin/files", 5),
        ("ConformanceReport", 5),
    ),
}

# The subject contract of g_pub.rs.
TICKS = 2
SIGNALS_PER_TICK = 2
PAGE_LIMIT = 3
SUBJECT_TIMELINE = "ni-g-pub-subject"
# `TimelineMeta::root` creates a `Live` Timeline (ADR-127 mode code 1) with no owner.
SUBJECT_TIMELINE_MODE_CODE = 1
EVENT_TYPE = "society.signal"
DIMENSIONS = ("trust", "opinion", "economy", "culture", "polarization")
EVALUATOR_SCHEMA = b"pigloros.g-pub.evaluator-input.v1"
EXPORT_MEMBER = "timeline-export"
ATTEMPT_OUTCOME = "admitted"
PLUGIN_ID = (1 << 80) | 0x4750_5550
PLUGIN_NAME = "ni-g-pub"
DRIVER_NAME = "ni-g-pub.driver"
# The Gateway v1 problem body of the over-limit page request (#1312): sorted keys, and the
# matched route template as `instance`, so it carries no run-local identity.
PAGE_LIMIT_ERROR = (
    b'{"code":"invalid-request","detail":"event poll limit must be between 1 and 100",'
    b'"instance":"/v1/timelines/{timeline_id}/events","retryable":false,'
    b'"schema_id":"urn:pigloros:gateway:v1:schema:problem","status":400,'
    b'"title":"Invalid request","type":"urn:pigloros:gateway:v1:problem:invalid-request"}'
)


# --- The subject ---


def permitted_input(row: str, variant: str) -> bytes:
    return f"g-pub permitted input v1/{row}/{variant}".encode()


def signals(permitted: bytes) -> list[tuple[str, float]]:
    """`g_pub_signals_v1`: the first two permitted bytes, cycled, as (dimension, value)."""
    chosen = [permitted[index % len(permitted)] for index in range(SIGNALS_PER_TICK)]
    return [(DIMENSIONS[byte % 5], (byte % 4) / 4) for byte in chosen]


def signal_payload(dimension: str, value: float) -> bytes:
    """`pos_plugin_society::draft_signal`: the serde struct `SocietySignal`."""
    return cbor(
        Struct(("dimension", dimension), ("value", Half(value)), ("subject", None), ("object", None))
    )


def subject_events(permitted: bytes) -> list[tuple[int, str, float]]:
    """Every Tick emits the same signals; Timeline Order assigns seq 1, 2, ..."""
    per_tick = signals(permitted)
    return [
        (seq, dimension, value)
        for seq, (dimension, value) in enumerate(per_tick * TICKS, start=1)
    ]


def event_stream(events: list[tuple[int, str, float]]) -> list:
    """The ADR-127 section 2 Event record `[seq, entity ordinal, event type, schema version,
    causation seq, correlation ordinal, payload, payload hash]`. The subject Timeline has no owner, so its one entity has ordinal 0;
    no subject Event names a cause or a correlation; the payload hash is the BLAKE3 digest of the
    payload (`pos_crypto::chain::hash_payload`)."""
    rows = []
    for seq, dimension, value in events:
        payload = signal_payload(dimension, value)
        rows.append([seq, 0, EVENT_TYPE, 1, None, None, payload, b3(payload)])
    return rows


# --- NI-EVAL-007 ---


def evaluator_surfaces(row: str, variant: str) -> tuple[list[bytes], list[bytes]]:
    permitted = permitted_input(row, variant)
    events = subject_events(permitted)
    stream = event_stream(events)
    # The ADR-127 `timeline.cbor` record `[mode code, name, owner ordinal, head]`, then the stream.
    exported = cbor([SUBJECT_TIMELINE_MODE_CODE, SUBJECT_TIMELINE, None, len(events), stream])
    manifest = cbor([[EXPORT_MEMBER, len(exported), b3(exported)]])
    descriptor = cbor(
        [row, variant, b3(permitted), ulid_text(PLUGIN_ID), PLUGIN_NAME, DRIVER_NAME]
    )
    case_id = f"{row}-{variant}"
    stdin = cbor([case_id, 3, [b3(EVALUATOR_SCHEMA), b3(exported), b3(manifest)]])
    report = cbor([[case_id, ATTEMPT_OUTCOME, b3(exported)]])
    return (
        [cbor(stream), manifest, descriptor, stdin, report],
        [exported, manifest, descriptor, stdin, report],
    )


# --- NI-PUBLIC-006 ---


def json_number(value: float) -> str:
    """serde_json's shortest round-trip float text, which Python's `repr` equals here."""
    return repr(float(value))


def event_view(seq: int, dimension: str, value: float) -> str:
    """One page Event: the Gateway's sorted `serde_json::Map`, with ULID text of fixed width."""
    payload = signal_payload(dimension, value)
    placeholder = "0" * ULID_TEXT_LEN
    return (
        f'{{"entity":"{placeholder}","event_type":"{EVENT_TYPE}","id":"{placeholder}",'
        f'"payload":{{"dimension":"{dimension}","object":null,"subject":null,'
        f'"value":{json_number(value)}}},"payload_hex":"{payload.hex()}","seq":{seq}}}'
    )


def page_body(page: list[tuple[int, str, float]], next_seq: int | None) -> bytes:
    """`{"events":[...],"next_cursor":...,"next_from_seq":...}` (sorted keys)."""
    if next_seq is None:
        cursor, from_seq = "null", "null"
    else:
        width = len(f"v1..{next_seq}") + GENERATION_HEX_LEN + 1 + ULID_TEXT_LEN
        cursor, from_seq = '"' + "x" * width + '"', str(next_seq)
    events = ",".join(event_view(*event) for event in page)
    return f'{{"events":[{events}],"next_cursor":{cursor},"next_from_seq":{from_seq}}}'.encode()


def public_surfaces(row: str, variant: str) -> tuple[list[bytes], list[bytes]]:
    events = subject_events(permitted_input(row, variant))
    pages = [events[start : start + PAGE_LIMIT] for start in range(0, len(events), PAGE_LIMIT)]
    bodies, cursors = [], []
    for index, page in enumerate(pages):
        next_seq = pages[index + 1][0][0] if index + 1 < len(pages) else None
        bodies.append(page_body(page, next_seq))
        cursors.append(None if next_seq is None else f"v1.G0.T0.{next_seq}")
    statuses = [201] + [201] * len(events) + [200] * len(pages)
    lengths = [len(body) for body in bodies]
    error: list = []
    if variant == "denial":
        statuses.append(400)
        lengths.append(len(PAGE_LIMIT_ERROR))
        error = [400, PAGE_LIMIT_ERROR]
    records = [cbor(error), cbor(statuses), cbor(cursors), cbor(len(pages)), cbor(lengths)]
    return records, list(records)


# --- Digests ---


def expected_result_digest(row: str, variant: str) -> bytes:
    authoritative, public = (public_surfaces if row == PUBLIC else evaluator_surfaces)(row, variant)
    return result_digest(row, SURFACES[row], authoritative, public)


# --- Self-test ---


def self_test() -> None:
    # A hand-derived Society Signal payload: map(4), "culture", half 0.75, two nulls.
    expected = bytes.fromhex(
        "a4696469 6d656e73 696f6e67 63756c74 757265 6576616c 7565f9 3a00"
        "677375 626a6563 74f6 666f626a 656374f6".replace(" ", "")
    )
    if signal_payload("culture", 0.75) != expected:
        raise SystemExit("the Society Signal payload encoding is wrong")
    if signals(permitted_input(EVAL, "denial")) != [("culture", 0.75), ("trust", 0.25)]:
        raise SystemExit("the subject signals are wrong")
    if ulid_text(PLUGIN_ID) != "000000000100000000013N0NAG":
        raise SystemExit("the Plugin id text is wrong")
    # A cursor is `v1.` + generation + `.` + Timeline ULID + `.4`: 96 characters.
    if b'"' + b"x" * 96 + b'"' not in page_body(subject_events(b"g-")[:PAGE_LIMIT], 4):
        raise SystemExit("the cursor width is wrong")
    statuses = decode(public_surfaces(PUBLIC, "denial")[0][1])[0]
    if statuses != [201, 201, 201, 201, 201, 200, 200, 400]:
        raise SystemExit("the denial status transition is wrong")
