#!/usr/bin/env python3
"""Derive the G-PUB non-interference expected results (ADR-062 Revision 8 slice N1, #1229).

The owner note `ADR-062_R8_NonInterference_Executions` (decisions 4 and 5) assigns this script
three jobs, for each executed case of NI-PUBLIC-006 and NI-EVAL-007 (modes L, R and F):

- Derive the expected NIA1 `result_digest` independently (ADR-062 Revision 8, Q3 (a)). It uses
  no Rust, no cargo and no binary of the repository, and implementation output is never an
  oracle. Every surface is rebuilt from the documented capture contract in
  `apps/pos-experiment/src/non_interference_harness/g_pub.rs`:
  - the subject's Society Signals, which come from the permitted input alone;
  - the position-relative Event stream;
  - the Gateway's page JSON and closed error body;
  - the export record, the evaluator member table, the fixture descriptor, the EAI1 member
    digests and the case outcomes.
  The digests then follow the #181 capture profile and the harness result domain.
- Flip a case in `matrix/execution-matrix.json` to `executed: true` only when its checked-in
  NIA1 under `non-interference/executions/` meets every condition below. `executed: true`
  never implies a pass.
  - Its file name is its content address.
  - It names the coordinate.
  - It is `equal`.
  - It carries exactly the independently derived result digest.
  The Rust test `apps/pos-experiment/tests/non_interference_g_pub.rs` checks the signature
  with the pos-reference verifier.
- Rebind the matrix's BLAKE3 digest, size and executed count in the knowledge-non-interference
  profile and in the publication review.

NI-ARCHIVE-009 moved to slice N1b (#1284) and Air-Gapped stays non-executed until N7 (#1235):
none of their cases is ever flipped.

Usage:
    python3 scripts/generate_non_interference_g_pub_fixtures.py          # write the bindings
    python3 scripts/generate_non_interference_g_pub_fixtures.py --check  # self-test and verify
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import generate_pmf1_golden_vectors as golden  # noqa: E402

FIXTURES = ROOT / "fixtures/conformance"
MATRIX = FIXTURES / "matrix/execution-matrix.json"
PROFILE = FIXTURES / "profiles/knowledge-non-interference/profile.json"
REVIEW = FIXTURES / "support/publication-review.json"
EXECUTOR = FIXTURES / "non-interference/executor.json"
EXECUTIONS = FIXTURES / "non-interference/executions"

PUBLIC = "NI-PUBLIC-006"
EVAL = "NI-EVAL-007"
EXECUTED_ROWS = (PUBLIC, EVAL)
# (matrix letter, serde name, #181 code)
VARIANTS = (("S", "success", 0), ("D", "denial", 1), ("W", "warm_cache", 2), ("C", "cold_cache", 3))
EXECUTABLE_MODES = (("L", "local"), ("R", "replay"), ("F", "fork"))

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
NORMALIZATION_VERSION = 1
MAX_SURFACE_BYTES = 1024 * 1024

# The subject contract of g_pub.rs.
TICKS = 2
SIGNALS_PER_TICK = 2
PAGE_LIMIT = 3
SUBJECT_TIMELINE = "ni-g-pub-subject"
# `TimelineMeta::root` creates a `Live` Timeline with no owner.
SUBJECT_TIMELINE_MODE = "Live"
EVENT_TYPE = "society.signal"
DIMENSIONS = ("trust", "opinion", "economy", "culture", "polarization")
EVALUATOR_SCHEMA = b"pigloros.g-pub.evaluator-input.v1"
EXPORT_MEMBER = "timeline-export"
ATTEMPT_OUTCOME = "admitted"
PLUGIN_ID = (1 << 80) | 0x4750_5550
PLUGIN_NAME = "ni-g-pub"
DRIVER_NAME = "ni-g-pub.driver"
PAGE_LIMIT_ERROR = b'{"error":"event poll limit must be between 1 and 100"}'
ULID_TEXT_LEN = 26
GENERATION_HEX_LEN = 64

RESULT_DOMAIN = b"PiglorOS.NonInterference.HarnessResult.v1"
ARTIFACT_DOMAIN = b"PiglorOS.NonInterference.ExecutionArtifact.v1"
PROFILE_DOMAIN = b"PiglorOS.NonInterference.CaptureProfile.v1"
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def b3(data: bytes) -> bytes:
    return golden.blake3(data)


def domain_digest(domain: bytes, value: bytes) -> bytes:
    return b3(domain + b"\0" + value)


def append(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def ulid_text(value: int) -> str:
    return "".join(CROCKFORD[(value >> (5 * (25 - index))) & 31] for index in range(26))


# --- CBOR (as ciborium writes it: definite lengths, shortest heads) ---


class Half:
    """An f64 whose value is exactly representable as an IEEE 754 half (ciborium writes the
    shortest lossless float)."""

    def __init__(self, value: float) -> None:
        packed = struct.pack(">e", value)
        if struct.unpack(">e", packed)[0] != value:
            raise ValueError(f"{value} is not exactly a half")
        self.packed = packed


class Struct:
    """A serde struct: a map in field declaration order."""

    def __init__(self, *pairs: tuple[str, object]) -> None:
        self.pairs = pairs


def head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([major << 5 | value])
    for info, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if value < 1 << (8 * width):
            return bytes([major << 5 | info]) + value.to_bytes(width, "big")
    raise ValueError("CBOR argument exceeds 64 bits")


def cbor(value: object) -> bytes:
    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(item) for item in value)
    if isinstance(value, Half):
        return b"\xf9" + value.packed
    if isinstance(value, Struct):
        return head(5, len(value.pairs)) + b"".join(cbor(k) + cbor(v) for k, v in value.pairs)
    raise TypeError(type(value))


def decode(data: bytes, pos: int = 0) -> tuple[object, int]:
    """Decode the definite-length CBOR of an NIA1 (maps, arrays, integers, text, bool, null)."""
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
    """`[seq, entity ordinal, event type, schema version, causation seq, correlation ordinal,
    payload hash, payload]`. The subject Timeline has no owner, so its one entity has ordinal 0;
    no subject Event names a cause or a correlation; the payload hash is the BLAKE3 digest of the
    payload (`pos_crypto::chain::hash_payload`)."""
    rows = []
    for seq, dimension, value in events:
        payload = signal_payload(dimension, value)
        rows.append([seq, 0, EVENT_TYPE, 1, None, None, b3(payload), payload])
    return rows


# --- NI-EVAL-007 ---


def evaluator_surfaces(row: str, variant: str) -> tuple[list[bytes], list[bytes]]:
    permitted = permitted_input(row, variant)
    events = subject_events(permitted)
    stream = event_stream(events)
    exported = cbor([SUBJECT_TIMELINE, SUBJECT_TIMELINE_MODE, None, len(events), stream])
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


def profile_digest(row: str) -> bytes:
    value = append(row.encode())
    for name, code in SURFACES[row]:
        value += append(name.encode()) + bytes([code])
    value += bytes([0, 1, 2, 3]) + bytes([0, 1, 2, 3])
    value += NORMALIZATION_VERSION.to_bytes(2, "big") + MAX_SURFACE_BYTES.to_bytes(8, "big")
    return domain_digest(PROFILE_DOMAIN, value)


def capture_digest(domain: bytes, row: str, surfaces: list[bytes]) -> bytes:
    value = append(row.encode()) + profile_digest(row)
    for (name, _), surface in zip(SURFACES[row], surfaces, strict=True):
        value += append(name.encode()) + append(surface)
    return domain_digest(domain, value)


def expected_result_digest(row: str, variant: str) -> bytes:
    authoritative, public = (public_surfaces if row == PUBLIC else evaluator_surfaces)(row, variant)
    return b3(
        RESULT_DOMAIN
        + b"\0"
        + capture_digest(b"authoritative", row, authoritative)
        + capture_digest(b"public", row, public)
    )


# --- Evidence ---


def accepted_executions() -> dict[str, dict]:
    """Every checked-in NIA1 by case id. Any file that is not content-addressed, names
    another coordinate, is not equal or carries a different result digest refuses the run."""
    accepted: dict[str, dict] = {}
    for path in sorted(EXECUTIONS.glob("*")):
        data = path.read_bytes()
        address = domain_digest(ARTIFACT_DOMAIN, data).hex()
        if path.name != f"{address}.nia1":
            raise SystemExit(f"{path.name} is not the content address of its NIA1")
        artifact, end = decode(data)
        if end != len(data) or not isinstance(artifact, dict):
            raise SystemExit(f"{path.name} is not one canonical NIA1")
        row, variant, mode = artifact["i"], artifact["x"], artifact["o"]
        letters = {name: letter for letter, name, _ in VARIANTS}
        modes = {name: letter for letter, name in EXECUTABLE_MODES}
        if row not in EXECUTED_ROWS or variant not in letters or mode not in modes:
            raise SystemExit(f"{path.name} names a coordinate N1 does not execute")
        case_id = f"{row}-{letters[variant]}-{modes[mode]}"
        expected = expected_result_digest(row, variant)
        if artifact["q"] is not True or artifact["d"] is not None:
            raise SystemExit(f"{path.name} ({case_id}) is not an equal execution")
        if bytes(artifact["r"]) != expected:
            raise SystemExit(f"{path.name} ({case_id}) differs from the expected result digest")
        if case_id in accepted:
            raise SystemExit(f"{case_id} has two NIA1")
        accepted[case_id] = {"address": address, "result_digest": expected.hex()}
    return accepted


def bound_matrix(matrix: dict, accepted: dict[str, dict]) -> dict:
    executed_by_row: dict[str, int] = {}
    for case in matrix["cases"]:
        execution = accepted.get(case["case_id"])
        case["executed"] = execution is not None
        case["authority_fixture_id"] = None
        case["authority_result_digest"] = None
        if execution is None:
            case["expected_result_digest"] = None
            case["expected_result"] = None
        else:
            case["expected_result_digest"] = execution["result_digest"]
            case["expected_result"] = {
                "equal": True,
                "first_divergence": None,
                "nia1_content_digest": execution["address"],
            }
            executed_by_row[case["fixture_id"]] = executed_by_row.get(case["fixture_id"], 0) + 1
    for row in matrix["rows"]:
        row["executed_case_count"] = executed_by_row.get(row["fixture_id"], 0)
    matrix["executed_case_count"] = sum(executed_by_row.values())
    if len(accepted) != matrix["executed_case_count"]:
        raise SystemExit("an accepted NIA1 names no matrix case")
    return matrix


def dump(value: dict, compact: bool = False) -> bytes:
    if compact:
        return (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def outputs() -> dict[Path, bytes]:
    accepted = accepted_executions()
    matrix_bytes = dump(bound_matrix(json.loads(MATRIX.read_text(encoding="utf-8")), accepted))
    matrix_digest = b3(matrix_bytes).hex()
    executed = json.loads(matrix_bytes)["executed_case_count"]
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    profile["adr_059_execution_matrix_blake3_digest"] = matrix_digest
    profile["matrix_blake3_digest"] = matrix_digest
    profile["matrix_size_bytes"] = len(matrix_bytes)
    review = json.loads(REVIEW.read_text(encoding="utf-8"))
    review["adr_059_execution_matrix"]["blake3_digest"] = matrix_digest
    review["adr_059_execution_matrix"]["executed_case_count"] = executed
    return {MATRIX: matrix_bytes, PROFILE: dump(profile), REVIEW: dump(review, compact=True)}


# --- Self-tests ---


def self_test() -> None:
    golden.self_test()
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


def check_executor() -> None:
    if not EXECUTOR.is_file():
        raise SystemExit("the executor key declaration is missing")
    executor = json.loads(EXECUTOR.read_text(encoding="utf-8"))
    if (
        executor.get("key_id") != "pigloros.fixture.non-interference-executor"
        or executor.get("authority_kind") != "repository-test-fixture-only"
        or executor.get("algorithm") != "Ed25519"
    ):
        raise SystemExit("the executor key declaration is not the repository test-fixture key")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--print-expected", action="store_true")
    arguments = parser.parse_args()
    self_test()
    if arguments.print_expected:
        for row in EXECUTED_ROWS:
            for _, variant, _ in VARIANTS:
                print(row, variant, expected_result_digest(row, variant).hex())
        return
    check_executor()
    generated = outputs()
    stale = [path for path, data in generated.items() if path.read_bytes() != data]
    if arguments.check:
        if stale:
            for path in stale:
                print(f"{path.relative_to(ROOT)} is not reproducible", file=sys.stderr)
            raise SystemExit(1)
        print(f"verified {len(accepted_executions())} G-PUB NIA1 and their matrix bindings")
        return
    for path in stale:
        path.write_bytes(generated[path])
    print(f"wrote {len(stale)} file(s)")


if __name__ == "__main__":
    main()
