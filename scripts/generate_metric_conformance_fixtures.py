#!/usr/bin/env python3
"""Generate the metric-conformance fixtures (ADR-062 Revision 7 section 5, slice 1, #1211).

This is the only writer of the payloads, `MCS1` composites, oracles and evidence-status records
of the `metric-conformance` layer, of its seven provider schemas and of the subject adapter's
`apps/pos-metric-conformance-adapter/src/schema_digests.rs`. It is called by
`scripts/conformance-fixture-adapters/metric-cbor-v1.sh render` (through the `render`
subcommand) and runs offline.

It does not use implementation output as an oracle: no Rust, no cargo and no binary of the
repository. Every expected value is computed here from the public profile text
(`fixtures/conformance/profiles/metric-conformance/normative-requirements.md`, which carries
ADR-062 Revision 7 sections 4.1 to 4.5) with exact integer and `fractions.Fraction` arithmetic.
The only primitives it imports are the BLAKE3 hash and the CBOR head encoder of
`generate_pmf1_golden_vectors.py`.

Usage:
    python3 scripts/generate_metric_conformance_fixtures.py          # write every output
    python3 scripts/generate_metric_conformance_fixtures.py --check  # self-test and verify
    python3 scripts/generate_metric_conformance_fixtures.py render ...  # one family (adapter)

`--check` first runs the self-tests: the BLAKE3 vectors, the worked example and the `MTQ1`
table of the profile text (section 4.3 and 4.4), a second, definitional computation of every
computed `MTR1` (means, per-record leave-one-out baselines and per-bin means instead of the
closed integer formulas), an independent quantization of every `MTQ1` pattern through
`Fraction(float)`, the strict `MTI1` decoder against every hand-written failure expectation,
the rounding ties and the personal-base-rate floor the positive sub-cases claim, the absence of
the redaction canary from every `MTR1`, and every payload against its schema. It then
regenerates every output and compares it with the checked-in file.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import struct
import sys
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import generate_pmf1_golden_vectors as golden  # noqa: E402

FIXTURES = ROOT / "fixtures/conformance"
BLAKE3_VECTORS = HERE / "data/blake3_test_vectors.json"
SCHEMA_DIGESTS_RUST = ROOT / "apps/pos-metric-conformance-adapter/src/schema_digests.rs"

CLAIM_LAYER = "metric-conformance"
SCHEMA_ID = "pigloros.metric-conformance.case.v2"
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
COMPOSITE_MAGIC = "MCS1"
COMPOSITE_MEDIA_TYPE = "application/vnd.pigloros.metric-cases.v1+cbor"
GENERATOR_COMMAND = "python3 scripts/generate_metric_conformance_fixtures.py --check"

# --- Profile constants (sections 4.2 and 4.3) ---

ALGORITHM_ID = "pigloros.metric.binary-calibration"
ALGORITHM_MAJOR = 1
EQUAL_WIDTH_10 = 0
D = 10**6
BIN_WIDTH = 100_000
BIN_COUNT = 10
PBR_SCALE = 10**18
MAX_RECORDS = 262_144
MAX_IDENTIFIER_BYTES = 64
MAX_MTI1_BYTES = 64 * 1024 * 1024
MAX_MTR1_BYTES = 1024
MAX_PATTERNS = 4096
INPUT_DOMAIN = b"PiglorOS.MetricInput.v1\0"
RESULT_DOMAIN = b"PiglorOS.MetricResult.v1\0"

ERRORS = (
    "InvalidEncoding",
    "UnsupportedVersion",
    "UnsupportedAlgorithm",
    "InvalidBinning",
    "InconsistentLength",
    "InvalidProbability",
    "InvalidOutcome",
    "InvalidIdentifier",
    "DuplicatePrediction",
    "NonCanonicalOrder",
    "InvalidMinimum",
    "ResourceLimit",
)
OBSERVED, PENDING, REDACTED, UNAVAILABLE = 0, 1, 2, 3
COMPUTED, INSUFFICIENT_SAMPLES = 0, 1
RESULT_KINDS = {COMPUTED: "Computed", INSUFFICIENT_SAMPLES: "InsufficientSamples"}
REDACTION_NONE, REDACTED_VIEWS, EVIDENCE_MISSING = 0, 1, 3
REDACTION_STATES = {
    REDACTION_NONE: "None",
    REDACTED_VIEWS: "RedactedViews",
    EVIDENCE_MISSING: "EvidenceMissing",
}
COUNT_NAMES = (
    "record_count",
    "scored",
    "pending",
    "redacted",
    "unavailable",
    "predictor_supplied",
    "scored_entities",
)
METRIC_NAMES = (
    "brier_micros",
    "crps_micros",
    "ece_micros",
    "population_avg_brier_micros",
    "lift_vs_population_avg_micros",
    "persistence_brier_micros",
    "lift_vs_persistence_micros",
    "personal_base_rate_brier_micros",
    "lift_vs_personal_base_rate_micros",
)
HEADER_FIELDS = (
    "magic",
    "version",
    "algorithm_id",
    "algorithm_major",
    "binning",
    "minimum_scored_records",
    "record_count",
    "records",
)

# --- Deterministic CBOR (RFC 8949 section 4.2.1) ---


@dataclass(frozen=True)
class Raw:
    """Bytes spliced into an encoding as they are; the malformed sub-cases use it."""

    data: bytes


def head(major: int, value: int) -> bytes:
    """The preferred (shortest) head of `major` with argument `value`."""
    if value < 24:
        return bytes([major << 5 | value])
    for info, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if value < 1 << (8 * width):
            return bytes([major << 5 | info]) + value.to_bytes(width, "big")
    raise ValueError("CBOR argument exceeds 64 bits")


def enc(value: object) -> bytes:
    if isinstance(value, Raw):
        return value.data
    if value is None:
        return b"\xf6"
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(enc(item) for item in value)
    raise TypeError(type(value))


def text_bytes(data: bytes) -> Raw:
    """A text string item whose content is `data` as given (it may be invalid UTF-8)."""
    return Raw(head(3, len(data)) + data)


# --- Rounding (section 4.3) ---


def round_half_even(value: Fraction) -> int:
    """`q = floor(x)`, `r = x - q`; `q + 1` if `r > 1/2`, or `r = 1/2` and `q` is odd."""
    q = math.floor(value)
    r = value - q
    if r > Fraction(1, 2) or (r == Fraction(1, 2) and q % 2 == 1):
        return q + 1
    return q


# --- Records ---


@dataclass(frozen=True)
class Rec:
    prediction_id: str
    entity_id: str
    probability: int
    state: int
    outcome: int | None
    supplied: bool = False

    def value(self) -> list:
        return [
            self.prediction_id,
            self.entity_id,
            self.probability,
            self.state,
            self.outcome,
            self.supplied,
        ]


def obs(pid: str, eid: str, p: int, o: int, supplied: bool = False) -> Rec:
    return Rec(pid, eid, p, OBSERVED, o, supplied)


def pending(pid: str, eid: str, p: int) -> Rec:
    return Rec(pid, eid, p, PENDING, None)


def redacted(pid: str, eid: str, p: int) -> Rec:
    return Rec(pid, eid, p, REDACTED, None)


def unavailable(pid: str, eid: str, p: int) -> Rec:
    return Rec(pid, eid, p, UNAVAILABLE, None)


def mti1(
    records: list,
    minimum: int = 1,
    *,
    record_count: object = None,
    magic: object = "MTI1",
    version: object = 1,
    algorithm_id: object = ALGORITHM_ID,
    major: object = ALGORITHM_MAJOR,
    binning: object = EQUAL_WIDTH_10,
    minimum_item: object = None,
    records_item: object = None,
    trailing: bytes = b"",
) -> bytes:
    """`MetricInputV1` bytes; any field may be replaced to build a malformed input."""
    items = [item.value() if isinstance(item, Rec) else item for item in records]
    fields = [
        magic,
        version,
        algorithm_id,
        major,
        binning,
        minimum if minimum_item is None else minimum_item,
        len(records) if record_count is None else record_count,
        items if records_item is None else records_item,
    ]
    return enc(fields) + trailing


# --- Strict MTI1 decoder (sections 4.2 and the decode-order rules of the profile text) ---


class Failure(Exception):
    """A closed `MetricErrorV1` and the CNR1 first coordinate."""

    def __init__(self, error: str, coordinate: str) -> None:
        super().__init__(f"{error} at {coordinate}")
        self.error = error
        self.coordinate = coordinate


class Reader:
    """Reads one deterministic-CBOR data item at a time, in encoding order."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def _take(self, count: int, where: str) -> bytes:
        if self.pos + count > len(self.data):
            raise Failure("InvalidEncoding", where)
        piece = self.data[self.pos : self.pos + count]
        self.pos += count
        return piece

    def head(self, where: str) -> tuple[int, int]:
        """`(major, argument)`; maps, tags, floats, other simple values, indefinite lengths and
        non-preferred widths are `InvalidEncoding` at `where`. Major 7 returns its info."""
        initial = self._take(1, where)[0]
        major, info = initial >> 5, initial & 31
        if major == 7:
            if info in (20, 21, 22):
                return 7, info
            raise Failure("InvalidEncoding", where)
        if major in (5, 6) or info > 27:
            raise Failure("InvalidEncoding", where)
        if info < 24:
            return major, info
        width = 1 << (info - 24)
        value = int.from_bytes(self._take(width, where), "big")
        if value < (24 if width == 1 else 1 << (4 * width)):
            raise Failure("InvalidEncoding", where)
        return major, value

    def uint(self, where: str) -> int:
        major, value = self.head(where)
        if major != 0:
            raise Failure("InvalidEncoding", where)
        return value

    def text(self, where: str) -> bytes:
        major, length = self.head(where)
        if major != 3:
            raise Failure("InvalidEncoding", where)
        return self._take(length, where)

    def array(self, where: str) -> int:
        major, length = self.head(where)
        if major != 4:
            raise Failure("InvalidEncoding", where)
        return length

    def uint_or_null(self, where: str) -> int | None:
        major, value = self.head(where)
        if major == 0:
            return value
        if major == 7 and value == 22:
            return None
        raise Failure("InvalidEncoding", where)

    def boolean(self, where: str) -> bool:
        major, value = self.head(where)
        if major == 7 and value in (20, 21):
            return value == 21
        raise Failure("InvalidEncoding", where)

    def finish(self) -> None:
        if self.pos != len(self.data):
            raise Failure("InvalidEncoding", "trailing")


@dataclass(frozen=True)
class MetricInput:
    minimum: int
    records: tuple[Rec, ...]


def identifier(reader: Reader, where: str) -> bytes:
    raw = reader.text(where)
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Failure("InvalidIdentifier", where) from None
    if not 1 <= len(raw) <= MAX_IDENTIFIER_BYTES:
        raise Failure("InvalidIdentifier", where)
    return raw


def skip_item(reader: Reader, where: str) -> None:
    """Consume one data item and everything inside it without keeping it."""
    major, argument = reader.head(where)
    if major in (2, 3):
        reader._take(argument, where)
    elif major == 4:
        for index in range(argument):
            skip_item(reader, f"{where}/{index}")


def check_structure(data: bytes) -> None:
    """The structural pass over the whole input (section 4.2 failure precedence: structure
    first). It keeps nothing: deterministic-CBOR well-formedness (no map, tag, float or other
    simple value, indefinite length, non-preferred head, truncation or trailing bytes) and the
    record shape (a root array of 8 fields, a records array, records of 6 fields)."""
    reader = Reader(data)
    major, length = reader.head("input")
    if major != 4 or length != len(HEADER_FIELDS):
        raise Failure("InvalidEncoding", "input")
    for name in HEADER_FIELDS[:-1]:
        skip_item(reader, name)
    major, count = reader.head("records")
    if major != 4:
        raise Failure("InvalidEncoding", "records")
    for index in range(count):
        at = f"records/{index}"
        major, length = reader.head(at)
        if major != 4 or length != 6:
            raise Failure("InvalidEncoding", at)
        for field_index in range(6):
            skip_item(reader, f"{at}/{field_index}")
    reader.finish()


def decode_mti1(data: bytes) -> MetricInput:
    """Decode `MTI1`: the structural pass, then header fields in index order, then records in
    order with fields in index order; the first failure wins (section 4.2)."""
    check_structure(data)
    reader = Reader(data)
    if reader.array("input") != len(HEADER_FIELDS):
        raise Failure("InvalidEncoding", "input")
    if reader.text("magic") != b"MTI1":
        raise Failure("UnsupportedVersion", "magic")
    if reader.uint("version") != 1:
        raise Failure("UnsupportedVersion", "version")
    if reader.text("algorithm_id") != ALGORITHM_ID.encode("ascii"):
        raise Failure("UnsupportedAlgorithm", "algorithm_id")
    if reader.uint("algorithm_major") != ALGORITHM_MAJOR:
        raise Failure("UnsupportedAlgorithm", "algorithm_major")
    if reader.uint("binning") != EQUAL_WIDTH_10:
        raise Failure("InvalidBinning", "binning")
    minimum = reader.uint("minimum_scored_records")
    if not 1 <= minimum <= MAX_RECORDS:
        raise Failure("InvalidMinimum", "minimum_scored_records")
    record_count = reader.uint("record_count")
    if record_count > MAX_RECORDS:
        raise Failure("ResourceLimit", "record_count")
    if reader.array("records") != record_count:
        raise Failure("InconsistentLength", "records")
    previous: bytes | None = None
    records = []
    for index in range(record_count):
        at = f"records/{index}"
        if reader.array(at) != 6:
            raise Failure("InvalidEncoding", at)
        prediction_id = identifier(reader, f"{at}/0")
        if previous is not None and prediction_id == previous:
            raise Failure("DuplicatePrediction", f"{at}/0")
        if previous is not None and prediction_id < previous:
            raise Failure("NonCanonicalOrder", f"{at}/0")
        previous = prediction_id
        entity_id = identifier(reader, f"{at}/1")
        probability = reader.uint(f"{at}/2")
        if probability > D:
            raise Failure("InvalidProbability", f"{at}/2")
        state = reader.uint(f"{at}/3")
        if state > UNAVAILABLE:
            raise Failure("InvalidOutcome", f"{at}/3")
        outcome = reader.uint_or_null(f"{at}/4")
        if state == OBSERVED and (outcome is None or outcome > 1):
            raise Failure("InvalidOutcome", f"{at}/4")
        if state != OBSERVED and outcome is not None:
            raise Failure("InvalidOutcome", f"{at}/4")
        supplied = reader.boolean(f"{at}/5")
        if supplied and state != OBSERVED:
            raise Failure("InvalidOutcome", f"{at}/5")
        records.append(
            Rec(
                prediction_id.decode("utf-8"),
                entity_id.decode("utf-8"),
                probability,
                state,
                outcome,
                supplied,
            )
        )
    reader.finish()
    return MetricInput(minimum, tuple(records))


# --- The algorithms (section 4.3), closed integer formulas ---


@dataclass(frozen=True)
class Exact:
    """The exact rational value of every metric before its one final rounding."""

    brier: Fraction
    ece: Fraction
    population_avg_brier: Fraction
    lift_vs_population_avg: Fraction
    persistence_brier: Fraction
    lift_vs_persistence: Fraction
    personal_base_rate_brier: Fraction
    lift_vs_personal_base_rate: Fraction
    lift_vs_personal_base_rate_without_floor: Fraction

    def micros(self) -> list[int]:
        brier = round_half_even(self.brier)
        return [
            brier,
            brier,
            round_half_even(self.ece),
            round_half_even(self.population_avg_brier),
            round_half_even(self.lift_vs_population_avg),
            round_half_even(self.persistence_brier),
            round_half_even(self.lift_vs_persistence),
            round_half_even(self.personal_base_rate_brier),
            round_half_even(self.lift_vs_personal_base_rate),
        ]


def scored(records: tuple[Rec, ...]) -> list[Rec]:
    return [record for record in records if record.state == OBSERVED]


def entity_term(count: int, positives: int) -> Fraction:
    """`T_e` of section 4.3 step 6."""
    if count == 1:
        return Fraction(positives)
    return Fraction(positives * (count - positives) * count, (count - 1) ** 2)


def exact_metrics(records: tuple[Rec, ...]) -> Exact:
    """Every metric value in micro-units, exact, by the closed formulas of section 4.3."""
    s = scored(records)
    n = len(s)
    e = sum((r.probability - D * r.outcome) ** 2 for r in s)
    deviations = [0] * BIN_COUNT
    sums = [0] * BIN_COUNT
    positives_in_bin = [0] * BIN_COUNT
    for r in s:
        k = min(r.probability // BIN_WIDTH, BIN_COUNT - 1)
        sums[k] += r.probability
        positives_in_bin[k] += r.outcome
    for k in range(BIN_COUNT):
        deviations[k] = abs(sums[k] - D * positives_in_bin[k])
    total_p = sum(r.probability for r in s)
    k_all = sum(r.outcome for r in s)
    pop = Fraction(sum((total_p - n * D * r.outcome) ** 2 for r in s), n**3 * D)
    model = Fraction(e, n * D)
    pers = Fraction(k_all * (n - k_all) * D, n**2)
    groups: dict[str, list[int]] = {}
    for r in s:
        groups.setdefault(r.entity_id, []).append(r.outcome)
    floored = 0
    unfloored = Fraction(0)
    for outcomes in groups.values():
        term = entity_term(len(outcomes), sum(outcomes))
        floored += math.floor(term * PBR_SCALE)
        unfloored += term * PBR_SCALE
    return Exact(
        brier=model,
        ece=Fraction(sum(deviations), n),
        population_avg_brier=pop,
        lift_vs_population_avg=pop - model,
        persistence_brier=pers,
        lift_vs_persistence=pers - model,
        personal_base_rate_brier=Fraction(floored, n * 10**12),
        lift_vs_personal_base_rate=Fraction(floored - D * e, n * 10**12),
        lift_vs_personal_base_rate_without_floor=(unfloored - D * e) / (n * 10**12),
    )


def bins(records: tuple[Rec, ...]) -> list[list[int]]:
    table = [[0, 0, 0] for _ in range(BIN_COUNT)]
    for r in scored(records):
        row = table[min(r.probability // BIN_WIDTH, BIN_COUNT - 1)]
        row[0] += 1
        row[1] += r.probability
        row[2] += r.outcome
    return table


def counts(records: tuple[Rec, ...]) -> list[int]:
    s = scored(records)
    return [
        len(records),
        len(s),
        sum(r.state == PENDING for r in records),
        sum(r.state == REDACTED for r in records),
        sum(r.state == UNAVAILABLE for r in records),
        sum(r.supplied for r in s),
        len({r.entity_id for r in s}),
    ]


def redaction_state(records: tuple[Rec, ...]) -> int:
    if any(r.state == UNAVAILABLE for r in records):
        return EVIDENCE_MISSING
    if any(r.state == REDACTED for r in records):
        return REDACTED_VIEWS
    return REDACTION_NONE


def mtr1_fields(
    data: bytes, metric_input: MetricInput, *, algorithm_major: int = ALGORITHM_MAJOR
) -> list:
    """Fields 0..11 of `MetricResultV1` for the `MTI1` bytes `data`."""
    records = metric_input.records
    computed = len(scored(records)) >= metric_input.minimum
    return [
        "MTR1",
        1,
        ALGORITHM_ID,
        algorithm_major,
        EQUAL_WIDTH_10,
        golden.blake3(INPUT_DOMAIN + data),
        COMPUTED if computed else INSUFFICIENT_SAMPLES,
        counts(records),
        metric_input.minimum,
        redaction_state(records),
        exact_metrics(records).micros() if computed else None,
        bins(records) if computed else None,
    ]


def seal_mtr1(fields: list) -> bytes:
    """`result_digest32` is the BLAKE3 of the domain and the encoding of fields 0..11."""
    digest = golden.blake3(RESULT_DOMAIN + enc(fields))
    encoded = enc(fields + [digest])
    if len(encoded) > MAX_MTR1_BYTES:
        raise SystemExit("an MTR1 exceeds the 1 KiB bound")
    return encoded


def compute_mtr1(data: bytes) -> bytes:
    return seal_mtr1(mtr1_fields(data, decode_mti1(data)))


def check_mtr1_header(data: bytes) -> None:
    """Accept an `MTR1` only for this profile's record version and algorithm major."""
    reader = Reader(data)
    if reader.array("result") != 13:
        raise Failure("InvalidEncoding", "result")
    if reader.text("magic") != b"MTR1":
        raise Failure("UnsupportedVersion", "magic")
    if reader.uint("version") != 1:
        raise Failure("UnsupportedVersion", "version")
    if reader.text("algorithm_id") != ALGORITHM_ID.encode("ascii"):
        raise Failure("UnsupportedAlgorithm", "algorithm_id")
    if reader.uint("algorithm_major") != ALGORITHM_MAJOR:
        raise Failure("UnsupportedAlgorithm", "algorithm_major")


# --- Probability quantization (section 4.4) ---


def quantize(bits: int) -> int | None:
    """`probability_micros` of a binary64 bit pattern, by integer arithmetic; `None` is
    `InvalidProbability`."""
    negative = bits >> 63
    exponent = (bits >> 52) & 0x7FF
    fraction = bits & ((1 << 52) - 1)
    if exponent == 0x7FF:
        return None
    mantissa = fraction if exponent == 0 else fraction | 1 << 52
    shift = (1 if exponent == 0 else exponent) - 1075
    if mantissa == 0:
        return 0
    if negative:
        return None
    if shift >= 0:
        value = Fraction(mantissa << shift)
    else:
        value = Fraction(mantissa, 1 << -shift)
    if value > 1:
        return None
    return round_half_even(value * D)


def mtq1(patterns: list[int]) -> bytes:
    if not 1 <= len(patterns) <= MAX_PATTERNS:
        raise SystemExit("an MTQ1 must hold 1 to 4096 patterns")
    return enc(["MTQ1", 1, patterns])


def mqr1(patterns: list[int]) -> bytes:
    entries: list = []
    for bits in patterns:
        micros = quantize(bits)
        entries.append([ERRORS.index("InvalidProbability")] if micros is None else micros)
    return enc(["MQR1", 1, entries])


def bits_of(value: float) -> int:
    return struct.unpack(">Q", struct.pack(">d", value))[0]


# --- Sub-cases ---


@dataclass
class SubCase:
    id: str
    title: str
    record: str | None = None
    member: bytes | None = None
    stimulus: dict | None = None
    expect: dict | None = None
    pins: tuple[str, ...] = ()
    marker: str | None = None
    floor_matters: bool = False
    patterns: list[int] | None = None

    def result(self) -> bytes:
        if self.record == "MTQ1":
            assert self.patterns is not None
            return mqr1(self.patterns)
        assert self.member is not None
        return compute_mtr1(self.member)


def result_case(sub_id: str, title: str, data: bytes, **extra) -> SubCase:
    return SubCase(sub_id, title, record="MTI1", member=data, expect={"kind": "result"}, **extra)


def error_case(sub_id: str, title: str, data: bytes, error: str, coordinate: str) -> SubCase:
    expect = {
        "kind": "metric-error",
        "error": error,
        "code": ERRORS.index(error),
        "first_coordinate": coordinate,
    }
    return SubCase(sub_id, title, record="MTI1", member=data, expect=expect)


def worked_example() -> bytes:
    return mti1(
        [
            obs("p01", "e1", 700_000, 1),
            obs("p02", "e1", 200_000, 0),
            obs("p03", "e1", 900_000, 1),
            obs("p04", "e2", 500_000, 0),
            pending("p05", "e3", 100_000),
        ]
    )


def pos4_records() -> list[Rec]:
    """Entities with `n_e` = 7, 4, 4, 2, 2, 2, 1 and 1; the three entity terms 7/3, 4/3 and
    4/3 are not multiples of 10^-18, and the squared errors are chosen so that the lift
    against the personal base rate is a tie without the floor and below it with the floor."""
    out = []
    # (entity, outcomes, distance |p - y| per record); p = d for 0, p = D - d for 1.
    plan = [
        ("a7", [1, 1, 1, 0, 0, 0, 0], [1224, 3, 0, 42, 7, 1, 0]),
        ("b4", [1, 0, 0, 0], [1, 0, 0, 0]),
        ("c4", [1, 1, 1, 0], [0, 0, 0, 0]),
        ("d1", [1], [0]),
        ("e1", [0], [0]),
        ("f2", [1, 1], [D, D]),
        ("g2", [0, 0], [0, 0]),
        ("h2", [1, 0], [0, 0]),
    ]
    index = 0
    for entity, outcomes, distances in plan:
        for outcome, distance in zip(outcomes, distances):
            index += 1
            p = D - distance if outcome else distance
            out.append(obs(f"r{index:02d}", entity, p, outcome))
    return out


def positive_subcases() -> list[SubCase]:
    wide = "é" * 32  # 32 two-byte characters: exactly 64 UTF-8 bytes
    return [
        result_case("pos.1", "worked example of section 4.3", worked_example()),
        result_case(
            "pos.2",
            "bin-edge probabilities 0, 99999, 100000, 899999, 900000, 999999 and 1000000",
            mti1(
                [
                    obs("b1", "e1", 0, 0),
                    obs("b2", "e1", 99_999, 1),
                    obs("b3", "e2", 100_000, 0),
                    obs("b4", "e2", 899_999, 1),
                    obs("b5", "e3", 900_000, 0),
                    obs("b6", "e3", 999_999, 1),
                    obs("b7", "e4", 1_000_000, 1),
                ]
            ),
        ),
        result_case(
            "pos.3a",
            "ties: brier 3/2 up to 2, negative lifts -1/2 to 0 and -3/2 to -2",
            mti1(
                [
                    obs("t1", "s1", 2000, 0),
                    obs("t2", "s2", 1000, 0),
                    obs("t3", "s3", 1000, 0),
                    obs("t4", "s4", 0, 0),
                ]
            ),
            pins=(
                "brier_micros",
                "lift_vs_population_avg_micros",
                "lift_vs_persistence_micros",
                "lift_vs_personal_base_rate_micros",
            ),
        ),
        result_case(
            "pos.3b",
            "ties: brier 1/2 down to 0, lift 499999/2 up to 250000",
            mti1([obs("t1", "s1", 1000, 0), obs("t2", "s2", 1_000_000, 1)]),
            pins=("brier_micros", "lift_vs_persistence_micros"),
        ),
        result_case(
            "pos.3c",
            "tie: ece 100001/2 down to 50000",
            mti1([obs("t1", "s1", 100_001, 0), obs("t2", "s2", 1_000_000, 1)]),
            pins=("ece_micros",),
        ),
        result_case(
            "pos.3d",
            "tie: ece 100003/2 up to 50002",
            mti1([obs("t1", "s1", 100_003, 0), obs("t2", "s2", 1_000_000, 1)]),
            pins=("ece_micros",),
        ),
        result_case(
            "pos.3e",
            "ties: brier 5/2 down to 2, negative lifts -5/2 up to -2 and -3/2 down to -2",
            mti1(
                [
                    obs("t1", "s1", 3000, 0),
                    obs("t2", "s2", 1000, 0),
                    obs("t3", "s3", 0, 0),
                    obs("t4", "s4", 0, 0),
                ]
            ),
            pins=(
                "brier_micros",
                "lift_vs_population_avg_micros",
                "lift_vs_persistence_micros",
                "lift_vs_personal_base_rate_micros",
            ),
        ),
        result_case(
            "pos.4",
            "personal base rate: n_e 1, 2, 4 and 7, all-positive and all-negative entities, "
            "and entity terms whose 10^-18 floor changes the rounded lift",
            mti1(pos4_records()),
            floor_matters=True,
        ),
        result_case(
            "pos.5",
            "predictor-supplied counting, a 64-byte identifier and UTF-8 byte order",
            mti1(
                [
                    obs("s1", "plain", 400_000, 1, supplied=True),
                    obs("s2", wide, 600_000, 0, supplied=True),
                    obs("s3", wide, 300_000, 1),
                    pending("s4", "plain", 800_000),
                    obs("sZ", "plain", 550_000, 0),
                    obs("sé", "plain", 450_000, 1, supplied=True),
                ]
            ),
        ),
        result_case(
            "pos.6a",
            "perfect predictor: brier 0 and ece 0",
            mti1(
                [
                    obs("q1", "e1", 0, 0),
                    obs("q2", "e1", 1_000_000, 1),
                    obs("q3", "e2", 0, 0),
                    obs("q4", "e2", 1_000_000, 1),
                ]
            ),
        ),
        result_case(
            "pos.6b",
            "worst predictor: brier 1000000 and ece 1000000",
            mti1(
                [
                    obs("q1", "e1", 1_000_000, 0),
                    obs("q2", "e1", 0, 1),
                    obs("q3", "e2", 1_000_000, 0),
                    obs("q4", "e2", 0, 1),
                ]
            ),
        ),
        quantization_case("pos.7", "the MTQ1 quantization vectors of section 4.4", PAGE_VECTORS),
        result_case(
            "pos.8a",
            "InsufficientSamples: zero records",
            mti1([]),
        ),
        result_case(
            "pos.8b",
            "InsufficientSamples: every record Pending",
            mti1(
                [
                    pending("w1", "e1", 100_000),
                    pending("w2", "e1", 200_000),
                    pending("w3", "e2", 300_000),
                ]
            ),
        ),
        result_case(
            "pos.8c",
            "InsufficientSamples: 2 scored records below the declared minimum 3",
            mti1([obs("w1", "e1", 100_000, 0), obs("w2", "e2", 900_000, 1)], minimum=3),
        ),
    ]


def quantization_case(sub_id: str, title: str, vectors: list[tuple[int, object]]) -> SubCase:
    patterns = [bits for bits, _wanted in vectors]
    return SubCase(
        sub_id,
        title,
        record="MTQ1",
        member=mtq1(patterns),
        expect={"kind": "result"},
        patterns=patterns,
    )


# Section 4.4 table: (bit pattern, probability_micros or None for InvalidProbability).
PAGE_VECTORS: list[tuple[int, object]] = [
    (0x0000000000000000, 0),
    (0x8000000000000000, 0),
    (0x3FF0000000000000, 1_000_000),
    (bits_of(0.1), 100_000),
    (bits_of(0.15), 150_000),
    (bits_of(2.0**-7), 7812),
    (bits_of(3 * 2.0**-7), 23438),
    (0x0000000000000001, 0),
    (bits_of(1.000001), None),
]

# ind.3: further patterns; the expected values come from `quantize` and are cross-checked
# through `Fraction(float)` in the self-test.
MORE_PATTERNS = [
    bits_of(0.5),
    bits_of(0.25),
    0x3FEFFFFFFFFFFFFF,  # the largest binary64 below 1
    0x3FF0000000000001,  # the smallest binary64 above 1
    bits_of(5 * 2.0**-7),  # 39062.5, a tie down to even
    bits_of(5e-7),  # just below a half micro
    bits_of(1.5e-6),  # just above one and a half micros
    bits_of(2.0**-20),
    bits_of(0.999999),
    0x000FFFFFFFFFFFFF,  # the largest subnormal
    0x8000000000000001,  # the negative smallest subnormal
    0xBFF0000000000000,  # -1.0
    0x7FF8000000000000,  # quiet NaN
    0x7FF0000000000001,  # signalling NaN
    0x7FF0000000000000,  # +Inf
    0xFFF0000000000000,  # -Inf
]

BASE = [obs("m01", "e1", 300_000, 1), obs("m02", "e2", 600_000, 0)]


def record_with(index: tuple[int, int | None], item: object, records: list | None = None) -> list:
    """`records` (default `BASE`) as values, with field or record `index` replaced."""
    values = [r.value() for r in (records or BASE)]
    record, field_index = index
    if field_index is None:
        values[record] = item
    else:
        values[record][field_index] = item
    return values


def denied_subcases() -> list[SubCase]:
    data = worked_example()
    return [
        SubCase(
            "den.1",
            "the subject requests a capability other than read-public-bundle",
            record="MTI1",
            member=data,
            stimulus={"kind": "capability-request", "capability": "mutate-subject"},
            expect={"kind": "denied", "code_id": "capability-denied", "output": None},
        ),
        SubCase(
            "den.2",
            "network use is denied: Air-Gapped is network-deny and Local declares no network",
            record="MTI1",
            member=data,
            stimulus={"kind": "network-request", "execution_profile": "deterministic-air-gapped-v1"},
            expect={"kind": "denied", "code_id": "capability-denied", "output": None},
        ),
    ]


def malformed_subcases() -> list[SubCase]:
    long_id = "é" * 32 + "x"  # 65 UTF-8 bytes
    return [
        error_case(
            "mal.1a", "half-precision float probability",
            mti1(record_with((0, 2), Raw(b"\xf9\x38\x00"))), "InvalidEncoding", "records/0/2",
        ),
        error_case(
            "mal.1b", "single-precision float probability",
            mti1(record_with((0, 2), Raw(b"\xfa" + struct.pack(">f", 0.3)))),
            "InvalidEncoding", "records/0/2",
        ),
        error_case(
            "mal.1c", "double-precision float probability",
            mti1(record_with((0, 2), Raw(b"\xfb" + struct.pack(">d", 0.3)))),
            "InvalidEncoding", "records/0/2",
        ),
        error_case(
            "mal.2a", "NaN float probability",
            mti1(record_with((1, 2), Raw(b"\xf9\x7e\x00"))), "InvalidEncoding", "records/1/2",
        ),
        error_case(
            "mal.2b", "+Inf float probability",
            mti1(record_with((1, 2), Raw(b"\xf9\x7c\x00"))), "InvalidEncoding", "records/1/2",
        ),
        error_case(
            "mal.2c", "-Inf float probability",
            mti1(record_with((1, 2), Raw(b"\xf9\xfc\x00"))), "InvalidEncoding", "records/1/2",
        ),
        error_case(
            "mal.3", "probability_micros 1000001",
            mti1(record_with((1, 2), 1_000_001)), "InvalidProbability", "records/1/2",
        ),
        error_case("mal.4", "binning 1", mti1(BASE, binning=1), "InvalidBinning", "binning"),
        error_case(
            "mal.5a", "record_count 3 with 2 records",
            mti1(BASE, record_count=3), "InconsistentLength", "records",
        ),
        error_case(
            "mal.5b", "record_count 1 with 2 records",
            mti1(BASE, record_count=1), "InconsistentLength", "records",
        ),
        error_case(
            "mal.6a", "wrong magic MTI2",
            mti1(BASE, magic="MTI2"), "UnsupportedVersion", "magic",
        ),
        error_case(
            "mal.6b", "record version 2",
            mti1(BASE, version=2), "UnsupportedVersion", "version",
        ),
        error_case(
            "mal.6c", "algorithm major 2",
            mti1(BASE, major=2), "UnsupportedAlgorithm", "algorithm_major",
        ),
        error_case(
            "mal.6d", "unknown algorithm id",
            mti1(BASE, algorithm_id="pigloros.metric.multi-class"),
            "UnsupportedAlgorithm", "algorithm_id",
        ),
        error_case(
            "mal.7", "duplicate prediction_id",
            mti1(record_with((1, 0), "m01")), "DuplicatePrediction", "records/1/0",
        ),
        error_case(
            "mal.8", "records not sorted by prediction_id bytes",
            mti1([BASE[1].value(), BASE[0].value()]), "NonCanonicalOrder", "records/1/0",
        ),
        error_case(
            "mal.9a", "Observed with a null outcome",
            mti1(record_with((0, 4), None)), "InvalidOutcome", "records/0/4",
        ),
        error_case(
            "mal.9b", "Pending with an outcome",
            mti1([BASE[0].value(), ["m02", "e2", 600_000, PENDING, 0, False]]),
            "InvalidOutcome", "records/1/4",
        ),
        error_case(
            "mal.9c", "outcome 2",
            mti1(record_with((0, 4), 2)), "InvalidOutcome", "records/0/4",
        ),
        error_case(
            "mal.9d", "predictor_supplied true on a Pending record",
            mti1([BASE[0].value(), ["m02", "e2", 600_000, PENDING, None, True]]),
            "InvalidOutcome", "records/1/5",
        ),
        error_case(
            "mal.10a", "non-preferred integer width (8-byte head for 300000)",
            mti1(record_with((0, 2), Raw(b"\x1b" + (300_000).to_bytes(8, "big")))),
            "InvalidEncoding", "records/0/2",
        ),
        error_case(
            "mal.10b", "indefinite-length records array",
            mti1(
                BASE,
                records_item=Raw(b"\x9f" + b"".join(enc(r.value()) for r in BASE) + b"\xff"),
            ),
            "InvalidEncoding", "records",
        ),
        error_case(
            "mal.10c", "tagged probability (tag 1)",
            mti1(record_with((0, 2), Raw(b"\xc1" + enc(300_000)))),
            "InvalidEncoding", "records/0/2",
        ),
        error_case(
            "mal.10d", "a record encoded as a map",
            mti1(record_with((1, None), Raw(b"\xa1" + enc("m02") + enc(0)))),
            "InvalidEncoding", "records/1",
        ),
        error_case(
            "mal.10e", "a trailing byte after MTI1",
            mti1(BASE, trailing=b"\x00"), "InvalidEncoding", "trailing",
        ),
        error_case(
            "mal.11a", "empty prediction_id",
            mti1(record_with((0, 0), "")), "InvalidIdentifier", "records/0/0",
        ),
        error_case(
            "mal.11b", "65-byte entity_id",
            mti1(record_with((0, 1), long_id)), "InvalidIdentifier", "records/0/1",
        ),
        error_case(
            "mal.11c", "invalid UTF-8 entity_id",
            mti1(record_with((1, 1), text_bytes(b"e\xff"))), "InvalidIdentifier", "records/1/1",
        ),
        error_case(
            "mal.12a", "minimum_scored_records 0",
            mti1(BASE, minimum=0), "InvalidMinimum", "minimum_scored_records",
        ),
        error_case(
            "mal.12b", "minimum_scored_records 262145",
            mti1(BASE, minimum=MAX_RECORDS + 1), "InvalidMinimum", "minimum_scored_records",
        ),
        # Several defects: the first in decode order wins.
        error_case(
            "mal.13a", "precedence: wrong magic before version 2",
            mti1(BASE, magic="MTI2", version=2), "UnsupportedVersion", "magic",
        ),
        error_case(
            "mal.13b", "precedence: version 2 before binning 1 and a bad record",
            mti1(record_with((0, 2), 1_000_001), version=2, binning=1),
            "UnsupportedVersion", "version",
        ),
        error_case(
            "mal.13c", "precedence: binning 1 before minimum 0",
            mti1(BASE, binning=1, minimum=0), "InvalidBinning", "binning",
        ),
        error_case(
            "mal.13d", "precedence: a structural defect in a record before a header failure",
            mti1(record_with((0, 2), Raw(b"\xf9\x38\x00")), minimum=0),
            "InvalidEncoding", "records/0/2",
        ),
        error_case(
            "mal.13e", "precedence: a float in field 2 before an empty identifier in field 0",
            mti1(_replace(record_with((0, 0), ""), (0, 2), Raw(b"\xf9\x38\x00"))),
            "InvalidEncoding", "records/0/2",
        ),
        error_case(
            "mal.13f", "precedence: a float in record 1 before outcome 2 in record 0",
            mti1(_replace(record_with((0, 4), 2), (1, 2), Raw(b"\xfb" + struct.pack(">d", 0.6)))),
            "InvalidEncoding", "records/1/2",
        ),
        error_case(
            "mal.13g", "precedence: order is checked at field 0, before field 2",
            mti1(_replace([BASE[1].value(), BASE[0].value()], (1, 2), 1_000_001)),
            "NonCanonicalOrder", "records/1/0",
        ),
        error_case(
            "mal.13h", "precedence: trailing bytes before a semantic record failure",
            mti1(record_with((1, 2), 1_000_001), trailing=b"\x00"),
            "InvalidEncoding", "trailing",
        ),
        error_case(
            "mal.13i", "precedence: a duplicate before a later invalid probability",
            mti1(_replace(record_with((1, 0), "m01"), (1, 2), 1_000_001)),
            "DuplicatePrediction", "records/1/0",
        ),
    ]


def _replace(values: list, index: tuple[int, int], item: object) -> list:
    record, field_index = index
    values[record][field_index] = item
    return values


def resource_subcases() -> list[SubCase]:
    return [
        error_case(
            "res.1", "declared record_count 262145: ResourceLimit before any record is read",
            mti1([], record_count=MAX_RECORDS + 1), "ResourceLimit", "record_count",
        ),
        SubCase(
            "res.2",
            "an MTI1 member above the 64 MiB member ceiling is rejected by the transport (#222)",
            stimulus={
                "kind": "oversized-member",
                "record": "MTI1",
                "bytes": MAX_MTI1_BYTES + 1,
                "ceiling_bytes": MAX_MTI1_BYTES,
                "fill": "zero",
            },
            expect={"kind": "transport-rejection", "error": "FieldOutOfBounds"},
        ),
        SubCase(
            "res.3",
            "execution-step budget exceeded",
            record="MTI1",
            member=worked_example(),
            stimulus={"kind": "execution-steps", "maximum": 10_000_000, "requested": 10_000_001},
            expect={"kind": "resource-limit", "code_id": "resource-limit"},
        ),
    ]


CANARY = "synthetic-secret-canary-del3"


def redaction_subcases() -> list[SubCase]:
    return [
        result_case(
            "del.1a",
            "Redacted and Unavailable records are excluded and counted: EvidenceMissing",
            mti1(
                [
                    obs("d1", "e1", 800_000, 1),
                    redacted("d2", "e1", 300_000),
                    obs("d3", "e2", 200_000, 0),
                    unavailable("d4", "e2", 700_000),
                    obs("d5", "e3", 600_000, 1),
                ]
            ),
        ),
        result_case(
            "del.1b",
            "Redacted records only: RedactedViews",
            mti1(
                [
                    obs("d1", "e1", 800_000, 1),
                    redacted("d2", "e1", 300_000),
                    obs("d3", "e2", 200_000, 0),
                    redacted("d4", "e2", 700_000),
                ]
            ),
        ),
        result_case(
            "del.2",
            "every record Redacted: InsufficientSamples with RedactedViews",
            mti1(
                [
                    redacted("d1", "e1", 800_000),
                    redacted("d2", "e1", 300_000),
                    redacted("d3", "e2", 200_000),
                ]
            ),
        ),
        result_case(
            "del.3",
            "a synthetic canary in entity_id never appears in MTR1",
            mti1(
                [
                    obs("d1", CANARY, 650_000, 1),
                    obs("d2", CANARY, 250_000, 0),
                    obs("d3", "e2", 400_000, 1),
                ]
            ),
            marker=CANARY,
        ),
    ]


def foreign_major_result() -> bytes:
    data = worked_example()
    return seal_mtr1(mtr1_fields(data, decode_mti1(data), algorithm_major=2))


def downgrade_subcases(context: Context) -> list[SubCase]:
    return [
        error_case(
            "dgr.1", "an MTI1 version-2 input presented to a version-1 subject, no fallback",
            mti1([r for r in decode_mti1(worked_example()).records], version=2),
            "UnsupportedVersion", "version",
        ),
        SubCase(
            "dgr.2",
            "provider 1.0.0 (fixture-ratio) presented where 2.0.0 is required",
            stimulus={
                "kind": "provider-contract",
                "presented": {"provider_id": context.provider_id, "contract_version": "1.0.0"},
                "required": {
                    "provider_id": context.provider_id,
                    "contract_version": context.contract_version,
                },
                "allow_fallback": False,
            },
            expect={"kind": "incompatible-contract", "code_id": "incompatible-contract"},
        ),
        SubCase(
            "dgr.3",
            "an MTR1 bound to algorithm major 2 is not a result of this profile",
            record="MTR1",
            member=foreign_major_result(),
            expect={
                "kind": "result-rejected",
                "error": "UnsupportedAlgorithm",
                "code": ERRORS.index("UnsupportedAlgorithm"),
                "first_coordinate": "algorithm_major",
            },
        ),
    ]


def mixed_records() -> list[Rec]:
    """40 deterministic records over seven entities with every outcome state."""
    out = []
    for index in range(1, 41):
        p = (index * 7919 * 104_729) % (D + 1)
        entity = "solo" if index == 40 else f"e{index % 6}"
        pid = f"i{index:02d}"
        if index % 11 == 5:
            out.append(pending(pid, entity, p))
        elif index % 13 == 7:
            out.append(redacted(pid, entity, p))
        elif index == 29:
            out.append(unavailable(pid, entity, p))
        else:
            outcome = 1 if (index * 31 + 7) % 3 == 0 or p > 800_000 else 0
            out.append(obs(pid, entity, p, outcome, supplied=index % 5 == 0))
    return out


def independent_subcases() -> list[SubCase]:
    return [
        result_case(
            "ind.1",
            "pos-reference recomputes this MTI1 and every positive and deletion-redaction oracle",
            mti1(mixed_records(), minimum=10),
            stimulus={"kind": "recompute", "families": ["positive", "deletion-redaction"]},
        ),
        SubCase(
            "ind.2",
            "the generator --check reproduces every oracle with exact fractions",
            stimulus={"kind": "generator-check", "command": GENERATOR_COMMAND},
            expect={"kind": "generator-check"},
        ),
        quantization_case(
            "ind.3",
            "pos-reference recomputes the MTQ1 vectors from bit patterns",
            [(bits, None) for bits in [bits for bits, _ in PAGE_VECTORS] + MORE_PATTERNS],
        ),
    ]


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
    composite: bytes


def subcases_of(family: str, context: Context) -> list[SubCase]:
    if family == "positive":
        return positive_subcases()
    if family == "denied":
        return denied_subcases()
    if family == "malformed":
        return malformed_subcases()
    if family == "resource-exhaustion":
        return resource_subcases()
    if family == "deletion-redaction":
        return redaction_subcases()
    if family == "downgrade":
        return downgrade_subcases(context)
    return independent_subcases()


def jcs(value) -> bytes:
    """RFC 8785 canonical JSON of ASCII text, integers, booleans and null, no whitespace."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def fraction_text(value: Fraction) -> str:
    return f"{value.numerator}/{value.denominator}"


def exact_by_name(exact: Exact) -> dict[str, Fraction]:
    return {
        "brier_micros": exact.brier,
        "crps_micros": exact.brier,
        "ece_micros": exact.ece,
        "population_avg_brier_micros": exact.population_avg_brier,
        "lift_vs_population_avg_micros": exact.lift_vs_population_avg,
        "persistence_brier_micros": exact.persistence_brier,
        "lift_vs_persistence_micros": exact.lift_vs_persistence,
        "personal_base_rate_brier_micros": exact.personal_base_rate_brier,
        "lift_vs_personal_base_rate_micros": exact.lift_vs_personal_base_rate,
    }


def expect_object(sub: SubCase) -> dict:
    """The payload expectation: the oracle digest of a result, or the closed failure."""
    expect = dict(sub.expect or {})
    if expect.get("kind") == "result":
        result = sub.result()
        expect["record"] = "MQR1" if sub.record == "MTQ1" else "MTR1"
        expect["blake3"] = golden.blake3(result).hex()
        if sub.pins or sub.floor_matters:
            exact = exact_metrics(decode_mti1(sub.member).records)
            named = exact_by_name(exact)
            pins = []
            for name in sub.pins:
                pins.append(
                    {
                        "field": name,
                        "exact": fraction_text(named[name]),
                        "rounded": round_half_even(named[name]),
                    }
                )
            if sub.floor_matters:
                name = "lift_vs_personal_base_rate_micros"
                pins.append(
                    {
                        "field": name,
                        "exact": fraction_text(named[name]),
                        "rounded": round_half_even(named[name]),
                        "without_floor": round_half_even(
                            exact.lift_vs_personal_base_rate_without_floor
                        ),
                    }
                )
            expect["pins"] = pins
        if sub.marker is not None:
            expect["absent_marker"] = sub.marker
    return expect


def subcase_object(sub: SubCase) -> dict:
    value: dict = {"id": sub.id, "title": sub.title, "expect": expect_object(sub)}
    value["member"] = (
        None
        if sub.member is None
        else {
            "record": sub.record,
            "blake3": golden.blake3(sub.member).hex(),
            "bytes": len(sub.member),
        }
    )
    if sub.stimulus is not None:
        value["stimulus"] = sub.stimulus
    return value


def mtr1_values(result: bytes) -> dict:
    """A readable view of an `MTR1` (the bytes remain the oracle)."""
    fields = cbor_decode(result)
    metrics = fields[10]
    table = fields[11]
    return {
        "input_digest": fields[5].hex(),
        "result_kind": RESULT_KINDS[fields[6]],
        "counts": dict(zip(COUNT_NAMES, fields[7])),
        "minimum_scored_records": fields[8],
        "redaction_state": REDACTION_STATES[fields[9]],
        "metrics": None if metrics is None else dict(zip(METRIC_NAMES, metrics)),
        "bins": table,
        "result_digest": fields[12].hex(),
    }


def mqr1_values(sub: SubCase) -> dict:
    assert sub.patterns is not None
    entries = []
    for bits in sub.patterns:
        micros = quantize(bits)
        entries.append(
            {
                "pattern": f"{bits:016x}",
                "probability_micros": micros,
                "error": "InvalidProbability" if micros is None else None,
            }
        )
    return {"entries": entries}


def oracle_entry(sub: SubCase) -> dict:
    expect = sub.expect or {}
    if expect.get("kind") == "result":
        result = sub.result()
        entry = {
            "id": sub.id,
            "record": "MQR1" if sub.record == "MTQ1" else "MTR1",
            "blake3": golden.blake3(result).hex(),
            "hex": result.hex(),
        }
        entry["values"] = mqr1_values(sub) if sub.record == "MTQ1" else mtr1_values(result)
        return entry
    # A generator check (`ind.2`) is not executed by a subject: its entry names the sub-case and
    # its kind only, which the subject adapter can output (ADR-062 R7 slice 4, #1217).
    return {"id": sub.id, **expect}


def composite(subcases: list[SubCase]) -> bytes:
    """`["MCS1", 1, [[digest32, bytes], ...]]`, members sorted by digest, deduplicated."""
    by_digest = {golden.blake3(sub.member): sub.member for sub in subcases if sub.member}
    return enc([COMPOSITE_MAGIC, 1, [[d, by_digest[d]] for d in sorted(by_digest)]])


def render_family(family: str, context: Context) -> Outputs:
    subcases = subcases_of(family, context)
    payload_object = {
        "schema": SCHEMA_ID,
        "family": family,
        "algorithm": {"id": ALGORITHM_ID, "major": ALGORITHM_MAJOR},
        "subcases": [subcase_object(sub) for sub in subcases],
    }
    payload = jcs(payload_object) + b"\n"
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
        "input_blake3_digest": golden.blake3(payload).hex(),
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

EXPECT_KINDS = {
    "positive": ("result",),
    "denied": ("denied",),
    "malformed": ("metric-error",),
    "resource-exhaustion": ("metric-error", "transport-rejection", "resource-limit"),
    "deletion-redaction": ("result",),
    "downgrade": ("metric-error", "incompatible-contract", "result-rejected"),
    "independent-evaluation": ("result", "generator-check"),
}
STIMULUS_KINDS = {
    "positive": (),
    "denied": ("capability-request", "network-request"),
    "malformed": (),
    "resource-exhaustion": ("oversized-member", "execution-steps"),
    "deletion-redaction": (),
    "downgrade": ("provider-contract",),
    "independent-evaluation": ("recompute", "generator-check"),
}
COORDINATE_PATTERN = (
    "^(input|trailing|magic|version|algorithm_id|algorithm_major|binning|"
    "minimum_scored_records|record_count|records(/(0|[1-9][0-9]*)(/[0-5])?)?)$"
)


def _expect_schemas() -> dict[str, dict]:
    ref = {"$ref": "#/$defs/hex32"}
    error = {
        "type": "object",
        "additionalProperties": False,
        "required": ["kind", "error", "code", "first_coordinate"],
        "properties": {
            "error": {"enum": list(ERRORS)},
            "code": {"type": "integer", "minimum": 0, "maximum": len(ERRORS) - 1},
            "first_coordinate": {"type": "string", "pattern": COORDINATE_PATTERN},
        },
    }
    pin = {
        "type": "object",
        "additionalProperties": False,
        "required": ["field", "exact", "rounded"],
        "properties": {
            "field": {"enum": list(METRIC_NAMES)},
            "exact": {"type": "string", "pattern": "^-?[0-9]+/[1-9][0-9]*$"},
            "rounded": {"type": "integer"},
            "without_floor": {"type": "integer"},
        },
    }
    return {
        "result": {
            "type": "object",
            "additionalProperties": False,
            "required": ["kind", "record", "blake3"],
            "properties": {
                "kind": {"const": "result"},
                "record": {"enum": ["MTR1", "MQR1"]},
                "blake3": ref,
                "pins": {"type": "array", "minItems": 1, "items": pin},
                "absent_marker": {"$ref": "#/$defs/text"},
            },
        },
        "metric-error": _with_kind(error, "metric-error"),
        "result-rejected": _with_kind(error, "result-rejected"),
        "denied": {
            "type": "object",
            "additionalProperties": False,
            "required": ["kind", "code_id", "output"],
            "properties": {
                "kind": {"const": "denied"},
                "code_id": {"const": "capability-denied"},
                "output": {"type": "null"},
            },
        },
        "transport-rejection": {
            "type": "object",
            "additionalProperties": False,
            "required": ["kind", "error"],
            "properties": {
                "kind": {"const": "transport-rejection"},
                "error": {"const": "FieldOutOfBounds"},
            },
        },
        "resource-limit": {
            "type": "object",
            "additionalProperties": False,
            "required": ["kind", "code_id"],
            "properties": {
                "kind": {"const": "resource-limit"},
                "code_id": {"const": "resource-limit"},
            },
        },
        "incompatible-contract": {
            "type": "object",
            "additionalProperties": False,
            "required": ["kind", "code_id"],
            "properties": {
                "kind": {"const": "incompatible-contract"},
                "code_id": {"const": "incompatible-contract"},
            },
        },
        "generator-check": {
            "type": "object",
            "additionalProperties": False,
            "required": ["kind"],
            "properties": {"kind": {"const": "generator-check"}},
        },
    }


def _with_kind(schema: dict, kind: str) -> dict:
    copy = json.loads(json.dumps(schema))
    copy["properties"]["kind"] = {"const": kind}
    return copy


def _stimulus_schemas() -> dict[str, dict]:
    provider = {
        "type": "object",
        "additionalProperties": False,
        "required": ["provider_id", "contract_version"],
        "properties": {
            "provider_id": {"$ref": "#/$defs/text"},
            "contract_version": {"type": "string", "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$"},
        },
    }
    u64 = {"$ref": "#/$defs/u64"}
    return {
        "capability-request": _object(
            {"kind": {"const": "capability-request"}, "capability": {"$ref": "#/$defs/text"}}
        ),
        "network-request": _object(
            {
                "kind": {"const": "network-request"},
                "execution_profile": {"const": "deterministic-air-gapped-v1"},
            }
        ),
        "oversized-member": _object(
            {
                "kind": {"const": "oversized-member"},
                "record": {"const": "MTI1"},
                "bytes": u64,
                "ceiling_bytes": {"const": MAX_MTI1_BYTES},
                "fill": {"const": "zero"},
            }
        ),
        "execution-steps": _object(
            {"kind": {"const": "execution-steps"}, "maximum": u64, "requested": u64}
        ),
        "provider-contract": _object(
            {
                "kind": {"const": "provider-contract"},
                "presented": provider,
                "required": provider,
                "allow_fallback": {"const": False},
            }
        ),
        "recompute": _object(
            {
                "kind": {"const": "recompute"},
                "families": {"type": "array", "minItems": 1, "items": {"enum": list(FAMILIES)}},
            }
        ),
        "generator-check": _object(
            {"kind": {"const": "generator-check"}, "command": {"const": GENERATOR_COMMAND}}
        ),
    }


def _object(properties: dict) -> dict:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(properties),
        "properties": properties,
    }


def family_schema(family: str) -> dict:
    expects = _expect_schemas()
    stimuli = _stimulus_schemas()
    subcase_properties = {
        "id": {"type": "string", "pattern": f"^{ID_PREFIX[family]}\\.[0-9]+[a-z]?$"},
        "title": {"$ref": "#/$defs/text"},
        "member": {"oneOf": [{"$ref": "#/$defs/member"}, {"type": "null"}]},
        "expect": {"oneOf": [{"$ref": f"#/$defs/expect-{kind}"} for kind in EXPECT_KINDS[family]]},
    }
    if STIMULUS_KINDS[family]:
        subcase_properties["stimulus"] = {
            "oneOf": [{"$ref": f"#/$defs/stimulus-{kind}"} for kind in STIMULUS_KINDS[family]]
        }
    defs: dict = {
        "text": {"type": "string", "pattern": "^[ -~]*$"},
        "u64": {"type": "integer", "minimum": 0, "maximum": 9007199254740991},
        "hex32": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "member": {
            "type": "object",
            "additionalProperties": False,
            "required": ["record", "blake3", "bytes"],
            "properties": {
                "record": {"enum": ["MTI1", "MTQ1", "MTR1"]},
                "blake3": {"$ref": "#/$defs/hex32"},
                "bytes": {"type": "integer", "minimum": 1, "maximum": MAX_MTI1_BYTES},
            },
        },
        "subcase": {
            "type": "object",
            "additionalProperties": False,
            "required": ["id", "title", "member", "expect"],
            "properties": subcase_properties,
        },
    }
    for kind in EXPECT_KINDS[family]:
        defs[f"expect-{kind}"] = expects[kind]
    for kind in STIMULUS_KINDS[family]:
        defs[f"stimulus-{kind}"] = stimuli[kind]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"urn:pigloros:metric-conformance:case:v2:{family}",
        "title": f"Metric conformance case payload, family {family}",
        "type": "object",
        "additionalProperties": False,
        "required": ["schema", "family", "algorithm", "subcases"],
        "properties": {
            "schema": {"const": SCHEMA_ID},
            "family": {"const": family},
            "algorithm": {
                "type": "object",
                "additionalProperties": False,
                "required": ["id", "major"],
                "properties": {
                    "id": {"const": ALGORITHM_ID},
                    "major": {"const": ALGORITHM_MAJOR},
                },
            },
            "subcases": {
                "type": "array",
                "minItems": 1,
                "maxItems": 64,
                "items": {"$ref": "#/$defs/subcase"},
            },
        },
        "$defs": defs,
    }


def schema_path(family: str) -> Path:
    return FIXTURES / f"providers/{CLAIM_LAYER}/schemas/{family}.schema.json"


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
    if "oneOf" in schema:
        matching = sum(not schema_errors(value, option, root, where) for option in schema["oneOf"])
        return [] if matching == 1 else [f"{where}: {matching} alternatives match"]
    found: list[str] = []
    if "type" in schema and not _type_ok(value, schema["type"]):
        return [f"{where}: wrong type"]
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


def cbor_decode(data: bytes) -> object:
    """Decode the well-formed deterministic CBOR this generator writes (self-tests only)."""
    value, end = _decode(data, 0)
    if end != len(data):
        raise ValueError("trailing bytes")
    return value


def _decode(data: bytes, pos: int) -> tuple[object, int]:
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
    raise ValueError("unsupported CBOR major type")


def check_blake3_vectors() -> None:
    golden.self_test()
    vectors = json.loads(BLAKE3_VECTORS.read_text(encoding="utf-8"))
    for case in vectors["cases"]:
        data = bytes(index % 251 for index in range(case["input_len"]))
        if golden.blake3(data).hex() != case["hash"][:64]:
            raise SystemExit(f"BLAKE3 hash failed for length {case['input_len']}")


def check_rounding() -> None:
    table = {
        Fraction(5, 2): 2,
        Fraction(7, 2): 4,
        Fraction(-1, 2): 0,
        Fraction(-3, 2): -2,
        Fraction(-5, 2): -2,
        Fraction(1, 3): 0,
        Fraction(-1, 3): 0,
        Fraction(-2, 3): -1,
        Fraction(2, 3): 1,
    }
    for value, wanted in table.items():
        if round_half_even(value) != wanted:
            raise SystemExit(f"round_half_even({value}) is not {wanted}")


def check_worked_example() -> None:
    """The values printed in section 4.3 for `pos.1`."""
    data = worked_example()
    fields = cbor_decode(compute_mtr1(data))
    wanted_metrics = [97500, 97500, 275000, 255625, 158125, 250000, 152500, 375000, 277500]
    wanted_bins = [[0, 0, 0]] * 10
    wanted_bins = [list(row) for row in wanted_bins]
    wanted_bins[2] = [1, 200000, 0]
    wanted_bins[5] = [1, 500000, 0]
    wanted_bins[7] = [1, 700000, 1]
    wanted_bins[9] = [1, 900000, 1]
    if fields[6] != COMPUTED or fields[7] != [5, 4, 1, 0, 0, 0, 2] or fields[9] != 0:
        raise SystemExit("the worked example counts disagree with section 4.3")
    if fields[10] != wanted_metrics:
        raise SystemExit(f"the worked example metrics disagree with section 4.3: {fields[10]}")
    if fields[11] != wanted_bins:
        raise SystemExit("the worked example bins disagree with section 4.3")
    exact = exact_metrics(decode_mti1(data).records)
    if exact.brier != Fraction(39, 400) * D or exact.ece != Fraction(11, 40) * D:
        raise SystemExit("the worked example fractions disagree with section 4.3")
    terms = {"e1": entity_term(3, 2), "e2": entity_term(1, 0)}
    if terms != {"e1": Fraction(3, 2), "e2": Fraction(0)}:
        raise SystemExit("the worked example entity terms disagree with section 4.3")


def definitional_micros(records: tuple[Rec, ...]) -> list[int]:
    """A second computation from the definitions, in probability units: the mean squared
    error, per-bin means, constant predictors and the per-record leave-one-out base rate."""
    s = [(Fraction(r.probability, D), r.outcome, r.entity_id) for r in records if r.state == 0]
    n = len(s)
    brier = sum((p - o) ** 2 for p, o, _ in s) / n
    ece = Fraction(0)
    for k in range(BIN_COUNT):
        members = [
            (p, o) for p, o, _ in s if k * Fraction(1, 10) <= p < (k + 1) * Fraction(1, 10)
            or (k == BIN_COUNT - 1 and p == 1)
        ]
        if members:
            mean_p = sum(p for p, _ in members) / len(members)
            frac = Fraction(sum(o for _, o in members), len(members))
            ece += Fraction(len(members), n) * abs(mean_p - frac)
    mean_p_all = sum(p for p, _, _ in s) / n
    pop = sum((mean_p_all - o) ** 2 for _, o, _ in s) / n
    rate = Fraction(sum(o for _, o, _ in s), n)
    pers = sum((rate - o) ** 2 for _, o, _ in s) / n
    by_entity: dict[str, list[int]] = {}
    for _, o, entity in s:
        by_entity.setdefault(entity, []).append(o)
    floored = 0
    for outcomes in by_entity.values():
        size = len(outcomes)
        term = Fraction(0)
        for index, o in enumerate(outcomes):
            others = outcomes[:index] + outcomes[index + 1 :]
            base = Fraction(sum(others), size - 1) if size >= 2 else Fraction(0)
            term += (base - o) ** 2
        floored += math.floor(term * PBR_SCALE)
    pbr = Fraction(floored, n * PBR_SCALE)
    values = [brier, brier, ece, pop, pop - brier, pers, pers - brier, pbr, pbr - brier]
    return [round_half_even(value * D) for value in values]


def every_subcase() -> list[tuple[str, SubCase]]:
    return [
        (family, sub)
        for family in FAMILIES
        for sub in subcases_of(family, provider_context(family))
    ]


def check_subcases() -> None:
    """Decoder, second computation, quantizer, pins, canary and bounds for every sub-case."""
    for _family, sub in every_subcase():
        expect = sub.expect or {}
        if sub.member is not None and len(sub.member) > MAX_MTI1_BYTES:
            raise SystemExit(f"{sub.id}: the member exceeds the 64 MiB bound")
        if sub.record == "MTI1":
            try:
                metric_input = decode_mti1(sub.member)
            except Failure as failure:
                if expect.get("kind") != "metric-error" or (
                    failure.error,
                    failure.coordinate,
                ) != (expect["error"], expect["first_coordinate"]):
                    raise SystemExit(f"{sub.id}: the decoder reports {failure}") from None
                continue
            if expect.get("kind") == "metric-error":
                raise SystemExit(f"{sub.id}: the decoder accepts a malformed input")
            if expect.get("kind") == "result":
                fields = cbor_decode(sub.result())
                if fields[10] is not None and fields[10] != definitional_micros(
                    metric_input.records
                ):
                    raise SystemExit(f"{sub.id}: the definitional computation disagrees")
                if fields[6] == COMPUTED and fields[10] is None:
                    raise SystemExit(f"{sub.id}: a computed result has no metrics")
                check_pins(sub, metric_input)
                if sub.marker is not None and sub.marker.encode("utf-8") in sub.result():
                    raise SystemExit(f"{sub.id}: the canary appears in MTR1")
        elif sub.record == "MTQ1":
            check_quantization(sub)
        elif sub.record == "MTR1":
            try:
                check_mtr1_header(sub.member)
            except Failure as failure:
                if (failure.error, failure.coordinate) != (
                    expect["error"],
                    expect["first_coordinate"],
                ):
                    raise SystemExit(f"{sub.id}: the result check reports {failure}") from None
            else:
                raise SystemExit(f"{sub.id}: the foreign result is accepted")
    expected_ids = {
        "positive": ["pos.1", "pos.2", "pos.3a", "pos.3b", "pos.3c", "pos.3d", "pos.3e",
                     "pos.4", "pos.5", "pos.6a", "pos.6b", "pos.7", "pos.8a", "pos.8b",
                     "pos.8c"],
    }  # fmt: skip
    ids = [sub.id for sub in positive_subcases()]
    if ids != expected_ids["positive"]:
        raise SystemExit("the positive catalogue changed")
    check_named_cases()


def check_pins(sub: SubCase, metric_input: MetricInput) -> None:
    if not sub.pins and not sub.floor_matters:
        return
    exact = exact_metrics(metric_input.records)
    named = exact_by_name(exact)
    for name in sub.pins:
        if named[name] - math.floor(named[name]) != Fraction(1, 2):
            raise SystemExit(f"{sub.id}: {name} is not a half-way tie")
    if sub.floor_matters:
        with_floor = round_half_even(exact.lift_vs_personal_base_rate)
        without = round_half_even(exact.lift_vs_personal_base_rate_without_floor)
        unfloored = exact.lift_vs_personal_base_rate_without_floor
        if with_floor == without or unfloored - math.floor(unfloored) != Fraction(1, 2):
            raise SystemExit(f"{sub.id}: the 10^-18 floor does not change the rounded lift")


def check_quantization(sub: SubCase) -> None:
    assert sub.patterns is not None
    for bits in sub.patterns:
        value = struct.unpack(">d", bits.to_bytes(8, "big"))[0]
        if math.isnan(value) or math.isinf(value):
            independent = None
        else:
            exact = Fraction(value)
            if exact < 0 or exact > 1:
                independent = None
            else:
                scaled = exact * D
                independent = round(scaled)  # Fraction.__round__ rounds half to even
        if quantize(bits) != independent:
            raise SystemExit(f"{sub.id}: quantization of {bits:016x} disagrees")
    if sub.id == "pos.7":
        wanted = [micros for _bits, micros in PAGE_VECTORS]
        if [quantize(bits) for bits in sub.patterns] != wanted:
            raise SystemExit("pos.7: the vectors disagree with the section 4.4 table")


def check_named_cases() -> None:
    """Values the sub-case titles state."""
    def metrics_of(sub_id: str) -> list | None:
        sub = next(s for _, s in every_subcase() if s.id == sub_id)
        return cbor_decode(sub.result())[10]

    if metrics_of("pos.6a")[0] != 0 or metrics_of("pos.6a")[2] != 0:
        raise SystemExit("pos.6a is not a perfect predictor")
    if metrics_of("pos.6b")[0] != D or metrics_of("pos.6b")[2] != D:
        raise SystemExit("pos.6b is not the worst predictor")
    for sub_id in ("pos.8a", "pos.8b", "pos.8c", "del.2"):
        sub = next(s for _, s in every_subcase() if s.id == sub_id)
        if cbor_decode(sub.result())[6] != INSUFFICIENT_SAMPLES:
            raise SystemExit(f"{sub_id} is not InsufficientSamples")
    states = {
        "del.1a": EVIDENCE_MISSING,
        "del.1b": REDACTED_VIEWS,
        "del.2": REDACTED_VIEWS,
        "del.3": REDACTION_NONE,
    }
    for sub_id, state in states.items():
        sub = next(s for _, s in every_subcase() if s.id == sub_id)
        if cbor_decode(sub.result())[9] != state:
            raise SystemExit(f"{sub_id} has the wrong redaction_state")
    bins_of_pos2 = cbor_decode(next(s for _, s in every_subcase() if s.id == "pos.2").result())[11]
    if [row[0] for row in bins_of_pos2] != [2, 1, 0, 0, 0, 0, 0, 0, 1, 3]:
        raise SystemExit("pos.2 bin assignment disagrees with section 4.3 step 3")


def check_payload_schemas() -> None:
    for family in FAMILIES:
        schema = family_schema(family)
        outputs = render_family(family, provider_context(family))
        errors = schema_errors(json.loads(outputs.payload), schema, schema)
        if errors:
            raise SystemExit(f"the {family} payload violates its schema: {errors[:3]}")


def self_test() -> None:
    check_blake3_vectors()
    check_rounding()
    check_worked_example()
    check_subcases()
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
    return f"inputs/{CLAIM_LAYER}/{family}.mcs1"


def rust_digest_const(name: str, digest: bytes) -> list[str]:
    lines = [f"const {name}: [u8; 32] = ["]
    for start in range(0, 32, 16):
        lines.append("    " + " ".join(f"0x{byte:02x}," for byte in digest[start : start + 16]))
    lines.append("];")
    return lines


def schema_digests_rust() -> str:
    """The subject adapter's pinned digest of each family's schema member (#1217)."""
    constants: list[str] = []
    for family in FAMILIES:
        name = family.upper().replace("-", "_")
        constants.extend(rust_digest_const(name, golden.blake3(jcs(family_schema(family)) + b"\n")))
    names = "".join(f"    {family.upper().replace('-', '_')},\n" for family in FAMILIES)
    header = """\
// @generated by scripts/generate_metric_conformance_fixtures.py; do not edit.

//! The pinned digests of the metric-conformance schema members of the seven families
//! (provider contract 2.0.0, ADR-062 Revision 7 slice 4).
//!
//! The digest of the schema member of an attempt must equal the digest pinned here for its
//! family; a mismatch, such as a schema member of the Draft provider contract 1.0.0, is a
//! non-executed outcome: there is no reader for 1.0.0. The fixture generator writes this file
//! from the checked-in schema members and its `--check` verifies it.

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
