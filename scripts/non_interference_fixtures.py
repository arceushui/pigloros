"""Shared helpers of the non-interference expected-result oracles (ADR-062 Revision 8 slices
N1-N4; owner notes `ADR-062_R8_NonInterference_Executions` and
`ADR-062_R8_NonInterference_Fork`).

One oracle module per channel group derives the expected NIA1 `result_digest` of its rows
independently (ADR-062 Revision 8, Q3 (a)): no Rust, no cargo and no binary of the repository.
This module holds what every oracle and the evidence binder share:

- the CBOR encoder (as ciborium writes it) and the NIA1 decoder;
- the #181 capture-profile and capture digests and the harness result digest;
- the rows whose verifier-accepted cases may be flipped, read from
  `scripts/non_interference_executed_rows.json`, the one declaration that the fixture verify
  script and the Plugin conformance checker also read;
- the evidence binder: it flips a matrix case to `executed: true` only when its checked-in NIA1
  is content-addressed, names the case, is `equal` and carries exactly the oracle's digest, and
  rebinds the matrix digest, size and executed count in the profile and publication review.

An oracle module exposes `ROWS` (its row ids), `SURFACES` (each row's #181 surface names and
normalization codes), `expected_result_digest(row, variant)` and `self_test()`.
`scripts/generate_non_interference_fixtures.py` plugs every oracle into the binder.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path
from types import ModuleType

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
EXECUTED_ROWS_FILE = HERE / "non_interference_executed_rows.json"

# (matrix letter, serde name, #181 code)
VARIANTS = (("S", "success", 0), ("D", "denial", 1), ("W", "warm_cache", 2), ("C", "cold_cache", 3))
EXECUTABLE_MODES = (("L", "local"), ("R", "replay"), ("F", "fork"))
NORMALIZATION_VERSION = 1
MAX_SURFACE_BYTES = 1024 * 1024

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


# --- Digests ---

Surfaces = tuple[tuple[str, int], ...]


def profile_digest(row: str, surfaces: Surfaces) -> bytes:
    """The #181 capture-profile digest of one row: its surfaces and normalization codes, the
    four variants and the four modes in matrix order."""
    value = append(row.encode())
    for name, code in surfaces:
        value += append(name.encode()) + bytes([code])
    value += bytes([0, 1, 2, 3]) + bytes([0, 1, 2, 3])
    value += NORMALIZATION_VERSION.to_bytes(2, "big") + MAX_SURFACE_BYTES.to_bytes(8, "big")
    return domain_digest(PROFILE_DOMAIN, value)


def capture_digest(domain: bytes, row: str, surfaces: Surfaces, values: list[bytes]) -> bytes:
    value = append(row.encode()) + profile_digest(row, surfaces)
    for (name, _), surface in zip(surfaces, values, strict=True):
        value += append(name.encode()) + append(surface)
    return domain_digest(domain, value)


def result_digest(
    row: str, surfaces: Surfaces, authoritative: list[bytes], public: list[bytes]
) -> bytes:
    """The harness result digest: the control run's authoritative and public capture digests."""
    return b3(
        RESULT_DOMAIN
        + b"\0"
        + capture_digest(b"authoritative", row, surfaces, authoritative)
        + capture_digest(b"public", row, surfaces, public)
    )


# --- The executed rows ---


def executed_rows() -> tuple[str, ...]:
    """The rows whose verifier-accepted L, R and F cases may be flipped."""
    declared = json.loads(EXECUTED_ROWS_FILE.read_text(encoding="utf-8"))
    rows = declared.get("rows")
    if not isinstance(rows, list) or not all(isinstance(row, str) for row in rows):
        raise SystemExit(f"{EXECUTED_ROWS_FILE.name} declares no row list")
    if declared.get("modes") != [letter for letter, _ in EXECUTABLE_MODES]:
        raise SystemExit(f"{EXECUTED_ROWS_FILE.name} declares other modes than L, R and F")
    return tuple(rows)


def oracle_rows(oracles: tuple[ModuleType, ...]) -> dict[str, ModuleType]:
    """Every executed row with the one oracle that derives it. The oracles must cover exactly the
    declared rows."""
    owners: dict[str, ModuleType] = {}
    for oracle in oracles:
        for row in oracle.ROWS:
            if row in owners:
                raise SystemExit(f"{row} has two oracles")
            owners[row] = oracle
    if sorted(owners) != sorted(executed_rows()):
        raise SystemExit("the oracles do not cover exactly the declared executed rows")
    return owners


# --- Evidence ---


def accepted_executions(oracles: tuple[ModuleType, ...]) -> dict[str, dict]:
    """Every checked-in NIA1 by case id. Any file that is not content-addressed, names
    another coordinate, is not equal or carries a different result digest refuses the run."""
    owners = oracle_rows(oracles)
    letters = {name: letter for letter, name, _ in VARIANTS}
    modes = {name: letter for letter, name in EXECUTABLE_MODES}
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
        if row not in owners or variant not in letters or mode not in modes:
            raise SystemExit(f"{path.name} names a coordinate no oracle executes")
        case_id = f"{row}-{letters[variant]}-{modes[mode]}"
        expected = owners[row].expected_result_digest(row, variant)
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


def outputs(accepted: dict[str, dict]) -> dict[Path, bytes]:
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


def self_test() -> None:
    golden.self_test()
