"""The NI-ARCHIVE-009 non-interference oracle (ADR-062 Revision 8 slice N1b, #1284; ADR-127).

This oracle derives the expected NIA1 `result_digest` of every executed NI-ARCHIVE-009 case
(modes L, R and F) independently (ADR-062 Revision 8, Q3 (a)). It uses no Rust, no cargo and no
binary of the repository. Every surface is rebuilt from the accepted ADR-127 contract and the
capture contract in `apps/pos-experiment/src/non_interference_harness/g_archive.rs`:
- the G-PUB subject's Events (`generate_non_interference_g_pub_fixtures.py`), imported into a
  fresh root `Live` Timeline without owner, so every entity ordinal is 0 and no Event names a
  cause or a correlation. The subject's signals come from the first two permitted-input bytes
  only, and every variant's permitted input starts with `g-`; so S, W and C share one result
  digest by design (as in N1), and D differs only through its refused-import probe;
- the RVA1 members: the marker `["RVA1", 1]`, one `events/<seq>.cbor` record per Event and the
  Timeline record, in bytewise name order, written by the shared canonical ustar encoder
  (`ustar.py`);
- the six surfaces of an admitted import, and for the `denial` variant the second import
  refused with `DigestMismatch`.
The digests then follow the #181 capture profile and the harness result domain
(`non_interference_fixtures.py`). In `self_test` the archive is also read with the standard
library's `tarfile`, as an interoperability check, not as the oracle.
"""

from __future__ import annotations

import io
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import generate_non_interference_g_pub_fixtures as g_pub  # noqa: E402
import ustar  # noqa: E402
from non_interference_fixtures import b3, cbor, result_digest  # noqa: E402

ARCHIVE = "NI-ARCHIVE-009"
ROWS = (ARCHIVE,)
# The #181 capture profile of the row (ADR-059 surface order; ByteExact = 5).
SURFACES = {
    ARCHIVE: (
        ("Member table", 5),
        ("archive bytes", 5),
        ("decompressed bundle", 5),
        ("digest", 5),
        ("evaluator import", 5),
        ("logs", 5),
    ),
}

MARKER = ["RVA1", 1]
LIVE = 1
MEMBER_MODE = 0o644


def members(variant: str) -> list[tuple[str, bytes]]:
    """The RVA1 members of the subject's export, in bytewise name order."""
    events = g_pub.subject_events(g_pub.permitted_input(ARCHIVE, variant))
    out = [("RVA1", cbor(MARKER))]
    for seq, dimension, value in events:
        payload = g_pub.signal_payload(dimension, value)
        record = [seq, 0, g_pub.EVENT_TYPE, 1, None, None, payload, b3(payload)]
        out.append((f"events/{seq:020}.cbor", cbor(record)))
    out.append(("timeline.cbor", cbor([LIVE, g_pub.SUBJECT_TIMELINE, None, len(events)])))
    return out


def surfaces(variant: str) -> tuple[list[bytes], list[bytes]]:
    entries = members(variant)
    archive = ustar.archive(entries)
    digest = b3(archive)
    table = cbor([[name, MEMBER_MODE, len(data), b3(data)] for name, data in entries])
    bundle = cbor([[name, data] for name, data in entries])
    digests = cbor([digest, [b3(data) for _, data in entries]])
    outcomes = [["admitted", 1, len(entries)]]
    logs = [["write", "ok", len(entries), len(archive)], ["import", "admitted"]]
    if variant == "denial":
        outcomes.append(["refused", "DigestMismatch"])
        logs.append(["import", "DigestMismatch"])
    imports = cbor(outcomes)
    import_public = cbor([outcomes, digest])
    log_bytes = cbor(logs)
    return (
        [table, bundle, bundle, table, imports, log_bytes],
        [table, archive, bundle, digests, import_public, log_bytes],
    )


def expected_result_digest(row: str, variant: str) -> bytes:
    authoritative, public = surfaces(variant)
    return result_digest(row, SURFACES[row], authoritative, public)


def self_test() -> None:
    ustar.self_test()
    entries = members("success")
    names = [name for name, _ in entries]
    if names != sorted(names, key=str.encode) or len(names) != 2 + g_pub.TICKS * 2:
        raise SystemExit("the RVA1 members are wrong")
    if cbor(MARKER) != b"\x82dRVA1\x01":
        raise SystemExit("the RVA1 marker encoding is wrong")
    archive = ustar.archive(entries)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as reader:
        listed = [(info.name, info.size, info.mode, info.mtime) for info in reader.getmembers()]
        read = [reader.extractfile(info).read() for info in reader.getmembers()]
    if listed != [(name, len(data), MEMBER_MODE, 0) for name, data in entries]:
        raise SystemExit("tarfile lists another member table")
    if read != [data for _, data in entries]:
        raise SystemExit("tarfile reads other member bytes")
    if len(archive) % 512 or archive[-1024:] != bytes(1024):
        raise SystemExit("the RVA1 end marker is wrong")
