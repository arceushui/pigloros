"""Canonical uncompressed ustar archives (ADR-127 section 1).

Every header is a function of the member name and size alone: mode `0644`, owner and group 0,
mtime 0, regular-file type `0`, magic `ustar\\0` with version `00`, and NUL in the link name, the
user and group names, the device numbers and the prefix. Member data is NUL-padded to 512 bytes,
and the archive ends with exactly two zero blocks and no record padding.

The RVA1 run-evidence oracle and the Plugin conformance fixtures share this one encoder. It uses
no Rust and no binary of the repository.
"""

from __future__ import annotations

BLOCK = 512
END_MARKER = 2 * BLOCK


def header(name: str, size: int) -> bytes:
    encoded = name.encode("ascii")
    if not 0 < len(encoded) < 100 or b"\0" in encoded:
        raise ValueError("a ustar member name is 1 to 99 NUL-free ASCII bytes")
    block = bytearray(BLOCK)
    block[: len(encoded)] = encoded
    block[100:108] = b"0000644\0"
    block[108:116] = b"0000000\0"
    block[116:124] = b"0000000\0"
    block[124:136] = f"{size:011o}".encode("ascii") + b"\0"
    block[136:148] = b"00000000000\0"
    block[148:156] = b"        "
    block[156:157] = b"0"
    block[257:263] = b"ustar\0"
    block[263:265] = b"00"
    block[148:156] = f"{sum(block):06o}".encode("ascii") + b"\0 "
    return bytes(block)


def archive(members: list[tuple[str, bytes]]) -> bytes:
    """The archive of `members` in the given order."""
    out = bytearray()
    for name, data in members:
        out += header(name, len(data)) + data + bytes(-len(data) % BLOCK)
    return bytes(out + bytes(END_MARKER))


def self_test() -> None:
    # A one-member archive: header, one data block, two zero blocks.
    data = archive([("RVA1", b"\x82dRVA1\x01")])
    if len(data) != 4 * BLOCK or data[BLOCK : BLOCK + 7] != b"\x82dRVA1\x01":
        raise SystemExit("the ustar layout is wrong")
    if data[148:156] != b"006376\0 ":
        raise SystemExit("the ustar checksum is wrong")
