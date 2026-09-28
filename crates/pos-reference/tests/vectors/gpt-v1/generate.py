"""Reproduce selector test GPT images using Python's independent CRC/UUID codecs.

No filesystem, dm-verity or PKCS#7 validity is claimed by these byte fixtures.
UEFI 2.10 chapter 5 defines the headers, entries, protective MBR and CRCs.
"""

import gzip
import hashlib
import json
import struct
import uuid
import zlib
from pathlib import Path

ROOT = Path(__file__).parent
TYPES = [
    "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
    "2c7357ed-ebd2-46d9-aec1-23d437ec2bf5",
    "41092b05-9fc8-4523-994f-2def0408b176",
]


def generate(sector, entry_size):
    count = max(3, 16384 // entry_size)
    table_size = count * entry_size
    start = ((2 * sector + table_size + 65535) // 65536) * 65536
    lengths = [65536, 32768, 4096]
    image_size = ((start + sum(lengths) + table_size + sector + 65535) // 65536) * 65536
    image = bytearray(image_size)
    last = image_size // sector - 1
    table_blocks = (table_size + sector - 1) // sector
    table = bytearray(table_size)
    descriptors = []
    offset = start
    for ordinal, (kind, length) in enumerate(zip(TYPES, lengths, strict=True)):
        instance = uuid.UUID(f"11111111-2222-4333-8444-55555555555{ordinal + 1}")
        kind = uuid.UUID(kind)
        entry = ordinal * entry_size
        table[entry:entry + 16] = kind.bytes_le
        table[entry + 16:entry + 32] = instance.bytes_le
        struct.pack_into("<QQQ", table, entry + 32, offset // sector, (offset + length) // sector - 1, 0)
        image[offset:offset + length] = bytes([ordinal + 1]) * length
        descriptors.append([list(kind.bytes), list(instance.bytes), offset, length])
        offset += length
    # Format marker only; the fixture is deliberately not a mountable filesystem.
    struct.pack_into("<I", image, start + 1024, 0xE0F5E1E2)
    for current, alternate, entries in [(1, last, 2), (last, 1, last - table_blocks)]:
        header = bytearray(sector)
        struct.pack_into("<8sIIIIQQQQ16sQIII", header, 0, b"EFI PART", 0x10000, 92, 0, 0,
                         current, alternate, 2 + table_blocks, last - table_blocks - 1,
                         uuid.UUID("12345678-1234-4234-8234-123456789abc").bytes_le,
                         entries, count, entry_size, zlib.crc32(table))
        struct.pack_into("<I", header, 16, zlib.crc32(header[:92]))
        image[current * sector:(current + 1) * sector] = header
        image[entries * sector:entries * sector + table_size] = table
    image[510:512] = b"\x55\xaa"
    struct.pack_into("<B3sB3sII", image, 446, 0, b"\0\2\0", 0xee, b"\xff\xff\xff", 1, min(last, 0xffffffff))
    name = f"{sector}-{entry_size}"
    (ROOT / f"{name}.img.gz").write_bytes(gzip.compress(image, mtime=0))
    (ROOT / f"{name}.json").write_text(json.dumps(descriptors, separators=(",", ":")) + "\n")
    return f"| {name} | {image_size} | `{hashlib.sha256(image).hexdigest()}` |"


if __name__ == "__main__":
    rows = [generate(sector, entry) for sector, entry in [(512, 128), (1024, 128), (2048, 128), (4096, 128), (512, 256), (512, 131072)]]
    (ROOT / "README.md").write_text("""# GPT admission vectors

Reproduce with `python3 generate.py`. Python's standard-library `struct`,
`uuid`, and `zlib.crc32` produce the GPT bytes independently of the Rust reader.
Gzip is storage compression only; the table records SHA-256 of expanded bytes.
JSON sidecars declare expected partition type/instance UUIDs in canonical byte
order plus byte offsets/lengths. Rust test setup signs SIM1 independently using
those declarations and hashes the declared extents.

These are selector admission fixtures, not filesystem, PKCS#7, dm-verity or
activation evidence. Their EROFS magic is only a marker. The 131072-byte entry
case crosses the reader's 64 KiB buffer and retains zero reserved extensions.

Format sources: [UEFI 2.10 chapter 5](https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html),
[DPS](https://uapi-group.org/specifications/specs/discoverable_partitions_specification/),
and [systemd v260.2 sector probing](https://github.com/systemd/systemd/blob/v260.2/src/shared/dissect-image.c).

| Sector-entry bytes | Image bytes | Expanded SHA-256 |
|---|---:|---|
""" + "\n".join(rows) + "\n")
