"""Independently describe one systemd-repart SIM1 DDI fixture.

Usage: python3 -I describe.py <x86-64|arm64> <image.raw> <output-directory>

Only the Python standard library is used: struct/zlib for UEFI 2.10 GPT,
hashlib for the dm-verity format-1 hash tree and json/base64 for systemd's
root-verity-sig partition. The script fails unless the image has exactly the
three DPS partitions, the EROFS superblock magic at byte 1024 of the root
partition, a verity tree whose recomputed root hash equals root-hash.txt and a
signature partition embedding exactly proof.der and signer.der's fingerprint.
It writes partitions.json and verity.json; it does not prove activation.
"""

import base64
import hashlib
import json
import struct
import sys
import uuid
import zlib
from pathlib import Path

TYPES = {
    "x86-64": [
        "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
        "2c7357ed-ebd2-46d9-aec1-23d437ec2bf5",
        "41092b05-9fc8-4523-994f-2def0408b176",
    ],
    "arm64": [
        "b921b045-1df0-41c3-af44-4c6f280d3fae",
        "df3300ce-d69f-4c92-978c-9bfb0f38d820",
        "6db69de6-29f4-4758-a7a5-962190f00ce3",
    ],
}
EROFS_MAGIC = 0xE0F5E1E2


def fail(message):
    raise SystemExit(f"describe.py: {message}")


def gpt_entries(image):
    sectors = [size for size in (512, 1024, 2048, 4096) if image[size:size + 8] == b"EFI PART"]
    if len(sectors) != 1:
        fail("expected one GPT sector size")
    sector = sectors[0]
    header = bytearray(image[sector:sector * 2])
    size = struct.unpack_from("<I", header, 12)[0]
    expected = struct.unpack_from("<I", header, 16)[0]
    header[16:20] = b"\0\0\0\0"
    if zlib.crc32(header[:size]) != expected:
        fail("primary header CRC")
    first_entry, count, entry_size, table_crc = struct.unpack_from("<QIII", header, 72)
    table = image[first_entry * sector:first_entry * sector + count * entry_size]
    if zlib.crc32(table) != table_crc:
        fail("partition table CRC")
    entries = []
    for index in range(count):
        entry = table[index * entry_size:(index + 1) * entry_size]
        if entry[:16] == bytes(16):
            continue
        first, last = struct.unpack_from("<QQ", entry, 32)
        entries.append(
            (
                uuid.UUID(bytes_le=entry[:16]),
                uuid.UUID(bytes_le=entry[16:32]),
                first * sector,
                (last - first + 1) * sector,
            )
        )
    return entries


def verity_root(data, hash_partition):
    signature, version, hash_type = struct.unpack_from("<8sII", hash_partition, 0)
    algorithm = hash_partition[32:64].rstrip(b"\0")
    data_block, hash_block, data_blocks, salt_size = struct.unpack_from("<IIQH", hash_partition, 64)
    salt = hash_partition[88:88 + salt_size]
    if signature != b"verity\0\0" or version != 1 or hash_type != 1 or algorithm != b"sha256":
        fail("unsupported verity superblock")
    if data_block != 4096 or hash_block != 4096 or data_blocks * data_block > len(data):
        fail("unexpected verity block geometry")
    level = [
        hashlib.sha256(salt + data[index * data_block:(index + 1) * data_block]).digest()
        for index in range(data_blocks)
    ]
    per_block = hash_block // 32
    # Each level hashes the previous one in zero-padded blocks until one hash
    # remains; a single data block therefore has no stored hash level.
    while len(level) > 1:
        blocks = [
            b"".join(level[start:start + per_block]).ljust(hash_block, b"\0")
            for start in range(0, len(level), per_block)
        ]
        level = [hashlib.sha256(salt + block).digest() for block in blocks]
    return level[0].hex(), salt, data_blocks


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in TYPES:
        fail("usage: describe.py <x86-64|arm64> <image.raw> <output-directory>")
    architecture, image_path, output = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    image = image_path.read_bytes()
    entries = gpt_entries(image)
    expected_types = [uuid.UUID(kind) for kind in TYPES[architecture]]
    if sorted(entry[0] for entry in entries) != sorted(expected_types):
        fail("expected exactly the three DPS root partitions")
    by_type = {entry[0]: entry for entry in entries}
    ordered = [by_type[kind] for kind in expected_types]
    root, verity, signature = [image[start:start + length] for _, _, start, length in ordered]
    if struct.unpack_from("<I", root, 1024)[0] != EROFS_MAGIC:
        fail("root partition is not EROFS")
    root_hash = (output / "root-hash.txt").read_bytes()
    proof = (output / "proof.der").read_bytes()
    certificate = (output / "signer.der").read_bytes()
    recomputed, salt, data_blocks = verity_root(root, verity)
    if recomputed.encode() != root_hash:
        fail("recomputed verity root hash differs from root-hash.txt")
    embedded = json.loads(signature.rstrip(b"\0"))
    if (
        embedded.get("rootHash") != recomputed
        or embedded.get("certificateFingerprint") != hashlib.sha256(certificate).hexdigest()
        or base64.b64decode(embedded.get("signature", ""), validate=True) != proof
    ):
        fail("signature partition does not embed the exact proof")
    (output / "partitions.json").write_text(
        json.dumps(
            [[list(kind.bytes), list(instance.bytes), start, length] for kind, instance, start, length in ordered],
            separators=(",", ":"),
        )
        + "\n"
    )
    (output / "verity.json").write_text(
        json.dumps(
            {
                "data_blocks": data_blocks,
                "image_bytes": len(image),
                "image_sha256": hashlib.sha256(image).hexdigest(),
                "root_hash": recomputed,
                "salt": salt.hex(),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
