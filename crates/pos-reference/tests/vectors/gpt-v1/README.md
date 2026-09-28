# GPT admission vectors

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
| 512-128 | 196608 | `54ed0e97b96bfbde07eded098d5fc69f83fa3565070e139a314f89181bfd0687` |
| 1024-128 | 196608 | `e4034959ee66ccf2b1efd72c63b3b5ab52c45bb476c23bec10f88615db3bee9f` |
| 2048-128 | 196608 | `1416b88e96b909151cb04fdaaf4c34aaa3677fe6df515ddd8037594c3e6b8340` |
| 4096-128 | 196608 | `29f6e99718030ea2fe7f83f8e59dfd9bb4dc5b4d486a9c82b2b6a459b568a92d` |
| 512-256 | 196608 | `120992188bd0b3bbb183eb59b9fdfb5e03e7b4701302ab6d284f57d41d5287f6` |
| 512-131072 | 983040 | `983089438d8d44b0e368996532d90715c94aea923bd44401c7ce99a5a22c4db4` |
