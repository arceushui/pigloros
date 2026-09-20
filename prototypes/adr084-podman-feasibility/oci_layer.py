#!/usr/bin/env python3
"""Bounded OCI gzip-layer hashing for the ADR-084 throwaway prototype."""

from __future__ import annotations

import hashlib
import io
import zlib
from typing import BinaryIO

MAX_UNCOMPRESSED_LAYER_BYTES = 268_435_456
MAX_UNCOMPRESSED_TOTAL_BYTES = 1_073_741_824
_CHUNK_BYTES = 65_536


def diff_id(stream: BinaryIO, cumulative_bytes: int) -> tuple[bytes, int]:
    """Hash one exact gzip member while enforcing revision-19 byte ceilings."""
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    digest = hashlib.sha256()
    layer_bytes = 0
    try:
        while compressed := stream.read(_CHUNK_BYTES):
            pending = compressed
            while pending:
                output_limit = min(
                    _CHUNK_BYTES,
                    MAX_UNCOMPRESSED_LAYER_BYTES - layer_bytes + 1,
                    MAX_UNCOMPRESSED_TOTAL_BYTES - cumulative_bytes - layer_bytes + 1,
                )
                output = decompressor.decompress(pending, output_limit)
                pending = decompressor.unconsumed_tail
                layer_bytes += len(output)
                if layer_bytes > MAX_UNCOMPRESSED_LAYER_BYTES:
                    raise ValueError("layer exceeds uncompressed byte ceiling")
                if cumulative_bytes + layer_bytes > MAX_UNCOMPRESSED_TOTAL_BYTES:
                    raise ValueError("layers exceed cumulative uncompressed byte ceiling")
                digest.update(output)
                if decompressor.eof:
                    if decompressor.unused_data or pending or stream.read(1):
                        raise ValueError("gzip layer has a second member or trailing bytes")
                    return digest.digest(), cumulative_bytes + layer_bytes
    except zlib.error as error:
        raise ValueError("invalid gzip layer") from error
    raise ValueError("truncated gzip layer")


def diff_id_bytes(content: bytes, cumulative_bytes: int) -> tuple[bytes, int]:
    """Apply ``diff_id`` to in-memory fixture bytes."""
    return diff_id(io.BytesIO(content), cumulative_bytes)
