#!/usr/bin/env python3
"""Derive a second valid, conformance-only SCS1 for concurrency evidence."""

from __future__ import annotations

import argparse
import pathlib
import subprocess

import cbor2


DOMAIN = b"PiglorOS.SCS1.v1\0"
ADDED_NAME = "cachestat"


def blake3(value: bytes) -> bytes:
    completed = subprocess.run(
        ["b3sum", "--raw"], input=value, check=True, capture_output=True
    )
    if len(completed.stdout) != 32:
        raise ValueError("b3sum returned a non-256-bit digest")
    return completed.stdout


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    arguments = parser.parse_args()
    original = arguments.input.read_bytes()
    value = cbor2.loads(original)
    if cbor2.dumps(value, canonical=True) != original:
        raise ValueError("source SCS1 is not preferred deterministic CBOR")
    if not isinstance(value, list) or len(value) != 2:
        raise ValueError("source SCS1 outer shape mismatch")
    unsigned, original_digest = value
    if (
        not isinstance(unsigned, list)
        or len(unsigned) != 5
        or unsigned[:2] != ["SCS1", 1]
        or not isinstance(unsigned[3], list)
        or not isinstance(unsigned[4], list)
        or not isinstance(original_digest, bytes)
    ):
        raise ValueError("source SCS1 shape mismatch")
    encoded_unsigned = cbor2.dumps(unsigned, canonical=True)
    if original_digest != blake3(DOMAIN + encoded_unsigned):
        raise ValueError("source SCS1 self-digest mismatch")
    if ADDED_NAME in unsigned[3] or ADDED_NAME in unsigned[4]:
        raise ValueError("derived SCS1 addition is already present")
    derived_unsigned = [
        *unsigned[:3],
        sorted([*unsigned[3], ADDED_NAME]),
        sorted([*unsigned[4], ADDED_NAME]),
    ]
    derived_encoded = cbor2.dumps(derived_unsigned, canonical=True)
    derived_digest = blake3(DOMAIN + derived_encoded)
    output = cbor2.dumps([derived_unsigned, derived_digest], canonical=True)
    if output == original:
        raise AssertionError("derived SCS1 did not change")
    arguments.output.write_bytes(output)


if __name__ == "__main__":
    main()
