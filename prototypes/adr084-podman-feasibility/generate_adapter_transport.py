#!/usr/bin/env python3
"""Generate narrow canonical EAI1/EAO1 vectors for the throwaway adapter."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess

import cbor2


ATTEMPT_DOMAIN = b"PiglorOS.EvaluatorAttemptStream.v1\0"
OBSERVATION_DOMAIN = b"PiglorOS.EvaluatorObservationStream.v1\0"


def digest(value: bytes) -> bytes:
    result = subprocess.run(
        ["b3sum", "--raw"], input=value, check=True, capture_output=True
    ).stdout
    if len(result) != 32:
        raise ValueError("b3sum returned a non-256-bit digest")
    return result


def frame(value: object) -> bytes:
    encoded = cbor2.dumps(value, canonical=True)
    return len(encoded).to_bytes(4, "big") + encoded


def attempt(payload: bytes) -> bytes:
    schema = b"opaque-schema-v1"
    framed = [
        frame(
            [
                "EAI1",
                1,
                "adr084-probe",
                0,
                0,
                0,
                digest(b"adr084-fixture"),
                [67108864, 1000, 1000, 1000, 65536, 65536, 1000, 1000000000],
                1000,
                False,
                0,
                2,
                65536,
                131072,
            ]
        ),
        frame(["EIM1", 1, 0, 0, len(schema), digest(schema), 1]),
        frame(["EIB1", 1, 0, 0, 0, schema]),
        frame(["EIM1", 1, 1, 0, len(payload), digest(payload), 1]),
        frame(["EIB1", 1, 1, 0, 0, payload]),
    ]
    transcript = digest(ATTEMPT_DOMAIN + b"".join(framed))
    return b"".join(framed) + frame(["EIE1", 1, transcript])


def observation(output: bytes) -> bytes:
    framed = [frame(["EAO1", 1]), frame(["EOB1", 1, 0, output])]
    transcript = digest(OBSERVATION_DOMAIN + b"".join(framed))
    return b"".join(framed) + frame(
        ["EOE1", 1, 0, len(output), digest(output), None, None, [0] * 8, transcript]
    )


def c_array(name: str, value: bytes) -> str:
    octets = ", ".join(f"0x{octet:02x}" for octet in value)
    return (
        f"static const unsigned char {name}[] = {{{octets}}};\n"
        f"static const size_t {name}_len = sizeof({name});\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=pathlib.Path)
    arguments = parser.parse_args()
    arguments.output.mkdir(parents=True, exist_ok=True)

    vectors = {
        "eai1_hello": attempt(b"hello\n"),
        "eai1_hold": attempt(b"HOLD\n"),
        "eai1_memory": attempt(b"MEMORY\n"),
        "eai1_memory_limit": attempt(b"MEMORY_LIMIT\n"),
        "eai1_tasks": attempt(b"TASKS\n"),
        "eai1_cpu": attempt(b"CPU\n"),
        "eai1_file": attempt(b"FILE\n"),
        "eai1_work": attempt(b"WORK\n"),
        "eai1_watchdog": attempt(b"WATCHDOG\n"),
        "eao1_hello": observation(b"hello\n"),
    }
    if any(
        left != right and value.startswith(vectors[right])
        for left, value in vectors.items()
        for right in vectors
    ):
        raise ValueError("an adapter transport vector is a prefix of another")
    for name, value in vectors.items():
        (arguments.output / f"{name}.bin").write_bytes(value)
    (arguments.output / "adapter_transport_vectors.h").write_text(
        "#ifndef ADAPTER_TRANSPORT_VECTORS_H\n"
        "#define ADAPTER_TRANSPORT_VECTORS_H\n"
        "#include <stddef.h>\n"
        + "".join(c_array(name, value) for name, value in vectors.items())
        + "#endif\n",
        encoding="ascii",
    )
    (arguments.output / "adapter-transport-vectors.json").write_text(
        json.dumps(
            {
                name: {
                    "bytes": len(value),
                    "sha256": hashlib.sha256(value).hexdigest(),
                }
                for name, value in vectors.items()
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
