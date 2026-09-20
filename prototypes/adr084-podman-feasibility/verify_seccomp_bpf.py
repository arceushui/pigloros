#!/usr/bin/env python3
"""Independently prove the exported classic-BPF syscall decision domain."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct

import z3


ALLOW = 0x7FFF0000
ERRNO_4094 = 0x00050000 | 4094
KILL = 0
AUDIT_ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}


def instructions(raw: bytes) -> list[tuple[int, int, int, int]]:
    if not raw or len(raw) % 8 != 0:
        raise ValueError("exported BPF is not a nonempty sock_filter array")
    result = [struct.unpack_from("=HBBI", raw, offset) for offset in range(0, len(raw), 8)]
    if len(result) > 4096:
        raise ValueError("exported BPF exceeds the kernel instruction limit")
    return result


def load_value(offset: int, nr: z3.BitVecRef, arch: z3.BitVecRef) -> z3.BitVecRef:
    if offset == 0:
        return nr
    if offset == 4:
        return arch
    raise ValueError(f"unexpected seccomp_data load offset: {offset}")


def enumerate_paths(
    program: list[tuple[int, int, int, int]],
    nr: z3.BitVecRef,
    arch: z3.BitVecRef,
) -> list[tuple[z3.BoolRef, z3.BitVecRef]]:
    pending: list[tuple[int, z3.BitVecRef, z3.BitVecRef, z3.BoolRef]] = [
        (0, z3.BitVecVal(0, 32), z3.BitVecVal(0, 32), z3.BoolVal(True))
    ]
    completed: list[tuple[z3.BoolRef, z3.BitVecRef]] = []
    steps = 0
    while pending:
        pc, accumulator, index, condition = pending.pop()
        steps += 1
        if steps > len(program) * len(program) * 4:
            raise ValueError("BPF control flow is cyclic or unexpectedly large")
        if pc < 0 or pc >= len(program):
            raise ValueError("BPF jump leaves the program")
        code, jump_true, jump_false, constant = program[pc]
        instruction_class = code & 0x07
        if instruction_class == 0x00:
            if code != 0x20:
                raise ValueError(f"unsupported BPF load opcode: {code:#x}")
            pending.append((pc + 1, load_value(constant, nr, arch), index, condition))
            continue
        if instruction_class == 0x04:
            source = index if code & 0x08 else z3.BitVecVal(constant, 32)
            operation = code & 0xF0
            operations = {
                0x00: lambda: accumulator + source,
                0x10: lambda: accumulator - source,
                0x20: lambda: accumulator * source,
                0x40: lambda: accumulator | source,
                0x50: lambda: accumulator & source,
                0x60: lambda: accumulator << source,
                0x70: lambda: z3.LShR(accumulator, source),
                0xA0: lambda: accumulator ^ source,
            }
            if operation == 0x80:
                value = -accumulator
            elif operation in operations:
                value = operations[operation]()
            else:
                raise ValueError(f"unsupported BPF ALU opcode: {code:#x}")
            pending.append((pc + 1, value, index, condition))
            continue
        if instruction_class == 0x05:
            operation = code & 0xF0
            if operation == 0x00:
                pending.append((pc + 1 + constant, accumulator, index, condition))
                continue
            source = index if code & 0x08 else z3.BitVecVal(constant, 32)
            predicates = {
                0x10: accumulator == source,
                0x20: z3.UGT(accumulator, source),
                0x30: z3.UGE(accumulator, source),
                0x40: accumulator & source != 0,
            }
            if operation not in predicates:
                raise ValueError(f"unsupported BPF jump opcode: {code:#x}")
            predicate = predicates[operation]
            pending.append(
                (pc + 1 + jump_true, accumulator, index, z3.And(condition, predicate))
            )
            pending.append(
                (pc + 1 + jump_false, accumulator, index, z3.And(condition, z3.Not(predicate)))
            )
            continue
        if instruction_class == 0x06:
            value = accumulator if code & 0x10 else z3.BitVecVal(constant, 32)
            completed.append((condition, value))
            continue
        if instruction_class == 0x07:
            operation = code & 0xF8
            if operation == 0x00:
                pending.append((pc + 1, accumulator, accumulator, condition))
            elif operation == 0x80:
                pending.append((pc + 1, index, index, condition))
            else:
                raise ValueError(f"unsupported BPF misc opcode: {code:#x}")
            continue
        raise ValueError(f"unsupported BPF instruction class: {code:#x}")
    return completed


def parse_interface(path: Path) -> tuple[set[int], list[str]]:
    allowed: set[int] = set()
    pnr: list[str] = []
    for line in path.read_text(encoding="ascii").splitlines():
        number, name = line.split(":", 1)
        if number == "PNR":
            pnr.append(name)
        else:
            value = int(number)
            if value in allowed:
                raise ValueError("interface contains duplicate numeric value")
            allowed.add(value)
    if not allowed:
        raise ValueError("interface contains no numeric rules")
    return allowed, pnr


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--architecture", choices=AUDIT_ARCH, required=True)
    parser.add_argument("--bpf", type=Path, required=True)
    parser.add_argument("--interface", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--base64", type=Path, required=True)
    arguments = parser.parse_args()
    raw = arguments.bpf.read_bytes()
    program = instructions(raw)
    allowed, pnr = parse_interface(arguments.interface)
    nr = z3.BitVec("nr", 32)
    arch = z3.BitVec("arch", 32)
    paths = enumerate_paths(program, nr, arch)
    native = z3.BitVecVal(AUDIT_ARCH[arguments.architecture], 32)
    is_allowed = z3.Or([nr == z3.BitVecVal(value, 32) for value in sorted(allowed)])
    expected_native = z3.If(
        is_allowed, z3.BitVecVal(ALLOW, 32), z3.BitVecVal(ERRNO_4094, 32)
    )
    solver = z3.Solver()
    for condition, result in paths:
        solver.push()
        solver.add(condition, arch == native, result != expected_native)
        if solver.check() != z3.unsat:
            raise AssertionError(f"native BPF mismatch: {solver.model()}")
        solver.pop()
        solver.push()
        solver.add(condition, arch != native, result != z3.BitVecVal(KILL, 32))
        if solver.check() != z3.unsat:
            raise AssertionError(f"foreign-architecture BPF mismatch: {solver.model()}")
        solver.pop()
    solver.add(z3.Not(z3.Or([condition for condition, _ in paths])))
    if solver.check() != z3.unsat:
        raise AssertionError(f"BPF has an uncovered input: {solver.model()}")
    encoded = base64.b64encode(raw)
    if base64.b64decode(encoded, validate=True) != raw:
        raise AssertionError("canonical base64 did not round-trip")
    arguments.base64.write_bytes(encoded)
    report = {
        "architecture": arguments.architecture,
        "bpf_sha256": hashlib.sha256(raw).hexdigest(),
        "byte_length": len(raw),
        "instruction_count": len(program),
        "numeric_allow_count": len(allowed),
        "path_count": len(paths),
        "pnr_no_rule": pnr,
        "proof": "all unsigned-32-bit native syscall numbers exact; every foreign architecture killed",
    }
    arguments.report.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
