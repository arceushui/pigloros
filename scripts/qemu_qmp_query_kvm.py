#!/usr/bin/env python3
"""Ask a running QEMU which accelerator it uses (ADR-069 R13 section 2.3).

One QMP exchange over QEMU's Unix socket: the greeting, `qmp_capabilities`
(whose reply must be an empty `return`), then `query-kvm`, whose reply is
printed as JSON. Asynchronous events are skipped. The connect is retried
while the socket does not exist yet, and only while QEMU is still running.

Usage: qemu_qmp_query_kvm.py SOCKET QEMU_PID
"""

from __future__ import annotations

import json
import socket
import sys
import time


ATTEMPTS = 60
INTERVAL = 0.5
TIMEOUT = 10.0


class QmpError(RuntimeError):
    """QEMU did not answer the exchange as QMP requires."""


def running(pid: int) -> bool:
    """True while the process exists and is not a zombie."""
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii", errors="replace") as stat:
            state = stat.read().rsplit(")", 1)[1].split()[0]
    except (OSError, IndexError):
        return False
    return state not in ("Z", "X")


def connect(path: str, pid: int, attempts: int = ATTEMPTS, interval: float = INTERVAL) -> socket.socket:
    for _ in range(attempts):
        client = socket.socket(socket.AF_UNIX)
        client.settimeout(TIMEOUT)
        try:
            client.connect(path)
            return client
        except (FileNotFoundError, ConnectionRefusedError):
            client.close()
        if not running(pid):
            raise QmpError("QEMU exited before its QMP socket accepted a connection")
        time.sleep(interval)
    raise QmpError("QMP socket never accepted a connection")


def query_kvm(client: socket.socket) -> dict:
    stream = client.makefile("rw", encoding="utf-8")

    def reply() -> dict:
        while True:
            line = stream.readline()
            if not line:
                raise QmpError("QEMU closed the QMP connection")
            message = json.loads(line)
            if not isinstance(message, dict):
                raise QmpError(f"QMP sent a non-object: {line!r}")
            if "event" not in message:
                return message

    if "QMP" not in reply():
        raise QmpError("QMP greeting missing")
    answers = []
    for command in ("qmp_capabilities", "query-kvm"):
        stream.write(json.dumps({"execute": command}) + "\n")
        stream.flush()
        answers.append(reply())
    if answers[0] != {"return": {}}:
        raise QmpError(f"qmp_capabilities was refused: {answers[0]}")
    return answers[1]


def main(argv: list[str]) -> int:
    if len(argv) != 2 or not argv[1].isdigit():
        print(__doc__.rsplit("Usage: ", 1)[1].strip(), file=sys.stderr)
        return 2
    try:
        with connect(argv[0], int(argv[1])) as client:
            answer = query_kvm(client)
    except (QmpError, OSError, ValueError) as error:
        print(f"qmp: {error}", file=sys.stderr)
        return 1
    print(json.dumps(answer, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
