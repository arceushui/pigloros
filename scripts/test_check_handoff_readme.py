#!/usr/bin/env python3
"""Fixture tests for the handoff README checker (ADR-061 revision 8, #620)."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts/check_handoff_readme.py"
SUPERVISOR = "crates/pos-plugin-supervisor/README.md"
ADAPTER = "apps/pos-plugin-conformance-adapter/README.md"

OWNER = "The EAI1/EAO1 subject adapter binary is owned by #194."
EVIDENCE = "Results are Local-relaxation engineering evidence, not hosted conformance."
WORKER = "The pos-plugin-worker binary must be built into the directory of this binary."

BOTH = f"# Title\n\n{OWNER} {EVIDENCE}\n"
ALL_THREE = f"# Title\n\n{OWNER} {EVIDENCE} {WORKER}\n"

WRAPPED_OWNER = OWNER.replace(" is ", "\nis ")
WRAPPED_EVIDENCE = EVIDENCE.replace(" not ", "\n  not ")
WRAPPED_WORKER = WORKER.replace(" built ", "\nbuilt ")
REWORDED_OWNER = OWNER.replace("owned by", "owned by the team of")

# Each case is the pair (supervisor README, adapter README); None means no file.
ACCEPTED = {
    "all sentences": (BOTH, ALL_THREE),
    "other text around them": (
        f"intro\n\n{OWNER}\n\nmiddle\n\n{EVIDENCE}\n\noutro\n",
        f"intro\n\n{OWNER}\n\n{EVIDENCE}\n\nmiddle\n\n{WORKER}\n\noutro\n",
    ),
    "line-wrapped sentences": (
        f"{WRAPPED_OWNER}\n{WRAPPED_EVIDENCE}\n",
        f"{WRAPPED_OWNER}\n{WRAPPED_EVIDENCE}\n{WRAPPED_WORKER}\n",
    ),
}
# Each rejected case names the README that the checker must report.
REJECTED = {
    "supervisor empty": ("", ALL_THREE, SUPERVISOR),
    "supervisor ownership only": (OWNER + "\n", ALL_THREE, SUPERVISOR),
    "supervisor evidence only": (EVIDENCE + "\n", ALL_THREE, SUPERVISOR),
    "supervisor ownership reworded": (f"{REWORDED_OWNER}\n{EVIDENCE}\n", ALL_THREE, SUPERVISOR),
    "supervisor evidence cased": (f"{OWNER}\n{EVIDENCE.lower()}\n", ALL_THREE, SUPERVISOR),
    "adapter empty": (BOTH, "", ADAPTER),
    "adapter lacks ownership": (BOTH, f"{EVIDENCE} {WORKER}\n", ADAPTER),
    "adapter lacks evidence": (BOTH, f"{OWNER} {WORKER}\n", ADAPTER),
    "adapter lacks the worker location": (BOTH, BOTH, ADAPTER),
    "adapter ownership reworded": (BOTH, f"{REWORDED_OWNER} {EVIDENCE} {WORKER}\n", ADAPTER),
    "adapter worker reworded": (
        BOTH,
        f"{OWNER} {EVIDENCE} {WORKER.replace('built', 'placed')}\n",
        ADAPTER,
    ),
    "adapter worker cased": (BOTH, f"{OWNER} {EVIDENCE} {WORKER.lower()}\n", ADAPTER),
}


def run(supervisor: str | None, adapter: str | None) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for relative, text in ((SUPERVISOR, supervisor), (ADAPTER, adapter)):
            if text is not None:
                path = root / relative
                path.parent.mkdir(parents=True)
                path.write_text(text, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(CHECKER), "--root", str(root)],
            capture_output=True,
            text=True,
            check=False,
        )


def check_accepted() -> None:
    for label, (supervisor, adapter) in ACCEPTED.items():
        result = run(supervisor, adapter)
        if result.returncode != 0:
            raise SystemExit(f"{label} was rejected:\n{result.stderr}")


def check_rejected() -> None:
    for label, (supervisor, adapter, reported) in REJECTED.items():
        result = run(supervisor, adapter)
        other = ADAPTER if reported == SUPERVISOR else SUPERVISOR
        if result.returncode == 0 or reported not in result.stderr or other in result.stderr:
            raise SystemExit(f"{label} was not rejected as {reported} alone:\n{result.stderr}")


def check_both_reported() -> None:
    result = run("", "")
    if result.returncode == 0 or SUPERVISOR not in result.stderr or ADAPTER not in result.stderr:
        raise SystemExit(f"two failing READMEs were not both reported:\n{result.stderr}")


def check_missing_files() -> None:
    for supervisor, adapter, missing in ((None, ALL_THREE, SUPERVISOR), (BOTH, None, ADAPTER)):
        result = run(supervisor, adapter)
        if result.returncode == 0 or f"{missing} does not exist" not in result.stderr:
            raise SystemExit(f"a missing {missing} was not rejected")


def check_repository() -> None:
    real = subprocess.run(
        [sys.executable, str(CHECKER)],
        capture_output=True,
        text=True,
        check=False,
    )
    if real.returncode != 0:
        raise SystemExit(f"the repository READMEs were rejected:\n{real.stderr}")


def main() -> None:
    check_accepted()
    check_rejected()
    check_both_reported()
    check_missing_files()
    check_repository()
    print("the handoff README checker rejects every missing sentence in both READMEs")


if __name__ == "__main__":
    main()
