#!/usr/bin/env python3
"""Fixture tests for the handoff README checker (ADR-061 revision 7, #585)."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts/check_handoff_readme.py"
README = "crates/pos-plugin-supervisor/README.md"

OWNER = "The EAI1/EAO1 subject adapter binary is owned by #194."
EVIDENCE = "Results are Local-relaxation engineering evidence, not hosted conformance."

ACCEPTED = {
    "both sentences": f"# Title\n\n{OWNER} {EVIDENCE}\n",
    "other text around them": f"intro\n\n{OWNER}\n\nmiddle\n\n{EVIDENCE}\n\noutro\n",
    "line-wrapped sentences": OWNER.replace(" is ", "\nis ") + "\n" + EVIDENCE.replace(" not ", "\n  not ") + "\n",
}
REJECTED = {
    "empty file": "",
    "ownership only": OWNER + "\n",
    "evidence only": EVIDENCE + "\n",
    "ownership reworded": OWNER.replace("owned by", "owned by the team of") + "\n" + EVIDENCE + "\n",
    "evidence reworded": OWNER + "\n" + EVIDENCE.replace("not hosted", "hosted") + "\n",
    "evidence cased": OWNER + "\n" + EVIDENCE.lower() + "\n",
}


def run(text: str | None) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        if text is not None:
            path = root / README
            path.parent.mkdir(parents=True)
            path.write_text(text, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(CHECKER), "--root", str(root)],
            capture_output=True,
            text=True,
            check=False,
        )


def main() -> None:
    for label, text in ACCEPTED.items():
        result = run(text)
        if result.returncode != 0:
            raise SystemExit(f"{label} was rejected:\n{result.stderr}")
    for label, text in REJECTED.items():
        result = run(text)
        if result.returncode == 0 or README not in result.stderr:
            raise SystemExit(f"{label} was not rejected")
    result = run(None)
    if result.returncode == 0 or "does not exist" not in result.stderr:
        raise SystemExit("a missing README was not rejected")
    real = subprocess.run([sys.executable, str(CHECKER)], capture_output=True, text=True, check=False)
    if real.returncode != 0:
        raise SystemExit(f"the repository README was rejected:\n{real.stderr}")
    print("the handoff README checker rejects every missing sentence")


if __name__ == "__main__":
    main()
