#!/usr/bin/env python3
"""Check the #194 handoff README of the community Plugin supervisor (ADR-061 revision 7, #585).

`crates/pos-plugin-supervisor/README.md` must contain, verbatim and each in one piece, the two
sentences that state the ownership of the EAI1/EAO1 subject adapter binary and the evidence
level of the results. Line wraps and runs of whitespace between words are ignored; the file may
contain other text.
"""

from __future__ import annotations

import argparse
from pathlib import Path

README = "crates/pos-plugin-supervisor/README.md"
SENTENCES = (
    "The EAI1/EAO1 subject adapter binary is owned by #194.",
    "Results are Local-relaxation engineering evidence, not hosted conformance.",
)


def missing(text: str) -> list[str]:
    flat = " ".join(text.split())
    return [sentence for sentence in SENTENCES if sentence not in flat]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    path = parser.parse_args().root.resolve() / README
    if not path.is_file():
        raise SystemExit(f"{README} does not exist")
    absent = missing(path.read_text(encoding="utf-8"))
    if absent:
        raise SystemExit("\n".join(f"{README} lacks: {sentence}" for sentence in absent))
    print("the handoff README states the #194 ownership and the evidence level")


if __name__ == "__main__":
    main()
