#!/usr/bin/env python3
"""Check the #194 handoff READMEs of the community Plugin host (ADR-061 revision 8, #620).

Two READMEs carry pinned sentences, each verbatim and in one piece:

- `crates/pos-plugin-supervisor/README.md`: the ownership of the EAI1/EAO1 subject adapter
  binary and the evidence level of the results (revision 7, #585);
- `apps/pos-plugin-conformance-adapter/README.md`: the same two sentences and the worker
  location sentence (revision 8 decision 14; the third sentence is owner decision O-17).

Line wraps and runs of whitespace between words are ignored; a file may contain other text.
"""

from __future__ import annotations

import argparse
from pathlib import Path

OWNER = "The EAI1/EAO1 subject adapter binary is owned by #194."
EVIDENCE = "Results are Local-relaxation engineering evidence, not hosted conformance."
WORKER = "The pos-plugin-worker binary must be built into the directory of this binary."

SUPERVISOR_README = "crates/pos-plugin-supervisor/README.md"
ADAPTER_README = "apps/pos-plugin-conformance-adapter/README.md"

READMES = {
    SUPERVISOR_README: (OWNER, EVIDENCE),
    ADAPTER_README: (OWNER, EVIDENCE, WORKER),
}


def missing(text: str, sentences: tuple[str, ...]) -> list[str]:
    flat = " ".join(text.split())
    return [sentence for sentence in sentences if sentence not in flat]


def problems(root: Path, readme: str, sentences: tuple[str, ...]) -> list[str]:
    path = root / readme
    if not path.is_file():
        return [f"{readme} does not exist"]
    absent = missing(path.read_text(encoding="utf-8"), sentences)
    return [f"{readme} lacks: {sentence}" for sentence in absent]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    root = parser.parse_args().root.resolve()
    found = [
        problem
        for readme, sentences in READMES.items()
        for problem in problems(root, readme, sentences)
    ]
    if found:
        raise SystemExit("\n".join(found))
    print("both handoff READMEs state the #194 ownership, evidence level and worker location")


if __name__ == "__main__":
    main()
