#!/usr/bin/env python3
"""Check current documentation for the community Plugin conformance adapter.

Two READMEs carry pinned sentences, each verbatim and in one piece:

- `crates/pos-plugin-supervisor/README.md`: the adapter path and the evidence level of results;
- `apps/pos-plugin-conformance-adapter/README.md`: the same path and evidence statements, plus
  the worker location needed to run the adapter.

Line wraps and runs of whitespace between words are ignored; a file may contain other text.
"""

from __future__ import annotations

import argparse
from pathlib import Path

ADAPTER_SENTENCE = "The EAI1/EAO1 subject adapter is `apps/pos-plugin-conformance-adapter`."
EVIDENCE = "Results are Local-relaxation engineering evidence, not hosted conformance."
WORKER = "The pos-plugin-worker binary must be built into the directory of this binary."

SUPERVISOR_README = "crates/pos-plugin-supervisor/README.md"
ADAPTER_README = "apps/pos-plugin-conformance-adapter/README.md"

READMES = {
    SUPERVISOR_README: (ADAPTER_SENTENCE, EVIDENCE),
    ADAPTER_README: (ADAPTER_SENTENCE, EVIDENCE, WORKER),
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
    print("both Plugin READMEs state the adapter path and evidence level")


if __name__ == "__main__":
    main()
