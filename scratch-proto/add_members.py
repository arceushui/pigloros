#!/usr/bin/env python3
"""THROWAWAY (#471): add prototype crates to the workspace on the CI runner only."""
import sys, pathlib, re
root = pathlib.Path(sys.argv[1])
members = sys.argv[2:]
cargo = root / "Cargo.toml"
s = cargo.read_text()
s = s.replace("members = [\n", "members = [\n" + "".join(f'  "{m}",\n' for m in members), 1)
cargo.write_text(s)
for m in members:
    t = root / m / "Cargo.toml"
    t.write_text(re.sub(r"(?m)^\[workspace\]\s*$", "", t.read_text()))
print("added members:", members)
