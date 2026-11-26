#!/usr/bin/env python3
"""Add the owner U-tier line observations to the hosted Linux LCOV for the CRAP gate.

ADR-110 E20 LG: the U-tier job runs the Linux hidraw, terminal and uhid tests
against a kernel uhid device and exports its own LCOV. Unlike the Windows shim
that scripts/merge_owner_bridge_lcov.py joins, these observations overlap the
hosted Linux run, so executed-line counts are added to the matching DA records
of crates/pos-owner-ctap/src and nothing else changes. A U-tier source that the
Linux LCOV lacks, a record outside that source tree, a wrong checkout or a
tampered digest is refused; missing observations are never invented.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys

from merge_owner_bridge_lcov import CoverageError, clean_path, records, require

SCOPE = pathlib.PurePosixPath("crates/pos-owner-ctap/src")
RECEIPT_KEYS = {"version", "checkout", "workspace_root", "lcov_sha256"}


def relative(root, filename):
    """The checkout-relative POSIX path of an LCOV source, or None outside the checkout."""
    path = pathlib.PurePosixPath(clean_path(filename))
    if not path.is_absolute():
        return path
    try:
        return path.relative_to(root)
    except ValueError:
        return None


def da_fields(line):
    values = line[3:].split(",")
    return int(values[0]), int(values[1]), values[2:]


def observations(uhid, root):
    """Executed-line counts of each crates/pos-owner-ctap/src source in the U-tier LCOV."""
    _, parsed = records(uhid)
    result = {}
    for filename, record, _ in parsed:
        path = relative(root, filename)
        if path is None or not path.is_relative_to(SCOPE) or path.suffix != ".rs":
            continue
        require(path not in result, "duplicate U-tier coverage source")
        result[path] = {number: hits for number, hits, _ in map(da_fields, filter(lambda l: l.startswith("DA:"), record))}
    require(result, "the U-tier LCOV has no pos-owner-ctap source observations")
    return result


def merge(linux, uhid, receipt, workspace, checkout):
    require(isinstance(receipt, dict) and receipt.keys() == RECEIPT_KEYS, "U-tier LCOV receipt fields changed")
    require(type(receipt["version"]) is int and receipt["version"] == 1, "unsupported U-tier LCOV receipt")
    require(re.fullmatch(r"[0-9a-f]{40}", checkout) is not None and receipt["checkout"] == checkout,
            "U-tier coverage belongs to another checkout")
    require(receipt["lcov_sha256"] == hashlib.sha256(uhid).hexdigest(), "U-tier LCOV digest mismatch")
    root = pathlib.PurePosixPath(clean_path(receipt["workspace_root"]))
    require(root.is_absolute(), "U-tier receipt paths must be absolute")
    added = observations(uhid, root)
    workspace = workspace.resolve()
    _, parsed = records(linux)
    seen, lines_added, lines_unmatched, out = set(), 0, 0, []
    for filename, record, _ in parsed:
        path = relative(pathlib.PurePosixPath(workspace.as_posix()), filename)
        hits = added.get(path) if path is not None else None
        if hits is None:
            out.extend(record)
            continue
        require(path not in seen, "duplicate Linux coverage source")
        seen.add(path)
        target = workspace / path
        require(target.suffix == ".rs" and target.is_file() and target.resolve().is_relative_to(workspace),
                "coverage source is absent from the consumer tree: " + str(path))
        counts = {}
        rewritten = []
        for line in record:
            if line.startswith("DA:"):
                number, count, rest = da_fields(line)
                extra = hits.get(number, 0)
                lines_added += int(number in hits)
                counts[number] = count + extra
                line = "DA:" + ",".join([str(number), str(count + extra), *rest])
            rewritten.append(line)
        lines_unmatched += len(set(hits) - set(counts))
        covered = sum(1 for count in counts.values() if count > 0)
        out.extend(f"LH:{covered}" if line.startswith("LH:") else line for line in rewritten)
    missing = set(added) - seen
    require(not missing, "the Linux LCOV lacks U-tier sources: " + ", ".join(sorted(map(str, missing))))
    return "\n".join(out) + "\n", {"sources": len(seen), "lines_added": lines_added, "lines_unmatched": lines_unmatched}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("linux", "uhid", "receipt", "workspace", "output"):
        parser.add_argument("--" + name, type=pathlib.Path, required=True)
    parser.add_argument("--checkout", required=True)
    args = parser.parse_args()
    try:
        actual = subprocess.run(["git", "-C", str(args.workspace), "rev-parse", "HEAD"],
                                capture_output=True, text=True, check=True).stdout.strip()
        require(actual == args.checkout, "consumer checkout identity mismatch")
        require(args.output.resolve() not in {args.linux.resolve(), args.uhid.resolve(), args.receipt.resolve()},
                "coverage output must not overwrite an input")
        require(not args.output.exists(), "coverage output must be fresh")
        output, summary = merge(args.linux.read_bytes(), args.uhid.read_bytes(),
                                json.loads(args.receipt.read_text(encoding="utf-8-sig")),
                                args.workspace, args.checkout)
        args.output.write_text(output, encoding="utf-8")
        print(json.dumps(summary, sort_keys=True))
    except (CoverageError, OSError, UnicodeError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"owner U-tier LCOV: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
