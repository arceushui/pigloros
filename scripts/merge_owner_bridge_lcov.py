#!/usr/bin/env python3
"""Join disjoint hosted Linux/Windows observations for the CRAP gate.

Only Windows SF paths are relocated to the consumer checkout. Executed-line
counts are preserved; missing observations are never invented or made green.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys


SHIM = pathlib.PurePosixPath("crates/pos-owner-bridge-windows")
RECEIPT_KEYS = {"version", "checkout", "workspace_root", "target_directory",
                "cargo_home", "rustup_home", "lcov_sha256"}


class CoverageError(ValueError):
    """Coverage cannot be bound unambiguously to this source checkout."""


def require(condition, message):
    if not condition:
        raise CoverageError(message)


def clean_path(value):
    require(isinstance(value, str) and value and not any(c in value for c in "\0\r\n"),
            "coverage paths must be nonempty text without control characters")
    value = value.replace("\\", "/")
    require(".." not in value.split("/"), "coverage path traverses parents")
    return value


def windows_path(value):
    path = pathlib.PureWindowsPath(clean_path(value))
    require(path.is_absolute(), "native receipt paths must be absolute")
    return path


def records(data):
    """Validate consumed LCOV fields while preserving every record's counters."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError as error:
        raise CoverageError("LCOV must be UTF-8") from error
    require("\0" not in text, "LCOV contains NUL")
    result, pending, current, source, lines = [], [], None, None, set()
    for line in text.splitlines():
        if line.startswith("SF:"):
            require(current is None, "unterminated LCOV source record")
            source = clean_path(line[3:])
            current = pending + [line]
            pending, lines = [], set()
        elif line == "end_of_record":
            require(current is not None, "LCOV terminator has no source")
            current.append(line)
            result.append((source, current, len(lines)))
            current = None
        elif current is None:
            require(not line or line.startswith("TN:"), "LCOV data has no source")
            pending.append(line)
        else:
            if line.startswith("DA:"):
                values = line[3:].split(",")
                require(len(values) in (2, 3) and all(re.fullmatch(r"[0-9]+", v) for v in values[:2]),
                        "invalid LCOV line/count")
                number, hits = map(int, values[:2])
                require(0 < number <= 0xFFFF_FFFF and hits <= 0xFFFF_FFFF_FFFF_FFFF,
                        "LCOV line/count is out of range")
                require(number not in lines, "duplicate LCOV line counter")
                lines.add(number)
            current.append(line)
    require(current is None and not any(pending), "incomplete LCOV record")
    require(result, "LCOV contains no source records")
    return text, result


def source_path(workspace, relative):
    path = workspace / pathlib.PurePosixPath(relative)
    require(path.suffix == ".rs" and path.is_file(), f"coverage source is absent from the consumer tree: {relative}")
    require(path.resolve().is_relative_to(workspace), "coverage source resolves outside the checkout")
    return path


def merge(linux, native, receipt, workspace, checkout):
    require(isinstance(receipt, dict) and receipt.keys() == RECEIPT_KEYS,
            "native LCOV receipt fields changed")
    require(type(receipt["version"]) is int and receipt["version"] == 1,
            "unsupported native LCOV receipt")
    require(re.fullmatch(r"[0-9a-f]{40}", checkout) is not None and receipt["checkout"] == checkout,
            "native coverage belongs to another checkout")
    require(receipt["lcov_sha256"] == hashlib.sha256(native).hexdigest(), "native LCOV digest mismatch")
    workspace = workspace.resolve()
    native_root = windows_path(receipt["workspace_root"])
    ignored = [windows_path(receipt[key]) for key in ("target_directory", "cargo_home", "rustup_home")]
    shim_root = native_root / str(SHIM)
    linux_text, linux_records = records(linux)
    _, native_records = records(native)
    seen = set()
    for filename, _, _ in linux_records:
        path = pathlib.PurePosixPath(clean_path(filename))
        try:
            relative = path.relative_to(workspace) if path.is_absolute() else path
        except ValueError as error:
            raise CoverageError("Linux coverage is outside the checkout") from error
        require(not relative.is_relative_to(SHIM), "Linux LCOV unexpectedly contains Windows shim observations")
        source_path(workspace, relative)
        require(relative not in seen, "duplicate Linux coverage source")
        seen.add(relative)
    appended, native_seen, counts, omitted = [], set(), {"safe": 0, "ffi": 0}, 0
    for filename, record, opportunities in native_records:
        # rustc embeds this virtual source prefix independently of drive roots.
        if re.match(r"^/rustc/[0-9a-f]+/library/", filename):
            omitted += 1
            continue
        path = windows_path(filename)
        # llvm-cov may anchor that same virtual prefix at the workspace root.
        if path.is_relative_to(native_root) and re.match(
                r"^rustc/[0-9a-f]{40}/library/", path.relative_to(native_root).as_posix()):
            omitted += 1
            continue
        if path.is_relative_to(shim_root / "src"):
            relative = pathlib.PurePosixPath(path.relative_to(native_root).as_posix())
            target = source_path(workspace, relative)
            require(relative not in seen and relative not in native_seen, "duplicate or overlapping native coverage source")
            native_seen.add(relative)
            group = "ffi" if relative.is_relative_to(SHIM / "src/ffi") else "safe"
            counts[group] += opportunities
            appended.extend("SF:" + str(target) if line.startswith("SF:") else line for line in record)
        elif path.is_relative_to(shim_root / "tests") or any(path.is_relative_to(root) for root in ignored):
            # Integration-test executables and toolchain/dependency sources are
            # outside this Windows production/src slice. Their counters are
            # counted here, never substituted for another package's coverage.
            omitted += 1
        else:
            raise CoverageError(f"native LCOV contains an unexpected source root: {filename}")
    require(all(count > 0 for count in counts.values()), "both native safe/ffi scopes must have measured lines")
    output = linux_text + ("" if linux_text.endswith("\n") else "\n") + "\n".join(appended) + "\n"
    return output, {"native_sources": len(native_seen), "native_lines": counts,
                    "omitted_non_src_records": omitted}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("linux", "native", "receipt", "workspace", "output"):
        parser.add_argument("--" + name, type=pathlib.Path, required=True)
    parser.add_argument("--checkout", required=True)
    args = parser.parse_args()
    try:
        actual = subprocess.run(["git", "-C", str(args.workspace), "rev-parse", "HEAD"],
                                capture_output=True, text=True, check=True).stdout.strip()
        require(actual == args.checkout, "consumer checkout identity mismatch")
        require(args.output.resolve() not in {args.linux.resolve(), args.native.resolve(), args.receipt.resolve()},
                "coverage output must not overwrite an input")
        require(not args.output.exists(), "coverage output must be fresh")
        output, summary = merge(args.linux.read_bytes(), args.native.read_bytes(),
                                json.loads(args.receipt.read_text(encoding="utf-8-sig")),
                                args.workspace, args.checkout)
        args.output.write_text(output, encoding="utf-8")
        print(json.dumps(summary, sort_keys=True))
    except (CoverageError, OSError, UnicodeError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"owner-bridge LCOV: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
