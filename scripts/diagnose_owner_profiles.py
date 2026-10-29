"""Temporary metadata-only probe for the hosted llvm-profdata merge crash."""

import json
import os
from pathlib import Path

root = Path("target/llvm-cov-target")
records = []
for path in sorted(root.rglob("*.profraw")):
    stat = path.stat()
    record = {
        "path": str(path),
        "mode": oct(stat.st_mode & 0o7777),
        "uid": stat.st_uid,
        "size": stat.st_size,
        "readable": os.access(path, os.R_OK),
    }
    try:
        with path.open("rb") as stream:
            record["header_hex"] = stream.read(64).hex()
    except OSError as error:
        record["read_error"] = str(error)
    records.append(record)
result = {"euid": os.geteuid(), "profiles": records}
Path("/tmp/owner-profile-metadata.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
