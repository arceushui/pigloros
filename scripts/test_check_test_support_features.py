#!/usr/bin/env python3
"""Adversarial tests for the test-support feature policy checker."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts/check_test_support_features.py"

ALLOWED = """
[features]
test-support = ["pos-runtime/test-support"]

[dependencies]
pos-runtime = { path = "../pos-runtime" }

[dev-dependencies]
pos-runtime = { path = "../pos-runtime", features = ["test-support"] }
"""

REJECTED = {
    "dependency": """
[dependencies]
pos-runtime = { path = "../pos-runtime", features = ["test-support"] }
""",
    "build dependency": """
[build-dependencies]
pos-runtime = { path = "../pos-runtime", features = ["test-support"] }
""",
    "target dependency": """
[target.'cfg(target_os = "linux")'.dependencies]
pos-runtime = { path = "../pos-runtime", features = ["test-support"] }
""",
    "workspace dependency": """
[workspace.dependencies]
pos-runtime = { path = "crates/pos-runtime", features = ["test-support"] }
""",
    "default feature": """
[features]
default = ["test-support"]
test-support = []
""",
    "transitive default feature": """
[features]
default = ["foo"]
foo = ["bar"]
bar = ["test-support"]
test-support = []
""",
    "renamed forwarding feature": """
[features]
fixtures = ["pos-runtime/test-support"]
""",
}


def invoke(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--root", str(root)],
        check=False,
        capture_output=True,
        text=True,
    )


def with_manifest(text: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        manifest = root / "apps/fixture/Cargo.toml"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(text, encoding="utf-8")
        ignored = root / "target/debug/Cargo.toml"
        ignored.parent.mkdir(parents=True)
        ignored.write_text(REJECTED["dependency"], encoding="utf-8")
        return invoke(root)


def main() -> None:
    repository = invoke(ROOT)
    if repository.returncode != 0:
        raise SystemExit(f"repository violates policy:\n{repository.stderr}")
    allowed = with_manifest(ALLOWED)
    if allowed.returncode != 0:
        raise SystemExit(f"checker rejected dev-only enablement:\n{allowed.stderr}")
    for case, text in REJECTED.items():
        if with_manifest(text).returncode == 0:
            raise SystemExit(f"checker accepted {case} enabling test-support")


if __name__ == "__main__":
    main()
