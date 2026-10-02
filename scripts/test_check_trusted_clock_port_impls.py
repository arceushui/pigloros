#!/usr/bin/env python3
"""Adversarial tests for the trusted-clock port implementation checker."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts/check_trusted_clock_port_impls.py"

STORE_IMPL = "impl TrustedClockStorePortV1 for Forged {}\n"
GUARD_IMPL = "impl pos_core::trusted_clock::ReleaseGuardPortV1 for Forged {}\n"
GENERIC_IMPL = "impl<'a> ReleaseGuardPortV1\n    for Forged<'a> {}\n"
GATE = '#![cfg(any(test, feature = "test-support"))]\n'

ALLOWED = {
    "crates/pos-store/src/trusted_clock.rs": STORE_IMPL,
    "crates/pos-runtime/src/host.rs": GUARD_IMPL,
    "crates/pos-core/src/trusted_clock_fixture.rs": GATE + STORE_IMPL + GUARD_IMPL,
    "crates/pos-state/src/docs.rs": "// impl ReleaseGuardPortV1 for Forged {}\n",
    "crates/pos-state/src/block.rs": "/* impl TrustedClockStorePortV1 for Forged {} */\n",
    "crates/pos-state/src/uses.rs": "fn f(_: &mut dyn ReleaseGuardPortV1) {}\n",
    "target/debug/build/generated.rs": STORE_IMPL,
}

REJECTED = {
    "crates/pos-state/src/forged.rs": GUARD_IMPL,
    "crates/pos-time/src/forged.rs": STORE_IMPL,
    "crates/pos-core/src/generic.rs": GENERIC_IMPL,
    "crates/pos-core/src/ungated.rs": '#[cfg(feature = "test-support")]\n' + STORE_IMPL,
}


def run(files: dict[str, str]) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for relative, text in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(CHECKER), "--root", str(root)],
            capture_output=True,
            text=True,
            check=False,
        )


def main() -> None:
    accepted = run(ALLOWED)
    if accepted.returncode != 0:
        raise SystemExit(f"allowed layout was rejected:\n{accepted.stderr}")
    for relative, text in REJECTED.items():
        result = run({**ALLOWED, relative: text})
        if result.returncode == 0 or relative not in result.stderr:
            raise SystemExit(f"{relative} was not rejected")
    print("trusted-clock port checker rejects every forged implementation")


if __name__ == "__main__":
    main()
