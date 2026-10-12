#!/usr/bin/env python3
"""Adversarial tests for the fixture evaluation instant confinement checker."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts/check_fixture_instant_confinement.py"

FIXTURE = 'pos-core = { path = "../pos-core", features = ["fixture-instant"] }\n'
ADMISSION = 'pos-runtime = { path = "../pos-runtime", features = ["local-admission-host"] }\n'
ADAPTER = 'pos-plugin-conformance-adapter = { path = "../pos-plugin-conformance-adapter" }\n'
NAMES = "use pos_core::trusted_clock::{FixtureEvaluationInstantV1, FixtureWallSourceV1};\n"

ADAPTER_MANIFEST = "apps/pos-plugin-conformance-adapter/Cargo.toml"
WORKER_MANIFEST = "apps/pos-plugin-worker/Cargo.toml"

ALLOWED_MANIFESTS = {
    "crates/pos-core/Cargo.toml": '[features]\nfixture-instant = []\ntest-support = []\n'
    + 'default = ["test-support"]\n',
    ADAPTER_MANIFEST: "[dependencies]\n"
    + FIXTURE
    + ADMISSION
    + '[features]\nfixture-instant = ["pos-core/fixture-instant"]\n'
    + 'admission = ["pos-runtime/local-admission-host"]\n',
    "apps/pos-experiment/Cargo.toml": "[dependencies]\n" + ADMISSION,
    "crates/pos-runtime/Cargo.toml": '[features]\nlocal-admission-host = []\n'
    + 'test-support = ["local-admission-host", "pos-core/test-support"]\n',
    "crates/pos-store/Cargo.toml": "[features]\n"
    + 'test-support = ["pos-runtime/local-admission-host"]\n',
    WORKER_MANIFEST: "[dev-dependencies]\n" + ADAPTER,
}

ALLOWED_SOURCES = {
    "crates/pos-core/src/trusted_clock.rs": "pub struct FixtureWallSourceV1;\n"
    + "pub struct FixtureEvaluationInstantV1;\n",
    "crates/pos-core/tests/trusted_clock_public.rs": NAMES,
    "apps/pos-plugin-conformance-adapter/src/lib.rs": NAMES,
    "apps/pos-plugin-conformance-adapter/tests/sealed.rs": NAMES,
    "crates/pos-core/src/lib.rs": "pub mod trusted_clock;\n"
    + "// FixtureWallSourceV1 is reached through the module.\n"
    + "pub use trusted_clock::{wall_time_from_epoch_duration, TrustedWallSourceV1};\n",
    "apps/pos-plugin-worker/tests/end_to_end.rs": "use pos_plugin_conformance_adapter::run;\n",
    "crates/pos-store/src/lib.rs": "/* FixtureEvaluationInstantV1 */ pub fn f() {}\n",
}

FEATURE_ENABLED = "enables fixture-instant"
FEATURE_FORWARDED = "forwards fixture-instant"
DEFAULT_ENABLES = "default feature enables fixture-instant"
DEFAULT_FORWARDS = "default feature forwards fixture-instant"
ADAPTER_DEPENDENT = "depends on the conformance adapter"
ADMISSION_ENABLED = "enables local-admission-host"
ADMISSION_FORWARDED = "forwards local-admission-host"
OUTSIDE = "names the fixture evaluation instant types outside their owners"
GLOB = "glob re-exports trusted_clock"

# Extra trees that must pass, each on top of the allowed tree.
EXTRA_ALLOWED = {
    "test-support forwarding in another crate": (
        "crates/pos-plugin-supervisor/Cargo.toml",
        '[features]\ntest-support = ["pos-runtime/local-admission-host"]\n',
    ),
    "glob over another module": (
        "crates/pos-core/src/lib.rs",
        "pub use clock::*;\npub use trusted_clock_fixture::*;\n",
    ),
}

REJECTED_MANIFESTS = {
    "inherited dependency with features": (
        "crates/pos-store/Cargo.toml",
        '[dependencies]\npos-core = { workspace = true, features = ["fixture-instant"] }\n',
        FEATURE_ENABLED,
    ),
    "table-form dependency": (
        "crates/pos-store/Cargo.toml",
        '[dependencies.pos-core]\npath = "../pos-core"\nfeatures = ["fixture-instant"]\n',
        FEATURE_ENABLED,
    ),
    "same-name forwarding in another crate": (
        "crates/pos-store/Cargo.toml",
        '[features]\nfixture-instant = ["pos-core/fixture-instant"]\n',
        FEATURE_FORWARDED,
    ),
    "test-support feature forwarding the fixture instant": (
        "crates/pos-store/Cargo.toml",
        '[features]\ntest-support = ["pos-core/fixture-instant"]\n',
        FEATURE_FORWARDED,
    ),
    "adapter named in workspace dependencies": (
        "Cargo.toml",
        "[workspace.dependencies]\n" + ADAPTER,
        ADAPTER_DEPENDENT,
    ),
    "dependency of another crate": (
        "crates/pos-store/Cargo.toml",
        "[dependencies]\n" + FIXTURE,
        FEATURE_ENABLED,
    ),
    "build dependency": (
        "crates/pos-store/Cargo.toml",
        "[build-dependencies]\n" + FIXTURE,
        FEATURE_ENABLED,
    ),
    "dev dependency of another crate": (
        "crates/pos-store/Cargo.toml",
        "[dev-dependencies]\n" + FIXTURE,
        FEATURE_ENABLED,
    ),
    "target dependency": (
        "crates/pos-store/Cargo.toml",
        "[target.'cfg(unix)'.dependencies]\n" + FIXTURE,
        FEATURE_ENABLED,
    ),
    "workspace dependency": (
        "Cargo.toml",
        "[workspace.dependencies]\n"
        + 'pos-core = { path = "crates/pos-core", features = ["fixture-instant"] }\n',
        FEATURE_ENABLED,
    ),
    "adapter dev dependency": (ADAPTER_MANIFEST, "[dev-dependencies]\n" + FIXTURE, FEATURE_ENABLED),
    "adapter target dependency": (
        ADAPTER_MANIFEST,
        "[target.'cfg(unix)'.dependencies]\n" + FIXTURE,
        FEATURE_ENABLED,
    ),
    "forwarding feature of another name": (
        "crates/pos-store/Cargo.toml",
        '[features]\nadapters = ["pos-core/fixture-instant"]\n',
        FEATURE_FORWARDED,
    ),
    "optional forwarding feature": (
        "crates/pos-store/Cargo.toml",
        '[features]\nadapters = ["pos-core?/fixture-instant"]\n',
        FEATURE_FORWARDED,
    ),
    "adapter forwarding feature of another name": (
        ADAPTER_MANIFEST,
        '[features]\nfixture = ["pos-core/fixture-instant"]\n',
        FEATURE_FORWARDED,
    ),
    "default closure": (
        "crates/pos-core/Cargo.toml",
        '[features]\ndefault = ["extras"]\nextras = ["fixture-instant"]\nfixture-instant = []\n',
        DEFAULT_ENABLES,
    ),
    "default forwarding": (
        "crates/pos-store/Cargo.toml",
        '[features]\ndefault = ["pos-core/fixture-instant"]\n',
        DEFAULT_FORWARDS,
    ),
    "library depending on the adapter": (
        "crates/pos-plugin-supervisor/Cargo.toml",
        "[dependencies]\n" + ADAPTER,
        ADAPTER_DEPENDENT,
    ),
    "library dev-depending on the adapter": (
        "crates/pos-plugin-supervisor/Cargo.toml",
        "[dev-dependencies]\n" + ADAPTER,
        ADAPTER_DEPENDENT,
    ),
    "renamed adapter dependency": (
        "crates/pos-plugin-supervisor/Cargo.toml",
        '[dependencies]\nadapter = { package = "pos-plugin-conformance-adapter", version = "0" }\n',
        ADAPTER_DEPENDENT,
    ),
    "adapter by path": (
        "crates/pos-plugin-supervisor/Cargo.toml",
        '[dependencies]\nadapter = { path = "../../apps/pos-plugin-conformance-adapter" }\n',
        ADAPTER_DEPENDENT,
    ),
    "worker normal dependency": (WORKER_MANIFEST, "[dependencies]\n" + ADAPTER, ADAPTER_DEPENDENT),
    "worker build dependency": (
        WORKER_MANIFEST,
        "[build-dependencies]\n" + ADAPTER,
        ADAPTER_DEPENDENT,
    ),
    "admission dependency of another crate": (
        "crates/pos-store/Cargo.toml",
        "[dependencies]\n" + ADMISSION,
        ADMISSION_ENABLED,
    ),
    "admission dev dependency": (
        "crates/pos-store/Cargo.toml",
        "[dev-dependencies]\n" + ADMISSION,
        ADMISSION_ENABLED,
    ),
    "admission workspace dependency": (
        "Cargo.toml",
        "[workspace.dependencies]\n"
        + 'pos-runtime = { path = "crates/pos-runtime", features = ["local-admission-host"] }\n',
        ADMISSION_ENABLED,
    ),
    "admission forwarded by another feature": (
        "crates/pos-store/Cargo.toml",
        '[features]\nadmission = ["pos-runtime/local-admission-host"]\n',
        ADMISSION_FORWARDED,
    ),
    "admission listed by another local feature": (
        "crates/pos-runtime/Cargo.toml",
        '[features]\nlocal-admission-host = []\nhost = ["local-admission-host"]\n',
        ADMISSION_FORWARDED,
    ),
}

REJECTED_SOURCES = {
    "another crate source": ("crates/pos-store/src/lib.rs", NAMES, OUTSIDE),
    "another crate tests": ("crates/pos-store/tests/clock.rs", NAMES, OUTSIDE),
    "another pos-core source": ("crates/pos-core/src/other.rs", NAMES, OUTSIDE),
    "pos-core lib": (
        "crates/pos-core/src/lib.rs",
        "pub use trusted_clock::FixtureWallSourceV1;\n",
        OUTSIDE,
    ),
    "pos-core lib braces": (
        "crates/pos-core/src/lib.rs",
        "pub use trusted_clock::{\n    FixtureEvaluationInstantV1,\n    TrustedWallSourceV1,\n};\n",
        OUTSIDE,
    ),
    "pos-core lib glob": ("crates/pos-core/src/lib.rs", "pub use trusted_clock::*;\n", GLOB),
    "pos-core lib self glob": (
        "crates/pos-core/src/lib.rs",
        "pub use self::trusted_clock::*;\n",
        GLOB,
    ),
    "pos-core lib braced glob": (
        "crates/pos-core/src/lib.rs",
        "pub use trusted_clock::{*};\n",
        GLOB,
    ),
    "pos-core lib self and glob": (
        "crates/pos-core/src/lib.rs",
        "pub use trusted_clock::{self, *};\n",
        GLOB,
    ),
    "pos-core lib crate glob": (
        "crates/pos-core/src/lib.rs",
        "pub use crate::trusted_clock::*;\n",
        GLOB,
    ),
    "worker tests": ("apps/pos-plugin-worker/tests/end_to_end.rs", NAMES, OUTSIDE),
    "worker source": ("apps/pos-plugin-worker/src/main.rs", NAMES, OUTSIDE),
    "other app": ("apps/pos-experiment/src/main.rs", NAMES, OUTSIDE),
    "adapter-like directory": (
        "apps/pos-plugin-conformance-adapter-x/src/lib.rs",
        NAMES,
        OUTSIDE,
    ),
    "adapter build script": ("apps/pos-plugin-conformance-adapter/build.rs", NAMES, OUTSIDE),
    "trusted clock prefix": ("crates/pos-core/src/trusted_clock_fixture.rs", NAMES, OUTSIDE),
}


def invoke(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--root", str(root)],
        check=False,
        capture_output=True,
        text=True,
    )


def with_files(files: dict[str, str]) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        ignored = {
            "target/debug/Cargo.toml": "[dependencies]\n" + FIXTURE,
            "target/debug/build.rs": NAMES,
        }
        for relative, text in {**ignored, **files}.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return invoke(root)


def expect_rejected(case: str, result: subprocess.CompletedProcess[str], reason: str) -> None:
    if result.returncode == 0:
        raise SystemExit(f"checker accepted {case}")
    if reason not in result.stderr:
        raise SystemExit(f"checker rejected {case} without {reason!r}:\n{result.stderr}")


def main() -> None:
    repository = invoke(ROOT)
    if repository.returncode != 0:
        raise SystemExit(f"repository violates policy:\n{repository.stderr}")
    allowed_files = {**ALLOWED_MANIFESTS, **ALLOWED_SOURCES}
    allowed = with_files(allowed_files)
    if allowed.returncode != 0:
        raise SystemExit(f"checker rejected an allowed use:\n{allowed.stderr}")
    for case, (relative, text) in EXTRA_ALLOWED.items():
        result = with_files({**allowed_files, relative: text})
        if result.returncode != 0:
            raise SystemExit(f"checker rejected {case}:\n{result.stderr}")
    for case, (relative, text, reason) in REJECTED_MANIFESTS.items():
        result = with_files({**allowed_files, relative: text})
        expect_rejected(f"a {case}", result, reason)
    for case, (relative, text, reason) in REJECTED_SOURCES.items():
        result = with_files({**allowed_files, relative: text})
        expect_rejected(f"the fixture types in {case}", result, reason)


if __name__ == "__main__":
    main()
