"""Throwaway hosted-only reproduction; never run Cargo on the local machine."""

import json
import os
from pathlib import Path
import subprocess
import tempfile

assert os.environ.get("GITHUB_ACTIONS") == "true", "hosted diagnostic only"
EVIDENCE = Path("/tmp/399-shear-evidence")
EVIDENCE.mkdir()


def execute(label, command, cwd):
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    output = result.stdout + result.stderr
    (EVIDENCE / f"{label}.log").write_text(output)
    print(f"[DEBUG-399-SHEAR] {label}: exit={result.returncode}")
    print(output[-6000:])
    return result.returncode, output


code, version = execute("version", ["cargo", "shear", "--version"], Path.cwd())
assert code == 0 and "1.14.0" in version
code, baseline = execute("actual-baseline", ["cargo", "shear", "--deny-warnings"], Path.cwd())
assert code == 1 and "unlinked" in baseline and "tests/support/nonce_ledger_replace.rs" in baseline

FILES = {
    "Cargo.toml": '[package]\nname="shear-path-repro"\nversion="0.1.0"\nedition="2021"\n[features]\ntest-support=[]\n',
    "src/lib.rs": 'pub mod encryptor_lock;\n#[cfg(test)]\n#[path="../tests/support/mod.rs"]\npub mod test_support;\n',
    "src/encryptor_lock.rs": '#![cfg(any(test, feature="test-support"))]\npub mod linux;\n',
    "src/encryptor_lock/linux.rs": '#![cfg(any(test, feature="test-support"))]\nmod nonce_ledger;\n',
    "src/encryptor_lock/linux/nonce_ledger.rs": '#![cfg(any(test, feature="test-support"))]\nmod replace;\n',
    "src/encryptor_lock/linux/nonce_ledger/replace.rs": '#![cfg(any(test, feature="test-support"))]\n#[cfg(test)]\n#[path="../../../../tests/support/nonce_ledger_replace.rs"]\nmod tests;\n',
    "tests/support/nonce_ledger_replace.rs": '#![cfg(any(test, feature="test-support"))]\n#[test]\nfn linked_probe() {}\n',
    "tests/support/mod.rs": 'pub fn fixture() {}\n',
    "tests/driver.rs": 'pub mod support;\n#[test]\nfn public_probe() { support::fixture(); }\n',
}
with tempfile.TemporaryDirectory(prefix="399-shear-") as temporary:
    root = Path(temporary)
    for name, content in FILES.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    (EVIDENCE / "fixture-source.json").write_text(json.dumps(FILES, indent=2))
    code, rust = execute("fixture-rust", ["cargo", "test", "--quiet", "--features", "test-support", "--", "--list"], root)
    assert code == 0 and "encryptor_lock::linux::nonce_ledger::replace::tests::linked_probe: test" in rust
    code, shear = execute("fixture-shear", ["cargo", "shear", "--deny-warnings"], root)
    observed = code == 1 and "unlinked" in shear and "tests/support/nonce_ledger_replace.rs" in shear
    (EVIDENCE / "verdict.json").write_text(json.dumps({"rust_links_and_lists_test": True, "shear_false_unlinked_reproduced": observed}, indent=2))
    assert observed, "minimal fixture did not reproduce the same unlinked-file finding"
