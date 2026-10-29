"""Throwaway hosted-only reproduction; never run Cargo on the local machine."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import posixpath
import re
import textwrap

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

# Phase 2: remove the second test-root tree, then shorten the private module
# chain one level at a time. Each case still has a real Rust-discovered test.
minimized = []
for depth in [4, 3, 2, 1, 0]:
    names = ["a", "b", "c", "d"][:depth]
    files = {"Cargo.toml": FILES["Cargo.toml"],
             "tests/support/nonce_ledger_replace.rs": FILES["tests/support/nonce_ledger_replace.rs"]}
    files["src/lib.rs"] = "mod a;\n" if depth else ''
    chain = ["src/" + "/".join(names[:i]) + ("/" if i else "") + name + ".rs" for i, name in enumerate(names)]
    for i, path in enumerate(chain):
        files[path] = '#![cfg(any(test, feature="test-support"))]\n'
        if i + 1 < depth:
            files[path] += "mod " + names[i + 1] + ";\n"
    last = chain[-1] if chain else "src/lib.rs"
    files[last] += '#[cfg(test)]\n#[path="' + "../" * max(1, depth) + 'tests/support/nonce_ledger_replace.rs"]\nmod tests;\n'
    with tempfile.TemporaryDirectory(prefix="399-shear-min-") as temporary:
        root = Path(temporary)
        for name, content in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        label = f"depth-{depth}"
        (EVIDENCE / f"{label}-source.json").write_text(json.dumps(files, indent=2))
        code, rust = execute(label + "-rust", ["cargo", "test", "--quiet", "--features", "test-support", "--", "--list"], root)
        expected = "::".join(names + ["tests", "linked_probe"]) + ": test"
        assert code == 0 and expected in rust
        code, shear = execute(label + "-shear", ["cargo", "shear", "--deny-warnings"], root)
        observed = code == 1 and "unlinked" in shear and "tests/support/nonce_ledger_replace.rs" in shear
        minimized.append({"depth": depth, "rust_links": True, "false_unlinked": observed})
(EVIDENCE / "minimized.json").write_text(json.dumps(minimized, indent=2))

# Keep the original module names, visibility and path fixed while removing
# one additional source-root link at a time.
root_cases = {}
without_alias = dict(FILES)
without_alias["src/lib.rs"] = "pub mod encryptor_lock;\n"
root_cases["without-root-alias"] = without_alias
without_driver = dict(FILES)
del without_driver["tests/driver.rs"]
root_cases["without-driver"] = without_driver
without_either = dict(without_alias)
del without_either["tests/driver.rs"]
del without_either["tests/support/mod.rs"]
root_cases["without-either"] = without_either
roots = []
for label, files in root_cases.items():
    with tempfile.TemporaryDirectory(prefix="399-shear-roots-") as temporary:
        root = Path(temporary)
        for name, content in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        (EVIDENCE / f"{label}-source.json").write_text(json.dumps(files, indent=2))
        code, rust = execute(label + "-rust", ["cargo", "test", "--quiet", "--features", "test-support", "--", "--list"], root)
        assert code == 0 and "encryptor_lock::linux::nonce_ledger::replace::tests::linked_probe: test" in rust
        code, shear = execute(label + "-shear", ["cargo", "shear", "--deny-warnings"], root)
        observed = code == 1 and "unlinked" in shear and "tests/support/nonce_ledger_replace.rs" in shear
        roots.append({"case": label, "rust_links": True, "false_unlinked": observed})
(EVIDENCE / "root-cases.json").write_text(json.dumps(roots, indent=2))

# Phase 4: one variable per prediction, keeping the Rust-discovered witness.
predictions = {}
separate = dict(FILES)
separate["tests/private/nonce_ledger_replace.rs"] = separate.pop("tests/support/nonce_ledger_replace.rs")
key = "src/encryptor_lock/linux/nonce_ledger/replace.rs"
separate[key] = separate[key].replace("tests/support/nonce_ledger_replace.rs", "tests/private/nonce_ledger_replace.rs")
predictions["separate-private-folder"] = (separate, "encryptor_lock::linux::nonce_ledger::replace::tests::linked_probe: test", "tests/private/nonce_ledger_replace.rs")
shallow = dict(FILES)
for name in list(shallow):
    if name.startswith("src/encryptor_lock"):
        del shallow[name]
shallow["src/lib.rs"] = '#[cfg(test)]\n#[path="../tests/support/nonce_ledger_replace.rs"]\nmod tests;\n'
predictions["root-level-include"] = (shallow, "tests::linked_probe: test", "tests/support/nonce_ledger_replace.rs")
feature = dict(FILES)
feature[key] = feature[key].replace("#[cfg(test)]", '#[cfg(feature="test-support")]')
predictions["feature-gate"] = (feature, "encryptor_lock::linux::nonce_ledger::replace::tests::linked_probe: test", "tests/support/nonce_ledger_replace.rs")
results = []
for label, (files, expected, target) in predictions.items():
    with tempfile.TemporaryDirectory(prefix="399-shear-prediction-") as temporary:
        root = Path(temporary)
        for name, content in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        (EVIDENCE / f"{label}-source.json").write_text(json.dumps(files, indent=2))
        code, rust = execute(label + "-rust", ["cargo", "test", "--quiet", "--features", "test-support", "--", "--list"], root)
        assert code == 0 and expected in rust
        code, shear = execute(label + "-shear", ["cargo", "shear", "--deny-warnings"], root)
        results.append({"case": label, "rust_links": True, "exit": code, "false_unlinked": code == 1 and "unlinked" in shear and target in shear})
(EVIDENCE / "predictions.json").write_text(json.dumps(results, indent=2))

# Verify the proposed ownership layout at the real repository boundary, then
# restore its exact bytes and reproduce the original finding once more.
repo = Path.cwd()
declaration = repo / "crates/pos-owner-bridge/src/encryptor_lock/linux/nonce_ledger/replace.rs"
previous = repo / "crates/pos-owner-bridge/tests/support/nonce_ledger_replace.rs"
candidate = repo / "crates/pos-owner-bridge/tests/private/nonce_ledger_replace.rs"
original_declaration = declaration.read_bytes()
original_witness = previous.read_bytes()
assert not candidate.exists()
candidate.parent.mkdir()
try:
    previous.rename(candidate)
    text = original_declaration.decode()
    assert text.count("tests/support/nonce_ledger_replace.rs") == 1
    declaration.write_text(text.replace("tests/support/nonce_ledger_replace.rs", "tests/private/nonce_ledger_replace.rs"))
    code, result = execute("actual-candidate-shear", ["cargo", "shear", "--deny-warnings"], repo)
    candidate_passes = code == 0
finally:
    if candidate.exists():
        candidate.rename(previous)
    declaration.write_bytes(original_declaration)
    candidate.parent.rmdir()
assert declaration.read_bytes() == original_declaration and previous.read_bytes() == original_witness
code, result = execute("actual-restored-shear", ["cargo", "shear", "--deny-warnings"], repo)
assert code == 1 and "unlinked" in result and "tests/support/nonce_ledger_replace.rs" in result
(EVIDENCE / "real-boundary.json").write_text(json.dumps({"candidate_shear_passes": candidate_passes, "restored_baseline_fails_again": True}, indent=2))

# Fourth, source-backed prediction: use ordinary adjacent module discovery and
# preserve an explicit inline cfg(test) boundary for the complexity visitor.
adjacent = repo / "crates/pos-owner-bridge/src/encryptor_lock/linux/nonce_ledger/replace/tests.rs"
assert not adjacent.exists()
adjacent.parent.mkdir()
try:
    lines = original_witness.decode().splitlines(keepends=True)
    header = "".join(lines[:2])
    body = "".join(lines[2:]).lstrip("\n")
    assert body.count("use super::super::{remove_opened_temporary, FILE_FLAGS};") == 1
    body = body.replace("use super::super::{remove_opened_temporary, FILE_FLAGS};", "use super::super::super::{remove_opened_temporary, FILE_FLAGS};")
    assert body.count("use super::{CommitStage, SubjectEncryptorLock, LEDGER_NAME, TEMPORARY_NAME};") == 1
    body = body.replace("use super::{CommitStage, SubjectEncryptorLock, LEDGER_NAME, TEMPORARY_NAME};", "use super::super::{CommitStage, SubjectEncryptorLock, LEDGER_NAME, TEMPORARY_NAME};")
    assert body.count("nonce_ledger::replace::tests::crash_probe") == 1
    body = body.replace("nonce_ledger::replace::tests::crash_probe", "nonce_ledger::replace::tests::cases::crash_probe")
    body += '''

#[test]
fn a_duplicate_descriptor_defers_ledger_unlock_after_commit() -> TestResult {
    let (_root, guard) = prepare()?;
    let staged = super::super::StagedLedger::open(&guard.directory)?;
    let duplicate = rustix::io::fcntl_dupfd_cloexec(&staged.file, 0)?;
    staged.commit(&image(13)?, |_| Ok(()))?;
    assert_eq!(
        guard.replace_nonce_ledger_bytes(&image(14)?),
        Err(BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable))
    );
    drop(duplicate);
    guard.replace_nonce_ledger_bytes(&image(14)?)?;
    assert_eq!(guard.read_nonce_ledger_bytes()?, image(14)?);
    Ok(())
}
'''
    adjacent.write_text(header + "\n#[cfg(test)]\nmod cases {\n" + textwrap.indent(body, "    ") + "}\n")
    previous.unlink()
    text = original_declaration.decode()
    attribute = '#[path = "../../../../tests/support/nonce_ledger_replace.rs"]\n'
    assert text.count(attribute) == 1
    declaration.write_text(text.replace(attribute, ""))
    code, output = execute("combo-format", ["rustfmt", "--edition", "2021", str(declaration), str(adjacent)], repo)
    assert code == 0
    code, output = execute("combo-source-gate", ["python3", "scripts/check_subject_encryption_activation.py"], repo)
    assert code == 0
    code, output = execute("combo-shear", ["cargo", "shear", "--deny-warnings"], repo)
    assert code == 0
    linux = repo / "crates/pos-owner-bridge/src/encryptor_lock/linux.rs"
    original_linux = linux.read_bytes()
    old_call = ".and_then(|()| fs::flock(file, FlockOperation::NonBlockingLockExclusive))"
    assert linux.read_text().count(old_call) == 1
    instrumented = linux.read_text().replace(old_call, '''.and_then(|()| fs::flock(file, FlockOperation::NonBlockingLockExclusive).inspect_err(|error| {
        if name == "subject-nonce-ledger.v1" {
            eprintln!("[DEBUG-399-FORK] ledger flock refused: {error:?}");
        }
    }))''')
    try:
        linux.write_text(instrumented)
        build = subprocess.run(["cargo", "test", "-p", "pos-owner-bridge", "--lib", "--all-features", "--locked", "--no-run", "--message-format=json"], cwd=repo, text=True, capture_output=True, check=False)
        (EVIDENCE / "parallel-build.log").write_text(build.stderr)
        assert build.returncode == 0
        artifacts = [json.loads(line) for line in build.stdout.splitlines() if line.startswith("{")]
        binaries = [a["executable"] for a in artifacts if a.get("reason") == "compiler-artifact" and a.get("profile", {}).get("test") and a.get("executable") and a.get("target", {}).get("name") == "pos_owner_bridge"]
        assert len(binaries) == 1, binaries
        binary = binaries[0]
        prefix = "encryptor_lock::linux::nonce_ledger::replace::tests::cases::"
        stress = {"parallel": [], "serial": []}
        for mode, count, flags in [("parallel", 100, []), ("serial", 10, ["--test-threads=1"])]:
            for index in range(count):
                trial = subprocess.run([binary, prefix, *flags], cwd=repo, capture_output=True, text=True, check=False)
                text = trial.stdout + trial.stderr
                (EVIDENCE / f"{mode}-{index}.log").write_text(text)
                stress[mode].append({"exit": trial.returncode, "ledger_flock_refusal": "[DEBUG-399-FORK] ledger flock refused" in text})
        (EVIDENCE / "parallel-stress.json").write_text(json.dumps(stress, indent=2))
        assert all(row["exit"] == 0 for row in stress["serial"])
        print("[DEBUG-399-FORK] baseline parallel failures", sum(row["exit"] != 0 for row in stress["parallel"]))
    finally:
        linux.write_bytes(original_linux)
    # A single test-process mutex prevents sibling forks from extending the
    # lifetime of short-lived flock descriptors. There are no other process
    # spawns in this library's unit tests; child probes exec a fresh test binary.
    body = body.replace("use std::time::{Duration, Instant};", "use std::time::{Duration, Instant};\nuse std::sync::Mutex;")
    body = body.replace("type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;", "type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;\n\n// fork duplicates descriptors until exec applies CLOEXEC. Serialize these\n// descriptor-lifetime witnesses with their sibling child-process creation.\nstatic PROCESS_TEST_LOCK: Mutex<()> = Mutex::new(());")
    pattern = r"(#\[test\]\s*fn (\w+)\(\) -> TestResult \{\n)"
    body, count = re.subn(pattern, lambda match: match[1] + ("    let _serial = PROCESS_TEST_LOCK.lock()?;\n" if match[2] != "crash_probe" else ""), body)
    assert count == 8, count
    assert body.count("let guard = SubjectEncryptorLock::acquire(&root)?;") == 1
    body = body.replace("let guard = SubjectEncryptorLock::acquire(&root)?;", "let _serial = PROCESS_TEST_LOCK.lock()?;\n    let guard = SubjectEncryptorLock::acquire(&root)?;")
    adjacent.write_text(header + "\n#[cfg(test)]\nmod cases {\n" + textwrap.indent(body, "    ") + "}\n")
    code, output = execute("combo-serialized-format", ["rustfmt", "--edition", "2021", str(adjacent)], repo)
    assert code == 0
    code, output = execute("combo-owner-coverage", ["cargo", "llvm-cov", "--manifest-path", "crates/pos-owner-bridge/Cargo.toml", "--all-features", "--locked", "--json", "--output-path", str(EVIDENCE / "combo-coverage.json"), "--", "--include-ignored"], repo)
    assert code == 0
    clean = re.sub(r"\x1b\[[0-9;]*m", "", output)
    private_names = re.findall(r"#\[test\]\s*fn (\w+)", adjacent.read_text())
    public_names = re.findall(r"#\[test\]\s*fn (\w+)", (repo / "crates/pos-owner-bridge/tests/nonce_ledger_replace_public.rs").read_text())
    assert len(private_names) == 8 and len(public_names) == 7
    for name in private_names:
        assert f"test encryptor_lock::linux::nonce_ledger::replace::tests::cases::{name} ... ok" in clean
    for name in public_names:
        assert f"test {name} ... ok" in clean
    data = json.loads((EVIDENCE / "combo-coverage.json").read_text())["data"][0]
    assert not any(posixpath.normpath(f["filename"]).endswith("/src/encryptor_lock/linux/nonce_ledger/replace/tests.rs") for f in data["files"])
    private_mappings = sum(1 for f in data["functions"] for region in f["regions"] if posixpath.normpath(f["filenames"][region[5]]).endswith("/src/encryptor_lock/linux/nonce_ledger/replace/tests.rs"))
    assert private_mappings > 0
    owned = []
    for path in ["src/encryptor_lock/linux.rs", "src/encryptor_lock/linux/nonce_ledger.rs", "src/encryptor_lock/linux/nonce_ledger/replace.rs"]:
        summary = next(f["summary"] for f in data["files"] if posixpath.normpath(f["filename"]).endswith("/pos-owner-bridge/" + path))
        assert all(summary[k]["covered"] == summary[k]["count"] for k in ["lines", "regions"])
        owned.append({"file": path, "summary": summary})
    code, output = execute("combo-lcov", ["cargo", "llvm-cov", "report", "--manifest-path", "crates/pos-owner-bridge/Cargo.toml", "--lcov", "--output-path", str(EVIDENCE / "combo.lcov")], repo)
    assert code == 0
    code, output = execute("combo-crap", ["cargo", "crap", "--workspace", "--lcov", str(EVIDENCE / "combo.lcov"), "--missing", "pessimistic", "--jobs", "2", "--exclude", "tests/**", "--format", "json", "--output", str(EVIDENCE / "combo-crap.json")], repo)
    assert code == 0
    entries = json.loads((EVIDENCE / "combo-crap.json").read_text())["entries"]
    assert not any(e["file"].endswith("/src/encryptor_lock/linux/nonce_ledger/replace/tests.rs") for e in entries)
    selected = [e for e in entries if "/crates/pos-owner-bridge/src/encryptor_lock/" in e["file"]]
    assert selected and all(e["coverage"] == 100 and e["crap"] <= 4 for e in selected)
    (EVIDENCE / "combo-adjacent-tests.rs").write_bytes(adjacent.read_bytes())
    (EVIDENCE / "combo-replace.rs").write_bytes(declaration.read_bytes())
    (EVIDENCE / "combo-verdict.json").write_text(json.dumps({"shear_passes": True, "all15_new_tests_run": True, "owned_mapped_coverage_full": True, "private_raw_mappings": private_mappings, "private_excluded_from_production_metrics": True, "owned_crap_max": max(e["crap"] for e in selected), "owned": owned}, indent=2))
finally:
    declaration.write_bytes(original_declaration)
    previous.write_bytes(original_witness)
    adjacent.unlink()
    adjacent.parent.rmdir()
assert declaration.read_bytes() == original_declaration and previous.read_bytes() == original_witness
