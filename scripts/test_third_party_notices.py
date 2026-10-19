#!/usr/bin/env python3
"""Adversarial tests for the third-party notice generator (#545)."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

import third_party_notices as notices  # noqa: E402

ROOT = notices.ROOT
GUEST = "plugins/community/examples/compatibility-prototype/rust-guest/Cargo.lock"
PROBE = "plugins/community/examples/compatibility-prototype/probe-guest/Cargo.lock"
REUSABLE = ROOT / ".github/workflows/third-party-notices.yml"
CI = ROOT / ".github/workflows/ci.yml"
TAKI = "taiki-e/install-action@4cef1412cce204788f482e778a0b9187f9626a29"


def package(name: str, version: str = "1.0.0") -> dict:
    return {"id": f"registry#{name}@{version}", "name": name, "version": version}


def report(*names: str) -> dict:
    """A minimal cargo-about JSON report: each crate MIT with its own text."""
    crates = [{"package": package(name), "license": "MIT"} for name in names]
    licences = [
        {
            "name": "MIT License",
            "id": "MIT",
            "text": f"MIT text of {name}\n",
            "source_path": "LICENSE-MIT",
            "used_by": [{"crate": package(name), "path": None}],
        }
        for name in names
    ]
    return {"overview": [], "licenses": licences, "crates": crates}


def reports() -> dict[str, dict]:
    return {
        "Cargo.lock": report("wasmtime", "anyhow"),
        GUEST: report("wit-bindgen"),
        PROBE: report("blake3"),
    }


class Workspace:
    """A temporary copy of the inputs the generator reads."""

    def __init__(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        for relative in ("deny.toml", "about.toml", "Cargo.lock", GUEST, PROBE):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        shutil.copytree(ROOT / "third_party", self.root / "third_party")
        fixtures = "plugins/community/examples/compatibility-prototype/fixtures"
        shutil.copytree(ROOT / fixtures, self.root / fixtures)

    def path(self, relative: str) -> Path:
        return self.root / relative

    def edit(self, relative: str, old: str, new: str) -> None:
        path = self.path(relative)
        text = path.read_text(encoding="utf-8")
        if old not in text:
            raise AssertionError(f"{old!r} not in {relative}")
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def close(self) -> None:
        self.directory.cleanup()


class WorkspaceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = Workspace()
        self.addCleanup(self.workspace.close)

    def errors(self) -> list[str]:
        return notices.offline_errors(self.workspace.root)

    def assert_error(self, fragment: str) -> None:
        errors = self.errors()
        self.assertTrue(any(fragment in error for error in errors), errors)


class RepositoryTests(unittest.TestCase):
    def test_committed_inputs_pass_every_offline_check(self) -> None:
        self.assertEqual(notices.offline_errors(ROOT), [])

    def test_check_command_succeeds(self) -> None:
        self.assertEqual(notices.main(["check"]), 0)

    def test_every_guest_lockfile_is_found(self) -> None:
        self.assertEqual(notices.guest_lockfiles(ROOT), sorted([GUEST, PROBE]))


class PolicyMirrorTests(WorkspaceTest):
    def test_accepted_order_must_match_deny(self) -> None:
        self.workspace.edit("about.toml", '  "MIT",\n  "MIT-0",', '  "MIT-0",\n  "MIT",')
        self.assert_error("about.toml accepted")

    def test_guest_accepted_must_match_deny(self) -> None:
        self.workspace.edit("third_party/about-guest.toml", '  "MPL-2.0",\n', "")
        self.assert_error("about-guest.toml accepted")

    def test_new_deny_allowance_needs_a_matching_about_entry(self) -> None:
        self.workspace.edit("deny.toml", '  "MPL-2.0",\n]', '  "MPL-2.0",\n  "BSL-1.0",\n]')
        self.assert_error("must equal deny.toml allow")

    def test_crate_exception_must_be_mirrored(self) -> None:
        exception = 'exceptions = [{ crate = "webpki-roots", allow = ["CDLA-Permissive-2.0"] }]'
        self.workspace.edit("deny.toml", "exceptions = []", exception)
        self.assert_error("crate-scoped accepted {} must equal deny.toml exceptions")
        for config in ("about.toml", "third_party/about-guest.toml"):
            path = self.workspace.path(config)
            with path.open("a", encoding="utf-8") as handle:
                handle.write('\n[webpki-roots]\naccepted = ["CDLA-Permissive-2.0"]\n')
        self.assertEqual(self.errors(), [])

    def test_versioned_crate_exception_is_rejected(self) -> None:
        exception = 'exceptions = [{ crate = "webpki-roots@1.0.0", allow = ["ISC"] }]'
        self.workspace.edit("deny.toml", "exceptions = []", exception)
        with self.assertRaisesRegex(notices.NoticeError, "without a version"):
            self.errors()

    def test_scope_settings_are_required(self) -> None:
        cases = {
            "targets": (
                'targets = ["x86_64-unknown-linux-gnu"]',
                'targets = ["aarch64-apple-darwin"]',
            ),
            "ignore-dev-dependencies": (
                "ignore-dev-dependencies = true",
                "ignore-dev-dependencies = false",
            ),
            "private = { ignore = true }": (
                "private = { ignore = true }",
                "private = { ignore = false }",
            ),
            "must not set workarounds": ("targets =", 'workarounds = ["ring"]\ntargets ='),
        }
        for fragment, (old, new) in cases.items():
            with self.subTest(fragment=fragment):
                workspace = Workspace()
                self.addCleanup(workspace.close)
                workspace.edit("about.toml", old, new)
                errors = notices.offline_errors(workspace.root)
                self.assertTrue(any(fragment in error for error in errors), errors)

    def test_guest_targets_are_fixed(self) -> None:
        self.workspace.edit(
            "third_party/about-guest.toml",
            'targets = ["wasm32-unknown-unknown"]',
            'targets = ["x86_64-unknown-linux-gnu"]',
        )
        self.assert_error("about-guest.toml targets")


class ManifestTests(WorkspaceTest):
    manifest = "third_party/notices/manifest.toml"

    def test_tampered_text_fails_its_digest(self) -> None:
        path = self.workspace.path("third_party/notices/wasi-libc/libc-top-half/musl/COPYRIGHT")
        path.write_bytes(path.read_bytes() + b"extra\n")
        self.assert_error("musl/COPYRIGHT does not match its digest")

    def test_tampered_excerpt_fails_its_digest(self) -> None:
        path = self.workspace.path("third_party/notices/wasi-libc/dlmalloc-malloc.c.lines-1-5")
        path.write_text("/* public domain */\n", encoding="utf-8")
        self.assert_error("dlmalloc-malloc.c.lines-1-5 does not match its digest")

    def test_missing_and_empty_texts_fail(self) -> None:
        self.workspace.path("third_party/notices/blake3-c/LICENSE_CC0").unlink()
        self.workspace.path("third_party/notices/rust/COPYRIGHT").write_bytes(b"\n")
        errors = self.errors()
        self.assertTrue(any("LICENSE_CC0 is missing" in error for error in errors), errors)
        self.assertTrue(any("COPYRIGHT is empty" in error for error in errors), errors)

    def test_unlisted_text_fails(self) -> None:
        self.workspace.path("third_party/notices/rust/EXTRA").write_text("x\n", encoding="utf-8")
        self.assert_error("rust/EXTRA is not in the manifest")

    def test_malformed_entries_fail(self) -> None:
        cases = {
            "schema must be 1": ("schema = 1", "schema = 2"),
            "needs a 40-hex commit": (
                'commit = "f3149ec5bb5449af877ba20377a11008ff499fa2"',
                'commit = "1.8.7"',
            ),
            "needs a tag or a submodule pin": ('tag = "1.8.7"\n', ""),
            "repository must be a https://github.com/ URL": (
                'repository = "https://github.com/BLAKE3-team/BLAKE3"',
                'repository = "http://example.com/BLAKE3"',
            ),
            "submodule needs exactly repository, tag and path": (
                'path = "src/llvm-project" }',
                'path = "src/llvm-project", branch = "main" }',
            ),
            "excerpt needs lines": ("lines = [1, 5]", "lines = [5, 1]"),
            "needs a sha256 digest": (
                'sha256 = "00fcc7a934ddbc9ece2a7cc063ac788e284b703b1d705ccbba72d462aa97921e"',
                'sha256 = "00fc"',
            ),
            "needs exactly path, local, sha256 and an optional excerpt": (
                'local = "blake3-c/LICENSE_A2"\n',
                'local = "blake3-c/LICENSE_A2"\nnote = "x"\n',
            ),
            "local path must stay relative": (
                'local = "blake3-c/LICENSE_A2"',
                'local = "../LICENSE_A2"',
            ),
            "component ids repeat": ('id = "compiler-rt"', 'id = "rust"'),
            "is listed twice": (
                'local = "blake3-c/LICENSE_A2LLVM"',
                'local = "blake3-c/LICENSE_A2"',
            ),
            "needs a non-empty name": ('name = "wasi-libc"\n', ""),
        }
        for fragment, (old, new) in cases.items():
            with self.subTest(fragment=fragment):
                workspace = Workspace()
                self.addCleanup(workspace.close)
                workspace.edit(self.manifest, old, new)
                errors = notices.offline_errors(workspace.root)
                self.assertTrue(any(fragment in error for error in errors), errors)

    def test_manifest_needs_components_and_files(self) -> None:
        self.assertIn("notice manifest lists no component", notices.check_manifest({"schema": 1}))
        component = {
            "id": "x",
            "name": "x",
            "licence": "MIT",
            "repository": "https://github.com/a/b",
            "commit": "0" * 40,
            "tag": "v1",
        }
        self.assertIn("component 'x' lists no notice file", notices.check_component(component))


class FixtureMapTests(WorkspaceTest):
    manifest = "third_party/notices/manifest.toml"

    def test_new_fixture_must_be_mapped(self) -> None:
        directory = "plugins/community/examples/compatibility-prototype/fixtures"
        self.workspace.path(f"{directory}/new-guest.wasm").write_bytes(b"\0asm")
        self.assert_error("must list exactly the committed fixtures")

    def test_unknown_and_unused_references_fail(self) -> None:
        cases = {
            "names unknown component 'zlib'": (
                '[fixtures.contents."rust-guest.wasm"]\ncomponents = ["rust"]',
                '[fixtures.contents."rust-guest.wasm"]\ncomponents = ["zlib"]',
            ),
            "names unknown guest lockfile": (
                'rust-guest/Cargo.lock",\n]',
                'other/Cargo.lock",\n]',
            ),
            "are used by no fixture": (
                'components = ["wasi-libc", "blake3-c", "compiler-rt"]',
                'components = ["wasi-libc", "blake3-c"]',
            ),
            "guest lockfiles": (
                'cargo = [\n  "plugins/community/examples/compatibility-prototype/probe-guest/Cargo.lock",\n]',
                "cargo = []",
            ),
            "needs exactly components and cargo": (
                '[fixtures.contents."no-guest-exports.wasm"]\ncomponents = []\ncargo = []',
                '[fixtures.contents."no-guest-exports.wasm"]\ncomponents = []',
            ),
        }
        for fragment, (old, new) in cases.items():
            with self.subTest(fragment=fragment):
                workspace = Workspace()
                self.addCleanup(workspace.close)
                workspace.edit(self.manifest, old, new)
                errors = notices.offline_errors(workspace.root)
                self.assertTrue(any(fragment in error for error in errors), errors)

    def test_missing_fixture_directory_fails(self) -> None:
        self.workspace.edit(self.manifest, 'directory = "plugins', 'directory = "missing/plugins')
        self.assert_error("does not exist")


class UpstreamTests(WorkspaceTest):
    def setUp(self) -> None:
        super().setUp()
        self.manifest = notices.load_toml(self.workspace.root, notices.MANIFEST)
        self.notices_dir = self.workspace.root / notices.NOTICES_DIR
        self.upstream: dict[str, bytes] = {}
        for component in self.manifest["component"]:
            for entry in component["file"]:
                url = notices.raw_url(component["repository"], component["commit"], entry["path"])
                data = (self.notices_dir / entry["local"]).read_bytes()
                if "lines" in entry:
                    # Stand in for the full upstream file around the excerpt.
                    data += b"the rest of the upstream file\n"
                    entry["sha256"] = notices.sha256(data)
                self.upstream[url] = data
        self.tags = {
            (component["repository"], component["tag"]): component["commit"]
            for component in self.manifest["component"]
            if "tag" in component
        }
        self.submodules = {
            (sub["repository"], sub["tag"], sub["path"]): component["commit"]
            for component in self.manifest["component"]
            if (sub := component.get("submodule"))
        }

    def run_check(self) -> list[str]:
        return notices.upstream_errors(
            self.manifest,
            self.notices_dir,
            fetch=self.upstream.__getitem__,
            tag_commit=lambda repository, tag: self.tags[(repository, tag)],
            submodule_commit=lambda repository, tag, path: self.submodules[(repository, tag, path)],
        )

    def excerpt_entry(self) -> tuple[dict, dict]:
        for component in self.manifest["component"]:
            for entry in component["file"]:
                if "lines" in entry:
                    return component, entry
        raise AssertionError("no excerpt entry")

    def test_matching_upstream_passes(self) -> None:
        self.assertEqual(self.run_check(), [])

    def test_moved_tag_and_submodule_fail(self) -> None:
        key = next(iter(self.tags))
        self.tags[key] = "f" * 40
        sub = next(iter(self.submodules))
        self.submodules[sub] = "e" * 40
        errors = self.run_check()
        self.assertTrue(any(f"is {'f' * 40}" in error for error in errors), errors)
        self.assertTrue(any(f"is {'e' * 40}" in error for error in errors), errors)

    def test_changed_upstream_bytes_fail(self) -> None:
        url = next(iter(self.upstream))
        self.upstream[url] = b"changed\n"
        self.assertTrue(any("does not match its sha256" in error for error in self.run_check()))

    def test_excerpt_must_equal_upstream_lines(self) -> None:
        component, entry = self.excerpt_entry()
        url = notices.raw_url(component["repository"], component["commit"], entry["path"])
        full = b"line one\nline two\nline three\nline four\nline five\nline six\n"
        self.upstream[url] = full
        entry["sha256"] = notices.sha256(full)
        errors = self.run_check()
        self.assertTrue(
            any(f"committed {entry['local']} differs" in error for error in errors), errors
        )
        self.upstream[url] = b"short\n"
        entry["sha256"] = notices.sha256(b"short\n")
        with self.assertRaisesRegex(notices.NoticeError, "fewer than"):
            self.run_check()

    def test_raw_url_and_excerpt(self) -> None:
        self.assertEqual(
            notices.raw_url("https://github.com/a/b", "c" * 40, "x/LICENSE"),
            f"https://raw.githubusercontent.com/a/b/{'c' * 40}/x/LICENSE",
        )
        self.assertEqual(notices.excerpt_bytes(b"1\n2\n3\n", [2, 3]), b"2\n3\n")


class ReportTests(unittest.TestCase):
    def test_valid_report_passes(self) -> None:
        self.assertEqual(notices.check_report(report("a", "b"), "Cargo.lock"), [])

    def test_unknown_licence_fails(self) -> None:
        bad = report("a")
        bad["crates"][0]["license"] = "Unknown"
        self.assertIn(
            "Cargo.lock: a 1.0.0 has an unknown licence", notices.check_report(bad, "Cargo.lock")
        )

    def test_crate_without_text_fails(self) -> None:
        bad = report("a", "b")
        bad["licenses"].pop()
        self.assertIn(
            "Cargo.lock: b 1.0.0 has no licence text", notices.check_report(bad, "Cargo.lock")
        )

    def test_empty_text_fails(self) -> None:
        bad = report("a")
        bad["licenses"][0]["text"] = "  \n"
        errors = notices.check_report(bad, "Cargo.lock")
        self.assertIn("Cargo.lock: licence MIT has an empty text", errors)
        self.assertIn("Cargo.lock: a 1.0.0 has no licence text", errors)


class AssembleTests(WorkspaceTest):
    def test_bundle_is_deterministic_and_complete(self) -> None:
        text, index = notices.assemble(self.workspace.root, reports())
        again, index_again = notices.assemble(self.workspace.root, copy.deepcopy(reports()))
        self.assertEqual((text, index), (again, index_again))
        for fragment in (
            "Cargo graph: Cargo.lock (SHA-256 ",
            f"Cargo graph: {GUEST}",
            "MIT text of wasmtime",
            "Component: wasi-libc",
            "dlmalloc/src/malloc.c, lines 1-5",
            "released to the public domain",
            "libc-bottom-half/cloudlibc/LICENSE",
            "Component: BLAKE3 C implementation 1.8.7",
            "compiler-rt/LICENSE.TXT",
            "c-guest.wasm: wasi-libc, blake3-c, compiler-rt",
            "no-guest-exports.wasm: first-party code only",
            "from the crate's LICENSE-MIT",
        ):
            self.assertIn(fragment, text)
        parsed = json.loads(index)
        self.assertEqual(
            [graph["lockfile"] for graph in parsed["graphs"]], ["Cargo.lock", PROBE, GUEST]
        )
        self.assertEqual(
            [component["id"] for component in parsed["components"]],
            ["wasi-libc", "blake3-c", "compiler-rt", "rust"],
        )

    def test_canonical_text_source_is_named(self) -> None:
        graphs = reports()
        graphs["Cargo.lock"]["licenses"][0]["source_path"] = None
        text, _ = notices.assemble(self.workspace.root, graphs)
        self.assertIn("from the SPDX licence list text (the crate ships none)", text)

    def test_every_graph_report_is_required(self) -> None:
        graphs = reports()
        del graphs[PROBE]
        with self.assertRaisesRegex(notices.NoticeError, "must be exactly"):
            notices.assemble(self.workspace.root, graphs)

    def test_report_and_offline_violations_stop_the_bundle(self) -> None:
        graphs = reports()
        graphs[GUEST]["crates"][0]["license"] = "Unknown"
        self.workspace.path("third_party/notices/rust/COPYRIGHT").write_text(
            "x\n", encoding="utf-8"
        )
        with self.assertRaises(notices.NoticeError) as raised:
            notices.assemble(self.workspace.root, graphs)
        self.assertIn("has an unknown licence", str(raised.exception))
        self.assertIn("rust/COPYRIGHT does not match its digest", str(raised.exception))


class CommandLineTests(WorkspaceTest):
    def write_reports(self) -> list[str]:
        args = []
        for number, (lock, content) in enumerate(sorted(reports().items())):
            path = self.workspace.root / f"report-{number}.json"
            path.write_text(json.dumps(content), encoding="utf-8")
            args += ["--graph", f"{lock}={path}"]
        return args

    def run_main(self, argv: list[str]) -> tuple[int, str]:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = notices.main(argv, root=self.workspace.root)
        return code, stderr.getvalue()

    def test_assemble_writes_the_bundle(self) -> None:
        output = self.workspace.root / "out"
        code, stderr = self.run_main(["assemble", *self.write_reports(), "--output", str(output)])
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn(
            "Component: wasi-libc", (output / notices.TEXT_NAME).read_text(encoding="utf-8")
        )
        self.assertEqual(
            json.loads((output / notices.INDEX_NAME).read_text(encoding="utf-8"))["schema"], 1
        )

    def test_repeated_graph_fails(self) -> None:
        args = self.write_reports()
        code, stderr = self.run_main(["assemble", *args, *args[:2], "--output", "out"])
        self.assertEqual(code, 1)
        self.assertIn("given twice", stderr)

    def test_malformed_graph_argument_is_rejected(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            notices.main(["assemble", "--graph", "Cargo.lock", "--output", "out"])

    def test_check_reports_errors(self) -> None:
        self.workspace.path("third_party/notices/rust/COPYRIGHT").write_text(
            "x\n", encoding="utf-8"
        )
        code, stderr = self.run_main(["check"])
        self.assertEqual(code, 1)
        self.assertIn("error: notice text rust/COPYRIGHT does not match its digest", stderr)

    def test_verify_upstream_stops_on_offline_errors(self) -> None:
        self.workspace.path("third_party/notices/rust/COPYRIGHT").write_text(
            "x\n", encoding="utf-8"
        )
        code, stderr = self.run_main(["verify-upstream"])
        self.assertEqual(code, 1)
        self.assertIn("does not match its digest", stderr)


class WorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reusable = yaml.safe_load(REUSABLE.read_text(encoding="utf-8"))
        cls.ci = yaml.safe_load(CI.read_text(encoding="utf-8"))

    def test_generator_is_a_reusable_workflow_only(self) -> None:
        # PyYAML 1.1 reads the bare `on` key as True.
        triggers = self.reusable.get("on", self.reusable.get(True))
        self.assertEqual(triggers, {"workflow_call": None})
        self.assertEqual(self.reusable["permissions"], {"contents": "read"})

    def test_generator_pins_cargo_about_and_runs_every_stage(self) -> None:
        steps = self.reusable["jobs"]["notices"]["steps"]
        installs = [step for step in steps if step.get("uses", "").startswith("taiki-e/")]
        self.assertEqual(
            installs,
            [{"name": "Install cargo-about", "uses": TAKI, "with": {"tool": "cargo-about@0.9.2"}}],
        )
        script = "\n".join(step.get("run", "") for step in steps)
        for fragment in (
            "third_party_notices.py verify-upstream",
            "cargo about generate --locked --fail --workspace --all-features",
            "--config third_party/about-guest.toml",
            "third_party_notices.py assemble",
        ):
            self.assertIn(fragment, script)
        upload = steps[-1]
        self.assertEqual(upload["with"]["name"], "third-party-notices")
        self.assertEqual(upload["with"]["if-no-files-found"], "error")

    def test_ci_calls_the_generator_and_requires_it(self) -> None:
        jobs = self.ci["jobs"]
        self.assertEqual(
            jobs["third-party-notices"]["uses"], "./.github/workflows/third-party-notices.yml"
        )
        preflight = jobs["preflight-gate"]
        self.assertIn("third-party-notices", preflight["needs"])
        script = preflight["steps"][0]["run"]
        self.assertIn('test "${NOTICES_RESULT}" = success', script)
        self.assertIn('test "${NOTICES_RESULT}" = skipped', script)


if __name__ == "__main__":
    unittest.main()
