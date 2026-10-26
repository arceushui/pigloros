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
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
from unittest import mock

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

import third_party_notices as notices  # noqa: E402

ROOT = notices.ROOT
GUEST = "plugins/community/examples/compatibility-prototype/rust-guest/Cargo.lock"
PROBE = "plugins/community/examples/compatibility-prototype/probe-guest/Cargo.lock"
REUSABLE = ROOT / ".github/workflows/third-party-notices.yml"
CI = ROOT / ".github/workflows/ci.yml"
TAKI = "taiki-e/install-action@4cef1412cce204788f482e778a0b9187f9626a29"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
# A stand-in for the toolchain's rust-src library/Cargo.lock and std manifest.
STD_LOCK = f"""version = 4

[[package]]
name = "dlmalloc"
version = "0.2.10"
source = "{REGISTRY}"

[[package]]
name = "rustc-demangle"
version = "0.1.27"
source = "{REGISTRY}"

[[package]]
name = "std"
version = "0.0.0"
"""
STD_MANIFEST = '[package]\nname = "std"\n'
STD_RLIBS = (
    "libcore-1a.rlib",
    "libstd-2b.rlib",
    "libdlmalloc-3c.rlib",
    "librustc_demangle-4d.rlib",
)


def package(name: str, version: str = "1.0.0") -> dict:
    return {
        "id": f"registry#{name}@{version}",
        "name": name,
        "version": version,
        "source": "registry+https://github.com/rust-lang/crates.io-index",
    }


def locked(lock: str, name: str) -> str:
    if lock == "std":
        return "0.0.0"
    """The version `lock` pins for registry package `name`."""
    versions = sorted(v for n, v in notices.lock_packages(ROOT / lock) if n == name)
    if len(versions) != 1:
        raise AssertionError(f"{lock} pins {name} at {versions}")
    return versions[0]


def report(*names: str, lock: str | None = None) -> dict:
    """A minimal cargo-about JSON report: each crate MIT with its own text.

    With `lock`, each crate takes the version that lockfile pins.
    """
    version = {name: locked(lock, name) if lock else "1.0.0" for name in names}
    version.update({"dlmalloc": "0.2.10", "rustc-demangle": "0.1.27"} if lock == "std" else {})
    crates = [{"package": package(name, version[name]), "license": "MIT"} for name in names]
    licences = [
        {
            "name": "MIT License",
            "id": "MIT",
            "text": f"MIT text of {name}\n",
            "source_path": "LICENSE-MIT",
            "used_by": [{"crate": package(name, version[name]), "path": None}],
        }
        for name in names
    ]
    return {"overview": [], "licenses": licences, "crates": crates}


def reports() -> dict[str, dict]:
    return {
        "Cargo.lock": report("wasmtime", "anyhow", lock="Cargo.lock"),
        GUEST: report("wit-bindgen", lock=GUEST),
        PROBE: report("blake3", lock=PROBE),
        notices.RUST_STD: report("dlmalloc", "rustc-demangle", lock="std"),
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
        self.sysroot = self.root / "sysroot"
        library = self.sysroot / notices.RUST_SRC / "library"
        (library / "std").mkdir(parents=True)
        (library / "Cargo.lock").write_text(STD_LOCK, encoding="utf-8")
        (library / "std/Cargo.toml").write_text(STD_MANIFEST, encoding="utf-8")
        rlibs = self.sysroot / notices.RUST_STD_RLIBS
        rlibs.mkdir(parents=True)
        for name in STD_RLIBS:
            (rlibs / name).write_bytes(b"!<arch>\n")
        manifest = notices.load_toml(ROOT, notices.MANIFEST)["rust_std"]
        self.edit(
            str(notices.MANIFEST),
            manifest["lockfile_sha256"],
            notices.sha256(STD_LOCK.encode()),
        )
        self.edit(
            str(notices.MANIFEST),
            manifest["std_manifest_sha256"],
            notices.sha256(STD_MANIFEST.encode()),
        )
        path = self.path(str(notices.MANIFEST))
        text = path.read_text(encoding="utf-8")
        start = text.index("other_rlibs = [")
        end = text.index("]", start) + 1
        path.write_text(
            text[:start] + 'other_rlibs = ["core", "std"]' + text[end:], encoding="utf-8"
        )

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
        # deny.toml carries the crate-scoped webpki-roots exception (#426).
        section = '[webpki-roots]\naccepted = ["CDLA-Permissive-2.0"]\n'
        self.assertEqual(self.errors(), [])
        self.workspace.edit("about.toml", section, "")
        self.assert_error("about.toml crate-scoped accepted {} must equal deny.toml exceptions")
        self.workspace.edit("about.toml", "MPL-2.0\",\n]\n", 'MPL-2.0",\n]\n' + section)
        self.assertEqual(self.errors(), [])
        self.workspace.edit("third_party/about-guest.toml", section, "")
        self.assert_error("about-guest.toml crate-scoped accepted {} must equal deny.toml exceptions")

    def test_versioned_crate_exception_is_rejected(self) -> None:
        self.workspace.edit("deny.toml", 'crate = "webpki-roots"', 'crate = "webpki-roots@1.0.0"')
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
            "must not set ignore-build-dependencies": (
                "targets =",
                "ignore-build-dependencies = true\ntargets =",
            ),
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

    def test_nested_manifest_name_is_not_exempt(self) -> None:
        nested = self.workspace.path("third_party/notices/rust/manifest.toml")
        nested.write_text("schema = 1\n", encoding="utf-8")
        self.assert_error("rust/manifest.toml is not in the manifest")

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
            "excerpt needs lines [first": ("lines = [1, 4]", "lines = [true, true]"),
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
            "rust_std needs exactly": ('features = ["backtrace", "panic-unwind"]\n', ""),
            "rust_std features must be a non-empty list": (
                'features = ["backtrace", "panic-unwind"]',
                "features = []",
            ),
            "must be one tagged component": ('component = "rust"', 'component = "compiler-rt"'),
            "rust_std lockfile must be a path under library/": (
                'lockfile = "library/Cargo.lock"',
                'lockfile = "library/../Cargo.lock"',
            ),
            "rust_std other_rlibs must be a sorted list": (
                'other_rlibs = ["core", "std"]',
                'other_rlibs = ["std", "core"]',
            ),
            "rust_std std_manifest_sha256 must be a sha256 digest": (
                'std_manifest_sha256 = "',
                'std_manifest_sha256 = "x',
            ),
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
            "names unknown Cargo graph": (
                'rust-guest/Cargo.lock",\n',
                'other/Cargo.lock",\n',
            ),
            "are used by no fixture": (
                'components = ["wasi-libc", "blake3-c", "compiler-rt", "wit-bindgen"]',
                'components = ["wasi-libc", "blake3-c", "compiler-rt"]',
            ),
            "Cargo graphs ['plugins/community/examples/compatibility-prototype/probe-guest": (
                '  "plugins/community/examples/compatibility-prototype/probe-guest/Cargo.lock",\n',
                "",
            ),
            "Cargo graphs ['rust-std'] are used by no fixture": ('  "rust-std",\n', ""),
            "needs exactly components and cargo": (
                '[fixtures.contents."no-guest-exports.wasm"]\ncomponents = []\ncargo = []',
                '[fixtures.contents."no-guest-exports.wasm"]\ncomponents = []',
            ),
        }
        for fragment, (old, new) in cases.items():
            with self.subTest(fragment=fragment):
                workspace = Workspace()
                self.addCleanup(workspace.close)
                path = workspace.path(self.manifest)
                text = path.read_text(encoding="utf-8")
                self.assertIn(old, text)
                path.write_text(text.replace(old, new), encoding="utf-8")
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
        rust = next(c for c in self.manifest["component"] if c["id"] == "rust")
        for path, data in (
            ("library/Cargo.lock", STD_LOCK),
            ("library/std/Cargo.toml", STD_MANIFEST),
        ):
            self.upstream[notices.raw_url(rust["repository"], rust["commit"], path)] = data.encode()
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

    def test_changed_rust_std_inputs_fail(self) -> None:
        rust = next(c for c in self.manifest["component"] if c["id"] == "rust")
        url = notices.raw_url(rust["repository"], rust["commit"], "library/Cargo.lock")
        self.upstream[url] += b"# changed\n"
        self.assertIn(
            "rust_std upstream library/Cargo.lock does not match its sha256", self.run_check()
        )

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


class FetchTests(unittest.TestCase):
    URL = "https://raw.githubusercontent.com/example/project/commit/LICENSE"

    def test_success_returns_exact_bytes_without_waiting(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"exact upstream bytes\n"
        with (
            mock.patch.object(notices.urllib.request, "urlopen", return_value=response) as fetch,
            mock.patch.object(notices.time, "sleep") as sleep,
        ):
            self.assertEqual(notices.fetch_url(self.URL), b"exact upstream bytes\n")
        fetch.assert_called_once_with(self.URL, timeout=60)
        sleep.assert_not_called()

    def test_transient_failure_waits_before_fetching_again(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"verified next\n"
        calls = mock.Mock()
        with (
            mock.patch.object(
                notices.urllib.request, "urlopen", side_effect=[OSError("reset"), response]
            ) as fetch,
            mock.patch.object(notices.time, "sleep") as sleep,
        ):
            calls.attach_mock(fetch, "fetch")
            calls.attach_mock(sleep, "sleep")
            self.assertEqual(notices.fetch_url(self.URL), b"verified next\n")
        self.assertEqual(fetch.call_count, 2)
        sleep.assert_called_once_with(60)
        self.assertEqual(
            calls.mock_calls,
            [mock.call.fetch(self.URL, timeout=60), mock.call.sleep(60), mock.call.fetch(self.URL, timeout=60)],
        )

    def test_exhaustion_is_bounded_and_preserves_the_failure(self) -> None:
        error = notices.urllib.error.HTTPError(self.URL, 429, "Too Many Requests", {}, None)
        with (
            mock.patch.object(notices.urllib.request, "urlopen", side_effect=error) as fetch,
            mock.patch.object(notices.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(notices.NoticeError, "429: Too Many Requests"):
                notices.fetch_url(self.URL)
        self.assertEqual(fetch.call_count, 3)
        self.assertEqual(sleep.call_args_list, [mock.call(60), mock.call(120)])

    def test_retry_after_seconds_and_http_date_are_respected(self) -> None:
        now = datetime(2026, 10, 27, tzinfo=timezone.utc)
        for value in [
            "90",
            format_datetime(datetime(2026, 10, 27, 0, 1, 30, tzinfo=timezone.utc), usegmt=True),
        ]:
            error = notices.urllib.error.HTTPError(
                self.URL, 429, "rate limited", {"Retry-After": value}, None
            )
            response = mock.MagicMock()
            response.__enter__.return_value.read.return_value = b"after cooldown\n"
            with (
                mock.patch.object(notices, "datetime") as clock,
                mock.patch.object(
                    notices.urllib.request, "urlopen", side_effect=[error, response]
                ),
                mock.patch.object(notices.time, "sleep") as sleep,
            ):
                clock.now.return_value = now
                self.assertEqual(notices.fetch_url(self.URL), b"after cooldown\n")
                sleep.assert_called_once_with(90)

    def test_malformed_or_past_retry_after_uses_the_backoff(self) -> None:
        for value in ["bad", "-1", "0", "Mon, 01 Jan 2001 00:00:00 GMT"]:
            error = notices.urllib.error.HTTPError(
                self.URL, 503, "unavailable", {"Retry-After": value}, None
            )
            self.assertEqual(notices.fetch_retry_delay(error, 0), 60)

    def test_long_server_delay_fails_without_retrying_early(self) -> None:
        error = notices.urllib.error.HTTPError(
            self.URL, 429, "rate limited", {"Retry-After": "3600"}, None
        )
        with (
            mock.patch.object(notices.urllib.request, "urlopen", side_effect=error) as fetch,
            mock.patch.object(notices.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(notices.NoticeError, "429"):
                notices.fetch_url(self.URL)
        fetch.assert_called_once()
        sleep.assert_not_called()


class GitTests(unittest.TestCase):
    def test_git_retries_then_reports_stderr(self) -> None:
        calls = []

        def failing(command, **kwargs):
            calls.append(kwargs["timeout"])
            raise notices.subprocess.CalledProcessError(128, command, stderr="fatal: no route\n")

        with mock.patch.object(notices.subprocess, "run", failing):
            with self.assertRaisesRegex(
                notices.NoticeError, "git ls-remote x failed: fatal: no route"
            ):
                notices.git("ls-remote", "x")
        self.assertEqual(calls, [notices.GIT_TIMEOUT_SECONDS] * notices.FETCH_ATTEMPTS)

    def test_git_reports_a_timeout(self) -> None:
        def hanging(command, **kwargs):
            raise notices.subprocess.TimeoutExpired(command, kwargs["timeout"])

        with mock.patch.object(notices.subprocess, "run", hanging):
            with self.assertRaisesRegex(notices.NoticeError, "timed out"):
                notices.git("fetch")

    def test_git_succeeds_after_a_transient_failure(self) -> None:
        results = [notices.subprocess.CalledProcessError(1, "git", stderr="reset"), "ok"]

        def flaky(command, **kwargs):
            result = results.pop(0)
            if isinstance(result, Exception):
                raise result
            return notices.subprocess.CompletedProcess(command, 0, stdout=result)

        with mock.patch.object(notices.subprocess, "run", flaky):
            self.assertEqual(notices.git("ls-remote"), "ok")


class RustStdReportTests(WorkspaceTest):
    def test_runs_cargo_about_on_std_with_the_release_features(self) -> None:
        calls = []

        def run(command, **kwargs):
            calls.append((command, kwargs))

        output = self.workspace.root / "rust-std.json"
        errors = notices.run_rust_std_report(
            self.workspace.root, self.workspace.sysroot, output, run=run
        )
        self.assertEqual(errors, [])
        ((command, kwargs),) = calls
        library = self.workspace.sysroot / notices.RUST_SRC / "library"
        self.assertEqual(
            command,
            [
                "cargo",
                "about",
                "generate",
                "--locked",
                "--fail",
                "--manifest-path",
                str(library / "std/Cargo.toml"),
                "--features",
                "backtrace panic-unwind",
                "--config",
                str(self.workspace.root / notices.GUEST_ABOUT),
                "--format",
                "json",
                "--output-file",
                str(output),
            ],
        )
        self.assertEqual(kwargs["env"]["RUSTC_BOOTSTRAP"], "1")
        self.assertIs(kwargs["check"], True)

    def test_cargo_about_failure_is_reported(self) -> None:
        def run(command, **kwargs):
            raise notices.subprocess.CalledProcessError(3, command)

        errors = notices.run_rust_std_report(
            self.workspace.root, self.workspace.sysroot, Path("out.json"), run=run
        )
        self.assertEqual(errors, ["cargo about on Rust std failed with exit status 3"])

    def test_unpinned_rust_src_or_manifest_is_refused_before_running(self) -> None:
        def run(command, **kwargs):
            raise AssertionError("cargo about must not run")

        (self.workspace.sysroot / notices.RUST_SRC / "library/std/Cargo.toml").write_text(
            "[package]\n", encoding="utf-8"
        )
        self.assertEqual(
            notices.run_rust_std_report(
                self.workspace.root, self.workspace.sysroot, Path("o"), run=run
            ),
            ["rust-src library/std/Cargo.toml differs from the pinned Rust tag"],
        )
        self.workspace.edit(str(notices.MANIFEST), 'component = "rust"', 'component = "none"')
        errors = notices.run_rust_std_report(
            self.workspace.root, self.workspace.sysroot, Path("o"), run=run
        )
        self.assertTrue(any("must be one tagged component" in error for error in errors), errors)

    def test_shipped_rlibs_are_named_by_crate(self) -> None:
        self.assertEqual(
            notices.shipped_rlibs(self.workspace.sysroot),
            {"core", "std", "dlmalloc", "rustc_demangle"},
        )


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

    def test_empty_report_fails(self) -> None:
        for key in ("crates", "licenses"):
            with self.subTest(key=key):
                bad = report("a")
                bad[key] = []
                self.assertEqual(
                    notices.check_report(bad, "Cargo.lock"),
                    ["Cargo.lock: the cargo-about report lists no crates or no licences"],
                )

    def test_empty_text_fails(self) -> None:
        bad = report("a")
        bad["licenses"][0]["text"] = "  \n"
        errors = notices.check_report(bad, "Cargo.lock")
        self.assertIn("Cargo.lock: licence MIT has an empty text", errors)
        self.assertIn("Cargo.lock: a 1.0.0 has no licence text", errors)


class AssembleTests(WorkspaceTest):
    def test_bundle_is_deterministic_and_complete(self) -> None:
        text, index = notices.assemble(self.workspace.root, reports(), self.workspace.sysroot)
        again, index_again = notices.assemble(
            self.workspace.root, copy.deepcopy(reports()), self.workspace.sysroot
        )
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
            "c-guest.wasm: wasi-libc, blake3-c, compiler-rt, wit-bindgen",
            "rust-guest.wasm: rust, plugins/community/examples/compatibility-prototype/"
            "rust-guest/Cargo.lock, rust-std",
            "Cargo graph: rust-std: Rust 1.97.1 library/Cargo.lock, std with features "
            "backtrace, panic-unwind, wasm32-unknown-unknown",
            "MIT text of dlmalloc",
            "which the guests do not link.\n  core, std",
            "Component: wit-bindgen 0.61.1 generated C bindings",
            "no-guest-exports.wasm: first-party code only",
            "from the crate's LICENSE-MIT",
        ):
            self.assertIn(fragment, text)
        parsed = json.loads(index)
        self.assertEqual(
            [graph["lockfile"][:20] for graph in parsed["graphs"]],
            ["Cargo.lock", PROBE[:20], GUEST[:20], "rust-std: Rust 1.97."],
        )
        self.assertEqual(parsed["graphs"][3]["other_rlibs"], ["core", "std"])
        self.assertEqual(parsed["graphs"][3]["lockfile_sha256"], notices.sha256(STD_LOCK.encode()))
        self.assertEqual(
            [component["id"] for component in parsed["components"]],
            ["wasi-libc", "blake3-c", "compiler-rt", "rust", "wit-bindgen"],
        )

    def test_canonical_text_source_is_named(self) -> None:
        graphs = reports()
        graphs["Cargo.lock"]["licenses"][0]["source_path"] = None
        text, _ = notices.assemble(self.workspace.root, graphs, self.workspace.sysroot)
        self.assertIn("from the SPDX licence list text (the crate ships none)", text)

    def test_report_from_another_graph_fails(self) -> None:
        graphs = reports()
        graphs[GUEST] = report("wasmtime", lock="Cargo.lock")
        with self.assertRaisesRegex(notices.NoticeError, f"is not a registry package of {GUEST}"):
            notices.assemble(self.workspace.root, graphs, self.workspace.sysroot)

    def test_licence_texts_are_ordered_by_id_then_digest(self) -> None:
        graphs = reports()
        graphs["Cargo.lock"]["licenses"].reverse()
        first, _ = notices.assemble(self.workspace.root, graphs, self.workspace.sysroot)
        graphs["Cargo.lock"]["licenses"].reverse()
        second, _ = notices.assemble(self.workspace.root, graphs, self.workspace.sysroot)
        self.assertEqual(first, second)

    def test_std_crate_without_a_wasm32_rlib_fails(self) -> None:
        (self.workspace.sysroot / notices.RUST_STD_RLIBS / "libdlmalloc-3c.rlib").unlink()
        with self.assertRaisesRegex(
            notices.NoticeError, "rust-std: dlmalloc 0.2.10 has no wasm32-unknown-unknown rlib"
        ):
            notices.assemble(self.workspace.root, reports(), self.workspace.sysroot)

    def test_std_graph_may_list_in_tree_library_crates_only(self) -> None:
        library = self.workspace.sysroot / notices.RUST_SRC / "library"
        graphs = reports()
        alloc = report("alloc", lock="std")
        alloc["crates"][0]["package"].update(
            {"source": None, "manifest_path": str(library / "alloc/Cargo.toml")}
        )
        graphs[notices.RUST_STD]["crates"] += alloc["crates"]
        graphs[notices.RUST_STD]["licenses"] += alloc["licenses"]
        (self.workspace.sysroot / notices.RUST_STD_RLIBS / "liballoc-5e.rlib").write_bytes(b"")
        text, _ = notices.assemble(self.workspace.root, graphs, self.workspace.sysroot)
        self.assertIn("  alloc 0.0.0: MIT", text)
        self.assertIn("which the guests do not link.\n  core, std", text)
        alloc["crates"][0]["package"]["manifest_path"] = str(
            self.workspace.root / "alloc/Cargo.toml"
        )
        graphs = reports()
        graphs[notices.RUST_STD]["crates"] += alloc["crates"]
        graphs[notices.RUST_STD]["licenses"] += alloc["licenses"]
        with self.assertRaisesRegex(notices.NoticeError, "alloc 0.0.0 is not a registry package"):
            notices.assemble(self.workspace.root, graphs, self.workspace.sysroot)

    def test_unreviewed_sysroot_rlib_fails(self) -> None:
        (self.workspace.sysroot / notices.RUST_STD_RLIBS / "libnewcrate-9f.rlib").write_bytes(b"")
        with self.assertRaisesRegex(
            notices.NoticeError, r"outside std's graph are \['core', 'newcrate', 'std'\]"
        ):
            notices.assemble(self.workspace.root, reports(), self.workspace.sysroot)

    def test_std_report_must_match_the_rust_src_lockfile(self) -> None:
        graphs = reports()
        graphs[notices.RUST_STD] = report("wasmtime", lock="Cargo.lock")
        with self.assertRaisesRegex(notices.NoticeError, "is not a registry package of rust-std"):
            notices.assemble(self.workspace.root, graphs, self.workspace.sysroot)

    def test_rust_src_must_be_the_pinned_tag(self) -> None:
        lock = self.workspace.sysroot / notices.RUST_SRC / "library/Cargo.lock"
        lock.write_text(STD_LOCK + "\n", encoding="utf-8")
        with self.assertRaisesRegex(notices.NoticeError, "differs from the pinned Rust tag"):
            notices.assemble(self.workspace.root, reports(), self.workspace.sysroot)
        lock.unlink()
        with self.assertRaisesRegex(notices.NoticeError, "library/Cargo.lock is missing"):
            notices.assemble(self.workspace.root, reports(), self.workspace.sysroot)

    def test_offline_violations_stop_before_the_reports(self) -> None:
        self.workspace.path("third_party/notices/wit-bindgen/LICENSE-MIT").unlink()
        with self.assertRaisesRegex(notices.NoticeError, "wit-bindgen/LICENSE-MIT is missing"):
            notices.assemble(self.workspace.root, {}, self.workspace.sysroot)

    def test_every_graph_report_is_required(self) -> None:
        graphs = reports()
        del graphs[PROBE]
        with self.assertRaisesRegex(notices.NoticeError, "must be exactly"):
            notices.assemble(self.workspace.root, graphs, self.workspace.sysroot)

    def test_report_violations_stop_the_bundle(self) -> None:
        graphs = reports()
        graphs[GUEST]["crates"][0]["license"] = "Unknown"
        graphs[PROBE]["licenses"][0]["text"] = ""
        with self.assertRaises(notices.NoticeError) as raised:
            notices.assemble(self.workspace.root, graphs, self.workspace.sysroot)
        self.assertIn("has an unknown licence", str(raised.exception))
        self.assertIn("has an empty text", str(raised.exception))


class CommandLineTests(WorkspaceTest):
    def write_reports(self) -> list[str]:
        args = []
        for number, (lock, content) in enumerate(sorted(reports().items())):
            path = self.workspace.root / f"report-{number}.json"
            path.write_text(json.dumps(content), encoding="utf-8")
            args += ["--graph", f"{lock}={path}"]
        return args

    def sysroot(self) -> list[str]:
        return ["--sysroot", str(self.workspace.sysroot)]

    def test_rust_std_report_command_refuses_unpinned_rust_src(self) -> None:
        (self.workspace.sysroot / notices.RUST_SRC / "library/Cargo.lock").unlink()
        code, stderr = self.run_main(["rust-std-report", *self.sysroot(), "--output", "o.json"])
        self.assertEqual(code, 1)
        self.assertIn("rust-src library/Cargo.lock is missing", stderr)

    def run_main(self, argv: list[str]) -> tuple[int, str]:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = notices.main(argv, root=self.workspace.root)
        return code, stderr.getvalue()

    def test_assemble_writes_the_bundle(self) -> None:
        output = self.workspace.root / "out"
        code, stderr = self.run_main(
            ["assemble", *self.write_reports(), *self.sysroot(), "--output", str(output)]
        )
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn(
            "Component: wasi-libc", (output / notices.TEXT_NAME).read_text(encoding="utf-8")
        )
        self.assertEqual(
            json.loads((output / notices.INDEX_NAME).read_text(encoding="utf-8"))["schema"], 1
        )

    def test_repeated_graph_fails(self) -> None:
        args = self.write_reports()
        code, stderr = self.run_main(
            ["assemble", *args, *args[:2], *self.sysroot(), "--output", "out"]
        )
        self.assertEqual(code, 1)
        self.assertIn("given twice", stderr)

    def test_malformed_graph_argument_is_rejected(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            notices.main(["assemble", "--graph", "Cargo.lock", "--sysroot", "s", "--output", "out"])

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
            "third_party_notices.py rust-std-report",
            '"rust-std=${REPORTS}/rust-std.json"',
            "third_party_notices.py assemble",
            '--sysroot "$(rustc --print sysroot)"',
        ):
            self.assertIn(fragment, script)
        toolchain = steps[1]["with"]
        self.assertEqual(
            (toolchain["toolchain"], toolchain["components"], toolchain["targets"]),
            ("1.97.1", "rust-src", "wasm32-unknown-unknown"),
        )
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
