#!/usr/bin/env python3
"""Tests for the pull-request affected-package resolver."""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import affected_packages as resolver  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCOPE_FILTER = ROOT / ".github" / "rust-scope.yml"


def listing(*entries: str | tuple[str, str]) -> str:
    lines = []
    for entry in entries:
        if isinstance(entry, tuple):
            lines.append(json.dumps({"filename": entry[0], "previous_filename": entry[1]}))
        else:
            lines.append(json.dumps({"filename": entry, "previous_filename": None}))
    return "".join(line + "\n" for line in lines)


class Workspace:
    """A temporary Cargo workspace written from manifests and sources."""

    def __init__(self, directory: str) -> None:
        self.root = pathlib.Path(directory)

    def write(self, path: str, text: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def member(self, path: str, name: str, extra: str = "", *, lib: bool = True) -> None:
        self.write(f"{path}/Cargo.toml", f'[package]\nname = "{name}"\n{extra}')
        self.write(f"{path}/src/{'lib' if lib else 'main'}.rs", "\n")


def standard_workspace(directory: str) -> Workspace:
    """core <- store (normal) <- runtime (dev) ; cli (bin) -> store ; gate (build) -> core.

    ``plugins/world`` is embedded by ``runtime``'s library; ``tool`` only reads
    ``plugins/world`` from an integration test; ``evidence`` reads the
    workspace root from a test; ``plugins/world/nested`` is a nested member.
    """
    workspace = Workspace(directory)
    workspace.write(
        "Cargo.toml",
        '[workspace]\nmembers = ["crates/*", "apps/cli", "plugins/world", '
        '"plugins/world/nested", "apps/evidence", "apps/tool", "apps/gate"]\n'
        'exclude = ["crates/excluded"]\n'
        "[workspace.dependencies]\n"
        'core = { path = "crates/core" }\n'
        'serde = "1"\n',
    )
    workspace.write(".github/rust-scope.yml", SCOPE_FILTER.read_text(encoding="utf-8"))
    workspace.member("crates/core", "core")
    workspace.member("crates/store", "store", "[dependencies]\ncore = { workspace = true }\nserde = { workspace = true }\n")
    workspace.member(
        "crates/runtime",
        "runtime",
        '[dev-dependencies]\nstore = { path = "../store" }\n',
    )
    workspace.write(
        "crates/runtime/src/embed.rs",
        'const WORLD: &[u8] = include_bytes!("../../../plugins/world/src/lib.rs");\n',
    )
    workspace.member("crates/excluded", "excluded")
    workspace.member(
        "apps/cli",
        "cli",
        '[target.\'cfg(unix)\'.dependencies]\nstore = { path = "../../crates/store" }\n',
        lib=False,
    )
    workspace.member("plugins/world", "world")
    workspace.member("plugins/world/nested", "nested")
    workspace.member("apps/evidence", "evidence", lib=False)
    workspace.write(
        "apps/evidence/tests/evidence.rs",
        'fn root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..") }\n',
    )
    workspace.member("apps/tool", "tool", lib=False)
    workspace.write(
        "apps/tool/tests/world.rs",
        'const SOURCE: &str = "plugins/world/src/lib.rs";\n'
        'const FIXTURE: &[u8] = include_bytes!("../../../fixtures/conformance/support/limits.md");\n',
    )
    workspace.member(
        "apps/gate",
        "gate",
        '[build-dependencies]\ncore = { path = "../../crates/core" }\n',
        lib=False,
    )
    return workspace


class ResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.workspace = standard_workspace(self.directory.name)

    def select(self, *paths: str) -> tuple[str, str]:
        return resolver.selection(list(paths), self.workspace.root)

    def names(self, *paths: str) -> list[str]:
        packages, _ = self.select(*paths)
        return packages.replace("-p ", "").split()

    def run_main(self, text: str, expected: int) -> tuple[list[str], str]:
        path = self.workspace.root / "listing.jsonl"
        path.write_text(text, encoding="utf-8")
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = resolver.main(
                [str(path), "--expected-files", str(expected), "--root", str(self.workspace.root)]
            )
        self.assertEqual(status, 0)
        return stdout.getvalue().splitlines(), stderr.getvalue()

    def assert_full(self, *paths: str) -> None:
        with self.assertRaises(resolver.ScopeError):
            self.select(*paths)

    # Workspace graph -------------------------------------------------------

    def test_members_follow_globs_excludes_and_every_dependency_kind(self) -> None:
        members = resolver.load_workspace(self.workspace.root)
        self.assertNotIn("crates/excluded", members)
        self.assertEqual(members["crates/store"].dependencies, {"crates/core"})
        self.assertEqual(members["crates/runtime"].dependencies, {"crates/store"})
        self.assertEqual(members["apps/cli"].dependencies, {"crates/store"})
        self.assertEqual(members["apps/gate"].dependencies, {"crates/core"})
        self.assertTrue(members["crates/core"].has_lib)
        self.assertFalse(members["apps/cli"].has_lib)

    def test_legacy_dependency_table_names_count(self) -> None:
        self.workspace.member(
            "crates/core", "core",
            '[dev_dependencies]\nworld = { path = "../../plugins/world" }\n'
            '[build_dependencies]\nnested = { path = "../../plugins/world/nested" }\n',
        )
        members = resolver.load_workspace(self.workspace.root)
        self.assertEqual(members["crates/core"].dependencies,
                         {"plugins/world", "plugins/world/nested"})

    def test_library_detection(self) -> None:
        self.workspace.member("apps/cli", "cli", '[lib]\npath = "src/main.rs"\n', lib=False)
        self.workspace.member("crates/core", "core", "[package.metadata]\n")
        self.workspace.write("crates/core/Cargo.toml", '[package]\nname = "core"\nautolib = false\n')
        members = resolver.load_workspace(self.workspace.root)
        self.assertTrue(members["apps/cli"].has_lib)
        self.assertFalse(members["crates/core"].has_lib)

    def test_unreadable_or_ambiguous_workspaces_are_errors(self) -> None:
        cases = {
            "no workspace": ("Cargo.toml", '[package]\nname = "root"\n'),
            "bad toml": ("Cargo.toml", "[workspace\n"),
            "members not a list": ("Cargo.toml", '[workspace]\nmembers = "crates/*"\n'),
            "exclude not a list": ("Cargo.toml", '[workspace]\nmembers = ["crates/core"]\nexclude = 1\n'),
            "no members": ("Cargo.toml", "[workspace]\nmembers = []\n"),
            "member above root": ("Cargo.toml", '[workspace]\nmembers = ["../x"]\n'),
            "member is root": ("Cargo.toml", '[workspace]\nmembers = ["."]\n'),
            "inherited table": ("Cargo.toml", '[workspace]\nmembers = ["crates/core"]\ndependencies = 1\n'),
            "missing member manifest": ("Cargo.toml", '[workspace]\nmembers = ["crates/missing"]\n'),
            "nameless member": ("crates/core/Cargo.toml", "[package]\n"),
            "odd name": ("crates/core/Cargo.toml", '[package]\nname = "a b"\n'),
            "duplicate name": ("crates/core/Cargo.toml", '[package]\nname = "store"\n'),
            "dependency table type": ("crates/core/Cargo.toml", 'dependencies = 1\n[package]\nname = "core"\n'),
            "target type": ("crates/core/Cargo.toml", 'target = 1\n[package]\nname = "core"\n'),
            "target cfg type": ("crates/core/Cargo.toml", '[package]\nname = "core"\n[target]\nunix = 1\n'),
        }
        for label, (path, text) in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                workspace = standard_workspace(directory)
                workspace.write(path, text)
                with self.assertRaises(resolver.ScopeError):
                    resolver.load_workspace(workspace.root)

    def test_owner_is_the_longest_member_prefix(self) -> None:
        members = ["plugins/world", "plugins/world/nested", "crates/core"]
        self.assertEqual(resolver.owner("plugins/world/nested/src/a.rs", members), "plugins/world/nested")
        self.assertEqual(resolver.owner("plugins/world/src/a.rs", members), "plugins/world")
        self.assertEqual(resolver.owner("plugins/worldly/src/a.rs", members), None)
        self.assertEqual(resolver.owner("crates/core", members), "crates/core")

    # Affected set ----------------------------------------------------------

    def test_reverse_closure_follows_every_dependency_kind(self) -> None:
        self.assertEqual(self.names("crates/core/src/lib.rs"),
                         ["cli", "core", "evidence", "gate", "runtime", "store"])
        self.assertEqual(self.names("crates/store/src/lib.rs"), ["cli", "evidence", "runtime", "store"])
        self.assertEqual(self.names("apps/cli/src/main.rs"), ["cli", "evidence"])

    def test_member_manifest_and_tests_mark_the_member(self) -> None:
        self.assertEqual(self.names("crates/runtime/Cargo.toml"), ["evidence", "runtime"])
        self.assertEqual(self.names("crates/runtime/tests/a.rs", "crates/runtime/README.md"),
                         ["evidence", "runtime"])

    def test_nested_member_is_attributed_to_itself(self) -> None:
        # tool names the plugins/world directory, which holds the nested member.
        self.assertEqual(self.names("plugins/world/nested/src/lib.rs"), ["evidence", "nested", "tool"])
        self.assertNotIn("nested", self.names("plugins/world/src/lib.rs"))

    def test_library_reads_propagate_and_test_reads_do_not(self) -> None:
        # runtime's library embeds plugins/world; its dependents rerun.
        self.workspace.member("apps/user", "user", '[dependencies]\nruntime = { path = "../../crates/runtime" }\n')
        self.workspace.write(
            "Cargo.toml",
            (self.workspace.root / "Cargo.toml").read_text(encoding="utf-8").replace(
                '"apps/gate"]', '"apps/gate", "apps/user"]'),
        )
        self.assertEqual(self.names("plugins/world/src/lib.rs"),
                         ["evidence", "runtime", "tool", "user", "world"])
        # tool only reads plugins/world from a test: nothing depends on that.
        self.workspace.member("apps/tool-user", "tool-user", '[dependencies]\ntool = { path = "../tool" }\n')
        self.assertNotIn("tool-user", self.names("plugins/world/src/lib.rs"))

    def test_documentation_outside_members_runs_only_its_readers(self) -> None:
        self.assertEqual(
            self.names("crates/core/src/lib.rs", "docs/guide.md", "README.md"),
            ["cli", "core", "evidence", "gate", "runtime", "store"],
        )
        # A Markdown fixture a test embeds selects that test's member.
        self.assertEqual(self.names("fixtures/conformance/support/limits.md"), ["evidence", "tool"])

    def test_only_unread_documentation_selects_nothing_and_runs_everything(self) -> None:
        # The evidence test reads the workspace root, so it reads every path.
        self.assertEqual(self.names("docs/guide.md"), ["evidence"])
        (self.workspace.root / "apps/evidence/tests/evidence.rs").unlink()
        self.assert_full("docs/guide.md")

    def test_paths_outside_members_run_the_whole_workspace(self) -> None:
        for path in (
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            ".cargo/config.toml",
            ".config/nextest.toml",
            "clippy.toml",
            "scripts/run-isolated-test.sh",
            "fixtures/conformance/profiles/a.json",
            ".github/workflows/ci.yml",
            ".github/rust-scope.yml",
            "crates/excluded/src/lib.rs",
            "crates/new-crate/src/lib.rs",
            "crates/README.txt",
            "fuzz/fuzz_targets/a.rs",
        ):
            with self.subTest(path=path):
                self.assert_full("crates/core/src/lib.rs", path)

    def test_documentation_excludes_come_from_the_trusted_filter(self) -> None:
        self.workspace.write(".github/rust-scope.yml", "rust:\n  - '**'\n")
        self.assert_full("crates/core/src/lib.rs", "docs/guide.md")
        for text in (
            "rust:\n  - '**'\n  - !docs/**\n",
            "rust:\n  - '**'\n  - '!{a,b}/**'\n",
        ):
            with self.subTest(text=text):
                self.workspace.write(".github/rust-scope.yml", text)
                self.assertEqual(resolver.documentation_excludes(self.workspace.root), [])
        (self.workspace.root / ".github/rust-scope.yml").unlink()
        self.assertEqual(resolver.documentation_excludes(self.workspace.root), [])
        self.workspace.write(
            ".github/rust-scope.yml",
            "# comment\nrust:\n\n  - '**'\n  - \"!docs/**\"\nother:\n  - '!crates/**'\n",
        )
        patterns = resolver.documentation_excludes(self.workspace.root)
        self.assertEqual([pattern.pattern for pattern in patterns], ["docs/.*"])

    def test_repository_filter_excludes_are_read(self) -> None:
        patterns = resolver.documentation_excludes(ROOT)
        self.assertEqual(len(patterns), 6)
        for path, excluded in (
            ("README.md", True), ("docs/a/b.txt", True), (".agents/x", True),
            ("a/b.rst", True), ("Cargo.toml", False), ("docs", False),
        ):
            with self.subTest(path=path):
                self.assertEqual(any(p.fullmatch(path) for p in patterns), excluded)

    def test_glob_translation(self) -> None:
        for pattern, path, expected in (
            ("**/*.md", "README.md", True),
            ("**/*.md", "a/b/c.md", True),
            ("docs/**", "docs/a/b", True),
            ("docs/**", "docs", False),
            ("a?", "ab", True),
            ("a?b", "a/b", False),
            ("*.md", "a/b.md", False),
        ):
            with self.subTest(pattern=pattern, path=path):
                self.assertEqual(bool(resolver.glob_regex(pattern).fullmatch(path)), expected)
        for pattern in ("{a,b}", "a/[bc]", "a**b", "+(a)", "!a"):
            with self.subTest(pattern=pattern), self.assertRaises(resolver.ScopeError):
                resolver.glob_regex(pattern)

    # Source reads ----------------------------------------------------------

    def test_literal_targets(self) -> None:
        members = ["crates/core", "crates/store", "plugins/world"]
        for literal, file_dir, expected in (
            ("../../store/tests/support/x.rs", "crates/core/tests", {"crates/store/tests/support/x.rs", "store/tests/support/x.rs"}),
            ("/../store/src", "crates/core/src", {"crates/core/store/src", "crates/store/src"}),
            ("crates/store/src/lib.rs", "crates/core/tests", {"crates/store"}),
            ("./crates/store", "crates/core/tests", {"crates/store"}),
            ("../..", "crates/core/tests", {"crates", "."}),
            ("..", "crates/core/tests", set()),
            ("/..", "crates/core/src", set()),
            ("../", "crates/core/src", set()),
            ("../../../../outside", "crates/core/src", set()),
            ("crates/storehouse", "crates/core/src", set()),
            ("pkg::crates/store", "crates/core/src", {"crates/store"}),
            ("my-crates/store", "crates/core/src", set()),
        ):
            with self.subTest(literal=literal):
                self.assertEqual(
                    resolver.literal_targets(literal, file_dir, "crates/core", members),
                    expected,
                )

    def test_scan_separates_library_and_test_reads(self) -> None:
        members = resolver.load_workspace(self.workspace.root)
        reads = resolver.scan_reads(self.workspace.root, members)
        self.assertIn("plugins/world/src/lib.rs", reads.library["crates/runtime"])
        self.assertEqual(reads.tests["crates/runtime"], set())
        self.assertIn("plugins/world", reads.tests["apps/tool"])
        self.assertIn("fixtures/conformance/support/limits.md", reads.tests["apps/tool"])
        self.assertIn(".", reads.tests["apps/evidence"])
        # A member's reads of its own files are not edges.
        self.workspace.write("crates/core/src/own.rs", 'const OWN: &str = "crates/core/README.md";\n')
        reads = resolver.scan_reads(self.workspace.root, resolver.load_workspace(self.workspace.root))
        self.assertEqual(reads.library["crates/core"], set())
        # A nested member's sources belong to it, not to the enclosing member.
        self.workspace.write("plugins/world/nested/src/n.rs", 'include_str!("../../../../crates/core/x");\n')
        reads = resolver.scan_reads(self.workspace.root, resolver.load_workspace(self.workspace.root))
        self.assertIn("crates/core/x", reads.library["plugins/world/nested"])
        self.assertNotIn("crates/core/x", reads.library["plugins/world"])

    # Changed-file listing --------------------------------------------------

    def test_listing_includes_both_sides_of_a_rename(self) -> None:
        self.assertEqual(resolver.parse_listing("\n" + listing("a") + "  \n", 1), ["a"])
        self.assertEqual(
            resolver.parse_listing(listing(("crates/core/a.rs", "crates/store/a.rs"), "docs/x.md"), 2),
            ["crates/core/a.rs", "crates/store/a.rs", "docs/x.md"],
        )

    def test_listing_refuses_anything_unattributable(self) -> None:
        for label, text, expected in (
            ("count mismatch", listing("a"), 2),
            ("blank lines do not count", "\n" + listing("a") + "\n", 2),
            ("extra entry", listing("a", "b"), 1),
            ("empty", "", 0),
            ("not json", "crates/core/a.rs\n", 1),
            ("not an object", "[1]\n", 1),
            ("missing filename", '{"previous_filename": null}\n', 1),
            ("empty filename", '{"filename": ""}\n', 1),
            ("absolute", listing("/etc/passwd"), 1),
            ("parent", listing("../x"), 1),
            ("dotted", listing("crates/./core/a.rs"), 1),
            ("backslash", listing("crates\\core\\a.rs"), 1),
            ("bad previous", '{"filename": "a", "previous_filename": 3}\n', 1),
        ):
            with self.subTest(label=label), self.assertRaises(resolver.ScopeError):
                resolver.parse_listing(text, expected)

    # Command line ----------------------------------------------------------

    def test_main_prints_the_scoped_selection(self) -> None:
        lines, _ = self.run_main(listing("crates/store/src/lib.rs"), 1)
        self.assertEqual(lines, [
            "rust_packages=-p cli -p evidence -p runtime -p store",
            "rust_doc_packages=-p runtime -p store",
        ])
        lines, _ = self.run_main(listing("apps/cli/src/main.rs"), 1)
        self.assertEqual(lines, ["rust_packages=-p cli -p evidence", "rust_doc_packages=none"])

    def test_main_runs_the_workspace_whenever_unsure(self) -> None:
        for label, text, expected in (
            ("truncated", listing("crates/core/src/lib.rs"), 3000),
            ("zero", "", 0),
            ("mismatch", listing("crates/core/src/lib.rs"), 2),
            ("outside", listing("Cargo.lock"), 1),
            ("rename from outside", listing(("crates/core/a.rs", "scripts/a.rs")), 1),
        ):
            with self.subTest(label=label):
                lines, reason = self.run_main(text, expected)
                self.assertEqual(lines, ["rust_packages=--workspace", "rust_doc_packages=--workspace"])
                self.assertIn("Running the whole workspace", reason)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            resolver.main([str(self.workspace.root / "missing"), "--expected-files", "1",
                           "--root", str(self.workspace.root)])
        self.assertEqual(stdout.getvalue(), "rust_packages=--workspace\nrust_doc_packages=--workspace\n")
        (self.workspace.root / "Cargo.toml").write_text("[workspace\n", encoding="utf-8")
        lines, _ = self.run_main(listing("crates/core/src/lib.rs"), 1)
        self.assertEqual(lines, ["rust_packages=--workspace", "rust_doc_packages=--workspace"])


class RepositoryTests(unittest.TestCase):
    """The resolver against this repository's real workspace."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.members = resolver.load_workspace(ROOT)
        cls.reads = resolver.scan_reads(ROOT, cls.members)
        cls.excludes = resolver.documentation_excludes(ROOT)

    def affected(self, path: str) -> set[str]:
        found = resolver.affected_members([path], self.members, self.reads, self.excludes)
        return {self.members[member].name for member in found}

    def test_known_cross_member_reads_are_found(self) -> None:
        library = self.reads.library
        tests = self.reads.tests
        self.assertIn("plugins/world/src/lib.rs", library["crates/pos-runtime"])
        self.assertIn("apps/piglor-gateway/src/lib.rs", library["crates/pos-runtime"])
        self.assertIn("crates/pos-core/tests/support/erasure.rs", tests["crates/pos-store"])
        self.assertIn("crates/pos-store/tests/support/fae1_fixture.rs", library["crates/pos-time"])
        self.assertIn(".", tests["apps/pos-root-selector"])
        self.assertIn(".", tests["apps/pos-experiment"])
        self.assertIn("crates/pos-reference", tests["apps/pos-root-selector"])
        self.assertTrue(any(target.startswith("crates/pos-conformance/vectors/")
                            for target in library["apps/pos-sandboxd"]))
        self.assertTrue(any(target.startswith("fixtures/conformance")
                            for target in library["crates/pos-conformance"]))

    def test_leaf_changes_stay_narrow(self) -> None:
        self.assertEqual(self.affected("apps/pos-cli/src/main.rs"),
                         {"pos-cli", "pos-experiment", "pos-root-selector"})
        self.assertEqual(self.affected("crates/pos-owner-bridge-windows/src/lib.rs"),
                         {"pos-owner-bridge-windows", "piglor-owner", "pos-experiment",
                          "pos-root-selector"})

    def test_embedded_plugin_sources_reach_the_runtime_dependents(self) -> None:
        affected = self.affected("plugins/world/src/reducer.rs")
        self.assertTrue({"pos-runtime", "piglor-gateway", "pos-cli"} <= affected)

    def test_documentation_fixture_reaches_its_reader(self) -> None:
        self.assertIn("pos-conformance",
                      self.affected("fixtures/conformance/support/limitations.md"))


if __name__ == "__main__":
    unittest.main()
