#!/usr/bin/env python3
"""Adversarial tests for the ADR-110 Windows unsafe-boundary checker."""

from __future__ import annotations

import contextlib
import importlib.util
import os
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CHECKER_PATH = ROOT / "scripts" / "check_owner_bridge_unsafe_policy.py"
SPEC = importlib.util.spec_from_file_location("owner_bridge_unsafe_policy", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load owner-bridge unsafe-policy checker")
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)

SHIM = "crates/pos-owner-bridge-windows"
OPS = f"{SHIM}/src/ffi/ops.rs"
HOST = f"{SHIM}/src/host.rs"
LIB = f"{SHIM}/src/lib.rs"
INV = f"{SHIM}/unsafe-inventory.toml"
SAFE_LIB_PATH = "crates/safe/src/lib.rs"
RESERVED = f"unsafe is reserved for {SHIM}/src/ffi"
BLOCK_ONLY = "only explicit unsafe blocks in src/ffi are allowed"

ROOT_MANIFEST_TEMPLATE = '''
[workspace]
members = [@MEMBERS@]

[workspace.lints.rust]
unsafe_code = "forbid"
warnings = { level = "deny", priority = -2 }
future_incompatible = { level = "deny", priority = -1 }
rust_2024_compatibility = { level = "deny", priority = -1 }
unexpected_cfgs = { level = "warn", check-cfg = ["cfg(coverage_nightly)", "cfg(coverage)"] }
unreachable_pub = "warn"

[workspace.lints.clippy]
all = "deny"
pedantic = "deny"
nursery = "deny"
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
unimplemented = "deny"
unreachable = "deny"
dbg_macro = "deny"
print_stdout = "deny"
print_stderr = "deny"
exit = "deny"
mem_forget = "deny"
let_underscore_must_use = "deny"
'''

SHIM_MANIFEST = '''
[package]
name = "pos-owner-bridge-windows"
version = "0.1.0"

[lints.rust]
unsafe_code = "allow"
warnings = { level = "deny", priority = -2 }
future_incompatible = { level = "deny", priority = -1 }
rust_2024_compatibility = { level = "deny", priority = -1 }
unexpected_cfgs = { level = "warn", check-cfg = ["cfg(coverage_nightly)", "cfg(coverage)"] }
unreachable_pub = "warn"
unsafe_op_in_unsafe_fn = "deny"

[lints.clippy]
all = "deny"
pedantic = "deny"
nursery = "deny"
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
unimplemented = "deny"
unreachable = "deny"
dbg_macro = "deny"
print_stdout = "deny"
print_stderr = "deny"
exit = "deny"
mem_forget = "deny"
let_underscore_must_use = "deny"
undocumented_unsafe_blocks = "deny"
multiple_unsafe_ops_per_block = "deny"
'''

MEMBER_MANIFEST = '''
[package]
name = "member"
version = "0.1.0"

[lints]
workspace = true
'''

CFG = "#![cfg(windows)]\n"
FORBID = "#![forbid(unsafe_code)]\n"
SAFE_LIB = FORBID + "pub fn safe() {}\n"
SHIM_LIB = CFG + "\n//! Shim root.\n"
HOST_MODULE = CFG + FORBID + "pub fn host() {}\n"
HOSTED_TESTS = CFG + FORBID + "\n#[test]\nfn ffi_fixture() {}\n"
EMPTY_INVENTORY = "# No FFI unsafe block has been added yet.\n"


def manifest_for(members: list[str]) -> str:
    return ROOT_MANIFEST_TEMPLATE.replace("@MEMBERS@", ", ".join(f'"{member}"' for member in members))


def root_manifest(*extra_members: str) -> str:
    return manifest_for(["crates/safe", SHIM, *extra_members])


BASE_FILES: dict[str, str] = {
    "Cargo.toml": root_manifest(),
    "crates/safe/Cargo.toml": MEMBER_MANIFEST,
    SAFE_LIB_PATH: SAFE_LIB,
    f"{SHIM}/Cargo.toml": SHIM_MANIFEST,
    LIB: SHIM_LIB,
    INV: EMPTY_INVENTORY,
}


def entry(
    file: str = "src/ffi/ops.rs",
    line: int = 5,
    function: str = "call",
    hosted: str = "ffi_fixture",
) -> str:
    return (
        "[[block]]\n"
        f'file = "{file}"\n'
        f"line = {line}\n"
        f'function = "{function}"\n'
        'operation = "fixture"\n'
        'invariant = "fixture"\n'
        f'hosted_test = "{hosted}"\n'
    )


def ffi_source(*body: str) -> str:
    """Return an ffi file whose first body line is line 4."""
    inner = "".join(f"    {line}\n" for line in body)
    return f"{CFG}\npub fn call() {{\n{inner}}}\n"


STANDARD_BODY = ("// SAFETY: fixture.", "unsafe {}")


def ffi_case(*body: str, line: int = 5, inventory: str | None = None) -> dict[str, str | None]:
    """Return a fully inventoried ffi fixture whose block sits at ``line``."""
    return {
        OPS: ffi_source(*body),
        INV: entry(line=line) if inventory is None else inventory,
        f"{SHIM}/tests/ffi.rs": HOSTED_TESTS,
    }


def write(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@contextlib.contextmanager
def tree(extra: dict[str, str | None] | None = None, links: dict[str, str] | None = None) -> Iterator[Path]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for relative, content in {**BASE_FILES, **(extra or {})}.items():
            if content is not None:
                write(root, relative, content)
        for link, target in (links or {}).items():
            path = root / link
            path.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(target, path, target_is_directory=(path.parent / target).is_dir())
        yield root


def fixture(extra: dict[str, str | None] | None = None, links: dict[str, str] | None = None) -> list[str]:
    with tree(extra, links) as root:
        return CHECKER.violations(root, component_fixture=True)


def require_accepted(
    name: str, extra: dict[str, str | None] | None = None, links: dict[str, str] | None = None
) -> None:
    found = fixture(extra, links)
    if found:
        raise SystemExit(f"{name} was rejected, expected no violations: {found}")


def require_rejected(
    name: str,
    extra: dict[str, str | None],
    expected: list[str],
    *,
    prefixes: bool = False,
    links: dict[str, str] | None = None,
) -> None:
    found = fixture(extra, links)
    wanted = sorted(expected)
    matches = (
        len(found) == len(wanted) and all(actual.startswith(prefix) for actual, prefix in zip(found, wanted))
        if prefixes
        else found == wanted
    )
    if not matches:
        raise SystemExit(f"{name}: expected exactly {wanted}, got {found}")


def at(path: str, line: int, message: str) -> str:
    return f"{path}:{line}: {message}"


ROOT_FORBID = (
    f"{LIB}: crate root must not hold a crate-wide #![forbid(unsafe_code)]; forbid each non-ffi mod instead"
)
SYMLINK = "symlinks are forbidden under a scanned workspace member"
MULTI_BLOCK = "more than one unsafe block on a line; put each block on its own line so the inventory counts match"
INCLUDE_OUTSIDE = "include! must name a .rs file inside a scanned workspace member"


def nonblock(path: str, line: int, kind: str) -> str:
    return at(path, line, f"unsafe {kind} is forbidden; {BLOCK_ONLY}")


def test_masker() -> None:
    cases = (
        ("// unsafe {}", False),
        ("/// unsafe {}", False),
        ("//! unsafe {}", False),
        ("/* unsafe {} */", False),
        ("/* a /* unsafe */ unsafe {} */", False),
        ("/* a /* b */ */ unsafe {}", True),
        ('"unsafe {}"', False),
        (r'"a\"unsafe {}"', False),
        (r'"\\" unsafe {}', True),
        (r'"\\\"" unsafe {}', True),
        (r'"a\"b"; unsafe {}', True),
        ('r"unsafe {}"', False),
        ('r#"a"b unsafe {}"#', False),
        ('r###"a"## unsafe {}"###', False),
        ('r"x" unsafe {}', True),
        ('b"unsafe {}"', False),
        ('br#"unsafe {}"#', False),
        ('c"unsafe {}"', False),
        ('cr"unsafe {}"', False),
        ("'\\'' unsafe {}", True),
        ("'\\\\' unsafe {}", True),
        ("'\\\"' unsafe {}", True),
        ("'\"' unsafe {}", True),
        ("b'\\'' unsafe {}", True),
        (r'br#"a\"#; unsafe{}', True),
        ("'u' unsafe {}", True),
        ("'\\u{1F600}' unsafe {}", True),
        ("fn f<'a>(x: &'a u8) { unsafe {} }", True),
        ("let x: &'static str = 1; unsafe {}", True),
        ("let r#unsafe = 1;", False),
        ("let my_unsafe = unsafe_fn();", False),
        ("let unsafe_code = 1;", False),
    )
    for source, visible in cases:
        code = CHECKER.scan(source).code
        newlines = [index for index, character in enumerate(source) if character == "\n"]
        if len(code) != len(source) or [i for i, c in enumerate(code) if c == "\n"] != newlines:
            raise SystemExit(f"masker changed offsets for {source!r}")
        if bool(CHECKER.UNSAFE_TOKEN.search(code)) != visible:
            raise SystemExit(f"masker mishandled {source!r}: visible={not visible}, code={code!r}")
    multiline = "let s = \"a\nunsafe {}\nb\"; unsafe {}\n"
    code = CHECKER.scan(multiline).code
    if len(CHECKER.UNSAFE_TOKEN.findall(code)) != 1 or code.count("\n") != multiline.count("\n"):
        raise SystemExit(f"masker mishandled a multi-line string: {code!r}")


def test_masker_unicode_word_boundaries() -> None:
    for word in ("é", "变量", "²", "Ⅻ", "_", "𐐀"):
        prefix = f"{word}unsafe "
        raw_identifier = f"r#{word}unsafe"
        source = prefix + raw_identifier + f' {word}r"unsafe" \t;::\n  // SAFETY: kept\n'
        expected = (
            prefix
            + "_" * len(raw_identifier)
            + f" {word}r"
            + " " * len('"unsafe"')
            + " \t;::\n"
            + " " * len("  // SAFETY: kept")
            + "\n"
        )
        scanned = CHECKER.scan(source)
        assert scanned.code == expected
        assert scanned.code_lines == tuple(expected.split("\n"))
        assert scanned.comments == {1: "SAFETY: kept"}
        assert scanned.raw_identifiers == (len(prefix),)
        assert scanned.source == source
    source = "r#e\u0301unsafe r#éunsafe \u200cunsafe"
    expected = "___\u0301unsafe " + "_" * len("r#éunsafe") + " \u200cunsafe"
    assert CHECKER.scan(source).code == expected


def test_masker_run_classes_cover_the_same_unicode_characters() -> None:
    for codepoint in range(sys.maxunicode + 1):
        character = chr(codepoint)
        word = character.isalnum() or character == "_"
        symbols = not word and character not in "/\"'"
        assert (CHECKER.WORD_RUN.fullmatch(character) is not None) == word
        assert (CHECKER.CODE_SYMBOLS.fullmatch(character) is not None) == symbols


def test_accepted() -> None:
    require_accepted("clean tree")
    require_accepted(
        "unsafe in comments, strings and raw strings",
        {
            SAFE_LIB_PATH: (
                FORBID
                + "// unsafe { }\n"
                + "/* unsafe /* nested unsafe */ still comment unsafe */\n"
                + "/// unsafe doc\n"
                + "pub fn safe<'a>(text: &'a str) -> &'a str {\n"
                + '    let _a = "unsafe { }";\n'
                + '    let _b = r#"unsafe { "quoted" }"#;\n'
                + '    let _c = r##"unsafe "# still"##;\n'
                + '    let _d = b"unsafe";\n'
                + '    let _e = br#"unsafe"#;\n'
                + "    let _f = 'u';\n"
                + "    let r#unsafe = 1;\n"
                + "    text\n"
                + "}\n"
            ),
            HOST: HOST_MODULE + '// unsafe { }\nconst TEXT: &str = "unsafe { }";\n',
        },
    )
    for statement in (
        r'let s = "\""; let t = "unsafe { }";',
        r'let s = "\\"; let t = "unsafe { }";',
        r"let s = '\"'; let t = " + '"unsafe { }";',
        r"let s = '\''; let t = " + '"unsafe { }";',
        r'let s = "\\\""; let t = "unsafe { }";',
        r"let s = '\\'; let t = " + '"unsafe { }";',
        r'let s = "a\"b"; let t = "unsafe { }";',
    ):
        require_accepted(f"string state after {statement}", {SAFE_LIB_PATH: f"{FORBID}{statement}\n"})
    require_accepted("fn pointer type is not an extern definition", {SAFE_LIB_PATH: FORBID + 'type F = extern "C" fn(i32);\n'})
    require_accepted(
        "complete shim with lib.rs and an inventoried ffi module",
        {
            LIB: CFG + "\nmod ffi;\n#[forbid(unsafe_code)]\nmod host;\n#[forbid(unsafe_code)]\n#[cfg(test)]\npub(crate) mod more {}\n",
            HOST: HOST_MODULE,
            f"{SHIM}/src/ffi/mod.rs": CFG + "\nmod ops;\n",
            **ffi_case(*STANDARD_BODY),
        },
    )
    require_accepted("multi-line SAFETY comment", ffi_case("// SAFETY: first line", "// continues here.", "unsafe {}", line=6))
    require_accepted("SAFETY comment above a let statement", ffi_case("// SAFETY: fixture.", "let _value = unsafe {};"))
    require_accepted(
        "SAFETY comment above a multi-line let statement",
        ffi_case("// SAFETY: fixture.", "let _value =", "    unsafe {};", line=6),
    )
    require_accepted(
        "unsafe text in ffi comments and strings is not a block",
        ffi_case('let _text = "unsafe { fake }"; // unsafe { fake }', *STANDARD_BODY, line=6),
    )
    require_accepted("qualified inventory function", ffi_case(*STANDARD_BODY, inventory=entry(function="Surface::call")))
    require_accepted(
        "hosted test between attributes in src",
        {
            **ffi_case(*STANDARD_BODY),
            f"{SHIM}/tests/ffi.rs": None,
            LIB: CFG
            + "\n#[forbid(unsafe_code)]\n#[cfg(test)]\nmod tests {\n    #[test]\n    #[cfg(windows)]\n    pub async fn ffi_fixture() {}\n}\n",
        },
    )
    require_accepted(
        "doc comment and bracketed attributes before the cfg and forbid lines",
        {HOST: '//! Host.\n#![cfg_attr(docsrs, doc = "x]y")]\n// note\n' + CFG + "/* c */\n" + FORBID},
    )
    require_accepted("target directory beside src is skipped", {"crates/safe/target/gen.rs": "unsafe {}\n"})
    require_accepted(
        "include of a scanned sibling file",
        {SAFE_LIB_PATH: FORBID + 'include!("extra.rs");\n', "crates/safe/src/extra.rs": "pub fn extra() {}\n"},
    )
    require_accepted(
        "path attribute naming a scanned sibling file",
        {SAFE_LIB_PATH: FORBID + '#[path = "extra.rs"]\nmod extra;\n', "crates/safe/src/extra.rs": "pub fn extra() {}\n"},
    )
    require_accepted(
        "generated and manifest-relative includes in a non-shim crate",
        {
            SAFE_LIB_PATH: FORBID
            + 'include!(concat!(env!("OUT_DIR"), "/generated.rs"));\n'
            + 'include!(concat!(\n    env!("CARGO_MANIFEST_DIR"),\n    "/src/extra.rs"\n));\n',
            "crates/safe/src/extra.rs": "pub fn extra() {}\n",
        },
    )
    require_accepted("data include in a non-shim crate", {SAFE_LIB_PATH: FORBID + 'const T: &str = include_str!("../../../README");\n'})
    require_accepted(
        "clean piglor-owner member",
        {
            "Cargo.toml": root_manifest("apps/piglor-owner"),
            "apps/piglor-owner/Cargo.toml": MEMBER_MANIFEST,
            "apps/piglor-owner/src/main.rs": FORBID + "fn main() {}\n",
        },
    )
    require_accepted("form feed and line separator do not shift lines", {SAFE_LIB_PATH: FORBID + "\x0cpub fn f() {}\n"})


def test_unsafe_evasions() -> None:
    for statement in (
        r'let s = "\""; unsafe {}',
        r'let s = "\\"; unsafe {}',
        r"let s = '\"'; unsafe {}",
        r"let s = '\''; unsafe {}",
        r'let s = "\\\""; unsafe {}',
        r"let s = '\\'; unsafe {}",
        r'let s = "a\"b"; unsafe {}',
        r'let s = b"\""; unsafe {}',
        "let s = '\"'; unsafe {}",
        "let s = r#\"a\"#; unsafe {}",
        r'let s = br#"a\"#; unsafe{}',
    ):
        require_rejected(
            f"unsafe after {statement}",
            {SAFE_LIB_PATH: f"{FORBID}{statement}\n"},
            [at(SAFE_LIB_PATH, 2, RESERVED)],
        )
    require_rejected(
        "form feed, vertical tab and line separator keep line numbers",
        {SAFE_LIB_PATH: FORBID + "\x0cpub fn f() {}\n// note \x0b\nunsafe {}\n"},
        [at(SAFE_LIB_PATH, 4, RESERVED)],
    )
    require_rejected(
        "safe crate unsafe operation",
        {SAFE_LIB_PATH: "pub fn forged() { unsafe {} }\n"},
        [at(SAFE_LIB_PATH, 1, RESERVED)],
    )
    require_rejected(
        "safe crate unsafe fn",
        {SAFE_LIB_PATH: FORBID + "pub unsafe fn forged() {}\n"},
        [at(SAFE_LIB_PATH, 2, RESERVED)],
    )
    require_rejected(
        "safe crate unsafe lint override",
        {"crates/safe/Cargo.toml": MEMBER_MANIFEST + '\n[lints.rust]\nunsafe_code = "allow"\n'},
        ["crates/safe/Cargo.toml: non-shim crate configures unsafe_code"],
    )
    require_rejected(
        "unsafe in a directory named target below src",
        {"crates/safe/src/target/gen.rs": "unsafe {}\n"},
        [at("crates/safe/src/target/gen.rs", 1, RESERVED)],
    )
    require_rejected(
        "piglor-owner member is scanned",
        {
            "Cargo.toml": root_manifest("apps/piglor-owner"),
            "apps/piglor-owner/Cargo.toml": MEMBER_MANIFEST,
            "apps/piglor-owner/src/main.rs": FORBID + "fn main() { unsafe {} }\n",
        },
        [at("apps/piglor-owner/src/main.rs", 2, RESERVED)],
    )
    require_rejected(
        "unsafe in an integration test of another member",
        {"crates/safe/tests/t.rs": "unsafe {}\n"},
        [at("crates/safe/tests/t.rs", 1, RESERVED)],
    )


def test_ffi_surface() -> None:
    require_rejected(
        "unsafe fn",
        {OPS: CFG + "pub unsafe fn call() {}\n"},
        [nonblock(OPS, 2, "fn")],
    )
    require_rejected("unsafe impl", {OPS: CFG + "struct S;\nunsafe impl Send for S {}\n"}, [nonblock(OPS, 3, "impl")])
    require_rejected("unsafe trait", {OPS: CFG + "unsafe trait T {}\n"}, [nonblock(OPS, 2, "trait")])
    require_rejected("unsafe extern", {OPS: CFG + 'unsafe extern "C" {}\n'}, [nonblock(OPS, 2, "extern")])
    require_rejected(
        "unsafe no_mangle attribute",
        {OPS: CFG + "#[unsafe(no_mangle)]\npub fn f() {}\n"},
        [nonblock(OPS, 2, "attribute"), at(OPS, 2, "no_mangle creates FFI surface and is forbidden")],
    )
    for name, attribute in (
        ("no_mangle", "#[no_mangle]"),
        ("export_name", '#[export_name = "x"]'),
        ("link_section", '#[link_section = ".x"]'),
    ):
        require_rejected(
            f"{name} attribute",
            {OPS: CFG + f"{attribute}\npub fn f() {{}}\n"},
            [at(OPS, 2, f"{name} creates FFI surface and is forbidden")],
        )
    require_rejected(
        "no_mangle attribute in a safe crate",
        {SAFE_LIB_PATH: FORBID + "#[no_mangle]\npub fn f() {}\n"},
        [at(SAFE_LIB_PATH, 2, "no_mangle creates FFI surface and is forbidden")],
    )
    extern_definition = "extern fn definition creates FFI surface and is forbidden"
    require_rejected("extern C fn in the shim", {OPS: CFG + 'pub extern "C" fn f() {}\n'}, [at(OPS, 2, extern_definition)])
    require_rejected(
        "extern C fn in a safe crate",
        {SAFE_LIB_PATH: FORBID + 'pub extern "C" fn f() {}\n'},
        [at(SAFE_LIB_PATH, 2, extern_definition)],
    )
    require_rejected(
        "unsafe block in a non-ffi shim file",
        {HOST: CFG + FORBID + "pub fn host() {\n    // SAFETY: fixture.\n    unsafe {}\n}\n"},
        [at(HOST, 5, "unsafe blocks belong only in src/ffi")],
    )
    for relative, source in (
        ("tests/t.rs", CFG + FORBID + "fn t() { unsafe {} }\n"),
        ("examples/e.rs", CFG + FORBID + "fn main() { unsafe {} }\n"),
        ("benches/b.rs", CFG + FORBID + "fn b() { unsafe {} }\n"),
    ):
        require_rejected(
            f"unsafe block in shim {relative}",
            {f"{SHIM}/{relative}": source},
            [at(f"{SHIM}/{relative}", 3, "unsafe blocks belong only in src/ffi")],
        )
    require_rejected(
        "shim examples file without cfg(windows)",
        {f"{SHIM}/examples/e.rs": FORBID + "fn main() {}\n"},
        [f"{SHIM}/examples/e.rs: must start with #![cfg(windows)]"],
    )
    require_rejected(
        "shim tests file without forbid",
        {f"{SHIM}/tests/t.rs": CFG + "fn t() {}\n"},
        [f"{SHIM}/tests/t.rs: non-ffi module must forbid unsafe_code"],
    )
    for statement, kind in (
        ('#[path = "x.rs"]\nmod x;', "#[path]"),
        ('include!("x.rs");', "include!"),
        ('const X: &str = include_str!("x.txt");', "include_str!"),
        ('const X: &[u8] = include_bytes!("x.bin");', "include_bytes!"),
    ):
        require_rejected(
            f"{kind} in the shim",
            {HOST: HOST_MODULE + statement + "\n"},
            [at(HOST, 4, f"{kind} is forbidden in the shim: it can pull in files outside the scanned tree")],
        )
    for statement, kind in (
        ('include!(concat!(env!("HOME"), "/x.rs"));', "include!"),
        ('include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../outside.rs"));', "include!"),
        ('include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/missing.rs"));', "include!"),
        ("include!(concat!(\n    env!(\"HOME\"),\n    \"/x.rs\"\n));", "include!"),
        ('include!("../../outside.rs");', "include!"),
        ('#[path = "../../outside.rs"]\nmod outside;', "#[path]"),
        ('#[path = "missing.rs"]\nmod missing;', "#[path]"),
    ):
        require_rejected(
            f"{kind} outside the scanned tree in a safe crate",
            {SAFE_LIB_PATH: FORBID + statement + "\n", "crates/outside.rs": "pub fn outside() {}\n"},
            [at(SAFE_LIB_PATH, 2, f"{kind} must name a .rs file inside a scanned workspace member")],
        )


def test_headers() -> None:
    require_rejected("missing safe-module forbid", {HOST: CFG + "pub fn host() {}\n"}, [f"{HOST}: non-ffi module must forbid unsafe_code"])
    require_rejected("missing cfg(windows) in a module", {HOST: FORBID + "pub fn host() {}\n"}, [f"{HOST}: must start with #![cfg(windows)]"])
    require_rejected("missing cfg(windows) in lib.rs", {LIB: "//! Root.\n"}, [f"{LIB}: must start with #![cfg(windows)]"])
    require_rejected("missing cfg(windows) in an ffi file", {OPS: "pub fn call() {}\n"}, [f"{OPS}: must start with #![cfg(windows)]"])
    require_rejected(
        "conditional forbid is not a forbid",
        {HOST: CFG + "#![cfg_attr(windows, forbid(unsafe_code))]\n"},
        [f"{HOST}: non-ffi module must forbid unsafe_code"],
    )
    require_rejected(
        "forbid after an item is not a leading attribute",
        {HOST: CFG + "pub fn host() {}\n" + FORBID},
        [f"{HOST}: non-ffi module must forbid unsafe_code"],
    )
    require_rejected(
        "lib.rs holds a crate-wide forbid",
        {LIB: CFG + FORBID},
        [
            f"{LIB}: crate root must not hold a crate-wide #![forbid(unsafe_code)]; "
            "forbid each non-ffi mod instead"
        ],
    )
    require_rejected(
        "lib.rs mod without the attribute",
        {LIB: CFG + "\nmod ffi;\nmod host;\n", HOST: HOST_MODULE},
        [at(LIB, 4, "mod host must carry #[forbid(unsafe_code)]")],
    )
    require_rejected(
        "lib.rs pub(crate) mod with an unrelated attribute only",
        {LIB: CFG + "\n#[cfg(test)]\npub(crate) mod host;\n"},
        [at(LIB, 4, "mod host must carry #[forbid(unsafe_code)]")],
    )
    require_rejected(
        "lib.rs inline mod without the attribute",
        {LIB: CFG + "\nmod inline {}\n"},
        [at(LIB, 3, "mod inline must carry #[forbid(unsafe_code)]")],
    )


def test_lints() -> None:
    require_rejected(
        "clippy lint drift",
        {f"{SHIM}/Cargo.toml": SHIM_MANIFEST.replace('unwrap_used = "deny"', 'unwrap_used = "allow"')},
        [f"{SHIM}/Cargo.toml: [lints.clippy] differs from ADR-110 policy in unwrap_used"],
    )
    require_rejected(
        "unsafe_code forbid in the shim",
        {f"{SHIM}/Cargo.toml": SHIM_MANIFEST.replace('unsafe_code = "allow"', 'unsafe_code = "forbid"')},
        [f"{SHIM}/Cargo.toml: [lints.rust] differs from ADR-110 policy in unsafe_code"],
    )
    require_rejected(
        "missing approved shim entry",
        {f"{SHIM}/Cargo.toml": SHIM_MANIFEST.replace('unsafe_op_in_unsafe_fn = "deny"\n', "")},
        [f"{SHIM}/Cargo.toml: [lints.rust] differs from ADR-110 policy in unsafe_op_in_unsafe_fn"],
    )
    require_rejected(
        "extra shim lint entry",
        {f"{SHIM}/Cargo.toml": SHIM_MANIFEST.replace("[lints.clippy]\n", '[lints.clippy]\nindexing_slicing = "allow"\n')},
        [f"{SHIM}/Cargo.toml: [lints.clippy] differs from ADR-110 policy in indexing_slicing"],
    )
    require_rejected(
        "shim inherits workspace lints",
        {f"{SHIM}/Cargo.toml": '[package]\nname = "pos-owner-bridge-windows"\n\n[lints]\nworkspace = true\n'},
        [
            f"{SHIM}/Cargo.toml: [lints] must hold only the rust and clippy tables, found workspace",
            f"{SHIM}/Cargo.toml: [lints.clippy] is missing or not a table",
            f"{SHIM}/Cargo.toml: [lints.rust] is missing or not a table",
        ],
    )
    require_rejected(
        "shim without any lints table",
        {f"{SHIM}/Cargo.toml": '[package]\nname = "pos-owner-bridge-windows"\n'},
        [f"{SHIM}/Cargo.toml: [lints] is missing or not a table"],
    )


def test_safety_comments() -> None:
    missing = at(OPS, 5, "unsafe block lacks // SAFETY:")
    require_rejected("no comment", ffi_case("unsafe {}", line=4), [at(OPS, 4, "unsafe block lacks // SAFETY:")])
    require_rejected("unrelated comment line", ffi_case("// not a safety note", "unsafe {}"), [missing])
    require_rejected("empty SAFETY text", ffi_case("// SAFETY:", "unsafe {}"), [missing])
    require_rejected("SAFETY comment separated by a blank line", ffi_case("// SAFETY: fixture.", "", "unsafe {}", line=6), [at(OPS, 6, "unsafe block lacks // SAFETY:")])
    require_rejected("SAFETY text in a string", ffi_case('let _s = "// SAFETY: fixture.";', "unsafe {}", line=5), [missing])
    require_rejected("block comment is not a line SAFETY comment", ffi_case("/* SAFETY: fixture. */", "unsafe {}"), [missing])
    require_rejected(
        "SAFETY above an unrelated earlier statement",
        ffi_case("// SAFETY: fixture.", "let _a = 1;", "let _b = unsafe {};", line=6),
        [at(OPS, 6, "unsafe block lacks // SAFETY:")],
    )
    require_rejected(
        "SAFETY line inside a multi-line string",
        ffi_case('let _s = "', "// SAFETY: fixture.", '"; unsafe {}', line=6),
        [at(OPS, 6, "unsafe block lacks // SAFETY:")],
    )


def test_inventory() -> None:
    require_rejected(
        "ffi block missing inventory",
        {**ffi_case(*STANDARD_BODY), INV: EMPTY_INVENTORY},
        [f"{INV}: missing record for src/ffi/ops.rs:5"],
    )
    require_rejected(
        "stale inventory record",
        {INV: entry(), f"{SHIM}/tests/ffi.rs": HOSTED_TESTS},
        [f"{INV}: stale record for src/ffi/ops.rs:5"],
    )
    require_rejected(
        "record at the wrong line",
        ffi_case(*STANDARD_BODY, inventory=entry(line=4)),
        [f"{INV}: missing record for src/ffi/ops.rs:5", f"{INV}: stale record for src/ffi/ops.rs:4"],
    )
    require_rejected(
        "duplicate inventory record",
        ffi_case(*STANDARD_BODY, inventory=entry() + entry()),
        [f"{INV}: duplicate record for src/ffi/ops.rs:5"],
    )
    require_rejected(
        "missing hosted test",
        ffi_case(*STANDARD_BODY, inventory=entry(hosted="absent_test")),
        [f"{INV}: hosted test absent_test for src/ffi/ops.rs:5 is not a live #[test] function under tests/ or src/"],
    )
    for name, source in (
        ("without #[test]", CFG + FORBID + "\nfn ffi_fixture() {}\n"),
        ("ignored", CFG + FORBID + "\n#[test]\n#[ignore]\nfn ffi_fixture() {}\n"),
        ("ignored with a reason", CFG + FORBID + '\n#[ignore = "slow"]\n#[test]\nfn ffi_fixture() {}\n'),
        ("cfg'd out", CFG + FORBID + "\n#[cfg(any())]\n#[test]\nfn ffi_fixture() {}\n"),
        ("conditionally ignored", CFG + FORBID + "\n#[test]\n#[cfg_attr(windows, ignore)]\nfn ffi_fixture() {}\n"),
        ("only in a comment", CFG + FORBID + "\n// #[test]\n// fn ffi_fixture() {}\n"),
        ("test attribute is not directly attached", CFG + FORBID + "\n#[test]\nconst X: u8 = 1;\nfn ffi_fixture() {}\n"),
    ):
        require_rejected(
            f"hosted test {name}",
            {**ffi_case(*STANDARD_BODY), f"{SHIM}/tests/ffi.rs": source},
            [f"{INV}: hosted test ffi_fixture for src/ffi/ops.rs:5 is not a live #[test] function under tests/ or src/"],
        )
    require_rejected(
        "function does not enclose the block",
        ffi_case(*STANDARD_BODY, inventory=entry(function="other")),
        [f"{INV}: function other for src/ffi/ops.rs:5 does not enclose the block (enclosed by call)"],
    )
    require_rejected(
        "block outside any function",
        {
            OPS: CFG + "\nconst X: u8 = {\n    // SAFETY: fixture.\n    unsafe {};\n    1\n};\n",
            INV: entry(line=5),
            f"{SHIM}/tests/ffi.rs": HOSTED_TESTS,
        },
        [f"{INV}: function call for src/ffi/ops.rs:5 does not enclose the block (enclosed by no fn)"],
    )
    require_rejected(
        "missing inventory fields",
        {INV: '[[block]]\nfile = "src/ffi/ops.rs"\nline = 5\n'},
        [f"{INV}: block 1 is missing function, operation, invariant, hosted_test"],
    )
    for name, replacement in (
        ("zero line", ("line = 5", "line = 0")),
        ("boolean line", ("line = 5", "line = true")),
        ("empty operation", ('operation = "fixture"', 'operation = ""')),
        ("non-string invariant", ('invariant = "fixture"', "invariant = 3")),
    ):
        require_rejected(
            f"malformed inventory entry: {name}",
            {INV: entry().replace(*replacement)},
            [f"{INV}: block 1 has an invalid field"],
        )
    require_rejected("inventory block is not an array", {INV: 'block = "x"\n'}, [f"{INV}: block must be an array"])
    require_rejected("inventory block is not a table", {INV: "block = [1]\n"}, [f"{INV}: block 1 is not a table"])
    for file in ("../ops.rs", "src/ffi/../x.rs", "/etc/ops.rs", "src/host.rs", "src/ffi/ops.txt", "src/ffi\\\\ops.rs"):
        require_rejected(
            f"invalid inventory ffi path {file}",
            {INV: entry(file=file)},
            [f"{INV}: block 1 has an invalid ffi file path"],
        )
    require_rejected("missing inventory file", {INV: None}, [f"{INV}: missing unsafe inventory"])


def test_manifests() -> None:
    require_rejected(
        "malformed inventory TOML",
        {INV: "[[block\n"},
        [f"{INV}: malformed TOML: "],
        prefixes=True,
    )
    require_rejected(
        "malformed shim manifest",
        {f"{SHIM}/Cargo.toml": "[lints\n"},
        [f"{SHIM}/Cargo.toml: malformed TOML: "],
        prefixes=True,
    )
    require_rejected(
        "malformed member manifest",
        {"crates/safe/Cargo.toml": "[package\n"},
        ["crates/safe/Cargo.toml: malformed TOML: "],
        prefixes=True,
    )
    require_rejected("malformed root manifest", {"Cargo.toml": "[workspace\n"}, ["Cargo.toml: malformed TOML: "], prefixes=True)
    require_rejected("missing root manifest", {"Cargo.toml": None}, ["Cargo.toml: missing workspace manifest"])
    require_rejected(
        "shim missing from the workspace",
        {"Cargo.toml": manifest_for(["crates/safe"])},
        [f"Cargo.toml: workspace must contain {SHIM}"],
    )
    require_rejected(
        "glob workspace member",
        {"Cargo.toml": root_manifest("crates/*")},
        ["Cargo.toml: glob workspace member crates/* cannot be audited; list members explicitly"],
    )
    require_rejected(
        "missing member manifest",
        {"Cargo.toml": root_manifest("crates/ghost")},
        ["crates/ghost/Cargo.toml: workspace member manifest is missing"],
    )
    require_rejected(
        "member outside the repository",
        {"Cargo.toml": root_manifest("../outside")},
        ["Cargo.toml: workspace member ../outside is outside the repository"],
    )
    require_rejected(
        "missing shim manifest",
        {f"{SHIM}/Cargo.toml": None},
        [f"{SHIM}/Cargo.toml: workspace member manifest is missing"],
    )
    require_rejected(
        "root without workspace lint tables",
        {"Cargo.toml": root_manifest().split("[workspace.lints.rust]")[0]},
        [f"{SHIM}/Cargo.toml: cannot verify shim lint tables without root [workspace.lints.rust] and [workspace.lints.clippy]"],
    )


def test_hardening() -> None:
    require_rejected("two blocks on one line", ffi_case("// SAFETY: fixture.", "unsafe { a() }; unsafe { b() };"), [at(OPS, 5, MULTI_BLOCK)])
    require_rejected(
        "SAFETY above an earlier terminated statement",
        ffi_case("// SAFETY: fixture.", "let _a = 1;", "unsafe {};", line=6),
        [at(OPS, 6, "unsafe block lacks // SAFETY:")],
    )
    require_rejected(
        "SAFETY above an enclosing if",
        ffi_case("// SAFETY: fixture.", "if true {", "unsafe {}", "}", line=6),
        [at(OPS, 6, "unsafe block lacks // SAFETY:")],
    )
    require_rejected(
        "trailing SAFETY comment after code",
        ffi_case("let _a = 1; // SAFETY: fixture.", "unsafe {}", line=5),
        [at(OPS, 5, "unsafe block lacks // SAFETY:")],
    )
    require_accepted(
        "SAFETY above a statement continued without terminators",
        ffi_case("// SAFETY: fixture.", "let _v = id(", "    1,", "    unsafe {},", ");", line=7),
    )
    for word in ("no_mangle", "export_name", "link_section"):
        require_rejected(
            f"macro-spelled {word}",
            {SAFE_LIB_PATH: FORBID + f"macro_rules! m {{ ($a:meta) => {{ #[$a] fn f() {{}} }} }} m!({word});\n"},
            [at(SAFE_LIB_PATH, 2, f"{word} creates FFI surface and is forbidden")],
        )
    require_rejected(
        "macro-spelled extern ABI",
        {SAFE_LIB_PATH: FORBID + 'macro_rules! m { ($abi:literal) => { pub extern $abi fn f() {} } } m!("C");\n'},
        [at(SAFE_LIB_PATH, 2, "extern fn definition creates FFI surface and is forbidden")],
    )
    require_rejected(
        "OUT_DIR include escaping the output directory",
        {SAFE_LIB_PATH: FORBID + 'include!(concat!(env!("OUT_DIR"), "/../../../../outside/x.rs"));\n'},
        [at(SAFE_LIB_PATH, 2, INCLUDE_OUTSIDE)],
    )
    require_rejected(
        "OUT_DIR include in the shim",
        {HOST: HOST_MODULE + 'include!(concat!(env!("OUT_DIR"), "/g.rs"));\n'},
        [at(HOST, 4, "include! is forbidden in the shim: it can pull in files outside the scanned tree")],
    )
    require_rejected(
        "hyphenated unsafe-code lint in a member",
        {"crates/safe/Cargo.toml": MEMBER_MANIFEST + '\n[lints.rust]\n"unsafe-code" = "allow"\n'},
        ["crates/safe/Cargo.toml: non-shim crate configures unsafe_code"],
    )
    require_rejected(
        "root unsafe_code is not forbid",
        {"Cargo.toml": root_manifest().replace('unsafe_code = "forbid"', 'unsafe_code = "allow"')},
        ['Cargo.toml: [workspace.lints.rust] unsafe_code must be "forbid"'],
    )
    require_accepted(
        "root unsafe_code forbid as a table",
        {"Cargo.toml": root_manifest().replace('unsafe_code = "forbid"', 'unsafe_code = { level = "forbid" }')},
    )
    helper = {"crates/helper/Cargo.toml": MEMBER_MANIFEST.replace("member", "helper"), "crates/helper/src/lib.rs": "pub fn h() {}\n"}
    not_member = "crates/safe/Cargo.toml: path dependency ../helper must name a listed workspace member"
    require_rejected(
        "path dependency on an unlisted in-workspace crate",
        {**helper, "crates/safe/Cargo.toml": MEMBER_MANIFEST + '\n[dependencies]\nhelper = { path = "../helper" }\n'},
        [not_member],
    )
    require_rejected(
        "target-specific path dependency on an unlisted crate",
        {
            **helper,
            "crates/safe/Cargo.toml": MEMBER_MANIFEST + "\n[target.'cfg(windows)'.dev-dependencies]\nhelper = { path = \"../helper\" }\n",
        },
        [not_member],
    )
    require_rejected(
        "workspace dependency path on an unlisted crate",
        {**helper, "Cargo.toml": root_manifest() + '\n[workspace.dependencies]\nhelper = { path = "crates/helper" }\n'},
        ["Cargo.toml: path dependency crates/helper must name a listed workspace member"],
    )
    for name, manifest_path, text, dependency in (
        ("outside the workspace", "crates/safe/Cargo.toml", '\n[dependencies]\nfar = { path = "../../../far" }\n', "../../../far"),
        ("an excluded crate", "crates/safe/Cargo.toml", '\n[build-dependencies]\nghost = { path = "../ghost" }\n', "../ghost"),
        ("a subtable", "crates/safe/Cargo.toml", '\n[dependencies.helper]\npath = "../helper"\n', "../helper"),
        ("dev_dependencies", "crates/safe/Cargo.toml", '\n[dev_dependencies]\nhelper = { path = "../helper" }\n', "../helper"),
        ("patch", "Cargo.toml", '\n[patch.crates-io]\nhelper = { path = "crates/helper" }\n', "crates/helper"),
        ("replace", "Cargo.toml", '\n[replace]\n"helper:0.1.0" = { path = "crates/helper" }\n', "crates/helper"),
        ("shim dependency", f"{SHIM}/Cargo.toml", '\n[dependencies]\nhelper = { path = "../helper" }\n', "../helper"),
    ):
        base = {"Cargo.toml": root_manifest(), "crates/safe/Cargo.toml": MEMBER_MANIFEST, f"{SHIM}/Cargo.toml": SHIM_MANIFEST}[manifest_path]
        extra = {**helper, manifest_path: base + text}
        if name == "an excluded crate":
            extra["Cargo.toml"] = root_manifest().replace("members = [", 'exclude = ["crates/ghost"]\nmembers = [')
            extra["crates/ghost/Cargo.toml"] = MEMBER_MANIFEST.replace("member", "ghost")
        require_rejected(
            f"path dependency on {name}",
            extra,
            [f"{manifest_path}: path dependency {dependency} must name a listed workspace member"],
        )
    require_accepted(
        "path dependency on a scanned member",
        {"crates/safe/Cargo.toml": MEMBER_MANIFEST + '\n[dependencies]\nshim = { path = "../pos-owner-bridge-windows" }\n'},
    )
    for key, manifest_text, files, shown in (
        ("lib.path", '\n[lib]\npath = "../../../o5/l.rs"\n', {}, "../../../o5/l.rs"),
        ("bin.path", '\n[[bin]]\nname = "g"\npath = "../ghost/src/l.rs"\n', {"crates/ghost/src/l.rs": "pub fn g() {}\n"}, "../ghost/src/l.rs"),
        ("test.path", '\n[[test]]\nname = "t"\npath = "../../../o5/t.rs"\n', {}, "../../../o5/t.rs"),
        ("bench.path", '\n[[bench]]\nname = "b"\npath = "../ghost/b.rs"\n', {"crates/ghost/b.rs": "fn b() {}\n"}, "../ghost/b.rs"),
        ("example.path", '\n[[example]]\nname = "e"\npath = "src/missing.rs"\n', {}, "src/missing.rs"),
    ):
        require_rejected(
            f"{key} outside the crate directory",
            {"crates/safe/Cargo.toml": MEMBER_MANIFEST + manifest_text, **files},
            [f"crates/safe/Cargo.toml: {key} {shown} must name a .rs file inside the crate directory"],
        )
    require_rejected(
        "package.build outside the crate directory",
        {"crates/safe/Cargo.toml": MEMBER_MANIFEST.replace('version = "0.1.0"', 'version = "0.1.0"\nbuild = "../build.rs"'), "crates/build.rs": "fn main() {}\n"},
        ["crates/safe/Cargo.toml: package.build ../build.rs must name a .rs file inside the crate directory"],
    )
    require_accepted(
        "target paths inside the crate directory",
        {
            "crates/safe/Cargo.toml": MEMBER_MANIFEST.replace('version = "0.1.0"', 'version = "0.1.0"\nbuild = "build.rs"')
            + '\n[lib]\npath = "src/lib.rs"\n\n[[bin]]\nname = "b"\npath = "src/bin/b.rs"\n',
            "crates/safe/src/bin/b.rs": FORBID + "fn main() {}\n",
            "crates/safe/build.rs": FORBID + "fn main() {}\n",
        },
    )
    require_accepted(
        "a local identifier named include",
        {SAFE_LIB_PATH: FORBID + "pub fn f(include: bool) -> bool {\n    include\n}\n"},
    )
    for spelling, word in (
        ("use core::include as inc;", "include"),
        ("use std::include;", "include"),
        ("use std::include_str;", "include_str"),
        ("use core::include_bytes as b;", "include_bytes"),
        ("let _f = core::include;", "include"),
        ("use std::{include as i, vec};", "include"),
    ):
        require_rejected(
            f"aliased include: {spelling}",
            {SAFE_LIB_PATH: FORBID + spelling + "\n"},
            [at(SAFE_LIB_PATH, 2, f"{word} must only be used as the {word}! macro; an import or alias would hide the include target")],
        )
    require_accepted("byte-order mark on a shim module and the crate root", {HOST: "\ufeff" + HOST_MODULE, LIB: "\ufeff" + SHIM_LIB})
    require_accepted("combined forbid list in a module", {HOST: CFG + "#![forbid(dead_code, unsafe_code)]\n"})
    for name, source in (
        ("a forbid list", CFG + "#![forbid(unsafe_code, dead_code)]\n"),
        ("a conditional forbid", CFG + "#![cfg_attr(all(), forbid(unsafe_code))]\n"),
    ):
        require_rejected(f"crate root with {name}", {LIB: source}, [ROOT_FORBID])


def symlinks_available() -> bool:
    with tempfile.TemporaryDirectory() as directory:
        try:
            os.symlink(".", Path(directory) / "probe", target_is_directory=True)
        except (OSError, NotImplementedError):
            return False
    return True


def test_symlinks() -> None:
    if not symlinks_available():
        if sys.platform == "win32":
            print("SKIPPED symlink tests: this Windows account may not create symlinks")
            return
        raise SystemExit("symlinks cannot be created on this platform; the symlink tests must not pass silently")
    outside = {"outside/mod.rs": "pub unsafe fn evil2() {}\n"}
    require_rejected(
        "directory symlink hiding an unsafe module",
        {SAFE_LIB_PATH: FORBID + "mod sub;\n", **outside},
        [f"crates/safe/src/sub: {SYMLINK}"],
        links={"crates/safe/src/sub": "../../../outside"},
    )
    expected = [f"crates/safe/src/link: {SYMLINK}"]
    if os.name != "nt":
        expected.append(at(SAFE_LIB_PATH, 2, INCLUDE_OUTSIDE))
    require_rejected(
        "include through a symlinked directory resolves physically",
        {
            SAFE_LIB_PATH: FORBID + 'include!("link/../x.rs");\n',
            "crates/safe/src/x.rs": "pub fn x() {}\n",
            "outside/keep.rs": "pub fn keep() {}\n",
            "x.rs": "pub unsafe fn evil() {}\n",
        },
        expected,
        links={"crates/safe/src/link": "../../../outside"},
    )
    require_rejected(
        "src/ffi directory symlink in the shim",
        {"outside/ops.rs": ffi_source(*STANDARD_BODY)},
        [f"{SHIM}/src/ffi: {SYMLINK}"],
        links={f"{SHIM}/src/ffi": "../../../outside"},
    )
    require_rejected(
        "file symlink",
        {},
        [f"crates/safe/src/alias.rs: {SYMLINK}"],
        links={"crates/safe/src/alias.rs": "lib.rs"},
    )
    require_rejected(
        "workspace member reached through a symlink",
        {"Cargo.toml": root_manifest("crates/linked")},
        ["Cargo.toml: workspace member crates/linked is a symlink"],
        links={"crates/linked": "safe"},
    )
    require_rejected(
        "workspace member symlinked outside the repository",
        {"Cargo.toml": root_manifest("crates/pt")},
        ["Cargo.toml: workspace member crates/pt is a symlink"],
        links={"crates/pt": "../../pt-outside"},
    )
    require_rejected(
        "workspace member below a symlinked directory",
        {"Cargo.toml": root_manifest("crates/deep/safe")},
        ["Cargo.toml: workspace member crates/deep/safe traverses a symlink"],
        links={"crates/deep": "."},
    )


def hosted_missing() -> list[str]:
    return [f"{INV}: hosted test ffi_fixture for src/ffi/ops.rs:5 is not a live #[test] function under tests/ or src/"]


def test_hosted_liveness() -> None:
    test = "#[test]\nfn ffi_fixture() {}\n"
    for name, source in (
        ("second inner cfg(any())", CFG + "#![cfg(any())]\n" + FORBID + "\n" + test),
        ("inner cfg after items", CFG + FORBID + "\n" + test + "#![cfg(any())]\n"),
        ("inner cfg(not(windows))", CFG + "#![cfg(not(windows))]\n" + FORBID + "\n" + test),
        ("inner cfg_attr that adds a cfg", CFG + "#![cfg_attr(windows, cfg(any()))]\n" + FORBID + "\n" + test),
        ("cfg(any()) on enclosing inline mod", CFG + FORBID + "\n#[cfg(any())]\nmod m {\n    " + test.replace("\n", "\n    ") + "}\n"),
        ("cfg_attr cfg on enclosing mod", CFG + FORBID + "\n#[cfg_attr(windows, cfg(any()))]\nmod m {\n    " + test + "}\n"),
        ("inner cfg inside inline mod", CFG + FORBID + "\nmod m {\n    #![cfg(any())]\n    " + test + "}\n"),
        ("nested inside another fn", CFG + FORBID + "\nfn outer() {\n    " + test.replace("\n", "\n    ") + "}\n"),
        ("on an impl method", CFG + FORBID + "\nstruct S;\nimpl S {\n    " + test + "}\n"),
        ("inside a trait", CFG + FORBID + "\ntrait T {\n    " + test + "}\n"),
        ("fn inside a live mod", CFG + FORBID + "\nmod m {\n    fn outer() {\n        " + test + "    }\n}\n"),
        ("cfg_attr adding cfg on the test", CFG + FORBID + "\n#[test]\n#[cfg_attr(windows, cfg(any()))]\nfn ffi_fixture() {}\n"),
    ):
        require_rejected(f"hosted test {name}", {**ffi_case(*STANDARD_BODY), f"{SHIM}/tests/ffi.rs": source}, hosted_missing())
    for name, source in (
        ("at file scope", CFG + FORBID + "\n" + test),
        ("inner cfg(test)", CFG + "#![cfg(test)]\n" + FORBID + "\n" + test),
        ("inner cfg(all(test, windows))", CFG + "#![cfg(all(test, windows))]\n" + FORBID + "\n" + test),
        ("in a live inline mod", CFG + FORBID + "\n#[cfg(test)]\nmod m {\n    " + test.replace("\n", "\n    ") + "}\n"),
        ("in nested live inline mods", CFG + FORBID + "\npub mod a {\n    #[cfg(windows)]\n    mod b {\n        " + test + "    }\n}\n"),
        ("after an earlier item", CFG + FORBID + "\nfn helper() {}\nconst X: u8 = 1;\n" + test),
    ):
        require_accepted(f"hosted test {name}", {**ffi_case(*STANDARD_BODY), f"{SHIM}/tests/ffi.rs": source})
def test_review_findings() -> None:
    no_lints = '[package]\nname = "member"\nversion = "0.1.0"\n'
    for name, manifest in (("absent", no_lints), ("false", no_lints + "\n[lints]\nworkspace = false\n")):
        require_rejected(
            f"member lints.workspace {name}",
            {"crates/safe/Cargo.toml": manifest},
            ["crates/safe/Cargo.toml: non-shim crate must set [lints] workspace = true"],
        )
    asm_message = "asm! is only allowed inside an unsafe block in src/ffi"
    global_message = "creates FFI surface without an unsafe block and is forbidden"
    require_rejected(
        "global_asm in a safe crate",
        {SAFE_LIB_PATH: FORBID + 'core::arch::global_asm!("nop");\n'},
        [at(SAFE_LIB_PATH, 2, f"global_asm {global_message}")],
    )
    require_rejected(
        "aliased global_asm in the shim",
        {OPS: CFG + "use core::arch::global_asm as g;\n"},
        [at(OPS, 2, f"global_asm {global_message}")],
    )
    require_rejected(
        "naked_asm in a safe crate",
        {SAFE_LIB_PATH: FORBID + 'naked_asm!("ret");\n'},
        [at(SAFE_LIB_PATH, 2, f"naked_asm {global_message}")],
    )
    require_rejected("asm in a safe crate", {SAFE_LIB_PATH: FORBID + 'fn f() { asm!("nop"); }\n'}, [at(SAFE_LIB_PATH, 2, asm_message)])
    require_rejected(
        "asm outside an unsafe block in an ffi file",
        {OPS: CFG + 'pub fn call() {\n    asm!("nop");\n}\n'},
        [at(OPS, 3, asm_message)],
    )
    require_rejected(
        "asm in a non-ffi shim file",
        {HOST: CFG + FORBID + 'pub fn host() {\n    asm!("nop");\n}\n'},
        [at(HOST, 4, asm_message)],
    )
    require_accepted("asm inside an inventoried ffi unsafe block", ffi_case("// SAFETY: fixture.", 'unsafe { asm!("nop") }'))
    for name, attribute in (
        ("link", '#[link(name = "x")]'),
        ("spaced link", '#[ link (name = "x")]'),
        ("unsafe link", '#[unsafe(link(name = "x"))]'),
        ("cfg_attr link", '#[cfg_attr(windows, link(name = "x"))]'),
        ("bare link", "#[link]"),
    ):
        found = fixture({SAFE_LIB_PATH: FORBID + attribute + "\nextern {}\n"})
        if not any("#[link] creates FFI surface" in item for item in found):
            raise SystemExit(f"{name} attribute was not rejected: {found}")
    require_accepted("link_name is not link", {SAFE_LIB_PATH: FORBID + '#[link_name = "x"]\nfn f() {}\n'})
    require_rejected(
        "forbid of another path ending in unsafe_code",
        {HOST: CFG + "#![forbid(foo::unsafe_code)]\n"},
        [f"{HOST}: non-ffi module must forbid unsafe_code"],
    )
    require_rejected(
        "forbid of a path with a prefix word",
        {HOST: CFG + "#![forbid(my_unsafe_code)]\n"},
        [f"{HOST}: non-ffi module must forbid unsafe_code"],
    )
    require_accepted("forbid with unsafe_code among several lints", {HOST: CFG + "#![forbid(clippy::all, unsafe_code)]\n"})
    require_rejected(
        "lib.rs mod forbidden only by a foreign unsafe_code path",
        {LIB: SHIM_LIB + "#[forbid(foo::unsafe_code)]\nmod host;\n", HOST: HOST_MODULE},
        [f"{LIB}:5: mod host must carry #[forbid(unsafe_code)]"],
    )


def test_structural_rules() -> None:
    inner_test = CFG + FORBID + "\n#[test]\nfn ffi_fixture() {}\n"
    base = {**ffi_case(*STANDARD_BODY), f"{SHIM}/tests/ffi.rs": None}
    missing = hosted_missing()
    root_test = "mod tests {\n    #[test]\n    fn ffi_fixture() {}\n}\n"
    forbid = "#[forbid(unsafe_code)]\n"

    def lib(declarations: str) -> str:
        return CFG + "\n" + declarations

    for name, files in (
        ("test in a src module file that lib.rs declares", {LIB: lib(forbid + "mod host;\n"), HOST: inner_test}),
        ("orphan src file", {HOST: inner_test}),
        ("mod tests without cfg(test)", {LIB: lib(forbid + root_test)}),
        ("mod tests with cfg(windows) only", {LIB: lib(forbid + "#[cfg(windows)]\n" + root_test)}),
        ("inline mod not named tests", {LIB: lib(forbid + "#[cfg(test)]\n" + root_test.replace("mod tests", "mod other"))}),
        ("cfg_attr adding a dead cfg on mod tests", {LIB: lib(forbid + "#[cfg_attr(all(), cfg(any()))]\n#[cfg(test)]\n" + root_test)}),
        ("dead cfg on mod tests", {LIB: lib(forbid + "#[cfg(any())]\n#[cfg(test)]\n" + root_test)}),
        ("mod tests; behind a dead cfg", {LIB: lib(forbid + "#[cfg(any())]\nmod tests;\n"), f"{SHIM}/src/tests.rs": inner_test}),
        ("mod tests; without cfg(test)", {LIB: lib(forbid + "mod tests;\n"), f"{SHIM}/src/tests.rs": inner_test}),
        ("mod tests; inside an inline mod", {LIB: lib(forbid + "#[cfg(test)]\nmod x {\n    mod tests;\n}\n"), f"{SHIM}/src/tests.rs": inner_test}),
        ("mod tests; target with a dead inner cfg", {LIB: lib(forbid + "#[cfg(test)]\nmod tests;\n"), f"{SHIM}/src/tests.rs": CFG + "#![cfg(any())]\n" + FORBID + "#[test]\nfn ffi_fixture() {}\n"}),
        ("test in tests/ below a directory", {f"{SHIM}/tests/deep/x.rs": inner_test}),
        ("test in a file a tests/ file declares", {f"{SHIM}/tests/ffi.rs": CFG + FORBID + "mod support;\n", f"{SHIM}/tests/support/mod.rs": inner_test}),
        ("test in examples", {f"{SHIM}/examples/e.rs": inner_test}),
    ):
        require_rejected(f"structural hosted test: {name}", {**base, **files}, missing)
    for name, files in (
        ("inline cfg(test) mod tests in lib.rs", {LIB: lib(forbid + "#[cfg(test)]\n" + root_test)}),
        ("inline cfg(all(test, windows)) mod tests", {LIB: lib(forbid + "#[cfg(all(test, windows))]\n" + root_test)}),
        ("nested live mod in mod tests", {LIB: lib(forbid + "#[cfg(test)]\nmod tests {\n    mod inner {\n        #[test]\n        fn ffi_fixture() {}\n    }\n}\n")}),
        ("mod tests; to src/tests.rs", {LIB: lib(forbid + "#[cfg(test)]\nmod tests;\n"), f"{SHIM}/src/tests.rs": inner_test}),
        ("mod tests; to src/tests/mod.rs", {LIB: lib(forbid + "pub(crate) mod tests;\n".replace("pub(crate) mod tests;\n", "#[cfg(all(test, windows))]\npub(crate) mod tests;\n")), f"{SHIM}/src/tests/mod.rs": inner_test}),
    ):
        require_accepted(f"structural hosted test: {name}", {**base, **files})
    for name, source in (
        ("plain", "fn main() {}\n"),
        ("with cfg(windows)", CFG + FORBID + "fn main() {}\n"),
        ("with unsafe", FORBID + "fn main() { unsafe {} }\n"),
    ):
        require_rejected(f"shim build.rs {name}", {f"{SHIM}/build.rs": source}, [f"{SHIM}/build.rs: build scripts are forbidden in the shim"])
    require_rejected(
        "src/ffi.rs instead of src/ffi/mod.rs",
        {f"{SHIM}/src/ffi.rs": CFG + "\n"},
        [f"{SHIM}/src/ffi.rs: the ffi module must be src/ffi/mod.rs, not src/ffi.rs", f"{SHIM}/src/ffi.rs: non-ffi module must forbid unsafe_code"],
    )
    require_accepted("src/ffi/mod.rs is the ffi module", {f"{SHIM}/src/ffi/mod.rs": CFG + "\n"})
    # stacked dead cfgs beside a live cfg(test)
    dead_stacks = (
        "#[cfg(test)]\n#[cfg(any())]\n",
        "#[cfg(any())]\n#[cfg(test)]\n",
        "#[cfg(test)]\n#[cfg_attr(windows, cfg(any()))]\n",
        "#[cfg(test)]\n#[cfg(unix)]\n",
        "#[cfg(test)]\n#[cfg(not(windows))]\n",
    )
    for stack in dead_stacks:
        label = stack.replace("\n", " ").strip()
        require_rejected(
            f"stacked dead cfg on mod tests; {label}",
            {**base, LIB: lib(forbid + stack + "mod tests;\n"), f"{SHIM}/src/tests.rs": inner_test},
            missing,
        )
        require_rejected(
            f"stacked dead cfg on inline mod tests {label}",
            {**base, LIB: lib(forbid + stack + root_test)},
            missing,
        )
        require_rejected(
            f"stacked dead cfg on the test fn {label}",
            {**base, f"{SHIM}/tests/ffi.rs": CFG + FORBID + "\n" + stack + "#[test]\nfn ffi_fixture() {}\n"},
            missing,
        )
    require_rejected(
        "stacked dead cfg on a mod in a tests/ file's test",
        {**base, f"{SHIM}/tests/ffi.rs": CFG + FORBID + "\n#[cfg(windows)]\n#[cfg(unix)]\nmod m {\n    #[test]\n    fn ffi_fixture() {}\n}\n"},
        missing,
    )
    require_rejected(
        "stacked dead inner cfg after a live one on src/tests.rs",
        {**base, LIB: lib(forbid + "#[cfg(test)]\nmod tests;\n"), f"{SHIM}/src/tests.rs": CFG + "#![cfg(test)]\n#![cfg(unix)]\n" + FORBID + "#[test]\nfn ffi_fixture() {}\n"},
        missing,
    )
    require_accepted(
        "stacked live cfgs",
        {**base, LIB: lib(forbid + "#[cfg(test)]\n#[cfg(windows)]\n#[cfg(all(test, windows))]\n" + root_test)},
    )
    # (e) nested mod inside an already-forbidden inline mod needs no redundant forbid
    require_accepted("nested mod inherits the forbid", {LIB: lib(forbid + "mod a {\n    mod b;\n}\n"), f"{SHIM}/src/a/b.rs": HOST_MODULE})
    require_rejected(
        "mod inside a fn body in lib.rs still needs its own forbid",
        {LIB: lib("fn f() {\n    mod b;\n}\n")},
        [f"{LIB}:4: mod b must carry #[forbid(unsafe_code)]"],
    )
    # (a) macros that could hide items or tests, and macro definitions, raw identifiers
    macro_message = "with items or attributes in its arguments is forbidden in the shim: it can hide never-compiled tests or modules"
    for name, source, line, expected in (
        ("paren macro hiding a test", "d!( #[test] fn ffi_fixture() {} );\n", 4, f"macro d! {macro_message}"),
        ("bracket macro hiding a test", "d![ #[test] fn ffi_fixture() {} ];\n", 4, f"macro d! {macro_message}"),
        ("brace macro hiding a mod", "d! { mod x; }\n", 4, f"macro d! {macro_message}"),
        ("paren macro hiding a forbidden mod", "d!( #[forbid(unsafe_code)] mod x; );\n", 4, f"macro d! {macro_message}"),
        ("spaced bang", "d ! ( fn f() {} );\n", 4, f"macro d! {macro_message}"),
        ("path macro", "crate::d!(fn f() {});\n", 4, f"macro d! {macro_message}"),
        ("macro_rules brace", "macro_rules! d { () => {}; }\n", 4, "macro_rules definitions are forbidden in the shim"),
        ("macro_rules paren", "macro_rules! d ( () => ( mod x; ) );\n", 4, "macro_rules definitions are forbidden in the shim"),
        ("macro 2.0 definition", "pub macro d() {}\n", 4, "macro definitions are forbidden in the shim"),
        ("raw identifier in an attribute", "#[r#cfg(any())]\nfn f() {}\n", 4, "raw identifiers are forbidden in the shim"),
        ("raw ignore", "#[r#ignore]\nfn f() {}\n", 4, "raw identifiers are forbidden in the shim"),
        ("raw path", '#[r#path = "x.rs"]\nfn f() {}\n', 4, "raw identifiers are forbidden in the shim"),
        ("raw identifier as a name", "fn r#type() {}\n", 4, "raw identifiers are forbidden in the shim"),
    ):
        found = fixture({HOST: HOST_MODULE + source})
        line_prefix = f"{HOST}:{line}: "
        if not any(item.startswith(line_prefix) and expected in item for item in found):
            raise SystemExit(f"shim {name} not rejected as '{expected}': {found}")
    require_accepted(
        "benign macros, bang operators and a raw string",
        {HOST: HOST_MODULE + 'pub fn m(a: u8) -> bool {\n    let _s = r#"x"#;\n    let b = !(a == 1);\n    b && a != 2 && matches!(a, 3 | 4)\n}\n'},
    )
    require_accepted("raw identifier outside the shim", {SAFE_LIB_PATH: FORBID + "pub fn r#type() {}\n"})

    # (b), (c) and the manifest allowlist
    reasons = {
        "package.autobins": ('version = "0.1.0"\n', 'version = "0.1.0"\nautobins = false\n'),
        "package.autolib": ('version = "0.1.0"\n', 'version = "0.1.0"\nautolib = false\n'),
        "package.autotests": ('version = "0.1.0"\n', 'version = "0.1.0"\nautotests = false\n'),
        "package.autoexamples": ('version = "0.1.0"\n', 'version = "0.1.0"\nautoexamples = false\n'),
        "package.autobenches": ('version = "0.1.0"\n', 'version = "0.1.0"\nautobenches = false\n'),
        "package.build": ('version = "0.1.0"\n', 'version = "0.1.0"\nbuild = "build.rs"\n'),
        "package.default-run": ('version = "0.1.0"\n', 'version = "0.1.0"\ndefault-run = "x"\n'),
    }
    for key, (old, new) in reasons.items():
        require_rejected(
            f"shim manifest {key}",
            {f"{SHIM}/Cargo.toml": SHIM_MANIFEST.replace(old, new)},
            [f"{SHIM}/Cargo.toml: {key} is not allowed in the shim manifest"],
        )
    require_rejected(
        "shim manifest dotted autobins",
        {f"{SHIM}/Cargo.toml": SHIM_MANIFEST.replace('version = "0.1.0"\n', 'version = "0.1.0"\nautobins.workspace = true\n')},
        [f"{SHIM}/Cargo.toml: package.autobins is not allowed in the shim manifest"],
    )
    require_rejected(
        "shim manifest inline package table",
        {f"{SHIM}/Cargo.toml": SHIM_MANIFEST.replace('[package]\nname = "pos-owner-bridge-windows"\nversion = "0.1.0"\n', 'package = { name = "pos-owner-bridge-windows", version = "0.1.0", autolib = false }\n')},
        [f"{SHIM}/Cargo.toml: package.autolib is not allowed in the shim manifest"],
    )
    for table, key, line in (
        ("lib", "test", "test = false"),
        ("lib", "harness", "harness = false"),
        ("lib", "path", 'path = "src/lib.rs"'),
        ("lib", "doctest", "doctest = false"),
        ("lib", "required-features", 'required-features = ["x"]'),
        ("test", "test", "test = false"),
        ("test", "harness", "harness = false"),
        ("test", "path", 'path = "src/ffi/a.rs"'),
        ("test", "required-features", 'required-features = ["x"]'),
        ("bin", "required-features", 'required-features = ["x"]'),
        ("bin", "path", 'path = "src/b.rs"'),
        ("bin", "test", "test = false"),
        ("bench", "required-features", 'required-features = ["x"]'),
        ("bench", "harness", "harness = false"),
        ("example", "path", 'path = "src/b.rs"'),
    ):
        header = "[lib]" if table == "lib" else f'[[{table}]]\nname = "ffi"'
        require_rejected(
            f"shim manifest {table}.{key}",
            {f"{SHIM}/Cargo.toml": SHIM_MANIFEST + f"\n{header}\n{line}\n"},
            [f"{SHIM}/Cargo.toml: {table}.{key} is not allowed in the shim manifest"],
        )
    require_rejected(
        "shim manifest dotted lib key",
        {f"{SHIM}/Cargo.toml": "lib.test = false\n" + SHIM_MANIFEST},
        [f"{SHIM}/Cargo.toml: lib.test is not allowed in the shim manifest"],
    )
    require_rejected(
        "shim manifest inline test array",
        {f"{SHIM}/Cargo.toml": 'test = [{ name = "ffi", harness = false }]\n' + SHIM_MANIFEST},
        [f"{SHIM}/Cargo.toml: test.harness is not allowed in the shim manifest"],
    )
    require_rejected(
        "shim manifest non-table lib",
        {f"{SHIM}/Cargo.toml": "lib = 1\n" + SHIM_MANIFEST},
        [f"{SHIM}/Cargo.toml: lib must be a table"],
    )
    require_rejected(
        "shim manifest test is not an array of tables",
        {f"{SHIM}/Cargo.toml": "test = 1\n" + SHIM_MANIFEST},
        [f"{SHIM}/Cargo.toml: test must be an array of tables"],
    )
    require_rejected(
        "shim manifest unknown top-level key",
        {f"{SHIM}/Cargo.toml": SHIM_MANIFEST + "\n[profile.dev]\nopt-level = 1\n"},
        [f"{SHIM}/Cargo.toml: top-level key profile is not allowed in the shim manifest"],
    )
    require_accepted(
        "shim manifest with named plain targets",
        {f"{SHIM}/Cargo.toml": SHIM_MANIFEST + '\n[lib]\nname = "pos_owner_bridge_windows"\ncrate-type = ["rlib"]\n\n[[test]]\nname = "ffi"\n\n[[bin]]\nname = "b"\n'},
    )


def run_cli(extra: dict[str, str | None] | None = None) -> subprocess.CompletedProcess[str]:
    with tree(extra) as root:
        return subprocess.run(
            [sys.executable, str(CHECKER_PATH), "--root", str(root)],
            capture_output=True,
            text=True,
            check=False,
        )


def test_windows_case_insensitive_source_suffix_cannot_hide_code() -> None:
    for suffix in [".RS", ".Rs", ".rS"]:
        path = f"{SHIM}/src/ffi/bypass{suffix}"
        require_rejected("noncanonical native Rust suffix", {path: CFG + "unsafe fn bypass() {}\n"}, [
            f"{path}: Rust source suffix must be canonical .rs",
            at(path, 2, f"unsafe fn is forbidden; {BLOCK_ONLY}"),
        ])
        path = f"crates/safe/src/bypass{suffix}"
        require_rejected("uppercase source is still scanned", {path: FORBID + "fn bypass() { unsafe {} }\n"}, [
            at(path, 2, RESERVED),
        ])


def test_forbidden_webview_authority() -> None:
    names = [
        "ExecuteScript", "ExecuteScriptWithResult", "AddScriptToExecuteOnDocumentCreated",
        "CallDevToolsProtocolMethod", "CallDevToolsProtocolMethodWithSessionId",
        "GetDevToolsProtocolEventReceiver", "AddBrowserExtension",
        "WebMessageReceived", "add_WebMessageReceived", "WebMessageReceivedEventHandler",
        "PostWebMessageAsJson", "PostWebMessageAsString", "ICoreWebView2Frame",
        "ICoreWebView2Frame4", "ICoreWebView2Frame10", "wait_for_async_operation",
    ]
    for name in names:
        for statement in [f"view.{name}();", f"use sdk::{name} as alias;"]:
            source = HOST_MODULE + f"fn forbidden() {{ {statement} }}\n"
            line = source[:source.index(name)].count("\n") + 1
            require_rejected(
                f"forbidden WebView authority {name}", {HOST: source},
                [at(HOST, line, f"forbidden owner WebView API {name}")],
            )
    require_accepted("API names in comments and data", {
        HOST: HOST_MODULE + '// ExecuteScript /* WebMessageReceived */\n'
        + 'const NOTE: &str = r#"CallDevToolsProtocolMethod AddBrowserExtension"#;\n'
        + 'fn allowed() { view.PostSharedBufferToScript(); view.add_FrameCreated(); }\n',
    })
    require_accepted("scope stays within native shim", {
        SAFE_LIB_PATH: FORBID + 'pub fn ExecuteScript() {}\n',
    })


def test_cli() -> None:
    clean = subprocess.run(
        [sys.executable, str(CHECKER_PATH), "--root", str(ROOT)],
        capture_output=True,
        text=True,
        check=False,
    )
    if clean.returncode != 0 or "owner-bridge Windows unsafe policy holds" not in clean.stdout:
        raise SystemExit(f"CLI rejected a clean tree: {clean}")
    incomplete = run_cli()
    if incomplete.returncode == 0 or "owned-parent" not in incomplete.stderr:
        raise SystemExit(f"CLI accepted a component fixture as a complete project: {incomplete}")
    dirty = run_cli({SAFE_LIB_PATH: FORBID + "fn f() { unsafe {} }\n", HOST: FORBID + CFG + "pub fn host() {}\n"})
    expected = [at(SAFE_LIB_PATH, 2, RESERVED)]
    lines = dirty.stderr.strip().splitlines()
    if dirty.returncode == 0 or dirty.stdout or any(line not in lines for line in expected):
        raise SystemExit(f"CLI did not report the expected violation {expected}: {dirty}")
    malformed = run_cli({INV: "[[block\n"})
    if malformed.returncode == 0 or "Traceback" in malformed.stderr or "malformed TOML" not in malformed.stderr:
        raise SystemExit(f"CLI did not report malformed TOML cleanly: {malformed}")


def test_control_observations_cannot_ship_in_product_builds() -> None:
    path = f"{SHIM}/src/ffi/events/control_fixture.rs"
    parent = f"{SHIM}/src/ffi/events/mod.rs"
    require_accepted("test-only control readbacks", {
        path: CFG + "#![cfg(test)]\nfn readback() { args.Cancel(output); }\n",
        parent: CFG + "#[cfg(test)]\nmod control_fixture;\n",
    })
    require_rejected("product control readback helper", {path: CFG}, [
        f"{path}: ADR-131 control observations require file-scope cfg(test)",
    ])
    for declaration in ["mod control_fixture;", "#[cfg(test)]\npub mod control_fixture;"]:
        require_rejected("exported or product control fixture", {parent: CFG + declaration}, [
            f"{parent}: ADR-131 control_fixture must be a private cfg(test) module",
        ])
    for call in ["args.Cancel(output)", "ICoreWebView2PermissionRequestedEventArgs::State(args, output)", "args.ProcessFailedKind(output)"]:
        require_rejected("relocated native observation", {OPS: CFG + f"fn readback() {{ {call}; }}\n"}, [
            at(OPS, 2, "ADR-131 control readback belongs only in control_fixture"),
        ])


def test_owned_process_fault_authority() -> None:
    path = ROOT / SHIM / "src/ffi/process_fault.rs"
    original = path.read_text()
    if not CHECKER._reviewed_fault_code(CHECKER.scan(original).code):
        raise SystemExit("the reviewed process fault source is not admitted")
    mutations = {
        "arbitrary pid": ("let pid = select(&first, kind)?;", "let pid = 1234;"),
        "extra rights": ("PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,", "PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | 0x400,"),
        "wrong exit code": ("const FAULT_EXIT: u32 = 0x535;", "const FAULT_EXIT: u32 = 0;"),
        "disabled authority": ("if !authority.valid()", "if false"),
        "removed empty-state recheck": ("buffers.ok_or(())?.load_state().map_err(|_| ())?", "0"),
        "removed pending-controller recheck": ("pending_controller.ok_or(())?.succeeded().is_some()", "false"),
        "incomplete second snapshot accepted": ("let second = observe()?;", "let second = observe().unwrap_or_default();"),
        "first snapshot failure swallowed": ("let first = observe()?;", "let first = observe().unwrap_or_default();"),
        "writing-state recheck": ("ControlState::Writing as u32", "ControlState::Empty as u32"),
        "ready-state recheck": ("ControlState::Ready as u32", "ControlState::Empty as u32"),
        "consuming-state recheck": ("ControlState::Consuming as u32", "ControlState::Empty as u32"),
        "different source": ("candidates(environment)?", "other_candidates(environment)?"),
        "indirect termination": ("TerminateProcess(handle, FAULT_EXIT)", "hidden(handle, FAULT_EXIT)"),
        "ambiguous renderer treated as absence": ("if matches.next().is_some() {\n        return Err(());", "if matches.next().is_some() {\n        return Ok(None);"),
        "second renderer snapshot suppressed": ("select_optional(&second, COREWEBVIEW2_PROCESS_KIND_RENDERER)? != renderer", "false"),
        "membership gate suppressed": ("select(&second, kind)? != pid", "false"),
        "fault call evidence suppressed": ("authority.record(crate::ProcessFaultMark::TerminationCall);", ""),
        "selected process evidence suppressed": ("authority.record(crate::ProcessFaultMark::Selected(observed));", ""),
        "late identity requery restored": ("fn exit_code(&self) -> Result<Option<u32>, ()> {\n        self.retained.exit_code()\n    }", "fn exit_code(&self) -> Result<Option<u32>, ()> {\n        self.verified_exit_code()\n    }"),
        "required earlier identity query removed": ("fn observe(&self) -> Result<Option<u32>, ()> {\n        self.verified_exit_code()\n    }", "fn observe(&self) -> Result<Option<u32>, ()> {\n        self.retained.exit_code()\n    }"),
        "required identity mismatch accepted": ("if identity != expected {", "if false {"),
        "required image mismatch accepted": ("if image != expected_image {", "if false {"),
    }
    for name, (old, new) in mutations.items():
        if old not in original:
            raise SystemExit(f"missing adversarial mutation target: {name}")
        changed = original.replace(old, new, 1)
        if CHECKER._reviewed_fault_code(CHECKER.scan(changed).code):
            raise SystemExit(f"process fault policy accepted {name}")
    helper = f"{SHIM}/src/ffi/process_fault.rs"
    for text in (original.replace("#![cfg(test)]", "", 1),):
        found = fixture({helper: text})
        if f"{helper}: process fault helper requires file-scope cfg(test)" not in found:
            raise SystemExit(f"product fault helper was accepted: {found}")
    parent = f"{SHIM}/src/ffi/mod.rs"
    for declaration in ("mod process_fault;", "#[cfg(test)]\npub mod process_fault;"):
        found = fixture({parent: CFG + declaration})
        if f"{parent}: process_fault must be a private cfg(test) module" not in found:
            raise SystemExit(f"product or exported fault module was accepted: {found}")
    for api in ("TerminateProcess", "PROCESS_TERMINATE", "GetProcessInfos", "GetExitCodeProcess"):
        source = CFG + f"fn forbidden() {{ {api}(); }}\n"
        found = fixture({OPS: source})
        message = at(OPS, 2, "process fault authority belongs only in the test helper")
        if message not in found:
            raise SystemExit(f"relocated fault authority {api} was accepted: {found}")
    # Removing any recorded event or the pre-cleanup evidence gate changes
    # the reviewed fixture and must be rejected even if the test still exists.
    fixture_path = ROOT / SHIM / "src/adapter/native_tests/process_fault.rs"
    fixture_source = fixture_path.read_text()
    surface_path = ROOT / SHIM / "src/adapter/surface/mod.rs"
    files = {
        "src/ffi/session.rs": (ROOT / SHIM / "src/ffi/session.rs").read_text(),
        "src/adapter/surface/mod.rs": surface_path.read_text(),
        "src/adapter/native_tests/process_fault.rs": fixture_source,
        "src/adapter/native_tests/retirement.rs": (ROOT / SHIM / "src/adapter/native_tests/retirement.rs").read_text(),
    }
    for old, new in (
        ("ProcessFaultMark::ExitCode(code)", "ProcessFaultMark::TerminationCall"),
        ("self.evidence_complete = true;", "self.evidence_complete = false;"),
        (".posted_fault_event(target)", ".posted_fault_event(ProcessFaultTarget::Browser)"),
        ("ProcessFaultMark::ControllerCompletion(success)", "ProcessFaultMark::TerminationCall"),
        ("self.on_consuming().is_err()", "false"),
        ("let won = self.inner.borrow().reply_compare_exchange(current, new)?;", "let won = true;"),
        ("Ok(won)", "Ok(true)"),
        ("self.inner.write_record(record)", "Ok(())"),
        ("decoded.browser_pid() != browser.browser_pid", "false"),
        (".push(ProcessFaultMark::RecordWritten)", ".push(ProcessFaultMark::TerminationCall)"),
        ("previous.len() != usize::from(point.post() - 1) * 2", "false"),
        ("self.prior_native_wipe = true;", "self.prior_native_wipe = false;"),
        ("pos_owner_bridge::ceremony::timing::FAST_POLL", "std::time::Duration::ZERO"),
        ("match self.surface.pending_opening_completion() {", "match Some(true) {"),
        ("self.surface.pending_opening_completion().is_none()", "true"),
        ("controller_held_before_exit(&crate::Native::callback_order())", "true"),
        ("Instant::now() >= self.deadline", "false"),
        (".arm_exit_capture(", ".arm_exit_capture_disabled("),
        ("self.observe_exit_control(deadline)?;", "self.evidence_complete = true;"),
        ("!self.surface.matching_exit_event()", "false"),
    ):
        if old not in fixture_source:
            raise SystemExit(f"missing ordered-evidence mutation target: {old}")
        changed = dict(files)
        changed["src/adapter/native_tests/process_fault.rs"] = fixture_source.replace(old, new, 1)
        scans = {}
        for relative, text in changed.items():
            scanned = CHECKER.scan(text)
            scans[relative] = (scanned, CHECKER._attributes(scanned.code))
        found = []
        CHECKER._check_fault_authority(ROOT, scans, found)
        if f"{SHIM}/src/adapter/native_tests/process_fault.rs: process fault fixture differs from reviewed sealed caller" not in found:
            raise SystemExit(f"ordered evidence mutation was accepted: {old}: {found}")
    # AwaitingLoad can advance during process discovery. The final retained
    # event guard and the fixture's pre-fault phase observation are both bound.
    for relative, old, new, expected in (
        ("src/adapter/surface/mod.rs", "&& events.loaded().is_none()", "&& true", "process fault authority function inject_awaiting_load_fault differs from reviewed code"),
        ("src/adapter/surface/mod.rs", "&& events.started().is_none()", "&& true", "process fault authority function inject_navigating_fault differs from reviewed code"),
        ("src/adapter/surface/mod.rs", "state.generation != u32::from(point.post())", "state.generation != 1", "process fault authority function posted_retry_fault_state differs from reviewed code"),
        ("src/adapter/surface/mod.rs", "self.activation_error.is_some()", "false", "process fault authority function before_record_fault_state differs from reviewed code"),
        ("src/adapter/surface/mod.rs", "generation != 1 || posts != 0", "generation != 1", "process fault authority function awaiting_load_fault_state differs from reviewed code"),
        ("src/adapter/native_tests/process_fault.rs", ".inject_awaiting_load_fault(ProcessFaultTarget::Browser, seal)", ".inject_exit_fault(seal)", "process fault fixture differs from reviewed sealed caller"),
    ):
        changed = dict(files)
        if old not in changed[relative]:
            raise SystemExit(f"missing awaiting-load mutation target: {old}")
        changed[relative] = changed[relative].replace(old, new, 1)
        scans = {}
        for item, text in changed.items():
            scanned = CHECKER.scan(text)
            scans[item] = (scanned, CHECKER._attributes(scanned.code))
        found = []
        CHECKER._check_fault_authority(ROOT, scans, found)
        if f"{SHIM}/{relative}: {expected}" not in found:
            raise SystemExit(f"awaiting-load authority mutation was accepted: {old}: {found}")
    # Each new phase must classify ProcessFailed through completed retirement.
    for function in ("run_awaiting_load", "run_navigating", "run_posted_empty", "run_first_opening_browser", "run_posted_writing", "run_posted_ready", "run_posted_retry", "run_consuming", "run_before_record"):
        start = fixture_source.find(f"fn {function}(")
        end = fixture_source.find("\n}", start)
        body = fixture_source[start:end]
        marker = ("finish_failed_case(" if function in (
            "run_awaiting_load", "run_navigating", "run_posted_empty", "run_before_record",
            "run_posted_writing", "run_posted_ready", "run_posted_retry",
        ) else "check_final_process_failures(")
        if start < 0 or end < 0 or marker not in body:
            raise SystemExit(f"missing final process failure classifier: {function}")
        mutated = body.replace(marker, "discard_final_assessment(", 1)
        changed = dict(files)
        changed["src/adapter/native_tests/process_fault.rs"] = fixture_source[:start] + mutated + fixture_source[end:]
        scans = {}
        for relative, text in changed.items():
            scanned = CHECKER.scan(text)
            scans[relative] = (scanned, CHECKER._attributes(scanned.code))
        found = []
        CHECKER._check_fault_authority(ROOT, scans, found)
        expected = f"{SHIM}/src/adapter/native_tests/process_fault.rs: process fault fixture differs from reviewed sealed caller"
        if expected not in found:
            raise SystemExit(f"final process failure classifier bypass was accepted: {function}: {found}")
    finish = fixture_source[fixture_source.find("fn finish_failed_case("):]
    if not 0 <= finish.find("self.retire(") < finish.find("check_final_process_failures("):
        raise SystemExit("shared failed-case classification must follow retirement")
    for old, new in (
        ("self.retire(", "self.discard_retire("),
        ("check_final_process_failures(finish.actual_fault", "discard_final_process_failures(finish.actual_fault"),
        ("controller_invoked_after_exit(", "discard_callback_order("),
        ("RendererPresence::Absent", "RendererPresence::Unique"),
        ("sdk_controller_result(&order, callback)", "true"),
        ("self.surface.controller_creation_retention(ceremony) == Some(Abandoned)", "true"),
        ("self.surface.abandoned_completed_browser(ceremony).ok()", "None"),
        ("|| !sdk_success", "|| false"),
        ("|| !self.retirement.no_resurrection", "|| false"),
        ("Some(EnvironmentSdkOutcome::NativeFailure) if self.obstruct", "Some(EnvironmentSdkOutcome::NativeFailure)"),
        ("Some(EnvironmentSdkOutcome::InitiationRefused) if self.obstruct", "Some(EnvironmentSdkOutcome::InitiationRefused)"),
        ("result.map_err(|()| query_error)?.ok_or(pending_error)", "Ok(0)"),
        ("nonzero_reply_zeroing_observed(&observations)", "true"),
        ("if !self.evidence_complete || self.result_error.is_none()", "if false"),
        ("|| !successful_close_observed(self.close)", "|| false"),
        ("|| !native_zeroing_observed(self.zero_observations)", "|| false"),
    ):
        if old not in fixture_source:
            raise SystemExit(f"missing new evidence mutation target: {old}")
        changed = dict(files)
        changed["src/adapter/native_tests/process_fault.rs"] = fixture_source.replace(old, new, 1)
        scans = {}
        for relative, text in changed.items():
            scanned = CHECKER.scan(text)
            scans[relative] = (scanned, CHECKER._attributes(scanned.code))
        found = []
        CHECKER._check_fault_authority(ROOT, scans, found)
        if f"{SHIM}/src/adapter/native_tests/process_fault.rs: process fault fixture differs from reviewed sealed caller" not in found:
            raise SystemExit(f"new evidence bypass accepted: {old}: {found}")
    # The ordered evidence must come from the actual SDK handlers and a
    # bounded test-only recorder, not an invented event or a comment decoy.
    for relative, old, new, expected in (
        ("src/ffi/creation.rs", "result.is_ok(),", "true,", "callback invocation differs from reviewed SDK path"),
        ("src/ffi/creation.rs", "classify_creation(hr.is_err(), value.is_some())", "classify_creation(false, value.is_some())", "callback invocation differs from reviewed SDK path"),
        ("src/ffi/creation.rs", "failed && present", "false", "callback invocation differs from reviewed SDK path"),
        ("src/ffi/creation.rs", "crate::CreationCallback::NativeFailure", "crate::CreationCallback::Success", "callback invocation differs from reviewed SDK path"),
        ("src/ffi/environment.rs", "crate::Native::record_callback(", "crate::Native::discard_callback(", "callback invocation differs from reviewed SDK path"),
        ("src/ffi/environment.rs", "super::events::observe(observed.as_ref(), EventKind::BrowserExited, result);", "let _ignored = result;", "callback invocation differs from reviewed SDK path"),
        ("src/ffi/environment.rs", "crate::Native::record_callback(crate::NativeCallbackMoment::BrowserExit(*pid));", "super::events::observe(observed.as_ref(), EventKind::BrowserExited, Ok(NativeEvent::BrowserExited { pid: *pid })); crate::Native::record_callback(crate::NativeCallbackMoment::BrowserExit(*pid));", "callback invocation differs from reviewed SDK path"),
        ("src/lib.rs", "if order.len() < 64", "if order.len() < 640", "callback ordering recorder differs from reviewed test-only code"),
    ):
        changed = dict(files)
        text = (ROOT / SHIM / relative).read_text()
        if old not in text:
            raise SystemExit(f"missing callback evidence mutation target: {old}")
        changed[relative] = text.replace(old, new, 1)
        scans = {}
        for item, source in changed.items():
            scanned = CHECKER.scan(source)
            scans[item] = (scanned, CHECKER._attributes(scanned.code))
        found = []
        CHECKER._check_fault_authority(ROOT, scans, found)
        if f"{SHIM}/{relative}: {expected}" not in found:
            raise SystemExit(f"callback evidence bypass accepted: {relative}: {found}")
    root_target = 'root.join("environment-obstruction")'
    if root_target not in fixture_source:
        raise SystemExit("missing UDF fixture root literal")
    changed = dict(files)
    changed["src/adapter/native_tests/process_fault.rs"] = fixture_source.replace(
        root_target, 'root.join("../other") /* root.join("environment-obstruction") */', 1)
    scans = {}
    for relative, source in changed.items():
        scanned = CHECKER.scan(source)
        scans[relative] = (scanned, CHECKER._attributes(scanned.code))
    found = []
    CHECKER._check_fault_authority(ROOT, scans, found)
    if f"{SHIM}/src/adapter/native_tests/process_fault.rs: UDF obstruction root must use its fixed fixture child" not in found:
        raise SystemExit(f"UDF root substitution was accepted: {found}")
    root_path = "src/adapter/native_tests.rs"
    root_source = (ROOT / SHIM / root_path).read_text()
    for old, new, expected in (
        ('"piglor-native-{}-{}-{}"', '"../escape-{}-{}-{}"', "fixture root must use its fixed temporary name"),
        ('crate::create_private_directory(&path)?', 'std::fs::create_dir_all(&path)?', "fixture root differs from reviewed private temporary directory"),
    ):
        if old not in root_source:
            raise SystemExit(f"missing fixture provenance mutation target: {old}")
        changed = dict(files)
        changed[root_path] = root_source.replace(old, new, 1)
        scans = {}
        for relative, source in changed.items():
            scanned = CHECKER.scan(source)
            scans[relative] = (scanned, CHECKER._attributes(scanned.code))
        found = []
        CHECKER._check_fault_authority(ROOT, scans, found)
        if f"{SHIM}/{root_path}: {expected}" not in found:
            raise SystemExit(f"fixture provenance bypass accepted: {old}: {found}")
    # Both refusal probes must use the real Surface and preserve its retained
    # folder, window, ceremony and pre-buffer state around the attempt.
    for relative, old, new, expected in (
        ("src/adapter/native_tests/process_fault.rs", "fixture.pre_environment_competitor_blocked(", "fixture.discard_competitor_check(", "process fault fixture differs from reviewed sealed caller"),
        ("src/adapter/surface/mod.rs", "!self.native.window().ok()?.exists", "false", "process fault authority function pre_environment_retention differs from reviewed code"),
        ("src/adapter/surface/mod.rs", "opening != spec || self.failed_open", "false", "competing-admission observation open differs from reviewed code"),
        ("src/ffi/session.rs", "self.window_ref()?.snapshot()", "unavailable_window()", "competing-admission observation window differs from reviewed code"),
        ("src/ffi/window.rs", "IsWindow(Some(self.hwnd))", "IsWindow(None)", "competing-admission observation snapshot differs from reviewed code"),
    ):
        changed = dict(files)
        source = (ROOT / SHIM / relative).read_text()
        if old not in source:
            raise SystemExit(f"missing competing-admission mutation target: {old}")
        changed[relative] = source.replace(old, new, 1)
        scans = {}
        for item, text in changed.items():
            scanned = CHECKER.scan(text)
            scans[item] = (scanned, CHECKER._attributes(scanned.code))
        found = []
        CHECKER._check_fault_authority(ROOT, scans, found)
        if f"{SHIM}/{relative}: {expected}" not in found:
            raise SystemExit(f"competing-admission witness bypass accepted: {old}: {found}")
    # The source-controlled owned-folder obstruction must remain a new,
    # fixed child file; comments cannot stand in for the actual literal.
    obstruction_path = "src/adapter/native_tests/process_fault/obstruction.rs"
    original_obstruction = (ROOT / SHIM / obstruction_path).read_text()
    for old, new, expected in (
        ('folder.join("EBWebView")', 'folder.join("other") /* folder.join("EBWebView") */', "UDF obstruction must use its fixed EBWebView child"),
        ('.create_new(true)', '.create_new(false)', "owned UDF obstruction differs from reviewed fixed fixture"),
        ('folder != self.expected.as_path()', 'false', "owned UDF obstruction differs from reviewed fixed fixture"),
    ):
        if old not in original_obstruction:
            raise SystemExit(f"missing obstruction mutation target: {old}")
        changed = dict(files)
        changed[obstruction_path] = original_obstruction.replace(old, new, 1)
        scans = {}
        for relative, source in changed.items():
            scanned = CHECKER.scan(source)
            scans[relative] = (scanned, CHECKER._attributes(scanned.code))
        found = []
        CHECKER._check_fault_authority(ROOT, scans, found)
        if f"{SHIM}/{obstruction_path}: {expected}" not in found:
            raise SystemExit(f"UDF obstruction boundary bypass accepted: {old}: {found}")
    # Taking the retired pairs disarms observation; the live pair must be
    # re-armed before injection and before its later native close.
    retry = fixture_source.find("fn drive_posted_retry(")
    arm = fixture_source.find("crate::Native::arm_native_zero_observations();", retry)
    inject = fixture_source.find(".inject_posted_retry_fault(", retry)
    if not 0 <= retry < arm < inject:
        raise SystemExit("retry witness is not re-armed before the fault")
    changed = dict(files)
    changed["src/adapter/native_tests/process_fault.rs"] = (
        fixture_source[:arm] + fixture_source[arm:].replace("crate::Native::arm_native_zero_observations();", "", 1)
    )
    scans = {}
    for relative, text in changed.items():
        scanned = CHECKER.scan(text)
        scans[relative] = (scanned, CHECKER._attributes(scanned.code))
    found = []
    CHECKER._check_fault_authority(ROOT, scans, found)
    expected = f"{SHIM}/src/adapter/native_tests/process_fault.rs: process fault fixture differs from reviewed sealed caller"
    if expected not in found:
        raise SystemExit(f"retry witness disarming was accepted: {found}")
    # A removed module or an inert hosted test must not disable the gate.
    found = fixture({helper: original})
    if f"{SHIM}/src/ffi/mod.rs: process fault helper must have exactly one private cfg(test) declaration" not in found:
        raise SystemExit(f"missing fault module declaration was accepted: {found}")
    inert = SHIM_LIB + "#[cfg(test)]\n#[forbid(unsafe_code)]\nmod tests { #[test] fn native_verified_owned_process_faults_retire() { } }\n"
    found = fixture({helper: original, LIB: inert})
    expected = f"{LIB}: process fault hosted test must call the real fixture"
    if expected not in found:
        raise SystemExit(f"inert process fault test was accepted: {found}")
    indirect = (
        (OPS, "fn f() { OpenProcess(1, false, 7); }", "OpenProcess is confined to the fixed probe and fault helper"),
        (OPS, "fn f() { LoadLibraryW(); }", "indirect process termination authority is forbidden"),
        (OPS, "fn f() { GetProcAddress(); }", "dynamic lookup must remain the fixed DefWindowProcW lookup"),
        (f"{SHIM}/src/ffi/process.rs", "use x::OpenProcess; fn f() { OpenProcess(1, false, 7); }", "product process probe must use its fixed query-only OpenProcess"),
    )
    for source_path, statement, expected in indirect:
        found = fixture({source_path: CFG + statement + "\n"})
        if f"{source_path}: {expected}" not in found:
            raise SystemExit(f"indirect authority was accepted: {statement}: {found}")

    window = f"{SHIM}/src/ffi/window.rs"
    approved = 'GetProcAddress(module, PCSTR(c"DefWindowProcW".as_ptr().cast()))'
    live = CFG + f"use x::GetProcAddress; fn f() {{ let _p = {approved}; }}\n"
    message = f"{window}: dynamic lookup must remain the fixed DefWindowProcW lookup"
    if message in fixture({window: live}):
        raise SystemExit("the fixed executable lookup was rejected")
    changed = live.replace('c"DefWindowProcW"', 'c"TerminateProcess"')
    for decoy in (f"// {approved}\n", f"/* {approved} */\n", f'const TEXT: &str = r#"{approved}"#;\n'):
        for source in (decoy + changed, changed + decoy):
            if message not in fixture({window: source}):
                raise SystemExit("a non-executable decoy satisfied the fixed lookup policy")

    observer = "src/ffi/process.rs"
    observer_source = (ROOT / SHIM / observer).read_text()
    observer_message = f"{SHIM}/{observer}: shared process identity differs from the reviewed read-only observer"

    def observer_errors(source: str) -> list[str]:
        scanned = CHECKER.scan(source)
        found: list[str] = []
        CHECKER._check_fault_authority(
            ROOT, {observer: (scanned, CHECKER._attributes(scanned.code))}, found
        )
        return found

    if observer_message in observer_errors(observer_source):
        raise SystemExit("the actual shared identity observer was rejected")
    for old, new in (
        ("times.map_err(|_| ()).and_then(|()| {", "Ok::<(), ()>(()).and_then(|()| {"),
        ("queried\n        .map_err(|_| ())", "Ok::<(), ()>(())"),
        ("absent_on_open_failure(&error).map(|()| None)", "Ok(None)"),
        (".filter(|image| !image.is_empty())", ".filter(|_| true)"),
        ("browser_pid: pid,", "browser_pid: 1,"),
        ("digest.update(unit.to_le_bytes());", "digest.update(unit.to_be_bytes());"),
        ("PathBuf::from(OsString::from_wide(image))", 'PathBuf::from("unrelated")'),
    ):
        if observer_source.count(old) != 1:
            raise SystemExit(f"missing shared identity mutation target: {old}")
        if observer_message not in observer_errors(observer_source.replace(old, new, 1)):
            raise SystemExit(f"the shared identity policy accepted {old} -> {new}")


def test_pending_model_callback_references_are_read_only() -> None:
    relative = "src/adapter/native_tests/process_fault/model_tests/pending_opening_tests.rs"
    message = f"{SHIM}/{relative}: callback evidence references belong only in reviewed paths"

    def errors(body: str) -> list[str]:
        scanned = CHECKER.scan(CFG + f"fn proposed() {{ {body} }}\n")
        found: list[str] = []
        CHECKER._check_fault_authority(
            ROOT, {relative: (scanned, CHECKER._attributes(scanned.code))}, found
        )
        return found

    reader = "let _ = crate::Native::callback_order(); let _: Option<crate::NativeCallbackMoment> = None;"
    if message in errors(reader):
        raise SystemExit("the reviewed pending model cannot read callback observations")
    for body in (
        "crate::Native::arm_callback_order();",
        "crate::Native::record_callback(crate::NativeCallbackMoment::BrowserExit(42));",
        "crate::Native::disarm_callback_order();",
        "let _ = &crate::CALLBACK_ORDER;",
        "let _ = crate::Native::creation_order();",
        "let _ = crate::NativeCreationMoment::EnvironmentReturned(true);",
    ):
        if message not in errors(body):
            raise SystemExit(f"the pending model escaped its read-only callback scope: {body}")


def test_fault_profile_bindings() -> None:
    directory = "crates/pos-owner-bridge"
    paths = (
        f"{directory}/src/listener/fixtures.rs",
        f"{directory}/src/listener/fixture_assets.rs",
        f"{directory}/assets/qualification/pending.html",
        f"{directory}/assets/qualification/delayed_delivery.html",
        f"{directory}/assets/qualification/successful_get_release_delay.html",
        f"{directory}/assets/qualification/successful_get_writing_delay.html",
        f"{directory}/assets/qualification/withheld_delivery.html",
    )
    sources = {path: (ROOT / path).read_text() for path in paths}

    def errors(changes: dict[str, str]) -> list[str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, text in {**sources, **changes}.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            found: list[str] = []
            CHECKER._check_fault_assets(root, found)
            return found

    if errors({}):
        raise SystemExit("the actual sealed fault profile bindings were rejected")
    for path in paths[2:]:
        if not errors({path: sources[path] + "<iframe></iframe>"}):
            raise SystemExit(f"changed fault topology was accepted: {path}")
    for variant, constant, filename in (
        ("Pending", "PENDING", "pending"),
        ("DelayedDelivery", "DELAYED_DELIVERY", "delayed_delivery"),
        ("SuccessfulGetReleaseDelay", "SUCCESSFUL_GET_RELEASE_DELAY", "successful_get_release_delay"),
        ("SuccessfulGetWritingDelay", "SUCCESSFUL_GET_WRITING_DELAY", "successful_get_writing_delay"),
        ("WithheldDelivery", "WITHHELD_DELIVERY", "withheld_delivery"),
    ):
        catalogue, responses = paths[:2]
        mapping = f"Self::{variant} => &fixture_assets::{constant}"
        if not errors({catalogue: sources[catalogue].replace(mapping, f"Self::{variant} => &fixture_assets::OTHER", 1)}):
            raise SystemExit(f"redirected fault catalogue was accepted: {variant}")
        redirected = sources[catalogue].replace(mapping, f"Self::{variant} => &fixture_assets::OTHER", 1)
        decoy = f"std::hint::black_box(match self {{ Self::{variant} => &fixture_assets::{constant}, _ => &fixture_assets::{constant} }});"
        for text in (redirected + "\n" + decoy, redirected.replace("match self {", decoy + "\nmatch self {", 1)):
            expected = f"{catalogue}: process fault catalogue differs from reviewed sealed response selection"
            if expected not in errors({catalogue: text}):
                raise SystemExit(f"executable catalogue decoy was accepted: {variant}")
        original = sources[responses]
        wrong = original.replace(f'qualification/{filename}.html', 'qualification/other.html', 1)
        decoy = f'const {constant}: Response = Response {{ body: include_bytes!("../../assets/qualification/{filename}.html") }};'
        for text in (wrong, f"/* {decoy} */\n" + wrong, wrong + f'\nconst TEXT: &str = r#"{decoy}"#;'):
            expected = f"{responses}: {variant} response must embed the reviewed asset"
            if expected not in errors({responses: text}):
                raise SystemExit(f"non-executable fault response decoy was accepted: {variant}")


def test_recordless_and_release_authority() -> None:
    cases = (
        ("src/ffi/creation.rs", "succeeded", "Result::is_ok", "Result::is_err"),
        ("src/ffi/session.rs", "recordless_fault_owners_retained", "== Some(true)", "== Some(false)"),
        ("src/ffi/session.rs", "pending_candidate_checked", "if !owners() {", "if false {"),
        ("src/ffi/session.rs", "pending_candidate_checked", "if callback().is_some() {", "if false {"),
        ("src/ffi/session.rs", "pending_candidate_checked", "let candidate = observe()?;", "let candidate = None;"),
        ("src/ffi/session.rs", "pending_candidate_checked", "if !owners() || callback().is_some() {", "if false {"),
        ("src/ffi/session.rs", "exit_fault_owners_retained", "self.view.is_none()", "self.view.is_some()"),
        ("src/adapter/surface/mod.rs", "recordless_opening_ready", "self.identity.is_none()", "self.identity.is_some()"),
        ("src/adapter/surface/mod.rs", "inject_recordless_browser", "ProcessFaultTarget::Browser", "ProcessFaultTarget::Renderer"),
        ("src/adapter/surface/mod.rs", "inject_view_fault", "std::time::Instant::now() < deadline", "true"),
        ("src/adapter/surface/mod.rs", "posted_fault_snapshot", "self.loopback.served().count != 1", "false"),
        ("src/adapter/surface/mod.rs", "posted_fault_snapshot", "self.runtime.identity(browser.browser_pid).map_err(|_| ())? != browser", "false"),
        ("src/adapter/surface/mod.rs", "posted_fault_state", "state.posts != 1", "false"),
    )
    for relative, name, old, new in cases:
        source = (ROOT / SHIM / relative).read_text()
        marker = source.index(f"fn {name}(")
        opening = source.index("{", marker)
        scanned = CHECKER.scan(source)
        end = CHECKER._matching_brace(scanned.code, opening) + 1
        body = source[marker:end]
        if body.count(old) != 1:
            raise SystemExit(f"missing authority mutation: {relative}::{name}: {old}")
        mutated = source[:marker] + body.replace(old, new, 1) + source[end:]
        changed = CHECKER.scan(mutated)
        found: list[str] = []
        CHECKER._check_fault_authority(ROOT, {relative: (changed, CHECKER._attributes(changed.code))}, found)
        expected = f"{SHIM}/{relative}: process fault authority function {name} differs from reviewed code"
        if expected not in found:
            raise SystemExit(f"authority bypass was accepted: {relative}::{name}")
    relative = "src/adapter/surface/mod.rs"
    source = (ROOT / SHIM / relative).read_text()
    for declaration in ("recordless_fault: Option<ProcessIdentity>", "recordless_fault: None"):
        guarded = "#[cfg(test)]\n" + ("    " if "Option" in declaration else "            ") + declaration
        if source.count(guarded) != 1:
            raise SystemExit(f"missing recordless field guard: {declaration}")
        changed = CHECKER.scan(source.replace(guarded, declaration, 1))
        found = []
        CHECKER._check_fault_authority(ROOT, {relative: (changed, CHECKER._attributes(changed.code))}, found)
        if f"{SHIM}/{relative}: recordless fixture identity and initialization require cfg(test)" not in found:
            raise SystemExit(f"product recordless fixture state was accepted: {declaration}")


def test_typed_process_failure_evidence() -> None:
    relative = "src/ffi/events/control_fixture.rs"
    source = (ROOT / SHIM / relative).read_text()
    message = f"{SHIM}/{relative}: process failure observations differ from reviewed typed callbacks"
    for old, new in (
        ("Some(_) => NativeProcessFailure::Other", "Some(_) => NativeProcessFailure::BrowserExited"),
        ("None => NativeProcessFailure::Unavailable", "None => NativeProcessFailure::BrowserExited"),
        ("let result = classify_process_kind(kind);", "let result = classify_process_kind(None);"),
        ("NativeProcessFailure::Unavailable => None", "NativeProcessFailure::Unavailable => Some(false)"),
        ("push_observation(failures, result)", "failures.borrow_mut().clear()"),
        ("PROCESS_FAILURES.with(|failures| failures.borrow().clone())", "Vec::new()"),
    ):
        if source.count(old) != 1:
            raise SystemExit(f"missing typed process failure mutation: {old}")
        changed = CHECKER.scan(source.replace(old, new, 1))
        found: list[str] = []
        CHECKER._check_fault_authority(ROOT, {relative: (changed, CHECKER._attributes(changed.code))}, found)
        if message not in found:
            raise SystemExit(f"typed process failure evidence bypass was accepted: {old}")

    relative = "src/lib.rs"
    source = (ROOT / SHIM / relative).read_text()
    guarded = "#[cfg(test)]\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub(crate) enum NativeProcessFailure"
    if source.count(guarded) != 1:
        raise SystemExit("missing native failure classification cfg mutation")
    changed = CHECKER.scan(source.replace(guarded, guarded.removeprefix("#[cfg(test)]\n"), 1))
    found = []
    CHECKER._check_fault_authority(ROOT, {relative: (changed, CHECKER._attributes(changed.code))}, found)
    if f"{SHIM}/{relative}: native failure classifications require cfg(test)" not in found:
        raise SystemExit("product native failure classification was accepted")


def test_private_fault_capability_construction() -> None:
    root = (ROOT / LIB).read_text()
    surface = "src/adapter/surface/mod.rs"
    sources = {
        "src/lib.rs": root,
        surface: (ROOT / SHIM / surface).read_text(),
        "src/adapter/native_tests/process_fault.rs": (ROOT / SHIM / "src/adapter/native_tests/process_fault.rs").read_text(),
    }

    def errors(files: dict[str, str]) -> list[str]:
        scans = {}
        for relative, text in files.items():
            scanned = CHECKER.scan(text)
            scans[relative] = (scanned, CHECKER._attributes(scanned.code))
        found: list[str] = []
        CHECKER._check_fault_capabilities(scans, found)
        return found

    if errors(sources):
        raise SystemExit(f"the private root capabilities were rejected: {errors(sources)}")
    for marker in ("struct FaultSeal", "impl FaultSeal", "struct FaultAuthority", "impl FaultAuthority"):
        old = f"#[cfg(test)]\n{marker}"
        if root.count(old) != 1:
            raise SystemExit(f"missing capability cfg mutation: {marker}")
        changed = dict(sources)
        changed["src/lib.rs"] = root.replace(old, marker, 1)
        if not errors(changed):
            raise SystemExit(f"product capability was accepted: {marker}")
    for statement, expected in (
        ("fn f() { crate::Native::model_main_renderer_exit(); }", "modeled renderer observation belongs only in its reviewed model"),
        ("type Alias = crate::RetainedExitHandle;", "retained-exit capability belongs only in reviewed paths"),
        ("fn f() { let _seal = crate::FaultSeal(Default::default()); }", "FaultSeal construction belongs only in the sealed fixture"),
        ("fn f() { let _seal = crate::FaultSeal { trace, deadline }; }", "FaultSeal construction belongs only in the sealed fixture"),
        ("fn f() { let _authority = crate::FaultAuthority {}; }", "FaultAuthority construction belongs only in the validated Surface path"),
        ("use crate::FaultSeal as Other;", "fault capabilities may not be aliased"),
        ("use crate::FaultAuthority as Other;", "fault capabilities may not be aliased"),
        ("impl crate::FaultSeal { fn forged() -> Self { Self(Default::default()) } }", "fault capability implementations belong only in the reviewed root types"),
        ("impl Default for crate::FaultAuthority { fn default() -> Self { Self {} } }", "fault capability implementations belong only in the reviewed root types"),
    ):
        changed = dict(sources)
        changed["src/adapter/other.rs"] = CFG + statement
        if f"{SHIM}/src/adapter/other.rs: {expected}" not in errors(changed):
            raise SystemExit(f"capability construction bypass was accepted: {statement}")

    resurrected = dict(sources)
    resurrected[surface] += "\nfn inject_exit_fault() { let _ = crate::FaultAuthority {}; }\n"
    expected = f"{SHIM}/{surface}: fault capability references belong only in reviewed authority paths"
    if expected not in errors(resurrected):
        raise SystemExit("removed exit authority could be resurrected by its old name")

    # The source-bound model spy may borrow a validated authority, but its
    # method allowance must not permit minting authority or adjacent callers.
    native = "src/adapter/surface/tests/native.rs"
    spy = (ROOT / SHIM / native).read_text()
    if errors(dict(sources, **{native: spy})):
        raise SystemExit("the source-bound fault model spy was rejected")
    for statement, expected in (
        ("fn unreviewed(authority: &crate::FaultAuthority) {}", "fault capability references belong only in reviewed authority paths"),
        ("fn inject_process_fault() { let _ = crate::FaultAuthority {}; }", "FaultAuthority construction belongs only in the validated Surface path"),
        ("fn inject_process_fault() { let _ = crate::FaultSeal { trace, deadline }; }", "FaultSeal construction belongs only in the sealed fixture"),
    ):
        changed = dict(sources, **{native: spy + "\n" + statement})
        if f"{SHIM}/{native}: {expected}" not in errors(changed):
            raise SystemExit(f"fault model spy allowance accepted bypass: {statement}")

    for statement in (
        "type Alias = crate::FaultAuthority; fn forge() -> Alias { Alias { browser, target, valid, trace } }",
        "type Alias<T> = T; fn forge() { let _ = Alias::<crate::FaultAuthority> { browser, target, valid, trace }; }",
        "use crate::{FaultAuthority as Other};",
        "use crate::FaultAuthority::{self as Other};",
        "use crate::{self as Root}; type Alias = Root::FaultAuthority;",
        "type Alias = crate::FaultSeal;",
        "type Alias<T = crate::FaultAuthority> = T;",
    ):
        for relative in ("src/lib.rs", surface, "src/adapter/other.rs"):
            changed = dict(sources)
            changed[relative] = changed.get(relative, CFG) + "\n" + statement
            expected = f"{SHIM}/{relative}: fault capability references belong only in reviewed authority paths"
            if expected not in errors(changed):
                raise SystemExit(f"capability alias bypass was accepted in {relative}: {statement}")


def test_live_mapping_witness_boundary() -> None:
    path = "src/ffi/buffers.rs"
    buffers = (ROOT / SHIM / path).read_text()
    root = (ROOT / LIB).read_text()

    def errors(buffer_source: str, root_source: str = root) -> list[str]:
        scans = {}
        for relative, text in ((path, buffer_source), ("src/lib.rs", root_source)):
            scanned = CHECKER.scan(text)
            scans[relative] = (scanned, CHECKER._attributes(scanned.code))
        found: list[str] = []
        CHECKER._check_zero_witness(scans, found)
        return found

    if errors(buffers):
        raise SystemExit(f"the live atomic witness was rejected: {errors(buffers)}")
    for old, new in (
        ("#[cfg(test)]\nmod zero_witness", "mod zero_witness"),
        ("#[cfg(test)]\n        let witness =", "let witness ="),
        ("#[cfg(test)]\n        zero_witness::after", "zero_witness::after"),
        ("let zeroed = self.zero_from(start);", "let zeroed = Ok(());"),
        ("zero_witness::after(self, start, witness, zeroed.is_ok());", ""),
        ("zero_witness::after(self, start, witness, zeroed.is_ok());", "self.base = None; zero_witness::after(self, start, witness, zeroed.is_ok());"),
        ("before_nonzero: before.before_nonzero,", "before_nonzero: Some(true),"),
    ):
        if buffers.count(old) != 1:
            raise SystemExit(f"missing native witness mutation: {old}")
        if not errors(buffers.replace(old, new, 1)):
            raise SystemExit(f"disabled/product/late native witness was accepted: {old}")
    for old, new in (
        ("#[cfg(test)]\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub(crate) struct NativeZeroObservation", "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\npub(crate) struct NativeZeroObservation"),
        ("pub(crate) zeroed: Option<bool>,", "pub(crate) zeroed: bool,"),
    ):
        if root.count(old) != 1:
            raise SystemExit(f"missing native observation mutation: {old}")
        if not errors(buffers, root.replace(old, new, 1)):
            raise SystemExit(f"native observation boundary change was accepted: {old}")


def test_owned_parent_fixture_is_test_only_and_exactly_bound() -> None:
    paths = (
        f"{SHIM}/src/lib.rs",
        f"{SHIM}/src/ffi/mod.rs",
        f"{SHIM}/src/ffi/fixture_parent.rs",
        f"{SHIM}/src/adapter/native_tests.rs",
        "crates/pos-owner-bridge/src/ceremony/plan.rs",
    )
    sources = {path: (ROOT / path).read_text(encoding="utf-8") for path in paths}

    def errors(values: dict[str, str]) -> list[str]:
        found: list[str] = []
        CHECKER._check_owned_parent_boundary(values, found)
        return found

    if errors(sources):
        raise SystemExit(f"owned-parent baseline rejected: {errors(sources)}")
    mutations = (
        (paths[0], "native_host_fixture_child", "renamed_host_fixture_child"),
        (paths[0], "native_host_fixture_child", ""),
        (paths[0], "#[test]\n    fn native_host_fixture_child", "fn native_host_fixture_child"),
        (paths[0], "#[test]\n    fn native_host_fixture_child", "#[test]\n    #[ignore]\n    fn native_host_fixture_child"),
        (paths[0], "#[test]\n    fn native_host_fixture_child", "#[test]\n    #[cfg(any())]\n    fn native_host_fixture_child"),
        (paths[0], "#[test]\n    fn native_host_fixture_child", "#[test]\n    #[should_panic]\n    fn native_host_fixture_child"),
        (paths[0], "#[test]\n    fn native_host_fixture_child", "#[test]\n    #[cfg_attr(test, ignore)]\n    fn native_host_fixture_child"),
        (paths[0], "#[cfg(test)]\n#[forbid(unsafe_code)]\nmod tests {", "#[cfg(any())]\n#[forbid(unsafe_code)]\nmod tests {"),
        (paths[1], "#[cfg(test)]\nmod fixture_parent;", "mod fixture_parent;"),
        (paths[1], "mod fixture_parent;", "pub mod fixture_parent;"),
        (paths[2], "struct OwnedParent {", "pub struct OwnedParent {"),
        (paths[2], "fn child_owner()", "pub fn child_owner()"),
        (paths[0], "crate::Native::native_host_parent_fixture()", "Ok(())"),
        (paths[2], '"PIGLOR_HOST_FIXTURE_PARENT"', '"UNREVIEWED_PARENT"'),
        (paths[2], "self.window.handle().0 as usize", "123_usize"),
        (paths[2], "self.pump.token.check()?;", ""),
        (paths[2], "parent.finish()?;", "drop(parent);"),
        (paths[2], "parent.pump()", "Ok(crate::NativePulse::Timer)"),
        (paths[3], ".with_test_owner_window(owner_window)", ".with_test_owner_window(123)"),
        (paths[4], '#[cfg(feature = "test-support")]\nimpl CeremonyPlan {', 'impl CeremonyPlan {'),
    )
    for path, old, new in mutations:
        if old not in sources[path]:
            raise SystemExit(f"owned-parent mutation anchor missing: {old}")
        changed = dict(sources, **{path: sources[path].replace(old, new, 1)})
        if not errors(changed):
            raise SystemExit(f"owned-parent boundary accepted mutation: {old}")
    changed = dict(sources, **{"crates/product/src/lib.rs": "fn f(p: CeremonyPlan) { p.with_test_owner_window(1); }"})
    if not errors(changed):
        raise SystemExit("owned-parent fixture capability accepted in product source")
    removed = dict(sources, **{paths[0]: sources[paths[0]].replace("native_host_fixture_child", "removed_child") + "\n// native_host_fixture_child\n"})
    if not errors(removed):
        raise SystemExit("owned-parent marker in a comment disabled the required guard")
    removed = dict(sources, **{paths[0]: sources[paths[0]].replace("native_host_fixture_child", "removed_child") + '\nconst DECOY: &str = "native_host_fixture_child";\n'})
    if not errors(removed):
        raise SystemExit("owned-parent marker in a string disabled the required guard")
    source = sources[paths[0]]
    marker = "    #[test]\n    fn native_host_fixture_child"
    start = source.index(marker)
    spans = [(a, b) for name, a, b in CHECKER._function_spans(CHECKER.scan(source).code) if name == "native_host_fixture_child"]
    if len(spans) != 1:
        raise SystemExit("owned-parent child test is missing or ambiguous")
    end = spans[0][1]
    nested = source[:start] + "    #[cfg(any())]\n    mod disabled {\n" + source[start:end] + "\n    }" + source[end:]
    if not errors(dict(sources, **{paths[0]: nested})):
        raise SystemExit("owned-parent test under a disabled nested module was accepted")


def test_external_qualification_is_sealed() -> None:
    sources = {name: (ROOT / name).read_text(encoding="utf-8") for name in CHECKER.EXTERNAL_FIXTURE_SOURCES}
    controls = f"{SHIM}/src/adapter/native_tests/controls.rs"
    assets = "scripts/owner_bridge_assets.py"
    navigation = f"{SHIM}/src/ffi/events/navigation.rs"
    resource = f"{SHIM}/src/ffi/events/resource.rs"
    fixture = f"{SHIM}/src/ffi/events/control_fixture.rs"
    helper = f"{SHIM}/src/lib.rs"

    def errors(values: dict[str, str]) -> list[str]:
        found: list[str] = []
        CHECKER._check_external_fixture(values, found)
        return found

    if errors(sources):
        raise SystemExit(f"External fixture baseline rejected: {errors(sources)}")
    if resource not in CHECKER.EXTERNAL_FIXTURE_SOURCES:
        raise SystemExit("resource callback diagnostic source binding was removed")
    mutations = (
        (f"{SHIM}/src/adapter/host.rs", "Self::start_with_profile(runtime, root, store, crate::require_windows_profile)", "Self::start_with_profile(runtime, root, store, || Ok(()))"),
        (f"{SHIM}/src/adapter/host.rs", "Self::spawn_with_factory(runtime, root, loopback, store, crate::Native::owner_factory)", "Self::spawn_with_factory(runtime, root, loopback, store, || panic!())"),
        (f"{SHIM}/src/adapter/surface/tests/fault_admission.rs", "deadline: Instant::now() + Duration::from_secs(10)", "deadline: Instant::now() + Duration::from_secs(3_600)"),
        (f"{SHIM}/src/adapter/native_tests/process_fault/obstruction/tests.rs", "Factory::new(Creation::Ready, FakeClock::start())", "crate::Native::owner_factory().unwrap()"),
        (resource, 'current.borrow_mut().register(retained_trace)', 'drop(retained_trace)'),
        (resource, 'self.callbacks.set(count + 1);', ''),
        (navigation, 'super::resource::reset_readiness_resource();', ''),
        (f"{SHIM}/src/adapter/native_tests/readiness.rs", 'let resource = crate::Native::readiness_resource_snapshot();', 'let resource: Option<(Option<u64>, u8, bool, u8)> = None;'),
        (f"{SHIM}/src/adapter/native_tests/readiness.rs", 'timing.report(number);', ''),
        (f"{SHIM}/src/adapter/native_tests/readiness.rs", 'timing.after_receipt.last_step_return =\n                            timing.before_receipt.last_step_return;', ''),
        (f"{SHIM}/src/adapter/native_tests/readiness.rs", 'let step = driver.step(&mut env(surface, loopback, store));', 'let step = Step::Pending;'),
        (resource, 'if count >= 9', 'if false'),
        (resource, 'prefix: "NATIVE_RESOURCE",\n        case: super::navigation::readiness_context(),', 'prefix: "NATIVE_RESOURCE",\n        case: None,'),
        (resource, 'prefix: "NATIVE_RESOURCE",', 'prefix: "NATIVE_RESOURCE_UNIT",'),
        (resource, 'trace.returning(reporting, false);', 'trace.returning(reporting, true);'),
        (resource, 'let selected = observe(signals, EventKind::Resource, request);', 'let selected = NativeAction::Allow;'),
        (f"{SHIM}/src/adapter/surface/controller_qualification.rs", '!self.native.pending_opening_owners_retained()', 'false'),
        (f"{SHIM}/src/adapter/native_tests/process_fault/quarantined.rs", '.share_mode(0)', '.share_mode(7)'),
        (f"{SHIM}/src/adapter/native_tests/process_fault/quarantined.rs", 'if !polled.remaining', 'if false'),
        (f"{SHIM}/src/adapter/native_tests/process_fault/quarantined.rs", 'if !refused || !wiped || !native_wiped', 'if false'),
        (f"{SHIM}/src/adapter/surface/diagnostics.rs", 'if !keeper_held.get()', 'if false'),
        (f"{SHIM}/src/adapter/surface/exit_boundary.rs", '!self.events.matching_exit_at_boundary(browser.browser_pid)', 'false'),
        (f"{SHIM}/src/adapter/surface/exit_boundary.rs", 'capture.consumed = true;', 'capture.consumed = false;'),
        (f"{SHIM}/src/adapter/surface/exit_boundary.rs", 'self.native.retained_exit_membership(handle.as_ref())?;', ''),
        (f"{SHIM}/src/lib.rs", 'entries.is_empty() || browser == Some(expected)', 'true'),
        (f"{SHIM}/src/adapter/surface/tests/exit_boundary_tests.rs", 'assert_retained_without_fault(&mut expired);', ''),
        (f"{SHIM}/src/adapter/surface/tests/exit_boundary_tests.rs", '#[test]\nfn exit_fault_refuses_malformed_or_nonempty_missing_membership', '#[cfg(any())]\n#[test]\nfn exit_fault_refuses_malformed_or_nonempty_missing_membership'),
        (f"{SHIM}/src/adapter/native_tests/process_fault.rs", 'active_status=259_ambiguous_not_liveness', 'active_status=alive'),
        (f"{SHIM}/src/adapter/native_tests/process_fault.rs", 'fixture.surface.fresh_success_own_exit(browser)', 'true'),
        (f"{SHIM}/src/adapter/native_tests/process_fault.rs", 'failure_stage={failure_stage:?}', 'failure_stage=omitted'),
        (f"{SHIM}/src/adapter/surface/exit_boundary.rs", 'record.creation_filetime() != browser.creation_filetime', 'false'),
        (f"{SHIM}/src/adapter/surface/tests/exit_boundary_tests.rs", '#[test]\nfn fresh_success_provenance_binds_record_and_matching_exit_to_owner', '#[cfg(any())]\n#[test]\nfn fresh_success_provenance_binds_record_and_matching_exit_to_owner'),
        (f"{SHIM}/src/adapter/native_tests/process_fault.rs", 'NATIVE_EXIT_CUTPOINT_OBSERVED', 'NATIVE_EXIT_NOT_OBSERVED'),
        (f"{SHIM}/src/adapter/surface/tests/exit_boundary_tests.rs", 'assert_eq!(handle.exit_code(), Err(()));', ''),
        (f"{SHIM}/src/ffi/process_fault.rs", '|| self.observe()?.is_some()', '|| false'),
        (f"{SHIM}/src/adapter/events.rs", '!self.exit_boundary_invalid.get()', 'true'),
        (f"{SHIM}/src/ffi/events/control_fixture.rs", 'MAX_OBSERVATIONS: usize = 2', 'MAX_OBSERVATIONS: usize = 1'),
        (f"{SHIM}/src/ffi/events/control_fixture.rs", 'last.overflowed = true;', 'last.overflowed = false;'),
        (controls, 'assert!(!before.overflowed);', ''),
        (controls, 'assert!(!after.overflowed);', ''),
        (f"{SHIM}/src/adapter/native_tests/session.rs", '.is_some_and(|expected| self.events.exited() == Some(expected))', '.is_none_or(|expected| self.events.exited() == Some(expected))'),
        (f"{SHIM}/src/adapter/surface/controller_qualification.rs", 'std::time::Instant::now() >= self.deadline', 'false'),
        (f"{SHIM}/src/ffi/session.rs", 'std::time::Instant::now() >= seal.deadline', 'false'),
        (f"{SHIM}/src/ffi/session.rs", 'self.recordless_controller_completion().is_some()', 'false'),
        (f"{SHIM}/src/ffi/window.rs", 'self.hwnd.0.is_null()', 'false'),
        (f"{SHIM}/src/ffi/window.rs", 'self.signals.destroyed.get()', 'false'),
        (f"{SHIM}/src/ffi/window.rs", 'std::time::Instant::now() >= deadline', 'false'),
        (f"{SHIM}/src/adapter/surface/controller_qualification.rs", 'self.native.recordless_controller_completion().is_some()', 'false'),
        (f"{SHIM}/src/ffi/process_fault.rs", 'failure=first-snapshot-incomplete', 'failure=first-snapshot-empty'),
        (f"{SHIM}/src/ffi/process_fault.rs", 'browser_candidate_from_observations(first, || candidates(environment), super::process::inspect)', 'browser_candidate_from_observations(first, || Ok(Vec::new()), super::process::inspect)'),
        (f"{SHIM}/src/ffi/process_fault.rs", 'if second_identity != (identity, image)', 'if false'),
        (f"{SHIM}/src/adapter/surface/tests/fault_states.rs", ".posted_fault_state(1).is_err()", ".posted_fault_state(1).is_ok()"),
        (f"{SHIM}/src/adapter/native_tests/process_fault/model_tests.rs", "assert_eq!(fixture.evidence_complete, expected.is_none());", "assert!(fixture.evidence_complete);"),
        (f"{SHIM}/src/adapter/native_tests/process_fault/model_tests.rs", "process_observation=scripted native_zeroing=scripted", "process_observation=observed native_zeroing=observed"),
        (f"{SHIM}/src/adapter/native_tests/process_fault/model_tests.rs", "fresh success driver ended without result", "fresh success accepted a completed driver"),
        (f"{SHIM}/src/adapter/native_tests/process_fault.rs", "self.observe_fault_with_clock(target, first, deadline, &SystemClock)", "self.observe_fault_with_clock(target, first, deadline + Duration::from_secs(1), &SystemClock)"),
        (f"{SHIM}/src/adapter/native_tests/process_fault.rs", "validate_process_failures(&observed, expected)", "Ok(())"),
        (f"{SHIM}/src/adapter/native_tests/process_fault.rs", "verdict.validate()?;", "let _ignored = verdict.validate();"),
        (f"{SHIM}/src/adapter/native_tests/process_fault/port_tests.rs", "assert!(!*port.reached.borrow());", "assert!(*port.reached.borrow());"),
        (f"{SHIM}/src/adapter/native_tests/process_fault/port_tests.rs", "assert_eq!(error.as_deref(), expected);", "let _ignored = expected;"),
        (f"{SHIM}/src/adapter/native_tests/process_fault/port_tests.rs", "(1, 0, other_ceremony, folder, identity(), mismatch)", "(1, 0, other_ceremony, other_folder, identity(), mismatch)"),
        (f"{SHIM}/src/adapter/surface/tests/native.rs", "preload_owners: Cell::new(false),", "preload_owners: Cell::new(true),"),
        (f"{SHIM}/src/adapter/native_tests/process_fault/port_tests.rs", "assert_eq!(port.write_record(&[]), Err(pos_owner_bridge::CleanupError));", ""),
        (f"{SHIM}/src/ffi/events/mod.rs", "assert_eq!(subscriptions.removers.len(), 1);", "assert!(subscriptions.removers.is_empty());"),
        (f"{SHIM}/src/ffi/events/mod.rs", "Err(error) => sink.failed(kind, error),", "Err(_) => NativeAction::Handled,"),
        (f"{SHIM}/src/adapter/native_tests/process_fault/quarantined.rs", "let native_wiped = native_zeroing_observed(observations);", "let native_wiped = true;"),
        (f"{SHIM}/src/adapter/native_tests/process_fault/quarantined.rs", "observation_count={} observations={:?}", "observation_count=unknown observations=unavailable"),
        (f"{SHIM}/src/adapter/native_tests/process_fault/quarantined.rs", "&observations[..observations.len().min(3)]", "observations"),
        (f"{SHIM}/src/ffi/events/control_denial.rs", "assert_eq!(navigation.kind(), EventKind::Navigation);", ""),
        (navigation, "content_loading(None),", ""),
        (f"{SHIM}/src/adapter/native_tests/process_fault.rs", "Box::new(crate::Native::callback_order)", "Box::new(Vec::new)"),
        (f"{SHIM}/src/adapter/native_tests/process_fault/model_tests/pending_opening_tests.rs", "assert_eq!(reads.get(), 1);", "assert_eq!(reads.get(), 0);"),
        (f"{SHIM}/src/adapter/native_tests/readiness.rs", "observation=scripted qualified=false", "observation=native qualified=true"),
        (f"{SHIM}/src/adapter/native_tests/process_fault.rs", 'if clock.now() >= self.deadline {\n                return Err("pending-opening browser exit timed out".into());', 'if clock.now() >= self.deadline + Duration::from_secs(1) {\n                return Err("pending-opening browser exit timed out".into());'),
        (f"{SHIM}/src/adapter/native_tests/process_fault.rs", 'if clock.now() >= self.deadline {\n                    return Err("late controller completion was not observed".into());', 'if false {\n                    return Err("late controller completion was not observed".into());'),
        (f"{SHIM}/src/adapter/native_tests/process_fault/model_tests/pending_opening_tests.rs", "assert!(crate::Native::callback_order().is_empty());", "let _ignored = crate::Native::callback_order();"),
        (f"{SHIM}/src/ffi/process_fault/candidate_tests.rs", 'assert_eq!(calls, ["identity", "snapshot", "identity"]);', 'assert!(calls.is_empty());'),
        (f"{SHIM}/src/adapter/surface/mod.rs", 'failure=callback-after', 'failure=callback-before'),
        (controls, '"ms-settings:privacy-location"', '"ms-settings:privacy-location?x=1"'),
        (assets, 'ms-settings:privacy-location', 'ms-settings:privacy-location#x'),
        (controls, 'self.allowance.borrow_mut().take()', 'self.allowance.borrow_mut().clone()'),
        (controls, 'self.events.loaded() == Some(marker.generation)', 'true'),
        (controls, 'profile == FixtureProfile::External', 'true'),
        (controls, '&& !*redirected', ''),
        (controls, 'if valid {', 'if true {'),
        (controls, 'self.events.event(event)', 'NativeAction::Observe'),
        (controls, 'assert_eq!(before.readback, Some(true));', ''),
        (controls, 'assert_eq!(before.completions, u32::from(before.deferred));', ''),
        (controls, '!probe.events.invalid()', 'true'),
        (controls, '!self.events.invalid()', 'true'),
        (controls, 'self.verified_owner.get() == self.events.loaded()', 'true'),
        (controls, 'probe.external_profile\n                && probe.verified_owner.get().is_none()', 'probe.isolated_external'),
        (controls, 'assert_eq!(probe.verified_owner.get(), probe.events.loaded());', ''),
        (controls, 'assert_eq!(listener.served().count, 1);', ''),
        (controls, 'served.count == 1', 'served.count > 0'),
        (controls, 'served.count == 1', 'true'),
        (controls, 'probe.delivered.get()', 'true'),
        (controls, 'assert_denials(before_exit, after_exit, kind, mode);', ''),
        (controls, 'assert_control_retired(&probe, &listener, &before_exit, &after_exit, case, armed);', ''),
        (controls, 'wait_for_control(&factory, &probe, &listener, &mut armed)', 'Ok(())'),
        (controls, 'probe.events.exited() == Some(identity.browser_pid)', 'true'),
        (navigation, 'args.SetCancel(!allow)', 'args.SetCancel(false)'),
        (f"{SHIM}/src/ffi/events/mod.rs", 'controls::install(view, signals, recovery, subscriptions)', 'Ok(())'),
        (f"{SHIM}/src/ffi/events/controls.rs", 'add_LaunchingExternalUriScheme', 'add_DisabledExternalUriScheme'),
        (fixture, 'value.as_bool()', 'true'),
        (helper, '#[cfg(test)]\n    mod native_tests;', 'mod native_tests;'),
    )
    for path, old, new in mutations:
        if old not in sources[path]:
            raise SystemExit(f"External mutation anchor missing: {old}")
        if not errors(dict(sources, **{path: sources[path].replace(old, new, 1)})):
            raise SystemExit(f"External fixture accepted mutation: {old}")
    missing_resource = dict(sources)
    del missing_resource[resource]
    if f"{resource}: External URI qualification differs from reviewed source" not in errors(missing_resource):
        raise SystemExit("missing resource callback diagnostic source was accepted")
    if not errors(dict(sources, **{"crates/product/src/lib.rs": "fn use_it(_: ExternalAllowance) {}"})):
        raise SystemExit("External allowance escaped into product source")
    pending_model = f"{SHIM}/src/adapter/surface/tests/pending_creation.rs"
    for escaped in (
        "fn escaped() { let call = Surface::lose_pending_controller_parent; }",
        "type Escaped = crate::ControllerParentLossSeal;",
    ):
        changed = dict(sources, **{pending_model: sources[pending_model] + "\n" + escaped})
        if not any("controller parent loss capability outside sealed test fixture" in item
                   for item in errors(changed)):
            raise SystemExit("Controller parent-loss authority escaped the modeled test")
    for escaped in (
        "type Escaped = crate::ControllerParentLossSeal;",
        "fn escaped() { let call = crate::NativeOperations::lose_controller_parent; }",
        "fn escaped() { let call = Surface::lose_pending_controller_parent; }",
        "fn escaped() { let call = Surface::lost_controller_parent_retention; }",
    ):
        found = errors(dict(sources, **{"crates/product/src/lib.rs": escaped}))
        if not any("controller parent loss capability outside sealed test fixture" in item for item in found):
            raise SystemExit("Controller parent-loss authority escaped its sealed fixture")


def main() -> None:
    test_masker()
    test_masker_unicode_word_boundaries()
    test_masker_run_classes_cover_the_same_unicode_characters()
    test_accepted()
    test_unsafe_evasions()
    test_ffi_surface()
    test_headers()
    test_lints()
    test_safety_comments()
    test_inventory()
    test_manifests()
    test_cli()
    test_forbidden_webview_authority()
    test_control_observations_cannot_ship_in_product_builds()
    test_owned_process_fault_authority()
    test_pending_model_callback_references_are_read_only()
    test_fault_profile_bindings()
    test_recordless_and_release_authority()
    test_typed_process_failure_evidence()
    test_private_fault_capability_construction()
    test_live_mapping_witness_boundary()
    test_owned_parent_fixture_is_test_only_and_exactly_bound()
    test_external_qualification_is_sealed()
    test_windows_case_insensitive_source_suffix_cannot_hide_code()
    test_hardening()
    test_symlinks()
    test_hosted_liveness()
    test_review_findings()
    test_structural_rules()
    print("owner-bridge unsafe-policy checker rejects every forged boundary")


if __name__ == "__main__":
    main()
