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
        return CHECKER.violations(root)


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


def test_cli() -> None:
    clean = run_cli()
    if clean.returncode != 0 or "owner-bridge Windows unsafe policy holds" not in clean.stdout:
        raise SystemExit(f"CLI rejected a clean tree: {clean}")
    dirty = run_cli({SAFE_LIB_PATH: FORBID + "fn f() { unsafe {} }\n", HOST: FORBID + CFG + "pub fn host() {}\n"})
    expected = [at(SAFE_LIB_PATH, 2, RESERVED)]
    lines = dirty.stderr.strip().splitlines()
    if dirty.returncode == 0 or dirty.stdout or lines != expected:
        raise SystemExit(f"CLI did not report the expected violation {expected}: {dirty}")
    malformed = run_cli({INV: "[[block\n"})
    if malformed.returncode == 0 or "Traceback" in malformed.stderr or "malformed TOML" not in malformed.stderr:
        raise SystemExit(f"CLI did not report malformed TOML cleanly: {malformed}")


def main() -> None:
    test_masker()
    test_accepted()
    test_unsafe_evasions()
    test_ffi_surface()
    test_headers()
    test_lints()
    test_safety_comments()
    test_inventory()
    test_manifests()
    test_cli()
    test_hardening()
    test_symlinks()
    test_hosted_liveness()
    test_review_findings()
    test_structural_rules()
    print("owner-bridge unsafe-policy checker rejects every forged boundary")


if __name__ == "__main__":
    main()
