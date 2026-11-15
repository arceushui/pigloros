#!/usr/bin/env python3
"""Keep the ADR-129 A5.9 authority trust-root seal inside the trusted composition roots (#1374).

`pos_core::AuthorityTrustRootSealV1` builds the `AuthenticatedPrincipalResultV1` and
`AuthorityRegistrySnapshotV1` values the authority evaluator trusts, and the metadata authority
installed by `pos_store::community::CommunityMetadataAuthorityV1::new`. Its constructor exists
only with `pos-core`'s `authority-trust-root` feature, so:

- only `apps/piglor-gateway`, `apps/pos-experiment` and `apps/pos-plugin-conformance-adapter`
  (the trusted composition roots) and `crates/pos-store` (the community owner, #560) may enable
  `authority-trust-root` in a deployable dependency table or forward it from a feature; every
  manifest may enable it from `[dev-dependencies]`;
- no feature named `local-admission-host`, nor any feature it reaches, forwards it, in any
  manifest: the local scheduled-admission host takes the seal from its caller and never mints it;
- outside `crates/pos-core/`, non-test code calls `for_composition_root` only at the pinned mint
  sites `apps/piglor-gateway/src/local_principal.rs`, `apps/pos-experiment/src/lib.rs`,
  `apps/pos-plugin-conformance-adapter/src/main.rs` and
  `crates/pos-store/src/community/attestation.rs` (the community owner's per-request snapshot and
  verified authentication result, ADR-129 R6.2(5)): exactly once each, only as the initializer
  of a `static`, and never inside a `macro_rules!` (which could expand it more than once). Crates
  that depend on an allowed crate compile the minter too (Cargo features are global) but cannot
  call it. Test code is exempt: a crate's top-level `tests` directory, an inline
  `#[cfg(test)] mod name { .. }`, and the file of a module declared `#[cfg(test)] mod name;`
  with all of its descendant modules. Any other guard (`cfg(all(test, ..))`, `#[path]`) is not
  recognised, so such a mint is rejected;
- non-test code pulls in files only by a plain string literal: `include!("..")`, `#[path = ".."]`
  or `include!(concat!(env!("CARGO_MANIFEST_DIR"), ".."))`, resolved and then checked as non-test
  code whatever else declares them (even under `tests` or with another extension), and
  `include!(concat!(env!("OUT_DIR"), ".."))` for build-script output. Every other `include!` or
  `path` form, including a `cfg_attr` that sets `path`, is rejected, as is a reference outside the
  repository. Build scripts and the files they pull in may not name the seal at all, not even in
  a literal, since they generate the `OUT_DIR` code. String and char literals are blanked
  (length-preserving) before any scan, so braces or names inside them change nothing;
- in non-test `crates/pos-core/src` code, the seal derives only `Debug` (no `cfg_attr` on it), has
  exactly one inherent impl (in `authority.rs`) whose only fn is `for_composition_root`, has no
  trait impl, no type alias and no `use .. as` rename, is never constructed by a literal (nor by
  `Self(())` outside that impl), and `for_composition_root` is never called, so no second
  constructor can bypass the doctests;
- no `default` feature closure reaches `authority-trust-root` or a feature that forwards it, and
  no `pos-core` feature forwards it;
- outside `crates/pos-core/` and the crates' top-level `tests` directories, no source re-exports
  the seal: no `pub use` names it, globs over a `pos_core` path, re-exports
  `pos_core::authority`, or re-exports the `pos_core` crate itself; no public fn, and no fn in a
  `pub trait`, returns it; no `pub enum` body names it; no type alias of any visibility names
  it; and no bare `pub` static, const, struct or field line names it
  (`pub(crate)`/`pub(super)` items other than aliases stay allowed);
- CI workflows, Dockerfiles and `.cargo/config*` never name the `authority-trust-root` feature,
  so no build flag can enable it outside the manifests above.

The source rule applies to the allowed crates too: they mint the seal for their own use and pass
it only by reference.

Stated limits: the check is textual. It does not cover `--all-features` builds (which enable the
feature by construction) nor build configuration outside manifests, workflows, Dockerfiles and
`.cargo/config*`; those stay a review responsibility.
"""

from __future__ import annotations

import argparse
import os
import re
import tomllib
from pathlib import Path

from check_counterfactual_adapter_seal import (
    CRATE_REEXPORT,
    PUBLIC_USE,
    _build_configs,
    _deployable_tables,
    _in_crate_tests,
    SKIPPED_PARTS,
)
from check_test_support_features import default_closure

FEATURE = "authority-trust-root"
SEAL_NAME = "AuthorityTrustRootSealV1"
SEAL = re.compile(rf"\b{SEAL_NAME}\b")
SEAL_MODULE = re.compile(r"\bauthority(?:as\w+)?(?:[,}]|$)|\bauthority::\{(?:.*,)?self\b")
PUBLIC_ITEM = re.compile(
    r"\bpub[ \t]+(?:type|static|struct|enum|"
    r"const\b(?![ \t]+(?:(?:async|unsafe|extern[ \t]+\"[^\"\n]*\")[ \t]+)*fn\b)|"
    rf"(?:r#)?[A-Za-z_]\w*[ \t]*:(?!:))[^\n]*\b{SEAL_NAME}\b"
)
SEAL_RETURN = re.compile(
    r"\bpub\s+(?:(?:const|async|unsafe|extern\s+\"[^\"]*\")\s+)*fn\b[^{;]*?->[^{;]*"
    rf"\b{SEAL_NAME}\b"
)
PUBLIC_BODY = re.compile(r"\bpub\s+(trait|enum)\b[^{;]*\{")
BODY_RETURN = re.compile(rf"\bfn\b[^{{;]*?->[^{{;]*\b{SEAL_NAME}\b")
ALIAS = re.compile(rf"\btype\s+\w+(?:<[^>]*>)?\s*=[^;]*\b{SEAL_NAME}\b")
ENABLING_MANIFESTS = (
    "apps/piglor-gateway/Cargo.toml",
    "apps/pos-experiment/Cargo.toml",
    "apps/pos-plugin-conformance-adapter/Cargo.toml",
    "crates/pos-store/Cargo.toml",
)
ADMISSION_FEATURE = "local-admission-host"
CORE_SOURCES = "crates/pos-core/"
CORE_SEAL_SOURCE = "crates/pos-core/src/authority.rs"
MINT = re.compile(r"\bfor_composition_root\b")
MINT_SITES = {
    "apps/piglor-gateway/src/local_principal.rs": 1,
    "apps/pos-experiment/src/lib.rs": 1,
    "apps/pos-plugin-conformance-adapter/src/main.rs": 1,
    "crates/pos-store/src/community/attestation.rs": 1,
}
TEST_ATTRIBUTES = r"#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*"
INLINE_TEST_MODULE = re.compile(TEST_ATTRIBUTES + r"\{")
OUTLINE_TEST_MODULE = re.compile(TEST_ATTRIBUTES + ";")
OUTLINE_MODULE = re.compile(r"(?:^|[;}\]\s])(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;")
SEAL_PATH = rf"(?:(?:\w+)?::)*{SEAL_NAME}\b"
SEAL_IMPL = re.compile(rf"\bimpl\b[^{{;]*?\bfor\s+{SEAL_PATH}")
SEAL_INHERENT = re.compile(rf"\bimpl\s+{SEAL_PATH}\s*\{{")
SEAL_ATTRIBUTES = re.compile(rf"((?:#\[[^\]]*\]\s*)*)pub\s+struct\s+{SEAL_NAME}\b")
DERIVE = re.compile(r"\bderive\(([^)]*)\)")
SEAL_LITERAL = re.compile(
    rf"(?<!struct )\b{SEAL_NAME}\s*(?:\(\s*\(\s*\)\s*\)|\{{\s*0\s*:)"
)
SELF_LITERAL = re.compile(r"\bSelf\s*(?:\(\s*\(\s*\)\s*\)|\{\s*0\s*:)")
FN_NAME = re.compile(r"\bfn\s+(\w+)")
MINT_DEFINITION = re.compile(r"\bfn\s+for_composition_root\b")
MACRO = re.compile(r"\bmacro_rules!\s*\w+\s*\{")
STATIC_MINT = re.compile(
    rf"\bstatic\s+[A-Z_][A-Z0-9_]*\s*:\s*{SEAL_PATH}\s*=\s*"
    rf"{SEAL_PATH}::for_composition_root\(\s*\)\s*;"
)
REFERENCE_START = re.compile(r"\binclude\s*!|#\[\s*path\b|\bcfg_attr\s*\(")
PLAIN_INCLUDE = re.compile(r'include!\(\s*"([^"\\]+)"\s*\)')
PLAIN_PATH = re.compile(r'#\[\s*path\s*=\s*"([^"\\]+)"\s*\]')
ENV_INCLUDE = re.compile(
    r'include!\(\s*concat!\(\s*env!\(\s*"(OUT_DIR|CARGO_MANIFEST_DIR)"\s*\)\s*,'
    r'\s*"([^"\\]+)"\s*\)\s*\)'
)
CFG_ATTR_PATH = re.compile(r"cfg_attr\s*\([^\]]*\bpath\s*=")
SEAL_RENAME = re.compile(rf"\b{SEAL_NAME}\s+as\s+\w+")
BUILD_SCRIPT = "build.rs"
TOKEN = re.compile(
    r'//[^\n]*|/\*|(?<!\w)b?r(#*)"(?:.|\n)*?"\1|(?<!\w)b?"(?:\\[\s\S]|[^"\\])*"'
    r"|(?<!\w)b?'(?:\\.|[^'\\\n])'"
)
BLOCK_COMMENT = re.compile(r"/\*|\*/")
BRACE = re.compile(r"[{}]")


def _forwards(members: list[str]) -> bool:
    return any(member == FEATURE or member.endswith(f"/{FEATURE}") for member in members)


def _closure(features: dict[str, list[str]], start: str) -> set[str]:
    """Return every local feature reachable from `start`, including `start`."""
    return default_closure({**features, "default": [start]}) - {"default"} | {start}


def _default_violations(name: str, features: dict[str, list[str]]) -> list[str]:
    reached = default_closure(features)
    if any(_forwards(features.get(feature, [])) for feature in reached):
        return [f"{name}: default feature enables {FEATURE}"]
    return []


def _forwarding_allowed(name: str, feature: str) -> bool:
    return name in ENABLING_MANIFESTS and feature != ADMISSION_FEATURE


def manifest_violations(root: Path) -> list[str]:
    found: list[str] = []
    for path in _sources(root.resolve(), "Cargo.toml"):
        name = path.relative_to(root).as_posix()
        manifest = tomllib.loads(path.read_text(encoding="utf-8"))
        features = manifest.get("features", {})
        found.extend(_default_violations(name, features))
        found.extend(
            f"{name}: feature {feature} forwards {FEATURE}"
            for feature, members in features.items()
            if _forwards(members) and not _forwarding_allowed(name, feature)
        )
        if ADMISSION_FEATURE in features:
            found.extend(
                f"{name}: feature {ADMISSION_FEATURE} reaches {FEATURE} through {feature}"
                for feature in sorted(_closure(features, ADMISSION_FEATURE) - {ADMISSION_FEATURE})
                if _forwards(features.get(feature, []))
            )
        if name in ENABLING_MANIFESTS:
            continue
        for section, dependencies in _deployable_tables(manifest):
            found.extend(
                f"{name}: [{section}] {dependency} enables {FEATURE}"
                for dependency, spec in dependencies.items()
                if isinstance(spec, dict) and FEATURE in spec.get("features", [])
            )
    return found


def _pos_core_leak(compact: str) -> bool:
    if not compact.startswith(("pos_core::", "::pos_core::")):
        return False
    return "*" in compact or SEAL_MODULE.search(compact) is not None


def _public_bodies(code: str, keyword: str) -> list[str]:
    """Return the brace-balanced bodies of every `pub trait` or `pub enum` in `code`."""
    bodies: list[str] = []
    for match in PUBLIC_BODY.finditer(code):
        if match.group(1) != keyword:
            continue
        bodies.append(code[match.end() : _block_end(code, match.end())])
    return bodies


def _leaks(name: str, code: str) -> list[str]:
    found: list[str] = []
    for statement in PUBLIC_USE.findall(code):
        compact = re.sub(r"\s+", "", statement)
        if CRATE_REEXPORT.search(compact):
            found.append(f"{name}: re-exports the pos_core crate")
        elif SEAL.search(statement) or _pos_core_leak(compact):
            found.append(f"{name}: re-exports the authority trust-root seal")
    enum_leak = any(SEAL.search(body) for body in _public_bodies(code, "enum"))
    if PUBLIC_ITEM.search(code) or enum_leak or ALIAS.search(code):
        found.append(f"{name}: exposes the authority trust-root seal from a public item")
    trait_leak = any(BODY_RETURN.search(body) for body in _public_bodies(code, "trait"))
    if SEAL_RETURN.search(code) or trait_leak:
        found.append(f"{name}: returns the authority trust-root seal from a public fn")
    return found


def _block_comment_end(text: str, start: int) -> int:
    """Return the index after the (possibly nested) block comment opening at `start`."""
    depth = 0
    for match in BLOCK_COMMENT.finditer(text, start):
        depth += 1 if match.group(0) == "/*" else -1
        if not depth:
            return match.end()
    return len(text)


def _scan(text: str) -> tuple[str, str]:
    """Return `text` without comments, and that text with every literal interior blanked.

    One pass replaces each comment with a space, as `strip_comments` does, and blanks the
    interior of every string, raw string and char literal in place, so offsets in the two
    results agree. A lifetime is not a char literal: one needs its closing quote.
    """
    kept: list[str] = []
    blanked: list[str] = []
    position = 0
    while (match := TOKEN.search(text, position)) is not None:
        kept.append(text[position : match.start()])
        blanked.append(text[position : match.start()])
        token = match.group(0)
        if token.startswith("/"):
            kept.append(" ")
            blanked.append(" ")
            end = match.end() if token.startswith("//") else _block_comment_end(text, match.start())
            position = end
        else:
            kept.append(token)
            blanked.append(_blank_interior(match))
            position = match.end()
    kept.append(text[position:])
    blanked.append(text[position:])
    return "".join(kept), "".join(blanked)


def _blank_interior(match: re.Match[str]) -> str:
    text = match.group(0)
    opening = text.index(text[-1] if text[-1] == "'" else '"') + 1
    closing = len(text) - (len(match.group(1) or "") + 1 if text[-1] != "'" else 1)
    interior = "".join("\n" if char == "\n" else " " for char in text[opening:closing])
    return text[:opening] + interior + text[closing:]



def _crate_directory(path: Path) -> Path:
    return next(
        (parent for parent in path.parents if (parent / "Cargo.toml").is_file()), path.parent
    )


def _references(path: Path, raw: str, blanked: str) -> tuple[list[Path], list[str]]:
    """Return the files that non-test `raw` (the code of `path`) pulls in, and refused forms.

    `include!` must take exactly one plain string literal, or be
    `include!(concat!(env!("CARGO_MANIFEST_DIR"), ".."))`, resolved against the crate, or
    `include!(concat!(env!("OUT_DIR"), ".."))`, whose generated code the build-script rule
    covers; `#[path]` must take exactly one plain string literal; and no `cfg_attr` may set
    `path`. `include_str!` and `include_bytes!` (which `include\\s*!` does not match) pull in
    data, not code, so they are allowed.
    """
    spans = _test_spans(blanked)
    files: list[Path] = []
    refused: list[str] = []
    for match in REFERENCE_START.finditer(blanked):
        start = match.start()
        if any(low <= start < high for low, high in spans):
            continue
        token = match.group(0)
        if token.startswith("cfg_attr"):
            if CFG_ATTR_PATH.match(blanked, start):
                refused.append("a cfg_attr path")
            continue
        plain = (PLAIN_INCLUDE if token.startswith("include") else PLAIN_PATH).match(raw, start)
        generated = ENV_INCLUDE.match(raw, start) if token.startswith("include") else None
        if plain:
            files.append((path.parent / plain.group(1)).resolve())
        elif generated and generated.group(1) == "CARGO_MANIFEST_DIR":
            relative = generated.group(2).lstrip("/")
            files.append((_crate_directory(path) / relative).resolve())
        elif not generated:
            refused.append(f"`{raw[start : start + 40].splitlines()[0]}`")
    return files, refused


def _block_end(code: str, start: int) -> int:
    depth = 1
    for match in BRACE.finditer(code, start):
        depth += 1 if match.group(0) == "{" else -1
        if not depth:
            return match.end()
    return len(code)


def _test_spans(code: str) -> list[tuple[int, int]]:
    """Return the spans of every inline `#[cfg(test)] mod name { ... }` in `code`."""
    return [
        (match.start(), _block_end(code, match.end()))
        for match in INLINE_TEST_MODULE.finditer(code)
    ]


def _module_files(path: Path, module: str) -> list[Path]:
    owns_directory = path.name in ("lib.rs", "main.rs", "mod.rs")
    directory = path.parent if owns_directory else path.with_suffix("")
    return [directory / f"{module}.rs", directory / module / "mod.rs"]


def _test_files(codes: dict[Path, str]) -> set[Path]:
    """Return the files of modules declared `#[cfg(test)] mod name;`, and their descendants."""
    pending = [
        candidate
        for path, code in codes.items()
        for match in OUTLINE_TEST_MODULE.finditer(code)
        for candidate in _module_files(path, match.group(1))
        if candidate in codes
    ]
    found: set[Path] = set()
    while pending:
        path = pending.pop()
        if path in found:
            continue
        found.add(path)
        pending.extend(
            candidate
            for match in OUTLINE_MODULE.finditer(codes[path])
            for candidate in _module_files(path, match.group(1))
            if candidate in codes
        )
    return found


def _non_test_references(
    raw: dict[Path, str], codes: dict[Path, str], non_test: list[Path], base: Path
) -> tuple[set[Path], list[str]]:
    """Return files that non-test code pulls in by `include!` or `#[path]`, transitively.

    A referenced file that is not a scanned `.rs` file (another extension, or a file under a
    skipped directory) is read and added to `raw` and `codes`, so its code is checked as
    non-test code too.
    A reference outside the repository is reported, since its code cannot be checked.
    """
    found: set[Path] = set()
    outside: list[str] = []
    pending = list(non_test)
    while pending:
        path = pending.pop()
        files, refused = _references(path, raw[path], codes[path])
        outside.extend(
            f"{path.relative_to(base).as_posix()}: pulls in a file by a non-literal path: {form}"
            for form in refused
        )
        for target in files:
            if target in found or not target.is_file():
                continue
            if not target.is_relative_to(base):
                outside.append(f"{path.relative_to(base).as_posix()}: includes {target}")
                continue
            if target not in raw:
                text = target.read_text(encoding="utf-8", errors="replace")
                raw[target], codes[target] = _scan(text)
            found.add(target)
            pending.append(target)
    return found, outside


def _without_tests(code: str) -> str:
    """Return `code` with every inline `#[cfg(test)]` module removed."""
    kept: list[str] = []
    position = 0
    for start, end in _test_spans(code):
        if start >= position:
            kept.append(code[position:start])
            position = end
    kept.append(code[position:])
    return "".join(kept)


def _mint_violations(name: str, code: str) -> list[str]:
    code = _without_tests(code)
    mints = len(MINT.findall(code))
    expected = MINT_SITES.get(name, 0)
    found: list[str] = []
    macros = [code[match.end() : _block_end(code, match.end())] for match in MACRO.finditer(code)]
    if any(MINT.search(body) for body in macros):
        found.append(f"{name}: expands the authority trust-root seal mint from a macro")
    seal = "the authority trust-root seal"
    if mints != expected and not expected:
        found.append(f"{name}: mints {seal} outside its pinned mint sites")
    elif mints != expected:
        found.append(f"{name}: mints {seal} {mints} times, expected {expected}")
    elif len(STATIC_MINT.findall(code)) != expected:
        found.append(f"{name}: mints {seal} other than as a static initializer")
    return found


def _seal_derives(code: str) -> list[str] | None:
    """Return the seal's derives, or None when its attributes are conditional or absent."""
    blocks = [match.group(1) for match in SEAL_ATTRIBUTES.finditer(code)]
    if len(blocks) != 1 or "cfg_attr" in blocks[0]:
        return None
    return sorted(
        item.strip()
        for derive in DERIVE.findall(blocks[0])
        for item in derive.split(",")
        if item.strip()
    )


def _core_seal_violations(name: str, code: str) -> list[str]:
    code = _without_tests(code)
    found: list[str] = []
    if SEAL_IMPL.search(code):
        found.append(f"{name}: implements a trait for the authority trust-root seal")
    if ALIAS.search(code) or SEAL_RENAME.search(code):
        found.append(f"{name}: aliases the authority trust-root seal")
    bodies = [
        (match.end(), _block_end(code, match.end())) for match in SEAL_INHERENT.finditer(code)
    ]
    inherent = [FN_NAME.findall(code[start:end]) for start, end in bodies]
    if name == CORE_SEAL_SOURCE and inherent != [["for_composition_root"]]:
        found.append(f"{name}: the seal's only constructor must be for_composition_root")
    elif name != CORE_SEAL_SOURCE and inherent:
        found.append(f"{name}: adds an inherent impl to the authority trust-root seal")
    if name == CORE_SEAL_SOURCE and _seal_derives(code) != ["Debug"]:
        found.append(f"{name}: the seal may derive only Debug")
    outside = "".join(
        code[end:start]
        for end, start in zip([0, *[e for _, e in bodies]], [*[s for s, _ in bodies], len(code)])
    )
    if SEAL_LITERAL.search(code) or (name == CORE_SEAL_SOURCE and SELF_LITERAL.search(outside)):
        found.append(f"{name}: constructs the seal outside for_composition_root")
    if len(MINT.findall(code)) != len(MINT_DEFINITION.findall(code)):
        found.append(f"{name}: mints the authority trust-root seal inside pos-core")
    return found


def _build_script_violations(
    raw: dict[Path, str], codes: dict[Path, str], base: Path
) -> list[str]:
    """Reject a build script, or a file it pulls in, that names the seal even in a literal.

    Code a build script generates into `OUT_DIR` reaches a crate through
    `include!(concat!(env!("OUT_DIR"), ..))`, which this checker cannot read; the script's own
    text is checked instead, literals included.
    """
    pending = [path for path in raw if path.name == BUILD_SCRIPT]
    seen: set[Path] = set()
    found: list[str] = []
    while pending:
        path = pending.pop()
        if path in seen or path not in raw:
            continue
        seen.add(path)
        if MINT.search(raw[path]) or SEAL.search(raw[path]):
            found.append(f"{path.relative_to(base).as_posix()}: build code names the seal")
        files, _ = _references(path, raw[path], codes[path])
        pending.extend(files)
    return found


def _sources(root: Path, suffix: str) -> list[Path]:
    """Return every file named `suffix` (or ending in it, for an extension) under `root`.

    The top-level build, VCS and tool directories are skipped without being walked.
    """
    found: list[Path] = []
    for directory, subdirectories, files in os.walk(root):
        if Path(directory) == root:
            subdirectories[:] = [name for name in subdirectories if name not in SKIPPED_PARTS]
        found.extend(
            Path(directory) / name
            for name in files
            if name == suffix or (suffix.startswith(".") and name.endswith(suffix))
        )
    return sorted(found)


def source_violations(root: Path) -> list[str]:
    base = root.resolve()
    raw: dict[Path, str] = {}
    codes: dict[Path, str] = {}
    for path in _sources(base, ".rs"):
        raw[path], codes[path] = _scan(path.read_text(encoding="utf-8", errors="replace"))
    tests = {
        path
        for path in _test_files(codes)
        if not _in_crate_tests(path.relative_to(base), base)
    }
    referenced, found = _non_test_references(
        raw,
        codes,
        [
            path
            for path in codes
            if path not in tests and not _in_crate_tests(path.relative_to(base), base)
        ],
        base,
    )
    found.extend(_build_script_violations(raw, codes, base))
    for path, code in codes.items():
        relative = path.relative_to(base)
        name = relative.as_posix()
        test_only = (path in tests or _in_crate_tests(relative, base)) and path not in referenced
        if name.startswith(CORE_SOURCES):
            if not test_only:
                found.extend(_core_seal_violations(name, code))
            continue
        if not test_only:
            found.extend(_mint_violations(name, code))
        if not _in_crate_tests(relative, base):
            found.extend(_leaks(name, code))
    found.extend(
        f"{name}: pinned mint site is missing"
        for name in MINT_SITES
        if (root / name).resolve() not in codes
    )
    return found


def config_violations(root: Path) -> list[str]:
    return [
        f"{path.relative_to(root).as_posix()}: enables {FEATURE} outside a manifest"
        for path in _build_configs(root)
        if FEATURE in path.read_text(encoding="utf-8", errors="replace")
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    root = parser.parse_args().root.resolve()
    found = [
        *manifest_violations(root),
        *source_violations(root),
        *config_violations(root),
    ]
    if found:
        raise SystemExit("\n".join(found))
    print(f"{FEATURE} and its seal stay inside the trusted composition roots")


if __name__ == "__main__":
    main()
