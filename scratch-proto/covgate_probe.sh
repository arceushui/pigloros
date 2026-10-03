#!/usr/bin/env bash
# THROWAWAY (#471): check ADR-110 r6 §15 claims about covgate 0.2.0:
#  (1) list-form include/exclude parse; (2) exclude requires include;
#  (3) nearest covgate.toml from cwd wins, patterns relative to repo root;
#  (4) root list-form gate still measures a changed codec file.
set -u
W="${RUNNER_TEMP:-/tmp}/cgfix"
rm -rf "$W"; mkdir -p "$W"; cd "$W"
git init -q -b main . && git config user.email p@x && git config user.name p
mkdir -p crates/pos-owner-bridge-windows/src/ffi crates/codec/src
cat > Cargo.toml <<'T'
[workspace]
members = ["crates/pos-owner-bridge-windows", "crates/codec"]
resolver = "2"
T
cat > crates/pos-owner-bridge-windows/Cargo.toml <<'T'
[package]
name = "shim"
version = "0.0.0"
edition = "2021"
T
cat > crates/codec/Cargo.toml <<'T'
[package]
name = "codec"
version = "0.0.0"
edition = "2021"
T
cat > crates/pos-owner-bridge-windows/src/lib.rs <<'T'
pub mod ffi;
pub fn covered() -> u32 {
    1
}
#[cfg(test)]
mod t {
    #[test]
    fn t() {
        assert_eq!(super::covered() + super::ffi::f(), 3);
    }
}
T
cat > crates/pos-owner-bridge-windows/src/ffi/mod.rs <<'T'
pub fn f() -> u32 {
    2
}
T
cat > crates/codec/src/lib.rs <<'T'
pub fn c() -> u32 {
    3
}
#[cfg(test)]
mod t {
    #[test]
    fn t() {
        assert_eq!(super::c(), 3);
    }
}
T
ROOT_LIST='[[gates]]
name = "new-production-rust-code"
include = ["**/src/**/*.rs"]
exclude = ["crates/pos-owner-bridge-windows/**"]
fail-under-lines = 99
fail-under-regions = 99'
NESTED='[[gates]]
name = "owner-bridge-windows-shim"
include = ["crates/pos-owner-bridge-windows/src/**/*.rs"]
exclude = ["crates/pos-owner-bridge-windows/src/ffi/**"]
fail-under-lines = 99
fail-under-regions = 99'
echo "$ROOT_LIST" > covgate.toml
echo "$NESTED" > crates/pos-owner-bridge-windows/covgate.toml
git add -A && git commit -qm base
UNCOV='
pub fn uncovered(x: u32) -> u32 {
    if x > 5 {
        x * 2
    } else {
        x + 1
    }
}'
scenario() { # name file content
  git checkout -q -B "$1" main
  printf '%s\n' "$3" >> "$2"
  git commit -qam "$1"
  cargo llvm-cov --workspace --json --output-path "$W/$1.json" >/dev/null 2>"$W/$1.llvmcov.log" || { echo "llvm-cov failed for $1"; cat "$W/$1.llvmcov.log"; }
}
run() { # label cwd report
  echo "---- [$1] cwd=$2 report=$3"
  git -C "$W" checkout -q "$3"
  ( cd "$2" && covgate check "$W/$3.json" --base main --no-github-summary ) 2>&1 | sed 's/^/    /'
  echo "    exit=${PIPESTATUS[0]}"
}
scenario s1_ffi_uncovered crates/pos-owner-bridge-windows/src/ffi/mod.rs "$UNCOV"
scenario s2_shim_uncovered crates/pos-owner-bridge-windows/src/lib.rs "$UNCOV"
scenario s3_codec_uncovered crates/codec/src/lib.rs "$UNCOV"
scenario s4_codec_covered crates/codec/src/lib.rs '
pub fn c2() -> u32 {
    4
}
#[test]
fn c2_t() {
    assert_eq!(c2(), 4);
}'
covgate --version 2>&1 | sed 's/^/covgate version: /'
echo "==== ROOT list-form config (expect: s1 pass, s2 pass, s3 FAIL, s4 pass measuring codec)"
for s in s1_ffi_uncovered s2_shim_uncovered s3_codec_uncovered s4_codec_covered; do run "root/$s" "$W" "$s"; done
echo "==== NESTED config from crates/pos-owner-bridge-windows (expect gate name owner-bridge-windows-shim; s1 pass, s2 FAIL, s3 pass/none)"
for s in s1_ffi_uncovered s2_shim_uncovered s3_codec_uncovered; do run "nested/$s" "$W/crates/pos-owner-bridge-windows" "$s"; done
echo "==== NESTED dir without its own file but a deeper cwd (crates/pos-owner-bridge-windows/src) — nearest-upward search"
run "nested-src/s2" "$W/crates/pos-owner-bridge-windows/src" s2_shim_uncovered
echo "==== exclude WITHOUT include (expect config error)"
printf '[[gates]]\nname = "x"\nexclude = ["crates/**"]\nfail-under-lines = 99\n' > covgate.toml
run "exclude-only" "$W" s3_codec_uncovered
echo "==== main's string-form include (expect parse OK, s3 FAIL)"
printf '[[gates]]\nname = "new-production-rust-code"\ninclude = "**/src/**/*.rs"\nfail-under-lines = 99\nfail-under-regions = 99\n' > covgate.toml
run "string-form" "$W" s3_codec_uncovered
echo "==== string-form exclude (expect parse OK)"
printf '[[gates]]\nname = "s"\ninclude = "**/src/**/*.rs"\nexclude = "crates/pos-owner-bridge-windows/**"\nfail-under-lines = 99\n' > covgate.toml
run "string-exclude/s2" "$W" s2_shim_uncovered
git checkout -q -- covgate.toml 2>/dev/null || true
