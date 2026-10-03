#!/usr/bin/env bash
# ADR-113 §7 staged-reducer purity guard (acceptance case 2).
#
# 1. Every admitted Plugin crate carries the canonical clippy.toml, whose
#    thresholds equal the root clippy.toml, and a src/reducer.rs that opens
#    with the forbid header and asserts its reducer is zero-sized.
# 2. A scratch crate inside the repository, below the root clippy.toml, uses
#    a Plugin crate's clippy.toml and reducer.rs header. Each forbidden use in
#    its reducer.rs must fail Clippy, a reducer with a field must fail the
#    zero-size assertion, and the same uses outside reducer.rs must pass.
#    A failing variant also proves that Clippy reads the nearest clippy.toml
#    instead of the root one, which has no disallowed lists.
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$root"

crates=(
  plugins/agent
  plugins/bridges
  plugins/entities/rule-agent
  plugins/eval
  plugins/observations/synthetic
  plugins/persona
  plugins/society
  plugins/world
)
canonical="plugins/agent/clippy.toml"
failures=0

fail() {
  printf 'reducer purity guard: %s\n' "$1" >&2
  failures=$((failures + 1))
}

forbid_header() {
  sed -n '/^#!\[forbid($/,/^)\]$/p' "$1"
}

while IFS= read -r threshold; do
  if ! tr -d ' ' <"$canonical" | grep -qxF -- "$threshold"; then
    fail "$canonical does not copy root setting $threshold"
  fi
done < <(grep -E '^[a-z-]+-threshold = ' clippy.toml | tr -d ' ')

header="$(forbid_header plugins/agent/src/reducer.rs)"
if [[ -z "$header" ]]; then
  printf 'reducer purity guard: %s\n' \
    "plugins/agent/src/reducer.rs has no #![forbid(...)] header to copy" >&2
  exit 1
fi
for lint in disallowed_methods disallowed_types disallowed_macros print_stdout print_stderr \
  dbg_macro exit; do
  if ! grep -qE -- "^    clippy::${lint},?$" <<<"$header"; then
    fail "the reducer.rs forbid header does not name clippy::${lint}"
  fi
done

for crate in "${crates[@]}"; do
  if ! cmp -s -- "$canonical" "$crate/clippy.toml"; then
    fail "$crate/clippy.toml differs from $canonical"
  fi
  if [[ "$(forbid_header "$crate/src/reducer.rs")" != "$header" ]]; then
    fail "$crate/src/reducer.rs lacks the canonical forbid header"
  fi
  if ! grep -qE '^const _: \(\) = assert!\(core::mem::size_of::<[A-Za-z]+Reducer>\(\) == 0\);$' \
    "$crate/src/reducer.rs"; then
    fail "$crate/src/reducer.rs lacks its zero-size assertion"
  fi
done

mkdir -p -- target
scratch="$(mktemp -d "$root/target/reducer-purity-guard.XXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT
mkdir -p -- "$scratch/src"
cp -- "$canonical" "$scratch/clippy.toml"
cat >"$scratch/Cargo.toml" <<'TOML'
[package]
name = "reducer-purity-guard"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[lints.clippy]
all = { level = "deny", priority = -1 }
pedantic = { level = "deny", priority = -1 }
nursery = { level = "deny", priority = -1 }
dbg_macro = "deny"
print_stdout = "deny"
print_stderr = "deny"
exit = "deny"
TOML

write_crate() {
  local lib_body="$1"
  local reducer_body="$2"
  printf '%s\n' "$lib_body" >"$scratch/src/lib.rs"
  {
    printf '%s\n\n' "$header"
    printf '%s\n' "$reducer_body"
  } >"$scratch/src/reducer.rs"
}

run_clippy() {
  CARGO_TARGET_DIR="$scratch/target" cargo clippy \
    --manifest-path "$scratch/Cargo.toml" --quiet --color never -- -D warnings 2>&1
}

clean_reducer='pub struct GuardReducer;

const _: () = assert!(core::mem::size_of::<GuardReducer>() == 0);'

plain_lib='mod reducer;

pub use reducer::GuardReducer;'

expect_fails() {
  local name="$1" expected="$2" lib_body="$3" reducer_body="$4" output
  write_crate "$lib_body" "$reducer_body"
  if output="$(run_clippy)"; then
    fail "variant '$name' passed Clippy"
  elif ! grep -qF -- "$expected" <<<"$output"; then
    printf '%s\n' "$output" >&2
    fail "variant '$name' failed without '$expected'"
  else
    printf 'reducer purity guard: %s rejected\n' "$name"
  fi
}

expect_fails "fs write" 'disallowed method `std::fs::write`' "$plain_lib" "$clean_reducer
pub fn effect() {
    let _ = std::fs::write(\"guard\", b\"x\");
}"
expect_fails "stdout handle" 'disallowed method `std::io::stdout`' "$plain_lib" "$clean_reducer
pub fn effect() -> std::io::Stdout {
    std::io::stdout()
}"
expect_fails "process exit" 'disallowed method `std::process::exit`' "$plain_lib" "$clean_reducer
pub fn effect() {
    std::process::exit(0);
}"
expect_fails "thread sleep" 'disallowed method `std::thread::sleep`' "$plain_lib" "$clean_reducer
pub fn effect() {
    std::thread::sleep(std::time::Duration::ZERO);
}"
expect_fails "atomic u8" 'disallowed type `std::sync::atomic::AtomicU8`' "$plain_lib" "$clean_reducer
pub static FLAG: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);"
expect_fails "once lock" 'disallowed type `std::sync::OnceLock`' "$plain_lib" "$clean_reducer
pub static CELL: std::sync::OnceLock<u8> = std::sync::OnceLock::new();"
expect_fails "thread local" 'disallowed macro `std::thread_local`' "$plain_lib" "$clean_reducer
std::thread_local! {
    pub static LOCAL: u8 = const { 0 };
}"
expect_fails "println" 'println!' "$plain_lib" "$clean_reducer
pub fn effect() {
    println!(\"guard\");
}"
expect_fails "eprintln" 'eprintln!' "$plain_lib" "$clean_reducer
pub fn effect() {
    eprintln!(\"guard\");
}"
expect_fails "dbg" 'dbg!' "$plain_lib" "$clean_reducer
pub fn effect() -> u8 {
    dbg!(1)
}"
expect_fails "inner allow" 'incompatible with previous forbid' "$plain_lib" "$clean_reducer
#[allow(clippy::disallowed_methods)]
pub fn effect() -> std::io::Stdin {
    std::io::stdin()
}"
expect_fails "reducer with a field" 'size_of::<FieldReducer>() == 0' "mod reducer;

pub use reducer::FieldReducer;" 'pub struct FieldReducer(pub u8);

const _: () = assert!(core::mem::size_of::<FieldReducer>() == 0);'

write_crate 'mod reducer;

pub use reducer::GuardReducer;

#[expect(
    clippy::disallowed_types,
    reason = "ADR-113 §7: the disallowed lists apply only inside reducer.rs"
)]
pub static CELL: std::sync::OnceLock<u8> = std::sync::OnceLock::new();

#[expect(
    clippy::disallowed_methods,
    reason = "ADR-113 §7: the disallowed lists apply only inside reducer.rs"
)]
pub fn effect() {
    let _ = std::fs::write("guard", b"x");
}' "$clean_reducer"
if ! output="$(run_clippy)"; then
  printf '%s\n' "$output" >&2
  fail "the same uses outside reducer.rs failed Clippy"
else
  printf 'reducer purity guard: uses outside reducer.rs accepted\n'
fi

if ((failures > 0)); then
  exit 1
fi
printf 'reducer purity guard: OK\n'
