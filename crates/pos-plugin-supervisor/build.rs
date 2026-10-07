//! Detects an `AddressSanitizer` build, for the worker data-ceiling allowance.
//!
//! The sanitizer's shadow memory is writable private address space, which
//! `RLIMIT_DATA` charges, so an instrumented worker cannot start under the
//! data ceiling. `src/launch.rs` lifts only that one ceiling when this script
//! sets `asan_build`; every other ceiling stays. Cargo passes the sanitizer
//! flag to this script through `CARGO_ENCODED_RUSTFLAGS`.
//!
//! The cfg reflects only the flags this package was built with, so the
//! supervisor and its worker must be built together with the same flags: a
//! sanitized worker under an unsanitized supervisor cannot start under the
//! data ceiling.

use std::io::Write;

/// Whether the `\x1f`-separated `flags` enable `AddressSanitizer`.
///
/// Whole flags are matched, in the two spellings `RUSTFLAGS` uses
/// (`-Z sanitizer=address` and `-Zsanitizer=address`), so that an unrelated
/// flag that merely contains the text cannot silently lift the data ceiling.
/// A combined spelling such as `-Zsanitizer=address,leak` is deliberately not
/// matched: the ceiling then stays and the worker fails closed.
fn sanitizes_address(flags: &str) -> bool {
    let flags: Vec<&str> = flags.split('\x1f').collect();
    flags.contains(&"-Zsanitizer=address")
        || flags
            .windows(2)
            .any(|pair| pair == ["-Z", "sanitizer=address"])
}

fn main() {
    let mut out = std::io::stdout();
    drop(writeln!(out, "cargo::rustc-check-cfg=cfg(asan_build)"));
    drop(writeln!(out, "cargo::rerun-if-changed=build.rs"));
    let flags = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    if sanitizes_address(&flags) {
        drop(writeln!(out, "cargo::rustc-cfg=asan_build"));
    }
}
