//! Detects an `AddressSanitizer` build, for the worker data-ceiling allowance.
//!
//! The sanitizer's shadow memory is writable private address space, which
//! `RLIMIT_DATA` charges, so an instrumented worker cannot start under the
//! data ceiling. `src/launch.rs` lifts only that one ceiling when this script
//! sets `asan_build`; every other ceiling stays. Cargo passes the sanitizer
//! flag to this script through `CARGO_ENCODED_RUSTFLAGS`.

use std::io::Write;

fn main() {
    let mut out = std::io::stdout();
    drop(writeln!(out, "cargo::rustc-check-cfg=cfg(asan_build)"));
    drop(writeln!(
        out,
        "cargo::rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS"
    ));
    let flags = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    if flags.contains("sanitizer=address") {
        drop(writeln!(out, "cargo::rustc-cfg=asan_build"));
    }
}
