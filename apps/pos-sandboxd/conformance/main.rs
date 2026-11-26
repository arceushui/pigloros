//! `pos-sandboxd-conformance IMAGE CERTIFICATE_DER KEY_DESCRIPTION ADAPTER
//! [ADAPTER_ARGUMENT...]`: the #444
//! QEMU evidence guest's driver (feature `test-support`, never deployed).
//!
//! This file only wires [`pos_sandboxd::packaged_conformance::run_mode`] to the
//! process: its arguments, standard input and output, and the library's
//! production `describe` and `release` of a held root. It has no branch of
//! its own.

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use pos_sandboxd::packaged_conformance::{describe, exit_status, release, run_mode, runtime};

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() -> std::process::ExitCode {
    let arguments = std::env::args_os().skip(1).collect();
    exit_status(
        runtime().and_then(|runtime| {
            runtime.block_on(run_mode(
                arguments,
                std::io::stdin(),
                &mut std::io::stdout(),
                describe,
                release,
            ))
        }),
        &mut std::io::stderr(),
    )
}

// Elsewhere the package still builds with every feature; the binary only
// reports that it cannot run. A macro keeps this stub out of the mutation
// scope: it is never compiled, and so never tested, on the guest targets.
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
macro_rules! unsupported_platform_main {
    () => {
        fn main() -> std::process::ExitCode {
            use std::io::Write;
            writeln!(
                std::io::stderr(),
                "pos-sandboxd-conformance runs only in the #444 Linux evidence guest"
            )
            .ok();
            std::process::ExitCode::FAILURE
        }
    };
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
unsupported_platform_main!();
