//! `pos-sandboxd-conformance IMAGE CERTIFICATE_DER KEY_DESCRIPTION`: the #444
//! QEMU evidence guest's driver (feature `test-support`, never deployed).
//!
//! This file only wires [`pos_sandboxd::packaged_conformance::run`] to the
//! process: its arguments, standard input and output, and the production
//! detach of a held root. It has no branch of its own. The two functions
//! below run only on a root that the packaged mountfsd and kernel actually
//! mounted, so only the evidence guest executes them (owner decision Q2).

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use pos_sandboxd::{
    packaged_conformance::{exit_status, run, runtime, Release, RELEASE_DEADLINE},
    PreparedAttemptDirectory, VerifiedRootMount,
};

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() -> std::process::ExitCode {
    let arguments = std::env::args_os().skip(1).collect();
    exit_status(
        runtime().and_then(|runtime| {
            runtime.block_on(run(
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

/// The mounted root's report text: its mount ID and attempt root path.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn describe(mount: &VerifiedRootMount) -> String {
    format!("{}\t{}", mount.mount_id(), mount.root_directory().as_str())
}

/// The production detach, under the driver's absolute cleanup deadline.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn release(mount: VerifiedRootMount, directory: &PreparedAttemptDirectory) -> Release<'_> {
    Box::pin(async move {
        mount
            .detach(directory, tokio::time::Instant::now() + RELEASE_DEADLINE)
            .await
            .map(drop)
    })
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
