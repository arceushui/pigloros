//! The `PiglorOS` systemd Sandbox Provider binary. The mode is chosen by argv.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    pos_sandboxd::run(std::env::args_os().skip(1))
}

// Off Linux the package still builds, so the workspace does; the binary only
// reports that it cannot run. A macro keeps this stub out of the mutation
// scope: it is never compiled, and so never tested, on Linux.
#[cfg(not(target_os = "linux"))]
macro_rules! unsupported_platform_main {
    () => {
        fn main() -> std::process::ExitCode {
            use std::io::Write;
            writeln!(
                std::io::stderr(),
                "pos-sandboxd is the Linux systemd provider and cannot run on this platform"
            )
            .ok();
            std::process::ExitCode::FAILURE
        }
    };
}

#[cfg(not(target_os = "linux"))]
unsupported_platform_main!();
