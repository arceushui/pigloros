//! The `PiglorOS` systemd Sandbox Provider binary. The mode is chosen by argv.

#[cfg(not(target_os = "linux"))]
compile_error!("pos-sandboxd is the Linux systemd provider and builds only on Linux");

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    pos_sandboxd::run(std::env::args_os().skip(1))
}
