//! The `PiglorOS` systemd Sandbox Provider binary. The mode is chosen by argv.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    pos_sandboxd::run(std::env::args_os().skip(1))
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(2)
}
