#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

fn main() -> std::process::ExitCode {
    eprintln!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    std::process::ExitCode::SUCCESS
}
