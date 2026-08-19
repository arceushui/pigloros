fn main() -> std::process::ExitCode {
    eprintln!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    std::process::ExitCode::SUCCESS
}
