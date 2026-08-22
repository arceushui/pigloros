#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

fn main() -> std::process::ExitCode {
    drop(std::io::Write::write_all(
        &mut std::io::stderr().lock(),
        format!("{} {}\n", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")).as_bytes(),
    ));
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    #[test]
    fn cover_main_stub() {
        let _ = super::main();
    }
}
