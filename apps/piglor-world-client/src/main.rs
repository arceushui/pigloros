#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(all(feature = "runtime", not(target_arch = "wasm32"), not(test)))]
#[rustfmt::skip]
fn main() {
    std::process::exit(run_main(piglor_world_client::run_native));
}

#[cfg(all(feature = "runtime", not(target_arch = "wasm32")))]
fn run_main(run: impl FnOnce() -> Result<(), piglor_world_client::ClientError>) -> i32 {
    match run() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(all(feature = "runtime", target_arch = "wasm32", not(test)))]
fn main() {}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(all(not(feature = "runtime"), not(test)))]
fn main() {}

#[cfg(all(feature = "runtime", not(target_arch = "wasm32"), test))]
mod tests {
    use super::run_main;
    use piglor_world_client::ClientError;

    #[test]
    fn run_main_returns_success_for_a_running_client() {
        assert_eq!(run_main(|| Ok(())), 0);
    }

    #[test]
    fn run_main_reports_client_errors() {
        assert_eq!(
            run_main(|| Err(ClientError::Invalid("test failure".to_owned()))),
            1
        );
    }
}
