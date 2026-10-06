#![forbid(unsafe_code)]

//! `pos-plugin-worker`: runs one community Plugin Component invocation.
//!
//! Launched only by the `pos-plugin-supervisor` crate, once per invocation.
//! All logic lives in the library; this entry point only wires the process's
//! streams to it, and the test below runs it.

fn main() -> std::process::ExitCode {
    pos_plugin_worker::run_worker(
        std::env::args_os(),
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_test_process_is_not_a_supervised_worker() {
        // The test harness's arguments are not a single supervisor PID, so the
        // worker refuses before it reads a request.
        let code = super::main();
        assert_eq!(format!("{code:?}"), format!("{:?}", std::process::ExitCode::FAILURE));
    }
}
