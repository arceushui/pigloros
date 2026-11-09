#![forbid(unsafe_code)]

//! `pos-ni-g-ops-worker`: the community Plugin Component worker of the G-OPS
//! non-interference subject (ADR-062 Revision 8 slice N3, #1231).
//!
//! It is `pos-plugin-worker` itself: this entry point only wires the
//! process's arguments and standard streams to `pos_plugin_worker`, so the
//! tests of this crate can name the program the supervisor launches. It
//! requires the `test-support` feature and runs only on Linux.

fn main() -> std::process::ExitCode {
    // The worker supervisor runs only on Linux; elsewhere this program fails.
    #[cfg(target_os = "linux")]
    {
        pos_plugin_worker::run_worker(
            std::env::args_os(),
            &mut std::io::stdin().lock(),
            &mut std::io::stdout().lock(),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::process::ExitCode::FAILURE
    }
}
