#![forbid(unsafe_code)]

//! `pos-ni-g-fork-subject`: the fresh-process Local subject of the G-FORK
//! non-interference row `NI-FORK-008` (ADR-062 Revision 8 slice N4, #1232).
//!
//! All logic lives in `pos_experiment::non_interference_harness::g_fork`;
//! this entry point only wires the process's standard streams and working
//! directory to it. It reads one `NLQ1` request from standard input and
//! writes one `NLC1` capture frame to standard output, or writes nothing and
//! exits non-zero. It requires the `test-support` feature and Linux, where
//! the ADR-064 counterfactual Fork exists; elsewhere it always exits
//! non-zero.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    use pos_experiment::non_interference_harness::{
        g_fork::serve_g_fork_local_subject_v1, NonInterferenceNonExecutedCauseV1,
    };

    std::env::current_dir()
        .map_err(NonInterferenceNonExecutedCauseV1::from)
        .and_then(|directory| {
            serve_g_fork_local_subject_v1(
                std::io::stdin().lock(),
                std::io::stdout().lock(),
                &directory,
            )
        })
        .map_or(std::process::ExitCode::FAILURE, |()| {
            std::process::ExitCode::SUCCESS
        })
}

// Off Linux the package still builds, so the workspace does; the binary only
// exits non-zero. A macro keeps this stub out of the mutation scope, as in
// `pos-sandboxd`: it is never compiled, and so never tested, on Linux.
#[cfg(not(target_os = "linux"))]
macro_rules! unsupported_platform_main {
    () => {
        fn main() -> std::process::ExitCode {
            std::process::ExitCode::FAILURE
        }
    };
}

#[cfg(not(target_os = "linux"))]
unsupported_platform_main!();
