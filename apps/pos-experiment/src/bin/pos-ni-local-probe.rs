#![forbid(unsafe_code)]

//! `pos-ni-local-probe`: the harness probe subject of the ADR-062 Revision 8
//! slice N0 fresh-process Local runner (#1227).
//!
//! All logic lives in `pos_experiment::non_interference_harness::probe`; this
//! entry point only wires the process's standard streams and working
//! directory to it. It reads one `NLQ1` request from standard input and
//! writes one `NLC1` capture frame to standard output, or writes nothing and
//! exits non-zero. It requires the `test-support` feature.

use pos_experiment::non_interference_harness::{
    probe::serve_local_probe_v1, NonInterferenceNonExecutedCauseV1,
};

fn main() -> std::process::ExitCode {
    std::env::current_dir()
        .map_err(NonInterferenceNonExecutedCauseV1::from)
        .and_then(|directory| {
            serve_local_probe_v1(
                std::io::stdin().lock(),
                std::io::stdout().lock(),
                &directory,
            )
        })
        .map_or(std::process::ExitCode::FAILURE, |()| {
            std::process::ExitCode::SUCCESS
        })
}
