#![forbid(unsafe_code)]

//! `pos-ni-g-pub-subject`: the fresh-process Local subject of the G-PUB
//! non-interference rows `NI-PUBLIC-006` and `NI-EVAL-007` (ADR-062
//! Revision 8 slice N1, #1229).
//!
//! All logic lives in `pos_experiment::non_interference_harness::g_pub`;
//! this entry point only wires the process's standard streams and working
//! directory to it. It reads one `NLQ1` request from standard input and
//! writes one `NLC1` capture frame to standard output, or writes nothing and
//! exits non-zero. It requires the `test-support` feature.

use pos_experiment::non_interference_harness::{
    g_pub::serve_g_pub_local_subject_v1, NonInterferenceNonExecutedCauseV1,
};

fn main() -> std::process::ExitCode {
    std::env::current_dir()
        .map_err(NonInterferenceNonExecutedCauseV1::from)
        .and_then(|directory| {
            serve_g_pub_local_subject_v1(
                std::io::stdin().lock(),
                std::io::stdout().lock(),
                &directory,
            )
        })
        .map_or(std::process::ExitCode::FAILURE, |()| {
            std::process::ExitCode::SUCCESS
        })
}
