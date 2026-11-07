#![forbid(unsafe_code)]

//! `pos-ni-g-plug-subject`: the fresh-process Local subject of the G-PLUG
//! non-interference rows `NI-TOOL-001`, `NI-STATE-003`, `NI-NET-010` and
//! `NI-SERVICE-011` (ADR-062 Revision 8 slice N2, #1230).
//!
//! All logic lives in `pos_experiment::non_interference_harness::g_plug`;
//! this entry point only wires the process's standard streams and working
//! directory to it. It reads one `NLQ1` request from standard input and
//! writes one `NLC1` capture frame to standard output, or writes nothing and
//! exits non-zero. It requires the `test-support` feature.

use pos_experiment::non_interference_harness::{
    g_plug::serve_g_plug_local_subject_v1, NonInterferenceNonExecutedCauseV1,
};

fn main() -> std::process::ExitCode {
    std::env::current_dir()
        .map_err(NonInterferenceNonExecutedCauseV1::from)
        .and_then(|directory| {
            serve_g_plug_local_subject_v1(
                std::io::stdin().lock(),
                std::io::stdout().lock(),
                &directory,
            )
        })
        .map_or(std::process::ExitCode::FAILURE, |()| {
            std::process::ExitCode::SUCCESS
        })
}
