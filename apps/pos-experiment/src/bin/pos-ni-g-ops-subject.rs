#![forbid(unsafe_code)]

//! `pos-ni-g-ops-subject`: the fresh-process Local subject of the G-OPS
//! non-interference rows `NI-CACHE-002`, `NI-OBS-004`, `NI-TIME-005` and
//! `NI-CRASH-012` (ADR-062 Revision 8 slice N3, #1231).
//!
//! All logic lives in `pos_experiment::non_interference_harness::g_ops`;
//! this entry point only wires the process's standard streams, its working
//! directory and the worker program named by `PIGLOROS_NI_G_OPS_WORKER` to
//! it. It reads one `NLQ1` request from standard input and writes one `NLC1`
//! capture frame to standard output, or writes nothing and exits non-zero. It
//! requires the `test-support` feature and runs only on Linux.

fn main() -> std::process::ExitCode {
    // The worker supervisor runs only on Linux; elsewhere this program fails.
    #[cfg(target_os = "linux")]
    {
        use pos_experiment::non_interference_harness::g_ops::{
            serve_g_ops_local_subject_v1, GOpsHostV1, G_OPS_SUBJECT_WATCHDOG_V1,
            G_OPS_WORKER_ENV_V1,
        };
        use pos_experiment::non_interference_harness::NonInterferenceNonExecutedCauseV1;

        std::env::var_os(G_OPS_WORKER_ENV_V1)
            .and_then(|worker| GOpsHostV1::new(worker.into(), G_OPS_SUBJECT_WATCHDOG_V1))
            .ok_or(NonInterferenceNonExecutedCauseV1::Unavailable)
            .and_then(|host| {
                std::env::current_dir()
                    .map_err(NonInterferenceNonExecutedCauseV1::from)
                    .and_then(|directory| {
                        serve_g_ops_local_subject_v1(
                            &host,
                            std::io::stdin().lock(),
                            std::io::stdout().lock(),
                            &directory,
                        )
                    })
            })
            .map_or(std::process::ExitCode::FAILURE, |()| {
                std::process::ExitCode::SUCCESS
            })
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::process::ExitCode::FAILURE
    }
}
