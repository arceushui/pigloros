#![forbid(unsafe_code)]

//! `pos-experiment`: the replay-conformance subject adapter (ADR-062
//! Revision 8 slice R4, section 3.1 option A).
//!
//! All logic lives in `pos_experiment::replay_conformance`; this entry point
//! only wires the process's streams to it. It reads one EAI1 attempt from
//! standard input and writes one EAO1 observation to standard output, or
//! writes nothing and exits non-zero. The adapter is compiled only with the
//! `test-support` feature; without it the binary exits with a failure.

#[cfg(feature = "test-support")]
fn main() -> std::process::ExitCode {
    let result =
        pos_experiment::replay_conformance::run(std::io::stdin().lock(), std::io::stdout().lock());
    pos_experiment::replay_conformance::exit_code(result)
}

#[cfg(not(feature = "test-support"))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
