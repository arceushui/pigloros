#![forbid(unsafe_code)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

//! The community Plugin Component worker (ADR-061 revision 4, #542).
//!
//! One worker process serves exactly one invocation:
//! 1. it runs the worker process checks of
//!    `pos_plugin_supervisor::prepare_worker_process` (the arguments
//!    `<pid> local` or `<pid> air-gapped`, parent-death signal, scrubbed
//!    environment, no inherited descriptor); the token names the one mode this
//!    worker serves;
//! 2. it reads one request frame from standard input;
//! 3. it runs the request through the in-worker engine seam ([`engine`]) under
//!    that mode;
//! 4. it writes one response frame to standard output and exits.
//!
//! On any failure before a response it exits unsuccessfully without writing
//! one, which the supervisor reports as the operational `WorkerCrashed`.
//!
//! This is the ADR-061 revision 4 Local relaxation: engineering evidence, not
//! a hosted, Candidate or Stable execution boundary.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::process::ExitCode;

use pos_plugin_supervisor::{prepare_worker_process, read_request, write_response};

pub mod engine;

/// Serve one invocation and report the process exit code.
#[must_use]
pub fn run_worker(
    arguments: impl IntoIterator<Item = OsString>,
    input: &mut impl Read,
    output: &mut impl Write,
) -> ExitCode {
    if serve(arguments, input, output) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Whether one invocation was served and its response written.
fn serve(
    arguments: impl IntoIterator<Item = OsString>,
    input: &mut impl Read,
    output: &mut impl Write,
) -> bool {
    prepare_worker_process(arguments)
        .and_then(|mode| read_request(input).map(|request| (mode, request)))
        .ok()
        .and_then(|(mode, request)| engine::invoke(request, mode))
        .is_some_and(|outcome| write_response(output, &outcome).is_ok())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn a_worker_without_its_supervisor_argument_writes_nothing() {
        let mut output = Vec::new();
        let mut input: &[u8] = &[];
        let arguments = [OsString::from("pos-plugin-worker")];
        assert!(!serve(arguments.clone(), &mut input, &mut output));
        assert!(output.is_empty());
        let code = run_worker(arguments, &mut input, &mut output);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::FAILURE));
    }

    #[test]
    fn a_worker_refuses_a_bad_mode_token_before_it_reads_a_request() {
        let request = [0_u8; 8];
        for token in ["Local", "airgapped"] {
            let mut input: &[u8] = &request;
            let mut output = Vec::new();
            let arguments = ["pos-plugin-worker", "1", token].map(OsString::from);
            assert!(!serve(arguments, &mut input, &mut output));
            assert_eq!(input.len(), request.len(), "{token}");
            assert!(output.is_empty());
        }
    }
}
