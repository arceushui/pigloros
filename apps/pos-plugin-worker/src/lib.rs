#![forbid(unsafe_code)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

//! The community Plugin Component worker (ADR-061 revision 4, #542).
//!
//! One worker process serves exactly one invocation:
//! 1. it runs the worker process checks of
//!    `pos_plugin_supervisor::prepare_worker_process` (parent-death signal,
//!    scrubbed environment, no inherited descriptor);
//! 2. it reads one request frame from standard input;
//! 3. it runs the request through the in-worker engine seam ([`engine`]);
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
        .and_then(|()| read_request(input))
        .ok()
        .and_then(|request| engine::invoke(&request))
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
}
