#![forbid(unsafe_code)]

//! Argument-recording worker for the supervisor's mode token tests.
//!
//! Built only with the `test-support` feature, from `tests/` so that no
//! production coverage or cargo-crap gate counts it. It reads one real request
//! and answers a `drive` call with a state that is its own arguments after the
//! program name, joined by single spaces, so a test can see exactly what the
//! supervisor passed. It never runs a Component and checks no process state.

use std::process::ExitCode;

use pos_plugin_supervisor::test_support::METERING;
use pos_plugin_supervisor::{read_request, write_response, WorkerCallV1, WorkerReturnV1};
use pos_runtime::community_plugin_host::{
    plugin_output_digest_v1, InvocationReportV1, PluginOutputV1,
};

/// The request could not be read.
const BAD_REQUEST: u8 = 2;
/// The call was not `drive`.
const NOT_DRIVE: u8 = 3;
/// The response could not be written.
const WRITE_FAILED: u8 = 5;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    let recorded = arguments.join(" ");
    read_request(&mut std::io::stdin().lock()).map_or_else(
        |_| ExitCode::from(BAD_REQUEST),
        |request| serve(&request.call, &recorded),
    )
}

fn serve(call: &WorkerCallV1, recorded: &str) -> ExitCode {
    let WorkerCallV1::Drive(invocation) = call else {
        return ExitCode::from(NOT_DRIVE);
    };
    let mut output = PluginOutputV1 {
        invocation_id: invocation.invocation_id,
        event_drafts: Vec::new(),
        next_state_schema: [1; 32],
        next_state_bytes: recorded.as_bytes().to_vec(),
        trace_annotations: Vec::new(),
        consumed_dependencies: Vec::new(),
        output_digest: [0; 32],
    };
    output.output_digest = plugin_output_digest_v1(&output);
    let outcome = Ok(WorkerReturnV1::Produced(InvocationReportV1 {
        result: Ok(output),
        metering: METERING,
        operational_log: Vec::new(),
    }));
    write_response(&mut std::io::stdout().lock(), &outcome)
        .map_or_else(|_| ExitCode::from(WRITE_FAILED), |()| ExitCode::SUCCESS)
}
