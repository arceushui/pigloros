#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Fault-injection worker for the supervisor's black-box tests.
//!
//! Built only with the `test-support` feature. It runs the same worker
//! process checks as the Component worker, reads one real request, and then
//! behaves as the request's invocation bytes name: it reports its own process
//! state, or misbehaves in one specific way. It never runs a Component.

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use pos_crypto::plugin_worker_ipc::{
    encode_worker_response_v1, WorkerCompletionV1, WorkerFailureV1, WorkerOutcomeV1,
    WorkerRequestV1, WorkerTrapClassV1,
};
use pos_plugin_supervisor::{
    open_descriptors, prepare_worker_process, read_request, write_response, WorkerFrameLimitsV1,
};
use rustix::process::{getpid, getppid, getrlimit, Pid, Resource};

/// Longest a misbehaving probe stays alive, so no test can hang forever.
const LINGER: Duration = Duration::from_mins(1);

#[cfg_attr(coverage_nightly, coverage(off))]
fn main() -> ExitCode {
    let request = prepare_worker_process(std::env::args_os())
        .and_then(|()| read_request(&mut std::io::stdin().lock()));
    request.map_or_else(|_| ExitCode::from(2), |request| serve(&request))
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn serve(request: &WorkerRequestV1) -> ExitCode {
    let completed = |payload: &[u8]| {
        WorkerOutcomeV1::Completed(WorkerCompletionV1 {
            payload: payload.to_vec(),
            startup_fuel: 1,
            call_fuel: 2,
            memory_bytes: 65_536,
        })
    };
    let valid = encode_worker_response_v1(&completed(b"payload"));
    match request.invocation.as_slice() {
        b"report" => reply(&completed(report().as_bytes())),
        b"payload" => reply(&completed(b"payload")),
        b"fuel" => reply(&WorkerOutcomeV1::Failed(WorkerFailureV1::FuelExhausted)),
        b"trap" => reply(&WorkerOutcomeV1::Trapped(WorkerTrapClassV1::StackExhausted)),
        b"exit" => ExitCode::from(3),
        b"abort" => std::process::abort(),
        b"hang" => linger(),
        b"garbage" => raw(&[&[0_u8, 0, 0, 1][..], &[0xff][..]]),
        b"noncanonical" => {
            // The version 1 in a two-byte head instead of its shortest form.
            let bytes = [&valid[..6], &[0x18, 0x01], &valid[7..]].concat();
            raw(&[&frame_prefix(bytes.len()), &bytes])
        }
        b"truncated" => raw(&[&frame_prefix(valid.len()), &valid[..valid.len() - 1]]),
        b"oversize" => {
            let limit = WorkerFrameLimitsV1::for_limits(&request.limits).response_bytes();
            raw(&[&frame_prefix(limit + 1)])
        }
        b"trailing" => raw(&[&frame_prefix(valid.len()), &valid, &[0]]),
        b"exit-after-reply" => {
            reply(&completed(b"payload"));
            ExitCode::from(1)
        }
        b"linger-after-reply" => {
            reply(&completed(b"payload"));
            linger()
        }
        b"allocate" => {
            // One GiB: more than the data ceiling of a 64 KiB-memory invocation.
            let allocation = std::hint::black_box(vec![0_u8; 1 << 30]);
            reply(&completed(&allocation[..1]))
        }
        _ => ExitCode::from(4),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn reply(outcome: &WorkerOutcomeV1) -> ExitCode {
    write_response(&mut std::io::stdout().lock(), outcome)
        .map_or_else(|_| ExitCode::from(5), |()| ExitCode::SUCCESS)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn raw(parts: &[&[u8]]) -> ExitCode {
    let mut stdout = std::io::stdout().lock();
    let written = parts
        .iter()
        .try_for_each(|part| stdout.write_all(part))
        .and_then(|()| stdout.flush());
    written.map_or_else(|_| ExitCode::from(5), |()| ExitCode::SUCCESS)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn frame_prefix(length: usize) -> [u8; 4] {
    u32::try_from(length).unwrap_or(u32::MAX).to_be_bytes()
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn linger() -> ExitCode {
    std::thread::sleep(LINGER);
    ExitCode::SUCCESS
}

/// `name=value` lines describing this process from the inside.
#[cfg_attr(coverage_nightly, coverage(off))]
fn report() -> String {
    let environment: Vec<String> = std::env::vars_os()
        .map(|(name, _)| name.to_string_lossy().into_owned())
        .collect();
    let descriptors: Vec<String> = open_descriptors()
        .unwrap_or_default()
        .iter()
        .map(ToString::to_string)
        .collect();
    let directory = std::env::current_dir().map_or_else(|_| String::new(), |path| {
        path.to_string_lossy().into_owned()
    });
    let mut lines = vec![
        format!("pid={}", getpid().as_raw_nonzero()),
        format!("ppid={}", Pid::as_raw(getppid())),
        format!("cwd={directory}"),
        format!("env={}", environment.join(",")),
        format!("fds={}", descriptors.join(",")),
    ];
    for (name, resource) in [
        ("cpu", Resource::Cpu),
        ("data", Resource::Data),
        ("fsize", Resource::Fsize),
        ("core", Resource::Core),
    ] {
        let limit = getrlimit(resource);
        lines.push(format!("{name}={}:{}", value(limit.current), value(limit.maximum)));
    }
    lines.join("\n")
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn value(limit: Option<u64>) -> String {
    limit.map_or_else(|| "unlimited".to_owned(), |limit| limit.to_string())
}
