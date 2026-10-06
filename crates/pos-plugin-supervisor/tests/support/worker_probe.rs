#![forbid(unsafe_code)]

//! Fault-injection worker for the supervisor's black-box tests.
//!
//! Built only with the `test-support` feature, from `tests/` so that no
//! production coverage or cargo-crap gate counts it: the supervisor's black-box
//! tests drive it, and its abort and hang behaviours cannot flush a coverage
//! profile. It runs the same worker
//! process checks as the Component worker, reads one real request, and then
//! behaves as the request's Component bytes name: it reports its own process
//! state, returns a chosen guest value or failure, or misbehaves in one
//! specific way. It never runs a Component.

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use pos_plugin_supervisor::test_support::METERING;
use pos_plugin_supervisor::{
    open_descriptors, prepare_worker_process, read_request, write_response, WorkerCallV1,
    WorkerFrameLimitsV1, WorkerOutcomeV1, WorkerRequestV1, WorkerReturnV1,
};
use pos_runtime::community_plugin_host::{
    plugin_output_digest_v1, CommunityPluginHostErrorV1, ComponentTrapClassV1, InvocationReportV1,
    PluginDescriptorV1, PluginOutputV1, TrapReproductionV1,
};
use rustix::process::{getpid, getppid, getrlimit, Pid, Resource};
use rustix::stdio::dup2_stdout;

/// Longest a misbehaving probe stays alive, so no test can hang forever.
const LINGER: Duration = Duration::from_mins(1);
/// The canonical `FuelExhausted` response envelope.
const FUEL: [u8; 10] = [0x83, 0x64, b'P', b'W', b'R', b'1', 0x01, 0x82, 0x02, 0x03];

fn main() -> ExitCode {
    let request = prepare_worker_process(std::env::args_os())
        .and_then(|()| read_request(&mut std::io::stdin().lock()));
    request.map_or_else(|_| ExitCode::from(2), |request| serve(&request))
}

fn serve(request: &WorkerRequestV1) -> ExitCode {
    match request.component.as_slice() {
        b"report" => reply(&Ok(produced(request, report().as_bytes(), false))),
        b"output" => reply(&Ok(produced(request, b"next", false))),
        b"bad-digest" => reply(&Ok(produced(request, b"next", true))),
        b"describe" => reply(&Ok(described(request, false))),
        b"foreign-descriptor" => reply(&Ok(described(request, true))),
        b"fuel" => reply(&Err(CommunityPluginHostErrorV1::FuelExhausted)),
        b"trap" => reply(&Err(CommunityPluginHostErrorV1::ComponentTrap {
            class: ComponentTrapClassV1::StackExhausted,
            reproduction: TrapReproductionV1::Unverified,
        })),
        b"exit" => ExitCode::from(3),
        b"abort" => std::process::abort(),
        b"hang" => linger(),
        b"garbage" => raw(&[&[0_u8, 0, 0, 1][..], &[0xff][..]]),
        b"noncanonical" => {
            // The version 1 in a two-byte head instead of its shortest form.
            let bytes = [&FUEL[..6], &[0x18, 0x01], &FUEL[7..]].concat();
            raw(&[&frame_prefix(bytes.len()), &bytes])
        }
        b"truncated" => raw(&[&frame_prefix(FUEL.len()), &FUEL[..FUEL.len() - 1]]),
        // `oversize` and `trailing` end in `linger()`, not in an exit: the
        // supervisor sees the fault before the pipe closes and kills the probe
        // at once, and a coverage-instrumented probe killed while it writes its
        // profile at exit leaves a corrupt `.profraw` that fails the whole run.
        b"oversize" => {
            let limits = request.negotiation.limits;
            let limit = WorkerFrameLimitsV1::for_limits(&limits).response_bytes();
            raw(&[&frame_prefix(limit + 1)]);
            linger()
        }
        b"trailing" => {
            raw(&[&frame_prefix(FUEL.len()), &FUEL, &[0]]);
            linger()
        }
        b"exit-after-reply" => {
            reply(&Err(CommunityPluginHostErrorV1::FuelExhausted));
            ExitCode::from(1)
        }
        b"linger-after-reply" => {
            reply(&Err(CommunityPluginHostErrorV1::FuelExhausted));
            linger()
        }
        b"close-then-linger" => {
            reply(&Err(CommunityPluginHostErrorV1::FuelExhausted));
            // Replace stdout by /dev/null: the supervisor sees the end of the
            // output while this process keeps running.
            let closed = std::fs::File::open("/dev/null")
                .ok()
                .and_then(|null| dup2_stdout(&null).ok());
            closed.map_or_else(|| ExitCode::from(6), |()| linger())
        }
        b"allocate" => {
            // One GiB: more than the data ceiling of a 64 KiB-memory invocation.
            let allocation = std::hint::black_box(vec![0_u8; 1 << 30]);
            reply(&Ok(produced(request, &allocation[..1], false)))
        }
        _ => ExitCode::from(4),
    }
}

/// A `reduce` or `drive` return carrying `state`, whatever the call was.
fn produced(request: &WorkerRequestV1, state: &[u8], tampered: bool) -> WorkerReturnV1 {
    let invocation_id = match &request.call {
        WorkerCallV1::Reduce(invocation) | WorkerCallV1::Drive(invocation) => {
            invocation.invocation_id
        }
        WorkerCallV1::Describe => [0; 16],
    };
    let mut output = PluginOutputV1 {
        invocation_id,
        event_drafts: Vec::new(),
        next_state_schema: [1; 32],
        next_state_bytes: state.to_vec(),
        trace_annotations: Vec::new(),
        consumed_dependencies: Vec::new(),
        output_digest: [0; 32],
    };
    output.output_digest = plugin_output_digest_v1(&output);
    output.output_digest[0] ^= u8::from(tampered);
    WorkerReturnV1::Produced(InvocationReportV1 {
        result: Ok(output),
        metering: METERING,
        operational_log: Vec::new(),
    })
}

/// The descriptor of the transported release, or of another Plugin.
fn described(request: &WorkerRequestV1, foreign: bool) -> WorkerReturnV1 {
    let negotiation = &request.negotiation;
    let plugin_id = if foreign {
        "another-plugin".to_owned()
    } else {
        negotiation.plugin_id.clone()
    };
    let descriptor = PluginDescriptorV1 {
        plugin_id,
        release_semver: "1.0.0".to_owned(),
        world: negotiation.world.clone(),
        abi_major: negotiation.abi_major,
        min_abi_minor: negotiation.declared_minors.0,
        max_abi_minor: negotiation.declared_minors.1,
        required_features: negotiation.required_features.clone(),
        event_schema_digests: Vec::new(),
        state_schema_digest: [2; 32],
        manifest_digest: [0; 32],
        release_digest: [0; 32],
    };
    WorkerReturnV1::Described(InvocationReportV1 {
        result: Ok(descriptor),
        metering: METERING,
        operational_log: Vec::new(),
    })
}

fn reply(outcome: &WorkerOutcomeV1) -> ExitCode {
    write_response(&mut std::io::stdout().lock(), outcome)
        .map_or_else(|_| ExitCode::from(5), |()| ExitCode::SUCCESS)
}

fn raw(parts: &[&[u8]]) -> ExitCode {
    let mut stdout = std::io::stdout().lock();
    let written = parts
        .iter()
        .try_for_each(|part| stdout.write_all(part))
        .and_then(|()| stdout.flush());
    written.map_or_else(|_| ExitCode::from(5), |()| ExitCode::SUCCESS)
}

fn frame_prefix(length: usize) -> [u8; 4] {
    u32::try_from(length).unwrap_or(u32::MAX).to_be_bytes()
}

fn linger() -> ExitCode {
    std::thread::sleep(LINGER);
    ExitCode::SUCCESS
}

/// `name=value` lines describing this process from the inside.
fn report() -> String {
    let environment: Vec<String> = std::env::vars_os()
        .map(|(name, _)| name.to_string_lossy().into_owned())
        .collect();
    let descriptors: Vec<String> = open_descriptors()
        .unwrap_or_default()
        .iter()
        .map(ToString::to_string)
        .collect();
    let directory = std::env::current_dir().map_or_else(
        |_| String::new(),
        |path| path.to_string_lossy().into_owned(),
    );
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
        lines.push(format!(
            "{name}={}:{}",
            value(limit.current),
            value(limit.maximum)
        ));
    }
    lines.join("\n")
}

fn value(limit: Option<u64>) -> String {
    limit.map_or_else(|| "unlimited".to_owned(), |limit| limit.to_string())
}
