#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]
// The ADR fixes the names (`WorldPortV1` in `world`, `PiecesV1` ...).
#![allow(clippy::module_name_repetitions)]

//! The community Plugin conformance subject adapter (ADR-061 revision 8 decision 2, #615).
//!
//! [`run()`] reads one EAI1 attempt, executes the sub-cases of its payload and writes one EAO1
//! observation; the `pos-plugin-conformance-adapter` binary only wires the process's standard
//! streams to it. [`run_with()`] is the test entry: it takes the [`SubCaseRunnerV1`] that runs
//! the sub-cases.
//!
//! The order of checks:
//! 1. The EAI1 stream decodes, else there is no EAO1 stream and the exit code is non-zero.
//! 2. The claim layer is `plugin-conformance` and the mode is Local or Air-Gapped, else the
//!    result is `Unavailable` with zero usage.
//! 3. The payload's `schema` string, when it carries one, is the pinned one, and
//! 4. the BLAKE3 of the schema member is the digest pinned for the family: either mismatch is a
//!    non-executed outcome (no EAO1 stream, a non-zero exit).
//! 5. The composite is found and verified ([`composite`]): a fault is a non-executed outcome.
//! 6. A payload that violates the grammar, or that names a piece the composite lacks, is the
//!    failure `payload-invalid`.
//! 7. Each sub-case runs on a fresh world and the case result is decided by
//!    [`map::case_result()`].
//!
//! Results are Local-relaxation engineering evidence, not hosted conformance.

use std::io::{Read, Write};
use std::process::ExitCode;

use pos_reference::adapter_transport::{read_attempt, write_observation};
use pos_reference::evaluator::{CaseAttempt, ResourceUsage, SubjectObservation, SubjectResult};
use pos_reference::evaluator_domain::{ClaimLayer, ExecutionMode};
use pos_runtime::community_plugin_host::CommunityPluginModeV1;

pub mod composite;
pub mod hex;
pub mod invocation;
pub mod jcs;
pub mod map;
pub mod payload;
pub mod runner;
pub mod schema_digests;
pub mod world;

pub use composite::{PiecesFaultV1, PiecesV1};
pub use runner::{EvaluationWorldPortV1, SubCaseRunnerV1, SupervisorRunnerV1};
pub use world::{interpret, ScanResultV1, ScanSource, SubCaseRecordV1, WorldPortV1};

/// The provider ID of every failure the adapter returns.
pub const PROVIDER_ID: &str = "pigloros.fixture.plugin-conformance";

/// The contract version of every failure the adapter returns.
pub const CONTRACT_VERSION: &str = "2.0.0";

/// The `schema` string of a case payload.
pub const SCHEMA_ID: &str = "pigloros.plugin-conformance.case.v2";

/// The code of the failure for a payload that violates the grammar. It equals no oracle.
pub const PAYLOAD_INVALID: &str = "payload-invalid";

/// The code of the failure for a case in which a sub-case did not match. It equals no oracle.
pub const SUBCASE_MISMATCH: &str = "subcase-mismatch";

/// The name of the worker program, resolved next to the adapter binary.
pub const WORKER_PROGRAM: &str = "pos-plugin-worker";

/// Why the adapter wrote no observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdapterRunErrorV1 {
    /// The EAI1 stream did not decode.
    #[error("the EAI1 attempt stream is invalid")]
    Wire,
    /// The attempt is not executed: its schema, its schema member or its composite is wrong.
    #[error("the attempt is not executed")]
    NotExecuted,
    /// The worker program cannot be located next to the adapter binary.
    #[error("the worker program cannot be located")]
    Worker,
    /// The EAO1 stream could not be written.
    #[error("the EAO1 observation stream could not be written")]
    Output,
}

impl AdapterRunErrorV1 {
    /// The exit code of the process.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Wire => 2,
            Self::NotExecuted => 3,
            Self::Worker => 4,
            Self::Output => 5,
        }
    }
}

/// The exit code of a run: success, or the code of the error.
#[must_use]
pub fn exit_code(result: Result<(), AdapterRunErrorV1>) -> ExitCode {
    result.map_or_else(|error| ExitCode::from(error.code()), |()| ExitCode::SUCCESS)
}

/// Read one EAI1 stream from `reader`, execute it with the supervised worker next to the
/// current executable, and write one EAO1 stream to `writer`.
///
/// The worker is `pos-plugin-worker` in the directory of `std::env::current_exe()`; no argument
/// and no environment variable names it, so `cargo build -p pos-plugin-conformance-adapter`
/// does not build it and the worker binary must be built into the same directory first.
///
/// # Errors
/// Returns the reason no observation was written: [`AdapterRunErrorV1::Worker`] when the
/// program cannot be located, then the errors of [`run_with()`].
pub fn run(reader: impl Read, writer: impl Write) -> Result<(), AdapterRunErrorV1> {
    let runner = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(WORKER_PROGRAM)))
        .and_then(SupervisorRunnerV1::with_program)
        .ok_or(AdapterRunErrorV1::Worker);
    runner.and_then(|runner| run_with(&runner, reader, writer))
}

/// Read one EAI1 stream from `reader`, execute it with `runner`, and write one EAO1 stream to
/// `writer`.
///
/// # Errors
/// Returns [`AdapterRunErrorV1::Wire`] for an EAI1 stream that does not decode,
/// [`AdapterRunErrorV1::NotExecuted`] for a wrong schema string, schema member or composite,
/// and [`AdapterRunErrorV1::Output`] when the EAO1 stream cannot be written.
pub fn run_with(
    runner: &dyn SubCaseRunnerV1,
    reader: impl Read,
    writer: impl Write,
) -> Result<(), AdapterRunErrorV1> {
    let attempt = read_attempt(reader).or(Err(AdapterRunErrorV1::Wire));
    let observation = attempt.and_then(|attempt| observe(runner, &attempt));
    observation.and_then(|observation| {
        write_observation(writer, &observation).or(Err(AdapterRunErrorV1::Output))
    })
}

/// The Execution Mode of the attempt, if the adapter runs it.
const fn mode_of(mode: ExecutionMode) -> Option<CommunityPluginModeV1> {
    match mode {
        ExecutionMode::Local => Some(CommunityPluginModeV1::Local),
        ExecutionMode::AirGapped => Some(CommunityPluginModeV1::AirGapped),
        ExecutionMode::Replay | ExecutionMode::Fork => None,
    }
}

/// An observation with no usage.
const fn unmeasured(result: SubjectResult) -> SubjectObservation {
    SubjectObservation {
        result,
        usage: ResourceUsage {
            memory_bytes: 0,
            cpu_fuel: 0,
            host_calls: 0,
            event_count: 0,
            output_bytes: 0,
            storage_bytes: 0,
            execution_steps: 0,
            simulation_time_ns: 0,
        },
    }
}

/// Checks (2) of the order: the claim layer and the mode.
fn observe(
    runner: &dyn SubCaseRunnerV1,
    attempt: &CaseAttempt,
) -> Result<SubjectObservation, AdapterRunErrorV1> {
    match mode_of(attempt.mode) {
        Some(mode) if attempt.claim_layer == ClaimLayer::PluginConformance => {
            execute(runner, attempt, mode)
        }
        _ => Ok(unmeasured(SubjectResult::Unavailable)),
    }
}

/// Whether the payload's schema string, when it carries one, is the pinned string.
fn schema_text_is_pinned(payload: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(payload)
        .ok()
        .and_then(|value| {
            value
                .get("schema")
                .and_then(serde_json::Value::as_str)
                .map(|schema| schema == SCHEMA_ID)
        })
        .unwrap_or(true)
}

/// Checks (3) to (5) of the order, then the sub-cases.
fn execute(
    runner: &dyn SubCaseRunnerV1,
    attempt: &CaseAttempt,
    mode: CommunityPluginModeV1,
) -> Result<SubjectObservation, AdapterRunErrorV1> {
    let pinned = schema_digests::pinned_digest(attempt.family);
    let schema_ok = blake3::hash(&attempt.schema.bytes).as_bytes() == &pinned
        && schema_text_is_pinned(&attempt.payload.bytes);
    if !schema_ok {
        return Err(AdapterRunErrorV1::NotExecuted);
    }
    match PiecesV1::find(&attempt.auxiliary) {
        Ok(pieces) => Ok(decide(runner, attempt, mode, &pieces)),
        Err(_fault) => Err(AdapterRunErrorV1::NotExecuted),
    }
}

/// Checks (6) and (7) of the order.
///
/// Every sub-case is resolved once here and again inside `interpret`: the resolution is cheap
/// (it copies the pieces of one sub-case) and keeps the `SubCaseRunnerV1` seam free of a
/// prepared type, so a fake runner never sees an unresolved payload.
fn decide(
    runner: &dyn SubCaseRunnerV1,
    attempt: &CaseAttempt,
    mode: CommunityPluginModeV1,
    pieces: &PiecesV1,
) -> SubjectObservation {
    let case = payload::CaseV1::parse(&attempt.payload.bytes, attempt.family).ok();
    let resolved = case.filter(|case| {
        case.subcases
            .iter()
            .all(|subcase| world::PreparedV1::build(subcase, pieces).is_ok())
    });
    resolved.map_or_else(
        || unmeasured(map::payload_invalid()),
        |case| {
            let records: Vec<SubCaseRecordV1> = case
                .subcases
                .iter()
                .map(|subcase| runner.run(subcase, pieces, mode))
                .collect();
            let decided = map::case_result(&attempt.case_id, attempt.family, &records);
            SubjectObservation {
                result: decided.result,
                usage: decided.usage,
            }
        },
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod test_support;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
