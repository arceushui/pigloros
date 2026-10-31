//! The subject adapter: the order of checks of the crate documentation, with its payload grammar
//! (`payload`), its sub-case execution (`execute`) and the pinned schema digests.

use std::io::{Read, Write};
use std::process::ExitCode;

use pos_reference::adapter_transport::{read_attempt, write_observation};
use pos_reference::evaluator::{CaseAttempt, ResourceUsage, SubjectObservation, SubjectResult};
use pos_reference::evaluator_domain::{ClaimLayer, ExecutionMode, FixtureFamily};
use pos_reference::profile::NamespacedFailure;

mod execute;
mod payload;
mod schema_digests;

/// The provider ID of every failure the adapter returns.
pub const PROVIDER_ID: &str = "pigloros.fixture.metric-conformance";

/// The contract version of every failure the adapter returns: the only provider contract the
/// subject reads.
pub const CONTRACT_VERSION: &str = "2.0.0";

/// The `schema` string of a case payload.
pub const SCHEMA_ID: &str = "pigloros.metric-conformance.case.v2";

/// The only capability the subject holds; any other requested capability is denied.
pub const CAPABILITY_ID: &str = "read-public-bundle";

/// The code of the failure for a payload that violates the grammar. It equals no oracle.
pub const PAYLOAD_INVALID: &str = "payload-invalid";

/// The code of the failure for a case in which a sub-case was not as expected. It equals no
/// oracle.
pub const SUBCASE_MISMATCH: &str = "subcase-mismatch";

/// Why the adapter wrote no observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdapterRunErrorV1 {
    /// The EAI1 stream did not decode.
    #[error("the EAI1 attempt stream is invalid")]
    Wire,
    /// The attempt is not executed: its schema member or its composite is wrong.
    #[error("the attempt is not executed")]
    NotExecuted,
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
            Self::Output => 4,
        }
    }
}

/// The exit code of a run: success, or the code of the error.
#[must_use]
pub fn exit_code(result: Result<(), AdapterRunErrorV1>) -> ExitCode {
    result.map_or_else(|error| ExitCode::from(error.code()), |()| ExitCode::SUCCESS)
}

/// Read one EAI1 stream from `reader`, execute it, and write one EAO1 stream to `writer`.
///
/// # Errors
/// Returns [`AdapterRunErrorV1::Wire`] for an EAI1 stream that does not decode,
/// [`AdapterRunErrorV1::NotExecuted`] for a wrong schema member or a missing composite, and
/// [`AdapterRunErrorV1::Output`] when the EAO1 stream cannot be written.
pub fn run(reader: impl Read, writer: impl Write) -> Result<(), AdapterRunErrorV1> {
    read_attempt(reader)
        .or(Err(AdapterRunErrorV1::Wire))
        .and_then(|attempt| observe(&attempt))
        .and_then(|observation| {
            write_observation(writer, &observation).or(Err(AdapterRunErrorV1::Output))
        })
}

/// The payload `family` text of a family.
const fn family_text(family: FixtureFamily) -> &'static str {
    match family {
        FixtureFamily::Positive => "positive",
        FixtureFamily::Denied => "denied",
        FixtureFamily::Malformed => "malformed",
        FixtureFamily::ResourceExhaustion => "resource-exhaustion",
        FixtureFamily::DeletionRedaction => "deletion-redaction",
        FixtureFamily::Downgrade => "downgrade",
        FixtureFamily::IndependentEvaluation => "independent-evaluation",
    }
}

/// The failure code of a `namespaced-failure` family, `None` for a `canonical-output` family
/// (the family contract of `fixtures/conformance`).
const fn failure_code(family: FixtureFamily) -> Option<&'static str> {
    match family {
        FixtureFamily::Denied => Some("capability-denied"),
        FixtureFamily::Malformed => Some("malformed-payload"),
        FixtureFamily::ResourceExhaustion => Some("resource-limit"),
        FixtureFamily::Downgrade => Some("incompatible-contract"),
        FixtureFamily::Positive
        | FixtureFamily::DeletionRedaction
        | FixtureFamily::IndependentEvaluation => None,
    }
}

fn failure(code: &str) -> SubjectResult {
    SubjectResult::Failure(NamespacedFailure {
        owner_id: PROVIDER_ID.to_owned(),
        contract_version: CONTRACT_VERSION.to_owned(),
        code_id: code.to_owned(),
    })
}

/// An observation with no usage.
fn unmeasured(result: SubjectResult) -> SubjectObservation {
    SubjectObservation {
        result,
        usage: ResourceUsage::default(),
    }
}

/// Checks (2) to (4) of the order.
fn observe(attempt: &CaseAttempt) -> Result<SubjectObservation, AdapterRunErrorV1> {
    let executes = match attempt.mode {
        ExecutionMode::Local | ExecutionMode::AirGapped => {
            attempt.claim_layer == ClaimLayer::MetricConformance
        }
        ExecutionMode::Replay | ExecutionMode::Fork => false,
    };
    if !executes {
        return Ok(unmeasured(SubjectResult::Unavailable));
    }
    let pinned = schema_digests::pinned_digest(attempt.family);
    payload::find_composite(&attempt.auxiliary)
        .filter(|_| blake3::hash(&attempt.schema.bytes).as_bytes() == &pinned)
        .map(|members| decide(attempt, &members))
        .ok_or(AdapterRunErrorV1::NotExecuted)
}

/// Checks (5) to (7) of the order.
fn decide(attempt: &CaseAttempt, members: &payload::MembersV1) -> SubjectObservation {
    let family = family_text(attempt.family);
    payload::parse(&attempt.payload.bytes, family, members).map_or_else(
        || unmeasured(failure(PAYLOAD_INVALID)),
        |subcases| {
            let records: Vec<execute::RecordV1> = subcases
                .iter()
                .map(|subcase| execute::run_subcase(subcase, attempt))
                .collect();
            let steps: u64 = records.iter().map(execute::RecordV1::steps).sum();
            let result = failure_code(attempt.family).map_or_else(
                || {
                    SubjectResult::Output(execute::output_record(
                        &attempt.case_id,
                        family,
                        &records,
                    ))
                },
                |code| {
                    let matched = records.iter().all(execute::RecordV1::matched);
                    failure(if matched { code } else { SUBCASE_MISMATCH })
                },
            );
            SubjectObservation {
                result,
                usage: ResourceUsage {
                    execution_steps: steps,
                    ..ResourceUsage::default()
                },
            }
        },
    )
}
