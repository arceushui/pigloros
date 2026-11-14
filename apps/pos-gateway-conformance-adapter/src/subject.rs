//! The subject adapter: the order of checks of the crate documentation, with its payload grammar
//! (`payload`), its sub-case execution (`execute`) and the pinned schema digests.

use std::io::{Read, Write};
use std::process::ExitCode;

use pos_reference::adapter_transport::{read_attempt, write_observation};
use pos_reference::evaluator::{
    CaseAttempt, FixtureExecutorV1, ResourceUsage, SubjectObservation, SubjectResult,
};
use pos_reference::evaluator_domain::{ClaimLayer, ExecutionMode, FixtureFamily};
use pos_reference::evaluator_protocol::SubjectAdapterKind;
use pos_reference::profile::{NamespacedFailure, ProviderKey};

mod execute;
mod payload;
mod schema_digests;

/// The provider ID of every failure the adapter returns.
pub const PROVIDER_ID: &str = "pigloros.fixture.gateway-client-conformance";

/// The contract version of every failure the adapter returns: the only contract it reads.
pub const CONTRACT_VERSION: &str = "2.0.0";

/// The ABI major version of the provider contract the adapter implements.
pub const ABI_MAJOR: u16 = 1;

/// The ABI minor version of the provider contract the adapter implements.
pub const ABI_MINOR: u16 = 0;

/// The `schema` string of a case payload.
pub const SCHEMA_ID: &str = "pigloros.gateway-client-conformance.case.v2";

/// The route capabilities the adapter implements, sorted.
pub const CAPABILITY_IDS: [&str; 6] = [
    "gateway.health.read",
    "gateway.ledger.read",
    "timeline.create",
    "timeline.events.read",
    "timeline.signals.append",
    "world.action.v1.submit",
];

/// The actor of the `authorized` composition's fixture Local Principal.
pub const ACTOR_ENTITY_ID: &str = "01JC0GATEWAYF1XTVREACT0R00";

/// The World body the fixture action payloads name.
pub const BODY_ENTITY_ID: &str = "01JC0GATEWAYF1XTVREB0DY000";

/// The code of the failure for a payload that violates the grammar. It equals no oracle.
pub const PAYLOAD_INVALID: &str = "payload-invalid";

/// The code of the failure for a case in which an exchange did not match. It equals no oracle.
pub const SUBCASE_MISMATCH: &str = "subcase-mismatch";

/// Why the adapter wrote no observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdapterRunErrorV1 {
    /// The EAI1 stream did not decode.
    #[error("the EAI1 attempt stream is invalid")]
    Wire,
    /// The attempt is not executed: its schema member is not the pinned one.
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

/// The exact ADR-068 executor declaration of this adapter, reached as the implementation
/// `implementation_digest` (provenance only).
#[must_use]
pub fn executor_declaration(implementation_digest: [u8; 32]) -> FixtureExecutorV1 {
    FixtureExecutorV1 {
        provider: ProviderKey {
            provider_id: PROVIDER_ID.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            abi_major: ABI_MAJOR,
            abi_minor: ABI_MINOR,
        },
        subject_adapter: SubjectAdapterKind::PublicGatewayProtocol,
        schema_digests: schema_digests::PINNED,
        implementation_digest,
        capability_ids: CAPABILITY_IDS.map(str::to_owned).to_vec(),
    }
}

/// Read one EAI1 stream from `reader`, execute it, and write one EAO1 stream to `writer`.
///
/// # Errors
/// Returns [`AdapterRunErrorV1::Wire`] for an EAI1 stream that does not decode,
/// [`AdapterRunErrorV1::NotExecuted`] for a schema member that is not the pinned one, and
/// [`AdapterRunErrorV1::Output`] when the EAO1 stream cannot be written.
pub fn run(reader: impl Read, writer: impl Write) -> Result<(), AdapterRunErrorV1> {
    read_attempt(reader)
        .or(Err(AdapterRunErrorV1::Wire))
        .and_then(|attempt| observe(&attempt))
        .and_then(|observation| {
            write_observation(writer, &observation).or(Err(AdapterRunErrorV1::Output))
        })
}

/// The payload `family` text and sub-case ID prefix of a family.
const fn family_text(family: FixtureFamily) -> (&'static str, &'static str) {
    match family {
        FixtureFamily::Positive => ("positive", "pos"),
        FixtureFamily::Denied => ("denied", "den"),
        FixtureFamily::Malformed => ("malformed", "mal"),
        FixtureFamily::ResourceExhaustion => ("resource-exhaustion", "res"),
        FixtureFamily::DeletionRedaction => ("deletion-redaction", "del"),
        FixtureFamily::Downgrade => ("downgrade", "dgr"),
        FixtureFamily::IndependentEvaluation => ("independent-evaluation", "ind"),
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

/// Checks (2) and (3) of the order.
fn observe(attempt: &CaseAttempt) -> Result<SubjectObservation, AdapterRunErrorV1> {
    let executes = match attempt.mode {
        ExecutionMode::Local | ExecutionMode::AirGapped => {
            attempt.claim_layer == ClaimLayer::GatewayClientConformance
        }
        ExecutionMode::Replay | ExecutionMode::Fork => false,
    };
    if !executes {
        return Ok(unmeasured(SubjectResult::Unavailable));
    }
    let pinned = schema_digests::pinned_digest(attempt.family);
    (blake3::hash(&attempt.schema.bytes).as_bytes() == &pinned)
        .then(|| decide(attempt))
        .ok_or(AdapterRunErrorV1::NotExecuted)
}

/// Checks (4) to (6) of the order.
fn decide(attempt: &CaseAttempt) -> SubjectObservation {
    let (family, prefix) = family_text(attempt.family);
    payload::parse(&attempt.payload.bytes, family, prefix).map_or_else(
        || unmeasured(failure(PAYLOAD_INVALID)),
        |subcases| {
            let case = execute::run_case(
                &subcases,
                &attempt.capability_ids,
                attempt.family == FixtureFamily::IndependentEvaluation,
            );
            let result = failure_code(attempt.family).map_or_else(
                || SubjectResult::Output(case.output_record(&attempt.case_id, family)),
                |code| {
                    failure(if case.matched() {
                        code
                    } else {
                        SUBCASE_MISMATCH
                    })
                },
            );
            SubjectObservation {
                result,
                usage: case.usage(),
            }
        },
    )
}
