//! The replay-conformance subject adapter (ADR-062 Revision 8 slice R4,
//! #1222; section 3.1 option A).
//!
//! [`run()`] reads one EAI1 attempt, runs the sub-cases of its payload
//! through the `RecordedReplay` ([`crate::recorded_replay`]) and
//! `ProfileRecomputation` / `CrossProfileConformance`
//! ([`crate::profile_recomputation`]) execution steps, and writes one EAO1
//! observation; the `pos-experiment` binary only wires the process's
//! standard streams to it. [`run_with_store()`] is the same with the store a
//! recomputation host opens (the test entry for a host that cannot start).
//!
//! The order of checks:
//! 1. The EAI1 stream decodes, else there is no EAO1 stream and the exit code
//!    is non-zero.
//! 2. The claim layer is `replay-conformance` and the mode is Local or
//!    Air-Gapped, else the result is `Unavailable` with zero usage. Every
//!    manifest of the attempt carries that Execution Mode.
//! 3. The BLAKE3 of the schema member is the digest pinned for the family
//!    (provider contract 2.0.0), and
//! 4. an auxiliary member is the family's `RCS1` composite: otherwise the
//!    attempt is not executed (no EAO1 stream, a non-zero exit). There is no
//!    reader for provider contract 1.0.0, so its attempts are not executed.
//! 5. A payload that violates the grammar of the `payload` module is the failure
//!    `payload-invalid`.
//! 6. Each sub-case runs one leg per profile on the host's EPF1 table and
//!    bundled TPS1 (the `execute` module); an operational host or codec failure makes
//!    the attempt `Unavailable`.
//! 7. A `canonical-output` family (positive, deletion-redaction,
//!    independent-evaluation) outputs its record of every sub-case and leg,
//!    which equals the oracle only when every leg is as expected. A
//!    `namespaced-failure` family returns its family failure when every leg
//!    is as expected, else `subcase-mismatch`.
//!
//! The adapter meters one execution step per leg; its other usage counters
//! are 0. It is compiled only with the `test-support` feature: the run uses
//! the open fixture erasure gate and the generated Plugin registration of
//! the Experiment host. Results are Local-relaxation engineering evidence,
//! not hosted conformance.

use std::io::{Read, Write};
use std::process::ExitCode;

use pos_conformance::ExecutionModeV1;
use pos_reference::adapter_transport::{read_attempt, write_observation};
use pos_reference::evaluator::{CaseAttempt, ResourceUsage, SubjectObservation, SubjectResult};
use pos_reference::evaluator_domain::{ClaimLayer, ExecutionMode, FixtureFamily};
use pos_reference::profile::NamespacedFailure;
use pos_store::StoreConfig;

mod execute;
mod payload;
mod schema_digests;

pub use payload::SCHEMA_ID;

/// The provider ID of every failure the adapter returns.
pub const PROVIDER_ID: &str = "pigloros.fixture.replay-conformance";

/// The contract version of every failure the adapter returns.
pub const CONTRACT_VERSION: &str = "2.0.0";

/// The code of the failure for a payload that violates the grammar. It
/// equals no oracle.
pub const PAYLOAD_INVALID: &str = "payload-invalid";

/// The code of the failure for a case in which a leg was not as expected.
/// It equals no oracle.
pub const SUBCASE_MISMATCH: &str = "subcase-mismatch";

/// Why the adapter wrote no observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdapterRunErrorV1 {
    /// The EAI1 stream did not decode.
    #[error("the EAI1 attempt stream is invalid")]
    Wire,
    /// The attempt is not executed: its schema member or its composite is
    /// wrong.
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

/// Read one EAI1 stream from `reader`, execute it, and write one EAO1 stream
/// to `writer`. Recomputation hosts keep their store in memory.
///
/// # Errors
/// Returns the reason no observation was written, as [`run_with_store()`].
pub fn run(reader: impl Read, writer: impl Write) -> Result<(), AdapterRunErrorV1> {
    run_with_store(&StoreConfig::Memory, reader, writer)
}

/// Read one EAI1 stream from `reader`, execute it with recomputation hosts
/// that open `store_config`, and write one EAO1 stream to `writer`.
///
/// # Errors
/// Returns [`AdapterRunErrorV1::Wire`] for an EAI1 stream that does not
/// decode, [`AdapterRunErrorV1::NotExecuted`] for a wrong schema member or a
/// missing composite, and [`AdapterRunErrorV1::Output`] when the EAO1 stream
/// cannot be written.
pub fn run_with_store(
    store_config: &StoreConfig,
    reader: impl Read,
    writer: impl Write,
) -> Result<(), AdapterRunErrorV1> {
    read_attempt(reader)
        .or(Err(AdapterRunErrorV1::Wire))
        .and_then(|attempt| observe(store_config, &attempt))
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

/// The failure code of a `namespaced-failure` family, `None` for a
/// `canonical-output` family (the family contract of `fixtures/conformance`).
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
fn observe(
    store_config: &StoreConfig,
    attempt: &CaseAttempt,
) -> Result<SubjectObservation, AdapterRunErrorV1> {
    let mode = match attempt.mode {
        ExecutionMode::Local => Some(ExecutionModeV1::Local),
        ExecutionMode::AirGapped => Some(ExecutionModeV1::AirGapped),
        ExecutionMode::Replay | ExecutionMode::Fork => None,
    };
    let Some(mode) = mode.filter(|_| attempt.claim_layer == ClaimLayer::ReplayConformance) else {
        return Ok(unmeasured(SubjectResult::Unavailable));
    };
    let pinned = schema_digests::pinned_digest(attempt.family);
    payload::find_composite(&attempt.auxiliary)
        .filter(|_| blake3::hash(&attempt.schema.bytes).as_bytes() == &pinned)
        .map(|members| decide(store_config, attempt, mode, &members))
        .ok_or(AdapterRunErrorV1::NotExecuted)
}

/// Checks (5) to (7) of the order.
fn decide(
    store_config: &StoreConfig,
    attempt: &CaseAttempt,
    mode: ExecutionModeV1,
    members: &payload::MembersV1,
) -> SubjectObservation {
    let family = family_text(attempt.family);
    payload::parse(&attempt.payload.bytes, family, members).map_or_else(
        || unmeasured(failure(PAYLOAD_INVALID)),
        |subcases| {
            let records: Option<Vec<(payload::RecordV1, bool)>> = execute::HostV1::install()
                .and_then(|host| {
                    subcases
                        .iter()
                        .map(|subcase| {
                            execute::run_subcase(
                                &host,
                                subcase,
                                attempt.fixture_digest,
                                mode,
                                store_config,
                            )
                            .map(|record| {
                                let matched = record.legs == subcase.expect;
                                (record, matched)
                            })
                        })
                        .collect()
                });
            records.map_or_else(
                || unmeasured(SubjectResult::Unavailable),
                |records| {
                    let legs: usize = records.iter().map(|(record, _)| record.legs.len()).sum();
                    let matched = records.iter().all(|(_, matched)| *matched);
                    let result = failure_code(attempt.family).map_or_else(
                        || {
                            let records: Vec<payload::RecordV1> =
                                records.into_iter().map(|(record, _)| record).collect();
                            SubjectResult::Output(payload::output_record(
                                &attempt.case_id,
                                family,
                                &records,
                            ))
                        },
                        |code| failure(if matched { code } else { SUBCASE_MISMATCH }),
                    );
                    SubjectObservation {
                        result,
                        usage: ResourceUsage {
                            execution_steps: u64::try_from(legs).unwrap_or(u64::MAX),
                            ..ResourceUsage::default()
                        },
                    }
                },
            )
        },
    )
}
