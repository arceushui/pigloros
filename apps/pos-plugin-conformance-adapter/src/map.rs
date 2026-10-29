//! From the stable outcome record to an EAO1 result (ADR-061 revision 8 decision 3).
//!
//! The mapping is total over the variants of [`CommunityPluginSubjectResultV1`]. An operational
//! result is never a typed failure and never an output: the case becomes `Unavailable`, which
//! the evaluator never turns into `Pass` or `Fail`. [`case_result`] is the only place a case
//! result is decided.

use pos_plugin_supervisor::{
    CommunityPluginSubjectOutcomeV1, CommunityPluginSubjectResultV1, OutputUsageV1,
};
use pos_reference::evaluator::{ResourceUsage, SubjectResult};
use pos_reference::evaluator_domain::FixtureFamily;
use pos_reference::profile::NamespacedFailure;
use pos_runtime::community_plugin_host::{
    CommunityPluginHostErrorV1, HostFailureClassV1, MeteringV1,
};

use crate::hex;
use crate::jcs::JsonV1;
use crate::payload::family_text;
use crate::world::SubCaseRecordV1;
use crate::{CONTRACT_VERSION, PAYLOAD_INVALID, PROVIDER_ID, SUBCASE_MISMATCH};

/// The 20 closed error names of ADR-061 revision 7 decision 3.
pub const KNOWN_ERRORS: [&str; 20] = [
    "InvalidManifest",
    "ArtifactTrustDenied",
    "ArtifactRevoked",
    "IncompatibleAbi",
    "MissingFeature",
    "CapabilityDenied",
    "InvalidInvocation",
    "InvalidGuestOutput",
    "UnsupportedSchema",
    "StateMigrationFailed",
    "GuestDeclaredFailure",
    "ComponentTrap",
    "WorkerCrashed",
    "FuelExhausted",
    "MemoryLimitExceeded",
    "HostCallLimitExceeded",
    "OutputLimitExceeded",
    "DeterministicDeadlineExceeded",
    "OperationalWatchdogStop",
    "AtomicCommitFailed",
];

/// The class name of an authoritative failure.
const AUTHORITATIVE: &str = HostFailureClassV1::Authoritative.name();

/// One sub-result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubResultV1 {
    /// The pass committed output with this digest; the usage of one outcome, or of the
    /// attempt for the sub-result of a record ([`of_record()`]).
    Committed {
        output_digest: [u8; 32],
        usage: ResourceUsage,
    },
    /// A refusal before any guest code ran.
    Refused {
        error: &'static str,
        basis: Option<&'static str>,
        class: &'static str,
        /// Only from a setup refusal: an outcome record carries none.
        index: Option<u64>,
    },
    /// An authoritative failure.
    Failed {
        error: &'static str,
        class: &'static str,
    },
    /// An operational fault: there is no expectation for it.
    Operational,
}

/// The usage of one committed invocation from its `metering` and its `output` usage
/// (ADR-068 R4 4.1).
///
/// `cpu_fuel` is the checked sum of the two fuel counters (overflow is `None`, which is
/// operational); `memory_bytes`, `host_calls`, the Event count, the output bytes (the Event
/// payload bytes) and the storage bytes (the next state bytes) are direct; the invocation is one
/// execution step; Simulation Time belongs to the sub-case ([`of_record()`]), so it is 0 here.
#[must_use]
pub fn usage_of(metering: MeteringV1, output: OutputUsageV1) -> Option<ResourceUsage> {
    metering
        .startup_fuel
        .checked_add(metering.call_fuel)
        .map(|cpu_fuel| ResourceUsage {
            memory_bytes: metering.memory_bytes,
            cpu_fuel,
            host_calls: metering.host_calls,
            event_count: output.event_count,
            output_bytes: output.event_payload_bytes,
            storage_bytes: output.state_bytes,
            execution_steps: 1,
            simulation_time_ns: 0,
        })
}

/// The usage of two invocations of one attempt (ADR-068 R4 4.2(1)): `memory_bytes` is the
/// maximum, every other counter but Simulation Time is the checked sum, and an overflow is
/// `None`. Simulation Time is left 0: it is the sub-case's advance.
const fn plus(left: ResourceUsage, right: ResourceUsage) -> Option<ResourceUsage> {
    let sums = (
        left.cpu_fuel.checked_add(right.cpu_fuel),
        left.host_calls.checked_add(right.host_calls),
        left.event_count.checked_add(right.event_count),
        left.output_bytes.checked_add(right.output_bytes),
        left.storage_bytes.checked_add(right.storage_bytes),
        left.execution_steps.checked_add(right.execution_steps),
    );
    match sums {
        (
            Some(cpu_fuel),
            Some(host_calls),
            Some(event_count),
            Some(output_bytes),
            Some(storage_bytes),
            Some(execution_steps),
        ) => Some(ResourceUsage {
            memory_bytes: greater(left.memory_bytes, right.memory_bytes),
            cpu_fuel,
            host_calls,
            event_count,
            output_bytes,
            storage_bytes,
            execution_steps,
            simulation_time_ns: 0,
        }),
        _ => None,
    }
}

/// The Simulation Time a sub-case consumed (ADR-068 R4 4.1(5)): the last pass value less the
/// first, 0 for one pass or none. The grammar makes the values non-decreasing.
fn advance(times: &[u64]) -> u64 {
    times
        .last()
        .zip(times.first())
        .map_or(0, |(last, first)| last.saturating_sub(*first))
}

/// The usage of the attempt of `record` (ADR-068 R4 4.2(1)): the [`plus()`] of the usage of
/// its committed outcomes, with Simulation Time the [`advance()`] of its passes; `None` on an
/// overflow.
fn attempt_usage(record: &SubCaseRecordV1) -> Option<ResourceUsage> {
    record
        .outcomes
        .iter()
        .filter_map(|outcome| match of_outcome(outcome) {
            SubResultV1::Committed { usage, .. } => Some(usage),
            SubResultV1::Refused { .. } | SubResultV1::Failed { .. } | SubResultV1::Operational => {
                None
            }
        })
        .try_fold(ResourceUsage::default(), plus)
        .map(|usage| ResourceUsage {
            simulation_time_ns: advance(&record.simulation_times),
            ..usage
        })
}

/// Whether `error` is one of the 20 closed names.
fn is_known(error: &str) -> bool {
    KNOWN_ERRORS.contains(&error)
}

/// The sub-result of an outcome record.
#[must_use]
pub fn of_outcome(outcome: &CommunityPluginSubjectOutcomeV1) -> SubResultV1 {
    match outcome.result {
        CommunityPluginSubjectResultV1::Committed {
            output_digest: Some(output_digest),
            metering: Some(metering),
            output_usage: Some(output),
        } => usage_of(metering, output).map_or(SubResultV1::Operational, |usage| {
            SubResultV1::Committed {
                output_digest,
                usage,
            }
        }),
        CommunityPluginSubjectResultV1::Refused {
            error,
            basis,
            class,
        } if is_known(error) => SubResultV1::Refused {
            error,
            basis,
            class,
            index: None,
        },
        CommunityPluginSubjectResultV1::Failed { error, class }
            if is_known(error) && class == AUTHORITATIVE =>
        {
            SubResultV1::Failed { error, class }
        }
        CommunityPluginSubjectResultV1::Committed { .. }
        | CommunityPluginSubjectResultV1::Refused { .. }
        | CommunityPluginSubjectResultV1::Failed { .. }
        | CommunityPluginSubjectResultV1::Staged { .. }
        | CommunityPluginSubjectResultV1::NotRun
        | CommunityPluginSubjectResultV1::Discarded => SubResultV1::Operational,
    }
}

/// The `index` of an error that carries one.
fn index_of(error: CommunityPluginHostErrorV1) -> Option<u64> {
    match error {
        CommunityPluginHostErrorV1::CapabilityDenied { index }
        | CommunityPluginHostErrorV1::MissingFeature { index } => u64::try_from(index).ok(),
        _ => None,
    }
}

/// The sub-result of a setup refusal (install, `gate_for_driver`, Driver build) by its class.
#[must_use]
pub fn of_error(error: CommunityPluginHostErrorV1) -> SubResultV1 {
    let class = error.class();
    match class {
        HostFailureClassV1::PreExecutionRejection => SubResultV1::Refused {
            error: error.name(),
            basis: error.basis_name(),
            class: class.name(),
            index: index_of(error),
        },
        HostFailureClassV1::Authoritative => SubResultV1::Failed {
            error: error.name(),
            class: class.name(),
        },
        HostFailureClassV1::Operational => SubResultV1::Operational,
    }
}

/// The sub-result of a record: its setup refusal, else the outcome of its last pass, else none
/// (a sub-case with no pass has no result, which `digest`, `absent` and `malformed` need not).
///
/// A committed sub-result carries the usage of the attempt, not of its last outcome: the
/// checked sum over the committed outcomes, the maximum `memory_bytes`, one execution step per
/// committed outcome and the Simulation Time advance (ADR-068 R4 4.1, 4.2(1)). An overflow of a
/// sum is operational.
#[must_use]
pub fn of_record(record: &SubCaseRecordV1) -> Option<SubResultV1> {
    let refusal = record.setup_refusal.map(of_error);
    refusal.or_else(|| {
        record.outcomes.last().map(|last| match of_outcome(last) {
            SubResultV1::Committed { output_digest, .. } => {
                attempt_usage(record).map_or(SubResultV1::Operational, |usage| {
                    SubResultV1::Committed {
                        output_digest,
                        usage,
                    }
                })
            }
            other => other,
        })
    })
}

/// The case result and the usage that goes with it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseResultV1 {
    pub result: SubjectResult,
    pub usage: ResourceUsage,
}

/// How a family states its oracle.
enum Oracle {
    /// The canonical record is the output.
    Output,
    /// The family's fixed failure code is the answer when every sub-case matched.
    Failure(&'static str),
}

const fn oracle(family: FixtureFamily) -> Oracle {
    match family {
        FixtureFamily::Positive
        | FixtureFamily::DeletionRedaction
        | FixtureFamily::IndependentEvaluation => Oracle::Output,
        FixtureFamily::Denied => Oracle::Failure("capability-denied"),
        FixtureFamily::Malformed => Oracle::Failure("malformed-payload"),
        FixtureFamily::ResourceExhaustion => Oracle::Failure("resource-limit"),
        FixtureFamily::Downgrade => Oracle::Failure("incompatible-contract"),
    }
}

/// The provider's typed failure with code `code`.
#[must_use]
pub fn failure(code: &str) -> SubjectResult {
    SubjectResult::Failure(NamespacedFailure {
        owner_id: PROVIDER_ID.to_owned(),
        contract_version: CONTRACT_VERSION.to_owned(),
        code_id: code.to_owned(),
    })
}

/// The `payload-invalid` failure, which equals no oracle.
#[must_use]
pub fn payload_invalid() -> SubjectResult {
    failure(PAYLOAD_INVALID)
}

/// The per-counter maximum of two usages.
const fn larger(left: ResourceUsage, right: ResourceUsage) -> ResourceUsage {
    ResourceUsage {
        memory_bytes: greater(left.memory_bytes, right.memory_bytes),
        cpu_fuel: greater(left.cpu_fuel, right.cpu_fuel),
        host_calls: greater(left.host_calls, right.host_calls),
        event_count: greater(left.event_count, right.event_count),
        output_bytes: greater(left.output_bytes, right.output_bytes),
        storage_bytes: greater(left.storage_bytes, right.storage_bytes),
        execution_steps: greater(left.execution_steps, right.execution_steps),
        simulation_time_ns: greater(left.simulation_time_ns, right.simulation_time_ns),
    }
}

/// The greater of two counters.
const fn greater(left: u64, right: u64) -> u64 {
    if left >= right {
        left
    } else {
        right
    }
}

/// The result of the case `case_id` of `family` over the records of its sub-cases.
///
/// 1. If any sub-result is operational the case is `Unavailable`.
/// 2. Else for a `canonical-output` family it is `Output`, the canonical record.
/// 3. Else it is the family's fixed failure when every sub-case matched, and
///    `subcase-mismatch` otherwise.
///
/// The usage is the per-counter maximum over the records (ADR-068 R4 4.2(2)); a record that did
/// not commit reports 0 for all eight counters.
#[must_use]
pub fn case_result(
    case_id: &str,
    family: FixtureFamily,
    records: &[SubCaseRecordV1],
) -> CaseResultV1 {
    let operational = records
        .iter()
        .any(|record| of_record(record) == Some(SubResultV1::Operational));
    if operational {
        return CaseResultV1 {
            result: SubjectResult::Unavailable,
            usage: ResourceUsage::default(),
        };
    }
    let usage = records
        .iter()
        .fold(ResourceUsage::default(), |seen, record| {
            larger(seen, record.usage)
        });
    let result = match oracle(family) {
        Oracle::Output => SubjectResult::Output(record_bytes(case_id, family, records)),
        Oracle::Failure(code) => {
            let matched = records.iter().all(|record| record.matched);
            failure(if matched { code } else { SUBCASE_MISMATCH })
        }
    };
    CaseResultV1 { result, usage }
}

/// The canonical oracle record of a `canonical-output` family, with its LF terminator.
#[must_use]
pub fn record_bytes(case_id: &str, family: FixtureFamily, records: &[SubCaseRecordV1]) -> Vec<u8> {
    let entries = records.iter().map(|record| entry(family, record)).collect();
    JsonV1::object([
        ("case_id", JsonV1::text(case_id)),
        ("claim_layer", JsonV1::text("plugin-conformance")),
        ("family", JsonV1::text(family_text(family))),
        (
            "oracle",
            JsonV1::object([("kind", JsonV1::text("canonical-output"))]),
        ),
        (
            "output",
            JsonV1::object([("subcases", JsonV1::Array(entries))]),
        ),
    ])
    .line()
}

/// The entry of one sub-case: its values when it matched, else `{"id","kind":"mismatch"}`, so
/// that a sub-case that did not match can never equal the oracle, whatever it observed.
fn entry(family: FixtureFamily, record: &SubCaseRecordV1) -> JsonV1 {
    let id = JsonV1::text(&record.id);
    match (family, record) {
        _ if !record.matched => JsonV1::object([("id", id), ("kind", JsonV1::text("mismatch"))]),
        (
            FixtureFamily::Positive,
            SubCaseRecordV1 {
                committed: Some(digest),
                ..
            },
        ) => JsonV1::object([
            ("id", id),
            ("kind", JsonV1::text("committed")),
            ("output_digest", JsonV1::text(&hex::encode(digest))),
        ]),
        (
            FixtureFamily::DeletionRedaction,
            SubCaseRecordV1 {
                scan: Some(scan), ..
            },
        ) => {
            let retained = JsonV1::object([
                (
                    "invocation_id_hex",
                    JsonV1::text(&scan.observed_invocation_id_hex),
                ),
                ("plugin_id", JsonV1::text(&scan.observed_plugin_id)),
            ]);
            JsonV1::object([
                ("id", id),
                ("kind", JsonV1::text("absent")),
                (
                    "prohibited_data_present",
                    JsonV1::Bool(!scan.found.is_empty()),
                ),
                ("retained_metadata", retained),
            ])
        }
        (
            FixtureFamily::IndependentEvaluation,
            SubCaseRecordV1 {
                computed: Some(digest),
                ..
            },
        ) => JsonV1::object([
            ("id", id),
            ("kind", JsonV1::text("digest")),
            ("value", JsonV1::text(&hex::encode(digest))),
        ]),
        _ => JsonV1::object([("id", id), ("kind", JsonV1::text("mismatch"))]),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
