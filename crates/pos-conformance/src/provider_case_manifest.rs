//! The provider conformance cases as one machine-readable manifest (#216).
//!
//! The guest collector, the host checker and the suite itself must agree on
//! what every case runs and what it must show. [`case_manifest_v1`] is that
//! one statement, built from [`ProviderConformanceCase`] and the adapter plan,
//! and a committed copy of it is the vector that the non-Rust parts read. A
//! test keeps the copy equal to what the code states.
//!
//! Each case names its driver, which tells the runner what it needs besides
//! the adapter: `single-execute` runs one attempt, `control` also acts on it
//! (cancel, revoke, broker crash), `admission` is refused before any attempt,
//! and `concurrent` runs several attempts at once.

use serde_json::{json, Value};

use crate::{
    ExpectedPublicOutcome, ProviderConformanceCase, SandboxProviderErrorCodeV1,
    SandboxTerminalOutcomeV1, MEMORY_CEILING_BYTES, OUTPUT_CEILING_BYTES, OVERSHOOT, TASK_CEILING,
    WATCHDOG_CEILING_MS, WORK_CEILING_BYTES,
};

/// The manifest's version.
const VERSION: u64 = 1;

/// What the runner needs of a case besides its adapter. Every case is named,
/// so a new case forces a decision here.
const fn driver(case: ProviderConformanceCase) -> &'static str {
    match case {
        ProviderConformanceCase::FilesystemEscape
        | ProviderConformanceCase::ReadOnlyRootWrite
        | ProviderConformanceCase::WorkAreaExhaustion
        | ProviderConformanceCase::NetworkEscape
        | ProviderConformanceCase::ForeignSignals
        | ProviderConformanceCase::OrphanedChild
        | ProviderConformanceCase::TaskExhaustion
        | ProviderConformanceCase::MemoryExhaustion
        | ProviderConformanceCase::WatchdogExpiry
        | ProviderConformanceCase::OversizedOutput
        | ProviderConformanceCase::AdapterCrash
        | ProviderConformanceCase::MalformedOutput => "single-execute",
        ProviderConformanceCase::CancelBeforeRelease
        | ProviderConformanceCase::CancelWhileRunning
        | ProviderConformanceCase::BrokerCrashRecovery
        | ProviderConformanceCase::RevokedWhileRunning => "control",
        ProviderConformanceCase::RevokedBeforeAdmission
        | ProviderConformanceCase::MissingHostFeature => "admission",
        ProviderConformanceCase::ConcurrentAttempts => "concurrent",
    }
}

/// The wire name of an SPY1 outcome, as the guest report prints it. The names
/// are written out so that renaming a variant cannot change the wire.
const fn outcome_name(outcome: SandboxTerminalOutcomeV1) -> &'static str {
    match outcome {
        SandboxTerminalOutcomeV1::Completed => "Completed",
        SandboxTerminalOutcomeV1::Cancelled => "Cancelled",
        SandboxTerminalOutcomeV1::UnavailableBeforeAdmission => "UnavailableBeforeAdmission",
        SandboxTerminalOutcomeV1::Rejected => "Rejected",
        SandboxTerminalOutcomeV1::UnavailableAfterAdmission => "UnavailableAfterAdmission",
    }
}

/// The wire name of every SPE1 refusal code, as the guest report prints it,
/// in the order the codes are declared. The names are written out so that
/// renaming a variant cannot change the wire; a test keeps the order and the
/// names right for every variant.
const CODE_NAMES: [(SandboxProviderErrorCodeV1, &str); 18] = [
    (
        SandboxProviderErrorCodeV1::InvalidEncoding,
        "InvalidEncoding",
    ),
    (
        SandboxProviderErrorCodeV1::UnsupportedVersion,
        "UnsupportedVersion",
    ),
    (
        SandboxProviderErrorCodeV1::FieldOutOfBounds,
        "FieldOutOfBounds",
    ),
    (
        SandboxProviderErrorCodeV1::NonCanonicalOrder,
        "NonCanonicalOrder",
    ),
    (SandboxProviderErrorCodeV1::DigestMismatch, "DigestMismatch"),
    (
        SandboxProviderErrorCodeV1::SignatureInvalid,
        "SignatureInvalid",
    ),
    (SandboxProviderErrorCodeV1::TrustRevoked, "TrustRevoked"),
    (
        SandboxProviderErrorCodeV1::AuthorityMismatch,
        "AuthorityMismatch",
    ),
    (
        SandboxProviderErrorCodeV1::ProviderCapabilityMissing,
        "ProviderCapabilityMissing",
    ),
    (
        SandboxProviderErrorCodeV1::ImageIdentityMismatch,
        "ImageIdentityMismatch",
    ),
    (SandboxProviderErrorCodeV1::SelfTestFailed, "SelfTestFailed"),
    (
        SandboxProviderErrorCodeV1::SandboxUnavailable,
        "SandboxUnavailable",
    ),
    (SandboxProviderErrorCodeV1::AdmissionBusy, "AdmissionBusy"),
    (
        SandboxProviderErrorCodeV1::AuditUnavailable,
        "AuditUnavailable",
    ),
    (SandboxProviderErrorCodeV1::CleanupFailed, "CleanupFailed"),
    (SandboxProviderErrorCodeV1::UnknownAttempt, "UnknownAttempt"),
    (
        SandboxProviderErrorCodeV1::RequestIdentityConflict,
        "RequestIdentityConflict",
    ),
    (
        SandboxProviderErrorCodeV1::PayloadTransferTimeout,
        "PayloadTransferTimeout",
    ),
];

/// The wire name of an SPE1 refusal code.
const fn code_name(code: SandboxProviderErrorCodeV1) -> &'static str {
    CODE_NAMES[code as usize].1
}

/// The public outcome a case must show, in the report's own names.
///
/// Every object lists its keys in alphabetical order, so the text is the same
/// whether or not `serde_json` keeps insertion order.
fn expectation(outcome: ExpectedPublicOutcome) -> Value {
    match outcome {
        ExpectedPublicOutcome::Terminal { outcome, codes } => {
            json!({ "codes": codes, "kind": "terminal", "outcome": outcome_name(outcome) })
        }
        ExpectedPublicOutcome::Refused(codes) => {
            let names: Vec<&str> = codes.iter().map(|code| code_name(*code)).collect();
            json!({ "codes": names, "kind": "refused" })
        }
    }
}

fn entry(case: ProviderConformanceCase) -> Value {
    json!({
        "arguments": case.adapter_plan().arguments(),
        "attempts": case.attempts(),
        "driver": driver(case),
        "expect": expectation(case.expectation()),
        "id": case.id(),
    })
}

/// The manifest of every case, in report order, with the ceilings the cases'
/// attempts are built with and the factor by which a limit case's bound
/// exceeds its ceiling.
#[must_use]
pub fn case_manifest_v1() -> Value {
    json!({
        "cases": ProviderConformanceCase::ALL.map(entry),
        "ceilings": {
            "memory_bytes": MEMORY_CEILING_BYTES,
            "output_bytes": OUTPUT_CEILING_BYTES,
            "tasks": TASK_CEILING,
            "watchdog_ms": WATCHDOG_CEILING_MS,
            "work_bytes": WORK_CEILING_BYTES,
        },
        "overshoot": OVERSHOOT,
        "version": VERSION,
    })
}

#[cfg(test)]
mod tests;
