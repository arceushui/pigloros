use std::collections::BTreeSet;

use super::{code_name, outcome_name, CODE_NAMES};
use crate::{SandboxProviderErrorCodeV1, SandboxTerminalOutcomeV1};

/// Names every code in one arm, so a new code is a compile error here until it
/// is placed in the table and in this list.
const fn every_code_is_named(code: SandboxProviderErrorCodeV1) {
    match code {
        SandboxProviderErrorCodeV1::InvalidEncoding
        | SandboxProviderErrorCodeV1::UnsupportedVersion
        | SandboxProviderErrorCodeV1::FieldOutOfBounds
        | SandboxProviderErrorCodeV1::NonCanonicalOrder
        | SandboxProviderErrorCodeV1::DigestMismatch
        | SandboxProviderErrorCodeV1::SignatureInvalid
        | SandboxProviderErrorCodeV1::TrustRevoked
        | SandboxProviderErrorCodeV1::AuthorityMismatch
        | SandboxProviderErrorCodeV1::ProviderCapabilityMissing
        | SandboxProviderErrorCodeV1::ImageIdentityMismatch
        | SandboxProviderErrorCodeV1::SelfTestFailed
        | SandboxProviderErrorCodeV1::SandboxUnavailable
        | SandboxProviderErrorCodeV1::AdmissionBusy
        | SandboxProviderErrorCodeV1::AuditUnavailable
        | SandboxProviderErrorCodeV1::CleanupFailed
        | SandboxProviderErrorCodeV1::UnknownAttempt
        | SandboxProviderErrorCodeV1::RequestIdentityConflict
        | SandboxProviderErrorCodeV1::PayloadTransferTimeout => {}
    }
}

#[test]
fn every_refusal_code_has_its_declared_position_and_wire_name() {
    for (position, (code, name)) in CODE_NAMES.iter().enumerate() {
        every_code_is_named(*code);
        assert_eq!(*code as usize, position);
        assert_eq!(format!("{code:?}"), *name);
        assert_eq!(code_name(*code), *name);
    }
}

#[test]
fn the_wire_names_are_unique() {
    let names: BTreeSet<&str> = CODE_NAMES.iter().map(|(_, name)| *name).collect();
    assert_eq!(names.len(), CODE_NAMES.len());
}

#[test]
fn every_terminal_outcome_has_its_wire_name() {
    let outcomes = [
        (SandboxTerminalOutcomeV1::Completed, "Completed"),
        (SandboxTerminalOutcomeV1::Cancelled, "Cancelled"),
        (
            SandboxTerminalOutcomeV1::UnavailableBeforeAdmission,
            "UnavailableBeforeAdmission",
        ),
        (SandboxTerminalOutcomeV1::Rejected, "Rejected"),
        (
            SandboxTerminalOutcomeV1::UnavailableAfterAdmission,
            "UnavailableAfterAdmission",
        ),
    ];
    for (outcome, name) in outcomes {
        assert_eq!(outcome_name(outcome), name);
    }
}
