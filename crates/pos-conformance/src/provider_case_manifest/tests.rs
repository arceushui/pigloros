use std::collections::BTreeSet;

use super::{code_name, outcome_name, CODE_NAMES};
use crate::{SandboxProviderErrorCodeV1, SandboxTerminalOutcomeV1};

/// The position and wire name of every code. The match is exhaustive, so a
/// new code is a compile error here until it is placed in the table.
const fn expected(code: SandboxProviderErrorCodeV1) -> (usize, &'static str) {
    match code {
        SandboxProviderErrorCodeV1::InvalidEncoding => (0, "InvalidEncoding"),
        SandboxProviderErrorCodeV1::UnsupportedVersion => (1, "UnsupportedVersion"),
        SandboxProviderErrorCodeV1::FieldOutOfBounds => (2, "FieldOutOfBounds"),
        SandboxProviderErrorCodeV1::NonCanonicalOrder => (3, "NonCanonicalOrder"),
        SandboxProviderErrorCodeV1::DigestMismatch => (4, "DigestMismatch"),
        SandboxProviderErrorCodeV1::SignatureInvalid => (5, "SignatureInvalid"),
        SandboxProviderErrorCodeV1::TrustRevoked => (6, "TrustRevoked"),
        SandboxProviderErrorCodeV1::AuthorityMismatch => (7, "AuthorityMismatch"),
        SandboxProviderErrorCodeV1::ProviderCapabilityMissing => (8, "ProviderCapabilityMissing"),
        SandboxProviderErrorCodeV1::ImageIdentityMismatch => (9, "ImageIdentityMismatch"),
        SandboxProviderErrorCodeV1::SelfTestFailed => (10, "SelfTestFailed"),
        SandboxProviderErrorCodeV1::SandboxUnavailable => (11, "SandboxUnavailable"),
        SandboxProviderErrorCodeV1::AdmissionBusy => (12, "AdmissionBusy"),
        SandboxProviderErrorCodeV1::AuditUnavailable => (13, "AuditUnavailable"),
        SandboxProviderErrorCodeV1::CleanupFailed => (14, "CleanupFailed"),
        SandboxProviderErrorCodeV1::UnknownAttempt => (15, "UnknownAttempt"),
        SandboxProviderErrorCodeV1::RequestIdentityConflict => (16, "RequestIdentityConflict"),
        SandboxProviderErrorCodeV1::PayloadTransferTimeout => (17, "PayloadTransferTimeout"),
    }
}

#[test]
fn every_refusal_code_has_its_declared_position_and_wire_name() {
    for (position, (code, name)) in CODE_NAMES.iter().enumerate() {
        assert_eq!(expected(*code), (position, *name));
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
