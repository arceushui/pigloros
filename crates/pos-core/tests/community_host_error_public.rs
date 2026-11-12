//! Closed ADR-061 identifiers remain stable independently of display messages.

use pos_core::community_lifecycle::{
    AtomicCommitFailureV1 as Atomic, BundleContentReasonV1 as Content,
    CommunityPluginHostErrorV1 as Host, ComponentTrapClassV1 as Trap, HostFailureClassV1 as Class,
    RevocationBasisV1 as Revocation, TrapReproductionV1 as Reproduction,
    TrustDenialBasisV1 as Denial,
};

#[test]
fn public_failure_class_and_trap_names_are_the_closed_protocol_identifiers() {
    for (class, expected) in [
        (Class::Authoritative, "Authoritative"),
        (Class::Operational, "Operational"),
        (Class::PreExecutionRejection, "PreExecutionRejection"),
    ] {
        assert_eq!(class.name(), expected);
    }
    for (class, expected) in [
        (Trap::Unreachable, "unreachable"),
        (Trap::MemoryOutOfBounds, "memory-out-of-bounds"),
        (Trap::TableOutOfBounds, "table-out-of-bounds"),
        (Trap::IndirectCall, "indirect-call"),
        (Trap::IntegerArithmetic, "integer-arithmetic"),
        (Trap::StackExhausted, "stack-exhausted"),
        (Trap::Other, "other"),
    ] {
        assert_eq!(class.name(), expected);
    }
}

#[test]
fn a_basis_is_reported_beside_its_host_name() {
    for (basis, expected) in [
        (Denial::Expired, "Expired"),
        (Denial::NotActive, "NotActive"),
        (Denial::Untrusted, "Untrusted"),
        (Denial::PolicyMismatch, "PolicyMismatch"),
        (Denial::TrustStateUnavailable, "TrustStateUnavailable"),
    ] {
        assert_eq!(basis.name(), expected);
        let error = Host::ArtifactTrustDenied { basis };
        assert_eq!(error.name(), "ArtifactTrustDenied");
        assert_eq!(error.basis_name(), Some(expected));
        assert!(error.produced_in_v1());
    }
    for (basis, expected) in [
        (Revocation::PublisherKey, "PublisherKey"),
        (Revocation::Artifact, "Artifact"),
        (Revocation::OperatorDenial, "OperatorDenial"),
    ] {
        assert_eq!(basis.name(), expected);
        let error = Host::ArtifactRevoked { basis };
        assert_eq!(error.name(), "ArtifactRevoked");
        assert_eq!(error.basis_name(), Some(expected));
        assert!(error.produced_in_v1());
    }
    for (reason, expected) in [
        (Content::BoundsExceeded, "BoundsExceeded"),
        (Content::UnsupportedFormat, "UnsupportedFormat"),
        (Content::Malformed, "Malformed"),
        (Content::ReferenceMismatch, "ReferenceMismatch"),
    ] {
        assert_eq!(reason.name(), expected);
        let error = Host::InvalidBundleContent { reason };
        assert_eq!(error.name(), "InvalidBundleContent");
        assert_eq!(error.basis_name(), Some(expected));
        assert_eq!(error.class(), Class::PreExecutionRejection);
        assert!(error.produced_in_v1());
    }
}

#[test]
fn host_names_preserve_reserved_errors_without_claiming_v1_can_produce_them() {
    for (error, expected, produced) in [
        (Host::InvalidManifest, "InvalidManifest", true),
        (Host::IncompatibleAbi, "IncompatibleAbi", true),
        (Host::MissingFeature { index: 255 }, "MissingFeature", true),
        (
            Host::CapabilityDenied { index: 255 },
            "CapabilityDenied",
            true,
        ),
        (Host::InvalidInvocation, "InvalidInvocation", true),
        (Host::InvalidGuestOutput, "InvalidGuestOutput", true),
        (Host::UnsupportedSchema, "UnsupportedSchema", true),
        (Host::StateMigrationFailed, "StateMigrationFailed", false),
        (Host::GuestDeclaredFailure, "GuestDeclaredFailure", true),
        (
            Host::ComponentTrap {
                class: Trap::Other,
                reproduction: Reproduction::Unverified,
            },
            "ComponentTrap",
            true,
        ),
        (Host::WorkerCrashed, "WorkerCrashed", true),
        (Host::FuelExhausted, "FuelExhausted", true),
        (Host::MemoryLimitExceeded, "MemoryLimitExceeded", true),
        (Host::HostCallLimitExceeded, "HostCallLimitExceeded", true),
        (Host::OutputLimitExceeded, "OutputLimitExceeded", true),
        (
            Host::DeterministicDeadlineExceeded,
            "DeterministicDeadlineExceeded",
            false,
        ),
        (
            Host::OperationalWatchdogStop,
            "OperationalWatchdogStop",
            true,
        ),
        (
            Host::AtomicCommitFailed {
                failure: Atomic::Operational,
            },
            "AtomicCommitFailed",
            true,
        ),
        (
            Host::AtomicCommitFailed {
                failure: Atomic::DeterministicTypedResult,
            },
            "AtomicCommitFailed",
            true,
        ),
    ] {
        assert_eq!(error.name(), expected);
        assert_eq!(error.basis_name(), None);
        assert_eq!(error.produced_in_v1(), produced);
    }
}
