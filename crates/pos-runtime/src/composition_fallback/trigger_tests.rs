use super::*;
use crate::community_plugin_host::{
    AtomicCommitFailureV1, ComponentTrapClassV1, RevocationBasisV1, TrustDenialBasisV1,
};

type Error = CommunityPluginHostErrorV1;

/// Every community host error variant, with the cause it maps to.
fn host_table() -> Vec<(Error, Cause)> {
    let unverified = TrapReproductionV1::Unverified;
    let reproduced = TrapReproductionV1::ReproducedByConformance;
    let trap = |reproduction| Error::ComponentTrap {
        class: ComponentTrapClassV1::Unreachable,
        reproduction,
    };
    let commit = |failure| Error::AtomicCommitFailed { failure };
    let mut table = vec![
        (Error::InvalidManifest, Cause::InvalidManifest),
        (Error::IncompatibleAbi, Cause::IncompatibleAbi),
        (Error::MissingFeature { index: 0 }, Cause::MissingFeature),
        (
            Error::CapabilityDenied { index: 12 },
            Cause::CapabilityDenied,
        ),
        (Error::InvalidInvocation, Cause::InvalidInvocation),
        (Error::InvalidGuestOutput, Cause::InvalidGuestOutput),
        (Error::UnsupportedSchema, Cause::UnsupportedSchema),
        (Error::StateMigrationFailed, Cause::StateMigrationFailed),
        (Error::GuestDeclaredFailure, Cause::GuestDeclaredFailure),
        (trap(unverified), Cause::ComponentTrapUnverified),
        (trap(reproduced), Cause::ComponentTrapReproduced),
        (Error::WorkerCrashed, Cause::WorkerCrashed),
        (Error::FuelExhausted, Cause::FuelExhausted),
        (Error::MemoryLimitExceeded, Cause::MemoryLimitExceeded),
        (Error::HostCallLimitExceeded, Cause::HostCallLimitExceeded),
        (Error::OutputLimitExceeded, Cause::OutputLimitExceeded),
        (
            Error::DeterministicDeadlineExceeded,
            Cause::DeterministicDeadlineExceeded,
        ),
        (
            Error::OperationalWatchdogStop,
            Cause::OperationalWatchdogStop,
        ),
    ];
    for failure in [
        AtomicCommitFailureV1::DeterministicTypedResult,
        AtomicCommitFailureV1::Operational,
    ] {
        table.push((commit(failure), Cause::AtomicCommitFailed));
    }
    for basis in [
        TrustDenialBasisV1::Expired,
        TrustDenialBasisV1::NotActive,
        TrustDenialBasisV1::Untrusted,
        TrustDenialBasisV1::PolicyMismatch,
        TrustDenialBasisV1::TrustStateUnavailable,
    ] {
        let denied = Error::ArtifactTrustDenied { basis };
        table.push((denied, Cause::ArtifactTrustDenied));
    }
    for basis in [
        RevocationBasisV1::PublisherKey,
        RevocationBasisV1::Artifact,
        RevocationBasisV1::OperatorDenial,
    ] {
        let revoked = Error::ArtifactRevoked { basis };
        table.push((revoked, Cause::ArtifactRevoked));
    }
    table
}

/// The eligible code of every cause; every cause not listed is never eligible.
const EXPECTED: [(Cause, Code); 8] = [
    (Cause::MissingImplementation, Code::MissingImplementation),
    (Cause::ComponentTrapReproduced, Code::ComponentTrap),
    (Cause::FuelExhausted, Code::ResourceLimit),
    (Cause::MemoryLimitExceeded, Code::ResourceLimit),
    (Cause::HostCallLimitExceeded, Code::ResourceLimit),
    (Cause::OutputLimitExceeded, Code::ResourceLimit),
    (Cause::ArtifactRevoked, Code::ArtifactRevoked),
    (Cause::WorkerCrashed, Code::WorkerCrashed),
];

fn expected(cause: Cause) -> Option<Code> {
    EXPECTED
        .iter()
        .find(|(listed, _)| *listed == cause)
        .map(|(_, code)| *code)
}

#[test]
fn every_host_error_maps_to_its_cause() {
    for (error, cause) in host_table() {
        assert_eq!(Cause::from_host_error(error), cause, "{error:?}");
        let failure = PassFailureV1::Host(error);
        assert_eq!(Cause::from_pass_failure(failure), cause, "{error:?}");
    }
}

#[test]
fn pass_failures_without_a_host_error_are_never_eligible() {
    let in_doubt = Cause::from_pass_failure(PassFailureV1::InDoubt);
    let unrelated = Cause::from_pass_failure(PassFailureV1::Unrelated);
    assert_eq!(in_doubt, Cause::InDoubt);
    assert_eq!(unrelated, Cause::Unrelated);
    assert_eq!(classify_fallback_trigger_v1(in_doubt), None);
    assert_eq!(classify_fallback_trigger_v1(unrelated), None);
}

#[test]
fn the_classifier_table_matches_adr_119() {
    for cause in Cause::ALL {
        let code = classify_fallback_trigger_v1(cause);
        assert_eq!(code, expected(cause), "{cause:?}");
    }
}

#[test]
fn the_never_eligible_list_is_never_eligible() {
    for cause in [
        Cause::InvalidManifest,
        Cause::ArtifactTrustDenied,
        Cause::IncompatibleAbi,
        Cause::MissingFeature,
        Cause::CapabilityDenied,
        Cause::InvalidInvocation,
        Cause::InvalidGuestOutput,
        Cause::UnsupportedSchema,
        Cause::StateMigrationFailed,
        Cause::GuestDeclaredFailure,
        Cause::ComponentTrapUnverified,
        Cause::DeterministicDeadlineExceeded,
        Cause::OperationalWatchdogStop,
        Cause::AtomicCommitFailed,
        Cause::InDoubt,
        Cause::ImplementationUnavailable,
        Cause::CompositionMismatch,
        Cause::Unrelated,
        Cause::BoundaryTransactionFailed,
    ] {
        assert_eq!(classify_fallback_trigger_v1(cause), None, "{cause:?}");
    }
}

#[test]
fn an_unverified_trap_waits_for_fu_7() {
    let trap = Error::ComponentTrap {
        class: ComponentTrapClassV1::Other,
        reproduction: TrapReproductionV1::Unverified,
    };
    let cause = Cause::from_host_error(trap);
    assert_eq!(classify_fallback_trigger_v1(cause), None);
}

#[test]
fn cause_codes_round_trip_and_are_unique() {
    for (index, cause) in Cause::ALL.into_iter().enumerate() {
        let code = cause.code();
        assert_eq!(usize::from(code), index + 1, "{cause:?}");
        assert_eq!(Cause::from_code(code), Some(cause));
    }
    assert_eq!(Cause::from_code(0), None);
    assert_eq!(Cause::from_code(28), None);
}

#[test]
fn the_basis_carries_the_cause_code_and_origin() {
    let origin = FallbackActivationOriginV1::Owner;
    let basis = Cause::WorkerCrashed.basis(origin);
    assert_eq!(basis.cause, 15);
    assert_eq!(basis.origin, origin);
    assert_eq!(format!("{:?}", Cause::WorkerCrashed), "WorkerCrashed");
}

#[test]
fn only_declared_triggers_fire() {
    let crash = Cause::WorkerCrashed;
    let undeclared = declared_fallback_trigger_v1(crash, &[Code::ResourceLimit]);
    assert_eq!(undeclared, None);
    let opted_in = [Code::ResourceLimit, Code::WorkerCrashed];
    let fired = declared_fallback_trigger_v1(crash, &opted_in);
    assert_eq!(fired, Some(Code::WorkerCrashed));
    let never = declared_fallback_trigger_v1(Cause::InDoubt, &Code::ALL);
    assert_eq!(never, None);
}
