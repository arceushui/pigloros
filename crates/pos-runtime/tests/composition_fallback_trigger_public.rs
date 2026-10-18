//! ADR-119 trigger-eligibility classifier, through the public API.
//!
//! This guard lives in an integration test so its exhaustive matches over
//! every `CommunityPluginHostErrorV1` variant stay out of the source
//! complexity gate.

use pos_core::{FallbackActivationOriginV1, FallbackTriggerCodeV1 as Code};
use pos_runtime::community_plugin_host::{
    AtomicCommitFailureV1, CommunityPluginHostErrorV1, ComponentTrapClassV1, PassFailureV1,
    RevocationBasisV1, TrapReproductionV1, TrustDenialBasisV1,
};
use pos_runtime::composition_fallback::{
    classify_fallback_trigger_v1, declared_fallback_trigger_v1, FallbackTriggerCauseV1 as Cause,
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

/// The number of `CommunityPluginHostErrorV1` variants.
const VARIANTS: usize = 20;

/// A distinct index in `0..VARIANTS` for every variant, as an exhaustive
/// `match` with no wildcard arm: a new variant does not compile until it gets
/// an index, and the test then fails until `host_table` samples it.
const fn variant_index(error: Error) -> usize {
    match error {
        Error::InvalidManifest => 0,
        Error::ArtifactTrustDenied { .. } => 1,
        Error::ArtifactRevoked { .. } => 2,
        Error::IncompatibleAbi => 3,
        Error::MissingFeature { .. } => 4,
        Error::CapabilityDenied { .. } => 5,
        Error::InvalidInvocation => 6,
        Error::InvalidGuestOutput => 7,
        Error::UnsupportedSchema => 8,
        Error::StateMigrationFailed => 9,
        Error::GuestDeclaredFailure => 10,
        Error::ComponentTrap { .. } => 11,
        Error::WorkerCrashed => 12,
        Error::FuelExhausted => 13,
        Error::MemoryLimitExceeded => 14,
        Error::HostCallLimitExceeded => 15,
        Error::OutputLimitExceeded => 16,
        Error::DeterministicDeadlineExceeded => 17,
        Error::OperationalWatchdogStop => 18,
        Error::AtomicCommitFailed { .. } => 19,
    }
}

/// The cause of `error` as an exhaustive `match` with no wildcard arm: a new
/// host error variant does not compile until it is classified here, and the
/// test then requires `from_host_error` to agree, so a variant missing from
/// the source table (which maps to `Unrelated`) fails.
const fn expected_cause(error: Error) -> Cause {
    match error {
        Error::InvalidManifest => Cause::InvalidManifest,
        Error::ArtifactTrustDenied { .. } => Cause::ArtifactTrustDenied,
        Error::ArtifactRevoked { .. } => Cause::ArtifactRevoked,
        Error::IncompatibleAbi => Cause::IncompatibleAbi,
        Error::MissingFeature { .. } => Cause::MissingFeature,
        Error::CapabilityDenied { .. } => Cause::CapabilityDenied,
        Error::InvalidInvocation => Cause::InvalidInvocation,
        Error::InvalidGuestOutput => Cause::InvalidGuestOutput,
        Error::UnsupportedSchema => Cause::UnsupportedSchema,
        Error::StateMigrationFailed => Cause::StateMigrationFailed,
        Error::GuestDeclaredFailure => Cause::GuestDeclaredFailure,
        Error::ComponentTrap {
            reproduction: TrapReproductionV1::Unverified,
            ..
        } => Cause::ComponentTrapUnverified,
        Error::ComponentTrap {
            reproduction: TrapReproductionV1::ReproducedByConformance,
            ..
        } => Cause::ComponentTrapReproduced,
        Error::WorkerCrashed => Cause::WorkerCrashed,
        Error::FuelExhausted => Cause::FuelExhausted,
        Error::MemoryLimitExceeded => Cause::MemoryLimitExceeded,
        Error::HostCallLimitExceeded => Cause::HostCallLimitExceeded,
        Error::OutputLimitExceeded => Cause::OutputLimitExceeded,
        Error::DeterministicDeadlineExceeded => Cause::DeterministicDeadlineExceeded,
        Error::OperationalWatchdogStop => Cause::OperationalWatchdogStop,
        Error::AtomicCommitFailed { .. } => Cause::AtomicCommitFailed,
    }
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
    let table = host_table();
    for &(error, cause) in &table {
        assert_eq!(expected_cause(error), cause, "{error:?}");
        assert_eq!(Cause::from_host_error(error), cause, "{error:?}");
        let failure = PassFailureV1::Host(error);
        assert_eq!(Cause::from_pass_failure(failure), cause, "{error:?}");
    }
    let mut sampled = [false; VARIANTS];
    for (error, _) in &table {
        sampled[variant_index(*error)] = true;
    }
    assert_eq!(sampled, [true; VARIANTS]);
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
