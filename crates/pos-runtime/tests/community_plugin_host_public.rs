//! ADR-061 revision 4 community Plugin host contract at its public seams.
//!
//! Execution projections come from the `pos-crypto` `test-support` fixture,
//! which models caller-fabricated PMF1 requirements, so every negotiation
//! rejection path is reachable without publishing a release closure. The
//! real projection is covered by `pos-crypto`'s PMF1 tests.

use pos_core::{CoreError, PipelineOutcomeV1};
use pos_crypto::plugin_execution::{
    DeterministicBudgetV1, PluginAbiRequirementV1, PluginCapabilityDescriptorV1,
    PluginExecutionProjectionFixtureV1, PluginExecutionProjectionV1, COMMUNITY_PLUGIN_WORLD_V1,
    WASM_PAGE_BYTES_V1,
};
use pos_runtime::community_plugin_host::{
    classify_pass_failure, negotiate_community_plugin_v1, quarantine_for, AtomicCommitFailureV1,
    CeilingValuesV1, CommunityPluginCeilingsV1, CommunityPluginExecutionProfileV1,
    CommunityPluginHostAbiErrorV1, CommunityPluginHostAbiV1, CommunityPluginHostErrorV1,
    CommunityPluginModeV1, CommunityPluginProfileErrorV1, ComponentTrapClassV1,
    EffectiveExecutionLimitsV1, ExecutionLimitV1, HostFailureClassV1, NegotiatedCommunityPluginV1,
    PassFailureV1, PinnedComponentRuntimeV1, PinnedEngineConfigV1, RevocationBasisV1,
    TrapOutcomeV1, TrapReproductionV1, TrapTableEntryV1, TrustDenialBasisV1,
    COMMUNITY_PLUGIN_ABI_MAJOR_V1,
};
use pos_runtime::{PluginAvailabilityV1, PluginExecutionModeV1, RuntimeError};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Negotiation = Result<NegotiatedCommunityPluginV1, Error>;
type Error = CommunityPluginHostErrorV1;
type ProfileError = CommunityPluginProfileErrorV1;

const AUTHORITATIVE: HostFailureClassV1 = HostFailureClassV1::Authoritative;
const OPERATIONAL: HostFailureClassV1 = HostFailureClassV1::Operational;
const REJECTION: HostFailureClassV1 = HostFailureClassV1::PreExecutionRejection;
const MAXIMA: DeterministicBudgetV1 = DeterministicBudgetV1::MAXIMA;
/// A budget inside every V1 host ceiling.
const SMALL_BUDGET: DeterministicBudgetV1 = DeterministicBudgetV1 {
    memory_bytes: 2 * WASM_PAGE_BYTES_V1,
    fuel: 5_000,
    host_calls: 40,
    event_count: 3,
    event_bytes: 900,
    state_bytes: 700,
    log_calls: 5,
    log_bytes: 600,
};
/// Every canonical trap class in ADR table order.
const TRAP_CLASSES: [ComponentTrapClassV1; 7] = [
    ComponentTrapClassV1::Unreachable,
    ComponentTrapClassV1::MemoryOutOfBounds,
    ComponentTrapClassV1::TableOutOfBounds,
    ComponentTrapClassV1::IndirectCall,
    ComponentTrapClassV1::IntegerArithmetic,
    ComponentTrapClassV1::StackExhausted,
    ComponentTrapClassV1::Other,
];
const TRAP: ComponentTrapClassV1 = ComponentTrapClassV1::StackExhausted;
const REPRODUCED: TrapReproductionV1 = TrapReproductionV1::ReproducedByConformance;
const UNVERIFIED: TrapReproductionV1 = TrapReproductionV1::Unverified;
const TYPED: AtomicCommitFailureV1 = AtomicCommitFailureV1::DeterministicTypedResult;
const UNTYPED: AtomicCommitFailureV1 = AtomicCommitFailureV1::Operational;
const TRUST_EXPIRED: TrustDenialBasisV1 = TrustDenialBasisV1::Expired;
const REVOKED_ARTIFACT: RevocationBasisV1 = RevocationBasisV1::Artifact;
/// Every trust-denial basis with its exact ADR-061 revision 7 name.
const TRUST_BASES: [(TrustDenialBasisV1, &str); 5] = [
    (TrustDenialBasisV1::Expired, "Expired"),
    (TrustDenialBasisV1::NotActive, "NotActive"),
    (TrustDenialBasisV1::Untrusted, "Untrusted"),
    (TrustDenialBasisV1::PolicyMismatch, "PolicyMismatch"),
    (
        TrustDenialBasisV1::TrustStateUnavailable,
        "TrustStateUnavailable",
    ),
];
/// Every revocation basis with its exact ADR-061 revision 7 name.
const REVOCATION_BASES: [(RevocationBasisV1, &str); 3] = [
    (RevocationBasisV1::PublisherKey, "PublisherKey"),
    (RevocationBasisV1::Artifact, "Artifact"),
    (RevocationBasisV1::OperatorDenial, "OperatorDenial"),
];
/// Every closed error with its ADR name, class and V1 production.
const ERRORS: [(Error, &str, HostFailureClassV1, bool); 22] = [
    (Error::InvalidManifest, "InvalidManifest", REJECTION, true),
    (
        Error::ArtifactTrustDenied {
            basis: TRUST_EXPIRED,
        },
        "ArtifactTrustDenied",
        REJECTION,
        true,
    ),
    (
        Error::ArtifactRevoked {
            basis: REVOKED_ARTIFACT,
        },
        "ArtifactRevoked",
        REJECTION,
        true,
    ),
    (Error::IncompatibleAbi, "IncompatibleAbi", REJECTION, true),
    (
        Error::MissingFeature { index: 2 },
        "MissingFeature",
        REJECTION,
        true,
    ),
    (
        Error::CapabilityDenied { index: 3 },
        "CapabilityDenied",
        REJECTION,
        true,
    ),
    (
        Error::InvalidInvocation,
        "InvalidInvocation",
        REJECTION,
        true,
    ),
    (
        Error::InvalidGuestOutput,
        "InvalidGuestOutput",
        AUTHORITATIVE,
        true,
    ),
    (
        Error::UnsupportedSchema,
        "UnsupportedSchema",
        AUTHORITATIVE,
        true,
    ),
    (
        Error::StateMigrationFailed,
        "StateMigrationFailed",
        AUTHORITATIVE,
        false,
    ),
    (
        Error::GuestDeclaredFailure,
        "GuestDeclaredFailure",
        AUTHORITATIVE,
        true,
    ),
    (
        Error::ComponentTrap {
            class: TRAP,
            reproduction: REPRODUCED,
        },
        "ComponentTrap",
        AUTHORITATIVE,
        true,
    ),
    (
        Error::ComponentTrap {
            class: TRAP,
            reproduction: UNVERIFIED,
        },
        "ComponentTrap",
        OPERATIONAL,
        true,
    ),
    (Error::WorkerCrashed, "WorkerCrashed", OPERATIONAL, true),
    (Error::FuelExhausted, "FuelExhausted", AUTHORITATIVE, true),
    (
        Error::MemoryLimitExceeded,
        "MemoryLimitExceeded",
        AUTHORITATIVE,
        true,
    ),
    (
        Error::HostCallLimitExceeded,
        "HostCallLimitExceeded",
        AUTHORITATIVE,
        true,
    ),
    (
        Error::OutputLimitExceeded,
        "OutputLimitExceeded",
        AUTHORITATIVE,
        true,
    ),
    (
        Error::DeterministicDeadlineExceeded,
        "DeterministicDeadlineExceeded",
        AUTHORITATIVE,
        false,
    ),
    (
        Error::OperationalWatchdogStop,
        "OperationalWatchdogStop",
        OPERATIONAL,
        true,
    ),
    (
        Error::AtomicCommitFailed { failure: TYPED },
        "AtomicCommitFailed",
        AUTHORITATIVE,
        true,
    ),
    (
        Error::AtomicCommitFailed { failure: UNTYPED },
        "AtomicCommitFailed",
        OPERATIONAL,
        true,
    ),
];

fn capability(operation: &str, required: bool) -> PluginCapabilityDescriptorV1 {
    PluginCapabilityDescriptorV1 {
        capability_id: "kv".to_owned(),
        operation: operation.to_owned(),
        resource_pattern: "state/*".to_owned(),
        purpose: "Read Plugin state".to_owned(),
        audience: "plugin".to_owned(),
        required,
        max_calls: 10,
        max_request_bytes: 1_024,
        max_response_bytes: 2_048,
    }
}

fn features(ids: &[&str]) -> Vec<String> {
    ids.iter().map(|id| (*id).to_owned()).collect()
}

/// Requirements accepted by the V1 host: ABI 0.0-0.1, one optional capability.
fn fixture() -> PluginExecutionProjectionFixtureV1 {
    PluginExecutionProjectionFixtureV1 {
        pmf1_digest: [0x11; 32],
        release_digest: [0x22; 32],
        plugin_id: "plugin-a".to_owned(),
        abi: PluginAbiRequirementV1 {
            major: 0,
            min_minor: 0,
            max_minor: 1,
            required_features: Vec::new(),
        },
        capabilities: vec![capability("read", false)],
        budget: SMALL_BUDGET,
    }
}

const fn local() -> CommunityPluginExecutionProfileV1 {
    CommunityPluginExecutionProfileV1::new(
        CommunityPluginModeV1::Local,
        CommunityPluginCeilingsV1::V1,
        None,
    )
}

fn negotiate(
    requirements: PluginExecutionProjectionFixtureV1,
    host: &CommunityPluginHostAbiV1,
) -> Negotiation {
    let execution = PluginExecutionProjectionV1::from(requirements);
    negotiate_community_plugin_v1(&execution, host, &local())
}

/// Negotiate ABI `major.min_minor..=major.max_minor` against host minors 2-5.
fn minor(
    major: u16,
    min_minor: u16,
    max_minor: u16,
) -> Result<Result<u16, Error>, CommunityPluginHostAbiErrorV1> {
    let host = CommunityPluginHostAbiV1::new(2, 5, Vec::new())?;
    let mut requirements = fixture();
    requirements.abi.major = major;
    requirements.abi.min_minor = min_minor;
    requirements.abi.max_minor = max_minor;
    Ok(negotiate(requirements, &host).map(|negotiated| negotiated.abi().1))
}

fn entry(trap_code: &str, outcome: TrapOutcomeV1) -> TrapTableEntryV1 {
    TrapTableEntryV1 {
        trap_code: trap_code.to_owned(),
        outcome,
    }
}

const ENGINE: PinnedEngineConfigV1 = PinnedEngineConfigV1 {
    max_wasm_stack: 524_288,
    consume_fuel: true,
    epoch_interruption: true,
};

fn pinned(trap_table: Vec<TrapTableEntryV1>) -> Result<PinnedComponentRuntimeV1, ProfileError> {
    let resolved = features(&["component-model", "cranelift"]);
    PinnedComponentRuntimeV1::new("0.0.0-test".to_owned(), resolved, ENGINE, trap_table)
}

fn runtime() -> Result<PinnedComponentRuntimeV1, ProfileError> {
    pinned(vec![
        entry("Interrupt", TrapOutcomeV1::WatchdogStop),
        entry("OutOfFuel", TrapOutcomeV1::FuelExhausted),
        entry(
            "UnreachableCodeReached",
            TrapOutcomeV1::Trap(ComponentTrapClassV1::Unreachable),
        ),
    ])
}

const fn ceiling_values(memory_bytes: u64, fuel: u64, host_calls: u64) -> CeilingValuesV1 {
    CeilingValuesV1 {
        memory_bytes,
        fuel,
        host_calls,
        event_bytes: 0,
        log_bytes: 0,
    }
}

#[test]
fn every_closed_error_has_its_adr_name_class_and_v1_production() {
    let mut messages = Vec::new();
    for (error, name, class, produced) in ERRORS {
        assert_eq!(error.name(), name);
        assert_eq!(error.class(), class, "{name}");
        assert_eq!(error.produced_in_v1(), produced, "{name}");
        messages.push(error.to_string());
    }
    let distinct = messages.iter().collect::<std::collections::BTreeSet<_>>();
    // 22 rows name 20 errors: the two ComponentTrap and the two
    // AtomicCommitFailed rows share one message each.
    assert_eq!(distinct.len(), 20);
    assert_eq!(
        Error::ComponentTrap {
            class: TRAP,
            reproduction: UNVERIFIED
        }
        .to_string(),
        "community Plugin Component trapped: stack-exhausted"
    );
    assert_eq!(
        Error::MissingFeature { index: 2 }.to_string(),
        "community Plugin requires unsupported feature 2"
    );
}

/// Every error name once, with every basis value for the two payload errors.
fn every_error_with_every_basis() -> Vec<Error> {
    let mut errors = vec![
        Error::InvalidManifest,
        Error::IncompatibleAbi,
        Error::MissingFeature { index: 0 },
        Error::CapabilityDenied { index: 0 },
        Error::InvalidInvocation,
        Error::InvalidGuestOutput,
        Error::UnsupportedSchema,
        Error::StateMigrationFailed,
        Error::GuestDeclaredFailure,
        Error::WorkerCrashed,
        Error::FuelExhausted,
        Error::MemoryLimitExceeded,
        Error::HostCallLimitExceeded,
        Error::OutputLimitExceeded,
        Error::DeterministicDeadlineExceeded,
        Error::OperationalWatchdogStop,
    ];
    errors.extend(TRUST_BASES.map(|(basis, _)| Error::ArtifactTrustDenied { basis }));
    errors.extend(REVOCATION_BASES.map(|(basis, _)| Error::ArtifactRevoked { basis }));
    for reproduction in [REPRODUCED, UNVERIFIED] {
        let class = TRAP;
        errors.push(Error::ComponentTrap {
            class,
            reproduction,
        });
    }
    for failure in [TYPED, UNTYPED] {
        errors.push(Error::AtomicCommitFailed { failure });
    }
    errors
}

const fn assert_copy<T: Copy>() {}

/// R7-F1: the class over all 20 names with every basis value.
#[test]
fn pre_execution_rejection_is_exactly_the_seven_names() {
    let rejections = [
        "InvalidManifest",
        "ArtifactTrustDenied",
        "ArtifactRevoked",
        "IncompatibleAbi",
        "MissingFeature",
        "CapabilityDenied",
        "InvalidInvocation",
    ];
    for error in every_error_with_every_basis() {
        let expected = rejections.contains(&error.name());
        assert_eq!(error.class() == REJECTION, expected, "{error:?}");
    }
    assert_eq!(Error::UnsupportedSchema.class(), AUTHORITATIVE);
    for (basis, _) in TRUST_BASES {
        let denied = Error::ArtifactTrustDenied { basis };
        assert_eq!(denied.class(), REJECTION, "{basis:?}");
    }
    for (basis, _) in REVOCATION_BASES {
        let revoked = Error::ArtifactRevoked { basis };
        assert_eq!(revoked.class(), REJECTION, "{basis:?}");
    }
}

/// R7-F2: names are unchanged by a basis, and bases have exact names.
#[test]
fn basis_names_are_exact_and_the_error_name_ignores_the_basis() {
    assert_copy::<Error>();
    for (basis, name) in TRUST_BASES {
        assert_eq!(basis.name(), name);
        let denied = Error::ArtifactTrustDenied { basis };
        assert_eq!(denied.name(), "ArtifactTrustDenied");
        assert_eq!(denied.basis_name(), Some(name));
    }
    for (basis, name) in REVOCATION_BASES {
        assert_eq!(basis.name(), name);
        let revoked = Error::ArtifactRevoked { basis };
        assert_eq!(revoked.name(), "ArtifactRevoked");
        assert_eq!(revoked.basis_name(), Some(name));
    }
    let every = every_error_with_every_basis();
    let names = every.iter().copied().map(Error::name);
    let distinct = names.collect::<std::collections::BTreeSet<_>>();
    assert_eq!(distinct.len(), 20);
    for error in every {
        let has_basis = matches!(
            error,
            Error::ArtifactTrustDenied { .. } | Error::ArtifactRevoked { .. }
        );
        assert_eq!(error.basis_name().is_some(), has_basis, "{error:?}");
    }
}

/// R7-F3: the quarantine mapping and the pass-failure classification.
#[test]
fn quarantine_for_keeps_the_accepted_mappings_and_revocation_quarantines() {
    use PluginAvailabilityV1 as Availability;
    for error in every_error_with_every_basis() {
        let expected = match error {
            Error::ArtifactRevoked { .. } => Some(Availability::Revoked),
            Error::ComponentTrap { .. } => Some(Availability::Trapped),
            Error::FuelExhausted
            | Error::MemoryLimitExceeded
            | Error::HostCallLimitExceeded
            | Error::OutputLimitExceeded => Some(Availability::ResourceExhausted),
            Error::WorkerCrashed => Some(Availability::Unavailable),
            _ => None,
        };
        assert_eq!(quarantine_for(error), expected, "{error:?}");
    }
}

#[test]
fn a_failed_pass_is_classified_by_its_commit_contract() {
    let host = PassFailureV1::Host;
    let typed = Error::AtomicCommitFailed { failure: TYPED };
    let untyped = Error::AtomicCommitFailed { failure: UNTYPED };
    let rejected = Box::new(PipelineOutcomeV1::Rejected);
    let not_admitted = RuntimeError::ScheduledPassNotAdmitted(rejected);
    let unknown = RuntimeError::Store(CoreError::StorageOutcomeUnknown("lost".to_owned()));
    let frozen = RuntimeError::Store(CoreError::ErasureAccessFrozen);
    let crashed = RuntimeError::from(Error::WorkerCrashed);
    assert_eq!(classify_pass_failure(&not_admitted), host(typed));
    assert_eq!(classify_pass_failure(&unknown), PassFailureV1::InDoubt);
    assert_eq!(classify_pass_failure(&frozen), host(untyped));
    assert_eq!(classify_pass_failure(&crashed), host(Error::WorkerCrashed));
    for unrelated in [
        RuntimeError::PendingDriverStep,
        RuntimeError::NoScheduledAdmissionInDoubt,
    ] {
        assert_eq!(classify_pass_failure(&unrelated), PassFailureV1::Unrelated);
    }
}

/// R7-F6: the three class names.
#[test]
fn failure_classes_have_their_exact_names() {
    assert_eq!(AUTHORITATIVE.name(), "Authoritative");
    assert_eq!(OPERATIONAL.name(), "Operational");
    assert_eq!(REJECTION.name(), "PreExecutionRejection");
}

#[test]
fn trap_classes_are_the_closed_adr_set_and_outcomes_map_to_host_errors() {
    let names = TRAP_CLASSES.map(ComponentTrapClassV1::name);
    assert_eq!(
        names,
        [
            "unreachable",
            "memory-out-of-bounds",
            "table-out-of-bounds",
            "indirect-call",
            "integer-arithmetic",
            "stack-exhausted",
            "other",
        ]
    );
    for class in TRAP_CLASSES {
        let error = TrapOutcomeV1::Trap(class).error();
        assert_eq!(
            error,
            Error::ComponentTrap {
                class,
                reproduction: UNVERIFIED
            }
        );
        assert_eq!(error.class(), OPERATIONAL);
    }
    assert_eq!(TrapOutcomeV1::FuelExhausted.error(), Error::FuelExhausted);
    assert_eq!(
        TrapOutcomeV1::WatchdogStop.error(),
        Error::OperationalWatchdogStop
    );
}

#[test]
fn only_local_and_air_gapped_modes_have_a_live_profile() {
    let modes = [
        PluginExecutionModeV1::Local,
        PluginExecutionModeV1::AirGapped,
        PluginExecutionModeV1::Replay,
    ]
    .map(CommunityPluginModeV1::from_execution_mode);
    let live = [
        Some(CommunityPluginModeV1::Local),
        Some(CommunityPluginModeV1::AirGapped),
    ];
    assert_eq!(modes, [live[0], live[1], None]);
}

#[test]
fn v1_ceilings_lower_memory_and_fuel_only() -> TestResult {
    let ceilings = CommunityPluginCeilingsV1::V1.values();
    assert_eq!(ceilings.memory_bytes, 67_108_864);
    assert!(ceilings.memory_bytes.is_multiple_of(WASM_PAGE_BYTES_V1));
    assert_eq!(ceilings.fuel, 1_000_000_000);
    assert_eq!(ceilings.host_calls, 1_000_000);
    assert_eq!(ceilings.event_bytes, 16_777_216);
    assert_eq!(ceilings.log_bytes, 16_384);
    assert_eq!(
        CommunityPluginCeilingsV1::new(ceilings)?,
        CommunityPluginCeilingsV1::V1
    );
    Ok(())
}

#[test]
fn operator_ceilings_stay_within_the_pmf1_member_ranges() -> TestResult {
    let smallest = ceiling_values(WASM_PAGE_BYTES_V1, 1, 0);
    assert_eq!(CommunityPluginCeilingsV1::new(smallest)?.values(), smallest);
    let largest = CeilingValuesV1 {
        memory_bytes: 1 << 32,
        fuel: u64::MAX,
        host_calls: 1_000_000,
        event_bytes: 1 << 24,
        log_bytes: 16_384,
    };
    assert_eq!(CommunityPluginCeilingsV1::new(largest)?.values(), largest);
    let rejected = [
        (ceiling_values(0, 1, 0), ExecutionLimitV1::MemoryBytes),
        (ceiling_values(65_535, 1, 0), ExecutionLimitV1::MemoryBytes),
        (ceiling_values(65_537, 1, 0), ExecutionLimitV1::MemoryBytes),
        (
            ceiling_values((1 << 32) + 65_536, 1, 0),
            ExecutionLimitV1::MemoryBytes,
        ),
        (ceiling_values(0, 0, 0), ExecutionLimitV1::MemoryBytes),
        (ceiling_values(65_536, 0, 0), ExecutionLimitV1::Fuel),
        (ceiling_values(65_536, 0, 1_000_001), ExecutionLimitV1::Fuel),
        (
            ceiling_values(65_536, 1, 1_000_001),
            ExecutionLimitV1::HostCalls,
        ),
        (
            CeilingValuesV1 {
                event_bytes: (1 << 24) + 1,
                ..smallest
            },
            ExecutionLimitV1::EventBytes,
        ),
        (
            CeilingValuesV1 {
                log_bytes: 16_385,
                ..smallest
            },
            ExecutionLimitV1::LogBytes,
        ),
        (
            CeilingValuesV1 {
                event_bytes: (1 << 24) + 1,
                log_bytes: 16_385,
                ..smallest
            },
            ExecutionLimitV1::EventBytes,
        ),
    ];
    for (input, limit) in rejected {
        let expected = Err(ProfileError::CeilingOutOfRange { limit });
        assert_eq!(CommunityPluginCeilingsV1::new(input), expected);
    }
    let names = [
        ExecutionLimitV1::MemoryBytes,
        ExecutionLimitV1::Fuel,
        ExecutionLimitV1::HostCalls,
        ExecutionLimitV1::EventBytes,
        ExecutionLimitV1::LogBytes,
    ]
    .map(ExecutionLimitV1::name);
    assert_eq!(
        names,
        [
            "memory_bytes",
            "fuel",
            "host_calls",
            "event_bytes",
            "log_bytes"
        ]
    );
    let message = ProfileError::CeilingOutOfRange {
        limit: ExecutionLimitV1::Fuel,
    }
    .to_string();
    assert_eq!(
        message,
        "community Plugin profile ceiling fuel is out of range"
    );
    Ok(())
}

#[test]
fn pinned_runtime_records_a_validated_trap_table() -> TestResult {
    let recorded = runtime()?;
    assert_eq!(recorded.wasmtime_version(), "0.0.0-test");
    assert_eq!(
        recorded.resolved_features(),
        features(&["component-model", "cranelift"])
    );
    assert_eq!(recorded.engine(), ENGINE);
    assert_eq!(recorded.trap_table().len(), 3);
    assert_eq!(
        recorded.trap_table()[1],
        entry("OutOfFuel", TrapOutcomeV1::FuelExhausted)
    );
    assert!(pinned(Vec::new())?.trap_table().is_empty());
    let class = TrapOutcomeV1::Trap(ComponentTrapClassV1::Other);
    let misclassified = [
        entry("OutOfFuel", class),
        entry("OutOfFuel", TrapOutcomeV1::WatchdogStop),
        entry("Interrupt", TrapOutcomeV1::FuelExhausted),
        entry("Interrupt", class),
        entry("StackOverflow", TrapOutcomeV1::FuelExhausted),
        entry("StackOverflow", TrapOutcomeV1::WatchdogStop),
    ];
    for wrong in misclassified {
        let table = vec![entry("NullReference", class), wrong];
        assert_eq!(
            pinned(table),
            Err(ProfileError::MisclassifiedTrapCode { index: 1 })
        );
    }
    let repeated = vec![
        entry("Interrupt", TrapOutcomeV1::FuelExhausted),
        entry("NullReference", class),
        entry("NullReference", class),
    ];
    assert_eq!(
        pinned(repeated),
        Err(ProfileError::DuplicateTrapCode { index: 2 })
    );
    let messages = [
        ProfileError::DuplicateTrapCode { index: 2 }.to_string(),
        ProfileError::MisclassifiedTrapCode { index: 1 }.to_string(),
    ];
    assert_eq!(
        messages,
        [
            "community Plugin trap table repeats code 2",
            "community Plugin trap table misclassifies code 1",
        ]
    );
    Ok(())
}

/// Every code ADR-061 revision 4 decision 6 names, with its class.
const ADR_TRAP_TABLE: [(&str, ComponentTrapClassV1); 18] = [
    ("UnreachableCodeReached", ComponentTrapClassV1::Unreachable),
    ("MemoryOutOfBounds", ComponentTrapClassV1::MemoryOutOfBounds),
    ("HeapMisaligned", ComponentTrapClassV1::MemoryOutOfBounds),
    ("ArrayOutOfBounds", ComponentTrapClassV1::MemoryOutOfBounds),
    ("TableOutOfBounds", ComponentTrapClassV1::TableOutOfBounds),
    ("IndirectCallToNull", ComponentTrapClassV1::IndirectCall),
    ("BadSignature", ComponentTrapClassV1::IndirectCall),
    ("IntegerOverflow", ComponentTrapClassV1::IntegerArithmetic),
    (
        "IntegerDivisionByZero",
        ComponentTrapClassV1::IntegerArithmetic,
    ),
    (
        "BadConversionToInteger",
        ComponentTrapClassV1::IntegerArithmetic,
    ),
    ("StackOverflow", ComponentTrapClassV1::StackExhausted),
    ("NullReference", ComponentTrapClassV1::Other),
    ("CastFailure", ComponentTrapClassV1::Other),
    ("AllocationTooLarge", ComponentTrapClassV1::Other),
    ("AlwaysTrapAdapter", ComponentTrapClassV1::Other),
    ("CannotEnterComponent", ComponentTrapClassV1::Other),
    ("CodeAddedByALaterVersion", ComponentTrapClassV1::Other),
    ("Unlisted", ComponentTrapClassV1::Other),
];

#[test]
fn every_trap_code_maps_to_exactly_its_adr_class() -> TestResult {
    let mut table = vec![
        entry("Interrupt", TrapOutcomeV1::WatchdogStop),
        entry("OutOfFuel", TrapOutcomeV1::FuelExhausted),
    ];
    table.extend(
        ADR_TRAP_TABLE
            .iter()
            .map(|&(code, class)| entry(code, TrapOutcomeV1::Trap(class))),
    );
    assert_eq!(pinned(table)?.trap_table().len(), 20);
    for (code, class) in ADR_TRAP_TABLE {
        for wrong in TRAP_CLASSES.into_iter().filter(|other| *other != class) {
            let table = vec![entry(code, TrapOutcomeV1::Trap(wrong))];
            let expected = Err(ProfileError::MisclassifiedTrapCode { index: 0 });
            assert_eq!(pinned(table), expected, "{code} as {}", wrong.name());
        }
    }
    Ok(())
}

#[test]
fn parity_profiles_carry_identical_ceilings_and_runtime() -> TestResult {
    let input = CeilingValuesV1 {
        memory_bytes: 4 * WASM_PAGE_BYTES_V1,
        fuel: 77,
        host_calls: 6,
        event_bytes: 5,
        log_bytes: 4,
    };
    let ceilings = CommunityPluginCeilingsV1::new(input)?;
    let recorded = runtime()?;
    let [local, air_gapped] =
        CommunityPluginExecutionProfileV1::parity_pair(ceilings, Some(&recorded));
    assert_eq!(local.mode(), CommunityPluginModeV1::Local);
    assert_eq!(air_gapped.mode(), CommunityPluginModeV1::AirGapped);
    assert_eq!(local.ceilings(), ceilings);
    assert_eq!(air_gapped.ceilings(), ceilings);
    assert_eq!(local.runtime(), Some(&recorded));
    assert_eq!(air_gapped.runtime(), Some(&recorded));
    let [bare_local, bare_air_gapped] =
        CommunityPluginExecutionProfileV1::parity_pair(ceilings, None);
    assert_eq!(bare_local.runtime(), None);
    assert_eq!(bare_air_gapped.runtime(), None);
    assert_eq!(bare_air_gapped.mode(), CommunityPluginModeV1::AirGapped);
    Ok(())
}

#[test]
fn host_abi_declarations_are_ordered_valid_ids() -> TestResult {
    let host = CommunityPluginHostAbiV1::new(4, 4, features(&["a", "b.c", "log"]))?;
    assert_eq!((host.min_minor(), host.max_minor()), (4, 4));
    assert_eq!(host.features(), features(&["a", "b.c", "log"]));
    let v1 = CommunityPluginHostAbiV1::v1();
    assert_eq!((v1.min_minor(), v1.max_minor()), (0, 0));
    assert!(v1.features().is_empty());
    let rejected = [
        (
            3,
            2,
            features(&["Bad"]),
            CommunityPluginHostAbiErrorV1::EmptyMinorRange,
        ),
        (
            0,
            0,
            features(&["a", "Bad"]),
            CommunityPluginHostAbiErrorV1::InvalidFeature { index: 1 },
        ),
        (
            0,
            0,
            features(&[""]),
            CommunityPluginHostAbiErrorV1::InvalidFeature { index: 0 },
        ),
        (
            0,
            0,
            features(&["a", "c", "b", "B"]),
            CommunityPluginHostAbiErrorV1::InvalidFeature { index: 3 },
        ),
        (
            0,
            0,
            features(&["a", "c", "b"]),
            CommunityPluginHostAbiErrorV1::UnorderedFeature { index: 2 },
        ),
        (
            0,
            0,
            features(&["a", "a"]),
            CommunityPluginHostAbiErrorV1::UnorderedFeature { index: 1 },
        ),
    ];
    for (min_minor, max_minor, ids, error) in rejected {
        assert_eq!(
            CommunityPluginHostAbiV1::new(min_minor, max_minor, ids),
            Err(error)
        );
    }
    let messages = [
        CommunityPluginHostAbiErrorV1::EmptyMinorRange.to_string(),
        CommunityPluginHostAbiErrorV1::InvalidFeature { index: 1 }.to_string(),
        CommunityPluginHostAbiErrorV1::UnorderedFeature { index: 2 }.to_string(),
    ];
    assert_eq!(
        messages,
        [
            "community Plugin host ABI minor range is empty",
            "community Plugin host feature 1 is not a valid ID",
            "community Plugin host feature 2 is out of order",
        ]
    );
    Ok(())
}

#[test]
fn negotiation_records_the_release_abi_and_not_granted_capabilities() -> TestResult {
    let mut requirements = fixture();
    requirements.capabilities = vec![capability("read", false), capability("write", false)];
    let expected_capabilities = requirements.capabilities.clone();
    let profile = CommunityPluginExecutionProfileV1::new(
        CommunityPluginModeV1::Local,
        CommunityPluginCeilingsV1::V1,
        Some(runtime()?),
    );
    let execution = PluginExecutionProjectionV1::from(requirements);
    let host = CommunityPluginHostAbiV1::v1();
    let negotiated = negotiate_community_plugin_v1(&execution, &host, &profile)?;
    assert_eq!(negotiated.world(), COMMUNITY_PLUGIN_WORLD_V1);
    assert_eq!(negotiated.plugin_id(), "plugin-a");
    assert_eq!(negotiated.pmf1_digest(), [0x11; 32]);
    assert_eq!(negotiated.release_digest(), [0x22; 32]);
    assert_eq!(negotiated.abi(), (COMMUNITY_PLUGIN_ABI_MAJOR_V1, 0));
    assert_eq!(negotiated.declared_minor_range(), (0, 1));
    assert!(negotiated.required_features().is_empty());
    assert_eq!(
        negotiated.not_granted_capabilities(),
        expected_capabilities.as_slice()
    );
    assert_eq!(negotiated.mode(), CommunityPluginModeV1::Local);
    assert_eq!(negotiated.runtime(), Some(&runtime()?));
    assert_eq!(negotiated.limits().values(), SMALL_BUDGET);
    let mut bare = fixture();
    bare.capabilities.clear();
    let negotiated = negotiate(bare, &host)?;
    assert!(negotiated.not_granted_capabilities().is_empty());
    assert_eq!(negotiated.runtime(), None);
    Ok(())
}

#[test]
fn abi_negotiation_picks_the_highest_common_minor_of_major_zero() -> TestResult {
    assert_eq!(minor(0, 0, 9)?, Ok(5));
    assert_eq!(minor(0, 3, 4)?, Ok(4));
    assert_eq!(minor(0, 0, 2)?, Ok(2));
    assert_eq!(minor(0, 5, 9)?, Ok(5));
    assert_eq!(minor(0, 6, 9)?, Err(Error::IncompatibleAbi));
    assert_eq!(minor(0, 0, 1)?, Err(Error::IncompatibleAbi));
    assert_eq!(minor(1, 0, 9)?, Err(Error::IncompatibleAbi));
    let mut above = fixture();
    above.abi.min_minor = 1;
    assert_eq!(
        negotiate(above, &CommunityPluginHostAbiV1::v1()),
        Err(Error::IncompatibleAbi)
    );
    Ok(())
}

#[test]
fn every_required_feature_must_be_provided_by_the_host() -> TestResult {
    let host = CommunityPluginHostAbiV1::new(0, 0, features(&["a", "c"]))?;
    let mut provided = fixture();
    provided.abi.required_features = features(&["a", "c"]);
    let negotiated = negotiate(provided, &host)?;
    assert_eq!(negotiated.required_features(), features(&["a", "c"]));
    let mut missing = fixture();
    missing.abi.required_features = features(&["a", "b", "c", "d"]);
    assert_eq!(
        negotiate(missing, &host),
        Err(Error::MissingFeature { index: 1 })
    );
    let mut none = fixture();
    none.abi.required_features = features(&["a"]);
    assert_eq!(
        negotiate(none, &CommunityPluginHostAbiV1::v1()),
        Err(Error::MissingFeature { index: 0 })
    );
    Ok(())
}

#[test]
fn a_required_capability_is_denied_and_no_capability_is_ever_granted() {
    let host = CommunityPluginHostAbiV1::v1();
    let mut required = fixture();
    required.capabilities = vec![
        capability("list", false),
        capability("read", true),
        capability("write", true),
    ];
    assert_eq!(
        negotiate(required, &host),
        Err(Error::CapabilityDenied { index: 1 })
    );
    let mut first = fixture();
    first.capabilities = vec![capability("read", true)];
    let denied = negotiate(first, &host);
    assert_eq!(denied, Err(Error::CapabilityDenied { index: 0 }));
    assert_eq!(denied.err().map(Error::class), Some(REJECTION));
}

#[test]
fn negotiation_fails_at_the_first_phase_in_validation_order() {
    let host = CommunityPluginHostAbiV1::v1();
    let mut everything = fixture();
    everything.abi.major = 1;
    everything.abi.required_features = features(&["missing"]);
    everything.capabilities = vec![capability("read", true)];
    assert_eq!(
        negotiate(everything.clone(), &host),
        Err(Error::IncompatibleAbi)
    );
    everything.abi.major = 0;
    let missing = negotiate(everything.clone(), &host);
    assert_eq!(missing, Err(Error::MissingFeature { index: 0 }));
    everything.abi.required_features.clear();
    assert_eq!(
        negotiate(everything, &host),
        Err(Error::CapabilityDenied { index: 0 })
    );
}

#[test]
fn budgets_above_a_ceiling_are_clamped_not_rejected() -> TestResult {
    let input = CeilingValuesV1 {
        memory_bytes: 3 * WASM_PAGE_BYTES_V1,
        fuel: 1_000,
        host_calls: 30,
        event_bytes: 800,
        log_bytes: 500,
    };
    let ceilings = CommunityPluginCeilingsV1::new(input)?;
    let above = DeterministicBudgetV1 {
        memory_bytes: 1 << 32,
        fuel: u64::MAX,
        host_calls: 1_000_000,
        event_count: 2_000,
        event_bytes: 1 << 24,
        state_bytes: 1 << 21,
        log_calls: 100,
        log_bytes: 16_384,
    };
    let expected = DeterministicBudgetV1 {
        memory_bytes: 3 * WASM_PAGE_BYTES_V1,
        fuel: 1_000,
        host_calls: 30,
        event_count: MAXIMA.event_count,
        event_bytes: 800,
        state_bytes: MAXIMA.state_bytes,
        log_calls: MAXIMA.log_calls,
        log_bytes: 500,
    };
    assert_eq!(
        EffectiveExecutionLimitsV1::clamp(above, ceilings).values(),
        expected
    );
    let below = EffectiveExecutionLimitsV1::clamp(SMALL_BUDGET, CommunityPluginCeilingsV1::V1);
    assert_eq!(below.values(), SMALL_BUDGET);
    let mut requirements = fixture();
    requirements.budget = above;
    let execution = PluginExecutionProjectionV1::from(requirements);
    let profile =
        CommunityPluginExecutionProfileV1::new(CommunityPluginModeV1::AirGapped, ceilings, None);
    let host = CommunityPluginHostAbiV1::v1();
    let negotiated = negotiate_community_plugin_v1(&execution, &host, &profile)?;
    assert_eq!(negotiated.limits().values(), expected);
    assert_eq!(negotiated.mode(), CommunityPluginModeV1::AirGapped);
    Ok(())
}

#[test]
fn parity_profiles_negotiate_identical_limits_in_both_modes() -> TestResult {
    let ceilings = CommunityPluginCeilingsV1::new(ceiling_values(WASM_PAGE_BYTES_V1, 2_000, 20))?;
    let execution = PluginExecutionProjectionV1::from(fixture());
    let host = CommunityPluginHostAbiV1::v1();
    let recorded = runtime()?;
    let [local, air_gapped] =
        CommunityPluginExecutionProfileV1::parity_pair(ceilings, Some(&recorded));
    let in_local = negotiate_community_plugin_v1(&execution, &host, &local)?;
    let in_air_gapped = negotiate_community_plugin_v1(&execution, &host, &air_gapped)?;
    assert_eq!(in_local.limits(), in_air_gapped.limits());
    assert_eq!(in_local.runtime(), in_air_gapped.runtime());
    assert_ne!(in_local.mode(), in_air_gapped.mode());
    assert_eq!(in_local.limits().values().memory_bytes, WASM_PAGE_BYTES_V1);
    Ok(())
}

/// R7-D1: the digest of the golden profile, computed offline with `b3sum`.
const R7_D1_DIGEST: [u8; 32] = [
    0x9d, 0xf8, 0x1c, 0xeb, 0x0d, 0x02, 0x96, 0x65, 0xc3, 0x31, 0x7e, 0x72, 0x73, 0x63, 0x85, 0xb2,
    0x1a, 0xf9, 0x51, 0x20, 0x0b, 0xab, 0xd3, 0x0c, 0xbb, 0xfc, 0x7d, 0x0a, 0x8d, 0x11, 0xe1, 0x00,
];

fn golden_runtime(
    version: &str,
    resolved: &[&str],
    engine: PinnedEngineConfigV1,
    rows: Vec<TrapTableEntryV1>,
) -> Result<PinnedComponentRuntimeV1, ProfileError> {
    PinnedComponentRuntimeV1::new(version.to_owned(), features(resolved), engine, rows)
}

fn golden_rows() -> Vec<TrapTableEntryV1> {
    vec![
        entry("OutOfFuel", TrapOutcomeV1::FuelExhausted),
        entry("Interrupt", TrapOutcomeV1::WatchdogStop),
        entry(
            "UnreachableCodeReached",
            TrapOutcomeV1::Trap(ComponentTrapClassV1::Unreachable),
        ),
    ]
}

fn digest_of(
    mode: CommunityPluginModeV1,
    ceilings: CommunityPluginCeilingsV1,
    runtime: PinnedComponentRuntimeV1,
) -> Option<[u8; 32]> {
    CommunityPluginExecutionProfileV1::new(mode, ceilings, Some(runtime)).digest()
}

/// R7-P1: the golden digest, mode exclusion, member sensitivity, order
/// independence and the absent digest of a profile without a runtime.
#[test]
fn the_profile_digest_matches_its_golden_vector_and_ignores_the_mode() -> TestResult {
    let sorted = ["component-model", "cranelift", "runtime"];
    let golden = golden_runtime("fixture-1", &sorted, ENGINE, golden_rows())?;
    let ceilings = CommunityPluginCeilingsV1::V1;
    let local = digest_of(CommunityPluginModeV1::Local, ceilings, golden.clone());
    assert_eq!(local, Some(R7_D1_DIGEST));
    let air_gapped = digest_of(CommunityPluginModeV1::AirGapped, ceilings, golden);
    assert_eq!(air_gapped, local);
    let mut rows = golden_rows();
    rows.reverse();
    let recorded = ["runtime", "component-model", "cranelift"];
    let reordered = golden_runtime("fixture-1", &recorded, ENGINE, rows)?;
    let mode = CommunityPluginModeV1::Local;
    assert_eq!(digest_of(mode, ceilings, reordered), local);
    Ok(())
}

#[test]
fn every_single_profile_member_changes_the_digest() -> TestResult {
    let sorted = ["component-model", "cranelift", "runtime"];
    let mode = CommunityPluginModeV1::Local;
    let values = CommunityPluginCeilingsV1::V1.values();
    let lowered = |change: fn(&mut CeilingValuesV1)| {
        let mut values = values;
        change(&mut values);
        CommunityPluginCeilingsV1::new(values)
    };
    let ceilings = [
        lowered(|v| v.memory_bytes -= WASM_PAGE_BYTES_V1)?,
        lowered(|v| v.fuel -= 1)?,
        lowered(|v| v.host_calls -= 1)?,
        lowered(|v| v.event_bytes -= 1)?,
        lowered(|v| v.log_bytes -= 1)?,
    ];
    let mut seen = std::collections::BTreeSet::from([R7_D1_DIGEST]);
    for changed in ceilings {
        let digest = digest_of(mode, changed, golden_runtime_of(&sorted)?);
        assert!(digest.is_some_and(|digest| seen.insert(digest)));
    }
    let stack = PinnedEngineConfigV1 {
        max_wasm_stack: ENGINE.max_wasm_stack + 1,
        ..ENGINE
    };
    let no_fuel = PinnedEngineConfigV1 {
        consume_fuel: false,
        ..ENGINE
    };
    let no_epoch = PinnedEngineConfigV1 {
        epoch_interruption: false,
        ..ENGINE
    };
    let mut other_row = golden_rows();
    other_row[2] = entry(
        "StackOverflow",
        TrapOutcomeV1::Trap(ComponentTrapClassV1::StackExhausted),
    );
    let mut fewer_rows = golden_rows();
    fewer_rows.pop();
    let mut more_rows = golden_rows();
    more_rows.push(entry(
        "NullReference",
        TrapOutcomeV1::Trap(ComponentTrapClassV1::Other),
    ));
    // The outcome is a function of the code, so a row differing from another
    // only in its code (same outcome) is the closest pair a valid runtime has.
    let mut other_code_row = golden_rows();
    other_code_row.push(entry(
        "NullPointer",
        TrapOutcomeV1::Trap(ComponentTrapClassV1::Other),
    ));
    let extra = ["cranelift", "runtime", "z"];
    let runtimes = [
        golden_runtime("fixture-2", &sorted, ENGINE, golden_rows())?,
        golden_runtime("fixture-1", &sorted[1..], ENGINE, golden_rows())?,
        golden_runtime("fixture-1", &extra, ENGINE, golden_rows())?,
        golden_runtime("fixture-1", &sorted, stack, golden_rows())?,
        golden_runtime("fixture-1", &sorted, no_fuel, golden_rows())?,
        golden_runtime("fixture-1", &sorted, no_epoch, golden_rows())?,
        golden_runtime("fixture-1", &sorted, ENGINE, other_row)?,
        golden_runtime("fixture-1", &sorted, ENGINE, fewer_rows)?,
        golden_runtime("fixture-1", &sorted, ENGINE, more_rows)?,
        golden_runtime("fixture-1", &sorted, ENGINE, other_code_row)?,
    ];
    for runtime in runtimes {
        let digest = digest_of(mode, CommunityPluginCeilingsV1::V1, runtime);
        assert!(digest.is_some_and(|digest| seen.insert(digest)));
    }
    Ok(())
}

fn golden_runtime_of(resolved: &[&str]) -> Result<PinnedComponentRuntimeV1, ProfileError> {
    golden_runtime("fixture-1", resolved, ENGINE, golden_rows())
}

#[test]
fn a_profile_without_a_runtime_has_no_digest_and_neither_has_its_record() -> TestResult {
    let bare = CommunityPluginExecutionProfileV1::new(
        CommunityPluginModeV1::Local,
        CommunityPluginCeilingsV1::V1,
        None,
    );
    assert_eq!(bare.digest(), None);
    let execution = PluginExecutionProjectionV1::from(fixture());
    let host = CommunityPluginHostAbiV1::v1();
    let negotiated = negotiate_community_plugin_v1(&execution, &host, &bare)?;
    assert_eq!(negotiated.execution_profile_digest(), None);
    let recorded = runtime()?;
    let full = CommunityPluginExecutionProfileV1::new(
        CommunityPluginModeV1::AirGapped,
        CommunityPluginCeilingsV1::V1,
        Some(recorded),
    );
    let negotiated = negotiate_community_plugin_v1(&execution, &host, &full)?;
    assert_eq!(negotiated.execution_profile_digest(), full.digest());
    assert!(full.digest().is_some());
    Ok(())
}

fn feature_runtime(
    resolved: &[&str],
    rows: Vec<TrapTableEntryV1>,
) -> Result<PinnedComponentRuntimeV1, ProfileError> {
    golden_runtime("fixture-1", resolved, ENGINE, rows)
}

/// R7-P7: a repeated feature text is rejected at the first repeat.
#[test]
fn a_duplicate_feature_is_rejected_at_the_first_repeat() {
    assert_eq!(
        feature_runtime(&["a", "b", "a", "b"], golden_rows()),
        Err(ProfileError::DuplicateFeature { index: 2 })
    );
    assert_eq!(
        feature_runtime(&["a", "a"], golden_rows()),
        Err(ProfileError::DuplicateFeature { index: 1 })
    );
    assert!(feature_runtime(&["a", "b"], golden_rows()).is_ok());
    assert!(feature_runtime(&[], golden_rows()).is_ok());
    // The feature rule is checked before the trap table rules.
    let other = TrapOutcomeV1::Trap(ComponentTrapClassV1::Other);
    let repeated_rows = vec![entry("NullReference", other), entry("NullReference", other)];
    assert_eq!(
        feature_runtime(&["a", "a"], repeated_rows),
        Err(ProfileError::DuplicateFeature { index: 1 })
    );
    assert_eq!(
        ProfileError::DuplicateFeature { index: 2 }.to_string(),
        "community Plugin runtime repeats feature 2"
    );
}
