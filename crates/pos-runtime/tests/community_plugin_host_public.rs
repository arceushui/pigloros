//! ADR-061 revision 4 community Plugin host contract at its public seams.
//!
//! Execution projections come from the `pos-crypto` `test-support` fixture,
//! which models caller-fabricated PMF1 requirements, so every negotiation
//! rejection path is reachable without publishing a release closure. The
//! real projection is covered by `pos-crypto`'s PMF1 tests.

use pos_crypto::plugin_execution::{
    DeterministicBudgetV1, PluginAbiRequirementV1, PluginCapabilityDescriptorV1,
    PluginExecutionProjectionFixtureV1, PluginExecutionProjectionV1, COMMUNITY_PLUGIN_WORLD_V1,
    WASM_PAGE_BYTES_V1,
};
use pos_runtime::community_plugin_host::{
    negotiate_community_plugin_v1, AtomicCommitFailureV1, CeilingValuesV1,
    CommunityPluginCeilingsV1, CommunityPluginExecutionProfileV1, CommunityPluginHostAbiErrorV1,
    CommunityPluginHostAbiV1, CommunityPluginHostErrorV1, CommunityPluginModeV1,
    CommunityPluginProfileErrorV1, ComponentTrapClassV1, EffectiveExecutionLimitsV1,
    ExecutionLimitV1, HostFailureClassV1, NegotiatedCommunityPluginV1, PinnedComponentRuntimeV1,
    PinnedEngineConfigV1, TrapOutcomeV1, TrapReproductionV1, TrapTableEntryV1,
    COMMUNITY_PLUGIN_ABI_MAJOR_V1,
};
use pos_runtime::PluginExecutionModeV1;

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
/// Every closed error with its ADR name, class and V1 production.
const ERRORS: [(Error, &str, HostFailureClassV1, bool); 22] = [
    (Error::InvalidManifest, "InvalidManifest", REJECTION, true),
    (
        Error::ArtifactTrustDenied,
        "ArtifactTrustDenied",
        REJECTION,
        true,
    ),
    (Error::ArtifactRevoked, "ArtifactRevoked", REJECTION, true),
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
        REJECTION,
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
    assert_eq!(ceilings.fuel, 10_000_000_000);
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
