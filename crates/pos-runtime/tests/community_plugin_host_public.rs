//! ADR-061 revision 4 community Plugin host contract at its public seams.
//!
//! Execution projections come from the `pos-crypto` `test-support` fixture,
//! which models caller-fabricated PMF1 requirements, so every negotiation
//! rejection path is reachable without publishing a release closure. The
//! real projection is covered by `pos-crypto`'s PMF1 tests.

use pos_crypto::plugin_execution::{
    DeterministicBudgetV1, PluginAbiRequirementV1, PluginCapabilityDescriptorV1,
    PluginExecutionProjectionFixtureV1, PluginExecutionProjectionV1, COMMUNITY_PLUGIN_WORLD_V1,
};
use pos_runtime::community_plugin_host::{
    negotiate_community_plugin_v1, AtomicCommitFailureV1, CommunityPluginCeilingsV1,
    CommunityPluginExecutionProfileV1, CommunityPluginHostAbiV1, CommunityPluginHostErrorV1,
    CommunityPluginModeV1, CommunityPluginProfileErrorV1, ComponentTrapClassV1,
    EffectiveExecutionLimitsV1, ExecutionLimitV1, HostFailureClassV1, NegotiatedCommunityPluginV1,
    PinnedComponentRuntimeV1, TrapOutcomeV1, TrapTableEntryV1, COMMUNITY_PLUGIN_ABI_MAJOR_V1,
    WASM_PAGE_BYTES_V1, WIT_EVENT_COUNT_CEILING_V1, WIT_LOG_CALLS_CEILING_V1,
    WIT_LOG_MESSAGE_BYTES_CEILING_V1, WIT_STATE_BYTES_CEILING_V1,
};
use pos_runtime::PluginExecutionModeV1;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Negotiation = Result<NegotiatedCommunityPluginV1, Error>;
type Error = CommunityPluginHostErrorV1;

const AUTHORITATIVE: HostFailureClassV1 = HostFailureClassV1::Authoritative;
const OPERATIONAL: HostFailureClassV1 = HostFailureClassV1::Operational;
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
    )
}

fn negotiate(
    requirements: PluginExecutionProjectionFixtureV1,
    host: &CommunityPluginHostAbiV1,
) -> Negotiation {
    let execution = PluginExecutionProjectionV1::from(requirements);
    negotiate_community_plugin_v1(&execution, host, &local())
}

/// Negotiate ABI `min..=max` against a host supporting minors 2-5.
fn minor(min_minor: u16, max_minor: u16, major: u16) -> Result<Result<u16, Error>, String> {
    let host = CommunityPluginHostAbiV1::new(2, 5, Vec::new()).ok_or("invalid host ABI")?;
    let mut requirements = fixture();
    requirements.abi.major = major;
    requirements.abi.min_minor = min_minor;
    requirements.abi.max_minor = max_minor;
    Ok(negotiate(requirements, &host).map(|negotiated| negotiated.abi().1))
}

fn runtime() -> PinnedComponentRuntimeV1 {
    PinnedComponentRuntimeV1 {
        wasmtime_version: "0.0.0-test".to_owned(),
        resolved_features: features(&["component-model", "cranelift"]),
        max_wasm_stack: 524_288,
        consume_fuel: true,
        epoch_interruption: true,
        trap_table: vec![TrapTableEntryV1 {
            trap_code: "OutOfFuel".to_owned(),
            outcome: TrapOutcomeV1::FuelExhausted,
        }],
    }
}

const TRAP: ComponentTrapClassV1 = ComponentTrapClassV1::StackExhausted;
const TYPED: AtomicCommitFailureV1 = AtomicCommitFailureV1::DeterministicTypedResult;
const UNTYPED: AtomicCommitFailureV1 = AtomicCommitFailureV1::Operational;
/// Every closed error with its ADR name, class and V1 production.
const ERRORS: [(Error, &str, HostFailureClassV1, bool); 21] = [
    (
        Error::InvalidManifest,
        "InvalidManifest",
        AUTHORITATIVE,
        true,
    ),
    (
        Error::ArtifactTrustDenied,
        "ArtifactTrustDenied",
        AUTHORITATIVE,
        true,
    ),
    (
        Error::ArtifactRevoked,
        "ArtifactRevoked",
        AUTHORITATIVE,
        true,
    ),
    (
        Error::IncompatibleAbi,
        "IncompatibleAbi",
        AUTHORITATIVE,
        true,
    ),
    (
        Error::MissingFeature { index: 2 },
        "MissingFeature",
        AUTHORITATIVE,
        true,
    ),
    (
        Error::CapabilityDenied { index: 3 },
        "CapabilityDenied",
        AUTHORITATIVE,
        true,
    ),
    (
        Error::InvalidInvocation,
        "InvalidInvocation",
        AUTHORITATIVE,
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
        Error::ComponentTrap { class: TRAP },
        "ComponentTrap",
        AUTHORITATIVE,
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
    assert_eq!(distinct.len(), messages.len() - 1);
    assert_eq!(
        Error::ComponentTrap { class: TRAP }.to_string(),
        "community Plugin Component trapped: stack-exhausted"
    );
    assert_eq!(
        Error::MissingFeature { index: 2 }.to_string(),
        "community Plugin requires unsupported feature 2"
    );
}

#[test]
fn trap_classes_are_the_closed_adr_set_and_outcomes_map_to_host_errors() {
    let names = ComponentTrapClassV1::ALL.map(ComponentTrapClassV1::name);
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
    for class in ComponentTrapClassV1::ALL {
        let error = TrapOutcomeV1::Trap(class).error();
        assert_eq!(error, Error::ComponentTrap { class });
        assert_eq!(error.class(), AUTHORITATIVE);
    }
    assert_eq!(TrapOutcomeV1::FuelExhausted.error(), Error::FuelExhausted);
    assert_eq!(
        TrapOutcomeV1::WatchdogStop.error(),
        Error::OperationalWatchdogStop
    );
    assert_eq!(TrapOutcomeV1::WatchdogStop.error().class(), OPERATIONAL);
}

#[test]
fn only_local_and_air_gapped_modes_have_a_live_profile() {
    let modes = [
        PluginExecutionModeV1::Local,
        PluginExecutionModeV1::AirGapped,
        PluginExecutionModeV1::Replay,
    ]
    .map(CommunityPluginModeV1::from_execution_mode);
    assert_eq!(
        modes,
        [
            Some(CommunityPluginModeV1::Local),
            Some(CommunityPluginModeV1::AirGapped),
            None
        ]
    );
}

#[test]
fn v1_ceilings_lower_memory_and_fuel_only() {
    let ceilings = CommunityPluginCeilingsV1::V1;
    assert_eq!(ceilings.memory_bytes(), 67_108_864);
    assert_eq!(ceilings.memory_bytes() % WASM_PAGE_BYTES_V1, 0);
    assert_eq!(ceilings.fuel(), 10_000_000_000);
    assert_eq!(ceilings.host_calls(), 1_000_000);
    assert_eq!(ceilings.event_bytes(), 16_777_216);
    assert_eq!(ceilings.log_bytes(), 16_384);
    assert_eq!(
        CommunityPluginCeilingsV1::new(67_108_864, 10_000_000_000, 1_000_000, 16_777_216, 16_384),
        Ok(ceilings)
    );
}

#[test]
fn operator_ceilings_stay_within_the_pmf1_member_ranges() -> TestResult {
    let smallest = CommunityPluginCeilingsV1::new(WASM_PAGE_BYTES_V1, 1, 0, 0, 0)?;
    assert_eq!(
        [
            smallest.memory_bytes(),
            smallest.fuel(),
            smallest.host_calls()
        ],
        [65_536, 1, 0]
    );
    assert_eq!([smallest.event_bytes(), smallest.log_bytes()], [0, 0]);
    let largest = CommunityPluginCeilingsV1::new(1 << 32, u64::MAX, 1_000_000, 1 << 24, 16_384)?;
    assert_eq!(
        [largest.memory_bytes(), largest.fuel()],
        [1 << 32, u64::MAX]
    );
    let rejected = [
        ([0, 1, 0, 0, 0], ExecutionLimitV1::MemoryBytes),
        ([65_535, 1, 0, 0, 0], ExecutionLimitV1::MemoryBytes),
        ([65_537, 1, 0, 0, 0], ExecutionLimitV1::MemoryBytes),
        (
            [(1 << 32) + 65_536, 1, 0, 0, 0],
            ExecutionLimitV1::MemoryBytes,
        ),
        ([0, 0, 0, 0, 0], ExecutionLimitV1::MemoryBytes),
        ([65_536, 0, 0, 0, 0], ExecutionLimitV1::Fuel),
        ([65_536, 1, 1_000_001, 0, 0], ExecutionLimitV1::HostCalls),
        (
            [65_536, 1, 0, (1 << 24) + 1, 0],
            ExecutionLimitV1::EventBytes,
        ),
        ([65_536, 1, 0, 0, 16_385], ExecutionLimitV1::LogBytes),
    ];
    for ([memory, fuel, host_calls, event_bytes, log_bytes], limit) in rejected {
        let ceilings =
            CommunityPluginCeilingsV1::new(memory, fuel, host_calls, event_bytes, log_bytes);
        assert_eq!(
            ceilings,
            Err(CommunityPluginProfileErrorV1::CeilingOutOfRange { limit })
        );
    }
    let message = CommunityPluginProfileErrorV1::CeilingOutOfRange {
        limit: ExecutionLimitV1::Fuel,
    };
    assert_eq!(
        message.to_string(),
        "community Plugin profile ceiling Fuel is out of range"
    );
    Ok(())
}

#[test]
fn parity_profiles_carry_identical_ceilings_and_runtime() -> TestResult {
    let ceilings = CommunityPluginCeilingsV1::new(4 * WASM_PAGE_BYTES_V1, 77, 6, 5, 4)?;
    let pinned = runtime();
    let [local, air_gapped] =
        CommunityPluginExecutionProfileV1::parity_pair(ceilings, Some(&pinned));
    assert_eq!(local.mode(), CommunityPluginModeV1::Local);
    assert_eq!(air_gapped.mode(), CommunityPluginModeV1::AirGapped);
    assert!(local.has_parity_with(&air_gapped));
    assert_eq!(local.ceilings(), ceilings);
    assert_eq!(air_gapped.runtime(), Some(&pinned));
    let unpinned =
        CommunityPluginExecutionProfileV1::new(CommunityPluginModeV1::AirGapped, ceilings);
    assert_eq!(unpinned.runtime(), None);
    assert!(!local.has_parity_with(&unpinned));
    let pinned_again = unpinned.with_runtime(pinned);
    assert!(local.has_parity_with(&pinned_again));
    let [lower, _] = CommunityPluginExecutionProfileV1::parity_pair(
        CommunityPluginCeilingsV1::V1,
        Some(&runtime()),
    );
    assert!(!local.has_parity_with(&lower));
    let [bare_local, bare_air_gapped] =
        CommunityPluginExecutionProfileV1::parity_pair(ceilings, None);
    assert!(bare_local.has_parity_with(&bare_air_gapped));
    assert_eq!(bare_air_gapped.runtime(), None);
    Ok(())
}

#[test]
fn negotiation_records_the_release_abi_and_not_granted_capabilities() -> TestResult {
    let mut requirements = fixture();
    requirements.capabilities = vec![capability("read", false), capability("write", false)];
    let expected_capabilities = requirements.capabilities.clone();
    let profile = local().with_runtime(runtime());
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
    assert_eq!(negotiated.runtime(), Some(&runtime()));
    let limits = negotiated.limits();
    assert_eq!(limits.memory_bytes, SMALL_BUDGET.memory_bytes);
    assert_eq!(limits.fuel, SMALL_BUDGET.fuel);
    assert_eq!(limits.log_bytes, SMALL_BUDGET.log_bytes);
    assert_eq!((host.min_minor(), host.max_minor()), (0, 0));
    assert!(host.features().is_empty());
    let mut bare = fixture();
    bare.capabilities.clear();
    let negotiated = negotiate(bare, &host)?;
    assert!(negotiated.not_granted_capabilities().is_empty());
    assert_eq!(negotiated.runtime(), None);
    Ok(())
}

#[test]
fn abi_negotiation_picks_the_highest_common_minor_of_major_zero() -> TestResult {
    assert_eq!(minor(0, 9, 0)?, Ok(5));
    assert_eq!(minor(3, 4, 0)?, Ok(4));
    assert_eq!(minor(0, 2, 0)?, Ok(2));
    assert_eq!(minor(5, 9, 0)?, Ok(5));
    assert_eq!(minor(6, 9, 0)?, Err(Error::IncompatibleAbi));
    assert_eq!(minor(0, 1, 0)?, Err(Error::IncompatibleAbi));
    assert_eq!(minor(0, 9, 1)?, Err(Error::IncompatibleAbi));
    assert_eq!(CommunityPluginHostAbiV1::new(3, 2, Vec::new()), None);
    let single = CommunityPluginHostAbiV1::new(4, 4, features(&["log"])).ok_or("invalid host")?;
    assert_eq!((single.min_minor(), single.max_minor()), (4, 4));
    assert_eq!(single.features(), features(&["log"]).as_slice());
    let mut v1 = fixture();
    v1.abi.min_minor = 1;
    assert_eq!(
        negotiate(v1, &CommunityPluginHostAbiV1::v1()),
        Err(Error::IncompatibleAbi)
    );
    Ok(())
}

#[test]
fn every_required_feature_must_be_provided_by_the_host() -> TestResult {
    let host = CommunityPluginHostAbiV1::new(0, 0, features(&["a", "c"])).ok_or("invalid host")?;
    let mut provided = fixture();
    provided.abi.required_features = features(&["a", "c"]);
    let negotiated = negotiate(provided, &host)?;
    assert_eq!(
        negotiated.required_features(),
        features(&["a", "c"]).as_slice()
    );
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
    assert_eq!(denied.err().map(Error::class), Some(AUTHORITATIVE));
}

#[test]
fn negotiation_fails_at_the_first_phase_in_validation_order() -> TestResult {
    let host = CommunityPluginHostAbiV1::new(0, 0, Vec::new()).ok_or("invalid host")?;
    let mut everything = fixture();
    everything.abi.major = 1;
    everything.abi.required_features = features(&["missing"]);
    everything.capabilities = vec![capability("read", true)];
    assert_eq!(
        negotiate(everything.clone(), &host),
        Err(Error::IncompatibleAbi)
    );
    everything.abi.major = 0;
    assert_eq!(
        negotiate(everything.clone(), &host),
        Err(Error::MissingFeature { index: 0 })
    );
    everything.abi.required_features.clear();
    assert_eq!(
        negotiate(everything, &host),
        Err(Error::CapabilityDenied { index: 0 })
    );
    Ok(())
}

#[test]
fn budgets_above_a_ceiling_are_clamped_not_rejected() -> TestResult {
    let ceilings = CommunityPluginCeilingsV1::new(3 * WASM_PAGE_BYTES_V1, 1_000, 30, 800, 500)?;
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
    let clamped = EffectiveExecutionLimitsV1::clamp(above, ceilings);
    let expected = EffectiveExecutionLimitsV1 {
        memory_bytes: 3 * WASM_PAGE_BYTES_V1,
        fuel: 1_000,
        host_calls: 30,
        event_count: WIT_EVENT_COUNT_CEILING_V1,
        event_bytes: 800,
        state_bytes: WIT_STATE_BYTES_CEILING_V1,
        log_calls: WIT_LOG_CALLS_CEILING_V1,
        log_bytes: 500,
    };
    assert_eq!(clamped, expected);
    let below = EffectiveExecutionLimitsV1::clamp(SMALL_BUDGET, CommunityPluginCeilingsV1::V1);
    let unchanged = EffectiveExecutionLimitsV1 {
        memory_bytes: SMALL_BUDGET.memory_bytes,
        fuel: SMALL_BUDGET.fuel,
        host_calls: SMALL_BUDGET.host_calls,
        event_count: SMALL_BUDGET.event_count,
        event_bytes: SMALL_BUDGET.event_bytes,
        state_bytes: SMALL_BUDGET.state_bytes,
        log_calls: SMALL_BUDGET.log_calls,
        log_bytes: SMALL_BUDGET.log_bytes,
    };
    assert_eq!(below, unchanged);
    assert_eq!(
        WIT_LOG_CALLS_CEILING_V1 * WIT_LOG_MESSAGE_BYTES_CEILING_V1,
        16_384
    );
    let mut requirements = fixture();
    requirements.budget = above;
    let execution = PluginExecutionProjectionV1::from(requirements);
    let profile =
        CommunityPluginExecutionProfileV1::new(CommunityPluginModeV1::AirGapped, ceilings);
    let negotiated =
        negotiate_community_plugin_v1(&execution, &CommunityPluginHostAbiV1::v1(), &profile)?;
    assert_eq!(negotiated.limits(), expected);
    assert_eq!(negotiated.mode(), CommunityPluginModeV1::AirGapped);
    Ok(())
}

#[test]
fn parity_profiles_negotiate_identical_limits_in_both_modes() -> TestResult {
    let ceilings = CommunityPluginCeilingsV1::new(WASM_PAGE_BYTES_V1, 2_000, 20, 500, 300)?;
    let execution = PluginExecutionProjectionV1::from(fixture());
    let host = CommunityPluginHostAbiV1::v1();
    let [local, air_gapped] =
        CommunityPluginExecutionProfileV1::parity_pair(ceilings, Some(&runtime()));
    let in_local = negotiate_community_plugin_v1(&execution, &host, &local)?;
    let in_air_gapped = negotiate_community_plugin_v1(&execution, &host, &air_gapped)?;
    assert_eq!(in_local.limits(), in_air_gapped.limits());
    assert_eq!(in_local.runtime(), in_air_gapped.runtime());
    assert_ne!(in_local.mode(), in_air_gapped.mode());
    assert_eq!(in_local.limits().memory_bytes, WASM_PAGE_BYTES_V1);
    Ok(())
}
