use pos_crypto::plugin_execution::{
    PluginAbiRequirementV1, PluginExecutionProjectionFixtureV1, PluginExecutionProjectionV1,
};

use super::super::negotiate_community_plugin_v1;
use super::*;
use crate::community_plugin_host::profile::{
    CommunityPluginCeilingsV1, PinnedComponentRuntimeV1, PinnedEngineConfigV1,
};

type Error = NegotiatedTransportErrorV1;
type LimitEdit = fn(&mut DeterministicBudgetV1);

fn runtime() -> PinnedComponentRuntimeV1 {
    let engine = PinnedEngineConfigV1 {
        max_wasm_stack: 524_288,
        consume_fuel: true,
        epoch_interruption: true,
    };
    PinnedComponentRuntimeV1::new("49.0.2".to_owned(), Vec::new(), engine, Vec::new())
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
}

fn profile(mode: CommunityPluginModeV1) -> CommunityPluginExecutionProfileV1 {
    CommunityPluginExecutionProfileV1::new(mode, CommunityPluginCeilingsV1::V1, Some(runtime()))
}

fn host() -> CommunityPluginHostAbiV1 {
    CommunityPluginHostAbiV1::new(1, 3, vec!["alpha".to_owned(), "beta".to_owned()])
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
}

fn capability(id: &str, required: bool) -> PluginCapabilityDescriptorV1 {
    PluginCapabilityDescriptorV1 {
        capability_id: id.to_owned(),
        operation: "read".to_owned(),
        resource_pattern: "*".to_owned(),
        purpose: "test".to_owned(),
        audience: "local".to_owned(),
        required,
        max_calls: 1,
        max_request_bytes: 1,
        max_response_bytes: 1,
    }
}

/// A record the supervisor negotiated: ABI 0.0-5 against host minors 1-3.
fn negotiated() -> NegotiatedCommunityPluginV1 {
    let fixture = PluginExecutionProjectionFixtureV1 {
        pmf1_digest: [0x11; 32],
        release_digest: [0x22; 32],
        plugin_id: "plugin-a".to_owned(),
        abi: PluginAbiRequirementV1 {
            major: 0,
            min_minor: 0,
            max_minor: 5,
            required_features: vec!["alpha".to_owned(), "beta".to_owned()],
        },
        capabilities: vec![capability("read", false)],
        budget: DeterministicBudgetV1::MAXIMA,
    };
    let execution = PluginExecutionProjectionV1::from(fixture);
    negotiate_community_plugin_v1(&execution, &host(), &profile(CommunityPluginModeV1::Local))
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
}

fn rebuild(transport: NegotiatedTransportV1) -> Result<NegotiatedCommunityPluginV1, Error> {
    NegotiatedCommunityPluginV1::from_transport(
        transport,
        &host(),
        &profile(CommunityPluginModeV1::Local),
    )
}

fn rejected(change: impl FnOnce(&mut NegotiatedTransportV1)) -> Option<Error> {
    let mut transport = negotiated().to_transport();
    change(&mut transport);
    rebuild(transport).err()
}

#[test]
fn a_negotiated_record_round_trips_through_its_transport() {
    let original = negotiated();
    let transport = original.to_transport();
    assert_eq!(transport.abi_major, 0);
    assert_eq!(transport.abi_minor, 3);
    assert_eq!(transport.declared_minors, (0, 5));
    assert_eq!(transport.world, COMMUNITY_PLUGIN_WORLD_V1);
    assert_eq!(transport.limits, original.limits().values());
    assert_eq!(rebuild(transport), Ok(original));
}

#[test]
fn the_runtime_comes_from_the_worker_profile() {
    let transport = negotiated().to_transport();
    let bare = CommunityPluginExecutionProfileV1::new(
        CommunityPluginModeV1::Local,
        CommunityPluginCeilingsV1::V1,
        None,
    );
    let result = NegotiatedCommunityPluginV1::from_transport(transport, &host(), &bare);
    assert_eq!(result.err(), Some(Error::Runtime));
}

#[test]
fn identity_and_abi_must_be_the_negotiated_ones() {
    assert_eq!(rejected(|t| t.world.push('x')), Some(Error::World));
    assert_eq!(
        rejected(|t| t.plugin_id = "Plugin".to_owned()),
        Some(Error::PluginId)
    );
    assert_eq!(rejected(|t| t.abi_major = 1), Some(Error::Abi));
    assert_eq!(rejected(|t| t.abi_minor = 2), Some(Error::Abi));
    assert_eq!(rejected(|t| t.abi_minor = 4), Some(Error::Abi));
    assert_eq!(rejected(|t| t.declared_minors = (4, 5)), Some(Error::Abi));
    assert_eq!(rejected(|t| t.declared_minors = (0, 0)), Some(Error::Abi));
    let narrower = |t: &mut NegotiatedTransportV1| {
        t.declared_minors = (2, 2);
        t.abi_minor = 2;
    };
    assert_eq!(rejected(narrower), None);
}

#[test]
fn features_must_be_valid_ordered_and_provided() {
    let with = |features: &[&str]| {
        rejected(|t| t.required_features = features.iter().map(|f| (*f).to_owned()).collect())
    };
    assert_eq!(with(&[]), None);
    assert_eq!(with(&["beta"]), None);
    assert_eq!(with(&["Alpha"]), Some(Error::Feature { index: 0 }));
    assert_eq!(with(&["alpha", "alpha"]), Some(Error::Feature { index: 1 }));
    assert_eq!(with(&["beta", "alpha"]), Some(Error::Feature { index: 1 }));
    assert_eq!(with(&["alpha", "gamma"]), Some(Error::Feature { index: 1 }));
}

#[test]
fn capabilities_must_be_optional_and_bounded() {
    let required = |t: &mut NegotiatedTransportV1| {
        t.not_granted_capabilities.push(capability("write", true));
    };
    assert_eq!(rejected(required), Some(Error::Capabilities));
    let most = |t: &mut NegotiatedTransportV1| {
        t.not_granted_capabilities = vec![capability("read", false); MAX_CAPABILITIES];
    };
    assert_eq!(rejected(most), None);
    let too_many = |t: &mut NegotiatedTransportV1| {
        t.not_granted_capabilities = vec![capability("read", false); MAX_CAPABILITIES + 1];
    };
    assert_eq!(rejected(too_many), Some(Error::Capabilities));
}

#[test]
fn the_mode_must_match_the_worker_profile() {
    assert_eq!(
        rejected(|t| t.mode = CommunityPluginModeV1::AirGapped),
        Some(Error::Mode)
    );
}

#[test]
fn limits_must_be_a_clamped_budget() {
    let ceilings = CommunityPluginCeilingsV1::V1.values();
    let wit = DeterministicBudgetV1::MAXIMA;
    let cases: [(&str, LimitEdit); 11] = [
        ("memory below a page", |l| l.memory_bytes = 0),
        ("memory not whole pages", |l| l.memory_bytes = 65_537),
        ("no fuel", |l| l.fuel = 0),
        ("memory above ceiling", |l| {
            l.memory_bytes += WASM_PAGE_BYTES_V1;
        }),
        ("fuel above ceiling", |l| l.fuel += 1),
        ("host calls above ceiling", |l| l.host_calls += 1),
        ("events above WIT", |l| l.event_count += 1),
        ("event bytes above ceiling", |l| l.event_bytes += 1),
        ("state above WIT", |l| l.state_bytes += 1),
        ("log calls above WIT", |l| l.log_calls += 1),
        ("log bytes above ceiling", |l| l.log_bytes += 1),
    ];
    for (name, change) in cases {
        assert_eq!(
            rejected(|t| change(&mut t.limits)),
            Some(Error::Limits),
            "{name}"
        );
    }
    assert_eq!(
        negotiated().limits().values().memory_bytes,
        ceilings.memory_bytes
    );
    assert_eq!(negotiated().limits().values().event_count, wit.event_count);
    let smallest = |t: &mut NegotiatedTransportV1| {
        t.limits = DeterministicBudgetV1::MINIMA;
    };
    assert_eq!(rejected(smallest), None);
}

#[test]
fn errors_have_stable_messages() {
    assert_eq!(
        Error::Feature { index: 2 }.to_string(),
        "transported community Plugin feature 2 is not acceptable"
    );
    assert_eq!(
        Error::Runtime.to_string(),
        "community Plugin profile pins no runtime"
    );
}
