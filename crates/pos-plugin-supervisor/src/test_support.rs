//! Releases, invocations and guest values shared by the tests of this crate
//! and of `pos-plugin-worker`.
//!
//! Compiled only for this crate's unit tests and with the `test-support`
//! feature, which `scripts/check_test_support_features.py` keeps out of
//! deployable builds. Nothing here grants authority: the releases come from
//! the unchecked `pos-crypto` projection fixture.

use pos_core::{Capability, Hash, Kind, Plugin, PluginId};
use pos_crypto::plugin_execution::{
    DeterministicBudgetV1, PluginAbiRequirementV1, PluginCapabilityDescriptorV1,
    PluginExecutionProjectionFixtureV1, PluginExecutionProjectionV1,
};
use pos_crypto::plugin_manifest::component_digest_v1;
use pos_runtime::community_plugin_host::{
    negotiate_community_plugin_v1, plugin_output_digest_v1, ArtifactRefV1,
    CommunityPassAuthorizationV1, CommunityPassV1, CommunityPluginCeilingsV1,
    CommunityPluginExecutionProfileV1, CommunityPluginHostAbiV1, CommunityPluginModeV1,
    EventDraftV1, GatedCommunityReleaseV1, MeteringV1, NegotiatedCommunityPluginV1,
    OperationalLogRecord, PinnedComponentRuntimeV1, PinnedEngineConfigV1, PluginDescriptorV1,
    PluginInvocationV1, PluginOutputV1, ReleaseIdentityV1, TimelinePositionV1, TraceAnnotationV1,
    TrapOutcomeV1, TrapTableEntryV1,
};
use pos_runtime::{DomainImplementationKindV1, PluginIsolationV1, PluginPinV1};

use crate::adapter::{CommunityDriverConfigV1, CommunityDriverSettingsV1, InvocationBindingV1};

/// A budget small enough that the worker's data ceiling stays far below 1 GiB.
pub const SMALL_BUDGET: DeterministicBudgetV1 = DeterministicBudgetV1 {
    memory_bytes: 65_536,
    fuel: 1_000,
    ..DeterministicBudgetV1::MAXIMA
};

/// The Tick of the fixture invocations and of the fixture authorizations.
pub const TICK: u64 = 3;

/// The TPS1 digest of the fixture invocations and of the fixture authorizations.
pub const TPS1_DIGEST: [u8; 32] = [4; 32];

/// The metering of every report these fixtures build.
pub const METERING: MeteringV1 = MeteringV1 {
    startup_fuel: 1,
    call_fuel: 300,
    memory_bytes: 65_536,
    host_calls: 4_294_967_296,
};

/// The value of `result`, or a test failure that names the error.
#[must_use]
pub fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
}

/// The error of `result`, or a test failure that names the unexpected value.
#[must_use]
pub fn err<T: std::fmt::Debug, E>(result: Result<T, E>) -> E {
    match result {
        Ok(value) => std::panic::resume_unwind(Box::new(format!("unexpected success: {value:?}"))),
        Err(error) => error,
    }
}

/// A Plugin that owns one Event type, for the adapter's registry tests.
pub struct DriverPlugin {
    /// The Plugin ID.
    pub id: PluginId,
    /// The Plugin name.
    pub name: &'static str,
    /// The one Event type it owns.
    pub event_type: &'static str,
    /// Whether it declares a Driver.
    pub has_driver: bool,
}

impl Plugin for DriverPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(self.event_type)],
            has_driver: self.has_driver,
            ..Capability::default()
        }
    }
}

/// A pin of the given kind and isolation with one role and a non-zero digest.
#[must_use]
pub fn pin_of(
    kind: DomainImplementationKindV1,
    isolation: PluginIsolationV1,
    byte: u8,
    role: &str,
) -> PluginPinV1 {
    ok(PluginPinV1::try_new(
        kind,
        isolation,
        Hash::from_bytes([byte; 32]),
        vec![role.to_owned()],
    ))
}

/// The pin of a community Plugin.
#[must_use]
pub fn community_pin(byte: u8, role: &str) -> PluginPinV1 {
    pin_of(
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::GovernedCommunity,
        byte,
        role,
    )
}

/// An optional capability, which negotiation records as not granted.
#[must_use]
pub fn optional_capability() -> PluginCapabilityDescriptorV1 {
    PluginCapabilityDescriptorV1 {
        capability_id: "read".to_owned(),
        operation: "get".to_owned(),
        resource_pattern: "*".to_owned(),
        purpose: "test".to_owned(),
        audience: "local".to_owned(),
        required: false,
        max_calls: 1,
        max_request_bytes: 2,
        max_response_bytes: 3,
    }
}

/// A pinned runtime that is the fixtures' own: it is no engine's, so only the probe worker (which
/// does not compare it) serves records under it.
#[must_use]
pub fn fixture_runtime() -> PinnedComponentRuntimeV1 {
    let row = |trap_code: &str, outcome| TrapTableEntryV1 {
        trap_code: trap_code.to_owned(),
        outcome,
    };
    ok(PinnedComponentRuntimeV1::new(
        "fixture-1".to_owned(),
        vec!["runtime".to_owned()],
        PinnedEngineConfigV1 {
            max_wasm_stack: 524_288,
            consume_fuel: true,
            epoch_interruption: true,
        },
        vec![
            row("OutOfFuel", TrapOutcomeV1::FuelExhausted),
            row("Interrupt", TrapOutcomeV1::WatchdogStop),
        ],
    ))
}

/// The Local profile that records [`fixture_runtime()`], and so has a profile digest.
#[must_use]
pub fn fixture_profile() -> CommunityPluginExecutionProfileV1 {
    CommunityPluginExecutionProfileV1::new(
        CommunityPluginModeV1::Local,
        CommunityPluginCeilingsV1::V1,
        Some(fixture_runtime()),
    )
}

/// The Local profile that records no runtime, and so no profile digest.
#[must_use]
pub const fn profile_without_digest() -> CommunityPluginExecutionProfileV1 {
    CommunityPluginExecutionProfileV1::new(
        CommunityPluginModeV1::Local,
        CommunityPluginCeilingsV1::V1,
        None,
    )
}

/// A gated release of `plugin_id` declaring ABI 0.0 and `budget`, holding `component`.
///
/// Nothing was gated: it is the `test-support` constructor of the gated release.
#[must_use]
pub fn gated_with(
    plugin_id: &str,
    budget: DeterministicBudgetV1,
    capabilities: Vec<PluginCapabilityDescriptorV1>,
    component: Vec<u8>,
) -> GatedCommunityReleaseV1 {
    let fixture = PluginExecutionProjectionFixtureV1 {
        pmf1_digest: [0x11; 32],
        release_digest: [0x22; 32],
        plugin_id: plugin_id.to_owned(),
        abi: PluginAbiRequirementV1 {
            major: 0,
            min_minor: 0,
            max_minor: 0,
            required_features: Vec::new(),
        },
        capabilities,
        budget,
    };
    let execution = PluginExecutionProjectionV1::from(fixture);
    GatedCommunityReleaseV1::for_test(execution, component)
}

/// `plugin_id` declaring ABI 0.0 and `budget`, negotiated by the V1 host under
/// [`fixture_profile()`], which has a profile digest.
#[must_use]
pub fn negotiated_with(
    plugin_id: &str,
    budget: DeterministicBudgetV1,
    capabilities: Vec<PluginCapabilityDescriptorV1>,
) -> NegotiatedCommunityPluginV1 {
    negotiated_under(plugin_id, budget, capabilities, &fixture_profile())
}

/// As [`negotiated_with`], negotiated under `profile`.
///
/// A worker serves a record only when its profile digest is the worker's own,
/// so a test that runs a real worker passes a profile with the worker's pinned
/// runtime and mode.
#[must_use]
pub fn negotiated_under(
    plugin_id: &str,
    budget: DeterministicBudgetV1,
    capabilities: Vec<PluginCapabilityDescriptorV1>,
    profile: &CommunityPluginExecutionProfileV1,
) -> NegotiatedCommunityPluginV1 {
    let gated = gated_with(plugin_id, budget, capabilities, Vec::new());
    ok(negotiate_community_plugin_v1(
        &gated,
        &CommunityPluginHostAbiV1::v1(),
        profile,
    ))
}

/// The config of a Driver for `plugin_id` holding `component`, built from a gated release under
/// `profile`.
#[must_use]
pub fn config_under(
    plugin_id: &str,
    component: &[u8],
    profile: &CommunityPluginExecutionProfileV1,
    settings: CommunityDriverSettingsV1,
) -> CommunityDriverConfigV1 {
    let gated = gated_with(plugin_id, SMALL_BUDGET, Vec::new(), component.to_vec());
    ok(CommunityDriverConfigV1::from_gated(
        gated,
        &CommunityPluginHostAbiV1::v1(),
        profile,
        plugin_id,
        settings,
    ))
}

/// As [`config_under`], under [`fixture_profile()`].
#[must_use]
pub fn config_with(
    plugin_id: &str,
    component: &[u8],
    settings: CommunityDriverSettingsV1,
) -> CommunityDriverConfigV1 {
    config_under(plugin_id, component, &fixture_profile(), settings)
}

/// An open pass at [`TICK`] that nothing closes unless the test does.
#[must_use]
pub fn open_pass() -> CommunityPassV1 {
    ok(CommunityPassV1::open_at_for_test(1_000, TICK))
}

/// The fields of a test authorization, so that a test can change exactly one of them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationFields {
    /// The exact PMF1 Plugin ID.
    pub plugin_id: String,
    /// The complete-PMF1 and release digests.
    pub identity: ReleaseIdentityV1,
    /// The Component digest.
    pub component_digest: [u8; 32],
    /// The Tick of the pass.
    pub tick: u64,
    /// The authenticated TPS1 digest.
    pub tps1_digest: [u8; 32],
}

impl AuthorizationFields {
    /// The fields that authorize the release `negotiated` records, holding `component`, at
    /// [`TICK`] and [`TPS1_DIGEST`].
    #[must_use]
    pub fn for_release(negotiated: &NegotiatedCommunityPluginV1, component: &[u8]) -> Self {
        Self {
            plugin_id: negotiated.plugin_id().to_owned(),
            identity: ReleaseIdentityV1 {
                pmf1_digest: negotiated.pmf1_digest(),
                release_digest: negotiated.release_digest(),
            },
            component_digest: component_digest_v1(component),
            tick: TICK,
            tps1_digest: TPS1_DIGEST,
        }
    }

    /// The authorization of `pass` with these fields.
    #[must_use]
    pub fn issue(&self, pass: &CommunityPassV1) -> CommunityPassAuthorizationV1 {
        CommunityPassAuthorizationV1::for_test(
            pass,
            &self.plugin_id,
            self.identity,
            self.component_digest,
            self.tick,
            self.tps1_digest,
        )
    }
}

/// The authorization of `pass` for the release `negotiated` records, holding `component`.
#[must_use]
pub fn authorization_in(
    pass: &CommunityPassV1,
    negotiated: &NegotiatedCommunityPluginV1,
    component: &[u8],
) -> CommunityPassAuthorizationV1 {
    AuthorizationFields::for_release(negotiated, component).issue(pass)
}

/// As [`authorization_in`], in a fresh open pass.
#[must_use]
pub fn authorization_for(
    negotiated: &NegotiatedCommunityPluginV1,
    component: &[u8],
) -> CommunityPassAuthorizationV1 {
    authorization_in(&open_pass(), negotiated, component)
}

/// `invocation` with the three values of `binding` copied in, as a host source does; a missing
/// profile digest is written as zeros.
#[must_use]
pub fn bound(
    mut invocation: PluginInvocationV1,
    binding: InvocationBindingV1,
) -> PluginInvocationV1 {
    invocation.timeline_position.tick = binding.tick;
    invocation.trust_policy_snapshot_digest = binding.tps1_digest;
    invocation.execution_profile_digest = binding.execution_profile_digest.unwrap_or([0; 32]);
    invocation
}

/// `plugin-a` with the largest budget and one optional capability.
#[must_use]
pub fn negotiated() -> NegotiatedCommunityPluginV1 {
    negotiated_with(
        "plugin-a",
        DeterministicBudgetV1::MAXIMA,
        vec![optional_capability()],
    )
}

/// An invocation of the compatibility behaviour with `observation`.
#[must_use]
pub fn invocation(observation: &[u8]) -> PluginInvocationV1 {
    let artifact = |schema_id| ArtifactRefV1 {
        schema_id,
        byte_length: 0,
        digest: [0; 32],
    };
    PluginInvocationV1 {
        invocation_id: [0x11; 16],
        timeline_position: TimelinePositionV1 {
            timeline_id: [0x22; 16],
            seq: 11,
            tick: TICK,
            scheduler_position: 0,
        },
        output_base_ordinal: 0,
        principal_ref: artifact(1),
        authorization_decision: artifact(2),
        observation_snapshot: artifact(3),
        observation_bytes: observation.to_vec(),
        prior_state_schema: [2; 32],
        prior_state_bytes: b"prior".to_vec(),
        execution_profile_digest: [3; 32],
        trust_policy_snapshot_digest: TPS1_DIGEST,
        deterministic_budget_id: "budget".to_owned(),
        deterministic_random_domain: [7; 32],
        provenance_root: [5; 32],
    }
}

/// The fixture invocation of `observation` bound to the pass authorization of
/// [`authorization_for()`] and to the profile digest of `negotiated`.
#[must_use]
pub fn invocation_for(
    observation: &[u8],
    negotiated: &NegotiatedCommunityPluginV1,
) -> PluginInvocationV1 {
    let binding = InvocationBindingV1 {
        tick: TICK,
        tps1_digest: TPS1_DIGEST,
        execution_profile_digest: negotiated.execution_profile_digest(),
    };
    bound(invocation(observation), binding)
}

/// A valid output answering `invocation`, with one draft and one annotation.
#[must_use]
pub fn output(invocation: &PluginInvocationV1) -> PluginOutputV1 {
    let mut output = PluginOutputV1 {
        invocation_id: invocation.invocation_id,
        event_drafts: vec![EventDraftV1 {
            event_schema_id: 1,
            entity_id: [0x55; 16],
            event_type: "plugin.event".to_owned(),
            canonical_payload: b"payload".to_vec(),
            dependency_digests: vec![[1; 32], [2; 32]],
        }],
        next_state_schema: [5; 32],
        next_state_bytes: b"next".to_vec(),
        trace_annotations: vec![TraceAnnotationV1 {
            annotation_schema_id: 9,
            canonical_bytes: b"trace".to_vec(),
            dependency_digests: vec![[3; 32]],
        }],
        consumed_dependencies: vec![[4; 32]],
        output_digest: [0; 32],
    };
    output.output_digest = plugin_output_digest_v1(&output);
    output
}

/// The descriptor that describes `negotiated`.
#[must_use]
pub fn descriptor(negotiated: &NegotiatedCommunityPluginV1) -> PluginDescriptorV1 {
    let (abi_major, _) = negotiated.abi();
    let (min_abi_minor, max_abi_minor) = negotiated.declared_minor_range();
    PluginDescriptorV1 {
        plugin_id: negotiated.plugin_id().to_owned(),
        release_semver: "1.2.3".to_owned(),
        world: negotiated.world().to_owned(),
        abi_major,
        min_abi_minor,
        max_abi_minor,
        required_features: negotiated.required_features().to_vec(),
        event_schema_digests: vec![[1; 32]],
        state_schema_digest: [2; 32],
        manifest_digest: [0; 32],
        release_digest: [0; 32],
    }
}

/// One operational log record.
#[must_use]
pub fn log() -> Vec<OperationalLogRecord> {
    vec![OperationalLogRecord {
        category: 2,
        message: "logged".to_owned(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_result_is_a_test_failure_naming_the_error() {
        assert_eq!(ok(Ok::<_, ()>(3)), 3);
        let failure = std::panic::catch_unwind(|| ok(Err::<u8, _>("boom")));
        let message = failure
            .err()
            .and_then(|payload| payload.downcast::<String>().ok());
        assert_eq!(message.as_deref().map(String::as_str), Some("\"boom\""));
    }

    #[test]
    fn an_unexpected_success_is_a_test_failure_naming_the_value() {
        assert_eq!(err(Err::<u8, _>("boom")), "boom");
        let failure = std::panic::catch_unwind(|| err(Ok::<u8, ()>(7)));
        let message = failure
            .err()
            .and_then(|payload| payload.downcast::<String>().ok());
        assert_eq!(
            message.as_deref().map(String::as_str),
            Some("unexpected success: 7")
        );
    }

    #[test]
    fn negotiation_keeps_the_small_budget_and_the_capability() {
        let small = negotiated_with("plugin-a", SMALL_BUDGET, Vec::new());
        assert_eq!(small.limits().values().memory_bytes, 65_536);
        assert_eq!(small.limits().values().fuel, 1_000);
        let default = negotiated();
        assert_eq!(default.not_granted_capabilities().len(), 1);
        assert_eq!(default.plugin_id(), "plugin-a");
    }

    #[test]
    fn the_fixture_authorization_names_the_fixture_release_and_its_pass() {
        let record = negotiated();
        assert!(record.execution_profile_digest().is_some());
        assert_eq!(profile_without_digest().digest(), None);
        let pass = open_pass();
        let authorization = authorization_in(&pass, &record, b"bytes");
        assert_eq!(authorization.plugin_id(), "plugin-a");
        assert_eq!(authorization.pmf1_digest(), record.pmf1_digest());
        assert_eq!(authorization.release_digest(), record.release_digest());
        assert_eq!(
            authorization.component_digest(),
            component_digest_v1(b"bytes")
        );
        assert_eq!(authorization.tick(), TICK);
        assert_eq!(authorization.tps1_digest(), TPS1_DIGEST);
        assert!(authorization.is_pass_open());
        pass.close_for_test();
        assert!(!authorization.is_pass_open());
        assert!(authorization_for(&record, b"bytes").is_pass_open());
    }

    #[test]
    fn a_bound_invocation_carries_the_binding_and_zeros_for_no_digest() {
        let binding = InvocationBindingV1 {
            tick: 9,
            tps1_digest: [8; 32],
            execution_profile_digest: None,
        };
        let call = bound(invocation(b"o"), binding);
        assert_eq!(call.timeline_position.tick, 9);
        assert_eq!(call.trust_policy_snapshot_digest, [8; 32]);
        assert_eq!(call.execution_profile_digest, [0; 32]);
        let record = negotiated();
        let call = invocation_for(b"o", &record);
        let digest = Some(call.execution_profile_digest);
        assert_eq!(digest, record.execution_profile_digest());
        assert_eq!(call.timeline_position.tick, TICK);
    }
}
