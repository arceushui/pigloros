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
use pos_runtime::community_plugin_host::{
    negotiate_community_plugin_v1, plugin_output_digest_v1, ArtifactRefV1,
    CommunityPluginCeilingsV1, CommunityPluginExecutionProfileV1, CommunityPluginHostAbiV1,
    CommunityPluginModeV1, EventDraftV1, GatedCommunityReleaseV1, MeteringV1,
    NegotiatedCommunityPluginV1, OperationalLogRecord, PluginDescriptorV1, PluginInvocationV1,
    PluginOutputV1, TimelinePositionV1, TraceAnnotationV1,
};
use pos_runtime::{DomainImplementationKindV1, PluginIsolationV1, PluginPinV1};

/// A budget small enough that the worker's data ceiling stays far below 1 GiB.
pub const SMALL_BUDGET: DeterministicBudgetV1 = DeterministicBudgetV1 {
    memory_bytes: 65_536,
    fuel: 1_000,
    ..DeterministicBudgetV1::MAXIMA
};

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

/// `plugin_id` declaring ABI 0.0 and `budget`, negotiated by the V1 host under
/// the Local profile, which records no runtime and so no profile digest.
#[must_use]
pub fn negotiated_with(
    plugin_id: &str,
    budget: DeterministicBudgetV1,
    capabilities: Vec<PluginCapabilityDescriptorV1>,
) -> NegotiatedCommunityPluginV1 {
    let profile = CommunityPluginExecutionProfileV1::new(
        CommunityPluginModeV1::Local,
        CommunityPluginCeilingsV1::V1,
        None,
    );
    negotiated_under(plugin_id, budget, capabilities, &profile)
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
    let gated = GatedCommunityReleaseV1::for_test(execution, Vec::new());
    ok(negotiate_community_plugin_v1(
        &gated,
        &CommunityPluginHostAbiV1::v1(),
        profile,
    ))
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
            tick: 3,
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
        trust_policy_snapshot_digest: [4; 32],
        deterministic_budget_id: "budget".to_owned(),
        deterministic_random_domain: [7; 32],
        provenance_root: [5; 32],
    }
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
}
