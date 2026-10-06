//! Releases, invocations and guest values shared by this crate's unit tests.

use pos_crypto::plugin_execution::{
    DeterministicBudgetV1, PluginAbiRequirementV1, PluginCapabilityDescriptorV1,
    PluginExecutionProjectionFixtureV1, PluginExecutionProjectionV1,
};
use pos_runtime::community_plugin_host::{
    negotiate_community_plugin_v1, plugin_output_digest_v1, ArtifactRefV1,
    CommunityPluginCeilingsV1, CommunityPluginExecutionProfileV1, CommunityPluginHostAbiV1,
    CommunityPluginModeV1, EventDraftV1, MeteringV1, NegotiatedCommunityPluginV1,
    OperationalLogRecord, PluginDescriptorV1, PluginInvocationV1, PluginOutputV1,
    TimelinePositionV1, TraceAnnotationV1,
};

#[must_use]
pub fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
}

/// A release negotiated by the V1 host: ABI 0.0, one optional capability.
#[must_use]
pub fn negotiated() -> NegotiatedCommunityPluginV1 {
    let fixture = PluginExecutionProjectionFixtureV1 {
        pmf1_digest: [0x11; 32],
        release_digest: [0x22; 32],
        plugin_id: "plugin-a".to_owned(),
        abi: PluginAbiRequirementV1 {
            major: 0,
            min_minor: 0,
            max_minor: 0,
            required_features: Vec::new(),
        },
        capabilities: vec![PluginCapabilityDescriptorV1 {
            capability_id: "read".to_owned(),
            operation: "get".to_owned(),
            resource_pattern: "*".to_owned(),
            purpose: "test".to_owned(),
            audience: "local".to_owned(),
            required: false,
            max_calls: 1,
            max_request_bytes: 2,
            max_response_bytes: 3,
        }],
        budget: DeterministicBudgetV1::MAXIMA,
    };
    let profile = CommunityPluginExecutionProfileV1::new(
        CommunityPluginModeV1::Local,
        CommunityPluginCeilingsV1::V1,
        None,
    );
    let execution = PluginExecutionProjectionV1::from(fixture);
    ok(negotiate_community_plugin_v1(
        &execution,
        &CommunityPluginHostAbiV1::v1(),
        &profile,
    ))
}

#[must_use]
pub fn invocation() -> PluginInvocationV1 {
    let artifact = |schema_id| ArtifactRefV1 {
        schema_id,
        byte_length: 300,
        digest: [u8::try_from(schema_id).unwrap_or(0); 32],
    };
    PluginInvocationV1 {
        invocation_id: [0x33; 16],
        timeline_position: TimelinePositionV1 {
            timeline_id: [0x44; 16],
            seq: 70_000,
            tick: u64::MAX,
            scheduler_position: 24,
        },
        output_base_ordinal: 255,
        principal_ref: artifact(1),
        authorization_decision: artifact(2),
        observation_snapshot: artifact(3),
        observation_bytes: b"observation".to_vec(),
        prior_state_schema: [5; 32],
        prior_state_bytes: b"prior".to_vec(),
        execution_profile_digest: [6; 32],
        trust_policy_snapshot_digest: [7; 32],
        deterministic_budget_id: "budget".to_owned(),
        deterministic_random_domain: [8; 32],
        provenance_root: [9; 32],
    }
}

/// A valid output answering `invocation`, with one draft and annotation.
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

pub const METERING: MeteringV1 = MeteringV1 {
    startup_fuel: 1,
    call_fuel: 300,
    memory_bytes: 65_536,
    host_calls: 4_294_967_296,
};

#[must_use]
pub fn log() -> Vec<OperationalLogRecord> {
    vec![OperationalLogRecord {
        category: 2,
        message: "logged".to_owned(),
    }]
}
