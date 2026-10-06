//! Releases, executions and invocations shared by the engine test suites.

use pos_crypto::plugin_execution::{
    DeterministicBudgetV1, PluginAbiRequirementV1, PluginExecutionProjectionFixtureV1,
    PluginExecutionProjectionV1,
};
use pos_plugin_host::{pinned_runtime, PinnedExecutionV1};
use pos_runtime::community_plugin_host::{
    negotiate_community_plugin_v1, ArtifactRefV1, CommunityPluginCeilingsV1,
    CommunityPluginExecutionProfileV1, CommunityPluginHostAbiV1, CommunityPluginModeV1, HostInputs,
    InvocationOptionsV1, NegotiatedCommunityPluginV1, PinnedComponentRuntimeV1, PluginInvocationV1,
    TimelinePositionV1,
};

/// The compatibility Rust guest.
pub const RUST_GUEST: &[u8] = include_bytes!(
    "../../../../plugins/community/examples/compatibility-prototype/fixtures/rust-guest.wasm"
);
/// The Plugin ID both compatibility guests describe.
pub const PLUGIN_ID: &str = "pigloros.compatibility-prototype";
/// The release's declared budget; the V1 profile clamps memory and fuel.
pub const BUDGET: DeterministicBudgetV1 = DeterministicBudgetV1::MAXIMA;
/// The invocation ID of [`invocation`].
pub const INVOCATION_ID: [u8; 16] = [0x11; 16];
/// The random domain of [`invocation`].
pub const DOMAIN: [u8; 32] = [7; 32];
/// The timeline sequence number of [`invocation`].
pub const SEQ: u64 = 11;
/// The artifact reference every test invocation uses.
pub const ARTIFACT: ArtifactRefV1 = ArtifactRefV1 {
    schema_id: 1,
    byte_length: 0,
    digest: [0; 32],
};

/// The value of `result`, or a test failure naming `context`.
pub fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, context: &str) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("{context}: {error:?}")))
    })
}

/// Invocation options with `simulation_time` and `watchdog_epochs`.
#[must_use]
pub const fn options(simulation_time: u64, watchdog_epochs: u32) -> InvocationOptionsV1 {
    InvocationOptionsV1 {
        host_inputs: HostInputs { simulation_time },
        watchdog_epochs,
    }
}

/// A release declaring ABI `0.0..=0.max_minor` and `features`.
#[must_use]
pub fn release(
    plugin_id: &str,
    max_minor: u16,
    features: &[&str],
    budget: DeterministicBudgetV1,
) -> PluginExecutionProjectionV1 {
    PluginExecutionProjectionV1::from(PluginExecutionProjectionFixtureV1 {
        pmf1_digest: [1; 32],
        release_digest: [2; 32],
        plugin_id: plugin_id.to_owned(),
        abi: PluginAbiRequirementV1 {
            major: 0,
            min_minor: 0,
            max_minor,
            required_features: features.iter().map(|id| (*id).to_owned()).collect(),
        },
        capabilities: Vec::new(),
        budget,
    })
}

/// `release` negotiated under the V1 Local profile recording `runtime`.
#[must_use]
pub fn negotiate(
    release: &PluginExecutionProjectionV1,
    host: &CommunityPluginHostAbiV1,
    runtime: Option<PinnedComponentRuntimeV1>,
) -> NegotiatedCommunityPluginV1 {
    let profile = CommunityPluginExecutionProfileV1::new(
        CommunityPluginModeV1::Local,
        CommunityPluginCeilingsV1::V1,
        runtime,
    );
    ok(
        negotiate_community_plugin_v1(release, host, &profile),
        "negotiation",
    )
}

/// `release` negotiated under a profile that pins this engine's runtime.
#[must_use]
pub fn pinned(
    release: &PluginExecutionProjectionV1,
    host: &CommunityPluginHostAbiV1,
) -> PinnedExecutionV1 {
    let runtime = ok(pinned_runtime(), "pinned runtime");
    ok(
        PinnedExecutionV1::new(negotiate(release, host, Some(runtime))),
        "pinned execution",
    )
}

/// The compatibility release under the default V1 profile with `budget`.
#[must_use]
pub fn execution(budget: DeterministicBudgetV1) -> PinnedExecutionV1 {
    pinned(
        &release(PLUGIN_ID, 0, &[], budget),
        &CommunityPluginHostAbiV1::v1(),
    )
}

/// An invocation of the compatibility behaviour with `observation`.
#[must_use]
pub fn invocation(observation: &[u8]) -> PluginInvocationV1 {
    PluginInvocationV1 {
        invocation_id: INVOCATION_ID,
        timeline_position: TimelinePositionV1 {
            timeline_id: [0x22; 16],
            seq: SEQ,
            tick: 3,
            scheduler_position: 0,
        },
        output_base_ordinal: 0,
        principal_ref: ARTIFACT,
        authorization_decision: ARTIFACT,
        observation_snapshot: ARTIFACT,
        observation_bytes: observation.to_vec(),
        prior_state_schema: [2; 32],
        prior_state_bytes: b"prior".to_vec(),
        execution_profile_digest: [3; 32],
        trust_policy_snapshot_digest: [4; 32],
        deterministic_budget_id: "budget".to_owned(),
        deterministic_random_domain: DOMAIN,
        provenance_root: [5; 32],
    }
}
