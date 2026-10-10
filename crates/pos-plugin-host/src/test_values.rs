//! Canonical ABI values and host values shared by the unit tests.

use pos_crypto::plugin_execution::{
    DeterministicBudgetV1, PluginAbiRequirementV1, PluginExecutionProjectionFixtureV1,
    PluginExecutionProjectionV1,
};
use pos_runtime::community_plugin_host::{
    negotiate_community_plugin_v1, ArtifactRefV1, CommunityPluginCeilingsV1,
    CommunityPluginExecutionProfileV1, CommunityPluginHostAbiV1, CommunityPluginModeV1,
    GatedCommunityReleaseV1, NegotiatedCommunityPluginV1, PinnedComponentRuntimeV1,
    PluginInvocationV1, TimelinePositionV1, MAX_OBSERVATION_BYTES_V1, MAX_STATE_BYTES_V1,
};
use wasmtime::component::Val;

use crate::engine::PinnedExecutionV1;
use crate::lift::widen;
use crate::runtime::pinned_runtime;

pub(crate) use crate::lower::{byte_list, record};

/// The value of `result`, or a test failure showing the error.
pub(crate) fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
}

/// A release of `plugin-a` declaring ABI `0.0..=0.max_minor` and `features`.
pub(crate) fn release(max_minor: u16, features: &[&str]) -> PluginExecutionProjectionV1 {
    PluginExecutionProjectionV1::from(PluginExecutionProjectionFixtureV1 {
        pmf1_digest: [1; 32],
        release_digest: [2; 32],
        plugin_id: "plugin-a".to_owned(),
        abi: PluginAbiRequirementV1 {
            major: 0,
            min_minor: 0,
            max_minor,
            required_features: features.iter().map(|id| (*id).to_owned()).collect(),
        },
        capabilities: Vec::new(),
        budget: DeterministicBudgetV1::MAXIMA,
    })
}

/// `release` negotiated against `host` under the V1 Local profile recording
/// `runtime`.
pub(crate) fn negotiate(
    release: &PluginExecutionProjectionV1,
    host: &CommunityPluginHostAbiV1,
    runtime: Option<PinnedComponentRuntimeV1>,
) -> NegotiatedCommunityPluginV1 {
    let profile = CommunityPluginExecutionProfileV1::new(
        CommunityPluginModeV1::Local,
        CommunityPluginCeilingsV1::V1,
        runtime,
    );
    let gated = GatedCommunityReleaseV1::for_test(release.clone(), Vec::new());
    ok(negotiate_community_plugin_v1(&gated, host, &profile))
}

/// The `plugin-a` release under the V1 host and a profile that pins this
/// engine's runtime.
pub(crate) fn execution() -> PinnedExecutionV1 {
    let runtime = ok(pinned_runtime());
    let negotiated = negotiate(
        &release(0, &[]),
        &CommunityPluginHostAbiV1::v1(),
        Some(runtime),
    );
    ok(PinnedExecutionV1::new(negotiated))
}

/// The artifact reference every test invocation uses.
pub(crate) const ARTIFACT: ArtifactRefV1 = ArtifactRefV1 {
    schema_id: 1,
    byte_length: 0,
    digest: [0; 32],
};

/// A `digest32` value of any length.
pub(crate) fn digest_val(bytes: &[u8]) -> Val {
    record(vec![("value", byte_list(bytes))])
}

/// A `list<digest32>` value.
pub(crate) fn digests_val(digests: &[[u8; 32]]) -> Val {
    Val::List(digests.iter().map(|digest| digest_val(digest)).collect())
}

/// A `bounded-text` value.
pub(crate) fn text_val(text: &str) -> Val {
    record(vec![("utf8", byte_list(text.as_bytes()))])
}

/// A 32-byte digest whose first eight bytes are `index`, big-endian.
pub(crate) fn numbered_digest(index: usize) -> [u8; 32] {
    let mut digest = [0; 32];
    digest[..8].copy_from_slice(&widen(index).to_be_bytes());
    digest
}

/// An invocation at its WIT bounds.
pub(crate) fn invocation() -> PluginInvocationV1 {
    PluginInvocationV1 {
        invocation_id: [1; 16],
        timeline_position: TimelinePositionV1 {
            timeline_id: [2; 16],
            seq: 3,
            tick: 4,
            scheduler_position: 5,
        },
        output_base_ordinal: 6,
        principal_ref: ARTIFACT,
        authorization_decision: ARTIFACT,
        observation_snapshot: ARTIFACT,
        observation_bytes: vec![0; MAX_OBSERVATION_BYTES_V1],
        prior_state_schema: [7; 32],
        prior_state_bytes: vec![0; MAX_STATE_BYTES_V1],
        execution_profile_digest: [8; 32],
        trust_policy_snapshot_digest: [9; 32],
        deterministic_budget_id: "budget".to_owned(),
        deterministic_random_domain: [10; 32],
        provenance_root: [11; 32],
    }
}
