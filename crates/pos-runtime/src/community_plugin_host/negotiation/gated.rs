//! The Linux-only negotiation of one gated release (ADR-061 revision 7 decision 2).

use pos_crypto::plugin_execution::{
    PluginAbiRequirementV1, PluginCapabilityDescriptorV1, COMMUNITY_PLUGIN_WORLD_V1,
};

use super::{
    CommunityPluginHostAbiV1, EffectiveExecutionLimitsV1, NegotiatedCommunityPluginV1,
    COMMUNITY_PLUGIN_ABI_MAJOR_V1,
};
use crate::community_plugin_host::error::CommunityPluginHostErrorV1;
use crate::community_plugin_host::gate::GatedCommunityReleaseV1;
use crate::community_plugin_host::profile::CommunityPluginExecutionProfileV1;

/// Negotiate one validated release against the host ABI and profile.
///
/// The checks run in ADR-061 validation order: ABI major and highest common
/// minor, every required feature, then capability attenuation. Budgets are
/// then clamped. No worker exists yet, so a failure launches nothing.
///
/// It takes the output of the execution-time trust gate, so the projection is
/// bound to a release that was authorized at the gate's own UTC second and Tick.
/// Negotiation confers no authority to execute at any other Tick. The function
/// exists on Linux only, like the gate; elsewhere a community Plugin cannot be
/// negotiated, which fails closed by absence.
///
/// # Errors
/// Returns `IncompatibleAbi` for an ABI major other than 0 or no common
/// minor, `MissingFeature` for the first required feature the host lacks,
/// and `CapabilityDenied` for the first required capability.
pub fn negotiate_community_plugin_v1(
    gated: &GatedCommunityReleaseV1,
    host: &CommunityPluginHostAbiV1,
    profile: &CommunityPluginExecutionProfileV1,
) -> Result<NegotiatedCommunityPluginV1, CommunityPluginHostErrorV1> {
    let execution = gated.execution();
    let abi_minor = negotiate_minor(execution.abi(), host)?;
    require_features(execution.abi(), host)?;
    let not_granted_capabilities = attenuate(execution.capabilities())?;
    Ok(NegotiatedCommunityPluginV1 {
        world: COMMUNITY_PLUGIN_WORLD_V1,
        plugin_id: execution.plugin_id().to_owned(),
        pmf1_digest: execution.pmf1_digest(),
        release_digest: execution.release_digest(),
        abi_minor,
        declared_minors: (execution.abi().min_minor, execution.abi().max_minor),
        required_features: execution.abi().required_features.clone(),
        not_granted_capabilities,
        mode: profile.mode(),
        limits: EffectiveExecutionLimitsV1::clamp(execution.budget(), profile.ceilings()),
        runtime: profile.runtime().cloned(),
        execution_profile_digest: profile.digest(),
    })
}

/// ABI major 0 and the highest minor both sides support.
fn negotiate_minor(
    abi: &PluginAbiRequirementV1,
    host: &CommunityPluginHostAbiV1,
) -> Result<u16, CommunityPluginHostErrorV1> {
    let lowest = abi.min_minor.max(host.min_minor);
    let highest = abi.max_minor.min(host.max_minor);
    let compatible = abi.major == COMMUNITY_PLUGIN_ABI_MAJOR_V1 && lowest <= highest;
    compatible
        .then_some(highest)
        .ok_or(CommunityPluginHostErrorV1::IncompatibleAbi)
}

/// Every required feature is one the host provides.
fn require_features(
    abi: &PluginAbiRequirementV1,
    host: &CommunityPluginHostAbiV1,
) -> Result<(), CommunityPluginHostErrorV1> {
    abi.required_features
        .iter()
        .position(|feature| !host.features.contains(feature))
        .map_or(Ok(()), |index| {
            Err(CommunityPluginHostErrorV1::MissingFeature { index })
        })
}

/// Deny every required capability; record every optional one as not granted.
fn attenuate(
    capabilities: &[PluginCapabilityDescriptorV1],
) -> Result<Vec<PluginCapabilityDescriptorV1>, CommunityPluginHostErrorV1> {
    capabilities
        .iter()
        .position(|capability| capability.required)
        .map_or_else(
            || Ok(capabilities.to_vec()),
            |index| Err(CommunityPluginHostErrorV1::CapabilityDenied { index }),
        )
}
