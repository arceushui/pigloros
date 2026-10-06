//! ABI negotiation, capability attenuation and budget clamping (ADR-061).
//!
//! Negotiation runs after release trust and before any worker exists. It
//! fixes the ABI minor, the not-granted capabilities and the effective limits
//! that the invocation, its result and the `ReproManifest` record.

use pos_crypto::plugin_execution::{
    DeterministicBudgetV1, PluginAbiRequirementV1, PluginCapabilityDescriptorV1,
    PluginExecutionProjectionV1, COMMUNITY_PLUGIN_WORLD_V1,
};

use super::error::CommunityPluginHostErrorV1;
use super::profile::{
    CommunityPluginCeilingsV1, CommunityPluginExecutionProfileV1, CommunityPluginModeV1,
    PinnedComponentRuntimeV1,
};

/// The only ABI major of the community Plugin world in ABI 0.x.
pub const COMMUNITY_PLUGIN_ABI_MAJOR_V1: u16 = 0;
/// WIT ceiling on `EventDrafts` per invocation.
pub const WIT_EVENT_COUNT_CEILING_V1: u64 = 1_024;
/// WIT ceiling on staged state bytes (1 MiB).
pub const WIT_STATE_BYTES_CEILING_V1: u64 = 1_048_576;
/// WIT ceiling on `record-operational-log` calls per invocation.
pub const WIT_LOG_CALLS_CEILING_V1: u64 = 64;
/// WIT ceiling on one operational log message in bytes.
pub const WIT_LOG_MESSAGE_BYTES_CEILING_V1: u64 = 256;

/// The ABI this host supports for `pigloros:plugin/community-plugin@0.1.0`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityPluginHostAbiV1 {
    min_minor: u16,
    max_minor: u16,
    features: Vec<String>,
}

impl CommunityPluginHostAbiV1 {
    /// The V1 host: ABI 0.0 only, with no optional feature.
    #[must_use]
    pub const fn v1() -> Self {
        Self {
            min_minor: 0,
            max_minor: 0,
            features: Vec::new(),
        }
    }

    /// A host supporting minors `min_minor..=max_minor` and `features`.
    ///
    /// Returns `None` when `min_minor > max_minor`.
    #[must_use]
    pub fn new(min_minor: u16, max_minor: u16, features: Vec<String>) -> Option<Self> {
        (min_minor <= max_minor).then_some(Self {
            min_minor,
            max_minor,
            features,
        })
    }

    /// The lowest supported ABI minor.
    #[must_use]
    pub const fn min_minor(&self) -> u16 {
        self.min_minor
    }

    /// The highest supported ABI minor.
    #[must_use]
    pub const fn max_minor(&self) -> u16 {
        self.max_minor
    }

    /// The feature IDs this host provides.
    #[must_use]
    pub fn features(&self) -> &[String] {
        &self.features
    }
}

/// The effective deterministic limits fixed at negotiation.
///
/// Five members are `min(PMF1 budget, profile ceiling)`; `event_count`,
/// `state_bytes` and `log_calls` are `min(PMF1 budget, WIT ceiling)`. A
/// budget above a ceiling is clamped, never rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectiveExecutionLimitsV1 {
    /// Linear memory bytes, a whole number of pages.
    pub memory_bytes: u64,
    /// Wasmtime fuel.
    pub fuel: u64,
    /// Host import calls.
    pub host_calls: u64,
    /// `EventDraft` count.
    pub event_count: u64,
    /// Total `EventDraft` bytes.
    pub event_bytes: u64,
    /// Staged state bytes.
    pub state_bytes: u64,
    /// `record-operational-log` calls.
    pub log_calls: u64,
    /// Total operational log bytes.
    pub log_bytes: u64,
}

impl EffectiveExecutionLimitsV1 {
    /// Clamp `budget` by `ceilings` and the WIT ceilings.
    #[must_use]
    pub fn clamp(budget: DeterministicBudgetV1, ceilings: CommunityPluginCeilingsV1) -> Self {
        Self {
            memory_bytes: budget.memory_bytes.min(ceilings.memory_bytes()),
            fuel: budget.fuel.min(ceilings.fuel()),
            host_calls: budget.host_calls.min(ceilings.host_calls()),
            event_count: budget.event_count.min(WIT_EVENT_COUNT_CEILING_V1),
            event_bytes: budget.event_bytes.min(ceilings.event_bytes()),
            state_bytes: budget.state_bytes.min(WIT_STATE_BYTES_CEILING_V1),
            log_calls: budget.log_calls.min(WIT_LOG_CALLS_CEILING_V1),
            log_bytes: budget.log_bytes.min(ceilings.log_bytes()),
        }
    }
}

/// The negotiated execution tuple of one community Plugin release.
///
/// It is `ReproManifest` input: world, release identity, negotiated ABI,
/// not-granted capabilities, mode, effective limits and the pinned runtime.
/// Only [`negotiate_community_plugin_v1`] constructs it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedCommunityPluginV1 {
    world: &'static str,
    plugin_id: String,
    pmf1_digest: [u8; 32],
    release_digest: [u8; 32],
    abi_minor: u16,
    required_features: Vec<String>,
    not_granted_capabilities: Vec<PluginCapabilityDescriptorV1>,
    mode: CommunityPluginModeV1,
    limits: EffectiveExecutionLimitsV1,
    runtime: Option<PinnedComponentRuntimeV1>,
}

impl NegotiatedCommunityPluginV1 {
    /// The exact Component world.
    #[must_use]
    pub const fn world(&self) -> &'static str {
        self.world
    }

    /// The PMF1 Plugin ID.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// BLAKE3-256 of the complete canonical PMF1 bytes.
    #[must_use]
    pub const fn pmf1_digest(&self) -> [u8; 32] {
        self.pmf1_digest
    }

    /// The PMF1 release digest.
    #[must_use]
    pub const fn release_digest(&self) -> [u8; 32] {
        self.release_digest
    }

    /// The negotiated `(major, minor)` ABI.
    #[must_use]
    pub const fn abi(&self) -> (u16, u16) {
        (COMMUNITY_PLUGIN_ABI_MAJOR_V1, self.abi_minor)
    }

    /// The required features, every one provided by the host.
    #[must_use]
    pub fn required_features(&self) -> &[String] {
        &self.required_features
    }

    /// Every declared optional capability, recorded as not granted.
    ///
    /// ABI 0.x has no capability-mediated import, so none is ever granted.
    #[must_use]
    pub fn not_granted_capabilities(&self) -> &[PluginCapabilityDescriptorV1] {
        &self.not_granted_capabilities
    }

    /// The live mode of the profile used.
    #[must_use]
    pub const fn mode(&self) -> CommunityPluginModeV1 {
        self.mode
    }

    /// The effective limits fixed before execution.
    #[must_use]
    pub const fn limits(&self) -> EffectiveExecutionLimitsV1 {
        self.limits
    }

    /// The pinned runtime identity the profile recorded, if any yet.
    #[must_use]
    pub const fn runtime(&self) -> Option<&PinnedComponentRuntimeV1> {
        self.runtime.as_ref()
    }
}

/// Negotiate one validated release against the host ABI and profile.
///
/// The checks run in ADR-061 validation order: ABI major and highest common
/// minor, every required feature, then capability attenuation. Budgets are
/// then clamped. No worker exists yet, so a failure launches nothing.
///
/// # Errors
/// Returns `IncompatibleAbi` for an ABI major other than 0 or no common
/// minor, `MissingFeature` for the first required feature the host lacks,
/// and `CapabilityDenied` for the first required capability.
pub fn negotiate_community_plugin_v1(
    execution: &PluginExecutionProjectionV1,
    host: &CommunityPluginHostAbiV1,
    profile: &CommunityPluginExecutionProfileV1,
) -> Result<NegotiatedCommunityPluginV1, CommunityPluginHostErrorV1> {
    let abi_minor = negotiate_minor(execution.abi(), host)?;
    require_features(execution.abi(), host)?;
    let not_granted_capabilities = attenuate(execution.capabilities())?;
    Ok(NegotiatedCommunityPluginV1 {
        world: COMMUNITY_PLUGIN_WORLD_V1,
        plugin_id: execution.plugin_id().to_owned(),
        pmf1_digest: execution.pmf1_digest(),
        release_digest: execution.release_digest(),
        abi_minor,
        required_features: execution.abi().required_features.clone(),
        not_granted_capabilities,
        mode: profile.mode(),
        limits: EffectiveExecutionLimitsV1::clamp(execution.budget(), profile.ceilings()),
        runtime: profile.runtime().cloned(),
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
