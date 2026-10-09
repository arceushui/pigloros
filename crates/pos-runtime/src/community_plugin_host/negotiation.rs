//! ABI negotiation, capability attenuation and budget clamping (ADR-061).
//!
//! Negotiation runs after release trust and before any worker exists. It
//! fixes the ABI minor, the not-granted capabilities and the effective limits
//! that the invocation, its result and the `ReproManifest` record.

use pos_crypto::plugin_execution::{
    is_valid_id_v1, DeterministicBudgetV1, PluginAbiRequirementV1, PluginCapabilityDescriptorV1,
    PluginExecutionProjectionV1, COMMUNITY_PLUGIN_WORLD_V1,
};

use super::error::CommunityPluginHostErrorV1;
use super::profile::{
    CommunityPluginCeilingsV1, CommunityPluginExecutionProfileV1, CommunityPluginModeV1,
    PinnedComponentRuntimeV1,
};

mod transport;

pub use transport::{NegotiatedTransportErrorV1, NegotiatedTransportV1};

/// The only ABI major of the community Plugin world in ABI 0.x.
pub const COMMUNITY_PLUGIN_ABI_MAJOR_V1: u16 = 0;

/// A rejected host ABI declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CommunityPluginHostAbiErrorV1 {
    /// The lowest supported minor is above the highest.
    #[error("community Plugin host ABI minor range is empty")]
    EmptyMinorRange,
    /// A feature ID does not match the PMF1 ID grammar.
    #[error("community Plugin host feature {index} is not a valid ID")]
    InvalidFeature {
        /// Position in the feature list.
        index: usize,
    },
    /// A feature ID does not strictly follow the one before it.
    #[error("community Plugin host feature {index} is out of order")]
    UnorderedFeature {
        /// Position in the feature list.
        index: usize,
    },
}

/// The ABI this host supports for `pigloros:plugin/community-plugin@0.1.0`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityPluginHostAbiV1 {
    min_minor: u16,
    max_minor: u16,
    features: Vec<String>,
}

impl CommunityPluginHostAbiV1 {
    /// The V1 host: ABI 0.0 only, with no optional feature.
    ///
    /// Minor 0 is the baseline ABI defined by the package
    /// `pigloros:plugin@0.1.0`. Any added import, export, record field,
    /// variant case or changed bound increments the minor.
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
    /// # Errors
    /// Returns `EmptyMinorRange` when `min_minor > max_minor`, then
    /// `InvalidFeature` for the first feature outside the PMF1 ID grammar,
    /// then `UnorderedFeature` for the first feature that is not strictly
    /// greater than the one before it.
    pub fn new(
        min_minor: u16,
        max_minor: u16,
        features: Vec<String>,
    ) -> Result<Self, CommunityPluginHostAbiErrorV1> {
        let failure = (min_minor > max_minor)
            .then_some(CommunityPluginHostAbiErrorV1::EmptyMinorRange)
            .or_else(|| feature_failure(&features));
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(Self {
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

    /// The feature IDs this host provides, strictly increasing.
    #[must_use]
    pub fn features(&self) -> &[String] {
        &self.features
    }
}

/// The first invalid or out-of-order feature ID.
fn feature_failure(features: &[String]) -> Option<CommunityPluginHostAbiErrorV1> {
    let invalid = features
        .iter()
        .position(|feature| !is_valid_id_v1(feature))
        .map(|index| CommunityPluginHostAbiErrorV1::InvalidFeature { index });
    let unordered = features
        .iter()
        .zip(features.iter().skip(1))
        .position(|(earlier, later)| earlier >= later)
        .map(|index| CommunityPluginHostAbiErrorV1::UnorderedFeature { index: index + 1 });
    invalid.or(unordered)
}

/// The effective deterministic limits fixed at negotiation.
///
/// Five members are `min(PMF1 budget, profile ceiling)`; `event_count`,
/// `state_bytes` and `log_calls` are `min(PMF1 budget, WIT ceiling)`. A
/// budget above a ceiling is clamped, never rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectiveExecutionLimitsV1 {
    limits: DeterministicBudgetV1,
}

impl EffectiveExecutionLimitsV1 {
    /// Clamp `budget` by `ceilings` and the WIT ceilings.
    #[must_use]
    pub fn clamp(budget: DeterministicBudgetV1, ceilings: CommunityPluginCeilingsV1) -> Self {
        Self {
            limits: ceilings.clamp(budget),
        }
    }

    /// The effective value of every budget member.
    #[must_use]
    pub const fn values(&self) -> DeterministicBudgetV1 {
        self.limits
    }
}

/// The negotiated execution tuple of one community Plugin release.
///
/// It is `ReproManifest` input: world, release identity, negotiated ABI,
/// not-granted capabilities, mode, effective limits, the pinned runtime and
/// the digest of the execution profile.
/// Only [`negotiate_community_plugin_v1`] constructs it; a worker process
/// rebuilds the supervisor's record with
/// [`NegotiatedCommunityPluginV1::from_transport`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedCommunityPluginV1 {
    world: &'static str,
    plugin_id: String,
    pmf1_digest: [u8; 32],
    release_digest: [u8; 32],
    abi_minor: u16,
    declared_minors: (u16, u16),
    required_features: Vec<String>,
    not_granted_capabilities: Vec<PluginCapabilityDescriptorV1>,
    mode: CommunityPluginModeV1,
    limits: EffectiveExecutionLimitsV1,
    runtime: Option<PinnedComponentRuntimeV1>,
    execution_profile_digest: Option<[u8; 32]>,
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

    /// The release's declared `(min, max)` ABI minors, PMF1 fields 6 and 7.
    ///
    /// The guest's `describe` must declare exactly this range.
    #[must_use]
    pub const fn declared_minor_range(&self) -> (u16, u16) {
        self.declared_minors
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

    /// The digest of the profile used, or `None` when it recorded no runtime.
    ///
    /// A record with no digest is refused at launch by the Driver binding
    /// check (#583); this slice only records it.
    #[must_use]
    pub const fn execution_profile_digest(&self) -> Option<[u8; 32]> {
        self.execution_profile_digest
    }
}

/// Negotiate one validated release against the host ABI and profile.
///
/// The checks run in ADR-061 validation order: ABI major and highest common
/// minor, every required feature, then capability attenuation. Budgets are
/// then clamped. No worker exists yet, so a failure launches nothing.
///
/// This function cannot check that `execution` is bound to an authorized
/// release. #544 must wrap it behind `PluginExecutionProjectionV1::is_bound_to`
/// and the trust-authorization gate before it becomes the public host
/// surface; until then it is not the #194 surface.
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
