//! The worker-side transport of a negotiated record (ADR-061 revision 6).
//!
//! The trusted supervisor negotiates a release, then sends the resulting
//! record to a fresh worker process as a [`NegotiatedTransportV1`]. The worker
//! rebuilds [`NegotiatedCommunityPluginV1`] with
//! [`NegotiatedCommunityPluginV1::from_transport`]: the only public way to
//! build a record besides [`super::negotiate_community_plugin_v1`]. It re-checks
//! every invariant negotiation establishes, against the worker's own host ABI
//! and execution profile, and takes the runtime identity from that profile,
//! never from the transport.

use pos_crypto::plugin_execution::{
    is_valid_id_v1, DeterministicBudgetV1, PluginCapabilityDescriptorV1, COMMUNITY_PLUGIN_WORLD_V1,
    WASM_PAGE_BYTES_V1,
};

use super::{
    CommunityPluginHostAbiV1, EffectiveExecutionLimitsV1, NegotiatedCommunityPluginV1,
    COMMUNITY_PLUGIN_ABI_MAJOR_V1,
};
use crate::community_plugin_host::profile::{
    CommunityPluginExecutionProfileV1, CommunityPluginModeV1, PinnedComponentRuntimeV1,
};

/// PMF1 V1 bound on capability descriptors (field 14).
const MAX_CAPABILITIES: usize = 256;

/// Every field of one negotiated record except the pinned runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedTransportV1 {
    /// The exact Component world.
    pub world: String,
    /// The PMF1 Plugin ID.
    pub plugin_id: String,
    /// BLAKE3-256 of the complete canonical PMF1 bytes.
    pub pmf1_digest: [u8; 32],
    /// The PMF1 release digest.
    pub release_digest: [u8; 32],
    /// The negotiated ABI major.
    pub abi_major: u16,
    /// The negotiated ABI minor.
    pub abi_minor: u16,
    /// The release's declared `(min, max)` ABI minors.
    pub declared_minors: (u16, u16),
    /// The required feature IDs, strictly increasing.
    pub required_features: Vec<String>,
    /// The declared optional capabilities, recorded as not granted.
    pub not_granted_capabilities: Vec<PluginCapabilityDescriptorV1>,
    /// The live mode of the negotiating profile.
    pub mode: CommunityPluginModeV1,
    /// The effective limits fixed at negotiation.
    pub limits: DeterministicBudgetV1,
    /// The digest of the negotiating profile, if it recorded a runtime.
    pub execution_profile_digest: Option<[u8; 32]>,
}

/// Why a transported record was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NegotiatedTransportErrorV1 {
    /// The world is not the V1 community Plugin world.
    #[error("transported community Plugin world is not the V1 world")]
    World,
    /// The Plugin ID does not match the PMF1 ID grammar.
    #[error("transported community Plugin ID is invalid")]
    PluginId,
    /// The ABI is not the one negotiation picks for this host.
    #[error("transported community Plugin ABI was not negotiated by this host")]
    Abi,
    /// A required feature is invalid, out of order, or not provided.
    #[error("transported community Plugin feature {index} is not acceptable")]
    Feature {
        /// Position in the required features.
        index: usize,
    },
    /// Too many capabilities, or a required one, which is never granted.
    #[error("transported community Plugin capabilities are not acceptable")]
    Capabilities,
    /// The mode differs from the worker's profile.
    #[error("transported community Plugin mode differs from the profile")]
    Mode,
    /// A limit is outside its PMF1 V1 range, not whole pages, or above the
    /// profile or WIT ceiling.
    #[error("transported community Plugin limits are not acceptable")]
    Limits,
    /// The worker's profile records no pinned runtime.
    #[error("community Plugin profile pins no runtime")]
    Runtime,
    /// The profile digest differs from the digest of the worker's profile.
    #[error("transported community Plugin profile digest differs from the profile")]
    ProfileDigest,
}

type Checked = Result<(), NegotiatedTransportErrorV1>;

impl NegotiatedCommunityPluginV1 {
    /// Every field the worker needs to rebuild this record.
    #[must_use]
    pub fn to_transport(&self) -> NegotiatedTransportV1 {
        NegotiatedTransportV1 {
            world: self.world.to_owned(),
            plugin_id: self.plugin_id.clone(),
            pmf1_digest: self.pmf1_digest,
            release_digest: self.release_digest,
            abi_major: COMMUNITY_PLUGIN_ABI_MAJOR_V1,
            abi_minor: self.abi_minor,
            declared_minors: self.declared_minors,
            required_features: self.required_features.clone(),
            not_granted_capabilities: self.not_granted_capabilities.clone(),
            mode: self.mode,
            limits: self.limits.values(),
            execution_profile_digest: self.execution_profile_digest,
        }
    }

    /// Rebuild a supervisor's record inside the worker process.
    ///
    /// `host` and `profile` are the worker's own; the record's runtime is the
    /// profile's pinned runtime.
    ///
    /// Capabilities are checked for their count and their `required` flag
    /// only. Their string fields are not re-validated against the PMF1
    /// grammar: the IPC decoder bounds their lengths, and the supervisor that
    /// sent them is trusted and took them from a validated release.
    ///
    /// # Errors
    /// Returns the first failed check, in this order: `World`, `PluginId`,
    /// `Abi` (major 0 and the highest minor common to the declared range and
    /// `host`), `Feature`, `Capabilities`, `Mode`, `Limits`, `Runtime` and
    /// `ProfileDigest` (the digest equals the digest of `profile`).
    pub fn from_transport(
        transport: NegotiatedTransportV1,
        host: &CommunityPluginHostAbiV1,
        profile: &CommunityPluginExecutionProfileV1,
    ) -> Result<Self, NegotiatedTransportErrorV1> {
        check(
            transport.world == COMMUNITY_PLUGIN_WORLD_V1,
            NegotiatedTransportErrorV1::World,
        )?;
        check(
            is_valid_id_v1(&transport.plugin_id),
            NegotiatedTransportErrorV1::PluginId,
        )?;
        check(
            negotiated_abi(&transport, host),
            NegotiatedTransportErrorV1::Abi,
        )?;
        features(&transport.required_features, host)?;
        check(
            optional_only(&transport.not_granted_capabilities),
            NegotiatedTransportErrorV1::Capabilities,
        )?;
        check(
            transport.mode == profile.mode(),
            NegotiatedTransportErrorV1::Mode,
        )?;
        check(
            limits_fit(transport.limits, profile),
            NegotiatedTransportErrorV1::Limits,
        )?;
        let runtime = profile_runtime(&transport, profile)?;
        Ok(Self {
            world: COMMUNITY_PLUGIN_WORLD_V1,
            plugin_id: transport.plugin_id,
            pmf1_digest: transport.pmf1_digest,
            release_digest: transport.release_digest,
            abi_minor: transport.abi_minor,
            declared_minors: transport.declared_minors,
            required_features: transport.required_features,
            not_granted_capabilities: transport.not_granted_capabilities,
            mode: transport.mode,
            limits: EffectiveExecutionLimitsV1 {
                limits: transport.limits,
            },
            runtime: Some(runtime),
            execution_profile_digest: transport.execution_profile_digest,
        })
    }
}

/// The profile's pinned runtime, once the transported digest is the profile's.
fn profile_runtime(
    transport: &NegotiatedTransportV1,
    profile: &CommunityPluginExecutionProfileV1,
) -> Result<PinnedComponentRuntimeV1, NegotiatedTransportErrorV1> {
    let runtime = profile
        .runtime()
        .cloned()
        .ok_or(NegotiatedTransportErrorV1::Runtime)?;
    check(
        transport.execution_profile_digest == profile.digest(),
        NegotiatedTransportErrorV1::ProfileDigest,
    )?;
    Ok(runtime)
}

const fn check(valid: bool, error: NegotiatedTransportErrorV1) -> Checked {
    if valid {
        Ok(())
    } else {
        Err(error)
    }
}

/// Major 0, and the minor negotiation picks: the highest common one.
fn negotiated_abi(transport: &NegotiatedTransportV1, host: &CommunityPluginHostAbiV1) -> bool {
    let (declared_min, declared_max) = transport.declared_minors;
    let lowest = declared_min.max(host.min_minor());
    let highest = declared_max.min(host.max_minor());
    transport.abi_major == COMMUNITY_PLUGIN_ABI_MAJOR_V1
        && lowest <= highest
        && transport.abi_minor == highest
}

/// Valid IDs, strictly increasing, each provided by `host`.
fn features(required: &[String], host: &CommunityPluginHostAbiV1) -> Checked {
    let ordered = |index: usize| index == 0 || required[index - 1] < required[index];
    required
        .iter()
        .enumerate()
        .position(|(index, feature)| {
            !(is_valid_id_v1(feature) && ordered(index) && host.features().contains(feature))
        })
        .map_or(Ok(()), |index| {
            Err(NegotiatedTransportErrorV1::Feature { index })
        })
}

fn optional_only(capabilities: &[PluginCapabilityDescriptorV1]) -> bool {
    capabilities.len() <= MAX_CAPABILITIES
        && capabilities.iter().all(|capability| !capability.required)
}

/// Within the PMF1 V1 ranges, whole pages, and a fixed point of clamping.
fn limits_fit(limits: DeterministicBudgetV1, profile: &CommunityPluginExecutionProfileV1) -> bool {
    let minima = DeterministicBudgetV1::MINIMA;
    limits.memory_bytes >= minima.memory_bytes
        && limits.memory_bytes.is_multiple_of(WASM_PAGE_BYTES_V1)
        && limits.fuel >= minima.fuel
        && EffectiveExecutionLimitsV1::clamp(limits, profile.ceilings()).values() == limits
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
