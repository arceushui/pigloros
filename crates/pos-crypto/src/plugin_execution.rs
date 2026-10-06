//! PMF1 V1 execution requirements of one validated release (ADR-061 revision 4).
//!
//! The PMF1 V1 codec validates the ABI requirement (fields 5-8), the
//! capability descriptors (field 14) and the `DeterministicBudgetV1` (field 15).
//! [`PluginExecutionProjectionV1`] retains them for the community Plugin
//! host's negotiation. It is built only by the same strict decoder, closure
//! binder and digest checks as the ADR-103 release projection, so it carries
//! no value that the full PMF1 validation did not accept. It is not a trust,
//! admission or capability grant.

use pos_plugin_release::VerifiedReleaseBundleV1;

use crate::plugin_manifest::{self, PluginManifestErrorV1};
use crate::plugin_trust::ValidatedPluginManifestProjectionV1;

/// The exact Component world every PMF1 V1 release targets (field 4).
pub const COMMUNITY_PLUGIN_WORLD_V1: &str = "pigloros:plugin/community-plugin@0.1.0";

/// The PMF1 V1 ABI requirement: fields 5-8.
///
/// The codec accepted major `0`, `min_minor <= max_minor`, and strictly
/// increasing ID-grammar feature IDs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginAbiRequirementV1 {
    /// Field 5: ABI major.
    pub major: u16,
    /// Field 6: lowest acceptable ABI minor.
    pub min_minor: u16,
    /// Field 7: highest acceptable ABI minor.
    pub max_minor: u16,
    /// Field 8: required feature IDs, strictly increasing.
    pub required_features: Vec<String>,
}

/// One PMF1 V1 `CapabilityDescriptorV1` (field 14, revision 3 section 3.2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginCapabilityDescriptorV1 {
    /// ID-grammar capability ID.
    pub capability_id: String,
    /// ID-grammar operation.
    pub operation: String,
    /// Bounded resource pattern label.
    pub resource_pattern: String,
    /// Bounded purpose label.
    pub purpose: String,
    /// Bounded audience label.
    pub audience: String,
    /// Whether the release cannot run without this capability.
    pub required: bool,
    /// Declared call bound.
    pub max_calls: u64,
    /// Declared request byte bound.
    pub max_request_bytes: u64,
    /// Declared response byte bound.
    pub max_response_bytes: u64,
}

/// The PMF1 V1 `DeterministicBudgetV1` (field 15, revision 3 section 3.3).
///
/// These are the manifest's declared protocol upper bounds. The host's
/// execution profile may lower them at negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeterministicBudgetV1 {
    /// Linear memory bytes, a multiple of 65,536.
    pub memory_bytes: u64,
    /// Wasmtime fuel under the pinned runtime.
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
    /// Total operational log message bytes.
    pub log_bytes: u64,
}

/// The execution requirements of one fully validated PMF1 V1 release.
///
/// The only production constructor is [`Self::from_verified_bundle`]. Its
/// fields are crate-private, so a caller cannot assemble requirements that
/// the PMF1 V1 validation did not accept.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginExecutionProjectionV1 {
    pub(crate) pmf1_digest: [u8; 32],
    pub(crate) release_digest: [u8; 32],
    pub(crate) plugin_id: String,
    pub(crate) abi: PluginAbiRequirementV1,
    pub(crate) capabilities: Vec<PluginCapabilityDescriptorV1>,
    pub(crate) budget: DeterministicBudgetV1,
}

impl PluginExecutionProjectionV1 {
    /// Project the execution requirements of one verified OCI release closure.
    ///
    /// It runs the complete ADR-061 revision 3 validation that
    /// [`ValidatedPluginManifestProjectionV1::from_verified_bundle`] runs, in
    /// the same order, and yields the same first failure.
    ///
    /// # Errors
    /// Returns the first PMF1 V1 decode, closure, inner-digest, or
    /// manifest/release-digest failure, and no projection.
    pub fn from_verified_bundle(
        bundle: &VerifiedReleaseBundleV1,
    ) -> Result<Self, PluginManifestErrorV1> {
        plugin_manifest::project_execution(bundle)
    }

    /// Whether this projection and `manifest` come from the same PMF1 bytes.
    ///
    /// Both bind the complete-PMF1 digest and the release digest; the host
    /// pairs execution requirements only with the trust projection they share.
    #[must_use]
    pub fn is_bound_to(&self, manifest: &ValidatedPluginManifestProjectionV1) -> bool {
        self.pmf1_digest == manifest.pmf1_digest && self.release_digest == manifest.release_digest
    }

    /// BLAKE3-256 of the complete canonical PMF1 bytes.
    #[must_use]
    pub const fn pmf1_digest(&self) -> [u8; 32] {
        self.pmf1_digest
    }

    /// The PMF1 field 27 release digest.
    #[must_use]
    pub const fn release_digest(&self) -> [u8; 32] {
        self.release_digest
    }

    /// The PMF1 field 2 Plugin ID.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// The ABI requirement, fields 5-8.
    #[must_use]
    pub const fn abi(&self) -> &PluginAbiRequirementV1 {
        &self.abi
    }

    /// Every capability descriptor in canonical field 14 order.
    #[must_use]
    pub fn capabilities(&self) -> &[PluginCapabilityDescriptorV1] {
        &self.capabilities
    }

    /// The declared deterministic budget, field 15.
    #[must_use]
    pub const fn budget(&self) -> DeterministicBudgetV1 {
        self.budget
    }
}

/// Raw, unchecked execution requirements for public-seam test fixtures only.
///
/// This type exists only with the `test-support` feature, which
/// `scripts/check_test_support_features.py` keeps out of deployable dependency
/// graphs. It represents caller-fabricated requirements, so negotiation tests
/// can reach every rejection path without publishing a release closure; it
/// is not a PMF1 parser and establishes no release authority.
#[cfg(feature = "test-support")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginExecutionProjectionFixtureV1 {
    /// BLAKE3-256 of the complete canonical PMF1 bytes.
    pub pmf1_digest: [u8; 32],
    /// PMF1 release digest.
    pub release_digest: [u8; 32],
    /// PMF1 Plugin ID.
    pub plugin_id: String,
    /// ABI requirement.
    pub abi: PluginAbiRequirementV1,
    /// Capability descriptors.
    pub capabilities: Vec<PluginCapabilityDescriptorV1>,
    /// Deterministic budget.
    pub budget: DeterministicBudgetV1,
}

#[cfg(feature = "test-support")]
impl From<PluginExecutionProjectionFixtureV1> for PluginExecutionProjectionV1 {
    fn from(fixture: PluginExecutionProjectionFixtureV1) -> Self {
        Self {
            pmf1_digest: fixture.pmf1_digest,
            release_digest: fixture.release_digest,
            plugin_id: fixture.plugin_id,
            abi: fixture.abi,
            capabilities: fixture.capabilities,
            budget: fixture.budget,
        }
    }
}
