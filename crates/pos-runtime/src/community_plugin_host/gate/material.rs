//! The trust material the composition supplies to the gate (ADR-061 revision 7 decision 2).

use pos_conformance::PluginTrustPolicyAnchorV1;
use pos_crypto::plugin_trust::TrustedPluginRootAnchorV1;

/// The operator-pinned anchors and the signed records of one gate call.
///
/// The composition yields it fresh on every gate call. The gate re-verifies the complete PTR1
/// and PRV1 histories from it and caches nothing across passes. For Air-Gapped mode the
/// implementation reads the offline bundle, which fails closed after expiry.
#[derive(Clone, Debug)]
pub struct CommunityPluginTrustMaterialV1 {
    policy_anchor: PluginTrustPolicyAnchorV1,
    root_anchor: TrustedPluginRootAnchorV1,
    tps1_bytes: Vec<u8>,
    roots: Vec<Vec<u8>>,
    revocations: Vec<Vec<u8>>,
}

impl CommunityPluginTrustMaterialV1 {
    /// Material from the two anchors, the signed TPS1 bytes, and the ordered PTR1 and PRV1
    /// record bytes (oldest first).
    #[must_use]
    pub const fn new(
        policy_anchor: PluginTrustPolicyAnchorV1,
        root_anchor: TrustedPluginRootAnchorV1,
        tps1_bytes: Vec<u8>,
        roots: Vec<Vec<u8>>,
        revocations: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            policy_anchor,
            root_anchor,
            tps1_bytes,
            roots,
            revocations,
        }
    }

    /// The operator-pinned registry anchor of the policy scope.
    #[must_use]
    pub const fn policy_anchor(&self) -> &PluginTrustPolicyAnchorV1 {
        &self.policy_anchor
    }

    /// The operator-pinned PTR1 genesis anchor.
    #[must_use]
    pub const fn root_anchor(&self) -> &TrustedPluginRootAnchorV1 {
        &self.root_anchor
    }

    /// The signed TPS1 bytes.
    #[must_use]
    pub fn tps1_bytes(&self) -> &[u8] {
        &self.tps1_bytes
    }

    /// The PTR1 record bytes, oldest first.
    #[must_use]
    pub fn roots(&self) -> &[Vec<u8>] {
        &self.roots
    }

    /// The PRV1 record bytes, oldest first.
    #[must_use]
    pub fn revocations(&self) -> &[Vec<u8>] {
        &self.revocations
    }
}

/// The trust material could not be read.
///
/// The gate maps it to `ArtifactTrustDenied{TrustStateUnavailable}`; it carries nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Plugin trust material is unavailable")]
pub struct PluginTrustMaterialUnavailableV1;

/// The composition's source of trust material.
///
/// Implemented by the trusted composition, never by a Plugin. On every gate call it yields
/// fresh material, which for Air-Gapped mode comes from the offline bundle.
pub trait PluginTrustMaterialSourceV1 {
    /// The current material.
    ///
    /// # Errors
    /// Returns `PluginTrustMaterialUnavailableV1` when the material cannot be read.
    fn material(&self) -> Result<CommunityPluginTrustMaterialV1, PluginTrustMaterialUnavailableV1>;
}
