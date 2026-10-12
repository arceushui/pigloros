//! Trust material built from raw bytes, and a source that serves it (ADR-061 revision 8
//! decision 5). Linux only, like the gate that consumes it.
//!
//! The constructor builds the two anchors and checks nothing else: no bound, capacity,
//! genesis-digest or signature pre-check, because the gate re-verifies the complete material on
//! every call. A record of any length is therefore accepted here and refused by the gate. The
//! names are confined to the trusted composition and the conformance adapter by rule 6 of
//! `scripts/check_plugin_trust_registry_impls.py`.

use std::sync::Arc;

use pos_conformance::{PluginTrustPolicyAnchorV1, PLUGIN_OPERATOR_ROLE_V1};
use pos_crypto::plugin_trust::TrustedPluginRootAnchorV1;
use thiserror::Error;

use super::{
    CommunityPluginTrustMaterialV1, PluginTrustMaterialSourceV1, PluginTrustMaterialUnavailableV1,
};

/// The operator-pinned anchor of one policy scope, as raw bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityTrustAnchorBytesV1 {
    /// The policy scope, equal to the TPS1 `policy_id`.
    pub scope: String,
    /// The pinned PTR1 genesis complete-record digest.
    pub ptr1_genesis_digest: [u8; 32],
    /// The pinned Ed25519 operator verification key; its role is always `deployment-operator`.
    pub operator_key: [u8; 32],
    /// BLAKE3-256 of the complete canonical genesis TPS1 bytes.
    pub genesis_tps1_digest: [u8; 32],
}

/// A closed failure of the byte-built trust material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CommunityTrustBytesErrorV1 {
    /// The scope or the operator key is not valid for an anchor.
    #[error("Plugin trust anchor is invalid")]
    Anchor,
    /// The PTR1 or the PRV1 history holds no record.
    #[error("Plugin trust record history is empty")]
    Empty,
}

impl CommunityPluginTrustMaterialV1 {
    /// Material from raw bytes: the anchor, the signed TPS1 bytes, and the ordered PTR1 and
    /// PRV1 record bytes (oldest first).
    ///
    /// # Errors
    /// Returns `Empty` for an empty PTR1 or PRV1 history and `Anchor` when the scope or the
    /// operator key is not valid. Nothing else is checked: the gate verifies every record on
    /// every call.
    pub fn from_bytes_v1(
        anchor: &CommunityTrustAnchorBytesV1,
        tps1: Vec<u8>,
        roots: Vec<Vec<u8>>,
        revocations: Vec<Vec<u8>>,
    ) -> Result<Self, CommunityTrustBytesErrorV1> {
        if roots.is_empty() || revocations.is_empty() {
            return Err(CommunityTrustBytesErrorV1::Empty);
        }
        let root = TrustedPluginRootAnchorV1::new(&anchor.scope, anchor.ptr1_genesis_digest)
            .map_err(|_| CommunityTrustBytesErrorV1::Anchor)?;
        let policy = PluginTrustPolicyAnchorV1::new(
            &anchor.scope,
            anchor.ptr1_genesis_digest,
            anchor.operator_key,
            PLUGIN_OPERATOR_ROLE_V1,
            anchor.genesis_tps1_digest,
        )
        .map_err(|_| CommunityTrustBytesErrorV1::Anchor)?;
        Ok(Self::new(policy, root, tps1, roots, revocations))
    }
}

/// A material source that serves one fixed material on every call.
///
/// The source is `Clone` over shared bytes: every clone serves equal material.
#[derive(Clone, Debug)]
pub struct FixedTrustMaterialSourceV1 {
    material: Option<Arc<CommunityPluginTrustMaterialV1>>,
}

impl FixedTrustMaterialSourceV1 {
    /// A source that serves `material`.
    #[must_use]
    pub fn new(material: CommunityPluginTrustMaterialV1) -> Self {
        Self {
            material: Some(Arc::new(material)),
        }
    }

    /// The explicit unreadable-material case: every call is `PluginTrustMaterialUnavailableV1`.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self { material: None }
    }
}

impl PluginTrustMaterialSourceV1 for FixedTrustMaterialSourceV1 {
    fn material(&self) -> Result<CommunityPluginTrustMaterialV1, PluginTrustMaterialUnavailableV1> {
        self.material
            .as_deref()
            .cloned()
            .ok_or(PluginTrustMaterialUnavailableV1)
    }
}
