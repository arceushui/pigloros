//! The community Plugin host member (ADR-061 revision 7 decision 10, #584).
//!
//! [`CommunityMemberV1`] wraps the Driver's [`CommunityPluginHandleV1`] and holds what the
//! composition supplies for that member: the release source, the bundle address, the trust
//! material source, the expected Plugin ID and the expected release pair. It implements
//! pos-runtime's `CommunityPluginMemberV1`, so `CommunityPluginHostV1` can gate, offer and
//! close each member's pass without knowing the Driver.

use pos_core::PluginId;
use pos_plugin_release::{BundleAddressV1, ReleaseSourceV1};
use pos_runtime::community_plugin_host::{
    CommunityPassAuthorizationV1, CommunityPluginHostErrorV1, CommunityPluginMemberV1,
    PluginTrustMaterialSourceV1,
};
use pos_runtime::{PluginRegistry, RuntimeError};

use crate::adapter::CommunityPluginHandleV1;

/// One member of the host pass seam.
///
/// The composition builds it from the handle that `CommunityDriverV1::new` returned for the
/// Driver it registered with `register_community_driver`. The Plugin ID text given here is the
/// one the gate expects at the address; the Driver's own copy was checked once by
/// `CommunityDriverConfigV1::from_gated`, and a divergence between the two fails closed as
/// `ArtifactTrustDenied{NotActive}`.
pub struct CommunityMemberV1 {
    handle: CommunityPluginHandleV1,
    source: Box<dyn ReleaseSourceV1>,
    address: BundleAddressV1,
    material: Box<dyn PluginTrustMaterialSourceV1>,
    expected_plugin_id: String,
    expected_release: Option<([u8; 32], [u8; 32])>,
}

impl CommunityMemberV1 {
    /// A member for `handle`, whose closure the composition re-supplies at `address` in
    /// `source`, whose trust material comes from `material`, and which is expected to hold the
    /// Plugin `expected_plugin_id` and, when a Driver was built, the release pair
    /// `expected_release` (the complete-PMF1 and release digests the Driver was built for).
    #[must_use]
    pub const fn new(
        handle: CommunityPluginHandleV1,
        source: Box<dyn ReleaseSourceV1>,
        address: BundleAddressV1,
        material: Box<dyn PluginTrustMaterialSourceV1>,
        expected_plugin_id: String,
        expected_release: Option<([u8; 32], [u8; 32])>,
    ) -> Self {
        Self {
            handle,
            source,
            address,
            material,
            expected_plugin_id,
            expected_release,
        }
    }

    /// The Driver's handle.
    #[must_use]
    pub const fn handle(&self) -> &CommunityPluginHandleV1 {
        &self.handle
    }
}

impl CommunityPluginMemberV1 for CommunityMemberV1 {
    fn plugin(&self) -> PluginId {
        self.handle.plugin_id()
    }

    fn expected_plugin_id(&self) -> &str {
        &self.expected_plugin_id
    }

    fn expected_release(&self) -> Option<([u8; 32], [u8; 32])> {
        self.expected_release
    }

    fn release_source(&self) -> &dyn ReleaseSourceV1 {
        self.source.as_ref()
    }

    fn release_address(&self) -> &BundleAddressV1 {
        &self.address
    }

    fn trust_material(&self) -> &dyn PluginTrustMaterialSourceV1 {
        self.material.as_ref()
    }

    fn offer_authorization(
        &self,
        authorization: CommunityPassAuthorizationV1,
    ) -> Result<(), CommunityPluginHostErrorV1> {
        self.handle.offer_authorization(authorization)
    }

    fn record_refusal(&self, error: CommunityPluginHostErrorV1) {
        self.handle.record_refusal(error);
    }

    fn close_pass(&self) {
        self.handle.close_pass();
    }

    fn pass_failure(&self) -> Option<CommunityPluginHostErrorV1> {
        self.handle.pass_failure()
    }

    fn pass_invocation_id(&self) -> Option<[u8; 16]> {
        self.handle.pass_invocation_id()
    }

    fn sync_registry(&self, registry: &mut PluginRegistry) -> Result<(), RuntimeError> {
        self.handle.sync_registry(registry)
    }
}
