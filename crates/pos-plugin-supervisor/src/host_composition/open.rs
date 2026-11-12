//! `open_memory`: construct the host over a retained-Memory domain.

use pos_core::community_lifecycle::CommunityLifecycleErrorV1 as Error;
use pos_runtime::community_plugin_host::{
    CommunityMetadataActionV1, CommunityMetadataPurposeV1, CommunityMetadataUseV1,
};
use pos_store::community::{
    CommunityBootstrapRequestV1, CommunityDomainOpenedV1, MemoryCommunityDomainV1,
};

use super::{CommunityInstalledCatalogueV1, CommunityLifecycleHostV1};

impl<'a> CommunityLifecycleHostV1<'a> {
    /// Open the host over exclusive use of a retained-Memory domain.
    ///
    /// Under a current metadata-service decision, a proven-empty domain is
    /// bootstrapped with exactly one key intent, its CMA1 anchor and encrypted
    /// CSI1. An existing domain is verified instead; the original control
    /// identity resolves its original bootstrap without new material. No
    /// guest permit or State is issued.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` for a missing, revoked or foreign
    /// metadata grant and for a missing or conflicting anchor, key intent or
    /// CSI1; `Conflict` when the control identity names another request.
    pub fn open_memory(
        catalogue: CommunityInstalledCatalogueV1,
        domain: &'a mut MemoryCommunityDomainV1,
        request: CommunityBootstrapRequestV1,
    ) -> Result<(Self, CommunityDomainOpenedV1), Error> {
        let mut host = Self { catalogue, domain };
        host.open_domain(request).map(|opened| (host, opened))
    }

    fn open_domain(
        &mut self,
        request: CommunityBootstrapRequestV1,
    ) -> Result<CommunityDomainOpenedV1, Error> {
        let metadata_use = CommunityMetadataUseV1 {
            store_incarnation: self.domain.store_incarnation(),
            action: if self.domain.is_bootstrapped() {
                CommunityMetadataActionV1::Inspect
            } else {
                CommunityMetadataActionV1::Write
            },
            purpose: CommunityMetadataPurposeV1::OwnerEnforcement,
        };
        let catalogue = &mut self.catalogue;
        self.domain
            .metadata_authority(&catalogue.metadata_policy)
            .and_then(|persisted| {
                catalogue.metadata_authority.authorize(
                    &catalogue.metadata_policy,
                    &persisted,
                    metadata_use,
                )
            })
            .and_then(|decision| self.domain.open(catalogue.binding(), request, &decision))
    }
}
