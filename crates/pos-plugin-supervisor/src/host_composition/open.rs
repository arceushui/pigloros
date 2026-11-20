//! `open_memory`: construct the host over a retained-Memory domain.

use pos_core::community_lifecycle::CommunityLifecycleErrorV1 as Error;
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
    /// guest permit or State is issued. The request's anchor Timeline and
    /// generation are caller-asserted by the trusted composition until the
    /// first generation initialization binds them (ADR-129 §3); A2's
    /// `initialize` MUST check the stored anchor against the first admitted
    /// Timeline/generation when it writes CGI1 and fail closed on mismatch.
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
        let (binding, authority) = self.catalogue.domain_parts();
        self.domain.open(binding, authority, request)
    }
}
