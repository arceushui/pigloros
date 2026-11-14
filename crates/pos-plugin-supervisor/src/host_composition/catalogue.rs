//! The installed authority catalogue, fixed at the trusted composition root.

use pos_core::community_lifecycle::{
    CommunityLifecycleErrorV1 as Error, CommunityMetadataPolicyV1,
};
use pos_core::Hash;
use pos_store::community::{CommunityDomainBindingV1, CommunityMetadataAuthorityV1};

/// Installed catalogue: metadata authority, metadata policy and the pinned
/// catalogue and native-profile identities. It is independent of any request
/// or guest, and changing it requires a new installation.
pub struct CommunityInstalledCatalogueV1 {
    metadata_authority: CommunityMetadataAuthorityV1,
    metadata_policy: CommunityMetadataPolicyV1,
    installed_catalogue_digest: Hash,
    native_profile_digest: Hash,
}

impl CommunityInstalledCatalogueV1 {
    /// Install the catalogue at the trusted composition root.
    ///
    /// # Errors
    /// Returns `InvalidBinding` for a zero catalogue or native-profile digest.
    pub fn new(
        metadata_authority: CommunityMetadataAuthorityV1,
        metadata_policy: CommunityMetadataPolicyV1,
        installed_catalogue_digest: Hash,
        native_profile_digest: Hash,
    ) -> Result<Self, Error> {
        if [installed_catalogue_digest, native_profile_digest].contains(&Hash::zero()) {
            Err(Error::InvalidBinding)
        } else {
            Ok(Self {
                metadata_authority,
                metadata_policy,
                installed_catalogue_digest,
                native_profile_digest,
            })
        }
    }

    /// The installed bindings plus the authority the domain evaluates
    /// itself; no decision is formed here.
    pub(super) const fn domain_parts(
        &mut self,
    ) -> (
        CommunityDomainBindingV1<'_>,
        &mut CommunityMetadataAuthorityV1,
    ) {
        (
            CommunityDomainBindingV1 {
                metadata_policy: &self.metadata_policy,
                installed_catalogue_digest: self.installed_catalogue_digest,
                native_profile_digest: self.native_profile_digest,
            },
            &mut self.metadata_authority,
        )
    }
}
