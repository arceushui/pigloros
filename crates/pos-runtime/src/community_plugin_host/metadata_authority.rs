//! ADR-129 §3 metadata-only service authority for the community owner.
//!
//! The installed composition pins the authenticated owner principal, the
//! trusted registry snapshot, policy revisions and the audience. Each use
//! evaluates the exact `community-metadata:<incarnation>` resource against the
//! store's current persisted grant chain with a fresh trusted wall sample. A
//! stored decision, caller time or decoded record is never the current one.
//!
//! The decision permits only private inspection, writing or disposition of
//! closed structural metadata schemas. It cannot decrypt State, observation or
//! guest payloads and is not a requesting principal's data-use decision.

use pos_core::community_lifecycle::{
    CommunityLifecycleErrorV1 as Error, CommunityMetadataPolicyV1,
};
use pos_core::trusted_clock::TrustedWallSourceV1;
use pos_core::{
    AuthenticatedPrincipalResultV1, AuthorityEvaluatorV1, AuthorityRegistrySnapshotV1,
    AuthorityRoleV1, AuthorizationDecisionV1, AuthorizationRequestDraftV1, AuthorizationRequestV1,
    ConsentEvidenceV1, EntityId, Hash, PersistedAuthorityV1, WallTime,
};

const DATA_CATEGORY: &str = "community.owner-metadata";

/// Closed metadata-service actions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommunityMetadataActionV1 {
    /// Private inspection of closed metadata schemas.
    Inspect,
    /// Writing closed metadata schemas.
    Write,
    /// Authorized disposition, including of frozen metadata.
    Dispose,
}

impl CommunityMetadataActionV1 {
    /// Exact authority action string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Write => "write",
            Self::Dispose => "dispose",
        }
    }
}

/// Closed metadata-service purposes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommunityMetadataPurposeV1 {
    /// Ordinary owner enforcement.
    OwnerEnforcement,
    /// Owner recovery of an original outcome.
    OwnerRecovery,
    /// Owner disposition of retained metadata.
    OwnerDisposition,
}

impl CommunityMetadataPurposeV1 {
    /// Exact authority purpose string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerEnforcement => "owner-enforcement",
            Self::OwnerRecovery => "owner-recovery",
            Self::OwnerDisposition => "owner-disposition",
        }
    }
}

/// Installed authority inputs, fixed at the trusted composition root.
pub struct CommunityMetadataAuthorityInputV1 {
    /// Trusted registry snapshot from the host's authoritative registry.
    pub registry: AuthorityRegistrySnapshotV1,
    /// Authenticated installed owner principal.
    pub principal: AuthenticatedPrincipalResultV1,
    /// Installed owner actor entity.
    pub actor_entity_id: EntityId,
    /// Installed owner principal role.
    pub principal_role: AuthorityRoleV1,
    /// Installed owner audience identity.
    pub audience: String,
    /// Pinned consent policy revision.
    pub consent_policy_revision: Hash,
    /// Pinned capability policy revision.
    pub capability_policy_revision: Hash,
}

/// One requested metadata-service use of one protected store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityMetadataUseV1 {
    /// Store incarnation naming the metadata resource.
    pub store_incarnation: [u8; 16],
    /// Closed action.
    pub action: CommunityMetadataActionV1,
    /// Closed purpose.
    pub purpose: CommunityMetadataPurposeV1,
}

/// Installed metadata-only service authority with its trusted wall source.
pub struct CommunityMetadataAuthorityV1 {
    input: CommunityMetadataAuthorityInputV1,
    wall: Box<dyn TrustedWallSourceV1>,
}

impl CommunityMetadataAuthorityV1 {
    /// Install the authority at the trusted composition root.
    #[must_use]
    pub fn new(
        input: CommunityMetadataAuthorityInputV1,
        wall: impl TrustedWallSourceV1 + 'static,
    ) -> Self {
        Self {
            input,
            wall: Box::new(wall),
        }
    }

    /// Evaluate one current metadata-service use.
    ///
    /// `persisted` must be the store's current chain for the policy's leaf
    /// grant, loaded under the same exclusive store use as the operation.
    ///
    /// # Errors
    /// Returns `EvidenceUnavailable` when the installed principal is not the
    /// policy's registry binding, the chain is not the policy's leaf grant,
    /// no trusted wall sample exists, the request is invalid or the current
    /// decision is anything other than active.
    pub fn authorize(
        &mut self,
        policy: &CommunityMetadataPolicyV1,
        persisted: &PersistedAuthorityV1,
        metadata_use: CommunityMetadataUseV1,
    ) -> Result<AuthorizationDecisionV1, Error> {
        let pinned = policy.as_input();
        if self.input.principal.registry_binding_digest() != pinned.metadata_owner_registry_binding
            || persisted.leaf_grant_id() != pinned.metadata_authority_leaf_grant
        {
            return Err(Error::EvidenceUnavailable);
        }
        self.wall
            .sample()
            .ok()
            .and_then(|at_time| self.request(persisted, metadata_use, at_time))
            .map(|request| {
                AuthorityEvaluatorV1::authorize(&request, persisted.chain(), &self.input.registry)
            })
            .filter(AuthorizationDecisionV1::is_allowed)
            .ok_or(Error::EvidenceUnavailable)
    }

    fn request(
        &self,
        persisted: &PersistedAuthorityV1,
        metadata_use: CommunityMetadataUseV1,
        at_time: WallTime,
    ) -> Option<AuthorizationRequestV1> {
        persisted.chain().grants().last().and_then(|leaf| {
            AuthorizationRequestV1::try_from_draft(AuthorizationRequestDraftV1 {
                authenticated: self.input.principal.clone(),
                actor_entity_id: self.input.actor_entity_id,
                subject_id: None,
                participant_id: None,
                plugin_id: None,
                installation_id: None,
                principal_role: self.input.principal_role,
                resource: metadata_resource(metadata_use.store_incarnation),
                data_category: DATA_CATEGORY.to_owned(),
                action: metadata_use.action.as_str().to_owned(),
                purpose: metadata_use.purpose.as_str().to_owned(),
                audience: self.input.audience.clone(),
                at_time,
                authority_timeline: leaf.issuance_timeline(),
                at_position: persisted.head_position(),
                consent_timeline: None,
                consent_at_position: None,
                use_count: 1,
                budget: 1,
                consent_policy_revision: self.input.consent_policy_revision,
                capability_policy_revision: self.input.capability_policy_revision,
                revocation_epoch: persisted.revocation_epoch(),
                revocation_state_current: true,
                authority_registry_digest: self.input.registry.registry_digest(),
                consent: ConsentEvidenceV1::NotRequired,
                environment_constraints: Vec::new(),
            })
            .ok()
        })
    }
}

/// Exact `community-metadata:<incarnation32>` resource, lowercase hex.
#[must_use]
pub fn metadata_resource(store_incarnation: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut resource = String::with_capacity(51);
    resource.push_str("community-metadata:");
    for byte in store_incarnation {
        resource.push(char::from(HEX[usize::from(byte >> 4)]));
        resource.push(char::from(HEX[usize::from(byte & 15)]));
    }
    resource
}
