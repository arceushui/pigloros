//! ADR-129 §3 metadata-only service authority, evaluated by the domain.
//!
//! "Before decoding CNE1, the concrete owner obtains current metadata-only
//! service authority from its pinned authenticated registry binding and actual
//! persisted grant/revocation state." The concrete owner is the sealed domain,
//! so evaluation happens here: the domain loads its own current grant chain,
//! builds the exact request (its own incarnation's resource, the closed
//! category, the action its operation needs, the purpose and a fresh trusted
//! wall sample) and runs the pinned evaluator. No caller-built or decoded
//! decision is ever accepted.
//!
//! The installed inputs (principal, actor, role, audience, policy revisions
//! and registry snapshot) are fixed at the trusted composition root. The
//! decision permits only private inspection or writing of closed structural
//! metadata; it cannot decrypt State, observation or guest payloads.

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
const PURPOSE: &str = "owner-enforcement";

/// Closed metadata-service action a domain operation needs.
#[derive(Clone, Copy)]
pub(super) enum MetadataActionV1 {
    /// Private inspection of closed metadata schemas.
    Inspect,
    /// Writing closed metadata schemas.
    Write,
}

impl MetadataActionV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Write => "write",
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

/// Installed metadata-only service authority with its trusted wall source.
///
/// It has no public evaluation method: only the domain evaluates it, over
/// the grant chain it loads itself, so no decision crosses the API.
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

    /// Evaluate the exact metadata request for `store_incarnation` against
    /// the chain the domain has just loaded, and return only an active
    /// decision.
    ///
    /// The request asserts `revocation_state_current: true`. That is
    /// legitimate here: `persisted` and its revocation epoch were read fresh
    /// from the store, with revocation fences applied, under the domain's
    /// exclusive use for this same operation; every grant and revocation
    /// advances the authority head, which becomes the request position; and
    /// each operation reloads and re-evaluates rather than reusing a decision.
    pub(super) fn authorize(
        &mut self,
        policy: &CommunityMetadataPolicyV1,
        persisted: &PersistedAuthorityV1,
        store_incarnation: [u8; 16],
        action: MetadataActionV1,
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
            .and_then(|at_time| self.request(persisted, store_incarnation, action, at_time))
            .map(|request| {
                AuthorityEvaluatorV1::authorize(&request, persisted.chain(), &self.input.registry)
            })
            .filter(AuthorizationDecisionV1::is_allowed)
            .ok_or(Error::EvidenceUnavailable)
    }

    /// Build the exact request. The leaf lookup cannot miss: a resolved
    /// `PersistedAuthorityV1` always holds a nonempty root-to-leaf chain (and
    /// the evaluator itself fails closed on an empty one), so `and_then` adds
    /// no branch. The draft fails on an invalid installed audience (an empty
    /// one), and that refusal is tested; a valid audience outside the grant's
    /// scope instead reaches the evaluator's denial.
    fn request(
        &self,
        persisted: &PersistedAuthorityV1,
        store_incarnation: [u8; 16],
        action: MetadataActionV1,
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
                resource: metadata_resource(store_incarnation),
                data_category: DATA_CATEGORY.to_owned(),
                action: action.as_str().to_owned(),
                purpose: PURPOSE.to_owned(),
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

/// Exact `community-metadata:<incarnation32>` resource, lowercase hex. The
/// trusted composition scopes the metadata grant to this resource.
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
