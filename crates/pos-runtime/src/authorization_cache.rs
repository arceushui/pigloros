//! Authorization decisions retained only by the erasure execution host.

use pos_core::{
    AuthorityEvaluatorV1, AuthorityRegistrySnapshotV1, AuthorizationDecisionV1,
    AuthorizationRequestV1, ConsentEvidenceV1, ErasureReferenceV1, Hash, PersistedAuthorityV1, Seq,
    TimelineId, WallTime,
};
use std::collections::{BTreeSet, HashMap};

// ---------------------------------------------------------------------------
// AuthorizationCacheV1
// ---------------------------------------------------------------------------

/// Exact invalidation identity for one cached active authorization decision.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AuthorizationCacheKeyV1 {
    request_digest: Hash,
    target_timeline: TimelineId,
    authority_timeline: TimelineId,
    grant_chain_bindings: Vec<Hash>,
    consent_policy_revision: Hash,
    capability_policy_revision: Hash,
    revocation_epoch: u64,
    inventory_generation: [u8; 32],
}

impl AuthorizationCacheKeyV1 {
    #[must_use]
    fn from_decision(
        decision: &AuthorizationDecisionV1,
        target_timeline: TimelineId,
        revocation_epoch: u64,
        inventory_generation: ErasureReferenceV1,
    ) -> Self {
        Self {
            request_digest: decision.request_digest(),
            target_timeline,
            authority_timeline: decision.authority_timeline(),
            grant_chain_bindings: decision.grant_chain_bindings().to_vec(),
            consent_policy_revision: decision.consent_policy_revision(),
            capability_policy_revision: decision.capability_policy_revision(),
            revocation_epoch,
            inventory_generation: inventory_generation.digest(),
        }
    }

    #[must_use]
    const fn authority_timeline(&self) -> TimelineId {
        self.authority_timeline
    }

    #[must_use]
    const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }

    #[must_use]
    pub const fn inventory_generation(&self) -> ErasureReferenceV1 {
        ErasureReferenceV1::from_digest(self.inventory_generation)
    }

    pub(crate) const fn target_timeline(&self) -> TimelineId {
        self.target_timeline
    }
}

#[derive(Clone, Debug)]
struct AuthorizationCacheEntryV1 {
    decision: AuthorizationDecisionV1,
    expires_at: WallTime,
    valid_until_position: Seq,
    grant_ids: BTreeSet<Hash>,
    consent_references: BTreeSet<Hash>,
    inventory_generation: ErasureReferenceV1,
}

impl AuthorizationCacheEntryV1 {
    fn is_current(
        &self,
        at_time: WallTime,
        at_position: Seq,
        inventory_generation: ErasureReferenceV1,
    ) -> bool {
        at_time < self.expires_at
            && at_position < self.valid_until_position
            && self.inventory_generation == inventory_generation
    }
}

/// Current authorized-decision projection with explicit expiry and revocation indexes.
///
/// Only active decisions are admitted. Every lookup supplies the current wall-time and
/// Timeline position, so an entry cannot outlive the shorter of its consent/grant wall
/// expiry and logical-position expiry. Parent and consent indexes make revocation
/// invalidation independent of which chain member was the leaf.
#[derive(Clone, Debug, Default)]
pub(crate) struct AuthorizationCacheV1 {
    entries: HashMap<AuthorizationCacheKeyV1, AuthorizationCacheEntryV1>,
}

impl AuthorizationCacheV1 {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Cache an active decision until its derived shortest expiry, bound to
    /// the exact installed erasure inventory generation.
    ///
    /// Returns the exact cache key, or `None` when the decision differs from
    /// a fresh evaluation of the supplied authority and registry, is denied,
    /// is expired, or has no capability chain.
    pub(crate) fn insert_active(
        &mut self,
        target_timeline: TimelineId,
        decision: AuthorizationDecisionV1,
        request: &AuthorizationRequestV1,
        authority: &PersistedAuthorityV1,
        registry: &AuthorityRegistrySnapshotV1,
        inventory_generation: ErasureReferenceV1,
    ) -> Option<AuthorizationCacheKeyV1> {
        let grants = authority.chain().grants();
        let grant_ids = grants
            .iter()
            .map(pos_core::CapabilityGrantV1::grant_id)
            .collect::<BTreeSet<_>>();
        let consent_references = grants
            .iter()
            .flat_map(|grant| grant.consent_references().iter().copied())
            .collect::<BTreeSet<_>>();
        let first_grant = &grants[0];
        let valid_until_position = grants
            .iter()
            .skip(1)
            .fold(first_grant.valid_until_position(), |shortest, grant| {
                shortest.min(grant.valid_until_position())
            });
        let authentication_expiry = request.authenticated().expires_at();
        let expires_at = match request.consent() {
            ConsentEvidenceV1::Resolved { grants } => {
                grants.iter().fold(authentication_expiry, |expiry, grant| {
                    expiry.min(grant.valid_until())
                })
            }
            _ => authentication_expiry,
        };
        let current_decision =
            AuthorityEvaluatorV1::authorize(request, authority.chain(), registry);
        if !decision.is_allowed()
            || decision != current_decision
            || authority.revocation_epoch() != request.revocation_epoch()
            || request.at_time() >= expires_at
            || valid_until_position <= decision.at_position()
            || grant_ids.is_empty()
        {
            return None;
        }
        let key = AuthorizationCacheKeyV1::from_decision(
            &decision,
            target_timeline,
            authority.revocation_epoch(),
            inventory_generation,
        );
        self.entries.insert(
            key.clone(),
            AuthorizationCacheEntryV1 {
                decision,
                expires_at,
                valid_until_position,
                grant_ids,
                consent_references,
                inventory_generation,
            },
        );
        Some(key)
    }

    /// Read an unexpired decision only when current authority and registry
    /// evidence reproduces the same active decision for this generation.
    /// Stale or denied entries are evicted before their decision is returned.
    pub(crate) fn get(
        &mut self,
        key: &AuthorizationCacheKeyV1,
        at_time: WallTime,
        at_position: Seq,
        request: &AuthorizationRequestV1,
        authority: &PersistedAuthorityV1,
        registry: &AuthorityRegistrySnapshotV1,
        inventory_generation: ErasureReferenceV1,
    ) -> Option<&AuthorizationDecisionV1> {
        let should_evict = self.entries.get(key).is_some_and(|entry| {
            let current_decision =
                AuthorityEvaluatorV1::authorize(request, authority.chain(), registry);
            key.inventory_generation() != inventory_generation
                || !entry.is_current(at_time, at_position, inventory_generation)
                || authority.revocation_epoch() != key.revocation_epoch()
                || request.revocation_epoch() != key.revocation_epoch()
                || !current_decision.is_allowed()
                || current_decision != entry.decision
        });
        if should_evict {
            self.entries.remove(key);
            None
        } else {
            self.entries.get(key).map(|entry| &entry.decision)
        }
    }

    /// Invalidate every leaf decision derived from this grant or any parent grant.
    pub(crate) fn invalidate_grant(&mut self, grant_id: Hash) -> usize {
        self.retain_and_count_evicted(|entry| !entry.grant_ids.contains(&grant_id))
    }

    /// Invalidate every decision derived from one revoked consent reference.
    pub(crate) fn invalidate_consent(&mut self, consent_reference: Hash) -> usize {
        self.retain_and_count_evicted(|entry| {
            !entry.consent_references.contains(&consent_reference)
        })
    }

    /// Drop stale epochs for one authority Timeline while leaving unrelated Timelines intact.
    pub(crate) fn retain_revocation_epoch(
        &mut self,
        authority_timeline: TimelineId,
        current_epoch: u64,
    ) -> usize {
        let before = self.entries.len();
        self.entries.retain(|key, _| {
            key.authority_timeline() != authority_timeline
                || key.revocation_epoch() == current_epoch
        });
        before.saturating_sub(self.entries.len())
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn evict(&mut self, key: &AuthorizationCacheKeyV1) {
        self.entries.remove(key);
    }

    fn retain_and_count_evicted(
        &mut self,
        mut keep: impl FnMut(&AuthorizationCacheEntryV1) -> bool,
    ) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| keep(entry));
        before.saturating_sub(self.entries.len())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::erasure_host::ErasureExecutionHostV1;
    use pos_core::ErasureRecoveryLimitsV1;
    use pos_core::{
        AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
        AuthorityGranteeV1, AuthorityPersistenceHostV1, AuthorityPersistenceStateV1,
        AuthorityRoleV1, AuthorizationRequestDraftV1, CapabilityGrantDraftV1, CapabilityGrantV1,
        CapabilityScopeDraftV1, CapabilityScopeV1, ConsentGrantRefDraftV1, ConsentGrantRefV1,
        ConsentGrantStatusV1, DelegateClassV1, DelegationChainV1, EntityId, PluginId,
        PrincipalRefV1, DELEGATE_ACTION_V1,
    };
    use pos_store::StoreConfig;

    fn test_ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
        })
    }

    const fn cache_generation(value: u8) -> ErasureReferenceV1 {
        ErasureReferenceV1::from_digest([value; 32])
    }

    const fn test_hash(value: u8) -> Hash {
        Hash::from_bytes([value; 32])
    }

    struct CacheFixture {
        decision: AuthorizationDecisionV1,
        registry: AuthorityRegistrySnapshotV1,
        request: AuthorizationRequestV1,
        authority: PersistedAuthorityV1,
        parent_grant_id: Hash,
        consent_reference: Hash,
    }

    fn active_decision(authority_timeline: TimelineId) -> CacheFixture {
        decision_with_capability_trust(authority_timeline, test_hash(5), true)
    }

    fn authority_registry(
        request: &AuthorizationRequestV1,
        grants: &[CapabilityGrantV1],
        registry_digest: Hash,
        trust_capability: bool,
    ) -> AuthorityRegistrySnapshotV1 {
        let mut capability_bindings = if trust_capability {
            grants
                .iter()
                .map(|grant| test_ok(grant.binding_digest()))
                .collect()
        } else {
            vec![]
        };
        capability_bindings.sort_unstable();
        test_ok(AuthorityRegistrySnapshotV1::try_new(
            registry_digest,
            vec![request.authenticated().registry_binding_digest()],
            capability_bindings,
            vec![],
        ))
    }

    fn delegation_scopes(actor: EntityId) -> (CapabilityScopeV1, CapabilityScopeV1) {
        let scope = |actions| {
            test_ok(CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
                resources: vec!["profile".to_owned()],
                actions,
                purposes: vec!["planning".to_owned()],
                audiences: vec!["local-host".to_owned()],
                actor_entity_ids: vec![actor],
                subject_ids: vec![],
                participant_ids: vec![],
                plugin_id: None,
                principal_roles: vec![AuthorityRoleV1::Actor],
                max_uses: 2,
                budget: 10,
                environment_constraints: vec!["local-only".to_owned()],
            }))
        };
        (
            scope(vec![DELEGATE_ACTION_V1.to_owned(), "read".to_owned()]),
            scope(vec!["read".to_owned()]),
        )
    }

    fn cache_request(
        authenticated: AuthenticatedPrincipalResultV1,
        actor: EntityId,
        authority_timeline: TimelineId,
        policy: Hash,
        registry_digest: Hash,
    ) -> AuthorizationRequestV1 {
        test_ok(AuthorizationRequestV1::try_from_draft(
            AuthorizationRequestDraftV1 {
                authenticated,
                actor_entity_id: actor,
                subject_id: None,
                participant_id: None,
                plugin_id: None,
                installation_id: None,
                principal_role: AuthorityRoleV1::Actor,
                resource: "profile".to_owned(),
                data_category: "public".to_owned(),
                action: "read".to_owned(),
                purpose: "planning".to_owned(),
                audience: "local-host".to_owned(),
                at_time: WallTime::from_micros(10),
                authority_timeline,
                at_position: Seq::from_u64(10),
                consent_timeline: None,
                consent_at_position: None,
                use_count: 1,
                budget: 5,
                consent_policy_revision: policy,
                capability_policy_revision: policy,
                revocation_epoch: 0,
                revocation_state_current: true,
                authority_registry_digest: registry_digest,
                consent: ConsentEvidenceV1::NotRequired,
                environment_constraints: vec!["local-only".to_owned()],
            },
        ))
    }

    fn projection_request(
        base: &AuthorizationRequestV1,
        subject_id: Option<EntityId>,
        participant_id: Option<EntityId>,
        plugin_context: Option<(PluginId, [u8; 16])>,
        consent: ConsentEvidenceV1,
        consent_timeline: Option<TimelineId>,
    ) -> AuthorizationRequestV1 {
        let (plugin_id, installation_id) = plugin_context.unzip();
        test_ok(AuthorizationRequestV1::try_from_draft(
            AuthorizationRequestDraftV1 {
                authenticated: base.authenticated().clone(),
                actor_entity_id: base.actor_entity_id(),
                subject_id,
                participant_id,
                plugin_id,
                installation_id,
                principal_role: base.principal_role(),
                resource: "projection.missing-reducer".to_owned(),
                data_category: base.data_category().to_owned(),
                action: base.action().to_owned(),
                purpose: base.purpose().to_owned(),
                audience: base.audience().to_owned(),
                at_time: base.at_time(),
                authority_timeline: base.authority_timeline(),
                at_position: base.at_position(),
                consent_timeline: consent_timeline
                    .or_else(|| subject_id.map(|_| base.authority_timeline())),
                consent_at_position: subject_id.map(|_| base.at_position()),
                use_count: base.use_count(),
                budget: base.budget(),
                consent_policy_revision: base.consent_policy_revision(),
                capability_policy_revision: base.capability_policy_revision(),
                revocation_epoch: base.revocation_epoch(),
                revocation_state_current: base.revocation_state_current(),
                authority_registry_digest: base.authority_registry_digest(),
                consent,
                environment_constraints: base.environment_constraints().to_vec(),
            },
        ))
    }

    fn cache_consent_grant(valid_until: u64) -> ConsentGrantRefV1 {
        test_ok(ConsentGrantRefV1::try_from_draft(ConsentGrantRefDraftV1 {
            consent_id: test_hash(61),
            subject_id: EntityId::new(),
            grantee_id: EntityId::new(),
            data_categories: vec!["private".to_owned()],
            purposes: vec!["planning".to_owned()],
            audiences: vec!["local-host".to_owned()],
            action_classes: vec!["read".to_owned()],
            valid_from: WallTime::from_micros(1),
            valid_until: WallTime::from_micros(valid_until),
            withdrawal_retention_policy: "erase".to_owned(),
            policy_revision: test_hash(62),
            issuer: test_ok(PrincipalRefV1::try_new([63; 16], "local.test")),
            issuer_evidence: test_hash(64),
            consent_timeline: TimelineId::new(),
            grant_position: Seq::from_u64(1),
            status: ConsentGrantStatusV1::Active,
            revocation_fence: None,
            authority_registry_digest: test_hash(65),
        }))
    }

    fn decision_with_capability_trust(
        authority_timeline: TimelineId,
        grant_id: Hash,
        trust_capability: bool,
    ) -> CacheFixture {
        let root_principal = test_ok(PrincipalRefV1::try_new([1; 16], "local.test"));
        let delegate = test_ok(PrincipalRefV1::try_new([2; 16], "local.test"));
        let leaf_principal = test_ok(PrincipalRefV1::try_new([3; 16], "local.test"));
        let actor = EntityId::new();
        let authenticated = test_ok(AuthenticatedPrincipalResultV1::try_from_draft(
            AuthenticatedPrincipalDraftV1 {
                principal: leaf_principal.clone(),
                adapter_id: "test-adapter".to_owned(),
                assurance: test_ok(AssuranceLevelV1::try_new(1)),
                issued_at: WallTime::from_micros(1),
                expires_at: WallTime::from_micros(100),
                binding_digest: test_hash(3),
            },
        ));
        let policy = test_hash(4);
        let consent_reference = test_hash(6);
        let registry_digest = test_hash(7);
        let (root_scope, child_scope) = delegation_scopes(actor);
        let parent_grant_id = test_hash(16);
        let parent = test_ok(CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
            grant_id: parent_grant_id,
            grantor: root_principal,
            grantee: AuthorityGranteeV1::Principal(delegate.clone()),
            trust_domain: "local.test".to_owned(),
            scope: root_scope,
            valid_from_position: Seq::from_u64(1),
            valid_until_position: Seq::from_u64(80),
            parent_grant_id: None,
            delegation_depth: 0,
            max_delegation_depth: 1,
            permitted_delegate_classes: vec![DelegateClassV1::Principal],
            consent_references: vec![consent_reference],
            policy_revision: policy,
            issuance_timeline: authority_timeline,
            issuance_seq: Seq::from_u64(1),
            revocation_epoch: 0,
            revocation_fence: None,
            authority_registry_digest: registry_digest,
        }));
        let child = test_ok(CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
            grant_id,
            grantor: delegate,
            grantee: AuthorityGranteeV1::Principal(leaf_principal),
            trust_domain: "local.test".to_owned(),
            scope: child_scope,
            valid_from_position: Seq::from_u64(2),
            valid_until_position: Seq::from_u64(80),
            parent_grant_id: Some(parent_grant_id),
            delegation_depth: 1,
            max_delegation_depth: 1,
            permitted_delegate_classes: vec![],
            consent_references: vec![consent_reference],
            policy_revision: policy,
            issuance_timeline: authority_timeline,
            issuance_seq: Seq::from_u64(2),
            revocation_epoch: 0,
            revocation_fence: None,
            authority_registry_digest: registry_digest,
        }));
        let request = cache_request(
            authenticated,
            actor,
            authority_timeline,
            policy,
            registry_digest,
        );
        let grants = vec![parent.clone(), child.clone()];
        let registry = authority_registry(&request, &grants, registry_digest, trust_capability);
        let chain = test_ok(DelegationChainV1::try_from_grants(grants));
        let decision = AuthorityEvaluatorV1::authorize(&request, &chain, &registry);
        let persistence_registry = authority_registry(
            &request,
            &[parent.clone(), child.clone()],
            registry_digest,
            true,
        );
        let host = AuthorityPersistenceHostV1::new(&persistence_registry);
        let mut state = AuthorityPersistenceStateV1::new();
        test_ok(state.issue_grant(test_ok(host.authorize_grant(&parent)), parent));
        test_ok(state.issue_grant(test_ok(host.authorize_grant(&child)), child));
        CacheFixture {
            decision,
            registry,
            request,
            authority: test_ok(state.resolve(grant_id)),
            parent_grant_id,
            consent_reference,
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authorization_cache_expires_at_the_shortest_time_or_position() {
        let fixture = active_decision(TimelineId::new());
        let mut by_time = AuthorizationCacheV1::new();
        let key = by_time
            .insert_active(
                fixture.request.authority_timeline(),
                fixture.decision.clone(),
                &fixture.request,
                &fixture.authority,
                &fixture.registry,
                cache_generation(1),
            )
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("active decision rejected")));
        assert!(by_time
            .get(
                &key,
                WallTime::from_micros(99),
                Seq::from_u64(79),
                &fixture.request,
                &fixture.authority,
                &fixture.registry,
                cache_generation(1),
            )
            .is_some());
        assert!(by_time
            .get(
                &key,
                WallTime::from_micros(100),
                Seq::from_u64(79),
                &fixture.request,
                &fixture.authority,
                &fixture.registry,
                cache_generation(1),
            )
            .is_none());
        assert!(by_time.is_empty());

        let mut by_position = AuthorizationCacheV1::new();
        let key = by_position
            .insert_active(
                fixture.request.authority_timeline(),
                fixture.decision,
                &fixture.request,
                &fixture.authority,
                &fixture.registry,
                cache_generation(1),
            )
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("active decision rejected")));
        assert!(by_position
            .get(
                &key,
                WallTime::from_micros(99),
                Seq::from_u64(80),
                &fixture.request,
                &fixture.authority,
                &fixture.registry,
                cache_generation(1),
            )
            .is_none());
    }

    #[test]
    fn authorization_cache_uses_resolved_consent_expiry() {
        let fixture = active_decision(TimelineId::new());
        let request = projection_request(
            &fixture.request,
            Some(EntityId::new()),
            Some(EntityId::new()),
            None,
            ConsentEvidenceV1::Resolved {
                grants: vec![cache_consent_grant(50)],
            },
            None,
        );
        let mut cache = AuthorizationCacheV1::new();
        assert!(cache
            .insert_active(
                fixture.request.authority_timeline(),
                fixture.decision,
                &request,
                &fixture.authority,
                &fixture.registry,
                cache_generation(1),
            )
            .is_none());
    }

    #[test]
    fn authorization_cache_rejects_a_pre_freeze_generation_hit() {
        let fixture = active_decision(TimelineId::new());
        let installed = cache_generation(1);
        let successor = cache_generation(2);
        let mut cache = AuthorizationCacheV1::new();
        let key = cache
            .insert_active(
                fixture.request.authority_timeline(),
                fixture.decision,
                &fixture.request,
                &fixture.authority,
                &fixture.registry,
                installed,
            )
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("active decision rejected")));

        assert_eq!(key.inventory_generation(), installed);
        assert!(cache
            .get(
                &key,
                WallTime::from_micros(99),
                Seq::from_u64(79),
                &fixture.request,
                &fixture.authority,
                &fixture.registry,
                successor,
            )
            .is_none());
        assert!(cache.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authorization_cache_invalidates_parent_consent_and_stale_epoch() {
        let timeline = TimelineId::new();
        let other_timeline = TimelineId::new();
        let fixture = active_decision(timeline);
        let other = active_decision(other_timeline);

        let mut grant_cache = AuthorizationCacheV1::new();
        assert!(grant_cache
            .insert_active(
                fixture.request.authority_timeline(),
                fixture.decision.clone(),
                &fixture.request,
                &fixture.authority,
                &fixture.registry,
                cache_generation(1),
            )
            .is_some());
        assert_eq!(grant_cache.invalidate_grant(fixture.parent_grant_id), 1);
        assert!(grant_cache.is_empty());

        let mut consent_cache = AuthorizationCacheV1::new();
        assert!(consent_cache
            .insert_active(
                fixture.request.authority_timeline(),
                fixture.decision.clone(),
                &fixture.request,
                &fixture.authority,
                &fixture.registry,
                cache_generation(1),
            )
            .is_some());
        assert_eq!(
            consent_cache.invalidate_consent(fixture.consent_reference),
            1
        );

        let mut epoch_cache = AuthorizationCacheV1::new();
        assert!(epoch_cache
            .insert_active(
                fixture.request.authority_timeline(),
                fixture.decision,
                &fixture.request,
                &fixture.authority,
                &fixture.registry,
                cache_generation(1),
            )
            .is_some());
        assert!(epoch_cache
            .insert_active(
                other.request.authority_timeline(),
                other.decision,
                &other.request,
                &other.authority,
                &other.registry,
                cache_generation(1),
            )
            .is_some());
        assert_eq!(epoch_cache.len(), 2);
        assert_eq!(epoch_cache.retain_revocation_epoch(timeline, 1), 1);
        assert_eq!(epoch_cache.len(), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn authorization_cache_rejects_mismatched_or_denied_entries() {
        let timeline = TimelineId::new();
        let fixture = active_decision(timeline);
        let mismatched = active_decision(TimelineId::new());
        let mismatched_chain = decision_with_capability_trust(timeline, test_hash(15), true);
        let mut cache = AuthorizationCacheV1::new();
        assert!(cache
            .insert_active(
                fixture.request.authority_timeline(),
                fixture.decision.clone(),
                &mismatched.request,
                &fixture.authority,
                &fixture.registry,
                cache_generation(1),
            )
            .is_none());
        assert!(cache
            .insert_active(
                fixture.request.authority_timeline(),
                fixture.decision.clone(),
                &fixture.request,
                &mismatched_chain.authority,
                &fixture.registry,
                cache_generation(1),
            )
            .is_none());

        let denied = decision_with_capability_trust(timeline, test_hash(5), false);
        assert!(!denied.decision.is_allowed());
        assert!(cache
            .insert_active(
                denied.request.authority_timeline(),
                denied.decision,
                &denied.request,
                &denied.authority,
                &denied.registry,
                cache_generation(1),
            )
            .is_none());
    }

    #[test]
    fn authorization_cache_rechecks_current_authority_before_exposure() {
        let timeline = TimelineId::new();
        let fixture = active_decision(timeline);
        let changed = decision_with_capability_trust(timeline, test_hash(15), true);
        let denied = decision_with_capability_trust(timeline, test_hash(5), false);
        let mut cache = AuthorizationCacheV1::new();
        let key = cache
            .insert_active(
                fixture.request.authority_timeline(),
                fixture.decision.clone(),
                &fixture.request,
                &fixture.authority,
                &fixture.registry,
                cache_generation(1),
            )
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("active decision rejected")));
        assert!(cache
            .get(
                &key,
                WallTime::from_micros(99),
                Seq::from_u64(79),
                &fixture.request,
                &changed.authority,
                &fixture.registry,
                cache_generation(1),
            )
            .is_none());
        assert!(cache.is_empty());
        let key = cache
            .insert_active(
                fixture.request.authority_timeline(),
                fixture.decision.clone(),
                &fixture.request,
                &fixture.authority,
                &fixture.registry,
                cache_generation(1),
            )
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("active decision rejected")));
        assert!(cache
            .get(
                &key,
                WallTime::from_micros(99),
                Seq::from_u64(79),
                &fixture.request,
                &fixture.authority,
                &denied.registry,
                cache_generation(1),
            )
            .is_none());
        assert!(cache.is_empty());
        assert!(cache
            .insert_active(
                fixture.request.authority_timeline(),
                fixture.decision,
                &fixture.request,
                &fixture.authority,
                &denied.registry,
                cache_generation(1),
            )
            .is_none());
    }

    #[test]
    fn host_cache_rechecks_authority_and_evicts_frozen_entries() {
        let limits = test_ok(ErasureRecoveryLimitsV1::new(4, 4, 4));
        let mut host = test_ok(ErasureExecutionHostV1::open_verified_empty(
            StoreConfig::Memory,
            limits,
        ));
        let timeline = test_ok(test_ok(host.command_sender()).create_timeline("authority"));
        let resource = test_ok(test_ok(host.command_sender()).create_timeline("resource"));
        let fixture = active_decision(timeline.id());
        let key = test_ok(test_ok(host.command_sender()).cache_authorization(
            resource.id(),
            &fixture.request,
            &fixture.authority,
            &fixture.registry,
        ))
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("active decision rejected")));
        let hit = test_ok(test_ok(host.command_sender()).cached_authorization(
            &key,
            WallTime::from_micros(20),
            Seq::from_u64(20),
            &fixture.request,
            &fixture.authority,
            &fixture.registry,
        ));
        assert_eq!(hit, Some(fixture.decision.clone()));
        let changed = decision_with_capability_trust(timeline.id(), test_hash(15), true);
        assert!(test_ok(test_ok(host.command_sender()).cached_authorization(
            &key,
            WallTime::from_micros(20),
            Seq::from_u64(20),
            &fixture.request,
            &changed.authority,
            &fixture.registry,
        ))
        .is_none());
        let key = test_ok(test_ok(host.command_sender()).cache_authorization(
            resource.id(),
            &fixture.request,
            &fixture.authority,
            &fixture.registry,
        ))
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("active decision rejected")));
        host.freeze_timeline_for_test(resource.id());
        assert!(test_ok(host.command_sender())
            .cached_authorization(
                &key,
                WallTime::from_micros(20),
                Seq::from_u64(20),
                &fixture.request,
                &fixture.authority,
                &fixture.registry,
            )
            .is_err());
    }

    #[test]
    fn host_cache_fences_authority_and_consent_timelines() {
        for freeze_consent in [false, true] {
            let mut host = test_ok(ErasureExecutionHostV1::open_verified_empty(
                StoreConfig::Memory,
                test_ok(ErasureRecoveryLimitsV1::new(4, 4, 4)),
            ));
            let (authority, consent, resource) = {
                let mut sender = test_ok(host.command_sender());
                (
                    test_ok(sender.create_timeline("authority")),
                    test_ok(sender.create_timeline("consent")),
                    test_ok(sender.create_timeline("resource")),
                )
            };
            let fixture = active_decision(authority.id());
            let request = projection_request(
                &fixture.request,
                Some(EntityId::new()),
                Some(EntityId::new()),
                None,
                ConsentEvidenceV1::Resolved {
                    grants: vec![cache_consent_grant(50)],
                },
                Some(consent.id()),
            );
            assert!(test_ok(test_ok(host.command_sender()).cache_authorization(
                resource.id(),
                &request,
                &fixture.authority,
                &fixture.registry,
            ))
            .is_none());

            let blocked = if freeze_consent {
                consent.id()
            } else {
                authority.id()
            };
            host.freeze_timeline_for_test(blocked);
            assert!(matches!(
                test_ok(host.command_sender()).cache_authorization(
                    resource.id(),
                    &request,
                    &fixture.authority,
                    &fixture.registry,
                ),
                Err(pos_core::ErasureHostErrorV1::AccessFrozen)
            ));
        }
    }

    #[test]
    fn host_cache_drops_old_generation_after_topology_change() {
        let limits = test_ok(ErasureRecoveryLimitsV1::new(4, 4, 4));
        let mut host = test_ok(ErasureExecutionHostV1::open_verified_empty(
            StoreConfig::Memory,
            limits,
        ));
        let timeline = test_ok(test_ok(host.command_sender()).create_timeline("authority"));
        let fixture = active_decision(timeline.id());
        let key = test_ok(test_ok(host.command_sender()).cache_authorization(
            timeline.id(),
            &fixture.request,
            &fixture.authority,
            &fixture.registry,
        ))
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("active decision rejected")));
        test_ok(test_ok(host.command_sender()).create_timeline("successor"));
        assert!(test_ok(test_ok(host.command_sender()).cached_authorization(
            &key,
            WallTime::from_micros(20),
            Seq::from_u64(20),
            &fixture.request,
            &fixture.authority,
            &fixture.registry,
        ))
        .is_none());
    }

    #[test]
    fn host_cache_revocation_invalidates_before_exposure_on_both_stores() {
        for config in [StoreConfig::Memory, StoreConfig::SqliteInMemory] {
            let limits = test_ok(ErasureRecoveryLimitsV1::new(4, 4, 4));
            let mut host = test_ok(ErasureExecutionHostV1::open_verified_empty(config, limits));
            let timeline = test_ok(test_ok(host.command_sender()).create_timeline("authority"));
            let fixture = active_decision(timeline.id());

            let grant_key = test_ok(test_ok(host.command_sender()).cache_authorization(
                timeline.id(),
                &fixture.request,
                &fixture.authority,
                &fixture.registry,
            ))
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("active decision rejected")));
            assert_eq!(
                test_ok(host.command_sender()).invalidate_cached_grant(fixture.parent_grant_id),
                1
            );
            assert!(test_ok(test_ok(host.command_sender()).cached_authorization(
                &grant_key,
                WallTime::from_micros(20),
                Seq::from_u64(20),
                &fixture.request,
                &fixture.authority,
                &fixture.registry,
            ))
            .is_none());

            let consent_key = test_ok(test_ok(host.command_sender()).cache_authorization(
                timeline.id(),
                &fixture.request,
                &fixture.authority,
                &fixture.registry,
            ))
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("active decision rejected")));
            assert_eq!(
                test_ok(host.command_sender()).invalidate_cached_consent(fixture.consent_reference),
                1
            );
            assert!(test_ok(test_ok(host.command_sender()).cached_authorization(
                &consent_key,
                WallTime::from_micros(20),
                Seq::from_u64(20),
                &fixture.request,
                &fixture.authority,
                &fixture.registry,
            ))
            .is_none());

            let epoch_key = test_ok(test_ok(host.command_sender()).cache_authorization(
                timeline.id(),
                &fixture.request,
                &fixture.authority,
                &fixture.registry,
            ))
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("active decision rejected")));
            assert_eq!(
                test_ok(host.command_sender()).retain_cached_revocation_epoch(timeline.id(), 1),
                1
            );
            assert!(test_ok(test_ok(host.command_sender()).cached_authorization(
                &epoch_key,
                WallTime::from_micros(20),
                Seq::from_u64(20),
                &fixture.request,
                &fixture.authority,
                &fixture.registry,
            ))
            .is_none());
        }
    }
}
