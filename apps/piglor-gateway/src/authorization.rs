//! Provider-neutral Gateway authentication and authorization seams.
//!
//! Authentication adapters only establish minimized Principal evidence.  The
//! Gateway owns construction of the authority request and delegates the policy
//! decision to the provider-neutral `pos-core` evaluator.  No credential,
//! bearer value, or provider-specific policy is retained here.
//!
//! The public seam implements the accepted [ADR-059 composition](https://redmine.piglor.com/projects/pigloros/wiki/ADR-059_Participant_Knowledge_Observation_and_Structured_Causal_Trace)
//! tracked by Redmine #180; the wiki page remains canonical.

use pos_core::{
    AuthenticatedPrincipalResultV1, AuthorityErrorV1, AuthorityEvaluatorV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, AuthorizationDecisionV1,
    AuthorizationRequestDraftV1, AuthorizationRequestV1, ConsentEvidenceV1, EntityId, EventId,
    Hash, PersistedAuthorityV1, PluginId, PrincipalRefV1, Seq, TimelineId, WallTime,
};
use std::{
    collections::VecDeque,
    sync::{Arc, RwLock},
};
use thiserror::Error;
use tokio::sync::{Mutex, OwnedMutexGuard};

const MAX_AUTHORIZATION_AUDITS: usize = 1_024;

/// Opaque, non-secret context supplied to one authentication adapter call.
///
/// The context is derived from the operation's stable authorization fields. It
/// deliberately contains no HTTP headers, bearer material, payload bytes, or
/// provider-specific token representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayAuthenticationRequest {
    operation_binding: Hash,
}

impl GatewayAuthenticationRequest {
    #[must_use]
    pub const fn operation_binding(self) -> Hash {
        self.operation_binding
    }
}

/// Stable adapter failures.  Implementations must not return provider or
/// credential details because these values can cross the public Gateway error
/// boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum GatewayAuthenticationError {
    #[error("authentication unavailable")]
    Unavailable,
    #[error("authentication evidence invalid")]
    InvalidEvidence,
}

/// Gateway authentication adapter boundary.
///
/// Implementations establish a validated [`AuthenticatedPrincipalResultV1`]
/// and do not evaluate capability, consent, delegation, or revocation policy.
/// A deployment may bind the adapter to local or Air-Gapped input without
/// selecting `WebAuthn`, `JWT`, `OAuth`, or a hosted identity provider here.
pub trait GatewayAuthenticationAdapter: Send + Sync {
    /// Establish minimized Principal evidence for one operation.
    ///
    /// # Errors
    /// Returns only a stable adapter error; credential and provider details do
    /// not cross this seam.
    fn authenticate(
        &self,
        request: &GatewayAuthenticationRequest,
    ) -> Result<AuthenticatedPrincipalResultV1, GatewayAuthenticationError>;
}

/// Local adapter backed by host-pinned, already-minimized Principal evidence.
#[derive(Clone)]
pub struct LocalAuthenticationAdapter {
    evidence: AuthenticatedPrincipalResultV1,
}

impl LocalAuthenticationAdapter {
    #[must_use]
    pub const fn new(evidence: AuthenticatedPrincipalResultV1) -> Self {
        Self { evidence }
    }
}

impl GatewayAuthenticationAdapter for LocalAuthenticationAdapter {
    fn authenticate(
        &self,
        _request: &GatewayAuthenticationRequest,
    ) -> Result<AuthenticatedPrincipalResultV1, GatewayAuthenticationError> {
        Ok(self.evidence.clone())
    }
}

/// Air-Gapped adapter backed by the same pinned, minimized Principal evidence.
///
/// The adapter intentionally has the same behavior as the local adapter for a
/// given pinned result.  Freshness and revocation remain host authority state,
/// not adapter-specific policy.
#[derive(Clone)]
pub struct AirGappedAuthenticationAdapter {
    evidence: AuthenticatedPrincipalResultV1,
}

impl AirGappedAuthenticationAdapter {
    #[must_use]
    pub const fn new(evidence: AuthenticatedPrincipalResultV1) -> Self {
        Self { evidence }
    }
}

impl GatewayAuthenticationAdapter for AirGappedAuthenticationAdapter {
    fn authenticate(
        &self,
        _request: &GatewayAuthenticationRequest,
    ) -> Result<AuthenticatedPrincipalResultV1, GatewayAuthenticationError> {
        Ok(self.evidence.clone())
    }
}

/// Stable Gateway authorization failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum GatewayAuthorizationError {
    #[error("authentication unavailable")]
    AuthenticationUnavailable,
    #[error("authorization request unavailable")]
    RequestUnavailable,
    #[error("authorization state unavailable")]
    AuthorityUnavailable,
    #[error("authorization denied")]
    AuthorizationDenied,
}

/// Public operation inputs resolved by the Gateway before authority evaluation.
///
/// `actor_entity_id` is the simulation actor.  It is intentionally separate
/// from the Principal emitted by the adapter.  Protected subject operations
/// must set `subject_id` and provide resolved consent evidence; no field is
/// inferred from the Principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayAuthorizationRequest {
    pub actor_entity_id: EntityId,
    pub subject_id: Option<EntityId>,
    pub participant_id: Option<EntityId>,
    pub plugin_id: Option<PluginId>,
    pub installation_id: Option<[u8; 16]>,
    pub principal_role: AuthorityRoleV1,
    pub resource: String,
    pub data_category: String,
    pub action: String,
    pub purpose: String,
    pub audience: String,
    pub at_time: WallTime,
    pub at_position: Seq,
    pub authority_timeline: Option<TimelineId>,
    pub consent_timeline: Option<TimelineId>,
    pub consent_at_position: Option<Seq>,
    pub use_count: u64,
    pub budget: u64,
    pub consent_policy_revision: Hash,
    pub capability_policy_revision: Hash,
    pub revocation_state_current: bool,
    pub consent: ConsentEvidenceV1,
    pub environment_constraints: Vec<String>,
}

impl GatewayAuthorizationRequest {
    /// Build an action request whose resource is the event type and whose action
    /// is the exact capability string later checked by `ActionApprover`.
    #[must_use]
    pub fn action(
        actor_entity_id: EntityId,
        event_type: impl Into<String>,
        capability: impl Into<String>,
        at_time: WallTime,
    ) -> Self {
        let event_type = event_type.into();
        Self {
            actor_entity_id,
            subject_id: None,
            participant_id: None,
            plugin_id: None,
            installation_id: None,
            principal_role: AuthorityRoleV1::Actor,
            resource: event_type.clone(),
            data_category: event_type,
            action: capability.into(),
            purpose: "action".to_owned(),
            audience: "gateway".to_owned(),
            at_time,
            at_position: Seq::ZERO,
            authority_timeline: None,
            consent_timeline: None,
            consent_at_position: None,
            use_count: 1,
            budget: 1,
            consent_policy_revision: Hash::zero(),
            capability_policy_revision: Hash::zero(),
            revocation_state_current: true,
            consent: ConsentEvidenceV1::NotRequired,
            environment_constraints: Vec::new(),
        }
    }

    /// Build a timeline read request for the protected Gateway read seam.
    #[must_use]
    pub fn read(actor_entity_id: EntityId, at_time: WallTime) -> Self {
        Self {
            actor_entity_id,
            subject_id: None,
            participant_id: None,
            plugin_id: None,
            installation_id: None,
            principal_role: AuthorityRoleV1::Actor,
            resource: "timeline.events".to_owned(),
            data_category: "timeline.events".to_owned(),
            action: "read".to_owned(),
            purpose: "read".to_owned(),
            audience: "gateway".to_owned(),
            at_time,
            at_position: Seq::ZERO,
            authority_timeline: None,
            consent_timeline: None,
            consent_at_position: None,
            use_count: 1,
            budget: 1,
            consent_policy_revision: Hash::zero(),
            capability_policy_revision: Hash::zero(),
            revocation_state_current: true,
            consent: ConsentEvidenceV1::NotRequired,
            environment_constraints: Vec::new(),
        }
    }
}

/// Immutable, minimized authorization evidence suitable for audit records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayAuthorizationAudit {
    principal: PrincipalRefV1,
    actor_entity_id: EntityId,
    request_digest: Hash,
    decision_digest: Hash,
    event_id: Option<EventId>,
}

impl GatewayAuthorizationAudit {
    #[must_use]
    pub const fn principal(&self) -> &PrincipalRefV1 {
        &self.principal
    }

    #[must_use]
    pub const fn actor_entity_id(&self) -> EntityId {
        self.actor_entity_id
    }

    #[must_use]
    pub const fn request_digest(&self) -> Hash {
        self.request_digest
    }

    #[must_use]
    pub const fn decision_digest(&self) -> Hash {
        self.decision_digest
    }

    #[must_use]
    pub const fn event_id(&self) -> Option<EventId> {
        self.event_id
    }

    #[must_use]
    pub(crate) const fn with_event_id(mut self, event_id: EventId) -> Self {
        self.event_id = Some(event_id);
        self
    }
}

/// Result of one host authorization evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayAuthorizationDecision {
    request: GatewayAuthorizationRequest,
    authenticated: AuthenticatedPrincipalResultV1,
    decision: AuthorizationDecisionV1,
}

impl GatewayAuthorizationDecision {
    #[must_use]
    pub const fn authenticated(&self) -> &AuthenticatedPrincipalResultV1 {
        &self.authenticated
    }

    #[must_use]
    pub const fn principal(&self) -> &PrincipalRefV1 {
        self.decision.principal()
    }

    #[must_use]
    pub const fn actor_entity_id(&self) -> EntityId {
        self.decision.actor_entity_id()
    }

    #[must_use]
    pub const fn decision(&self) -> &AuthorizationDecisionV1 {
        &self.decision
    }

    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        self.decision.is_allowed()
    }

    #[must_use]
    pub const fn request_digest(&self) -> Hash {
        self.decision.request_digest()
    }

    #[must_use]
    pub const fn decision_digest(&self) -> Hash {
        self.decision.decision_digest()
    }

    #[must_use]
    pub fn audit(&self) -> GatewayAuthorizationAudit {
        GatewayAuthorizationAudit {
            principal: self.decision.principal().clone(),
            actor_entity_id: self.decision.actor_entity_id(),
            request_digest: self.decision.request_digest(),
            decision_digest: self.decision.decision_digest(),
            event_id: None,
        }
    }

    #[must_use]
    pub const fn request(&self) -> &GatewayAuthorizationRequest {
        &self.request
    }
}

/// Host-owned authority evaluator used by Gateway protected seams.
#[derive(Clone)]
pub struct GatewayAuthorization {
    adapter: Arc<dyn GatewayAuthenticationAdapter>,
    authority: Arc<RwLock<PersistedAuthorityV1>>,
    registry: AuthorityRegistrySnapshotV1,
    commit_lock: Arc<Mutex<()>>,
    audits: Arc<Mutex<VecDeque<GatewayAuthorizationAudit>>>,
}

impl GatewayAuthorization {
    /// Bind one authentication adapter to a trusted, pinned authority snapshot.
    #[must_use]
    pub fn new(
        adapter: Arc<dyn GatewayAuthenticationAdapter>,
        authority: PersistedAuthorityV1,
        registry: AuthorityRegistrySnapshotV1,
    ) -> Self {
        Self {
            adapter,
            authority: Arc::new(RwLock::new(authority)),
            registry,
            commit_lock: Arc::new(Mutex::new(())),
            audits: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Evaluate a request and return its complete structured decision.
    ///
    /// A denied decision remains available to callers that need a typed audit
    /// outcome.  Use [`Self::authorize`] for a stable fail-closed result.
    ///
    /// # Errors
    /// Returns a stable authentication, authority-state, or request-validation
    /// error when the host cannot establish a complete decision.
    pub fn evaluate(
        &self,
        request: GatewayAuthorizationRequest,
    ) -> Result<GatewayAuthorizationDecision, GatewayAuthorizationError> {
        let operation_binding = operation_binding(&request);
        self.adapter
            .authenticate(&GatewayAuthenticationRequest { operation_binding })
            .map_err(|_| GatewayAuthorizationError::AuthenticationUnavailable)
            .and_then(|authenticated| {
                self.authority
                    .read()
                    .map(|authority| authority.clone())
                    .map_err(|_| GatewayAuthorizationError::AuthorityUnavailable)
                    .and_then(|authority| {
                        core_request(&request, &authenticated, &authority, &self.registry)
                            .map_err(|_| GatewayAuthorizationError::RequestUnavailable)
                            .map(|core_request| GatewayAuthorizationDecision {
                                request,
                                authenticated,
                                decision: AuthorityEvaluatorV1::authorize(
                                    &core_request,
                                    authority.chain(),
                                    &self.registry,
                                ),
                            })
                    })
            })
    }

    /// Evaluate and require an active authorization decision.
    ///
    /// # Errors
    /// Returns a stable authorization-denied error or one of the host
    /// authentication, authority-state, or request-validation errors.
    pub fn authorize(
        &self,
        request: GatewayAuthorizationRequest,
    ) -> Result<GatewayAuthorizationDecision, GatewayAuthorizationError> {
        self.evaluate(request).and_then(|decision| {
            if decision.is_allowed() {
                Ok(decision)
            } else {
                Err(GatewayAuthorizationError::AuthorizationDenied)
            }
        })
    }

    /// Replace the pinned authority snapshot at a host-controlled fence.
    ///
    /// The same commit lock used by Gateway appends prevents an update from
    /// racing a final authorization check and append.
    ///
    /// # Errors
    /// Returns [`GatewayAuthorizationError::AuthorityUnavailable`] when the
    /// host authority lock is poisoned and cannot be replaced safely.
    pub async fn replace_authority(
        &self,
        authority: PersistedAuthorityV1,
    ) -> Result<(), GatewayAuthorizationError> {
        let _guard = self.commit_lock.lock().await;
        self.authority
            .write()
            .map(|mut current| {
                *current = authority;
            })
            .map_err(|_| GatewayAuthorizationError::AuthorityUnavailable)
    }

    /// Retain one accepted action's minimized authorization audit.
    pub(crate) async fn record_audit(&self, audit: GatewayAuthorizationAudit) {
        let mut audits = self.audits.lock().await;
        if audits.len() >= MAX_AUTHORIZATION_AUDITS {
            audits.pop_front();
        }
        audits.push_back(audit);
    }

    /// Return the minimized authorization audits retained by this Gateway host.
    #[must_use]
    pub async fn audits(&self) -> Vec<GatewayAuthorizationAudit> {
        self.audits.lock().await.iter().cloned().collect()
    }

    /// Acquire the append fence used by the Gateway before a final recheck.
    pub(crate) async fn commit_fence(&self) -> OwnedMutexGuard<()> {
        Arc::clone(&self.commit_lock).lock_owned().await
    }
}

fn core_request(
    request: &GatewayAuthorizationRequest,
    authenticated: &AuthenticatedPrincipalResultV1,
    authority: &PersistedAuthorityV1,
    registry: &AuthorityRegistrySnapshotV1,
) -> Result<AuthorizationRequestV1, AuthorityErrorV1> {
    let Some(leaf) = authority.chain().grants().last() else {
        return Err(AuthorityErrorV1::CapabilityMissing);
    };
    let authority_timeline = request
        .authority_timeline
        .unwrap_or_else(|| leaf.issuance_timeline());
    let at_position = request.at_position.max(authority.head_position());
    let capability_policy_revision =
        nonzero_or(request.capability_policy_revision, leaf.policy_revision());
    let consent_policy_revision =
        nonzero_or(request.consent_policy_revision, leaf.policy_revision());
    AuthorizationRequestV1::try_from_draft(AuthorizationRequestDraftV1 {
        authenticated: authenticated.clone(),
        actor_entity_id: request.actor_entity_id,
        subject_id: request.subject_id,
        participant_id: request.participant_id,
        plugin_id: request.plugin_id,
        installation_id: request.installation_id,
        principal_role: request.principal_role,
        resource: request.resource.clone(),
        data_category: request.data_category.clone(),
        action: request.action.clone(),
        purpose: request.purpose.clone(),
        audience: request.audience.clone(),
        at_time: request.at_time,
        authority_timeline,
        at_position,
        consent_timeline: request.consent_timeline,
        consent_at_position: request.consent_at_position,
        use_count: request.use_count,
        budget: request.budget,
        consent_policy_revision,
        capability_policy_revision,
        revocation_epoch: authority.revocation_epoch(),
        revocation_state_current: request.revocation_state_current,
        authority_registry_digest: registry.registry_digest(),
        consent: request.consent.clone(),
        environment_constraints: request.environment_constraints.clone(),
    })
}

fn nonzero_or(value: Hash, fallback: Hash) -> Hash {
    if value == Hash::zero() {
        fallback
    } else {
        value
    }
}

fn operation_binding(request: &GatewayAuthorizationRequest) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.GatewayAuthorizationRequest.v1\0");
    hasher.update(request.actor_entity_id.to_string().as_bytes());
    for value in [
        request.resource.as_str(),
        request.data_category.as_str(),
        request.action.as_str(),
        request.purpose.as_str(),
        request.audience.as_str(),
    ] {
        hasher.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

#[cfg(test)]
pub(crate) fn test_authorization_for(actor: EntityId) -> GatewayAuthorization {
    tests::fixture_authorization_with_actor(actor)
}

#[cfg(test)]
pub(crate) fn test_authorization_unavailable_for(actor: EntityId) -> GatewayAuthorization {
    tests::fixture_authorization_unavailable_with_actor(actor)
}

#[cfg(test)]
pub(crate) fn test_revoked_authority_for(actor: EntityId) -> PersistedAuthorityV1 {
    tests::fixture_revoked_authority_with_actor(actor)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_core::{
        AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthorityGranteeV1,
        AuthorityPersistenceHostV1, AuthorityPersistenceStateV1, CapabilityGrantDraftV1,
        CapabilityGrantV1, CapabilityRevocationDraftV1, CapabilityRevocationV1,
        CapabilityScopeDraftV1, CapabilityScopeV1, PrincipalRefV1,
    };

    trait TestOk<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestOk<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!("fixture error: {error:?}")))
            })
        }
    }

    const fn hash(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    struct Fixture {
        authorization: GatewayAuthorization,
        authenticated: AuthenticatedPrincipalResultV1,
        actor: EntityId,
        authority: PersistedAuthorityV1,
        revoked_authority: PersistedAuthorityV1,
    }

    fn fixture() -> Fixture {
        fixture_with_actor(EntityId::new())
    }

    fn fixture_with_actor(actor: EntityId) -> Fixture {
        let principal = PrincipalRefV1::try_new([1; 16], "gateway.test").test_ok();
        let authenticated =
            AuthenticatedPrincipalResultV1::try_from_draft(AuthenticatedPrincipalDraftV1 {
                principal: principal.clone(),
                adapter_id: "fixture".to_owned(),
                assurance: AssuranceLevelV1::try_new(1).test_ok(),
                issued_at: WallTime::from_micros(1),
                expires_at: WallTime::from_micros(u64::MAX),
                binding_digest: hash(2),
            })
            .test_ok();
        let authority_timeline = TimelineId::new();
        let registry_digest = hash(3);
        let policy_revision = hash(4);
        let scope = CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
            resources: vec!["timeline.events".to_owned(), "world.action".to_owned()],
            actions: vec!["read".to_owned(), "world.action.submit".to_owned()],
            purposes: vec!["action".to_owned(), "read".to_owned()],
            audiences: vec!["gateway".to_owned()],
            actor_entity_ids: vec![actor],
            subject_ids: Vec::new(),
            participant_ids: Vec::new(),
            plugin_id: None,
            principal_roles: vec![AuthorityRoleV1::Actor],
            max_uses: 1,
            budget: 1,
            environment_constraints: Vec::new(),
        })
        .test_ok();
        let grant = CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
            grant_id: hash(5),
            grantor: principal.clone(),
            grantee: AuthorityGranteeV1::Principal(principal),
            trust_domain: "gateway.test".to_owned(),
            scope,
            valid_from_position: Seq::from_u64(1),
            valid_until_position: Seq::from_u64(50),
            parent_grant_id: None,
            delegation_depth: 0,
            max_delegation_depth: 0,
            permitted_delegate_classes: Vec::new(),
            consent_references: Vec::new(),
            policy_revision,
            issuance_timeline: authority_timeline,
            issuance_seq: Seq::from_u64(1),
            revocation_epoch: 0,
            revocation_fence: None,
            authority_registry_digest: registry_digest,
        })
        .test_ok();
        let registry = AuthorityRegistrySnapshotV1::try_new(
            registry_digest,
            vec![authenticated.registry_binding_digest()],
            vec![grant.binding_digest().test_ok()],
            Vec::new(),
        )
        .test_ok();
        let host = AuthorityPersistenceHostV1::new(&registry);
        let mut state = AuthorityPersistenceStateV1::new();
        state
            .issue_grant(host.authorize_grant(&grant).test_ok(), grant.clone())
            .test_ok();
        let authority = state.resolve(grant.grant_id()).test_ok();
        let revocation = CapabilityRevocationV1::try_from_draft(CapabilityRevocationDraftV1 {
            grant_id: grant.grant_id(),
            authority_timeline,
            fence_position: Seq::from_u64(2),
            revocation_epoch: 1,
            policy_revision,
            authority_registry_digest: registry_digest,
        })
        .test_ok();
        state
            .revoke_grant(
                host.authorize_revocation(&grant, &revocation).test_ok(),
                revocation,
            )
            .test_ok();
        let revoked_authority = state.resolve(grant.grant_id()).test_ok();
        let authorization = GatewayAuthorization::new(
            Arc::new(LocalAuthenticationAdapter::new(authenticated.clone())),
            authority.clone(),
            registry,
        );
        Fixture {
            authorization,
            authenticated,
            actor,
            authority,
            revoked_authority,
        }
    }

    pub(super) fn fixture_authorization_with_actor(actor: EntityId) -> GatewayAuthorization {
        fixture_with_actor(actor).authorization
    }

    pub(super) fn fixture_authorization_unavailable_with_actor(
        actor: EntityId,
    ) -> GatewayAuthorization {
        let fixture = fixture_with_actor(actor);
        GatewayAuthorization::new(
            Arc::new(RejectingAdapter),
            fixture.authority,
            fixture.authorization.registry.clone(),
        )
    }

    pub(super) fn fixture_revoked_authority_with_actor(actor: EntityId) -> PersistedAuthorityV1 {
        fixture_with_actor(actor).revoked_authority
    }

    fn action(fixture: &Fixture) -> GatewayAuthorizationRequest {
        GatewayAuthorizationRequest::action(
            fixture.actor,
            "world.action",
            "world.action.submit",
            WallTime::from_micros(10),
        )
    }

    #[test]
    fn local_adapter_establishes_minimized_principal_evidence() {
        let fixture = fixture();
        let request = GatewayAuthenticationRequest {
            operation_binding: hash(9),
        };
        let result = GatewayAuthenticationAdapter::authenticate(
            &LocalAuthenticationAdapter::new(fixture.authenticated.clone()),
            &request,
        )
        .test_ok();
        assert_eq!(result, fixture.authenticated);
        assert_eq!(request.operation_binding(), hash(9));
    }

    struct RejectingAdapter;

    impl GatewayAuthenticationAdapter for RejectingAdapter {
        fn authenticate(
            &self,
            _request: &GatewayAuthenticationRequest,
        ) -> Result<AuthenticatedPrincipalResultV1, GatewayAuthenticationError> {
            Err(GatewayAuthenticationError::Unavailable)
        }
    }

    #[test]
    fn adapter_failure_is_stable_and_does_not_reveal_evidence() {
        let fixture = fixture();
        let authorization = GatewayAuthorization::new(
            Arc::new(RejectingAdapter),
            fixture.authority.clone(),
            fixture.authorization.registry.clone(),
        );
        assert_eq!(
            authorization.evaluate(action(&fixture)),
            Err(GatewayAuthorizationError::AuthenticationUnavailable)
        );
    }

    #[test]
    fn malformed_operation_is_rejected_before_policy_evaluation() {
        let fixture = fixture();
        let mut request = action(&fixture);
        request.resource.clear();
        assert_eq!(
            fixture.authorization.evaluate(request),
            Err(GatewayAuthorizationError::RequestUnavailable)
        );
    }

    #[test]
    fn local_and_air_gapped_adapters_have_identical_authority_semantics() {
        let fixture = fixture();
        let local = GatewayAuthorization::new(
            Arc::new(LocalAuthenticationAdapter::new(
                fixture.authenticated.clone(),
            )),
            fixture.authority.clone(),
            fixture.authorization.registry.clone(),
        );
        let air_gapped = GatewayAuthorization::new(
            Arc::new(AirGappedAuthenticationAdapter::new(
                fixture.authenticated.clone(),
            )),
            fixture.authority.clone(),
            fixture.authorization.registry.clone(),
        );
        let local_decision = local.authorize(action(&fixture)).test_ok();
        let air_decision = air_gapped.authorize(action(&fixture)).test_ok();
        assert_eq!(local_decision.decision(), air_decision.decision());
        assert_eq!(local_decision.audit(), air_decision.audit());
    }

    #[test]
    fn denied_decision_does_not_enumerate_principal_or_entity() {
        let fixture = fixture();
        let mut request = action(&fixture);
        request.actor_entity_id = EntityId::new();
        let decision = fixture.authorization.evaluate(request).test_ok();
        assert!(!decision.is_allowed());
        assert_eq!(
            decision.decision().error(),
            Some(AuthorityErrorV1::CapabilityMissing)
        );
        assert!(!GatewayAuthorizationError::AuthorizationDenied
            .to_string()
            .contains(&decision.principal().trust_domain().to_owned()));
        assert!(!GatewayAuthorizationError::AuthorizationDenied
            .to_string()
            .contains(&decision.actor_entity_id().to_string()));
    }

    #[test]
    fn invalid_expiry_is_denied_by_authority_not_adapter() {
        let fixture = fixture();
        let mut request = action(&fixture);
        request.at_time = WallTime::from_micros(u64::MAX);
        let decision = fixture.authorization.evaluate(request).test_ok();
        assert!(!decision.is_allowed());
        assert_eq!(decision.decision().error(), None);
    }

    #[tokio::test]
    async fn replacing_authority_is_serialized_with_the_commit_fence() {
        let fixture = fixture();
        let guard = fixture.authorization.commit_fence().await;
        let replacement = fixture.authority.clone();
        let authorization = fixture.authorization.clone();
        let task = tokio::spawn(async move {
            authorization.replace_authority(replacement).await.test_ok();
        });
        assert!(!task.is_finished());
        drop(guard);
        assert!(task.await.is_ok());
    }

    #[tokio::test]
    async fn poisoned_authority_update_fails_closed() {
        let fixture = fixture();
        let authorization = fixture.authorization.clone();
        let authority = Arc::clone(&authorization.authority);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = authority.write().test_ok();
            panic!("poison authority lock");
        }));
        assert_eq!(
            authorization.replace_authority(fixture.authority).await,
            Err(GatewayAuthorizationError::AuthorityUnavailable)
        );
    }

    #[tokio::test]
    async fn authorization_audit_retention_is_bounded() {
        let fixture = fixture();
        let audit = fixture
            .authorization
            .evaluate(action(&fixture))
            .test_ok()
            .audit();
        for _ in 0..=MAX_AUTHORIZATION_AUDITS {
            fixture.authorization.record_audit(audit.clone()).await;
        }
        assert_eq!(
            fixture.authorization.audits().await.len(),
            MAX_AUTHORIZATION_AUDITS
        );
    }
}
