//! Provider-neutral Gateway authentication and authorization seams.
//!
//! Authentication adapters only establish minimized Principal evidence.  The
//! Gateway owns construction of the authority request and delegates the policy
//! decision to the provider-neutral `pos-core` evaluator.  No credential,
//! bearer value, or provider-specific policy is retained here.
//!
//! The public seam implements the accepted [ADR-059 composition](https://redmine.piglor.com/projects/pigloros/wiki/ADR-059_Participant_Knowledge_Observation_and_Structured_Causal_Trace)
//! tracked by Redmine #180; the wiki page remains canonical.

use crate::denial_evidence::{GatewayDenialEvidencePort, GatewayDenialRecordV1};
use pos_core::{
    AuthenticatedPrincipalResultV1, AuthorityErrorV1, AuthorityEvaluatorV1,
    AuthorityPersistenceErrorV1, AuthorityPersistenceHostV1, AuthorityPersistencePortV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, AuthorityViewV1, AuthorizationDecisionV1,
    AuthorizationOutcomeV1, AuthorizationRequestDraftV1, AuthorizationRequestV1, ConsentEvidenceV1,
    EntityId, EventId, Hash, PersistedAuthorityV1, PluginId, PrincipalRefV1, Seq, TimelineId,
    WallTime,
};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, RwLock},
};
use thiserror::Error;
use tokio::sync::{OwnedRwLockReadGuard, RwLock as AsyncRwLock};

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

/// The closed public family of one denied authority decision.
///
/// Each family is one problem `code` of the Gateway v1 contract; the mapping
/// from the AUD1 outcome is fixed by [`GatewayAuthorization::authorize`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum GatewayAuthorityDenial {
    /// The authentication evidence is outside its validity window, or the
    /// host cannot resolve it to a Principal its authority trusts.
    #[error("authentication not accepted")]
    Unauthenticated,
    /// No trusted grant or capability covers the operation.
    #[error("authorization denied")]
    Unauthorized,
    /// The grant or consent was revoked at the evaluation fence, or expired.
    #[error("authority revoked")]
    Revoked,
    /// The consent the operation requires is absent or does not bind it.
    #[error("consent invalid")]
    ConsentInvalid,
    /// The host cannot vouch that its revocation state is current.
    #[error("revocation state unavailable")]
    RevocationStateStale,
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
    /// A complete decision denied the operation and its durable evidence is
    /// recorded.
    #[error("authorization denied")]
    Denied(GatewayAuthorityDenial),
    /// A decision denied the operation but its evidence could not be made
    /// durable, so the denial is not answered.
    #[error("authorization evidence unavailable")]
    EvidenceUnavailable,
}

/// Exact Timeline target bound into one protected Gateway operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayAuthorizationTarget {
    /// One proposed action on a Timeline.
    Action { timeline_id: TimelineId },
    /// One bounded read range on a Timeline.
    Read {
        timeline_id: TimelineId,
        from_position: Seq,
        limit: usize,
    },
}

impl GatewayAuthorizationTarget {
    #[must_use]
    pub const fn timeline_id(self) -> TimelineId {
        match self {
            Self::Action { timeline_id } | Self::Read { timeline_id, .. } => timeline_id,
        }
    }
}

/// Public operation inputs resolved by the Gateway before authority evaluation.
///
/// `actor_entity_id` is the simulation actor.  It is intentionally separate
/// from the Principal emitted by the adapter.  Protected subject operations
/// must set `subject_id` and provide resolved consent evidence; no field is
/// inferred from the Principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayAuthorizationRequest {
    /// The Timeline targeted by this protected operation, when applicable.
    /// Target coordinates are part of the host operation binding and are not
    /// inferred from the Principal or capability strings.
    pub target: GatewayAuthorizationTarget,
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
    /// Return whether this request is bound to the exact protected read target.
    #[must_use]
    pub fn targets_read(
        &self,
        target_timeline: TimelineId,
        from_position: u64,
        limit: usize,
    ) -> bool {
        matches!(
            self.target,
            GatewayAuthorizationTarget::Read {
                timeline_id,
                from_position: target_from_position,
                limit: target_limit,
            } if timeline_id == target_timeline
                && target_from_position == Seq::from_u64(from_position)
                && target_limit == limit
        )
    }

    /// Build an action request whose resource is the event type and whose action
    /// is the exact capability string later checked by `ActionApprover`.
    #[must_use]
    pub fn action(
        actor_entity_id: EntityId,
        target_timeline: TimelineId,
        event_type: impl Into<String>,
        capability: impl Into<String>,
        at_time: WallTime,
    ) -> Self {
        let event_type = event_type.into();
        Self {
            target: GatewayAuthorizationTarget::Action {
                timeline_id: target_timeline,
            },
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
    pub fn read(
        actor_entity_id: EntityId,
        target_timeline: TimelineId,
        from_position: u64,
        limit: usize,
        at_time: WallTime,
    ) -> Self {
        Self {
            target: GatewayAuthorizationTarget::Read {
                timeline_id: target_timeline,
                from_position: Seq::from_u64(from_position),
                limit,
            },
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
    operation_binding: Hash,
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
    pub const fn operation_binding(&self) -> Hash {
        self.operation_binding
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
    operation_binding: Hash,
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
    pub const fn operation_binding(&self) -> Hash {
        self.operation_binding
    }

    #[must_use]
    pub fn audit(&self) -> GatewayAuthorizationAudit {
        GatewayAuthorizationAudit {
            principal: self.decision.principal().clone(),
            actor_entity_id: self.decision.actor_entity_id(),
            request_digest: self.decision.request_digest(),
            operation_binding: self.operation_binding,
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
    authority: Arc<RwLock<Arc<AuthorityViewV1>>>,
    registry: AuthorityRegistrySnapshotV1,
    persistence: AuthorityPersistenceHostV1,
    revocation_state_current: bool,
    commit_lock: Arc<AsyncRwLock<()>>,
    audits: Arc<Mutex<VecDeque<GatewayAuthorizationAudit>>>,
    evidence: Arc<dyn GatewayDenialEvidencePort>,
}

impl GatewayAuthorization {
    /// Bind one authentication adapter to a trusted, pinned authority
    /// snapshot and the durable evidence seam every denial is recorded in.
    #[must_use]
    pub fn new(
        adapter: Arc<dyn GatewayAuthenticationAdapter>,
        authority: AuthorityViewV1,
        registry: AuthorityRegistrySnapshotV1,
        evidence: Arc<dyn GatewayDenialEvidencePort>,
    ) -> Self {
        Self::new_with_revocation_state(adapter, authority, registry, true, evidence)
    }

    /// Bind one adapter to host-pinned authority state with an explicit
    /// revocation-freshness claim.
    ///
    /// Local hosts normally pass `true`. An Air-Gapped host must pass `false`
    /// until its pinned revocation snapshot is current; authorization then
    /// fails closed with [`GatewayAuthorityDenial::RevocationStateStale`].
    #[must_use]
    pub fn new_with_revocation_state(
        adapter: Arc<dyn GatewayAuthenticationAdapter>,
        authority: AuthorityViewV1,
        registry: AuthorityRegistrySnapshotV1,
        revocation_state_current: bool,
        evidence: Arc<dyn GatewayDenialEvidencePort>,
    ) -> Self {
        Self {
            adapter,
            authority: Arc::new(RwLock::new(Arc::new(authority))),
            persistence: AuthorityPersistenceHostV1::new(&registry),
            registry,
            revocation_state_current,
            commit_lock: Arc::new(AsyncRwLock::new(())),
            audits: Arc::new(Mutex::new(VecDeque::new())),
            evidence,
        }
    }

    /// Evaluate a request and return its complete structured decision,
    /// allowed or denied, without recording evidence. Only
    /// [`Self::authorize`] answers a caller.
    fn evaluate(
        &self,
        mut request: GatewayAuthorizationRequest,
    ) -> Result<GatewayAuthorizationDecision, GatewayAuthorizationError> {
        request.revocation_state_current = self.revocation_state_current;
        let operation_binding = operation_binding(&request);
        self.adapter
            .authenticate(&GatewayAuthenticationRequest { operation_binding })
            .map_err(|_| GatewayAuthorizationError::AuthenticationUnavailable)
            .and_then(|authenticated| {
                self.authority
                    .read()
                    .map(|view| Arc::clone(&view))
                    .map_err(|_| GatewayAuthorizationError::AuthorityUnavailable)
                    .and_then(|view| {
                        let authority = view.authority();
                        core_request(&request, &authenticated, authority, &self.registry)
                            .map_err(|_| GatewayAuthorizationError::RequestUnavailable)
                            .map(|core_request| GatewayAuthorizationDecision {
                                request,
                                authenticated,
                                decision: AuthorityEvaluatorV1::authorize(
                                    &core_request,
                                    authority.chain(),
                                    &self.registry,
                                ),
                                operation_binding,
                            })
                    })
            })
    }

    /// Evaluate and require an active authorization decision.
    ///
    /// A denied decision is durably recorded through the evidence seam before
    /// its typed [`GatewayAuthorizationError::Denied`] is returned. The AUD1
    /// outcome maps to one [`GatewayAuthorityDenial`]: `RevokedAtFence` and a
    /// grant or consent `Expired` to `Revoked`, an `Expired` outside the
    /// authentication window or an unresolved Principal to `Unauthenticated`,
    /// `ConsentMissing` to `ConsentInvalid`, `RevocationStateStale` to itself,
    /// and `ParentInvalid` or any other fail-closed answer to `Unauthorized`.
    ///
    /// # Errors
    /// Returns the typed denial, [`GatewayAuthorizationError::EvidenceUnavailable`]
    /// when the denial cannot be recorded, or one of the host authentication,
    /// authority-state, or request-validation errors.
    pub fn authorize(
        &self,
        request: GatewayAuthorizationRequest,
    ) -> Result<GatewayAuthorizationDecision, GatewayAuthorizationError> {
        self.evaluate(request).and_then(|decision| {
            public_denial(&decision)
                .map(|denial| {
                    self.record_denial(
                        &decision,
                        decision.decision.outcome(),
                        decision.decision.error(),
                        denial,
                    )
                })
                .map_or(Ok(decision), Err)
        })
    }

    /// Record a denial the store reported at its commit fence for an
    /// operation this host had authorized, and return its typed error.
    ///
    /// The store composes the persisted authority chain, so it can find a
    /// revocation or expiry another host persisted after this host's own
    /// decision. Authentication evidence was accepted by that decision, so an
    /// expiry here is the grant's.
    pub(crate) fn deny_at_commit_fence(
        &self,
        decision: &GatewayAuthorizationDecision,
        outcome: AuthorizationOutcomeV1,
        error: Option<AuthorityErrorV1>,
    ) -> GatewayAuthorizationError {
        self.record_denial(
            decision,
            outcome,
            error,
            denial_of(outcome, error, false).unwrap_or(GatewayAuthorityDenial::Unauthorized),
        )
    }

    /// Persist one denial record, then return the typed denial; a record that
    /// cannot be made durable fails closed without answering the denial.
    fn record_denial(
        &self,
        decision: &GatewayAuthorizationDecision,
        outcome: AuthorizationOutcomeV1,
        error: Option<AuthorityErrorV1>,
        denial: GatewayAuthorityDenial,
    ) -> GatewayAuthorizationError {
        self.evidence
            .persist(&GatewayDenialRecordV1::new(
                decision.request_digest(),
                decision.operation_binding(),
                outcome,
                error,
            ))
            .map_or(GatewayAuthorizationError::EvidenceUnavailable, |()| {
                GatewayAuthorizationError::Denied(denial)
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
        authority: AuthorityViewV1,
    ) -> Result<(), GatewayAuthorizationError> {
        let _guard = self.commit_lock.write().await;
        self.authority
            .write()
            .map(|mut current| {
                *current = Arc::new(authority);
            })
            .map_err(|_| GatewayAuthorizationError::AuthorityUnavailable)
    }

    /// Retain one accepted action's minimized authorization audit.
    #[cfg(test)]
    pub(crate) fn record_audit(&self, audit: GatewayAuthorizationAudit) {
        let mut audits = self
            .audits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::retain_audit(&mut audits, audit);
    }

    /// Retain an accepted action audit from the dedicated synchronous host
    /// command thread before that command releases its result.
    pub(crate) fn record_audit_synchronously(&self, audit: GatewayAuthorizationAudit) {
        let mut audits = self
            .audits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::retain_audit(&mut audits, audit);
    }

    fn retain_audit(
        audits: &mut VecDeque<GatewayAuthorizationAudit>,
        audit: GatewayAuthorizationAudit,
    ) {
        if audits.len() >= MAX_AUTHORIZATION_AUDITS {
            audits.pop_front();
        }
        audits.push_back(audit);
    }

    /// Return the minimized authorization audits retained by this Gateway host.
    #[must_use]
    pub fn audits(&self) -> Vec<GatewayAuthorizationAudit> {
        self.audits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    /// Acquire the append fence used by the Gateway before a final recheck.
    pub(crate) async fn commit_fence(&self) -> OwnedRwLockReadGuard<()> {
        Arc::clone(&self.commit_lock).read_owned().await
    }

    /// Persist every immutable record behind the current authority view in
    /// the admission store and load the chain back as the store resolves it.
    ///
    /// This Gateway is the trusted composition root for its pinned registry,
    /// so it binds the store to its own persistence host and replays the
    /// view's grants and revocation records in Timeline Order, each under its
    /// own host permit (an exact retry, or a record another host already
    /// persisted, is unchanged). A revocation this host learned through
    /// [`Self::replace_authority`] therefore becomes a persisted record that
    /// the store composes at its admission serialization point, and a
    /// revocation another host persisted is returned in the loaded chain.
    /// The returned leaf grant names that persisted chain. Call it under
    /// [`Self::commit_fence`], so an authority replacement cannot interleave.
    ///
    /// # Errors
    /// Returns a closed persistence error when the store is bound to another
    /// host, or a record cannot be persisted for this registry or conflicts
    /// with the persisted state.
    pub(crate) fn persist_authority(
        &self,
        store: &mut dyn AuthorityPersistencePortV1,
    ) -> Result<(Hash, PersistedAuthorityV1), AuthorityPersistenceErrorV1> {
        // Replacement only swaps a complete snapshot, so a poisoned lock
        // still holds a whole view; only its shared handle is cloned.
        let view = Arc::clone(
            &self
                .authority
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        self.persistence
            .persist_authority(store, &view)
            .map(|persisted| (persisted.leaf_grant_id(), persisted))
    }

    /// The pinned authority registry digest and revocation-freshness claim
    /// that select this host's execution profile.
    pub(crate) const fn execution_profile(&self) -> (Hash, bool) {
        (
            self.registry.registry_digest(),
            self.revocation_state_current,
        )
    }
}

/// The public denial of one evaluated decision, or `None` when it is active.
fn public_denial(decision: &GatewayAuthorizationDecision) -> Option<GatewayAuthorityDenial> {
    let at_time = decision.request.at_time;
    let authenticated = &decision.authenticated;
    denial_of(
        decision.decision.outcome(),
        decision.decision.error(),
        at_time < authenticated.issued_at() || at_time >= authenticated.expires_at(),
    )
}

/// The closed mapping from an AUD1 outcome and safe-error code to its public
/// denial (owner decisions D3 and D9 on #302).
///
/// The evaluator checks the authentication window before consent and
/// capability, so an `Expired` outcome while the evidence is outside its
/// window is the evidence's expiry (`Unauthenticated`); any other `Expired`
/// is a grant or consent expiry and reads as `Revoked`. A broken delegation
/// parent (`ParentInvalid`) confers no capability, and every other
/// fail-closed indeterminate answer is `Unauthorized`, except an unresolved
/// Principal, which no trusted authority recognizes (`Unauthenticated`).
const fn denial_of(
    outcome: AuthorizationOutcomeV1,
    error: Option<AuthorityErrorV1>,
    authentication_lapsed: bool,
) -> Option<GatewayAuthorityDenial> {
    match outcome {
        AuthorizationOutcomeV1::Active => None,
        // A lapsed window yields `Expired` unless the evidence is not trusted
        // at all, which yields an unresolved Principal first.
        AuthorizationOutcomeV1::Expired | AuthorizationOutcomeV1::IndeterminateFailClosed
            if authentication_lapsed
                || matches!(error, Some(AuthorityErrorV1::PrincipalUnresolved)) =>
        {
            Some(GatewayAuthorityDenial::Unauthenticated)
        }
        AuthorizationOutcomeV1::RevokedAtFence | AuthorizationOutcomeV1::Expired => {
            Some(GatewayAuthorityDenial::Revoked)
        }
        AuthorizationOutcomeV1::ConsentMissing => Some(GatewayAuthorityDenial::ConsentInvalid),
        AuthorizationOutcomeV1::RevocationStateStale => {
            Some(GatewayAuthorityDenial::RevocationStateStale)
        }
        AuthorizationOutcomeV1::ParentInvalid | AuthorizationOutcomeV1::IndeterminateFailClosed => {
            Some(GatewayAuthorityDenial::Unauthorized)
        }
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
    let capability_policy_revision = fallback_to_grant_policy_revision(
        request.capability_policy_revision,
        leaf.policy_revision(),
    );
    let consent_policy_revision =
        fallback_to_grant_policy_revision(request.consent_policy_revision, leaf.policy_revision());
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

fn fallback_to_grant_policy_revision(value: Hash, fallback: Hash) -> Hash {
    if value == Hash::zero() {
        fallback
    } else {
        value
    }
}

fn operation_binding(request: &GatewayAuthorizationRequest) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.GatewayAuthorizationRequest.v1\0");
    match request.target {
        GatewayAuthorizationTarget::Action { timeline_id } => {
            hasher.update(&[0]);
            hasher.update(&timeline_bytes(timeline_id));
        }
        GatewayAuthorizationTarget::Read {
            timeline_id,
            from_position,
            limit,
        } => {
            hasher.update(&[1]);
            hasher.update(&timeline_id.inner().to_bytes());
            hasher.update(&from_position.as_u64().to_be_bytes());
            hasher.update(&u64::try_from(limit).unwrap_or(u64::MAX).to_be_bytes());
        }
    }
    hasher.update(&entity_bytes(request.actor_entity_id));
    digest_optional_fixed(&mut hasher, request.subject_id.map(entity_bytes));
    digest_optional_fixed(&mut hasher, request.participant_id.map(entity_bytes));
    digest_optional_fixed(&mut hasher, request.plugin_id.map(plugin_bytes));
    digest_optional_fixed(&mut hasher, request.installation_id);
    hasher.update(&[role_code(request.principal_role)]);
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
    hasher.update(&request.at_time.as_micros().to_be_bytes());
    hasher.update(&request.at_position.as_u64().to_be_bytes());
    digest_optional_fixed(&mut hasher, request.authority_timeline.map(timeline_bytes));
    digest_optional_fixed(&mut hasher, request.consent_timeline.map(timeline_bytes));
    digest_optional_fixed(
        &mut hasher,
        request
            .consent_at_position
            .map(Seq::as_u64)
            .map(u64::to_be_bytes),
    );
    hasher.update(&request.use_count.to_be_bytes());
    hasher.update(&request.budget.to_be_bytes());
    hasher.update(request.consent_policy_revision.as_bytes());
    hasher.update(request.capability_policy_revision.as_bytes());
    hasher.update(&[u8::from(request.revocation_state_current)]);
    digest_consent(&mut hasher, &request.consent);
    hasher.update(
        &u64::try_from(request.environment_constraints.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for constraint in &request.environment_constraints {
        hasher.update(
            &u64::try_from(constraint.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(constraint.as_bytes());
    }
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn entity_bytes(value: EntityId) -> [u8; 16] {
    let raw: u128 = value.inner().into();
    raw.to_be_bytes()
}

fn plugin_bytes(value: PluginId) -> [u8; 16] {
    let raw: u128 = value.inner().into();
    raw.to_be_bytes()
}

fn timeline_bytes(value: TimelineId) -> [u8; 16] {
    let raw: u128 = value.inner().into();
    raw.to_be_bytes()
}

fn digest_optional_fixed<const N: usize>(hasher: &mut blake3::Hasher, value: Option<[u8; N]>) {
    match value {
        None => {
            hasher.update(&[0]);
        }
        Some(bytes) => {
            hasher.update(&[1]);
            hasher.update(&(N as u64).to_be_bytes());
            hasher.update(&bytes);
        }
    }
}

const fn role_code(value: AuthorityRoleV1) -> u8 {
    match value {
        AuthorityRoleV1::Actor => 0,
        AuthorityRoleV1::Approver => 1,
        AuthorityRoleV1::Evaluator => 2,
    }
}

fn digest_consent(hasher: &mut blake3::Hasher, consent: &ConsentEvidenceV1) {
    match consent {
        ConsentEvidenceV1::NotRequired => {
            hasher.update(&[0]);
        }
        ConsentEvidenceV1::Resolved { grants } => {
            hasher.update(&[1]);
            hasher.update(
                &u64::try_from(grants.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            for grant in grants {
                hasher.update(grant.binding_digest().as_bytes());
            }
        }
        ConsentEvidenceV1::Missing => {
            hasher.update(&[2]);
        }
        ConsentEvidenceV1::Indeterminate => {
            hasher.update(&[3]);
        }
    }
}

#[cfg(test)]
pub(crate) fn test_authorization_for(actor: EntityId) -> GatewayAuthorization {
    test_authorization_with_evidence(
        actor,
        Arc::new(crate::denial_evidence::VolatileDenialEvidence::default()),
    )
}

#[cfg(test)]
pub(crate) fn test_authorization_with_evidence(
    actor: EntityId,
    evidence: Arc<dyn GatewayDenialEvidencePort>,
) -> GatewayAuthorization {
    tests::fixture_authorization_with_actor(actor, evidence)
}

#[cfg(test)]
pub(crate) fn test_action_only_authorization_for(actor: EntityId) -> GatewayAuthorization {
    tests::fixture_action_only_authorization_with_actor(actor)
}

#[cfg(test)]
pub(crate) fn test_expired_authorization_for(
    actor: EntityId,
    evidence: Arc<dyn GatewayDenialEvidencePort>,
) -> GatewayAuthorization {
    tests::fixture_expired_authorization_with_actor(actor, evidence)
}

#[cfg(test)]
pub(crate) fn test_expired_grant_authorization_for(
    actor: EntityId,
    evidence: Arc<dyn GatewayDenialEvidencePort>,
) -> GatewayAuthorization {
    tests::fixture_expired_grant_authorization_with_actor(actor, evidence)
}

#[cfg(test)]
pub(crate) fn test_authorization_unavailable_for(actor: EntityId) -> GatewayAuthorization {
    tests::fixture_authorization_unavailable_with_actor(actor)
}

#[cfg(test)]
pub(crate) fn test_authorization_reject_after_first_for(actor: EntityId) -> GatewayAuthorization {
    tests::fixture_authorization_reject_after_first_with_actor(actor)
}

#[cfg(test)]
pub(crate) fn test_revoked_authority_for(actor: EntityId) -> AuthorityViewV1 {
    tests::fixture_revoked_authority_with_actor(actor)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::denial_evidence::VolatileDenialEvidence;
    use pos_core::{
        AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthorityGranteeV1,
        AuthorityPersistenceHostV1, AuthorityPersistenceStateV1, CapabilityGrantDraftV1,
        CapabilityGrantV1, CapabilityRevocationDraftV1, CapabilityRevocationV1,
        CapabilityScopeDraftV1, CapabilityScopeV1, ConsentGrantRefDraftV1, ConsentGrantRefV1,
        ConsentGrantStatusV1, PrincipalRefV1,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    fn consent_grant() -> ConsentGrantRefV1 {
        ConsentGrantRefV1::try_from_draft(ConsentGrantRefDraftV1 {
            consent_id: hash(61),
            subject_id: EntityId::new(),
            grantee_id: EntityId::new(),
            data_categories: vec!["private".to_owned()],
            purposes: vec!["action".to_owned()],
            audiences: vec!["gateway".to_owned()],
            action_classes: vec!["world.action.v1.submit".to_owned()],
            valid_from: WallTime::from_micros(1),
            valid_until: WallTime::from_micros(100),
            withdrawal_retention_policy: "erase".to_owned(),
            policy_revision: hash(62),
            issuer: PrincipalRefV1::try_new([63; 16], "gateway.test").test_ok(),
            issuer_evidence: hash(64),
            consent_timeline: TimelineId::new(),
            grant_position: Seq::from_u64(1),
            status: ConsentGrantStatusV1::Active,
            revocation_fence: None,
            authority_registry_digest: hash(65),
        })
        .test_ok()
    }

    struct Fixture {
        authorization: GatewayAuthorization,
        evidence: Arc<VolatileDenialEvidence>,
        authenticated: AuthenticatedPrincipalResultV1,
        actor: EntityId,
        target_timeline: TimelineId,
        authority: AuthorityViewV1,
        revoked_authority: AuthorityViewV1,
    }

    fn fixture() -> Fixture {
        fixture_with_actor(EntityId::new())
    }

    fn fixture_with_actor(actor: EntityId) -> Fixture {
        fixture_with_scope(
            actor,
            vec!["timeline.events".to_owned(), "world.action.v1".to_owned()],
            vec!["read".to_owned(), "world.action.v1.submit".to_owned()],
            vec!["action".to_owned(), "read".to_owned()],
        )
    }

    fn fixture_authenticated(expires_at: WallTime) -> AuthenticatedPrincipalResultV1 {
        AuthenticatedPrincipalResultV1::try_from_draft(AuthenticatedPrincipalDraftV1 {
            principal: PrincipalRefV1::try_new([1; 16], "gateway.test").test_ok(),
            adapter_id: "fixture".to_owned(),
            assurance: AssuranceLevelV1::try_new(1).test_ok(),
            issued_at: WallTime::from_micros(1),
            expires_at,
            binding_digest: hash(2),
        })
        .test_ok()
    }

    /// One root grant of the fixture Principal for `actor` on the actor's
    /// own authority Timeline, so every fixture for one actor agrees on it.
    fn fixture_grant(
        actor: EntityId,
        scope: CapabilityScopeV1,
        grant_id: u8,
        issuance: u64,
        valid_until: u64,
    ) -> CapabilityGrantV1 {
        let principal = PrincipalRefV1::try_new([1; 16], "gateway.test").test_ok();
        CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
            grant_id: hash(grant_id),
            grantor: principal.clone(),
            grantee: AuthorityGranteeV1::Principal(principal),
            trust_domain: "gateway.test".to_owned(),
            scope,
            valid_from_position: Seq::from_u64(issuance),
            valid_until_position: Seq::from_u64(valid_until),
            parent_grant_id: None,
            delegation_depth: 0,
            max_delegation_depth: 0,
            permitted_delegate_classes: Vec::new(),
            consent_references: Vec::new(),
            policy_revision: hash(4),
            issuance_timeline: authority_timeline(actor),
            issuance_seq: Seq::from_u64(issuance),
            revocation_epoch: 0,
            revocation_fence: None,
            authority_registry_digest: hash(3),
        })
        .test_ok()
    }

    fn authority_timeline(actor: EntityId) -> TimelineId {
        TimelineId::from_ulid(actor.inner())
    }

    fn fixture_scope(
        actor: EntityId,
        resources: Vec<String>,
        actions: Vec<String>,
        purposes: Vec<String>,
    ) -> CapabilityScopeV1 {
        CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
            resources,
            actions,
            purposes,
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
        .test_ok()
    }

    fn fixture_registry(
        authenticated: &AuthenticatedPrincipalResultV1,
        mut bindings: Vec<Hash>,
    ) -> AuthorityRegistrySnapshotV1 {
        bindings.sort_unstable();
        AuthorityRegistrySnapshotV1::try_new(
            hash(3),
            vec![authenticated.registry_binding_digest()],
            bindings,
            Vec::new(),
        )
        .test_ok()
    }

    fn fixture_with_scope(
        actor: EntityId,
        resources: Vec<String>,
        actions: Vec<String>,
        purposes: Vec<String>,
    ) -> Fixture {
        let authenticated = fixture_authenticated(WallTime::from_micros(u64::MAX));
        let grant = fixture_grant(
            actor,
            fixture_scope(actor, resources, actions, purposes),
            5,
            1,
            50,
        );
        let issued = fixture_registry(&authenticated, vec![grant.binding_digest().test_ok()]);
        let host = AuthorityPersistenceHostV1::new(&issued);
        let mut state = AuthorityPersistenceStateV1::new();
        state
            .issue_grant(host.authorize_grant(&grant).test_ok(), grant.clone())
            .test_ok();
        let authority = state.view(grant.grant_id()).test_ok();
        let revocation = CapabilityRevocationV1::try_from_draft(CapabilityRevocationDraftV1 {
            grant_id: grant.grant_id(),
            authority_timeline: authority_timeline(actor),
            fence_position: Seq::from_u64(2),
            revocation_epoch: 1,
            policy_revision: hash(4),
            authority_registry_digest: hash(3),
        })
        .test_ok();
        state
            .revoke_grant(
                host.authorize_revocation(&grant, &revocation).test_ok(),
                revocation,
            )
            .test_ok();
        let revoked_authority = state.view(grant.grant_id()).test_ok();
        // The registry also attests the grant as resolved after its
        // revocation, so the evaluator reaches the revocation fence instead
        // of distrusting the resolved record.
        let registry = fixture_registry(
            &authenticated,
            vec![
                grant.binding_digest().test_ok(),
                revoked_authority.authority().chain().grants()[0]
                    .binding_digest()
                    .test_ok(),
            ],
        );
        let evidence = Arc::new(VolatileDenialEvidence::default());
        let authorization = GatewayAuthorization::new(
            Arc::new(LocalAuthenticationAdapter::new(authenticated.clone())),
            authority.clone(),
            registry,
            evidence.clone(),
        );
        Fixture {
            authorization,
            evidence,
            authenticated,
            actor,
            target_timeline: authority_timeline(actor),
            authority,
            revoked_authority,
        }
    }

    /// Rebind a fixture's authority to another adapter and evidence seam.
    fn rebound(
        fixture: &Fixture,
        adapter: Arc<dyn GatewayAuthenticationAdapter>,
        evidence: Arc<dyn GatewayDenialEvidencePort>,
    ) -> GatewayAuthorization {
        GatewayAuthorization::new(
            adapter,
            fixture.authority.clone(),
            fixture.authorization.registry.clone(),
            evidence,
        )
    }

    pub(super) fn fixture_authorization_with_actor(
        actor: EntityId,
        evidence: Arc<dyn GatewayDenialEvidencePort>,
    ) -> GatewayAuthorization {
        let fixture = fixture_with_actor(actor);
        rebound(
            &fixture,
            Arc::new(LocalAuthenticationAdapter::new(
                fixture.authenticated.clone(),
            )),
            evidence,
        )
    }

    pub(super) fn fixture_action_only_authorization_with_actor(
        actor: EntityId,
    ) -> GatewayAuthorization {
        fixture_with_scope(
            actor,
            vec!["world.action.v1".to_owned()],
            vec!["world.action.v1.submit".to_owned()],
            vec!["action".to_owned()],
        )
        .authorization
    }

    pub(super) fn fixture_expired_authorization_with_actor(
        actor: EntityId,
        evidence: Arc<dyn GatewayDenialEvidencePort>,
    ) -> GatewayAuthorization {
        let fixture = fixture_with_actor(actor);
        let authenticated = fixture_authenticated(WallTime::from_micros(2));
        let registry = fixture_registry(
            &authenticated,
            fixture
                .authority
                .authority()
                .chain()
                .grants()
                .iter()
                .map(CapabilityGrantV1::binding_digest)
                .collect::<Result<Vec<_>, _>>()
                .test_ok(),
        );
        GatewayAuthorization::new(
            Arc::new(LocalAuthenticationAdapter::new(authenticated)),
            fixture.authority,
            registry,
            evidence,
        )
    }

    /// A grant valid for positions 1..2 whose authority Timeline a later
    /// sibling grant advanced to position 2, so the grant has expired.
    pub(super) fn fixture_expired_grant_authorization_with_actor(
        actor: EntityId,
        evidence: Arc<dyn GatewayDenialEvidencePort>,
    ) -> GatewayAuthorization {
        let authenticated = fixture_authenticated(WallTime::from_micros(u64::MAX));
        let scope = || {
            fixture_scope(
                actor,
                vec!["timeline.events".to_owned(), "world.action.v1".to_owned()],
                vec!["read".to_owned(), "world.action.v1.submit".to_owned()],
                vec!["action".to_owned(), "read".to_owned()],
            )
        };
        let expiring = fixture_grant(actor, scope(), 5, 1, 2);
        let sibling = fixture_grant(actor, scope(), 6, 2, 50);
        let registry = fixture_registry(
            &authenticated,
            vec![
                expiring.binding_digest().test_ok(),
                sibling.binding_digest().test_ok(),
            ],
        );
        let host = AuthorityPersistenceHostV1::new(&registry);
        let mut state = AuthorityPersistenceStateV1::new();
        for grant in [&expiring, &sibling] {
            state
                .issue_grant(host.authorize_grant(grant).test_ok(), grant.clone())
                .test_ok();
        }
        GatewayAuthorization::new(
            Arc::new(LocalAuthenticationAdapter::new(authenticated)),
            state.view(expiring.grant_id()).test_ok(),
            registry,
            evidence,
        )
    }

    pub(super) fn fixture_authorization_unavailable_with_actor(
        actor: EntityId,
    ) -> GatewayAuthorization {
        let fixture = fixture_with_actor(actor);
        rebound(
            &fixture,
            Arc::new(RejectingAdapter),
            fixture.evidence.clone(),
        )
    }

    pub(super) fn fixture_authorization_reject_after_first_with_actor(
        actor: EntityId,
    ) -> GatewayAuthorization {
        let fixture = fixture_with_actor(actor);
        rebound(
            &fixture,
            Arc::new(RejectAfterFirstAdapter {
                evidence: fixture.authenticated.clone(),
                calls: Arc::new(AtomicUsize::new(0)),
            }),
            fixture.evidence.clone(),
        )
    }

    pub(super) fn fixture_revoked_authority_with_actor(actor: EntityId) -> AuthorityViewV1 {
        fixture_with_actor(actor).revoked_authority
    }

    fn action(fixture: &Fixture) -> GatewayAuthorizationRequest {
        GatewayAuthorizationRequest::action(
            fixture.actor,
            fixture.target_timeline,
            "world.action.v1",
            "world.action.v1.submit",
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

    struct RejectAfterFirstAdapter {
        evidence: AuthenticatedPrincipalResultV1,
        calls: Arc<AtomicUsize>,
    }

    impl GatewayAuthenticationAdapter for RejectAfterFirstAdapter {
        fn authenticate(
            &self,
            _request: &GatewayAuthenticationRequest,
        ) -> Result<AuthenticatedPrincipalResultV1, GatewayAuthenticationError> {
            if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(self.evidence.clone())
            } else {
                Err(GatewayAuthenticationError::Unavailable)
            }
        }
    }

    #[test]
    fn adapter_failure_is_stable_and_does_not_reveal_evidence() {
        let fixture = fixture();
        let authorization = rebound(
            &fixture,
            Arc::new(RejectingAdapter),
            fixture.evidence.clone(),
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
        let local = rebound(
            &fixture,
            Arc::new(LocalAuthenticationAdapter::new(
                fixture.authenticated.clone(),
            )),
            fixture.evidence.clone(),
        );
        let air_gapped = rebound(
            &fixture,
            Arc::new(AirGappedAuthenticationAdapter::new(
                fixture.authenticated.clone(),
            )),
            fixture.evidence.clone(),
        );
        let local_decision = local.authorize(action(&fixture)).test_ok();
        let air_decision = air_gapped.authorize(action(&fixture)).test_ok();
        assert_eq!(local_decision.decision(), air_decision.decision());
        assert_eq!(local_decision.audit(), air_decision.audit());
    }

    #[test]
    fn operation_binding_includes_the_exact_protected_target() {
        let fixture = fixture();
        let first = fixture.authorization.evaluate(action(&fixture)).test_ok();
        let mut second_request = action(&fixture);
        second_request.target = GatewayAuthorizationTarget::Action {
            timeline_id: TimelineId::new(),
        };
        let second = fixture.authorization.evaluate(second_request).test_ok();
        assert_ne!(
            first.operation_binding(),
            second.operation_binding(),
            "a different target Timeline must not reuse an authorization binding"
        );
        assert_ne!(
            first.audit().operation_binding(),
            second.audit().operation_binding()
        );
    }

    #[test]
    fn operation_binding_includes_every_decision_identifying_field() {
        let fixture = fixture();
        let baseline = operation_binding(&action(&fixture));
        let mut variants = Vec::new();

        let mut request = action(&fixture);
        request.subject_id = Some(EntityId::new());
        variants.push(request);

        let mut request = action(&fixture);
        request.participant_id = Some(EntityId::new());
        variants.push(request);

        let mut request = action(&fixture);
        request.plugin_id = Some(PluginId::new());
        variants.push(request);

        let mut request = action(&fixture);
        request.installation_id = Some([7; 16]);
        variants.push(request);

        let mut request = action(&fixture);
        request.principal_role = AuthorityRoleV1::Approver;
        variants.push(request);

        let mut request = action(&fixture);
        request.principal_role = AuthorityRoleV1::Evaluator;
        variants.push(request);

        let mut request = action(&fixture);
        request.at_time = WallTime::from_micros(11);
        variants.push(request);

        let mut request = action(&fixture);
        request.at_position = Seq::from_u64(1);
        variants.push(request);

        let mut request = action(&fixture);
        request.authority_timeline = Some(TimelineId::new());
        variants.push(request);

        let mut request = action(&fixture);
        request.consent_timeline = Some(TimelineId::new());
        variants.push(request);

        let mut request = action(&fixture);
        request.consent_at_position = Some(Seq::from_u64(2));
        variants.push(request);

        let mut request = action(&fixture);
        request.use_count = 2;
        variants.push(request);

        let mut request = action(&fixture);
        request.budget = 2;
        variants.push(request);

        let mut request = action(&fixture);
        request.revocation_state_current = false;
        variants.push(request);

        let mut request = action(&fixture);
        request.consent = ConsentEvidenceV1::Resolved {
            grants: vec![consent_grant()],
        };
        variants.push(request);

        let mut request = action(&fixture);
        request.consent = ConsentEvidenceV1::Missing;
        variants.push(request);

        let mut request = action(&fixture);
        request.consent = ConsentEvidenceV1::Indeterminate;
        variants.push(request);

        let mut request = action(&fixture);
        request.environment_constraints = vec!["air-gapped".to_owned()];
        variants.push(request);

        for variant in variants {
            assert_ne!(baseline, operation_binding(&variant));
        }
    }

    #[test]
    fn authorization_public_accessors_expose_the_bound_operation_and_audit() {
        let fixture = fixture();
        let mut request = action(&fixture);
        request.capability_policy_revision = hash(10);
        request.consent_policy_revision = hash(11);
        let decision = fixture.authorization.evaluate(request.clone()).test_ok();
        let audit = decision.audit();

        assert_eq!(decision.authenticated(), &fixture.authenticated);
        assert_eq!(decision.request(), &request);
        assert_eq!(
            decision.request_digest(),
            decision.decision().request_digest()
        );
        assert_eq!(
            decision.decision_digest(),
            decision.decision().decision_digest()
        );
        assert_eq!(decision.operation_binding(), audit.operation_binding());
        assert_eq!(audit.principal(), decision.principal());
        assert_eq!(audit.actor_entity_id(), fixture.actor);
        assert_eq!(audit.request_digest(), decision.request_digest());
        assert_eq!(audit.decision_digest(), decision.decision_digest());
        assert_eq!(audit.event_id(), None);
        assert_eq!(
            GatewayAuthorizationTarget::Action {
                timeline_id: fixture.target_timeline,
            }
            .timeline_id(),
            fixture.target_timeline
        );
        assert_eq!(
            GatewayAuthorizationTarget::Read {
                timeline_id: fixture.target_timeline,
                from_position: Seq::from_u64(3),
                limit: 2,
            }
            .timeline_id(),
            fixture.target_timeline
        );
    }

    /// Authorize `request` and return its typed error and the one durable
    /// record it left, after checking the record binds the exact evaluation.
    fn denied(
        authorization: &GatewayAuthorization,
        evidence: &VolatileDenialEvidence,
        request: GatewayAuthorizationRequest,
    ) -> (GatewayAuthorizationError, GatewayDenialRecordV1) {
        let before = evidence.records().len();
        let evaluated = authorization.evaluate(request.clone()).test_ok();
        let error = authorization.authorize(request).err().test_some();
        let records = evidence.records();
        assert_eq!(records.len(), before + 1);
        let record = records[before];
        assert_eq!(record.request_digest(), evaluated.request_digest());
        assert_eq!(record.operation_binding(), evaluated.operation_binding());
        assert_eq!(record.outcome(), evaluated.decision().outcome());
        assert_eq!(record.error(), evaluated.decision().error());
        (error, record)
    }

    trait TestSome<T> {
        fn test_some(self) -> T;
    }

    impl<T> TestSome<T> for Option<T> {
        fn test_some(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected a value")))
        }
    }

    #[test]
    fn denied_decision_does_not_enumerate_principal_or_entity() {
        let fixture = fixture();
        let mut request = action(&fixture);
        request.actor_entity_id = EntityId::new();
        let decision = fixture.authorization.evaluate(request.clone()).test_ok();
        assert!(!decision.is_allowed());
        let (error, record) = denied(&fixture.authorization, &fixture.evidence, request);
        assert_eq!(
            error,
            GatewayAuthorizationError::Denied(GatewayAuthorityDenial::Unauthorized)
        );
        assert_eq!(record.error(), Some(AuthorityErrorV1::CapabilityMissing));
        for text in [
            error.to_string(),
            GatewayAuthorityDenial::Unauthorized.to_string(),
        ] {
            assert!(!text.contains(decision.principal().trust_domain()));
            assert!(!text.contains(&decision.actor_entity_id().to_string()));
        }
    }

    #[test]
    fn subject_bound_request_requires_resolved_consent() {
        let fixture = fixture();
        let mut request = action(&fixture);
        request.subject_id = Some(fixture.actor);
        request.consent_timeline = Some(fixture.target_timeline);
        request.consent_at_position = Some(Seq::from_u64(1));
        let (error, record) = denied(&fixture.authorization, &fixture.evidence, request);
        assert_eq!(
            error,
            GatewayAuthorizationError::Denied(GatewayAuthorityDenial::ConsentInvalid)
        );
        assert_eq!(record.error(), Some(AuthorityErrorV1::ConsentMissing));
    }

    #[test]
    fn stale_pinned_revocation_state_denies_even_when_the_grant_is_valid() {
        let fixture = fixture();
        let request = action(&fixture);
        let stale = GatewayAuthorization::new_with_revocation_state(
            Arc::new(LocalAuthenticationAdapter::new(
                fixture.authenticated.clone(),
            )),
            fixture.authority.clone(),
            fixture.authorization.registry.clone(),
            false,
            fixture.evidence.clone(),
        );
        let (error, record) = denied(&stale, &fixture.evidence, request);
        assert_eq!(
            error,
            GatewayAuthorizationError::Denied(GatewayAuthorityDenial::RevocationStateStale)
        );
        assert_eq!(
            record.outcome(),
            AuthorizationOutcomeV1::RevocationStateStale
        );
    }

    #[test]
    fn expired_authentication_evidence_is_unauthenticated() {
        let fixture = fixture();
        let mut request = action(&fixture);
        request.at_time = WallTime::from_micros(u64::MAX);
        let (error, record) = denied(&fixture.authorization, &fixture.evidence, request);
        assert_eq!(
            error,
            GatewayAuthorizationError::Denied(GatewayAuthorityDenial::Unauthenticated)
        );
        assert_eq!(record.outcome(), AuthorizationOutcomeV1::Expired);
        assert_eq!(record.error(), None);
    }

    #[tokio::test]
    async fn a_revoked_or_expired_grant_is_revoked() {
        let fixture = fixture();
        fixture
            .authorization
            .replace_authority(fixture.revoked_authority.clone())
            .await
            .test_ok();
        let (error, record) = denied(&fixture.authorization, &fixture.evidence, action(&fixture));
        assert_eq!(
            error,
            GatewayAuthorizationError::Denied(GatewayAuthorityDenial::Revoked)
        );
        assert_eq!(record.outcome(), AuthorizationOutcomeV1::RevokedAtFence);
        assert_eq!(record.error(), Some(AuthorityErrorV1::RevokedAtFence));

        let evidence = Arc::new(VolatileDenialEvidence::default());
        let expired =
            fixture_expired_grant_authorization_with_actor(fixture.actor, evidence.clone());
        let (error, record) = denied(&expired, &evidence, action(&fixture));
        assert_eq!(
            error,
            GatewayAuthorizationError::Denied(GatewayAuthorityDenial::Revoked)
        );
        assert_eq!(record.outcome(), AuthorizationOutcomeV1::Expired);
        assert_eq!(record.error(), None);
    }

    struct UnavailableEvidence;

    impl GatewayDenialEvidencePort for UnavailableEvidence {
        fn persist(
            &self,
            _record: &GatewayDenialRecordV1,
        ) -> Result<(), crate::denial_evidence::GatewayDenialEvidenceError> {
            Err(crate::denial_evidence::GatewayDenialEvidenceError::Unavailable)
        }
    }

    #[test]
    fn a_denial_without_durable_evidence_is_not_answered() {
        let fixture = fixture();
        let authorization = rebound(
            &fixture,
            Arc::new(LocalAuthenticationAdapter::new(
                fixture.authenticated.clone(),
            )),
            Arc::new(UnavailableEvidence),
        );
        let mut request = action(&fixture);
        assert!(authorization.authorize(request.clone()).is_ok());
        request.actor_entity_id = EntityId::new();
        assert_eq!(
            authorization.authorize(request).err(),
            Some(GatewayAuthorizationError::EvidenceUnavailable)
        );
    }

    #[test]
    fn every_authority_outcome_has_one_public_denial() {
        use super::GatewayAuthorityDenial as Denial;
        use pos_core::AuthorizationOutcomeV1 as Outcome;
        let cases = [
            (Outcome::Active, None, false, None),
            (Outcome::Active, None, true, None),
            (
                Outcome::RevokedAtFence,
                Some(AuthorityErrorV1::RevokedAtFence),
                false,
                Some(Denial::Revoked),
            ),
            (Outcome::Expired, None, false, Some(Denial::Revoked)),
            (Outcome::Expired, None, true, Some(Denial::Unauthenticated)),
            (
                Outcome::ConsentMissing,
                Some(AuthorityErrorV1::ConsentMissing),
                false,
                Some(Denial::ConsentInvalid),
            ),
            (
                Outcome::RevocationStateStale,
                Some(AuthorityErrorV1::RevocationStateStale),
                false,
                Some(Denial::RevocationStateStale),
            ),
            (
                Outcome::ParentInvalid,
                Some(AuthorityErrorV1::DelegationInvalid),
                false,
                Some(Denial::Unauthorized),
            ),
            (
                Outcome::IndeterminateFailClosed,
                Some(AuthorityErrorV1::PrincipalUnresolved),
                false,
                Some(Denial::Unauthenticated),
            ),
            (
                Outcome::IndeterminateFailClosed,
                Some(AuthorityErrorV1::CapabilityMissing),
                false,
                Some(Denial::Unauthorized),
            ),
            (
                Outcome::IndeterminateFailClosed,
                Some(AuthorityErrorV1::PolicyIndeterminate),
                false,
                Some(Denial::Unauthorized),
            ),
            (
                Outcome::IndeterminateFailClosed,
                None,
                false,
                Some(Denial::Unauthorized),
            ),
        ];
        for (outcome, error, lapsed, expected) in cases {
            assert_eq!(denial_of(outcome, error, lapsed), expected, "{outcome:?}");
        }
    }

    #[test]
    fn a_commit_fence_denial_is_recorded_against_the_authorized_operation() {
        let fixture = fixture();
        let decision = fixture.authorization.authorize(action(&fixture)).test_ok();
        for (outcome, error) in [
            (
                AuthorizationOutcomeV1::RevokedAtFence,
                Some(AuthorityErrorV1::RevokedAtFence),
            ),
            (AuthorizationOutcomeV1::Expired, None),
        ] {
            assert_eq!(
                fixture
                    .authorization
                    .deny_at_commit_fence(&decision, outcome, error),
                GatewayAuthorizationError::Denied(GatewayAuthorityDenial::Revoked)
            );
        }
        let records = fixture.evidence.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].request_digest(), decision.request_digest());
        assert_eq!(records[0].operation_binding(), decision.operation_binding());
        assert_eq!(records[1].outcome(), AuthorizationOutcomeV1::Expired);
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
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = authority.write().test_ok();
            std::panic::resume_unwind(Box::new("poison authority lock"));
        }))
        .is_err());
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
            fixture.authorization.record_audit(audit.clone());
        }
        assert_eq!(
            fixture.authorization.audits().len(),
            MAX_AUTHORIZATION_AUDITS
        );
    }
}
