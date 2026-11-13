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
    AuthorityPersistenceErrorV1, AuthorityPersistenceHostV1, AuthorityPersistencePortV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, AuthorityViewV1, AuthorizationDecisionV1,
    AuthorizationDenialEvidenceV1, AuthorizationDenialRecordV1, AuthorizationDenialScopeV1,
    AuthorizationDenialSuppressionV1, AuthorizationExpiryV1, AuthorizationOutcomeV1,
    AuthorizationRequestDraftV1, AuthorizationRequestV1, ConsentEvidenceV1, EntityId, EventId,
    Hash, PersistedAuthorityV1, PluginId, PrincipalRefV1, Seq, TimelineId, WallTime,
};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::{OwnedRwLockReadGuard, RwLock as AsyncRwLock};

const MAX_AUTHORIZATION_AUDITS: usize = 1_024;
/// Denial records one Principal may cause per window before further denials
/// are answered as `429 resource-limit-exceeded` without their own record.
///
/// The bound is operational, never authoritative: a fixed one-minute window
/// on the monotonic [`Instant`] clock, held in memory, so a burst straddling
/// a window boundary can reach twice the bound and a restart resets every
/// count. Every suppressed denial is still counted in one ADS1 marker per
/// bound and window. With the single host-pinned Local Principal (owner
/// decision D1 on #302) this per-Principal bound is effectively host-wide.
pub const MAX_DENIAL_RECORDS_PER_PRINCIPAL_PER_MINUTE: u32 = 60;
/// Denial records the whole host may write per window, under the same
/// fixed-window, monotonic, reset-on-restart rules.
pub const MAX_DENIAL_RECORDS_PER_MINUTE: u32 = 600;
const DENIAL_RECORD_WINDOW: Duration = Duration::from_mins(1);

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
/// from the AUD1 outcome is fixed by [`GatewayAuthorization::authorize`]. A
/// family reaches a caller only inside a [`RecordedAuthorityDenial`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum GatewayAuthorityDenial {
    /// The authentication evidence is outside its validity window, or the
    /// host cannot resolve it to a Principal its authority trusts.
    #[error("authentication not accepted")]
    Unauthenticated,
    /// No trusted grant or capability covers the operation.
    #[error("authorization denied")]
    Unauthorized,
    /// The grant, a delegation parent or the consent was revoked at the
    /// evaluation or commit fence, or expired.
    #[error("authority revoked")]
    Revoked,
    /// The consent the operation requires is absent or does not bind it.
    #[error("consent invalid")]
    ConsentInvalid,
    /// The host cannot vouch that its revocation state is current.
    #[error("revocation state unavailable")]
    RevocationStateStale,
}

/// A denied decision whose durable evidence is not yet recorded.
///
/// It carries the ADN1 record to persist and the public family to answer once
/// the record is durable; neither is reachable outside this module except
/// through `GatewayAuthorization::record_denial`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingAuthorityDenial {
    record: AuthorizationDenialRecordV1,
    principal: PrincipalRefV1,
    denial: GatewayAuthorityDenial,
}

/// A denial whose ADN1 record a store committed; the only value the Gateway
/// answers as an authority denial. It is constructed solely by
/// `GatewayAuthorization::record_denial` after the store write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordedAuthorityDenial(GatewayAuthorityDenial);

impl RecordedAuthorityDenial {
    /// The public family of the recorded denial.
    #[must_use]
    pub const fn denial(self) -> GatewayAuthorityDenial {
        self.0
    }

    /// A recorded denial for mapping tests that do not exercise a store.
    #[cfg(test)]
    pub(crate) const fn recorded_for_test(denial: GatewayAuthorityDenial) -> Self {
        Self(denial)
    }
}

impl std::fmt::Display for RecordedAuthorityDenial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Stable Gateway authorization failures.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum GatewayAuthorizationError {
    #[error("authentication unavailable")]
    AuthenticationUnavailable,
    #[error("authorization request unavailable")]
    RequestUnavailable,
    #[error("authorization state unavailable")]
    AuthorityUnavailable,
    /// A complete decision denied the operation. It is answered only after
    /// its evidence is recorded through `GatewayAuthorization::record_denial`.
    #[error("authorization denied")]
    Denied(PendingAuthorityDenial),
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
    /// One [`GatewayOperationV1`], on a Timeline when the operation names
    /// one (an append) and on the host when it does not (a create).
    Operation { timeline_id: Option<TimelineId> },
}

/// One protected Gateway operation, keyed by the capability `resource` and
/// `action` a Principal's grant must cover, and the `purpose` it is
/// evaluated for (#1361).
///
/// The named constants are the closed set this Gateway serves; the Local
/// Principal is provisioned with grants named by [`Self::name`]. Later
/// operations (#303, #304, #309) add a constant with a fresh resource and
/// action pair and authorize through [`crate::Gateway::authorize_operation`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayOperationV1 {
    name: &'static str,
    resource: &'static str,
    action: &'static str,
    purpose: &'static str,
}

impl GatewayOperationV1 {
    /// `POST /v1/timelines`: create a root Timeline.
    pub const CREATE_TIMELINE: Self =
        Self::new("timeline.create", "timeline", "create", "operation");
    /// `POST /v1/timelines/{timeline_id}/signals`: append one Society Signal.
    pub const APPEND_SIGNAL: Self = Self::new(
        "timeline.signals.append",
        "society.signal",
        "append",
        "operation",
    );
    /// `POST /v1/ledger/predictions`: register one Prediction Ledger entry.
    pub const CREATE_PREDICTION: Self = Self::new(
        "ledger.predictions.create",
        "ledger.prediction",
        "create",
        "operation",
    );
    /// `GET /v1/timelines/{timeline_id}/events`, as [`GatewayAuthorizationRequest::read`] builds it.
    pub const READ_EVENTS: Self =
        Self::new("timeline.events.read", "timeline.events", "read", "read");
    /// `POST /v1/timelines/{timeline_id}/actions`, as [`GatewayAuthorizationRequest::action`]
    /// builds it for `world.action.v1`.
    pub const SUBMIT_WORLD_ACTION: Self = Self::new(
        "world.action.v1.submit",
        "world.action.v1",
        "world.action.v1.submit",
        "action",
    );
    /// Every operation this Gateway serves, in name order.
    pub const ALL: [Self; 5] = [
        Self::CREATE_PREDICTION,
        Self::CREATE_TIMELINE,
        Self::READ_EVENTS,
        Self::APPEND_SIGNAL,
        Self::SUBMIT_WORLD_ACTION,
    ];

    /// An operation keyed by `resource` and `action`, evaluated for `purpose`.
    #[must_use]
    pub const fn new(
        name: &'static str,
        resource: &'static str,
        action: &'static str,
        purpose: &'static str,
    ) -> Self {
        Self {
            name,
            resource,
            action,
            purpose,
        }
    }

    /// The operation name a Local Principal grant lists.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// The capability resource.
    #[must_use]
    pub const fn resource(self) -> &'static str {
        self.resource
    }

    /// The capability action.
    #[must_use]
    pub const fn action(self) -> &'static str {
        self.action
    }

    /// The purpose the operation is evaluated for.
    #[must_use]
    pub const fn purpose(self) -> &'static str {
        self.purpose
    }

    /// The served operation named `name`, if any.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|operation| operation.name == name)
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

    /// Build the request of one [`GatewayOperationV1`] by `actor_entity_id`,
    /// bound to `target_timeline` when the operation names one.
    #[must_use]
    pub fn operation(
        actor_entity_id: EntityId,
        operation: GatewayOperationV1,
        target_timeline: Option<TimelineId>,
        at_time: WallTime,
    ) -> Self {
        Self {
            target: GatewayAuthorizationTarget::Operation {
                timeline_id: target_timeline,
            },
            actor_entity_id,
            subject_id: None,
            participant_id: None,
            plugin_id: None,
            installation_id: None,
            principal_role: AuthorityRoleV1::Actor,
            resource: operation.resource().to_owned(),
            data_category: operation.resource().to_owned(),
            action: operation.action().to_owned(),
            purpose: operation.purpose().to_owned(),
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
    expiry: Option<AuthorizationExpiryV1>,
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

/// The trusted source a host recomposes its pinned authority from (#1361).
///
/// A host whose authorizer names a source reads the source's recorded chain
/// from its store before each protected decision; when the store is ahead of
/// the pinned chain (a revocation recorded by another writer), the host
/// recomposes the view and the registry that attests it together, so a
/// revocation is current (owner decision D10 on #302) and is answered
/// `revoked` (D3).
pub trait GatewayAuthoritySourceV1: Send + Sync {
    /// The leaf grant the store records this host's authority under.
    fn leaf_grant_id(&self) -> Hash;

    /// The view and attesting registry of one recorded chain, or `None`
    /// when the source cannot reproduce that chain exactly.
    fn recompose(
        &self,
        persisted: &PersistedAuthorityV1,
    ) -> Option<(AuthorityViewV1, AuthorityRegistrySnapshotV1)>;
}

/// The authority a host decides with: one recorded chain and the registry
/// that attests it, always replaced together.
struct PinnedAuthorityV1 {
    view: AuthorityViewV1,
    registry: AuthorityRegistrySnapshotV1,
}

/// Host-owned authority evaluator used by Gateway protected seams.
#[derive(Clone)]
pub struct GatewayAuthorization {
    adapter: Arc<dyn GatewayAuthenticationAdapter>,
    authority: Arc<RwLock<Arc<PinnedAuthorityV1>>>,
    registry_digest: Hash,
    source: Option<Arc<dyn GatewayAuthoritySourceV1>>,
    persistence: AuthorityPersistenceHostV1,
    revocation_state_current: bool,
    commit_lock: Arc<AsyncRwLock<()>>,
    audits: Arc<Mutex<VecDeque<GatewayAuthorizationAudit>>>,
    denial_budget: Arc<Mutex<DenialRecordBudget>>,
}

impl GatewayAuthorization {
    /// Bind one authentication adapter to a trusted, pinned authority snapshot.
    #[must_use]
    pub fn new(
        adapter: Arc<dyn GatewayAuthenticationAdapter>,
        authority: AuthorityViewV1,
        registry: AuthorityRegistrySnapshotV1,
    ) -> Self {
        Self::new_with_revocation_state(adapter, authority, registry, true)
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
    ) -> Self {
        Self {
            adapter,
            persistence: AuthorityPersistenceHostV1::new(&registry),
            registry_digest: registry.registry_digest(),
            authority: Arc::new(RwLock::new(Arc::new(PinnedAuthorityV1 {
                view: authority,
                registry,
            }))),
            source: None,
            revocation_state_current,
            commit_lock: Arc::new(AsyncRwLock::new(())),
            audits: Arc::new(Mutex::new(VecDeque::new())),
            denial_budget: Arc::new(Mutex::new(DenialRecordBudget::default())),
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
                    .map(|pinned| Arc::clone(&pinned))
                    .map_err(|_| GatewayAuthorizationError::AuthorityUnavailable)
                    .and_then(|pinned| {
                        let authority = pinned.view.authority();
                        core_request(&request, &authenticated, authority, &pinned.registry)
                            .map_err(|_| GatewayAuthorizationError::RequestUnavailable)
                            .map(|core_request| {
                                let (decision, expiry) =
                                    AuthorityEvaluatorV1::authorize_with_expiry(
                                        &core_request,
                                        authority.chain(),
                                        &pinned.registry,
                                    );
                                GatewayAuthorizationDecision {
                                    request,
                                    authenticated,
                                    decision,
                                    expiry,
                                    operation_binding,
                                }
                            })
                    })
            })
    }

    /// Evaluate and require an active authorization decision.
    ///
    /// A denied decision returns [`GatewayAuthorizationError::Denied`] with
    /// its pending ADN1 record; nothing is answered as a denial until
    /// `Self::record_denial` has made that record durable. The AUD1 outcome
    /// maps to one [`GatewayAuthorityDenial`]: `RevokedAtFence`, a grant or
    /// consent `Expired` and a revoked or expired delegation parent
    /// (`ParentInvalid`) to `Revoked`; expired authentication evidence or an
    /// unresolved Principal to `Unauthenticated`; `ConsentMissing` to
    /// `ConsentInvalid`; `RevocationStateStale` to itself; and every other
    /// fail-closed answer to `Unauthorized`.
    ///
    /// # Errors
    /// Returns the pending denial, or one of the host authentication,
    /// authority-state, or request-validation errors.
    pub fn authorize(
        &self,
        request: GatewayAuthorizationRequest,
    ) -> Result<GatewayAuthorizationDecision, GatewayAuthorizationError> {
        self.evaluate(request).and_then(|decision| {
            AuthorizationDenialRecordV1::from_decision(
                &decision.decision,
                decision.operation_binding,
            )
            .map(|record| {
                GatewayAuthorizationError::Denied(PendingAuthorityDenial {
                    record,
                    principal: decision.decision.principal().clone(),
                    denial: denial_of(&record, decision.expiry),
                })
            })
            .map_or(Ok(decision), Err)
        })
    }

    /// The pending denial of a store refusal at its commit fence for an
    /// operation this host had authorized; `None` when `outcome` is active.
    ///
    /// The store composes the persisted authority chain, so it can find a
    /// revocation or expiry another host persisted after this host's own
    /// decision. Authentication evidence was accepted by that decision, so an
    /// expiry here is the grant's.
    pub(crate) fn deny_at_commit_fence(
        decision: &GatewayAuthorizationDecision,
        outcome: AuthorizationOutcomeV1,
        error: Option<AuthorityErrorV1>,
    ) -> Option<PendingAuthorityDenial> {
        AuthorizationDenialRecordV1::with_outcome(
            &decision.decision,
            decision.operation_binding,
            outcome,
            error,
        )
        .map(|record| PendingAuthorityDenial {
            record,
            principal: decision.decision.principal().clone(),
            denial: denial_of(&record, Some(AuthorizationExpiryV1::Grant)),
        })
    }

    /// Admit one more denial record under the per-Principal and host-wide
    /// fixed-window bounds. A suppressed denial is answered as
    /// `resource-limit-exceeded` without a record of its own and is counted
    /// toward its bound's suppression marker.
    ///
    /// An admitted denial is returned with the suppression markers handed
    /// out when its window opened, if any; the caller must settle them with
    /// [`Self::settle_denial_markers`].
    pub(crate) fn admit_denial_record(
        &self,
        pending: PendingAuthorityDenial,
    ) -> Result<DenialEvidenceBatch, DenialSuppression> {
        self.budget()
            .admit(&pending.principal, Instant::now())
            .map(|suppressions| DenialEvidenceBatch {
                suppressions,
                denial: Some(pending),
            })
    }

    /// Hand out every unrecorded suppression count as markers, for a window
    /// flush or a shutdown; settle them with [`Self::settle_denial_markers`].
    pub(crate) fn take_denial_markers(&self) -> DenialEvidenceBatch {
        DenialEvidenceBatch {
            suppressions: self.budget().take(),
            denial: None,
        }
    }

    /// Settle markers handed out by a batch: a committed marker's count is
    /// recorded for good, any other marker's count is returned for a later
    /// marker, so a count is recorded exactly once whatever part of a batch
    /// committed.
    pub(crate) fn settle_denial_markers(
        &self,
        handed_out: &[AuthorizationDenialSuppressionV1],
        committed: &[AuthorizationDenialSuppressionV1],
    ) {
        self.budget().settle(handed_out, committed);
    }

    /// Whether any suppression count is still waiting for a marker.
    #[cfg(test)]
    pub(crate) fn denial_markers_pending(&self) -> bool {
        self.budget().has_pending()
    }

    /// Whether a handed-out count still awaits its settlement.
    #[cfg(test)]
    pub(crate) fn denial_markers_in_flight(&self) -> bool {
        let budget = self.budget();
        let in_flight = budget.in_flight_principal > 0 || budget.in_flight_host > 0;
        drop(budget);
        in_flight
    }

    fn budget(&self) -> std::sync::MutexGuard<'_, DenialRecordBudget> {
        self.denial_budget
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Shorten the denial-record window so a test can observe its expiry.
    #[cfg(test)]
    pub(crate) fn with_denial_window(self, window: Duration) -> Self {
        self.budget().window = window;
        self
    }

    /// Record one batch of denial evidence in the authority store: each ADS1
    /// marker, then the admitted denial's ADN1 record, each in its own
    /// committed transaction. The receipt names the markers that committed
    /// and, when the denial's record committed, the only value the Gateway
    /// answers as an authority denial.
    ///
    /// The store is bound to this host's persistence identity first (an
    /// idempotent rebind); a store bound to another host commits nothing.
    /// Run it on the store worker, never under the commit fence.
    pub(crate) fn record_denial(
        &self,
        store: &mut dyn AuthorityPersistencePortV1,
        batch: &DenialEvidenceBatch,
    ) -> DenialEvidenceReceipt {
        if store
            .bind_authority_persistence(self.persistence.persistence_binding())
            .is_err()
        {
            return DenialEvidenceReceipt::default();
        }
        let mut committed = Vec::new();
        for marker in &batch.suppressions {
            if store
                .record_authorization_denial(
                    self.persistence
                        .authorize_denial(AuthorizationDenialEvidenceV1::Suppressed(*marker)),
                )
                .is_ok()
            {
                committed.push(*marker);
            }
        }
        let denial = batch.denial.as_ref().and_then(|pending| {
            store
                .record_authorization_denial(
                    self.persistence
                        .authorize_denial(AuthorizationDenialEvidenceV1::Denial(pending.record)),
                )
                .ok()
                .map(|()| RecordedAuthorityDenial(pending.denial))
        });
        DenialEvidenceReceipt { committed, denial }
    }

    /// Replace the pinned authority snapshot at a host-controlled fence.
    ///
    /// The same commit lock used by Gateway appends prevents an update from
    /// racing a final authorization check and append. An authorizer with a
    /// [`GatewayAuthoritySourceV1`] rebuilds the attesting registry with the
    /// view through that source, exactly as a store refresh does, so a
    /// revocation learned here is answered `revoked`. The replacement is the
    /// host's own in-process decision and is installed as given; a later
    /// store refresh never rolls it back (see [`Self::is_behind`]).
    ///
    /// # Errors
    /// Returns [`GatewayAuthorizationError::AuthorityUnavailable`] when the
    /// host authority lock is poisoned and cannot be replaced safely, or the
    /// source cannot reproduce `authority` under this host's registry digest.
    pub async fn replace_authority(
        &self,
        authority: AuthorityViewV1,
    ) -> Result<(), GatewayAuthorizationError> {
        let _guard = self.commit_lock.write().await;
        self.pinned_for(authority)
            .and_then(|pinned| self.install(pinned))
    }

    /// Attach the source this host recomposes its authority from.
    #[must_use]
    pub fn with_source(mut self, source: Arc<dyn GatewayAuthoritySourceV1>) -> Self {
        self.source = Some(source);
        self
    }

    /// The leaf grant this host's source records its authority under.
    pub(crate) fn source_leaf(&self) -> Option<Hash> {
        self.source
            .as_ref()
            .map(|source| GatewayAuthoritySourceV1::leaf_grant_id(source.as_ref()))
    }

    /// Whether the store's `persisted` chain is ahead of the pinned one: a
    /// later revocation epoch or Timeline position another writer recorded.
    /// A chain this host learned first (through [`Self::replace_authority`])
    /// is never rolled back by an older record.
    pub(crate) fn is_behind(&self, persisted: &PersistedAuthorityV1) -> bool {
        let pinned = self.pinned();
        let current = pinned.view.authority();
        (persisted.revocation_epoch(), persisted.head_position())
            > (current.revocation_epoch(), current.head_position())
    }

    /// Recompose the pinned view and registry from the store's `persisted`
    /// chain under the commit-fence write guard, so no decision or admitted
    /// operation interleaves.
    ///
    /// The comparison is repeated under the guard: a refresh that raced a
    /// newer one never installs its older record over the newer pin.
    pub(crate) async fn refresh(
        &self,
        persisted: &PersistedAuthorityV1,
    ) -> Result<(), GatewayAuthorizationError> {
        let _guard = self.commit_lock.write().await;
        if !self.is_behind(persisted) {
            return Ok(());
        }
        self.recomposed(persisted)
            .and_then(|pinned| self.install(pinned))
    }

    /// Decide `request` as a host that cannot vouch for its revocation
    /// state: a store whose authority record could not be read or
    /// recomposed. A covered request is denied `RevocationStateStale`
    /// (`503`, retryable; D3 on #302), never answered as unauthenticated.
    pub(crate) fn authorize_with_stale_state(
        &self,
        request: GatewayAuthorizationRequest,
    ) -> Result<GatewayAuthorizationDecision, GatewayAuthorizationError> {
        let mut stale = self.clone();
        stale.revocation_state_current = false;
        stale.authorize(request)
    }

    /// Wait until every operation admitted under the commit fence has
    /// released it.
    pub(crate) async fn wait_for_admitted_operations(&self) {
        drop(self.commit_lock.write().await);
    }

    /// The source's view and registry for `persisted`, under this host's
    /// unchanged registry digest.
    fn recomposed(
        &self,
        persisted: &PersistedAuthorityV1,
    ) -> Result<PinnedAuthorityV1, GatewayAuthorizationError> {
        self.source
            .as_ref()
            .and_then(|source| source.recompose(persisted))
            .filter(|(_, registry)| registry.registry_digest() == self.registry_digest)
            .map(|(view, registry)| PinnedAuthorityV1 { view, registry })
            .ok_or(GatewayAuthorizationError::AuthorityUnavailable)
    }

    /// The pinned authority of a replacement view: rebuilt through the
    /// source when there is one, else with the current registry.
    fn pinned_for(
        &self,
        view: AuthorityViewV1,
    ) -> Result<PinnedAuthorityV1, GatewayAuthorizationError> {
        if self.source.is_none() {
            return Ok(PinnedAuthorityV1 {
                registry: self.pinned().registry.clone(),
                view,
            });
        }
        self.recomposed(view.authority()).and_then(|pinned| {
            (pinned.view == view)
                .then_some(pinned)
                .ok_or(GatewayAuthorizationError::AuthorityUnavailable)
        })
    }

    /// Swap in a complete pinned authority.
    fn install(&self, pinned: PinnedAuthorityV1) -> Result<(), GatewayAuthorizationError> {
        self.authority
            .write()
            .map(|mut current| {
                *current = Arc::new(pinned);
            })
            .map_err(|_| GatewayAuthorizationError::AuthorityUnavailable)
    }

    /// The current pinned authority; replacement only swaps a complete
    /// snapshot, so a poisoned lock still holds a whole one.
    fn pinned(&self) -> Arc<PinnedAuthorityV1> {
        Arc::clone(
            &self
                .authority
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// The registry the host currently decides with.
    #[cfg(test)]
    pub(crate) fn registry_for_test(&self) -> AuthorityRegistrySnapshotV1 {
        self.pinned().registry.clone()
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
        let pinned = self.pinned();
        self.persistence
            .persist_authority(store, &pinned.view)
            .map(|persisted| (persisted.leaf_grant_id(), persisted))
    }

    /// The pinned authority registry digest and revocation-freshness claim
    /// that select this host's execution profile.
    pub(crate) const fn execution_profile(&self) -> (Hash, bool) {
        (self.registry_digest, self.revocation_state_current)
    }
}

/// The closed mapping from an ADN1 record and the evaluator's expiry report
/// to its public denial (owner decisions D3 and D9 on #302).
///
/// Expired authentication evidence and an unresolved Principal are
/// `Unauthenticated`. A revoked or expired grant, consent or delegation parent
/// (`ParentInvalid` is a parent revoked or expired before the leaf) reads as
/// `Revoked`. Every other fail-closed indeterminate answer is `Unauthorized`.
/// A record never holds `Active`; it shares the `Revoked` arm only so the
/// match stays total.
const fn denial_of(
    record: &AuthorizationDenialRecordV1,
    expiry: Option<AuthorizationExpiryV1>,
) -> GatewayAuthorityDenial {
    match record.outcome() {
        AuthorizationOutcomeV1::Expired | AuthorizationOutcomeV1::IndeterminateFailClosed
            if matches!(expiry, Some(AuthorizationExpiryV1::AuthenticationEvidence))
                || matches!(record.error(), Some(AuthorityErrorV1::PrincipalUnresolved)) =>
        {
            GatewayAuthorityDenial::Unauthenticated
        }
        AuthorizationOutcomeV1::ConsentMissing => GatewayAuthorityDenial::ConsentInvalid,
        AuthorizationOutcomeV1::RevocationStateStale => {
            GatewayAuthorityDenial::RevocationStateStale
        }
        AuthorizationOutcomeV1::IndeterminateFailClosed => GatewayAuthorityDenial::Unauthorized,
        AuthorizationOutcomeV1::Active
        | AuthorizationOutcomeV1::RevokedAtFence
        | AuthorizationOutcomeV1::Expired
        | AuthorizationOutcomeV1::ParentInvalid => GatewayAuthorityDenial::Revoked,
    }
}

/// Denial evidence awaiting its store write: handed-out suppression markers
/// and at most one admitted denial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenialEvidenceBatch {
    suppressions: Vec<AuthorizationDenialSuppressionV1>,
    denial: Option<PendingAuthorityDenial>,
}

impl DenialEvidenceBatch {
    /// The suppression markers this batch hands out.
    pub(crate) fn markers(&self) -> &[AuthorizationDenialSuppressionV1] {
        &self.suppressions
    }

    /// Whether the batch has nothing to write.
    pub(crate) const fn is_empty(&self) -> bool {
        self.suppressions.is_empty() && self.denial.is_none()
    }
}

/// What one batch committed: its markers that committed and its recorded
/// denial, if that record committed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DenialEvidenceReceipt {
    committed: Vec<AuthorizationDenialSuppressionV1>,
    denial: Option<RecordedAuthorityDenial>,
}

impl DenialEvidenceReceipt {
    /// The markers whose records committed.
    pub(crate) fn committed(&self) -> &[AuthorizationDenialSuppressionV1] {
        &self.committed
    }

    /// The recorded denial, when the batch held one and it committed.
    pub(crate) const fn denial(&self) -> Option<RecordedAuthorityDenial> {
        self.denial
    }
}

/// A suppressed denial: how long until its window closes, and the instant at
/// which to flush the window's markers when this is its first suppression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DenialSuppression {
    pub(crate) retry_after: Duration,
    pub(crate) flush_at: Option<Instant>,
}

/// A fixed-window bound on denial records (#1359): at most
/// [`MAX_DENIAL_RECORDS_PER_PRINCIPAL_PER_MINUTE`] per Principal and
/// [`MAX_DENIAL_RECORDS_PER_MINUTE`] in total. A new window forgets every
/// Principal, so the map never holds more entries than the host-wide bound.
///
/// Suppressed denials are counted per bound. Counts are handed out as ADS1
/// markers when the next window opens, when a saturated window expires (one
/// flush timer per window) or at shutdown. A handed-out count stays in
/// flight until its marker is settled: a committed marker is acknowledged,
/// any other is returned to the pending count, so a store fault, a full log
/// or a dropped command never loses or duplicates a count, and a flood costs
/// O(1) marker writes per window.
#[derive(Debug)]
struct DenialRecordBudget {
    window: Duration,
    window_start: Option<Instant>,
    total: u32,
    per_principal: BTreeMap<PrincipalRefV1, u32>,
    flush_armed: bool,
    pending_principal: u64,
    pending_host: u64,
    in_flight_principal: u64,
    in_flight_host: u64,
}

impl Default for DenialRecordBudget {
    fn default() -> Self {
        Self {
            window: DENIAL_RECORD_WINDOW,
            window_start: None,
            total: 0,
            per_principal: BTreeMap::new(),
            flush_armed: false,
            pending_principal: 0,
            pending_host: 0,
            in_flight_principal: 0,
            in_flight_host: 0,
        }
    }
}

impl DenialRecordBudget {
    fn admit(
        &mut self,
        principal: &PrincipalRefV1,
        now: Instant,
    ) -> Result<Vec<AuthorizationDenialSuppressionV1>, DenialSuppression> {
        let opened = self
            .window_start
            .is_none_or(|start| now.saturating_duration_since(start) >= self.window);
        if opened {
            self.window_start = Some(now);
            self.total = 0;
            self.per_principal.clear();
            self.flush_armed = false;
        }
        let used = self.per_principal.get(principal).copied().unwrap_or(0);
        if self.total >= MAX_DENIAL_RECORDS_PER_MINUTE {
            self.pending_host = self.pending_host.saturating_add(1);
            return Err(self.suppression(now));
        }
        if used >= MAX_DENIAL_RECORDS_PER_PRINCIPAL_PER_MINUTE {
            self.pending_principal = self.pending_principal.saturating_add(1);
            return Err(self.suppression(now));
        }
        self.total = self.total.saturating_add(1);
        self.per_principal
            .insert(principal.clone(), used.saturating_add(1));
        Ok(if opened { self.take() } else { Vec::new() })
    }

    /// Whether any count waits for a marker.
    #[cfg(test)]
    const fn has_pending(&self) -> bool {
        self.pending_principal > 0 || self.pending_host > 0
    }

    /// Hand out the pending counts as markers and move them in flight.
    fn take(&mut self) -> Vec<AuthorizationDenialSuppressionV1> {
        let markers = [
            (
                AuthorizationDenialScopeV1::Principal,
                self.pending_principal,
            ),
            (AuthorizationDenialScopeV1::Host, self.pending_host),
        ]
        .into_iter()
        .filter_map(|(scope, suppressed)| {
            AuthorizationDenialSuppressionV1::try_new(scope, suppressed)
        })
        .collect();
        self.in_flight_principal = self
            .in_flight_principal
            .saturating_add(self.pending_principal);
        self.in_flight_host = self.in_flight_host.saturating_add(self.pending_host);
        self.pending_principal = 0;
        self.pending_host = 0;
        markers
    }

    /// Acknowledge committed markers and return every other handed-out
    /// marker's count to the pending count.
    fn settle(
        &mut self,
        handed_out: &[AuthorizationDenialSuppressionV1],
        committed: &[AuthorizationDenialSuppressionV1],
    ) {
        for marker in handed_out {
            let (pending, in_flight) = match marker.scope() {
                AuthorizationDenialScopeV1::Principal => {
                    (&mut self.pending_principal, &mut self.in_flight_principal)
                }
                AuthorizationDenialScopeV1::Host => {
                    (&mut self.pending_host, &mut self.in_flight_host)
                }
            };
            *in_flight = in_flight.saturating_sub(marker.suppressed());
            if !committed.contains(marker) {
                *pending = pending.saturating_add(marker.suppressed());
            }
        }
    }

    /// The retry delay of a suppressed denial, arming the window's one flush.
    fn suppression(&mut self, now: Instant) -> DenialSuppression {
        let window_end = self.window_start.map_or(now, |start| start + self.window);
        let flush_at = (!self.flush_armed).then_some(window_end);
        self.flush_armed = true;
        DenialSuppression {
            retry_after: window_end.saturating_duration_since(now),
            flush_at,
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
    digest_target(&mut hasher, request.target);
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

/// Bind the exact protected target of one request.
fn digest_target(hasher: &mut blake3::Hasher, target: GatewayAuthorizationTarget) {
    match target {
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
        GatewayAuthorizationTarget::Operation { timeline_id } => {
            hasher.update(&[2]);
            digest_optional_fixed(hasher, timeline_id.map(timeline_bytes));
        }
    }
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
    tests::fixture_authorization_with_actor(actor)
}

#[cfg(test)]
pub(crate) fn test_action_only_authorization_for(actor: EntityId) -> GatewayAuthorization {
    tests::fixture_action_only_authorization_with_actor(actor)
}

#[cfg(test)]
pub(crate) fn test_expired_authorization_for(actor: EntityId) -> GatewayAuthorization {
    tests::fixture_expired_authorization_with_actor(actor)
}

#[cfg(test)]
pub(crate) fn test_expired_grant_authorization_for(actor: EntityId) -> GatewayAuthorization {
    tests::fixture_expired_grant_authorization_with_actor(actor)
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

    trait TestSome<T> {
        fn test_some(self) -> T;
    }

    impl<T> TestSome<T> for Option<T> {
        fn test_some(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected a value")))
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
            [
                "ledger.prediction",
                "society.signal",
                "timeline",
                "timeline.events",
                "world.action.v1",
            ]
            .map(str::to_owned)
            .to_vec(),
            ["append", "create", "read", "world.action.v1.submit"]
                .map(str::to_owned)
                .to_vec(),
            ["action", "operation", "read"].map(str::to_owned).to_vec(),
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
        let authorization = GatewayAuthorization::new(
            Arc::new(LocalAuthenticationAdapter::new(authenticated.clone())),
            authority.clone(),
            registry,
        );
        Fixture {
            authorization,
            authenticated,
            actor,
            target_timeline: authority_timeline(actor),
            authority,
            revoked_authority,
        }
    }

    /// Rebind a fixture's authority to another authentication adapter.
    fn rebound(
        fixture: &Fixture,
        adapter: Arc<dyn GatewayAuthenticationAdapter>,
    ) -> GatewayAuthorization {
        GatewayAuthorization::new(
            adapter,
            fixture.authority.clone(),
            fixture.authorization.registry_for_test(),
        )
    }

    pub(super) fn fixture_authorization_with_actor(actor: EntityId) -> GatewayAuthorization {
        fixture_with_actor(actor).authorization
    }

    pub(super) fn fixture_action_only_authorization_with_actor(
        actor: EntityId,
    ) -> GatewayAuthorization {
        fixture_with_scope(
            actor,
            vec!["timeline".to_owned(), "world.action.v1".to_owned()],
            vec!["create".to_owned(), "world.action.v1.submit".to_owned()],
            vec!["action".to_owned(), "operation".to_owned()],
        )
        .authorization
    }

    pub(super) fn fixture_expired_authorization_with_actor(
        actor: EntityId,
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
        )
    }

    /// A grant valid for positions 1..2 whose authority Timeline a later
    /// sibling grant advanced to position 2, so the grant has expired.
    pub(super) fn fixture_expired_grant_authorization_with_actor(
        actor: EntityId,
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
        )
    }

    pub(super) fn fixture_authorization_unavailable_with_actor(
        actor: EntityId,
    ) -> GatewayAuthorization {
        let fixture = fixture_with_actor(actor);
        rebound(&fixture, Arc::new(RejectingAdapter))
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
        let authorization = rebound(&fixture, Arc::new(RejectingAdapter));
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
        );
        let air_gapped = rebound(
            &fixture,
            Arc::new(AirGappedAuthenticationAdapter::new(
                fixture.authenticated.clone(),
            )),
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
    }

    #[test]
    fn served_operations_are_closed_and_keyed_by_resource_and_action() {
        let names = GatewayOperationV1::ALL.map(GatewayOperationV1::name);
        let mut sorted = names;
        sorted.sort_unstable();
        assert_eq!(names, sorted);
        for operation in GatewayOperationV1::ALL {
            assert_eq!(GatewayOperationV1::named(operation.name()), Some(operation));
        }
        assert_eq!(GatewayOperationV1::named("timeline.delete"), None);
        let custom = GatewayOperationV1::new("scenario.create", "scenario", "create", "operation");
        assert_eq!(
            (custom.resource(), custom.action(), custom.purpose()),
            ("scenario", "create", "operation")
        );
        let request = GatewayAuthorizationRequest::operation(
            EntityId::new(),
            custom,
            None,
            WallTime::from_micros(1),
        );
        assert_eq!(request.resource, "scenario");
        assert_eq!(request.action, "create");
        assert_eq!(request.purpose, "operation");
        assert_eq!(
            request.target,
            GatewayAuthorizationTarget::Operation { timeline_id: None }
        );
        let bound = GatewayAuthorizationRequest::operation(
            request.actor_entity_id,
            custom,
            Some(TimelineId::new()),
            request.at_time,
        );
        assert_ne!(operation_binding(&request), operation_binding(&bound));
    }

    /// Authorize `request`, require a pending denial and check that its ADN1
    /// record binds the exact evaluation.
    fn denied(
        authorization: &GatewayAuthorization,
        request: GatewayAuthorizationRequest,
    ) -> PendingAuthorityDenial {
        let evaluated = authorization.evaluate(request.clone()).test_ok();
        let Some(GatewayAuthorizationError::Denied(pending)) =
            authorization.authorize(request).err()
        else {
            std::panic::resume_unwind(Box::new("expected a pending denial"));
        };
        assert_eq!(pending.record.request_digest(), evaluated.request_digest());
        assert_eq!(
            pending.record.operation_binding(),
            evaluated.operation_binding()
        );
        assert_eq!(pending.record.outcome(), evaluated.decision().outcome());
        assert_eq!(pending.record.error(), evaluated.decision().error());
        assert_eq!(&pending.principal, evaluated.principal());
        pending
    }

    #[test]
    fn denied_decision_does_not_enumerate_principal_or_entity() {
        let fixture = fixture();
        let mut request = action(&fixture);
        request.actor_entity_id = EntityId::new();
        let decision = fixture.authorization.evaluate(request.clone()).test_ok();
        assert!(!decision.is_allowed());
        let pending = denied(&fixture.authorization, request);
        assert_eq!(pending.denial, GatewayAuthorityDenial::Unauthorized);
        assert_eq!(
            pending.record.error(),
            Some(AuthorityErrorV1::CapabilityMissing)
        );
        for text in [
            GatewayAuthorizationError::Denied(pending).to_string(),
            RecordedAuthorityDenial(GatewayAuthorityDenial::Unauthorized).to_string(),
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
        let pending = denied(&fixture.authorization, request);
        assert_eq!(pending.denial, GatewayAuthorityDenial::ConsentInvalid);
        assert_eq!(
            pending.record.error(),
            Some(AuthorityErrorV1::ConsentMissing)
        );
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
            fixture.authorization.registry_for_test(),
            false,
        );
        let pending = denied(&stale, request);
        assert_eq!(pending.denial, GatewayAuthorityDenial::RevocationStateStale);
        assert_eq!(
            pending.record.outcome(),
            AuthorizationOutcomeV1::RevocationStateStale
        );
    }

    #[test]
    fn expired_authentication_evidence_is_unauthenticated() {
        let fixture = fixture();
        let mut request = action(&fixture);
        request.at_time = WallTime::from_micros(u64::MAX);
        let pending = denied(&fixture.authorization, request);
        assert_eq!(pending.denial, GatewayAuthorityDenial::Unauthenticated);
        assert_eq!(pending.record.outcome(), AuthorizationOutcomeV1::Expired);
        assert_eq!(pending.record.error(), None);
    }

    #[tokio::test]
    async fn a_revoked_or_expired_grant_is_revoked() {
        let fixture = fixture();
        fixture
            .authorization
            .replace_authority(fixture.revoked_authority.clone())
            .await
            .test_ok();
        let pending = denied(&fixture.authorization, action(&fixture));
        assert_eq!(pending.denial, GatewayAuthorityDenial::Revoked);
        assert_eq!(
            pending.record.outcome(),
            AuthorizationOutcomeV1::RevokedAtFence
        );

        let expired = fixture_expired_grant_authorization_with_actor(fixture.actor);
        let pending = denied(&expired, action(&fixture));
        assert_eq!(pending.denial, GatewayAuthorityDenial::Revoked);
        assert_eq!(pending.record.outcome(), AuthorizationOutcomeV1::Expired);
        assert_eq!(pending.record.error(), None);
    }

    #[test]
    fn a_denial_is_answered_only_after_the_store_commits_its_record() {
        let fixture = fixture();
        let mut request = action(&fixture);
        request.actor_entity_id = EntityId::new();
        let pending = denied(&fixture.authorization, request);
        let record = pending.record;
        let marker = marker(AuthorizationDenialScopeV1::Host, 4);
        let batch = DenialEvidenceBatch {
            suppressions: vec![marker],
            denial: Some(pending),
        };
        assert!(!batch.is_empty());
        assert_eq!(batch.markers(), &[marker]);

        let mut store = pos_store::memory::MemoryStore::new();
        let receipt = fixture.authorization.record_denial(&mut store, &batch);
        assert_eq!(receipt.committed(), &[marker]);
        assert_eq!(
            receipt.denial(),
            Some(RecordedAuthorityDenial(
                GatewayAuthorityDenial::Unauthorized
            ))
        );
        assert_eq!(
            store.load_authorization_denials(0, 8).test_ok(),
            vec![
                (1, AuthorizationDenialEvidenceV1::Suppressed(marker)),
                (2, AuthorizationDenialEvidenceV1::Denial(record)),
            ]
        );
        let empty = fixture.authorization.take_denial_markers();
        assert!(empty.is_empty());
        assert_eq!(
            fixture.authorization.record_denial(&mut store, &empty),
            DenialEvidenceReceipt::default()
        );
        assert_eq!(
            RecordedAuthorityDenial(GatewayAuthorityDenial::Revoked).denial(),
            GatewayAuthorityDenial::Revoked
        );

        // A store bound to another host refuses every record: nothing is
        // recorded, so the caller is never answered with the denial.
        let mut foreign = pos_store::memory::MemoryStore::new();
        foreign
            .bind_authority_persistence(
                AuthorityPersistenceHostV1::new(&fixture.authorization.registry_for_test())
                    .persistence_binding(),
            )
            .test_ok();
        assert_eq!(
            fixture.authorization.record_denial(&mut foreign, &batch),
            DenialEvidenceReceipt::default()
        );
        assert!(foreign
            .load_authorization_denials(0, 8)
            .test_ok()
            .is_empty());
    }

    fn marker(scope: AuthorizationDenialScopeV1, count: u64) -> AuthorizationDenialSuppressionV1 {
        AuthorizationDenialSuppressionV1::try_new(scope, count).test_some()
    }

    /// A memory store that refuses every denial-evidence write after its
    /// first `accepted` ones.
    struct FlakyStore {
        inner: pos_store::memory::MemoryStore,
        accepted: usize,
    }

    impl AuthorityPersistencePortV1 for FlakyStore {
        fn bind_authority_persistence(
            &mut self,
            binding: pos_core::AuthorityPersistenceBindingV1,
        ) -> Result<(), AuthorityPersistenceErrorV1> {
            self.inner.bind_authority_persistence(binding)
        }

        fn issue_capability_grant(
            &mut self,
            permit: pos_core::AuthorityMutationPermitV1,
            grant: &CapabilityGrantV1,
        ) -> Result<pos_core::AuthorityCommitOutcomeV1, AuthorityPersistenceErrorV1> {
            self.inner.issue_capability_grant(permit, grant)
        }

        fn revoke_capability_grant(
            &mut self,
            permit: pos_core::AuthorityMutationPermitV1,
            revocation: &CapabilityRevocationV1,
        ) -> Result<pos_core::AuthorityCommitOutcomeV1, AuthorityPersistenceErrorV1> {
            self.inner.revoke_capability_grant(permit, revocation)
        }

        fn load_authority(
            &self,
            leaf_grant_id: Hash,
        ) -> Result<PersistedAuthorityV1, AuthorityPersistenceErrorV1> {
            self.inner.load_authority(leaf_grant_id)
        }

        fn record_authorization_denial(
            &mut self,
            permit: pos_core::AuthorizationDenialPermitV1,
        ) -> Result<(), AuthorityPersistenceErrorV1> {
            if self.accepted == 0 {
                return Err(AuthorityPersistenceErrorV1::Unavailable);
            }
            self.accepted -= 1;
            self.inner.record_authorization_denial(permit)
        }

        fn load_authorization_denials(
            &self,
            after: u64,
            limit: usize,
        ) -> Result<Vec<(u64, AuthorizationDenialEvidenceV1)>, AuthorityPersistenceErrorV1>
        {
            self.inner.load_authorization_denials(after, limit)
        }
    }

    /// Hand out the budget's markers, write them to `store` and settle them,
    /// as the Gateway does.
    fn flush(authorization: &GatewayAuthorization, store: &mut FlakyStore) {
        let batch = authorization.take_denial_markers();
        let receipt = authorization.record_denial(store, &batch);
        authorization.settle_denial_markers(batch.markers(), receipt.committed());
    }

    #[test]
    fn suppression_counts_survive_failed_and_partial_writes_exactly_once() {
        let fixture = fixture();
        let start = Instant::now();
        let principal = |byte: u8| PrincipalRefV1::try_new([byte; 16], "gateway.test").test_ok();
        {
            let mut budget = fixture.authorization.budget();
            for byte in 1..=10 {
                for _ in 0..MAX_DENIAL_RECORDS_PER_PRINCIPAL_PER_MINUTE {
                    assert!(budget.admit(&principal(byte), start).is_ok());
                }
                if byte == 1 {
                    // One Principal over its own bound before the host fills.
                    assert!(budget.admit(&principal(1), start).is_err());
                }
            }
            // Two more over the host bound.
            assert!(budget.admit(&principal(11), start).is_err());
            assert!(budget.admit(&principal(12), start).is_err());
            drop(budget);
        }
        let both = vec![
            marker(AuthorizationDenialScopeV1::Principal, 1),
            marker(AuthorizationDenialScopeV1::Host, 2),
        ];

        // A store that refuses everything keeps every count pending.
        let mut store = FlakyStore {
            inner: pos_store::memory::MemoryStore::new(),
            accepted: 0,
        };
        flush(&fixture.authorization, &mut store);
        // A store that commits only the first marker of the batch.
        store.accepted = 1;
        assert_eq!(fixture.authorization.budget().take(), both);
        fixture.authorization.settle_denial_markers(&both, &[]);
        flush(&fixture.authorization, &mut store);
        // The next write records only the count that did not commit.
        store.accepted = 8;
        flush(&fixture.authorization, &mut store);
        flush(&fixture.authorization, &mut store);
        assert_eq!(
            store.load_authorization_denials(0, 8).test_ok(),
            vec![
                (1, AuthorizationDenialEvidenceV1::Suppressed(both[0])),
                (2, AuthorizationDenialEvidenceV1::Suppressed(both[1])),
            ]
        );
        let budget = fixture.authorization.budget();
        let counts = (
            budget.pending_principal,
            budget.pending_host,
            budget.in_flight_principal,
            budget.in_flight_host,
        );
        drop(budget);
        assert_eq!(counts, (0, 0, 0, 0));
    }

    #[test]
    fn every_authority_outcome_has_one_public_denial() {
        use super::GatewayAuthorityDenial as Denial;
        use pos_core::AuthorizationOutcomeV1 as Outcome;
        let fixture = fixture();
        let decision = fixture.authorization.authorize(action(&fixture)).test_ok();
        let record = |outcome, error| {
            AuthorizationDenialRecordV1::with_outcome(
                &decision.decision,
                decision.operation_binding,
                outcome,
                error,
            )
        };
        assert_eq!(record(Outcome::Active, None), None);
        let cases = [
            (
                Outcome::RevokedAtFence,
                Some(AuthorityErrorV1::RevokedAtFence),
                None,
                Denial::Revoked,
            ),
            (
                Outcome::Expired,
                None,
                Some(AuthorizationExpiryV1::Grant),
                Denial::Revoked,
            ),
            (
                Outcome::Expired,
                None,
                Some(AuthorizationExpiryV1::Consent),
                Denial::Revoked,
            ),
            (
                Outcome::Expired,
                None,
                Some(AuthorizationExpiryV1::AuthenticationEvidence),
                Denial::Unauthenticated,
            ),
            (
                Outcome::ParentInvalid,
                Some(AuthorityErrorV1::DelegationInvalid),
                None,
                Denial::Revoked,
            ),
            (
                Outcome::ConsentMissing,
                Some(AuthorityErrorV1::ConsentMissing),
                None,
                Denial::ConsentInvalid,
            ),
            (
                Outcome::RevocationStateStale,
                Some(AuthorityErrorV1::RevocationStateStale),
                None,
                Denial::RevocationStateStale,
            ),
            (
                Outcome::IndeterminateFailClosed,
                Some(AuthorityErrorV1::PrincipalUnresolved),
                None,
                Denial::Unauthenticated,
            ),
            (
                Outcome::IndeterminateFailClosed,
                Some(AuthorityErrorV1::CapabilityMissing),
                None,
                Denial::Unauthorized,
            ),
            (
                Outcome::IndeterminateFailClosed,
                Some(AuthorityErrorV1::PolicyIndeterminate),
                None,
                Denial::Unauthorized,
            ),
        ];
        for (outcome, error, expiry, expected) in cases {
            let Some(record) = record(outcome, error) else {
                std::panic::resume_unwind(Box::new("a denied outcome has a record"));
            };
            assert_eq!(denial_of(&record, expiry), expected, "{outcome:?}");
        }
    }

    #[test]
    fn a_commit_fence_denial_binds_the_rechecked_operation() {
        let fixture = fixture();
        let decision = fixture.authorization.authorize(action(&fixture)).test_ok();
        assert_eq!(
            GatewayAuthorization::deny_at_commit_fence(
                &decision,
                AuthorizationOutcomeV1::Active,
                None
            ),
            None
        );
        for (outcome, error) in [
            (
                AuthorizationOutcomeV1::RevokedAtFence,
                Some(AuthorityErrorV1::RevokedAtFence),
            ),
            (AuthorizationOutcomeV1::Expired, None),
        ] {
            let Some(pending) =
                GatewayAuthorization::deny_at_commit_fence(&decision, outcome, error)
            else {
                std::panic::resume_unwind(Box::new("a fence refusal is a denial"));
            };
            assert_eq!(pending.denial, GatewayAuthorityDenial::Revoked);
            assert_eq!(pending.record.request_digest(), decision.request_digest());
            assert_eq!(
                pending.record.operation_binding(),
                decision.operation_binding()
            );
            assert_eq!(pending.record.outcome(), outcome);
        }
    }

    #[test]
    fn denial_records_are_bounded_per_principal_and_host_wide_per_window() {
        let start = Instant::now();
        let principal = |byte: u8| PrincipalRefV1::try_new([byte; 16], "gateway.test").test_ok();
        let mut budget = DenialRecordBudget::default();
        for _ in 0..MAX_DENIAL_RECORDS_PER_PRINCIPAL_PER_MINUTE {
            assert_eq!(budget.admit(&principal(1), start), Ok(Vec::new()));
        }
        let later = start + Duration::from_secs(20);
        let window_end = start + DENIAL_RECORD_WINDOW;
        assert_eq!(
            budget.admit(&principal(1), later),
            Err(DenialSuppression {
                retry_after: Duration::from_secs(40),
                flush_at: Some(window_end),
            })
        );
        for _ in 0..2 {
            assert_eq!(
                budget.admit(&principal(1), later),
                Err(DenialSuppression {
                    retry_after: Duration::from_secs(40),
                    flush_at: None,
                })
            );
        }
        assert_eq!(budget.admit(&principal(2), later), Ok(Vec::new()));

        // The first admitted denial of the next window hands out one marker
        // with the suppressed count, and a new window forgets every
        // Principal; the count stays in flight until it is settled.
        let principal_marker = marker(AuthorizationDenialScopeV1::Principal, 3);
        assert_eq!(
            budget.admit(&principal(1), window_end),
            Ok(vec![principal_marker])
        );
        assert_eq!(budget.per_principal.len(), 1);
        assert!(budget.take().is_empty());
        assert_eq!(budget.in_flight_principal, 3);
        budget.settle(&[principal_marker], &[principal_marker]);
        assert_eq!(budget.in_flight_principal, 0);

        let mut budget = DenialRecordBudget::default();
        let principals =
            MAX_DENIAL_RECORDS_PER_MINUTE / MAX_DENIAL_RECORDS_PER_PRINCIPAL_PER_MINUTE;
        for byte in 0..principals {
            for _ in 0..MAX_DENIAL_RECORDS_PER_PRINCIPAL_PER_MINUTE {
                assert!(budget
                    .admit(&principal(u8::try_from(byte + 1).test_ok()), start)
                    .is_ok());
            }
        }
        assert_eq!(
            budget.admit(&principal(200), start),
            Err(DenialSuppression {
                retry_after: DENIAL_RECORD_WINDOW,
                flush_at: Some(window_end),
            })
        );
        assert_eq!(budget.total, MAX_DENIAL_RECORDS_PER_MINUTE);
        assert_eq!(
            budget.take(),
            vec![marker(AuthorizationDenialScopeV1::Host, 1)]
        );

        let fixture = fixture();
        let mut request = action(&fixture);
        request.actor_entity_id = EntityId::new();
        let pending = denied(&fixture.authorization, request);
        for _ in 0..MAX_DENIAL_RECORDS_PER_PRINCIPAL_PER_MINUTE {
            assert!(fixture
                .authorization
                .admit_denial_record(pending.clone())
                .is_ok());
        }
        assert!(fixture.authorization.admit_denial_record(pending).is_err());
        assert_eq!(
            fixture.authorization.take_denial_markers().markers(),
            &[marker(AuthorizationDenialScopeV1::Principal, 1)]
        );
        let shortened = fixture
            .authorization
            .with_denial_window(Duration::from_millis(5));
        assert_eq!(shortened.budget().window, Duration::from_millis(5));
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
