//! The reusable operation-authorization seam of the Gateway (#1361).
//!
//! A protected route names its [`GatewayOperationV1`] through an
//! [`OperationSpecV1`] marker, extracts its [`OperationAuthority`] (the acting
//! entity of the `x-piglor-actor-entity` header, never a credential: owner
//! decision D1 on #302 makes loopback reachability the Local trust boundary),
//! and authorizes it against the host-pinned Principal before it mutates or
//! looks anything up. Before each decision the host compares the authority
//! its store records with the pinned one and, when the store is ahead (a
//! revocation recorded by another writer), recomposes the view and its
//! registry together (owner decisions D3 and D10 on #302). A Principal with
//! consents is read through the consent Timeline of the host that owns the
//! store: once another process records anything to the store, that read
//! fails, so once the store is ahead of the pin (a revocation recorded
//! there) every covered decision is stale revocation state (`503`,
//! retryable) until the host restarts and recomposes the revocation.
//! The returned [`GatewayOperationPermitV1`] holds the authority commit fence, and
//! [`OperationAuthority::run`] runs the admitted mutation as a detached task
//! that owns the permit until the mutation completes, even when the request
//! is cancelled; so a revocation waits for every operation admitted before
//! it and takes effect before the next one.
//!
//! A denial is answered only after its evidence is recorded, exactly as the
//! action and read seams answer theirs. A Gateway without an authorizer whose
//! composition requires one (an unprovisioned host) answers every protected
//! operation `401 unauthenticated`.

use std::{convert::Infallible, future::Future, marker::PhantomData, sync::Arc};

use axum::{extract::FromRequestParts, http::request::Parts};
use pos_core::{EntityId, Hash, SeqRange, TimelineId, WallTime};
use tokio::sync::OwnedRwLockReadGuard;

use crate::{
    Gateway, GatewayAuthorityRecordV1, GatewayAuthorization, GatewayAuthorizationDecision,
    GatewayAuthorizationError, GatewayAuthorizationRequest, GatewayConsentRecordV1, GatewayError,
    GatewayOperationV1,
};

/// The header that names the acting entity of a protected operation.
pub const ACTOR_ENTITY_HEADER: &str = "x-piglor-actor-entity";

/// Names the operation one protected route authorizes.
pub trait OperationSpecV1 {
    /// The operation, keyed by its capability resource and action.
    const OPERATION: GatewayOperationV1;
}

/// `POST /v1/timelines`.
pub struct CreateTimelineOperation;

impl OperationSpecV1 for CreateTimelineOperation {
    const OPERATION: GatewayOperationV1 = GatewayOperationV1::CREATE_TIMELINE;
}

/// `POST /v1/timelines/{timeline_id}/signals`.
pub struct AppendSignalOperation;

impl OperationSpecV1 for AppendSignalOperation {
    const OPERATION: GatewayOperationV1 = GatewayOperationV1::APPEND_SIGNAL;
}

/// `POST /v1/ledger/predictions`.
pub struct CreatePredictionOperation;

impl OperationSpecV1 for CreatePredictionOperation {
    const OPERATION: GatewayOperationV1 = GatewayOperationV1::CREATE_PREDICTION;
}

/// `GET /v1/session`.
pub struct ReadSessionOperation;

impl OperationSpecV1 for ReadSessionOperation {
    const OPERATION: GatewayOperationV1 = GatewayOperationV1::READ_SESSION;
}

/// `POST /v1/scenario-rooms`.
pub struct CreateScenarioRoomOperation;

impl OperationSpecV1 for CreateScenarioRoomOperation {
    const OPERATION: GatewayOperationV1 = GatewayOperationV1::CREATE_SCENARIO_ROOM;
}

/// `POST /v1/scenario-rooms/{room_id}/revisions`.
pub struct DeriveScenarioRoomOperation;

impl OperationSpecV1 for DeriveScenarioRoomOperation {
    const OPERATION: GatewayOperationV1 = GatewayOperationV1::DERIVE_SCENARIO_ROOM;
}

/// `GET /v1/scenario-rooms/{room_id}/revisions/{revision}`.
pub struct ReadScenarioRoomOperation;

impl OperationSpecV1 for ReadScenarioRoomOperation {
    const OPERATION: GatewayOperationV1 = GatewayOperationV1::READ_SCENARIO_ROOM;
}

/// `POST /v1/me/consent-revocations`.
pub struct RevokeConsentOperation;

impl OperationSpecV1 for RevokeConsentOperation {
    const OPERATION: GatewayOperationV1 = GatewayOperationV1::REVOKE_CONSENT;
}

/// `POST /v1/me/erasures`.
pub struct RequestErasureOperation;

impl OperationSpecV1 for RequestErasureOperation {
    const OPERATION: GatewayOperationV1 = GatewayOperationV1::REQUEST_ERASURE;
}

/// `GET /v1/me/erasures/{erasure_id}`.
pub struct ReadErasureOperation;

impl OperationSpecV1 for ReadErasureOperation {
    const OPERATION: GatewayOperationV1 = GatewayOperationV1::READ_ERASURE;
}

/// `POST /v1/preferences`.
pub struct CreatePreferenceOperation;

impl OperationSpecV1 for CreatePreferenceOperation {
    const OPERATION: GatewayOperationV1 = GatewayOperationV1::CREATE_PREFERENCE;
}

/// `GET /v1/preferences/{preference_id}/revisions/{revision}`.
pub struct ReadPreferenceOperation;

impl OperationSpecV1 for ReadPreferenceOperation {
    const OPERATION: GatewayOperationV1 = GatewayOperationV1::READ_PREFERENCE;
}

/// `POST /v1/option-specs`.
pub struct CreateOptionSpecOperation;

impl OperationSpecV1 for CreateOptionSpecOperation {
    const OPERATION: GatewayOperationV1 = GatewayOperationV1::CREATE_OPTION_SPEC;
}

/// `GET /v1/option-specs/{option_spec_id}/revisions/{revision}`.
pub struct ReadOptionSpecOperation;

impl OperationSpecV1 for ReadOptionSpecOperation {
    const OPERATION: GatewayOperationV1 = GatewayOperationV1::READ_OPTION_SPEC;
}

/// The actor a protected decision admitted.
///
/// Only [`OperationAuthority::run_as_actor`] makes one, from the decision it
/// took, so a mutation that records its actor, such as the owner of a new
/// root Timeline ([`Gateway::create_timeline`], ADR-136 §1), can never be
/// handed an entity no decision admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmittedActorV1(EntityId);

impl AdmittedActorV1 {
    /// The admitted actor's entity.
    #[must_use]
    pub const fn entity_id(self) -> EntityId {
        self.0
    }
}

/// The authority inputs of one protected operation, from the request head.
///
/// They are only the acting entity, when the request names a valid one.
/// Extraction never fails; a missing or malformed actor is decided by
/// [`Self::authorize`].
pub struct OperationAuthority<O> {
    actor_entity_id: Option<EntityId>,
    acting_entity_id: Option<EntityId>,
    operation: PhantomData<fn() -> O>,
}

impl<O, S> FromRequestParts<S> for OperationAuthority<O>
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self {
            actor_entity_id: parts
                .headers
                .get(ACTOR_ENTITY_HEADER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| crate::parse_entity_id(value).ok()),
            acting_entity_id: None,
            operation: PhantomData,
        })
    }
}

impl<O> OperationAuthority<O> {
    /// The authority inputs of a request by `actor_entity_id`.
    #[cfg(test)]
    pub(crate) const fn for_test(actor_entity_id: Option<EntityId>) -> Self {
        Self {
            actor_entity_id,
            acting_entity_id: None,
            operation: PhantomData,
        }
    }
}

impl<O: OperationSpecV1> OperationAuthority<O> {
    /// Bind the entity the operation's payload acts as. It must be the
    /// header actor: any other entity is bound into the decision as a
    /// participant no grant covers, so the operation is a recorded
    /// `403 unauthorized` denial.
    #[must_use]
    pub const fn acting_as(mut self, entity: Option<EntityId>) -> Self {
        self.acting_entity_id = entity;
        self
    }

    /// Authorize the operation on `gateway`, bound to `target_timeline` when
    /// it names one.
    ///
    /// # Errors
    /// Returns the stable authorization failures of
    /// [`Gateway::authorize_operation`].
    pub async fn authorize(
        self,
        gateway: &Gateway,
        target_timeline: Option<TimelineId>,
    ) -> Result<GatewayOperationPermitV1, GatewayError> {
        gateway
            .authorize_operation(
                O::OPERATION,
                self.actor_entity_id,
                target_timeline,
                self.acting_entity_id,
            )
            .await
    }

    /// Authorize the operation, then run `operation` on its own task, which
    /// owns the permit until the mutation completes.
    ///
    /// A request cancelled after the decision does not release the fence
    /// early: the mutation either commits before a later revocation lands
    /// or is never started. Such tasks are bounded by the requests in flight
    /// and by the store command deadline: a hung mutation holds the read
    /// fence (delaying revocations) until its store command expires.
    /// [`Gateway::shutdown`] first waits, up to its shutdown deadline, for
    /// every admitted operation to release the fence; an operation still
    /// running then is reported and abandoned, and its store command fails
    /// once the store has shut down.
    ///
    /// # Errors
    /// Returns the failures of [`Self::authorize`], before `operation` is
    /// started, or the error of `operation`.
    pub async fn run<T, F, Fut>(
        self,
        gateway: &Gateway,
        target_timeline: Option<TimelineId>,
        operation: F,
    ) -> Result<T, GatewayError>
    where
        F: FnOnce(Gateway) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, GatewayError>> + Send + 'static,
        T: Send + 'static,
    {
        self.run_as_actor(gateway, target_timeline, move |gateway, _| {
            operation(gateway)
        })
        .await
    }

    /// [`Self::run`], handing `operation` the actor the decision admitted:
    /// `None` on a Gateway composition that protects nothing. A mutation
    /// that records its actor, such as the owner of a new root Timeline
    /// (ADR-136 §1), takes it from here, never from the request.
    ///
    /// # Errors
    /// Returns the failures of [`Self::run`].
    pub async fn run_as_actor<T, F, Fut>(
        self,
        gateway: &Gateway,
        target_timeline: Option<TimelineId>,
        operation: F,
    ) -> Result<T, GatewayError>
    where
        F: FnOnce(Gateway, Option<AdmittedActorV1>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, GatewayError>> + Send + 'static,
        T: Send + 'static,
    {
        let permit = self.authorize(gateway, target_timeline).await?;
        let gateway = gateway.clone();
        tokio::spawn(async move {
            // The permit moves into the task whole: it holds the authority
            // fence until the operation completes.
            let actor = permit
                .decision()
                .map(|decision| AdmittedActorV1(decision.actor_entity_id()));
            let output = operation(gateway, actor).await;
            drop(permit);
            output
        })
        .await
        .unwrap_or(Err(GatewayError::StoreExecutorUnhealthy))
    }

    /// [`Self::run`], requiring the Principal's grant to also cover every
    /// entity of `covered` as an actor, decided under the same fence (a
    /// Scenario Room's `persona` participants, #303 decision 3a). The first
    /// entity the grant does not cover is a recorded denial, and `operation`
    /// never starts.
    ///
    /// # Errors
    /// Returns the failures of [`Self::run`], and a recorded
    /// [`GatewayError::AuthorizationDenied`] for an uncovered entity.
    pub async fn run_covering<T, F, Fut>(
        self,
        gateway: &Gateway,
        covered: Vec<EntityId>,
        operation: F,
    ) -> Result<T, GatewayError>
    where
        F: FnOnce(Gateway, GatewayOperationPermitV1) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, GatewayError>> + Send + 'static,
        T: Send + 'static,
    {
        let permit = gateway
            .authorize_operation_covering(O::OPERATION, self.actor_entity_id, &covered)
            .await?;
        let gateway = gateway.clone();
        tokio::spawn(async move { operation(gateway, permit).await })
            .await
            .unwrap_or(Err(GatewayError::StoreExecutorUnhealthy))
    }
}

/// The authority commit fence held over one protected decision, taken after
/// the host brought its pinned authority current with its store.
pub(crate) struct AuthorityFence {
    _guard: OwnedRwLockReadGuard<()>,
    stale: bool,
}

impl AuthorityFence {
    /// Decide `request`; when the store's authority could not be read or
    /// recomposed, decide it as a host whose revocation state is stale, so
    /// a covered request is answered `503` and retryable.
    pub(crate) fn authorize(
        &self,
        authorization: &GatewayAuthorization,
        request: GatewayAuthorizationRequest,
    ) -> Result<GatewayAuthorizationDecision, GatewayAuthorizationError> {
        if self.stale {
            authorization.authorize_with_stale_state(request)
        } else {
            authorization.authorize(request)
        }
    }
}

/// The authority of one admitted protected operation.
///
/// While it lives it holds the authority commit fence, so the host authority
/// snapshot cannot be replaced under the operation it admitted.
#[must_use = "dropping the permit releases the authority fence before the operation runs"]
pub struct GatewayOperationPermitV1 {
    decision: Option<GatewayAuthorizationDecision>,
    fence: Option<AuthorityFence>,
}

impl GatewayOperationPermitV1 {
    /// The decision that admitted the operation; `None` on a Gateway
    /// composition that protects nothing.
    #[must_use]
    pub const fn decision(&self) -> Option<&GatewayAuthorizationDecision> {
        self.decision.as_ref()
    }
}

impl Gateway {
    /// Authorize one protected `operation` by `actor_entity_id` against the
    /// host-pinned Principal, before any lookup or mutation. An
    /// `acting_entity_id` other than the actor is bound as a participant no
    /// grant covers, so the operation is denied.
    ///
    /// A Gateway composition that protects nothing admits it without a
    /// decision. Otherwise the decision is taken under the authority commit
    /// fence, which the returned permit keeps until it is dropped.
    ///
    /// # Errors
    /// Returns [`GatewayError::AuthorizationUnavailable`] (`401`) when the
    /// host has no authorizer or the request names no valid actor, a
    /// recorded [`GatewayError::AuthorizationDenied`] for a denial, or the
    /// denial-evidence failures of the action and read seams.
    pub async fn authorize_operation(
        &self,
        operation: GatewayOperationV1,
        actor_entity_id: Option<EntityId>,
        target_timeline: Option<TimelineId>,
        acting_entity_id: Option<EntityId>,
    ) -> Result<GatewayOperationPermitV1, GatewayError> {
        if !self.has_authorization() {
            return Ok(GatewayOperationPermitV1 {
                decision: None,
                fence: None,
            });
        }
        let (Some(authorization), Some(actor)) = (self.authorization.as_ref(), actor_entity_id)
        else {
            return Err(GatewayError::AuthorizationUnavailable);
        };
        let mut request = GatewayAuthorizationRequest::operation(
            actor,
            operation,
            target_timeline,
            WallTime::now(),
        );
        request.participant_id = acting_entity_id.filter(|entity| *entity != actor);
        let fence = self.current_fence(authorization).await;
        match fence.authorize(authorization, request) {
            Ok(decision) => Ok(GatewayOperationPermitV1 {
                decision: Some(decision),
                fence: Some(fence),
            }),
            Err(error) => {
                // The denial's evidence is written after the fence is
                // released, so an authority replacement never waits on it.
                drop(fence);
                Err(self.authorization_failure(authorization, error).await)
            }
        }
    }

    /// [`Self::authorize_operation`] on the host, then decide `operation`
    /// for each entity of `covered` as its actor under the same fence.
    ///
    /// # Errors
    /// Returns the failures of [`Self::authorize_operation`], and a recorded
    /// [`GatewayError::AuthorizationDenied`] for the first uncovered entity.
    pub(crate) async fn authorize_operation_covering(
        &self,
        operation: GatewayOperationV1,
        actor_entity_id: Option<EntityId>,
        covered: &[EntityId],
    ) -> Result<GatewayOperationPermitV1, GatewayError> {
        let permit = self
            .authorize_operation(operation, actor_entity_id, None, None)
            .await?;
        let uncovered = permit
            .fence
            .as_ref()
            .zip(self.authorization.as_ref())
            .zip(permit.decision())
            .and_then(|((fence, authorization), decision)| {
                let at_time = decision.request().at_time;
                covered.iter().find_map(|entity| {
                    fence
                        .authorize(
                            authorization,
                            GatewayAuthorizationRequest::operation(
                                *entity, operation, None, at_time,
                            ),
                        )
                        .err()
                        .map(|error| (Arc::clone(authorization), error))
                })
            });
        match uncovered {
            None => Ok(permit),
            Some((authorization, error)) => {
                drop(permit);
                Err(self.authorization_failure(&authorization, error).await)
            }
        }
    }

    /// Take the authority commit fence for one decision, after bringing the
    /// pinned authority current with the host store.
    pub(crate) async fn current_fence(
        &self,
        authorization: &Arc<GatewayAuthorization>,
    ) -> AuthorityFence {
        let stale = self.bring_current(authorization).await.is_err();
        AuthorityFence {
            _guard: authorization.commit_fence().await,
            stale,
        }
    }

    /// Reload the chains the store records for the authorizer's source, and
    /// the consent Timeline head when its Principal binds consents, and
    /// recompose the pinned authority when the store is ahead of it.
    pub(crate) async fn bring_current(
        &self,
        authorization: &GatewayAuthorization,
    ) -> Result<(), GatewayAuthorizationError> {
        match self.source_record(authorization).await {
            Ok(Some(record)) if authorization.is_behind(&record) => {
                self.refresh_with_consent_events(authorization, record)
                    .await
            }
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Read the consent Timeline's Events into `record`, then recompose the
    /// pinned authority from it under the commit-fence write guard.
    async fn refresh_with_consent_events(
        &self,
        authorization: &GatewayAuthorization,
        record: GatewayAuthorityRecordV1,
    ) -> Result<(), GatewayAuthorizationError> {
        authorization
            .refresh(self.with_consent_events(authorization, Ok(record)).await)
            .await
    }

    /// The authority record the store holds under the source leaf of the
    /// authorizer; `None` for an authorizer without a store source.
    pub(crate) async fn source_record(
        &self,
        authorization: &GatewayAuthorization,
    ) -> Result<Option<GatewayAuthorityRecordV1>, GatewayAuthorizationError> {
        let Some(leaf) = authorization.source_leaf() else {
            return Ok(None);
        };
        self.authority_record(authorization, leaf).await.map(Some)
    }

    /// The authority record the store holds under the source leaf `leaf`
    /// of the authorizer, without the consent Timeline's Events.
    pub(crate) async fn authority_record(
        &self,
        authorization: &GatewayAuthorization,
        leaf: Hash,
    ) -> Result<GatewayAuthorityRecordV1, GatewayAuthorizationError> {
        let chain = self.store.load_authority(leaf).await;
        let consented = match authorization.consented_binding() {
            Some((leaves, timeline)) => Some(self.consent_record(&leaves, timeline).await),
            None => None,
        };
        match (chain, consented.transpose()) {
            (Ok(Ok(chain)), Ok(consented)) => Ok(GatewayAuthorityRecordV1 { chain, consented }),
            _ => Err(GatewayAuthorizationError::AuthorityUnavailable),
        }
    }

    /// The consent-bound chains under `leaves` and the head of the consent
    /// Timeline `timeline`.
    async fn consent_record(
        &self,
        leaves: &[Hash],
        timeline: TimelineId,
    ) -> Result<GatewayConsentRecordV1, GatewayAuthorizationError> {
        let mut chains = Vec::with_capacity(leaves.len());
        for leaf in leaves {
            chains.push(self.store.load_authority(*leaf).await);
        }
        let head = self.store.protected_logical_head(timeline).await;
        match (
            chains.into_iter().collect::<Result<Result<Vec<_>, _>, _>>(),
            head,
        ) {
            (Ok(Ok(chains)), Ok(head)) => Ok(GatewayConsentRecordV1 {
                chains,
                head,
                events: None,
            }),
            _ => Err(GatewayAuthorizationError::AuthorityUnavailable),
        }
    }

    /// `record` with the Events of the authorizer's consent Timeline, when
    /// its Principal binds consents. The consent Timeline is read whatever
    /// `record` is, so a failure of either read is one unavailable answer.
    pub(crate) async fn with_consent_events(
        &self,
        authorization: &GatewayAuthorization,
        record: Result<GatewayAuthorityRecordV1, GatewayAuthorizationError>,
    ) -> Result<GatewayAuthorityRecordV1, GatewayAuthorizationError> {
        let Some((_, timeline)) = authorization.consented_binding() else {
            return record;
        };
        let read = self
            .store
            .read(
                timeline,
                SeqRange::all(),
                crate::local_principal::consent_bounds(),
            )
            .await
            .map_err(|_| GatewayAuthorizationError::AuthorityUnavailable);
        record.and_then(|record| {
            read.map(|events| GatewayAuthorityRecordV1 {
                chain: record.chain,
                consented: record.consented.map(|consented| GatewayConsentRecordV1 {
                    events: Some(events),
                    ..consented
                }),
            })
        })
    }
}
