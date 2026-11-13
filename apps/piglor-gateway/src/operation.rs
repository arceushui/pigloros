//! The reusable operation-authorization seam of the Gateway (#1361).
//!
//! A protected route names its [`GatewayOperationV1`] through an
//! [`OperationSpecV1`] marker, extracts its [`OperationAuthority`] (the acting
//! entity of the `x-piglor-actor-entity` header, never a credential: owner
//! decision D1 on #302 makes loopback reachability the Local trust boundary),
//! and authorizes it against the host-pinned Principal before it mutates or
//! looks anything up. The returned [`GatewayOperationPermitV1`] holds the
//! authority commit fence until the route drops it, so a replacement of the
//! authority snapshot (a revocation) waits for the admitted operation and
//! takes effect before the next one.
//!
//! A denial is answered only after its evidence is recorded, exactly as the
//! action and read seams answer theirs. A Gateway without an authorizer whose
//! composition requires one (an unprovisioned host) answers every protected
//! operation `401 unauthenticated`.

use std::{convert::Infallible, future::Future, marker::PhantomData};

use axum::{extract::FromRequestParts, http::request::Parts};
use pos_core::{EntityId, TimelineId, WallTime};
use tokio::sync::OwnedRwLockReadGuard;

use crate::{
    Gateway, GatewayAuthorizationDecision, GatewayAuthorizationRequest, GatewayError,
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

/// The authority inputs of one protected operation, from the request head.
///
/// They are only the acting entity, when the request names a valid one.
/// Extraction never fails; a missing or malformed actor is decided by
/// [`Self::authorize`].
pub struct OperationAuthority<O> {
    actor_entity_id: Option<EntityId>,
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
            operation: PhantomData,
        })
    }
}

impl<O: OperationSpecV1> OperationAuthority<O> {
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
            .authorize_operation(O::OPERATION, self.actor_entity_id, target_timeline)
            .await
    }

    /// Authorize the operation, then run `operation` under the permit, so
    /// no authority replacement lands while it runs.
    ///
    /// # Errors
    /// Returns the failures of [`Self::authorize`], before `operation` is
    /// polled, or the error of `operation`.
    pub async fn run<T>(
        self,
        gateway: &Gateway,
        target_timeline: Option<TimelineId>,
        operation: impl Future<Output = Result<T, GatewayError>>,
    ) -> Result<T, GatewayError> {
        let permit = self.authorize(gateway, target_timeline).await?;
        let output = operation.await;
        drop(permit);
        output
    }
}

/// The authority of one admitted protected operation.
///
/// While it lives it holds the authority commit fence, so the host authority
/// snapshot cannot be replaced under the operation it admitted.
#[must_use = "dropping the permit releases the authority fence before the operation runs"]
pub struct GatewayOperationPermitV1 {
    decision: Option<GatewayAuthorizationDecision>,
    _fence: Option<OwnedRwLockReadGuard<()>>,
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
    /// host-pinned Principal, before any lookup or mutation.
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
    ) -> Result<GatewayOperationPermitV1, GatewayError> {
        if !self.has_authorization() {
            return Ok(GatewayOperationPermitV1 {
                decision: None,
                _fence: None,
            });
        }
        let (Some(authorization), Some(actor)) = (self.authorization.as_ref(), actor_entity_id)
        else {
            return Err(GatewayError::AuthorizationUnavailable);
        };
        let fence = authorization.commit_fence().await;
        match authorization.authorize(GatewayAuthorizationRequest::operation(
            actor,
            operation,
            target_timeline,
            WallTime::now(),
        )) {
            Ok(decision) => Ok(GatewayOperationPermitV1 {
                decision: Some(decision),
                _fence: Some(fence),
            }),
            Err(error) => {
                // The denial's evidence is written after the fence is
                // released, so an authority replacement never waits on it.
                drop(fence);
                Err(self.authorization_failure(authorization, error).await)
            }
        }
    }
}
