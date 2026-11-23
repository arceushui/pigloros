//! The served erasure operations (ADR-136 §3 and §7; #1449).
//!
//! - `POST /v1/me/erasures` (`requestErasure`, grant `erasure.request`):
//!   the acting subject requests the erasure of its own data in one scope
//!   class. A malformed body and a missing `Idempotency-Key` are `400`
//!   before the authority decision. After the decision a retained-only
//!   scope is `400 erasure-scope-retained` before anything is submitted
//!   (owner decision D4 of 2026-11-18 on #1413). The Local erasure host
//!   then admits the request through `submit_local_erasure`, and the
//!   answer is a `202` admission receipt; an exact retry, also after the
//!   bundle or the execution-mode binding changed, answers the same bytes
//!   from the request's ELADM1 (D5). After every `202` the driver is woken.
//! - `GET /v1/me/erasures/{erasure_id}` (`getErasure`, grant
//!   `erasure.read`): the projection of one of the subject's own erasures.
//!   An unknown id, another subject's id and a refused decision are the
//!   same `404 not-found-or-unavailable`.
//!
//! Both operations are consent-exempt. A Gateway without a Local erasure
//! composition answers `requestErasure` `503` and `getErasure` `404` (D9).
//! The `idempotency_key_digest` is BLAKE3 of the key bytes (D6), and the
//! projection's `provenance.digest` is the raw ERS1 state digest (D13).
//! Nothing a response carries names a Timeline, Fork, selector, target,
//! owner or bundle content.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use pos_core::{
    ArtifactDataClassV1, ErasureLifecycleV1, ErasureReferenceV1, ErasureReplayClaimV1,
    ErasureScopeV1,
};
use pos_runtime::{LocalErasureAdmittedV1, LocalErasureProjectionV1, LocalErasureSubmitErrorV1};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    executor::{erasure::LocalErasureRequestV1, StoreExecutorError},
    operation::{OperationAuthority, ReadErasureOperation, RequestErasureOperation},
    problem::{ProblemCodeV1, ProblemV1},
    Gateway, GatewayError, GatewayOperationPermitV1,
};

/// The `$id` of the 202 admission receipt.
const ADMISSION_RECEIPT_SCHEMA_ID: &str = "urn:pigloros:gateway:v1:schema:admission-receipt";
/// The `$id` of the erasure projection.
const ERASURE_SCHEMA_ID: &str = "urn:pigloros:gateway:v1:schema:erasure";
/// The route of one erasure, followed by its `erasure_id`.
const ERASURE_ROUTE_PREFIX: &str = "/v1/me/erasures/";

/// The body of `requestErasure`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErasureRequestBodyV1 {
    scope: ErasureScopeWireV1,
    impact_acknowledged: bool,
}

/// One scope class as the contract names it.
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ErasureScopeWireV1 {
    PrivateSubjectData,
    ConsentedSharedData,
    PublicRecord,
    Aggregate,
    StructuralAuditMetadata,
}

impl ErasureScopeWireV1 {
    /// The destruction-eligible scope class, `None` for a class Local V1
    /// always retains.
    const fn destructible(self) -> Option<ErasureScopeV1> {
        match self {
            Self::PrivateSubjectData => Some(ErasureScopeV1::PrivateSubjectData),
            Self::ConsentedSharedData => Some(ErasureScopeV1::ConsentedSharedData),
            Self::PublicRecord | Self::Aggregate | Self::StructuralAuditMetadata => None,
        }
    }
}

/// The wire name of a destruction-eligible scope class. A request of any
/// other class is refused before it exists, so no projection names one.
const fn scope_name(scope: ErasureScopeV1) -> &'static str {
    match scope {
        ErasureScopeV1::ConsentedSharedData => "consented-shared-data",
        _ => "private-subject-data",
    }
}

/// The wire name of an ADR-060 lifecycle.
const fn lifecycle_name(lifecycle: ErasureLifecycleV1) -> &'static str {
    match lifecycle {
        ErasureLifecycleV1::Submitted => "submitted",
        ErasureLifecycleV1::Authorized => "authorized",
        ErasureLifecycleV1::AccessFrozen => "access-frozen",
        ErasureLifecycleV1::DestructionDispatched => "destruction-dispatched",
        ErasureLifecycleV1::AwaitingAcknowledgements => "awaiting-acknowledgements",
        ErasureLifecycleV1::Complete => "complete",
        ErasureLifecycleV1::PartialFailure => "partial-failure",
        ErasureLifecycleV1::Rejected => "rejected",
    }
}

/// The wire name of an ADR-060 `ReplayClaim`.
const fn replay_claim_name(claim: ErasureReplayClaimV1) -> &'static str {
    match claim {
        ErasureReplayClaimV1::Exact => "exact",
        ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews => {
            "exact-authoritative-with-redacted-views"
        }
        ErasureReplayClaimV1::StructuralOnly => "structural-only",
        ErasureReplayClaimV1::UnverifiableArtifactsMissing => "unverifiable-artifacts-missing",
        ErasureReplayClaimV1::IncompatibleProfile => "incompatible-profile",
    }
}

/// The wire name of a class the compiled ELP1 retains.
const fn retained_class_name(class: ArtifactDataClassV1) -> &'static str {
    match class {
        ArtifactDataClassV1::PublicRecord => "public-record",
        ArtifactDataClassV1::AggregateData => "aggregate",
        _ => "structural-audit-metadata",
    }
}

/// Lower-case hex of one digest.
fn hex(digest: ErasureReferenceV1) -> String {
    blake3::Hash::from_bytes(digest.digest())
        .to_hex()
        .to_string()
}

/// The 202 admission receipt of `admitted` under `key_digest` (ADR-136 §7):
/// its request and operation are the `erasure_id`, and it binds the pinned
/// policy and the ELADM1's bundle and mode profile. It is a function of the
/// retained records alone, so an exact retry answers the same bytes.
fn receipt(admitted: &LocalErasureAdmittedV1, key_digest: ErasureReferenceV1) -> Value {
    let id = admitted.erasure_id.to_string();
    json!({
        "schema_id": ADMISSION_RECEIPT_SCHEMA_ID,
        "request_id": id,
        "operation_id": id,
        "state": "admitted",
        "operation_url": format!("{ERASURE_ROUTE_PREFIX}{id}"),
        "idempotency_key_digest": hex(key_digest),
        "bound_inputs": {
            "policy": hex(admitted.policy),
            "trust": hex(admitted.admission.trust),
            "mode_profile": hex(admitted.admission.mode_profile),
        },
    })
}

/// The `Erasure` resource of `projection`, or `None` when its ELADM1 names
/// an execution mode this Gateway does not compile.
fn erasure_resource(projection: &LocalErasureProjectionV1) -> Option<Value> {
    crate::mode_profile::produced_under_digest_v1(
        projection.admission.mode_profile.digest(),
        projection.admission.binding_epoch,
    )
    .map(|mode| {
        let classes = projection
            .classes
            .iter()
            .map(|count| {
                json!({
                    "class": count.class,
                    "required": count.required,
                    "positive": count.positive,
                })
            })
            .collect::<Vec<_>>();
        json!({
            "schema_id": ERASURE_SCHEMA_ID,
            "id": projection.erasure_id.to_string(),
            "generation": projection.generation,
            "provenance": {
                "digest": hex(projection.state.state_digest()),
                "origin": "host-derived",
            },
            "mode_profile": mode.disclosure(),
            "execution_profile": {
                "profile_kind": "epf1",
                "state": "unavailable",
                "reason": "not-installed",
            },
            "availability": {"state": "available", "withheld": []},
            "state": lifecycle_name(projection.state.lifecycle()),
            "scope": scope_name(projection.scope),
            "replay_claim": replay_claim_name(projection.state.replay_claim()),
            "retained_classes": pos_runtime::compiled_local_erasure_policy_v1()
                .retained_classes
                .into_iter()
                .map(retained_class_name)
                .collect::<Vec<_>>(),
            "acknowledgements": {
                "required": projection.required,
                "positive": projection.positive,
                "classes": classes,
            },
            "external_copies": "not-covered",
        })
    })
}

/// The answer to a refused submission.
fn submit_refusal(error: LocalErasureSubmitErrorV1) -> ProblemV1 {
    match error {
        LocalErasureSubmitErrorV1::Concurrent => ProblemV1::new(
            ProblemCodeV1::ResourceLimitExceeded,
            StatusCode::TOO_MANY_REQUESTS,
            "another erasure of the subject is in progress",
        )
        .retryable(),
        LocalErasureSubmitErrorV1::QuotaExhausted => ProblemV1::new(
            ProblemCodeV1::ErasureQuotaExhausted,
            StatusCode::CONFLICT,
            "the subject has used its erasure request quota",
        ),
        LocalErasureSubmitErrorV1::ScopeTooLarge => ProblemV1::new(
            ProblemCodeV1::ErasureScopeTooLarge,
            StatusCode::BAD_REQUEST,
            "the erasure scope exceeds the Local erasure limit",
        ),
        // The operator closed admissions (#1408): only reopening clears it,
        // so a retry alone never succeeds.
        LocalErasureSubmitErrorV1::OperatorClosed => ProblemV1::new(
            ProblemCodeV1::ErasureAdmissionsClosed,
            StatusCode::SERVICE_UNAVAILABLE,
            "the operator closed erasure admissions on this host",
        ),
        LocalErasureSubmitErrorV1::AdmissionsClosed | LocalErasureSubmitErrorV1::Unserved => {
            ProblemV1::new(
                ProblemCodeV1::TemporarilyUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "erasure admissions are closed on this host",
            )
        }
        LocalErasureSubmitErrorV1::Host(pos_core::ErasureHostErrorV1::Conflict) => ProblemV1::new(
            ProblemCodeV1::IdempotencyConflict,
            StatusCode::CONFLICT,
            "the Idempotency-Key named another erasure request",
        ),
        // Every other host failure, an authority denial included: the
        // Gateway's own decision already admitted the operation on the same
        // root grant, so a host that still denies it disagrees with the
        // authority state the decision pinned and cannot vouch for it. That
        // is a retryable 503, never a 403, which needs a recorded denial.
        LocalErasureSubmitErrorV1::Host(_) => ProblemV1::new(
            ProblemCodeV1::TemporarilyUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "the erasure host is unavailable",
        )
        .retryable(),
    }
}

/// The `400 invalid-request` of a body outside the `ErasureRequest`
/// schema, which requires `impact_acknowledged: true`.
fn invalid_body() -> ProblemV1 {
    ProblemV1::new(
        ProblemCodeV1::InvalidRequest,
        StatusCode::BAD_REQUEST,
        "the body is not an erasure request that acknowledges its impact",
    )
}

/// The 400 of a retained-only scope (D4).
fn scope_retained() -> ProblemV1 {
    ProblemV1::new(
        ProblemCodeV1::ErasureScopeRetained,
        StatusCode::BAD_REQUEST,
        "Local erasure always retains this scope class",
    )
}

/// The one answer to an id the subject may not observe.
fn not_found() -> Response {
    GatewayError::ResourceUnavailable.into_response()
}

/// The answer to a store command that did not run.
fn not_run(error: StoreExecutorError) -> Response {
    GatewayError::from(error).into_response()
}

/// The decided Principal and actor of `permit`; `None` on a Gateway that
/// protects nothing, which therefore serves no erasure.
fn subject_of(
    permit: &GatewayOperationPermitV1,
) -> Option<(pos_core::PrincipalRefV1, pos_core::EntityId)> {
    permit
        .decision()
        .map(|decision| (decision.principal().clone(), decision.actor_entity_id()))
}

/// `POST /v1/me/erasures`: admit one erasure request of the acting
/// subject under the permit of its `erasure.request` decision.
pub(crate) async fn request(
    gateway: &Gateway,
    authority: OperationAuthority<RequestErasureOperation>,
    key: &str,
    body: Value,
) -> Response {
    let Some(body) = serde_json::from_value::<ErasureRequestBodyV1>(body)
        .ok()
        .filter(|body| body.impact_acknowledged)
    else {
        return invalid_body().into_response();
    };
    let permit = match authority.authorize(gateway, None).await {
        Ok(permit) => permit,
        Err(error) => return error.into_response(),
    };
    let Some((principal, actor)) = subject_of(&permit) else {
        return GatewayError::AuthorizationUnavailable.into_response();
    };
    let Some(scope) = body.scope.destructible() else {
        return scope_retained().into_response();
    };
    let idempotency_key_digest =
        ErasureReferenceV1::from_digest(*blake3::hash(key.as_bytes()).as_bytes());
    let request = LocalErasureRequestV1 {
        principal,
        actor,
        scope,
        idempotency_key_digest,
    };
    match submit_holding(gateway.clone(), permit, request).await {
        Ok(Ok(admitted)) => {
            gateway.wake_local_erasure();
            (
                StatusCode::ACCEPTED,
                Json(receipt(&admitted, idempotency_key_digest)),
            )
                .into_response()
        }
        Ok(Err(refusal)) => submit_refusal(refusal).into_response(),
        Err(error) => not_run(error),
    }
}

/// Submit `request` on its own task, which owns `permit` until the
/// submission settles, so a cancelled request never releases the authority
/// fence early.
async fn submit_holding(
    gateway: Gateway,
    permit: GatewayOperationPermitV1,
    request: LocalErasureRequestV1,
) -> Result<Result<LocalErasureAdmittedV1, LocalErasureSubmitErrorV1>, StoreExecutorError> {
    tokio::spawn(async move {
        let submitted = gateway.store.submit_local_erasure(request).await;
        drop(permit);
        submitted
    })
    .await
    .unwrap_or(Err(StoreExecutorError::Unhealthy))
}

/// `GET /v1/me/erasures/{erasure_id}`: the acting subject's own erasure
/// under the permit of its `erasure.read` decision. A refused decision is
/// recorded like any denial but answered as the same `404` as an unknown
/// id, so a caller without the grant learns nothing (ADR-136 acceptance
/// test 9).
pub(crate) async fn read(
    gateway: &Gateway,
    authority: OperationAuthority<ReadErasureOperation>,
    erasure_id: &str,
) -> Response {
    let Some(erasure_id) = crate::revision::canonical_ulid(erasure_id) else {
        return ProblemV1::new(
            ProblemCodeV1::InvalidRequest,
            StatusCode::BAD_REQUEST,
            "the path does not name a canonical erasure ID",
        )
        .into_response();
    };
    let permit = match authority.authorize(gateway, None).await {
        Ok(permit) => permit,
        Err(error) => return hide_refusal(error),
    };
    let Some((principal, actor)) = subject_of(&permit) else {
        return GatewayError::AuthorizationUnavailable.into_response();
    };
    let projected = gateway
        .store
        .local_erasure_projection(principal, actor, erasure_id)
        .await;
    drop(permit);
    match projected {
        Ok(Ok(Some(projection))) => erasure_resource(&projection).map_or_else(
            || ProblemV1::internal(StatusCode::INTERNAL_SERVER_ERROR).into_response(),
            |body| (StatusCode::OK, Json(body)).into_response(),
        ),
        Ok(Ok(None)) => not_found(),
        Ok(Err(_)) => ProblemV1::new(
            ProblemCodeV1::TemporarilyUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "the erasure host is unavailable",
        )
        .retryable()
        .into_response(),
        Err(error) => not_run(error),
    }
}

impl Gateway {
    /// Hand this Gateway the admission hook of its Local erasure driver;
    /// the first hook stays, as one Gateway runs one driver.
    pub(crate) fn bind_local_erasure_trigger(
        &self,
        trigger: crate::local_erasure_composition::LocalErasureTriggerV1,
    ) {
        drop(self.local_erasure_wake.set(trigger));
    }

    /// Wake the Local erasure driver after an admission, when one runs, so
    /// the request advances before the driver's next tick (D7).
    fn wake_local_erasure(&self) {
        if let Some(trigger) = self.local_erasure_wake.get() {
            trigger.admitted();
        }
    }
}

/// A refused decision answered as the `404` of an unknown id: its `403`,
/// and the `429` of a denial over the denial-record bound, which only a
/// refused caller can reach (its suppressed denial is still counted in the
/// window's durable marker). Every other failure, which a granted caller
/// meets alike, keeps its answer.
fn hide_refusal(error: GatewayError) -> Response {
    let suppressed = matches!(error, GatewayError::DenialRecordLimitReached { .. });
    let response = error.into_response();
    if suppressed || response.status() == StatusCode::FORBIDDEN {
        not_found()
    } else {
        response
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
