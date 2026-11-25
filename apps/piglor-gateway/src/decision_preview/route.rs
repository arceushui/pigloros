//! The served Decision Preview routes (ADR-140 sections 6, 7 and 9; #305).
//!
//! - `POST /v1/decision-previews` (`createDecisionPreview`, grant
//!   `decision-preview.create`): a malformed body, a malformed ULID, digest
//!   or profile ID and a `schema_version` other than 1 are `400` before the
//!   authority decision, like the missing or malformed `Idempotency-Key`,
//!   the oversized body and the other content type the extractors refuse.
//!   The decided request is admitted by [`Gateway::create_decision_preview`]
//!   on its own task, which owns the permit until the admission settles, so
//!   a cancelled request never releases the authority fence early. The
//!   answer is the `202` admission receipt, a function of the stored claim
//!   and the presented key alone, so an exact retry answers the same bytes.
//! - `GET /v1/decision-previews/{preview_id}` (`getDecisionPreview`, grant
//!   `decision-preview.read`): a malformed ID is `400` before the decision;
//!   the preview is read by [`Gateway::read_decision_preview`] and answered
//!   as the `DecisionPreview` resource.
//!
//! Every refusal is one problem of the contract. Every response carries
//! `Cache-Control: no-store` (see `http::finish`).

use std::time::Duration;

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use pos_core::{CoreError, EventId};
use pos_runtime::{
    ComputedRecommendationV1, PreviewRequestV1, PreviewRevisionRefV1, RecommendationV1,
    PREVIEW_REQUEST_SCHEMA_VERSION_V1, PREVIEW_RESULT_EVENT_TYPE_V1,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{
    decision_previews_timeline, DecisionPreviewErrorV1, DecisionPreviewModeV1,
    DecisionPreviewReceiptV1, DecisionPreviewResultEventV1, DecisionPreviewStateV1,
    DecisionPreviewV1,
};
use crate::{
    operation::{CreateDecisionPreviewOperation, OperationAuthority, ReadDecisionPreviewOperation},
    problem::{ProblemCodeV1, ProblemV1},
    revision::{canonical_ulid, revision_number},
    scenario_room::digest_bytes,
    Gateway, GatewayError, GatewayOperationPermitV1,
};

/// The `$id` of the 202 admission receipt.
const ADMISSION_RECEIPT_SCHEMA_ID: &str = "urn:pigloros:gateway:v1:schema:admission-receipt";
/// The `$id` of the `DecisionPreview` resource.
const DECISION_PREVIEW_SCHEMA_ID: &str = "urn:pigloros:gateway:v1:schema:decision-preview";
/// The `$id` of the committed Event receipt.
const COMMITTED_RECEIPT_SCHEMA_ID: &str = "urn:pigloros:gateway:v1:schema:committed-event-receipt";
/// The route of one preview, followed by its `preview_id`.
const PREVIEW_ROUTE_PREFIX: &str = "/v1/decision-previews/";
/// The longest `ExecutionProfileId`.
const MAX_PROFILE_ID_BYTES: usize = 64;
/// The namespace of the Gateway execution-mode profiles, which no
/// `ExecutionProfileId` uses.
const MODE_PROFILE_NAMESPACE: &str = "gateway-mode-";

/// The body of `createDecisionPreview`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequestBodyV1 {
    schema_version: u64,
    scenario_room: WireRevisionRefV1,
    preference: WireRevisionRefV1,
    option_spec: WireRevisionRefV1,
    profile_id: String,
}

/// One `RevisionRef` as the contract names it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRevisionRefV1 {
    id: String,
    revision: u64,
    digest: String,
}

impl WireRevisionRefV1 {
    /// The reference, when its ID is a canonical ULID, its revision is 1 to
    /// 2^53 - 1 and its digest is 64 lower-case hex digits.
    fn admit(self) -> Option<PreviewRevisionRefV1> {
        canonical_ulid(&self.id)
            .zip(revision_number(self.revision))
            .zip(digest_bytes(&self.digest))
            .map(|((id, revision), digest)| PreviewRevisionRefV1 {
                id,
                revision,
                digest,
            })
    }
}

impl CreateRequestBodyV1 {
    /// The request, when every reference is well formed.
    fn admit(self) -> Option<PreviewRequestV1> {
        let Self {
            scenario_room,
            preference,
            option_spec,
            profile_id,
            ..
        } = self;
        scenario_room
            .admit()
            .zip(preference.admit())
            .zip(option_spec.admit())
            .map(
                |((scenario_room, preference), option_spec)| PreviewRequestV1 {
                    scenario_room,
                    preference,
                    option_spec,
                    profile_id,
                },
            )
    }
}

/// Whether `text` is an `ExecutionProfileId`.
///
/// That is a versioned lower-case slug of at most 64 bytes,
/// `^[a-z][a-z0-9]*(-[a-z0-9]+)*-v[1-9][0-9]*$`, outside the `gateway-mode-`
/// namespace.
fn execution_profile_id(text: &str) -> bool {
    text.len() <= MAX_PROFILE_ID_BYTES
        && !text.starts_with(MODE_PROFILE_NAMESPACE)
        && text.rsplit_once("-v").is_some_and(|(slug, version)| {
            slug.starts_with(|first: char| first.is_ascii_lowercase())
                && slug.split('-').all(|segment| {
                    !segment.is_empty()
                        && segment
                            .bytes()
                            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                })
                && version.starts_with(|first: char| matches!(first, '1'..='9'))
                && version.bytes().all(|byte| byte.is_ascii_digit())
        })
}

/// The `400 invalid-request` of a request outside the contract.
fn invalid(detail: &'static str) -> ProblemV1 {
    ProblemV1::new(
        ProblemCodeV1::InvalidRequest,
        StatusCode::BAD_REQUEST,
        detail,
    )
}

/// The request of a `createDecisionPreview` body (ADR-140 section 6 step 2).
///
/// # Errors
/// `400 unsupported-version` for an integer `schema_version` other than 1,
/// and `400 invalid-request` for any other body outside the
/// `CreateDecisionPreviewRequest` schema.
fn parse_request(body: &Value) -> Result<PreviewRequestV1, ProblemV1> {
    if body
        .get("schema_version")
        .and_then(Value::as_u64)
        .is_some_and(|version| version != PREVIEW_REQUEST_SCHEMA_VERSION_V1)
    {
        return Err(ProblemV1::new(
            ProblemCodeV1::UnsupportedVersion,
            StatusCode::BAD_REQUEST,
            "unsupported schema_version",
        ));
    }
    CreateRequestBodyV1::deserialize(body)
        .ok()
        .filter(|request| {
            request.schema_version == PREVIEW_REQUEST_SCHEMA_VERSION_V1
                && execution_profile_id(&request.profile_id)
        })
        .and_then(CreateRequestBodyV1::admit)
        .ok_or_else(|| invalid("the body is not a Decision Preview request"))
}

/// `digest` in lower-case hex.
fn hex(digest: [u8; 32]) -> String {
    blake3::Hash::from_bytes(digest).to_hex().to_string()
}

/// The `202` admission receipt of `receipt` (ADR-140 P21): its request and
/// operation are the preview ID, and it binds the claim's three inputs, its
/// EPF1 digest and the GMP1 digest the claim committed under.
fn receipt_json(receipt: &DecisionPreviewReceiptV1) -> Value {
    let id = receipt.preview_id.to_string();
    let claim = &receipt.claim;
    json!({
        "schema_id": ADMISSION_RECEIPT_SCHEMA_ID,
        "request_id": id,
        "operation_id": id,
        "state": "admitted",
        "operation_url": format!("{PREVIEW_ROUTE_PREFIX}{id}"),
        "idempotency_key_digest": hex(receipt.idempotency_key_digest),
        "bound_inputs": {
            "scenario_room": hex(claim.request.scenario_room.digest),
            "preference": hex(claim.request.preference.digest),
            "option_spec": hex(claim.request.option_spec.digest),
            "execution_profile": hex(claim.profile_digest),
            "mode_profile": hex(claim.mode_profile_digest),
        },
    })
}

/// One `RevisionRef`.
fn revision_ref_json(reference: &PreviewRevisionRefV1) -> Value {
    json!({
        "id": reference.id.to_string(),
        "revision": reference.revision.get(),
        "digest": hex(reference.digest),
    })
}

/// The `computed` Recommendation of `computed`.
fn computed_json(computed: &ComputedRecommendationV1) -> Value {
    let scores = computed
        .scores
        .iter()
        .map(|score| {
            json!({
                "option_key": score.option_key,
                "match_score_micro": score.match_score_micro,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "status": "computed",
        "option_key": computed.option_key,
        "toss_up": computed.toss_up,
        "margin_micro": computed.margin_micro,
        "scores": scores,
    })
}

/// A recomputed Recommendation.
fn recommendation_json(recommendation: &RecommendationV1) -> Value {
    match recommendation {
        RecommendationV1::InsufficientEvidence => json!({"status": "insufficient-evidence"}),
        RecommendationV1::Computed(computed) => computed_json(computed),
    }
}

/// The receipt of a preview's `preview.result.v1` Event (ADR-140 P23). No
/// client reads the `decision-previews` Timeline, so it names no cursor.
fn result_json(result: DecisionPreviewResultEventV1) -> Value {
    json!({
        "schema_id": COMMITTED_RECEIPT_SCHEMA_ID,
        "timeline_id": decision_previews_timeline().to_string(),
        "event_id": result.event_id.to_string(),
        "seq": result.seq.as_u64(),
        "event_schema_id": PREVIEW_RESULT_EVENT_TYPE_V1,
        "next_cursor": null,
    })
}

/// The GMP1 binding the preview's claim committed under.
fn mode_profile_json(mode: &DecisionPreviewModeV1) -> Value {
    json!({
        "profile_kind": "gateway-mode-v1",
        "mode_profile_id": mode.profile.as_str(),
        "mode": mode.profile.mode(),
        "mode_profile_digest": hex(mode.digest),
        "binding_epoch": mode.binding_epoch.get(),
    })
}

/// The members of a `DecisionPreview` its lifecycle state decides (ADR-140
/// P17 and P25).
struct StateMembersV1 {
    state: &'static str,
    recommendation: Value,
    committed: Value,
    failure: Value,
    availability: Value,
}

impl StateMembersV1 {
    /// The members of `state`. Only a `degraded` preview withholds anything:
    /// its Recommendation, erased with an input.
    fn of(state: &DecisionPreviewStateV1) -> Self {
        let available = || json!({"state": "available", "withheld": []});
        let pending = || json!({"status": "pending"});
        match state {
            DecisionPreviewStateV1::Admitted => Self {
                state: "admitted",
                recommendation: pending(),
                committed: Value::Null,
                failure: Value::Null,
                availability: available(),
            },
            DecisionPreviewStateV1::Committed {
                result,
                recommendation,
            } => Self {
                state: "committed",
                recommendation: recommendation_json(recommendation),
                committed: result_json(*result),
                failure: Value::Null,
                availability: available(),
            },
            DecisionPreviewStateV1::Failed { code } => Self {
                state: "failed",
                recommendation: pending(),
                committed: Value::Null,
                failure: json!({"code": code.as_str()}),
                availability: available(),
            },
            DecisionPreviewStateV1::Degraded { result } => Self {
                state: "degraded",
                recommendation: json!({"status": "withheld"}),
                committed: result_json(*result),
                failure: Value::Null,
                availability: json!({
                    "state": "partial",
                    "withheld": [{"member": "/recommendation", "reason": "deleted"}],
                }),
            },
        }
    }
}

/// The `DecisionPreview` resource of `preview` (ADR-140 section 7).
fn preview_json(preview: &DecisionPreviewV1) -> Value {
    let claim = &preview.claim;
    let members = StateMembersV1::of(&preview.state);
    json!({
        "schema_id": DECISION_PREVIEW_SCHEMA_ID,
        "id": preview.preview_id.to_string(),
        "generation": preview.state.generation(),
        "provenance": {
            "digest": hex(preview.provenance_digest),
            "origin": "host-derived",
        },
        "mode_profile": mode_profile_json(&preview.mode_profile),
        "execution_profile": {
            "profile_kind": "epf1",
            "state": "installed",
            "profile_id": claim.request.profile_id,
            "profile_digest": hex(claim.profile_digest),
        },
        "availability": members.availability,
        "state": members.state,
        "inputs": {
            "scenario_room": revision_ref_json(&claim.request.scenario_room),
            "preference": revision_ref_json(&claim.request.preference),
            "option_spec": revision_ref_json(&claim.request.option_spec),
        },
        "factual_timeline_id": null,
        "recommendation": members.recommendation,
        "committed": members.committed,
        "failure": members.failure,
        "uncertainty": {"status": "unavailable"},
        "calibration": {"status": "unavailable", "reason": "no-resolved-predictions"},
        "proposals": "inert",
        "actuation": "none",
    })
}

/// The one answer to a preview or input the caller may not use.
fn not_found() -> Response {
    GatewayError::ResourceUnavailable.into_response()
}

/// The internal-failure arm (ADR-140 P29): nothing is described.
fn internal() -> Response {
    ProblemV1::internal(StatusCode::INTERNAL_SERVER_ERROR).into_response()
}

/// The `Retry-After` seconds of the time `left` in a quota window: rounded
/// up to whole seconds and at least 1, so a retry never comes early.
fn retry_after_seconds(left: Duration) -> u64 {
    left.as_secs()
        .saturating_add(u64::from(left.subsec_nanos() > 0))
        .max(1)
}

/// The retryable `429` of a Principal's used per-minute admissions, with
/// `Retry-After` until its window closes.
fn quota_exceeded(left: Duration) -> Response {
    let mut response = ProblemV1::new(
        ProblemCodeV1::ResourceLimitExceeded,
        StatusCode::TOO_MANY_REQUESTS,
        "the Principal used its Decision Preview admissions for this minute",
    )
    .retryable()
    .into_response();
    let value = HeaderValue::from(retry_after_seconds(left));
    response.headers_mut().insert(header::RETRY_AFTER, value);
    response
}

/// A store failure (ADR-140 P34): a host or store that cannot answer now is
/// the Gateway's retryable `503`, which also marks a stale binding; every
/// other store failure is the internal-failure arm.
fn store_failure(error: CoreError) -> Response {
    if matches!(
        error,
        CoreError::ErasureContainmentUnavailable | CoreError::ModeBindingStale
    ) {
        GatewayError::Store(error).into_response()
    } else {
        internal()
    }
}

/// The problem of one refused Decision Preview operation (ADR-140 section 9).
fn refusal(error: DecisionPreviewErrorV1) -> Response {
    use ProblemCodeV1 as Code;
    let (code, status, detail, retryable) = match error {
        DecisionPreviewErrorV1::Gateway(error) => return error.into_response(),
        DecisionPreviewErrorV1::NotFound => return not_found(),
        DecisionPreviewErrorV1::QuotaExceeded { retry_after } => {
            return quota_exceeded(retry_after)
        }
        // A revision load answers only `InvalidRecord`, `Unavailable` or
        // `ModeBindingStale`, so the conflict and parent-head arms of
        // `revision::store_failure` cannot occur here.
        DecisionPreviewErrorV1::Revisions(error) => return crate::revision::store_failure(error),
        DecisionPreviewErrorV1::Store(error) => return store_failure(error),
        DecisionPreviewErrorV1::Internal => return internal(),
        DecisionPreviewErrorV1::InFlightLimit => (
            Code::ResourceLimitExceeded,
            StatusCode::TOO_MANY_REQUESTS,
            "the Principal has four Decision Preview requests in flight",
            true,
        ),
        DecisionPreviewErrorV1::IdempotencyConflict => (
            Code::IdempotencyConflict,
            StatusCode::CONFLICT,
            "the Idempotency-Key was used for a different request",
            false,
        ),
        DecisionPreviewErrorV1::IncompatibleProfile => (
            Code::IncompatibleProfile,
            StatusCode::CONFLICT,
            "the profile is not servable in this mode or has no installed EPF1",
            false,
        ),
        DecisionPreviewErrorV1::StoreFull => (
            Code::ResourceLimitExceeded,
            StatusCode::TOO_MANY_REQUESTS,
            "the store holds its maximum number of Decision Previews; a retry cannot succeed",
            false,
        ),
        DecisionPreviewErrorV1::TopologyUnavailable => (
            Code::TemporarilyUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "this Gateway cannot open the Decision Preview store under an active erasure",
            false,
        ),
        DecisionPreviewErrorV1::ModeUnavailable => (
            Code::TemporarilyUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "the Decision Preview store is unavailable",
            true,
        ),
    };
    let problem = ProblemV1::new(code, status, detail);
    if retryable {
        problem.retryable().into_response()
    } else {
        problem.into_response()
    }
}

/// Admit `request` on its own task, which owns `permit` until the admission
/// settles.
async fn admit_holding(
    gateway: Gateway,
    permit: GatewayOperationPermitV1,
    idempotency_key: String,
    request: PreviewRequestV1,
) -> Result<DecisionPreviewReceiptV1, DecisionPreviewErrorV1> {
    tokio::spawn(async move {
        gateway
            .create_decision_preview(permit, &idempotency_key, request)
            .await
    })
    .await
    .unwrap_or(Err(DecisionPreviewErrorV1::Gateway(
        GatewayError::StoreExecutorUnhealthy,
    )))
}

/// `POST /v1/decision-previews`: admit one Decision Preview of the acting
/// entity under the permit of its `decision-preview.create` decision.
pub(crate) async fn create(
    gateway: &Gateway,
    authority: OperationAuthority<CreateDecisionPreviewOperation>,
    idempotency_key: String,
    body: &Value,
) -> Response {
    let request = match parse_request(body) {
        Ok(request) => request,
        Err(problem) => return problem.into_response(),
    };
    match authority.authorize(gateway, None).await {
        Ok(permit) => admit_holding(gateway.clone(), permit, idempotency_key, request)
            .await
            .map_or_else(refusal, |receipt| {
                (StatusCode::ACCEPTED, Json(receipt_json(&receipt))).into_response()
            }),
        Err(error) => error.into_response(),
    }
}

/// `GET /v1/decision-previews/{preview_id}`: one of the acting entity's own
/// Decision Previews under the permit of its `decision-preview.read`
/// decision.
pub(crate) async fn read(
    gateway: &Gateway,
    authority: OperationAuthority<ReadDecisionPreviewOperation>,
    preview_id: &str,
) -> Response {
    let Some(preview_id) = canonical_ulid(preview_id).map(EventId::from_ulid) else {
        return invalid("the path does not name a canonical preview ID").into_response();
    };
    match authority.authorize(gateway, None).await {
        Ok(permit) => gateway
            .read_decision_preview(permit, preview_id)
            .await
            .map_or_else(refusal, |preview| {
                (StatusCode::OK, Json(preview_json(&preview))).into_response()
            }),
        Err(error) => error.into_response(),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
