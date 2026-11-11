//! RFC 9457 problem details of the public Gateway v1 contract (#301, #1312).
//!
//! Every failure the Gateway answers is an `application/problem+json` body whose `code` is one
//! of the closed problem families of `contracts/gateway/v1/problem-types.json`. The `type` is a
//! stable URN derived from the code, `instance` is the matched route template, and `detail` never carries
//! a host fault description: an internal failure answers a fixed safe text.

use axum::{
    body::Body,
    extract::{
        rejection::{JsonRejection, PathRejection},
        FromRequest, FromRequestParts, MatchedPath, Path, Request,
    },
    http::{header, request::Parts, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::de::DeserializeOwned;
use serde_json::json;

/// The media type of every problem body.
pub const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";

/// The stable schema identifier of a problem body.
pub const PROBLEM_SCHEMA_ID: &str = "urn:pigloros:gateway:v1:schema:problem";

/// The prefix of every problem `type` URN; the code follows it.
pub const PROBLEM_TYPE_PREFIX: &str = "urn:pigloros:gateway:v1:problem:";

/// The fixed `detail` of an internal failure; host fault text never leaves the Gateway.
const INTERNAL_DETAIL: &str = "the Gateway could not complete the request";

/// The closed public failure families of the v1 contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProblemCodeV1 {
    InvalidRequest,
    UnsupportedVersion,
    IncompatibleProfile,
    Unauthenticated,
    Unauthorized,
    ConsentInvalid,
    Revoked,
    Deleted,
    NotFoundOrUnavailable,
    AdmissionRejected,
    ApprovalRejected,
    AppendConflict,
    IdempotencyConflict,
    ArtifactMissing,
    ArtifactUntrusted,
    ReplayClaimInsufficient,
    DependencyGraphIncomplete,
    MixedForkGeneration,
    CounterfactualIncomplete,
    ResourceLimitExceeded,
    TemporarilyUnavailable,
    InternalSafeFailure,
}

impl ProblemCodeV1 {
    /// Every code, in registry order.
    pub const ALL: [Self; 22] = [
        Self::InvalidRequest,
        Self::UnsupportedVersion,
        Self::IncompatibleProfile,
        Self::Unauthenticated,
        Self::Unauthorized,
        Self::ConsentInvalid,
        Self::Revoked,
        Self::Deleted,
        Self::NotFoundOrUnavailable,
        Self::AdmissionRejected,
        Self::ApprovalRejected,
        Self::AppendConflict,
        Self::IdempotencyConflict,
        Self::ArtifactMissing,
        Self::ArtifactUntrusted,
        Self::ReplayClaimInsufficient,
        Self::DependencyGraphIncomplete,
        Self::MixedForkGeneration,
        Self::CounterfactualIncomplete,
        Self::ResourceLimitExceeded,
        Self::TemporarilyUnavailable,
        Self::InternalSafeFailure,
    ];

    /// The stable wire code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid-request",
            Self::UnsupportedVersion => "unsupported-version",
            Self::IncompatibleProfile => "incompatible-profile",
            Self::Unauthenticated => "unauthenticated",
            Self::Unauthorized => "unauthorized",
            Self::ConsentInvalid => "consent-invalid",
            Self::Revoked => "revoked",
            Self::Deleted => "deleted",
            Self::NotFoundOrUnavailable => "not-found-or-unavailable",
            Self::AdmissionRejected => "admission-rejected",
            Self::ApprovalRejected => "approval-rejected",
            Self::AppendConflict => "append-conflict",
            Self::IdempotencyConflict => "idempotency-conflict",
            Self::ArtifactMissing => "artifact-missing",
            Self::ArtifactUntrusted => "artifact-untrusted",
            Self::ReplayClaimInsufficient => "replay-claim-insufficient",
            Self::DependencyGraphIncomplete => "dependency-graph-incomplete",
            Self::MixedForkGeneration => "mixed-fork-generation",
            Self::CounterfactualIncomplete => "counterfactual-incomplete",
            Self::ResourceLimitExceeded => "resource-limit-exceeded",
            Self::TemporarilyUnavailable => "temporarily-unavailable",
            Self::InternalSafeFailure => "internal-safe-failure",
        }
    }

    /// The fixed human-readable `title` of the family.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::InvalidRequest => "Invalid request",
            Self::UnsupportedVersion => "Unsupported version",
            Self::IncompatibleProfile => "Incompatible profile",
            Self::Unauthenticated => "Unauthenticated",
            Self::Unauthorized => "Unauthorized",
            Self::ConsentInvalid => "Consent invalid",
            Self::Revoked => "Revoked",
            Self::Deleted => "Deleted",
            Self::NotFoundOrUnavailable => "Not found or unavailable",
            Self::AdmissionRejected => "Admission rejected",
            Self::ApprovalRejected => "Approval rejected",
            Self::AppendConflict => "Append conflict",
            Self::IdempotencyConflict => "Idempotency conflict",
            Self::ArtifactMissing => "Artifact missing",
            Self::ArtifactUntrusted => "Artifact untrusted",
            Self::ReplayClaimInsufficient => "Replay claim insufficient",
            Self::DependencyGraphIncomplete => "Dependency graph incomplete",
            Self::MixedForkGeneration => "Mixed Fork generation",
            Self::CounterfactualIncomplete => "Counterfactual incomplete",
            Self::ResourceLimitExceeded => "Resource limit exceeded",
            Self::TemporarilyUnavailable => "Temporarily unavailable",
            Self::InternalSafeFailure => "Internal safe failure",
        }
    }
}

/// One problem answer: its family, HTTP status, safe detail and retry hint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProblemV1 {
    code: ProblemCodeV1,
    status: StatusCode,
    detail: String,
    retryable: bool,
}

impl ProblemV1 {
    /// A problem of `code` with a safe `detail`.
    #[must_use]
    pub fn new(code: ProblemCodeV1, status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            status,
            detail: detail.into(),
            retryable: false,
        }
    }

    /// An internal failure; its detail is the fixed safe text.
    #[must_use]
    pub fn internal(status: StatusCode) -> Self {
        Self::new(ProblemCodeV1::InternalSafeFailure, status, INTERNAL_DETAIL)
    }

    /// Mark the problem as one an identical retry may resolve.
    #[must_use]
    pub const fn retryable(mut self) -> Self {
        self.retryable = true;
        self
    }

    /// The family of the problem.
    #[must_use]
    pub const fn code(&self) -> ProblemCodeV1 {
        self.code
    }

    /// The HTTP status of the problem.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// The problem body for the request at `instance`.
    #[must_use]
    pub fn body(&self, instance: &str) -> serde_json::Value {
        json!({
            "type": format!("{PROBLEM_TYPE_PREFIX}{}", self.code.as_str()),
            "title": self.code.title(),
            "status": self.status.as_u16(),
            "detail": self.detail,
            "instance": instance,
            "code": self.code.as_str(),
            "schema_id": PROBLEM_SCHEMA_ID,
            "retryable": self.retryable,
        })
    }

    /// A problem for an extractor rejection: a body over the limit is a resource limit, every
    /// other rejection an invalid request.
    fn rejected(status: StatusCode, detail: String) -> Self {
        let code = if status == StatusCode::PAYLOAD_TOO_LARGE {
            ProblemCodeV1::ResourceLimitExceeded
        } else {
            ProblemCodeV1::InvalidRequest
        };
        Self::new(code, status, detail)
    }
}

/// A handler answer carries the problem as an extension; the `problem_instance` layer renders
/// it with its `instance`. Every Gateway router installs that layer.
impl IntoResponse for ProblemV1 {
    fn into_response(self) -> Response {
        let mut response = self.status.into_response();
        response.extensions_mut().insert(self);
        response
    }
}

/// Render the problem a handler or extractor answered with. `instance` is the matched route
/// template (such as `/v1/timelines/{timeline_id}/events`), so a problem body never echoes a
/// run-local identifier; a request no route matched uses its path. A response without a problem
/// passes through unchanged.
pub(crate) async fn problem_instance(request: Request, next: Next) -> Response {
    let instance = request.extensions().get::<MatchedPath>().map_or_else(
        || request.uri().path().to_owned(),
        |matched| matched.as_str().to_owned(),
    );
    let (mut parts, body) = next.run(request).await.into_parts();
    let Some(problem) = parts.extensions.remove::<ProblemV1>() else {
        return Response::from_parts(parts, body);
    };
    parts.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(PROBLEM_MEDIA_TYPE),
    );
    Response::from_parts(parts, Body::from(problem.body(&instance).to_string()))
}

/// The answer to a path no route serves; it does not reveal whether a resource exists.
pub(crate) async fn not_routed() -> ProblemV1 {
    ProblemV1::new(
        ProblemCodeV1::NotFoundOrUnavailable,
        StatusCode::NOT_FOUND,
        "resource not found",
    )
}

/// The answer to a served path called with a method it does not serve.
pub(crate) async fn method_not_allowed() -> ProblemV1 {
    ProblemV1::new(
        ProblemCodeV1::InvalidRequest,
        StatusCode::METHOD_NOT_ALLOWED,
        "method not allowed",
    )
}

/// A JSON request body whose rejection is a problem rather than axum's plain-text answer.
pub(crate) struct ContractJson<T>(pub(crate) T);

impl<T, S> FromRequest<S> for ContractJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ProblemV1;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|rejection: JsonRejection| {
                ProblemV1::rejected(rejection.status(), rejection.body_text())
            })
    }
}

/// A path parameter whose rejection is a problem rather than axum's plain-text answer.
pub(crate) struct ContractPath<T>(pub(crate) T);

impl<T, S> FromRequestParts<S> for ContractPath<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = ProblemV1;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(value)| Self(value))
            .map_err(|rejection: PathRejection| {
                ProblemV1::rejected(rejection.status(), rejection.body_text())
            })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    const REGISTRY: &str = include_str!("../../../contracts/gateway/v1/problem-types.json");

    fn registry() -> Vec<serde_json::Value> {
        let value: serde_json::Value = serde_json::from_str(REGISTRY).unwrap_or_default();
        value["problem_types"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    #[test]
    fn every_code_is_registered_in_order_with_its_type_and_title() {
        let entries = registry();
        assert_eq!(entries.len(), ProblemCodeV1::ALL.len());
        for (code, entry) in ProblemCodeV1::ALL.iter().zip(&entries) {
            assert_eq!(entry["code"], code.as_str());
            assert_eq!(entry["title"], code.title());
            assert_eq!(
                entry["type"],
                format!("{PROBLEM_TYPE_PREFIX}{}", code.as_str())
            );
        }
    }

    #[test]
    fn a_problem_body_carries_every_member_and_an_internal_detail_is_fixed() {
        let problem = ProblemV1::internal(StatusCode::INTERNAL_SERVER_ERROR).retryable();
        assert_eq!(problem.code(), ProblemCodeV1::InternalSafeFailure);
        assert_eq!(problem.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = problem.body("/v1/timelines");
        assert_eq!(
            body["type"],
            "urn:pigloros:gateway:v1:problem:internal-safe-failure"
        );
        assert_eq!(body["title"], "Internal safe failure");
        assert_eq!(body["status"], 500);
        assert_eq!(body["detail"], INTERNAL_DETAIL);
        assert_eq!(body["instance"], "/v1/timelines");
        assert_eq!(body["code"], "internal-safe-failure");
        assert_eq!(body["schema_id"], PROBLEM_SCHEMA_ID);
        assert_eq!(body["retryable"], true);
    }

    #[test]
    fn a_rejected_body_over_the_limit_is_a_resource_limit() {
        let limit = ProblemV1::rejected(StatusCode::PAYLOAD_TOO_LARGE, "too large".to_owned());
        assert_eq!(limit.code(), ProblemCodeV1::ResourceLimitExceeded);
        let other = ProblemV1::rejected(StatusCode::BAD_REQUEST, "bad".to_owned());
        assert_eq!(other.code(), ProblemCodeV1::InvalidRequest);
    }
}
