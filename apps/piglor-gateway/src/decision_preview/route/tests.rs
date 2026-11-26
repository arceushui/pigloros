//! The served Decision Preview routes (ADR-140 C3 test plan): the problem of
//! every refusal, the request grammar, and both routes on the production
//! composition with the release and the seam installed-profile ports.

use axum::{
    body::Body,
    http::{request::Builder, Request},
    Router,
};
use piglor_ledger::LedgerView;
use pos_core::{EntityId, GatewayRevisionErrorV1, GatewayRevisionKindV1};
use pos_runtime::{
    match_score_v1, ErasureCoordinatorCompositionV1, PreferenceWeightV1, PreviewOptionV1,
};
use pos_store::StoreConfig;
use tower::ServiceExt;

use super::*;
use crate::{
    decision_preview::{
        tests::{on_host, previews_events, seam, seed, served, store_path, Served, OTHER_ACTOR},
        InFlightSlotV1, MAX_IN_FLIGHT_PER_PRINCIPAL,
    },
    executor::decision_preview::{
        tests::{erase, interrupted, seeded, ACTOR, PRINCIPAL},
        MAX_ADMISSIONS_PER_MINUTE,
    },
    local_principal::local_gateway,
    mode_profile::{test_attach_host, test_binding, GatewayModeProfileIdV1},
    operation::ACTOR_ENTITY_HEADER,
    router,
    startup::{open_recovered_erasure_host, GatewayHostStoreV1},
    AppState, LedgerWriteMode,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The create route.
const PREVIEWS: &str = "/v1/decision-previews";
/// The golden GMP1 digest of the Local mode profile.
const LOCAL_DIGEST: &str = "26d6c7e75b11df673a1ef2d3210733b4ca431648eab0b9ae93bf4a6f6e69da3f";

/// The problem body and `Retry-After` of a handler's answer, before the
/// router renders it.
fn problem_of(response: &Response) -> TestResult<(Value, Option<String>)> {
    let problem = response
        .extensions()
        .get::<ProblemV1>()
        .ok_or("the answer is a problem")?;
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .map(|value| value.to_str().map(str::to_owned))
        .transpose()?;
    Ok((problem.body(PREVIEWS), retry_after))
}

/// ADR-140 section 9 and the C2 hand-offs: each refusal is its contract
/// problem. A quota refusal states `Retry-After` in whole seconds, rounded
/// up; a store or host that cannot answer now is the retryable `503` (a
/// stale binding also stops the serve loop); every other store failure is
/// the internal-failure arm.
#[test]
fn every_refusal_answers_its_problem() -> TestResult {
    use DecisionPreviewErrorV1 as Error;
    const LIMIT: &str = "resource-limit-exceeded";
    const UNAVAILABLE: &str = "temporarily-unavailable";
    const INTERNAL: &str = "internal-safe-failure";
    const NOT_FOUND: &str = "not-found-or-unavailable";
    const CONFLICT: &str = "idempotency-conflict";
    const PROFILE: &str = "incompatible-profile";
    let unauthenticated = Error::Gateway(GatewayError::AuthorizationUnavailable);
    let denied = Error::Gateway(GatewayError::DenialRecordLimitReached {
        retry_after_seconds: 7,
    });
    let quota = Error::QuotaExceeded {
        retry_after: Duration::from_millis(36_200),
    };
    let revisions_unavailable = Error::Revisions(GatewayRevisionErrorV1::Unavailable);
    let invalid_record = Error::Revisions(GatewayRevisionErrorV1::InvalidRecord);
    let contained = Error::Store(CoreError::ErasureContainmentUnavailable);
    let stale = Error::Store(CoreError::ModeBindingStale);
    let frozen = Error::Store(CoreError::ErasureAccessFrozen);
    let cases: [(Error, u16, &str, bool, Option<&str>); 16] = [
        (unauthenticated, 401, "unauthenticated", false, None),
        (denied, 429, LIMIT, true, Some("7")),
        (Error::InFlightLimit, 429, LIMIT, true, None),
        (Error::NotFound, 404, NOT_FOUND, false, None),
        (Error::IdempotencyConflict, 409, CONFLICT, false, None),
        (Error::IncompatibleProfile, 409, PROFILE, false, None),
        (quota, 429, LIMIT, true, Some("37")),
        (Error::StoreFull, 429, LIMIT, false, None),
        (Error::TopologyUnavailable, 503, UNAVAILABLE, false, None),
        (Error::ModeUnavailable, 503, UNAVAILABLE, true, None),
        (revisions_unavailable, 503, UNAVAILABLE, true, None),
        (invalid_record, 500, INTERNAL, false, None),
        (Error::Internal, 500, INTERNAL, false, None),
        (contained, 503, UNAVAILABLE, true, None),
        (stale, 503, UNAVAILABLE, true, None),
        (frozen, 500, INTERNAL, false, None),
    ];
    for (error, status, code, retryable, retry_after) in cases {
        let case = format!("{error:?}");
        let marked = matches!(error, Error::Store(CoreError::ModeBindingStale));
        let response = preview_problem(error);
        assert_eq!(response.status().as_u16(), status, "{case}");
        let (body, header) = problem_of(&response)?;
        assert_eq!(body["code"], code, "{case}");
        assert_eq!(body["retryable"], retryable, "{case}");
        assert_eq!(header.as_deref(), retry_after, "{case}");
        assert_eq!(
            response
                .extensions()
                .get::<crate::mode_profile::ModeBindingStaleResponseV1>()
                .is_some(),
            marked,
            "{case}"
        );
    }
    Ok(())
}

/// The served limits the contract states are the Gateway's own constants:
/// the store ceiling is half the Event ceiling (two Events per preview), and
/// the per-minute and in-flight quotas are the ones the Gateway enforces.
#[test]
fn the_contract_limits_are_the_gateway_constants() -> TestResult {
    let path = format!(
        "{}/../../contracts/gateway/v1/openapi.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let contract: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let limit = |name: &str| contract["x-pigloros-limits"][name]["value"].clone();
    let per_store = crate::MAX_EVENTS_PER_TIMELINE / 2;
    assert_eq!(limit("decision_previews_per_store"), per_store);
    assert_eq!(
        limit("principal_admissions_per_minute"),
        MAX_ADMISSIONS_PER_MINUTE
    );
    assert_eq!(
        limit("principal_concurrent_operations"),
        MAX_IN_FLIGHT_PER_PRINCIPAL
    );
    Ok(())
}

/// A quota window's time left is rounded up to whole seconds, never below 1,
/// so a retry never comes early.
#[test]
fn retry_after_rounds_up_to_whole_seconds_of_at_least_one() {
    for (left, seconds) in [
        (Duration::ZERO, 1),
        (Duration::from_nanos(1), 1),
        (Duration::from_secs(1), 1),
        (Duration::from_millis(1_001), 2),
        (Duration::from_mins(1), 60),
    ] {
        assert_eq!(quota_retry_after_seconds(left), seconds, "{left:?}");
    }
}

/// `ExecutionProfileId` is a versioned lower-case slug of at most 64 bytes
/// outside the `gateway-mode-` namespace.
#[test]
fn execution_profile_ids_follow_the_contract_pattern() {
    let longest = format!("{}-v1", "a".repeat(61));
    let longer = format!("{}-v1", "a".repeat(62));
    for id in [
        "replay-v1",
        "deterministic-local-v1",
        "live-air-gapped-v1",
        "a1-b2-v30",
        "x-v1-v2",
        longest.as_str(),
    ] {
        assert!(is_execution_profile_id(id), "{id}");
    }
    for id in [
        longer.as_str(),
        "gateway-mode-local-v1",
        "replay",
        "Replay-v1",
        "1replay-v1",
        "-v1",
        "replay--x-v1",
        "re_play-v1",
        "replay-v",
        "replay-v0",
        "replay-v1x",
    ] {
        assert!(!is_execution_profile_id(id), "{id}");
    }
}

/// The weights of a Preference.
fn weights(entries: &[(&str, i64)]) -> Vec<PreferenceWeightV1> {
    entries
        .iter()
        .map(|(dimension, weight_micro)| PreferenceWeightV1 {
            dimension: (*dimension).to_owned(),
            weight_micro: *weight_micro,
        })
        .collect()
}

/// The options of an `OptionSpec`.
fn options(entries: &[(&str, &[&str])]) -> Vec<PreviewOptionV1> {
    entries
        .iter()
        .map(|(key, tags)| PreviewOptionV1 {
            key: (*key).to_owned(),
            tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
        })
        .collect()
}

/// ADR-140 section 9: the Recommendation of every read golden example is the
/// rendering of `pigloros.match-score.v1` over the inputs it names: the
/// worked example, a Toss-up with margin 0 and `insufficient-evidence`.
#[test]
fn the_golden_recommendations_are_the_rendered_match_score() -> TestResult {
    let worked = (
        weights(&[("city", -300_000), ("nature", 800_000), ("quiet", 500_000)]),
        options(&[
            ("coast", &["nature", "quiet", "surf"]),
            ("city", &["city", "nightlife"]),
        ]),
    );
    let toss_up = (
        weights(&[("nature", 400_000), ("quiet", 400_000)]),
        options(&[("coast", &["nature"]), ("lake", &["quiet"])]),
    );
    let insufficient = (
        weights(&[("cost", -400_000)]),
        options(&[("coast", &["nature"]), ("city", &["culture"])]),
    );
    for (name, (weights, options)) in [
        ("decision-preview-committed", worked),
        ("decision-preview-toss-up", toss_up),
        ("decision-preview-insufficient-evidence", insufficient),
    ] {
        let recommendation =
            match_score_v1(&weights, &options).map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            recommendation_json(&recommendation),
            golden(name)?["recommendation"],
            "{name}"
        );
    }
    Ok(())
}

/// One `RevisionRef` of a request body, its digest `byte` repeated.
fn wire_reference(id: &str, revision: u64, byte: &str) -> Value {
    json!({"id": id, "revision": revision, "digest": byte.repeat(32)})
}

/// A well-formed `createDecisionPreview` body.
fn request_body() -> Value {
    json!({
        "schema_version": 1,
        "scenario_room": wire_reference("01JC0GATEWAYW9R00M00000001", 2, "0a"),
        "preference": wire_reference("01JC0GATEWAYW9PREF0000002A", 1, "0b"),
        "option_spec": wire_reference("01JC0GATEWAYW9QPT10N00002A", 1, "0c"),
        "profile_id": "deterministic-local-v1",
    })
}

/// The problem code a parse refusal answers.
fn parse_refusal(body: &Value) -> TestResult<Value> {
    let problem = parse_request(body)
        .err()
        .ok_or("the body is refused")?
        .into_response();
    let (body, _) = problem_of(&problem)?;
    Ok(body["code"].clone())
}

/// ADR-140 section 6 step 2 and P26: the body is the closed
/// `CreateDecisionPreviewRequest`; an integer `schema_version` other than 1
/// is `unsupported-version`, every other defect `invalid-request`.
#[test]
fn a_request_body_must_match_its_schema() -> TestResult {
    let request = parse_request(&request_body()).map_err(|problem| format!("{problem:?}"))?;
    assert_eq!(request.scenario_room.revision.get(), 2);
    assert_eq!(request.preference.digest, [0x0b; 32]);
    assert_eq!(request.profile_id, "deterministic-local-v1");
    // Any number but the integer 1 is another version; a value that is no
    // number is a malformed body.
    for version in [json!(0), json!(2), json!(-1), json!(1.0), json!(2.5)] {
        let mut body = request_body();
        body["schema_version"] = version.clone();
        assert_eq!(parse_refusal(&body)?, "unsupported-version", "{version}");
    }
    let lower = "01jc0gatewayw9r00m00000001";
    let unsafe_revision = 9_007_199_254_740_992_u64;
    for (path, value) in [
        (&["schema_version"][..], json!("1")),
        (&["schema_version"][..], Value::Null),
        (&["profile_id"][..], json!("gateway-mode-local-v1")),
        (&["profile_id"][..], json!(1)),
        (&["scenario_room", "id"][..], json!(lower)),
        (&["preference", "revision"][..], json!(0)),
        (&["preference", "revision"][..], json!(unsafe_revision)),
        (&["option_spec", "digest"][..], json!("0C".repeat(32))),
        (&["option_spec", "digest"][..], json!("0c")),
        (&["option_spec", "label"][..], json!("extra")),
        (&["unknown"][..], json!(true)),
    ] {
        let mut body = request_body();
        let mut member = &mut body;
        for segment in path {
            member = &mut member[*segment];
        }
        *member = value;
        assert_eq!(parse_refusal(&body)?, "invalid-request", "{path:?}");
    }
    let mut missing = request_body();
    missing
        .as_object_mut()
        .and_then(|members| members.remove("schema_version"))
        .ok_or("the body names its version")?;
    assert_eq!(parse_refusal(&missing)?, "invalid-request");
    assert_eq!(parse_refusal(&json!([1]))?, "invalid-request");
    Ok(())
}

/// One answer of the router.
struct Answer {
    status: StatusCode,
    retry_after: Option<String>,
    bytes: Vec<u8>,
    body: Value,
}

/// Send `request` with `body`; every answer is `no-store` (#1407).
async fn exchange(app: &Router, request: Builder, body: Body) -> TestResult<Answer> {
    let response = app.clone().oneshot(request.body(body)?).await?;
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let status = response.status();
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .map(|value| value.to_str().map(str::to_owned))
        .transpose()?;
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await?
        .to_vec();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok(Answer {
        status,
        retry_after,
        bytes,
        body,
    })
}

/// A JSON request that names no actor.
fn builder(method: &str, uri: &str) -> Builder {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
}

/// A JSON request of `actor`.
fn acting(method: &str, uri: &str, actor: &str) -> Builder {
    builder(method, uri).header(ACTOR_ENTITY_HEADER, actor)
}

/// `createDecisionPreview` of `body` by the fixture actor under `key`.
async fn post_preview(app: &Router, key: &str, body: &Value) -> TestResult<Answer> {
    exchange(
        app,
        acting("POST", PREVIEWS, ACTOR).header("idempotency-key", key),
        Body::from(body.to_string()),
    )
    .await
}

/// `getDecisionPreview` of `preview_id` by `actor`.
async fn get_preview(app: &Router, preview_id: &str, actor: &str) -> TestResult<Answer> {
    exchange(
        app,
        acting("GET", &format!("{PREVIEWS}/{preview_id}"), actor),
        Body::empty(),
    )
    .await
}

/// The body of `request`.
fn body_of(request: &PreviewRequestV1) -> Value {
    json!({
        "schema_version": 1,
        "scenario_room": revision_ref_json(&request.scenario_room),
        "preference": revision_ref_json(&request.preference),
        "option_spec": revision_ref_json(&request.option_spec),
        "profile_id": request.profile_id,
    })
}

/// The router of `gateway`.
fn app_of(gateway: Gateway) -> Router {
    router(AppState {
        gateway,
        ledger_view: LedgerView::default(),
        ledger_write: LedgerWriteMode::Disabled,
    })
}

/// The router of `served`'s Gateway with the seam installed-profile port.
fn seam_app(served: &Served) -> Router {
    app_of(seam(&served.gateway))
}

/// The JSON type of `value` and of every member and item below it: a
/// served body and its frozen golden example agree on every member and
/// type.
fn shape(value: &Value) -> Value {
    match value {
        Value::Object(members) => Value::Object(
            members
                .iter()
                .map(|(name, member)| (name.clone(), shape(member)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(shape).collect()),
        Value::String(_) => json!("string"),
        Value::Number(_) => json!("number"),
        Value::Bool(_) => json!("bool"),
        Value::Null => json!("null"),
    }
}

/// The response body of the frozen golden example `name`.
fn golden(name: &str) -> TestResult<Value> {
    let path = format!(
        "{}/../../contracts/gateway/v1/compatibility/examples/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let example: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    Ok(example["response"]["body"].clone())
}

/// The text of `value` at `pointer`.
fn text<'a>(value: &'a Value, pointer: &str) -> TestResult<&'a str> {
    Ok(value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{pointer} in {value}"))?)
}

/// Whether the store records the `decision-previews` Timeline.
async fn recorded(gateway: &Gateway) -> TestResult<bool> {
    on_host(gateway, |host| {
        host.command_sender()
            .and_then(|mut commands| commands.records_timeline(decision_previews_timeline()))
            .map_err(|error| format!("{error:?}"))
    })
    .await
}

/// ADR-140 D1 and the C3 test plan: on the release composition a
/// well-formed, authorized fresh request is `409 incompatible-profile`, and
/// its `400`, `401`, `403`, `415` and `429` answers come before the gate.
/// The body, its content type and the key are refused before the authority
/// decision, so an actor no grant covers still gets the `400` and `415`.
/// Nothing is recorded.
#[tokio::test]
async fn the_release_composition_refuses_every_fresh_request() -> TestResult {
    let directory = tempfile::tempdir()?;
    let served = served(&directory).await?;
    let body = body_of(&seed(&served).await?);
    let app = &served.app;
    let gated = post_preview(app, "k-1", &body).await?;
    assert_eq!(
        (gated.status, text(&gated.body, "/code")?),
        (StatusCode::CONFLICT, "incompatible-profile")
    );
    assert_eq!(text(&gated.body, "/instance")?, PREVIEWS);
    let stranger = EntityId::new().to_string();
    let mut versioned = body.clone();
    versioned["schema_version"] = json!(2);
    for (sent_request, sent, status, code) in [
        (
            acting("POST", PREVIEWS, &stranger).header("idempotency-key", "k-2"),
            versioned.to_string(),
            StatusCode::BAD_REQUEST,
            "unsupported-version",
        ),
        (
            acting("POST", PREVIEWS, &stranger),
            body.to_string(),
            StatusCode::BAD_REQUEST,
            "invalid-request",
        ),
        (
            builder("POST", PREVIEWS).header("idempotency-key", "k-2"),
            body.to_string(),
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        ),
        (
            acting("POST", PREVIEWS, &stranger).header("idempotency-key", "k-2"),
            body.to_string(),
            StatusCode::FORBIDDEN,
            "unauthorized",
        ),
        (
            Request::builder()
                .method("POST")
                .uri(PREVIEWS)
                .header("content-type", "text/plain")
                .header(ACTOR_ENTITY_HEADER, &stranger)
                .header("idempotency-key", "k-2"),
            body.to_string(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid-request",
        ),
    ] {
        let answer = exchange(app, sent_request, Body::from(sent)).await?;
        assert_eq!(
            (answer.status, text(&answer.body, "/code")?),
            (status, code),
            "{}",
            answer.body
        );
    }
    // A fifth request in flight is a retryable `429` without `Retry-After`.
    let in_flight = &served.gateway.decision_previews.in_flight;
    let slots = (0..MAX_IN_FLIGHT_PER_PRINCIPAL)
        .map(|_| InFlightSlotV1::take(in_flight, PRINCIPAL))
        .collect::<Option<Vec<_>>>()
        .ok_or("the Principal has four slots")?;
    let saturated = post_preview(app, "k-1", &body).await?;
    assert_eq!(saturated.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(saturated.body["retryable"], true);
    assert_eq!(saturated.retry_after, None);
    drop(slots);
    // A read is decided before any lookup: without an actor it is `401`.
    let unknown = format!("{PREVIEWS}/{}", EntityId::new());
    let anonymous = exchange(app, builder("GET", &unknown), Body::empty()).await?;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    assert!(!recorded(&served.gateway).await?);
    served.gateway.shutdown().await?;
    drop(served);
    Ok(())
}

/// ADR-140 sections 6, 7 and D5 through the seam: the `202` receipt names
/// the preview and its bound inputs, an exact retry answers its bytes, the
/// same key with another request conflicts before the release port's gate,
/// and the preview reads back `committed` with the worked example's
/// Recommendation, through either port, to its actor only.
#[tokio::test]
async fn a_preview_is_admitted_retried_and_read_over_http() -> TestResult {
    let directory = tempfile::tempdir()?;
    let served = served(&directory).await?;
    let request = seed(&served).await?;
    let body = body_of(&request);
    let app = seam_app(&served);
    let admitted = post_preview(&app, "k-1", &body).await?;
    assert_eq!(admitted.status, StatusCode::ACCEPTED, "{}", admitted.body);
    assert_eq!(
        shape(&admitted.body),
        shape(&golden("decision-preview-admitted")?)
    );
    let id = text(&admitted.body, "/request_id")?.to_owned();
    assert_eq!(text(&admitted.body, "/operation_id")?, id);
    assert_eq!(
        text(&admitted.body, "/operation_url")?,
        format!("{PREVIEWS}/{id}")
    );
    assert_eq!(
        text(&admitted.body, "/idempotency_key_digest")?,
        blake3::hash(b"k-1").to_hex().as_str()
    );
    let seam_digest = digest_hex(crate::decision_preview::test_seam::SEAM_PROFILE_DIGEST);
    assert_eq!(
        admitted.body["bound_inputs"],
        json!({
            "scenario_room": digest_hex(request.scenario_room.digest),
            "preference": digest_hex(request.preference.digest),
            "option_spec": digest_hex(request.option_spec.digest),
            "execution_profile": seam_digest,
            "mode_profile": LOCAL_DIGEST,
        })
    );
    let retried = post_preview(&app, "k-1", &body).await?;
    assert_eq!(
        (retried.status, &retried.bytes),
        (StatusCode::ACCEPTED, &admitted.bytes)
    );
    // P35: with three other requests in flight, an exact retry takes the
    // fourth slot and is answered.
    let in_flight = &served.gateway.decision_previews.in_flight;
    let slots = (1..MAX_IN_FLIGHT_PER_PRINCIPAL)
        .map(|_| InFlightSlotV1::take(in_flight, PRINCIPAL))
        .collect::<Option<Vec<_>>>()
        .ok_or("the Principal has three free slots")?;
    let crowded = post_preview(&app, "k-1", &body).await?;
    assert_eq!(
        (crowded.status, &crowded.bytes),
        (StatusCode::ACCEPTED, &admitted.bytes)
    );
    drop(slots);
    let mut other = body;
    other["profile_id"] = json!("replay-v1");
    let conflict = post_preview(&served.app, "k-1", &other).await?;
    assert_eq!(
        (conflict.status, text(&conflict.body, "/code")?),
        (StatusCode::CONFLICT, "idempotency-conflict")
    );
    let committed = golden("decision-preview-committed")?;
    for reader in [&app, &served.app] {
        let read = get_preview(reader, &id, ACTOR).await?;
        assert_eq!(read.status, StatusCode::OK, "{}", read.body);
        assert_eq!(shape(&read.body), shape(&committed));
        assert_eq!(read.body["state"], "committed");
        assert_eq!(read.body["generation"], 2);
        assert_eq!(read.body["recommendation"], committed["recommendation"]);
        assert_eq!(
            read.body["committed"]["timeline_id"],
            decision_previews_timeline().to_string()
        );
        assert_eq!(
            read.body["committed"]["event_schema_id"],
            "preview.result.v1"
        );
        assert_eq!(read.body["mode_profile"], committed["mode_profile"]);
        for member in [
            "factual_timeline_id",
            "failure",
            "uncertainty",
            "calibration",
            "availability",
            "proposals",
            "actuation",
        ] {
            assert_eq!(read.body[member], committed[member], "{member}");
        }
    }
    let unknown = EntityId::new().to_string();
    let lower = id.to_lowercase();
    for (requested, actor, status) in [
        (id.as_str(), OTHER_ACTOR, StatusCode::NOT_FOUND),
        (unknown.as_str(), ACTOR, StatusCode::NOT_FOUND),
        ("not-a-preview", ACTOR, StatusCode::BAD_REQUEST),
        (lower.as_str(), ACTOR, StatusCode::BAD_REQUEST),
    ] {
        let read = get_preview(&app, requested, actor).await?;
        assert_eq!(read.status, status, "{requested}: {}", read.body);
        assert_eq!(
            text(&read.body, "/instance")?,
            "/v1/decision-previews/{preview_id}"
        );
    }
    assert_eq!(previews_events(&served.gateway).await?, 2);
    served.gateway.shutdown().await?;
    drop(served);
    Ok(())
}

/// D5: a restarted Gateway answers an exact retry with the same receipt
/// bytes, from the stored claim alone.
#[tokio::test]
async fn a_restarted_gateway_answers_the_same_receipt_bytes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let served = served(&directory).await?;
    let body = body_of(&seed(&served).await?);
    let admitted = post_preview(&seam_app(&served), "k-1", &body).await?;
    assert_eq!(admitted.status, StatusCode::ACCEPTED, "{}", admitted.body);
    served.gateway.shutdown().await?;
    drop(served);
    let path = store_path(&directory)?;
    let binding = test_binding(GatewayModeProfileIdV1::Local, []);
    let host = open_recovered_erasure_host(
        StoreConfig::Sqlite { path },
        GatewayHostStoreV1::Standard,
        &ErasureCoordinatorCompositionV1::closed(),
    )?;
    let gateway = local_gateway(test_attach_host(host, &binding), None, &binding)?;
    let retried = post_preview(&app_of(gateway.clone()), "k-1", &body).await?;
    assert_eq!(
        (retried.status, retried.bytes),
        (StatusCode::ACCEPTED, admitted.bytes)
    );
    gateway.shutdown().await?;
    drop(gateway);
    Ok(())
}

/// D6: a room whose consent the Principal does not hold is
/// `403 consent-invalid`, checked after every `404`; once the consent is
/// revoked, an exact retry, a fresh request and a read are `403 revoked`,
/// and the retry of an interrupted preview appends no result.
#[tokio::test]
async fn the_room_consent_is_checked_on_create_retry_and_read() -> TestResult {
    let directory = tempfile::tempdir()?;
    let served = served(&directory).await?;
    let app = seam_app(&served);
    let unheld = on_host(&served.gateway, |host| seeded(host, EntityId::new())).await?;
    let refused = post_preview(&app, "k-0", &body_of(&unheld)).await?;
    assert_eq!(
        (refused.status, text(&refused.body, "/code")?),
        (StatusCode::FORBIDDEN, "consent-invalid")
    );
    let request = seed(&served).await?;
    let body = body_of(&request);
    let admitted = post_preview(&app, "k-1", &body).await?;
    let id = text(&admitted.body, "/request_id")?.to_owned();
    let consent = served.consent;
    on_host(&served.gateway, move |host| {
        interrupted(host, &request, "k-2", consent, None)
    })
    .await?;
    let revocation = exchange(
        &served.app,
        acting("POST", "/v1/me/consent-revocations", ACTOR).header("idempotency-key", "r"),
        Body::from(json!({"consent_ref": served.consent.to_string()}).to_string()),
    )
    .await?;
    assert_eq!(
        revocation.status,
        StatusCode::CREATED,
        "{}",
        revocation.body
    );
    for key in ["k-1", "k-2", "k-3"] {
        let answer = post_preview(&app, key, &body).await?;
        assert_eq!(
            (answer.status, text(&answer.body, "/code")?),
            (StatusCode::FORBIDDEN, "revoked"),
            "{key}"
        );
    }
    let read = get_preview(&app, &id, ACTOR).await?;
    assert_eq!(
        (read.status, text(&read.body, "/code")?),
        (StatusCode::FORBIDDEN, "revoked")
    );
    // The first preview's two Events and the unfinished claim.
    assert_eq!(previews_events(&served.gateway).await?, 3);
    served.gateway.shutdown().await?;
    drop(served);
    Ok(())
}

/// P17 and P34: a claim the host interrupted reads `admitted` (generation 1,
/// no commit, a pending Recommendation) until an exact retry, also under the
/// release port, finishes it.
#[tokio::test]
async fn an_interrupted_preview_reads_admitted_until_a_retry_finishes_it() -> TestResult {
    let directory = tempfile::tempdir()?;
    let served = served(&directory).await?;
    let request = seed(&served).await?;
    let body = body_of(&request);
    let consent = served.consent;
    let preview_id = on_host(&served.gateway, move |host| {
        interrupted(host, &request, "k-1", consent, None)
    })
    .await?
    .to_string();
    let read = get_preview(&served.app, &preview_id, ACTOR).await?;
    assert_eq!(read.status, StatusCode::OK, "{}", read.body);
    assert_eq!(
        shape(&read.body),
        shape(&golden("decision-preview-admitted-not-committed")?)
    );
    assert_eq!(
        (&read.body["state"], &read.body["generation"]),
        (&json!("admitted"), &json!(1))
    );
    assert_eq!(read.body["recommendation"], json!({"status": "pending"}));
    assert_eq!(read.body["committed"], Value::Null);
    let finished = post_preview(&served.app, "k-1", &body).await?;
    assert_eq!(finished.status, StatusCode::ACCEPTED, "{}", finished.body);
    assert_eq!(text(&finished.body, "/request_id")?, preview_id);
    let read = get_preview(&served.app, &preview_id, ACTOR).await?;
    assert_eq!(read.body["state"], "committed");
    served.gateway.shutdown().await?;
    drop(served);
    Ok(())
}

/// D9, P18 and P25: once a bound Preference is erased, a computed preview
/// reads `degraded`, withholding its Recommendation with reason `deleted`
/// and keeping its commit; an interrupted one is finished `failed` with
/// `input-deleted` and stays `available`; a fresh request is `404`.
#[tokio::test]
async fn an_erased_input_degrades_or_fails_a_preview() -> TestResult {
    let directory = tempfile::tempdir()?;
    let served = served(&directory).await?;
    let request = seed(&served).await?;
    let body = body_of(&request);
    let app = seam_app(&served);
    let admitted = post_preview(&app, "k-1", &body).await?;
    let computed = text(&admitted.body, "/request_id")?.to_owned();
    let consent = served.consent;
    let claimed = request.clone();
    let interrupted_id = on_host(&served.gateway, move |host| {
        interrupted(host, &claimed, "k-2", consent, None)
    })
    .await?
    .to_string();
    let preference = request.preference;
    on_host(&served.gateway, move |host| {
        erase(host, GatewayRevisionKindV1::Preference, &preference)
            .map_err(|error| error.to_string())
    })
    .await?;
    let degraded = get_preview(&app, &computed, ACTOR).await?;
    assert_eq!(degraded.status, StatusCode::OK, "{}", degraded.body);
    assert_eq!(
        shape(&degraded.body),
        shape(&golden("decision-preview-degraded")?)
    );
    assert_eq!(degraded.body["state"], "degraded");
    assert_eq!(
        degraded.body["recommendation"],
        json!({"status": "withheld"})
    );
    assert_eq!(
        degraded.body["availability"],
        json!({
            "state": "partial",
            "withheld": [{"member": "/recommendation", "reason": "deleted"}],
        })
    );
    assert_eq!(
        degraded.body["committed"]["event_schema_id"],
        "preview.result.v1"
    );
    let finished = post_preview(&app, "k-2", &body).await?;
    assert_eq!(finished.status, StatusCode::ACCEPTED, "{}", finished.body);
    let failed = get_preview(&app, &interrupted_id, ACTOR).await?;
    assert_eq!(
        shape(&failed.body),
        shape(&golden("decision-preview-failed")?)
    );
    assert_eq!(failed.body["state"], "failed");
    assert_eq!(failed.body["failure"], json!({"code": "input-deleted"}));
    assert_eq!(failed.body["committed"], Value::Null);
    assert_eq!(failed.body["recommendation"], json!({"status": "pending"}));
    assert_eq!(failed.body["availability"]["state"], "available");
    let fresh = post_preview(&app, "k-3", &body).await?;
    assert_eq!(
        (fresh.status, text(&fresh.body, "/code")?),
        (StatusCode::NOT_FOUND, "not-found-or-unavailable")
    );
    served.gateway.shutdown().await?;
    drop(served);
    Ok(())
}

/// D8: the room is bound by its `provenance.digest`; any other digest is the
/// same `404` as an unknown room.
#[tokio::test]
async fn the_room_digest_must_be_its_provenance_digest() -> TestResult {
    let directory = tempfile::tempdir()?;
    let served = served(&directory).await?;
    let mut request = seed(&served).await?;
    request.scenario_room.digest = [9; 32];
    let answer = post_preview(&seam_app(&served), "k-1", &body_of(&request)).await?;
    assert_eq!(
        (answer.status, text(&answer.body, "/code")?),
        (StatusCode::NOT_FOUND, "not-found-or-unavailable")
    );
    assert!(!recorded(&served.gateway).await?);
    served.gateway.shutdown().await?;
    drop(served);
    Ok(())
}

/// D5 and step 12.1: two concurrent fresh requests under one key commit one
/// claim and answer the same receipt.
#[tokio::test]
async fn concurrent_requests_under_one_key_commit_one_preview() -> TestResult {
    let directory = tempfile::tempdir()?;
    let served = served(&directory).await?;
    let body = body_of(&seed(&served).await?);
    let app = seam_app(&served);
    let (first, second) = tokio::join!(
        post_preview(&app, "k-1", &body),
        post_preview(&app, "k-1", &body)
    );
    let (first, second) = (first?, second?);
    assert_eq!(
        (first.status, &first.bytes),
        (StatusCode::ACCEPTED, &second.bytes)
    );
    assert_eq!(second.status, StatusCode::ACCEPTED);
    assert_eq!(previews_events(&served.gateway).await?, 2);
    served.gateway.shutdown().await?;
    drop(served);
    Ok(())
}

/// P11 through the router: a fresh request that would leave no room for its
/// two Events is the permanent `429`, not retryable and without
/// `Retry-After`, while an exact retry of an earlier preview is answered.
#[tokio::test]
async fn a_full_store_refuses_a_fresh_request_for_good() -> TestResult {
    let directory = tempfile::tempdir()?;
    let served = served(&directory).await?;
    let body = body_of(&seed(&served).await?);
    let app = {
        let mut gateway = seam(&served.gateway);
        gateway.limits.max_events_per_timeline = 3;
        app_of(gateway)
    };
    let admitted = post_preview(&app, "k-1", &body).await?;
    assert_eq!(admitted.status, StatusCode::ACCEPTED, "{}", admitted.body);
    let full = post_preview(&app, "k-2", &body).await?;
    assert_eq!(
        (full.status, text(&full.body, "/code")?),
        (StatusCode::TOO_MANY_REQUESTS, "resource-limit-exceeded")
    );
    assert_eq!(full.body["retryable"], false);
    assert_eq!(full.retry_after, None);
    let retried = post_preview(&app, "k-1", &body).await?;
    assert_eq!(
        (retried.status, &retried.bytes),
        (StatusCode::ACCEPTED, &admitted.bytes)
    );
    assert_eq!(previews_events(&served.gateway).await?, 2);
    served.gateway.shutdown().await?;
    drop(served);
    Ok(())
}

/// D11 through the router: the 33rd new claim of a Principal in one window
/// is a retryable `429` whose `Retry-After` header states the whole seconds
/// left in the window; an exact retry is not counted and is still answered.
#[tokio::test]
async fn the_per_minute_quota_answers_retry_after_on_the_wire() -> TestResult {
    let directory = tempfile::tempdir()?;
    let served = served(&directory).await?;
    let body = body_of(&seed(&served).await?);
    let app = seam_app(&served);
    for index in 0..MAX_ADMISSIONS_PER_MINUTE {
        let admitted = post_preview(&app, &format!("k-{index}"), &body).await?;
        assert_eq!(admitted.status, StatusCode::ACCEPTED, "{}", admitted.body);
    }
    let limited = post_preview(&app, "k-over", &body).await?;
    assert_eq!(
        (limited.status, text(&limited.body, "/code")?),
        (StatusCode::TOO_MANY_REQUESTS, "resource-limit-exceeded")
    );
    assert_eq!(limited.body["retryable"], true);
    let seconds = limited
        .retry_after
        .as_deref()
        .ok_or("the quota states Retry-After")?
        .parse::<u64>()?;
    assert!((1..=60).contains(&seconds), "{seconds}");
    let retried = post_preview(&app, "k-0", &body).await?;
    assert_eq!(retried.status, StatusCode::ACCEPTED, "{}", retried.body);
    served.gateway.shutdown().await?;
    drop(served);
    Ok(())
}
