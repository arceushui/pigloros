//! Axum HTTP surface for [`crate::Gateway`] (WebSocket stream deferred — HTTP
//! poll is the current foundation; configured host authorization protects reads).

use crate::{
    ActionRequest, CreateTimelineRequest, EventView, EventsQuery, Gateway, GatewayError,
    GenerationBoundEventPage, LedgerWriteMode, SignalRequest, MAX_EVENTS_PER_POLL,
    MAX_EVENTS_RESPONSE_BYTES, MAX_HTTP_BODY_BYTES,
};
use axum::{
    extract::{DefaultBodyLimit, Path, RawQuery, State},
    http::{
        header::{self, CONTENT_SECURITY_POLICY},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use piglor_ledger::{render_html, LedgerView};
use pos_core::{
    clock::{Seq, WallTime},
    ActionRejected, CoreError, ErasureReferenceV1,
};
use pos_plugin_ledger::NewPrediction;
use pos_runtime::ErasureHostStatusV1;
use serde_json::json;
use std::net::SocketAddr;

/// Shared axum state.
#[derive(Clone)]
pub struct AppState {
    pub gateway: Gateway,
    pub ledger_view: LedgerView,
    pub ledger_write: LedgerWriteMode,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod coverage_tests {
    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            match self {
                Ok(value) => value,
                Err(error) => {
                    std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
                }
            }
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test value")))
        }
    }

    use super::*;
    use pos_core::Kind;
    use pos_store::{open_store, StoreConfig};

    #[tokio::test]
    async fn bounded_response_rejects_geographic_event() {
        let gateway = Gateway::new(open_store(StoreConfig::Memory).test_ok());
        let timeline = gateway.create_timeline("coverage-geo").await.test_ok();
        let mut event = gateway
            .append_action(
                &timeline.id().to_string(),
                &pos_core::EntityId::new().to_string(),
                crate::EVENT_TYPE_ACTION,
                &serde_json::json!({"value": 1}),
            )
            .await
            .test_ok();
        event.event_type = Kind::new(pos_core::GEOGRAPHIC_EVENT_TYPE);
        assert!(bounded_events_response(
            GenerationBoundEventPage {
                page: crate::EventPage {
                    events: vec![event],
                    next_from_seq: None,
                    next_cursor: None,
                },
                inventory_generation: None,
            },
            MAX_EVENTS_RESPONSE_BYTES,
            &timeline.id().to_string(),
        )
        .is_err());
        drop(gateway);
    }
}

/// Build the Gateway foundation router (ADR-014 route table; WS deferred to follow-up).
pub fn router(state: AppState) -> Router {
    build_router(state, MAX_HTTP_BODY_BYTES)
}

/// Build the loopback router with the explicit local `OwnTracks` route enabled.
fn router_with_owntracks(state: AppState) -> Router {
    let gateway = state.gateway.clone();
    build_router(state, MAX_HTTP_BODY_BYTES).route(
        "/v1/bridges/owntracks",
        post(move |headers, body| crate::owntracks_http::post_owntracks(gateway, headers, body)),
    )
}

/// Build the only route table that can activate the local `OwnTracks` bridge.
pub fn router_for_addr(addr: SocketAddr, state: AppState) -> Router {
    if !addr.ip().is_loopback() {
        spectator_router(state)
    } else if state.gateway.owntracks_enabled {
        router_with_owntracks(state)
    } else {
        router(state)
    }
}

/// Build the public spectator router for a non-loopback Gateway deployment.
///
/// Until #68 adds an authentication boundary, this exposes only the public
/// Prediction Ledger surfaces from ADR-017 and ADR-020. Timeline and Ledger
/// mutation routes remain available only on a loopback-bound Gateway.
pub fn spectator_router(state: AppState) -> Router {
    spectator_routes()
        .layer(DefaultBodyLimit::max(MAX_HTTP_BODY_BYTES))
        .with_state(state)
}

fn build_router(state: AppState, max_body_bytes: usize) -> Router {
    spectator_routes()
        .route("/v1/ledger/predictions", post(post_ledger_prediction))
        .route("/v1/timelines", post(create_timeline))
        .route("/v1/timelines/{id}/events", get(list_events))
        .route("/v1/timelines/{id}/actions", post(post_action))
        .route("/v1/timelines/{id}/signals", post(post_signal))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .with_state(state)
}

fn spectator_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(root_redirect))
        .route("/ledger", get(ledger_page))
        .route("/health", get(health))
        .route("/v1/ledger", get(get_ledger))
}

async fn root_redirect() -> impl IntoResponse {
    (StatusCode::FOUND, [(header::LOCATION, "/ledger")])
}

async fn ledger_page(State(state): State<AppState>) -> impl IntoResponse {
    let html = render_html(&state.ledger_view, None);
    let mut response = Html(html).into_response();
    response.headers_mut().insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(piglor_ledger::CONTENT_SECURITY_POLICY),
    );
    response
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let ready = matches!(
        (
            state.gateway.is_ready(),
            state.gateway.erasure_status().await,
        ),
        (true, Ok(ErasureHostStatusV1::Ready))
    );
    if ready {
        (StatusCode::OK, Json(json!({ "ok": true })))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "error": "store executor or erasure host not ready"
            })),
        )
    }
}

async fn get_ledger(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "domain": "piglor.com",
        "path": "/ledger",
        "ledger": state.ledger_view.entries,
    }))
}

async fn create_timeline(
    State(state): State<AppState>,
    Json(body): Json<CreateTimelineRequest>,
) -> Result<impl IntoResponse, GatewayError> {
    let tl = state.gateway.create_timeline(&body.name).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": tl.id().to_string(),
            "name": tl.meta.name,
            "head": tl.head.as_u64(),
        })),
    ))
}

async fn list_events(
    State(state): State<AppState>,
    Path(id): Path<String>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Result<impl IntoResponse, GatewayError> {
    let response =
        match list_events_response(&state.gateway, &id, raw_query.as_deref(), &headers).await {
            Ok(response) => response,
            Err(error) => return Err(error),
        };
    Ok(Json(response))
}

async fn list_events_response(
    gateway: &Gateway,
    timeline_id: &str,
    raw_query: Option<&str>,
    headers: &HeaderMap,
) -> Result<serde_json::Value, GatewayError> {
    let request = parse_event_page_request(raw_query, timeline_id)?;
    let page = read_events_page(gateway, timeline_id, &request, headers).await?;
    bounded_events_response(page, MAX_EVENTS_RESPONSE_BYTES, timeline_id)
}

struct EventPageRequest {
    query: EventsQuery,
    expected_generation: Option<ErasureReferenceV1>,
}

fn parse_event_page_request(
    raw_query: Option<&str>,
    timeline_id: &str,
) -> Result<EventPageRequest, GatewayError> {
    let mut query = parse_events_query(raw_query)?;
    let expected_generation = if let Some(cursor) = query.cursor.as_deref() {
        let (from_seq, generation) = parse_event_cursor(cursor, timeline_id)?;
        query.from_seq = from_seq;
        Some(generation)
    } else {
        None
    };
    Ok(EventPageRequest {
        query,
        expected_generation,
    })
}

async fn read_events_page(
    gateway: &Gateway,
    timeline_id: &str,
    request: &EventPageRequest,
    headers: &HeaderMap,
) -> Result<GenerationBoundEventPage, GatewayError> {
    if gateway.has_authorization() {
        read_authorized_events(gateway, timeline_id, request, headers).await
    } else {
        gateway
            .read_events_page_at_generation(
                timeline_id,
                request.query.from_seq,
                request.query.limit,
                request.expected_generation,
            )
            .await
    }
}

async fn read_authorized_events(
    gateway: &Gateway,
    timeline_id: &str,
    request: &EventPageRequest,
    headers: &HeaderMap,
) -> Result<GenerationBoundEventPage, GatewayError> {
    let Some(actor) = headers
        .get("x-piglor-actor-entity")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| crate::parse_entity_id(value).ok())
    else {
        return Err(GatewayError::AuthorizationUnavailable);
    };
    let target_timeline = match crate::parse_timeline_id(timeline_id) {
        Ok(timeline) => timeline,
        Err(error) => return Err(error),
    };
    gateway
        .read_events_page_authorized_at_generation(
            timeline_id,
            request.query.from_seq,
            request.query.limit,
            crate::GatewayAuthorizationRequest::read(
                actor,
                target_timeline,
                request.query.from_seq,
                request.query.limit,
                WallTime::now(),
            ),
            request.expected_generation,
        )
        .await
}

fn parse_events_query(raw_query: Option<&str>) -> Result<EventsQuery, GatewayError> {
    let Some(raw_query) = raw_query.filter(|query| !query.is_empty()) else {
        return Ok(EventsQuery::default());
    };
    let query = parse_events_query_fields(raw_query)?;
    if query.limit == 0 || query.limit > MAX_EVENTS_PER_POLL {
        return Err(GatewayError::InvalidPageLimit {
            maximum: MAX_EVENTS_PER_POLL,
        });
    }
    Ok(query)
}

fn parse_events_query_fields(raw_query: &str) -> Result<EventsQuery, GatewayError> {
    let mut query = EventsQuery::default();
    let mut saw_from_seq = false;
    let mut saw_limit = false;
    let mut saw_cursor = false;
    for field in raw_query.split('&') {
        let Some((name, value)) = field.split_once('=') else {
            return Err(GatewayError::InvalidEventsQuery(field.to_owned()));
        };
        match name {
            "from_seq" if !saw_from_seq => {
                query.from_seq = value
                    .parse()
                    .map_err(|_| GatewayError::InvalidEventsQuery(field.to_owned()))?;
                saw_from_seq = true;
            }
            "limit" if !saw_limit => {
                query.limit = value
                    .parse()
                    .map_err(|_| GatewayError::InvalidEventsQuery(field.to_owned()))?;
                saw_limit = true;
            }
            "cursor" if !saw_cursor => {
                query.cursor = Some(value.to_owned());
                saw_cursor = true;
            }
            _ => return Err(GatewayError::InvalidEventsQuery(field.to_owned())),
        }
    }
    if saw_from_seq && saw_cursor {
        return Err(GatewayError::InvalidEventsQuery("cursor".to_owned()));
    }
    Ok(query)
}

fn parse_event_cursor(
    cursor: &str,
    timeline_id: &str,
) -> Result<(u64, ErasureReferenceV1), GatewayError> {
    let invalid = || GatewayError::InvalidEventsQuery("cursor".to_owned());
    let mut parts = cursor.split('.');
    let (Some("v1"), Some(hex), Some(bound_timeline), Some(position), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Err(invalid());
    };
    if hex.len() != 64 || bound_timeline != timeline_id {
        return Err(invalid());
    }
    let mut digest = [0; 32];
    for (slot, pair) in digest.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        let high = hex_nibble(pair[0]).ok_or_else(invalid)?;
        let low = hex_nibble(pair[1]).ok_or_else(invalid)?;
        *slot = high * 16 + low;
    }
    let from_seq = position
        .parse::<u64>()
        .ok()
        .filter(|position| *position > 0)
        .ok_or_else(invalid)?;
    Ok((from_seq, ErasureReferenceV1::from_digest(digest)))
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn next_event_cursor(
    generation: Option<ErasureReferenceV1>,
    timeline_id: &str,
    next_from_seq: Option<Seq>,
) -> Option<String> {
    generation
        .zip(next_from_seq)
        .map(|(generation, seq)| crate::event_cursor(generation, timeline_id, seq.as_u64()))
}

fn bounded_events_response(
    bounded: GenerationBoundEventPage,
    maximum_bytes: usize,
    timeline_id: &str,
) -> Result<serde_json::Value, GatewayError> {
    let GenerationBoundEventPage {
        page,
        inventory_generation,
    } = bounded;
    let mut events = Vec::with_capacity(page.events.len());
    let mut source = page.events.into_iter().peekable();
    loop {
        let next_event = source.next();
        let Some(event) = next_event else {
            break;
        };
        let event_seq = event.seq.as_u64();
        let view = EventView::try_from(&event)?;
        events.push(crate::event_view_json(&view));
        let next_from_seq = source
            .peek()
            .map(|next| Seq::from_u64(next.seq.as_u64()))
            .or(page.next_from_seq);
        let candidate = json!({
            "events": events,
            "next_from_seq": next_from_seq,
            "next_cursor": next_event_cursor(inventory_generation, timeline_id, next_from_seq),
        });
        if serialized_len(&candidate) > maximum_bytes {
            events.pop();
            if events.is_empty() {
                return Err(GatewayError::EventResponseTooLarge {
                    maximum: maximum_bytes,
                });
            }
            return Ok(json!({
                "events": events,
                "next_from_seq": Seq::from_u64(event_seq),
                "next_cursor": next_event_cursor(
                    inventory_generation,
                    timeline_id,
                    Some(Seq::from_u64(event_seq)),
                ),
            }));
        }
    }
    Ok(json!({
        "events": events,
        "next_from_seq": page.next_from_seq,
        "next_cursor": next_event_cursor(
            inventory_generation,
            timeline_id,
            page.next_from_seq,
        ),
    }))
}

fn serialized_len(value: &serde_json::Value) -> usize {
    crate::serialized_json_len(value)
}

async fn post_action(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<ActionRequest>,
) -> Result<impl IntoResponse, GatewayError> {
    if let Some(ingress_id) = body.ingress_id.as_deref() {
        let result = state
            .gateway
            .submit_identified_json_action(
                &id,
                &body.entity_id,
                &body.event_type,
                &body.payload,
                &body.capability,
                ingress_id,
            )
            .await?;
        let status = if result.duplicate() {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        };
        return EventView::try_from(result.event()).map(|view| (status, Json(view)));
    }
    let action = state
        .gateway
        .submit_json_action(
            &id,
            &body.entity_id,
            &body.event_type,
            &body.payload,
            &body.capability,
        )
        .await?;
    EventView::try_from(action.event()).map(|view| (StatusCode::CREATED, Json(view)))
}

async fn post_signal(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<SignalRequest>,
) -> Result<impl IntoResponse, GatewayError> {
    let entity_id = body.entity_id.clone();
    let event = state
        .gateway
        .append_signal(&id, &entity_id, &body.into_signal())
        .await?;
    EventView::try_from(&event).map(|view| (StatusCode::CREATED, Json(view)))
}

async fn post_ledger_prediction(
    State(state): State<AppState>,
    Json(body): Json<NewPrediction>,
) -> Result<impl IntoResponse, GatewayError> {
    let ledger = match &state.ledger_write {
        LedgerWriteMode::Disabled => return Err(GatewayError::LedgerWriteDisabled),
        LedgerWriteMode::Unconfigured => return Err(GatewayError::LedgerUnavailable),
        LedgerWriteMode::Ready(ledger) => ledger,
    };
    body.validate()?;
    let prediction_id = ledger.register(body).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "prediction_id": prediction_id })),
    ))
}

const fn gateway_store_status(error: &CoreError) -> Option<StatusCode> {
    match error {
        CoreError::TimelineNotFound(_) => Some(StatusCode::NOT_FOUND),
        CoreError::ErasureContainmentUnavailable => Some(StatusCode::SERVICE_UNAVAILABLE),
        _ => None,
    }
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = Json(json!({ "error": self.to_string() }));
        (status, body).into_response()
    }
}

impl GatewayError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidId(_)
            | Self::InvalidPageLimit { .. }
            | Self::InvalidEventsQuery(_)
            | Self::InvalidAuthorizationRequest
            | Self::ConsentCodec(_)
            | Self::ConsentGrantSequenceMismatch
            | Self::ConsentRevocationFenceMismatch => StatusCode::BAD_REQUEST,
            Self::ActionRejected(ar) => match ar {
                ActionRejected::UnknownEventType => StatusCode::BAD_REQUEST,
                ActionRejected::CapabilityNotGranted => StatusCode::FORBIDDEN,
                ActionRejected::InvalidActorEntityId
                | ActionRejected::DomainValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
                ActionRejected::PayloadTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            },
            Self::Consent(_)
            | Self::LedgerWriteDisabled
            | Self::AuthorizationDenied
            | Self::Store(CoreError::ErasureAccessFrozen) => StatusCode::FORBIDDEN,
            Self::TimelineLimitReached { .. }
            | Self::EventLimitReached { .. }
            | Self::StoreExecutorSaturated => StatusCode::TOO_MANY_REQUESTS,
            Self::EventPayloadTooLarge { .. }
            | Self::EventMetadataTooLarge { .. }
            | Self::ForkDepthTooLarge { .. }
            | Self::EventResponseTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            Self::EventReadTimeExceeded { .. } => StatusCode::GATEWAY_TIMEOUT,
            Self::CompatibilityReadTruncated { .. }
            | Self::IngressConflict
            | Self::ActionObservationStale
            | Self::StaleEventCursor => StatusCode::CONFLICT,
            Self::ResourceUnavailable => StatusCode::NOT_FOUND,
            Self::Store(error) => {
                gateway_store_status(error).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
            }
            Self::ActionRegistry(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ActionAuthorizationUnavailable | Self::AuthorizationUnavailable => {
                StatusCode::UNAUTHORIZED
            }
            Self::StoreExecutorClosed
            | Self::StoreExecutorDeadlineExceeded
            | Self::StoreExecutorUnhealthy
            | Self::LedgerUnavailable
            | Self::OwnTracksOwnerKeyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Ledger(le) => match le {
                pos_plugin_ledger::LedgerError::InvalidPrediction(_) => {
                    StatusCode::UNPROCESSABLE_ENTITY
                }
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            match self {
                Ok(value) => value,
                Err(error) => {
                    std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
                }
            }
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test value")))
        }
    }

    use super::*;
    use crate::{LedgerConfig, LedgerGateway, EVENT_BUS_CAPACITY};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        ids::{EntityId, TimelineId},
    };
    use pos_plugin_ledger::LedgerStore;
    use pos_runtime::ErasureExecutionHostV1;
    use pos_store::{open_store, StoreConfig};
    use std::path::PathBuf;
    use tower::ServiceExt;

    fn test_world_body() -> EntityId {
        EntityId::from_ulid(ulid::Ulid::from_string("01J38AE3E964B9281A2ADF6FDB").test_ok())
    }

    fn test_action_actor() -> EntityId {
        EntityId::from_ulid(ulid::Ulid::from_string("01J38AE3E965B9281A2ADF6FDB").test_ok())
    }

    fn test_app() -> Router {
        let gw = Gateway::new_with_world_bodies(
            open_store(StoreConfig::Memory).test_ok(),
            [test_world_body()],
        );
        router(AppState {
            gateway: gw,
            ledger_view: LedgerView::default(),
            ledger_write: LedgerWriteMode::Disabled,
        })
    }

    /// A host-owned Gateway whose only human action path is authenticated
    /// Principal authorization plus atomic host admission.
    fn action_test_app() -> Router {
        let host = ErasureExecutionHostV1::open_verified_empty(
            StoreConfig::Memory,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .test_ok();
        let gateway = crate::gateway_with_erasure_host_and_authorization(
            host,
            [test_world_body()],
            crate::authorization::test_authorization_for(test_action_actor()),
        )
        .test_ok();
        router(AppState {
            gateway,
            ledger_view: LedgerView::default(),
            ledger_write: LedgerWriteMode::Disabled,
        })
    }

    async fn host_cursor_fixture(name: &str) -> (Gateway, Router, String, String) {
        let host = ErasureExecutionHostV1::open_verified_empty(
            StoreConfig::Memory,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .test_ok();
        let gateway = Gateway::new_with_erasure_host(host).test_ok();
        let timeline = gateway.create_timeline(name).await.test_ok();
        let app = router(AppState {
            gateway: gateway.clone(),
            ledger_view: LedgerView::default(),
            ledger_write: LedgerWriteMode::Disabled,
        });
        (
            gateway,
            app,
            timeline.id().to_string(),
            EntityId::new().to_string(),
        )
    }

    fn test_app_with_body_limit(max_body_bytes: usize) -> Router {
        let gw = Gateway::new(open_store(StoreConfig::Memory).test_ok());
        build_router(
            AppState {
                gateway: gw,
                ledger_view: LedgerView::default(),
                ledger_write: LedgerWriteMode::Disabled,
            },
            max_body_bytes,
        )
    }

    fn authority_test_app(actor: EntityId) -> Router {
        let gateway = Gateway::new_with_world_bodies_and_authorization(
            open_store(StoreConfig::Memory).test_ok(),
            [],
            crate::authorization::test_authorization_for(actor),
        );
        router(AppState {
            gateway,
            ledger_view: LedgerView::default(),
            ledger_write: LedgerWriteMode::Disabled,
        })
    }

    fn world_action_payload(actor: &str, body: &str, marker: u8) -> serde_json::Value {
        json!({
            "actor_entity_id": actor,
            "body_entity_id": body,
            "action_kind": "impulse",
            "params": [f64::from(marker), 0.0],
            "action_scope": 0,
            "catalogue_version": 1,
            "tick": u64::from(marker)
        })
    }

    #[tokio::test]
    async fn versioned_action_contract_validates_typed_payload_and_rejects_legacy() {
        let app = action_test_app();
        let (_, created) = json_request(
            app.clone(),
            "POST",
            "/v1/timelines",
            Some(json!({"name": "versioned-actions"})),
        )
        .await;
        let path = format!("/v1/timelines/{}/actions", created["id"].as_str().test_ok());
        let actor = test_action_actor().to_string();
        let body = test_world_body().to_string();
        let payload = world_action_payload(&actor, &body, 1);
        let request = json!({
            "entity_id": actor,
            "event_type": "world.action.v1",
            "capability": "world.action.v1.submit",
            "payload": payload,
        });
        let (status, event) = json_request(app.clone(), "POST", &path, Some(request.clone())).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(event["event_type"], "world.action.v1");
        assert_eq!(event["payload"][0], json!([87, 65, 67, 49]));
        assert_eq!(event["payload"][1], 1);
        assert_eq!(event["entity"], actor);
        assert_eq!(
            event["payload"][2],
            json!(test_action_actor().inner().to_bytes())
        );
        assert_eq!(
            event["payload"][3],
            json!(test_world_body().inner().to_bytes())
        );
        assert_eq!(event["payload"][4], "impulse");
        assert_eq!(event["payload"][5], json!([130, 249, 60, 0, 249, 0, 0]));
        assert_eq!(event["payload"][6], 0);
        assert_eq!(event["payload"][7], 1);
        assert_eq!(event["payload"][8], 1);

        let mut target_velocity = request.clone();
        target_velocity["payload"]["action_kind"] = json!("target_velocity");
        let (status, _) = json_request(app.clone(), "POST", &path, Some(target_velocity)).await;
        assert_eq!(status, StatusCode::CREATED);

        for (field, value, expected) in [
            ("event_type", json!("world.action"), StatusCode::BAD_REQUEST),
            (
                "capability",
                json!("world.action.submit"),
                StatusCode::FORBIDDEN,
            ),
        ] {
            let mut rejected = request.clone();
            rejected[field] = value;
            let (status, _) = json_request(app.clone(), "POST", &path, Some(rejected)).await;
            assert_eq!(status, expected);
        }
        for (field, value) in [
            ("actor_entity_id", json!(EntityId::new().to_string())),
            ("body_entity_id", json!(EntityId::new().to_string())),
            ("body_entity_id", json!("not-an-id")),
            ("action_kind", json!("unsupported")),
            ("action_scope", json!(1)),
            ("catalogue_version", json!(2)),
            ("params", json!([0xff])),
            ("params", json!([1, 2])),
            ("params", json!([0x18, 1])),
            ("params", json!([0xf9, 0x7e, 0])),
            ("params", json!([0xf9, 0x7c, 0])),
            ("params", json!([0x81, 0xf9, 0xfc, 0])),
            ("params", json!([0xa1, 0xf9, 0x7e, 0, 1])),
            ("params", json!([0xa1, 1, 0xf9, 0x7e, 0])),
            ("params", json!([0xc0, 0xf9, 0x7e, 0])),
            ("params", json!([0xa2, 2, 2, 1, 1])),
            ("params", json!([0xa2, 1, 1, 1, 2])),
            ("params", json!([1, 0.0])),
            ("params", json!([1.0, "0.0"])),
            ("params", json!([1.0])),
            ("params", json!([1.0, 0.0, 0.0])),
            ("params", json!([f64::MAX, 0.0])),
            ("params", json!([0.0, -f64::MAX])),
            ("tick", json!(-1)),
            ("unexpected", json!(true)),
        ] {
            let mut rejected = request.clone();
            rejected["payload"][field] = value;
            let (status, _) = json_request(app.clone(), "POST", &path, Some(rejected)).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{field}");
        }
        for (params, encoded) in [
            (json!([1.0, 0.0]), json!([130, 249, 60, 0, 249, 0, 0])),
            (json!([1.0, -0.0]), json!([130, 249, 60, 0, 249, 128, 0])),
            (
                json!([0.333_333_333_333_333_3, -0.0]),
                json!([130, 250, 62, 170, 170, 171, 249, 128, 0]),
            ),
        ] {
            let mut accepted = request.clone();
            accepted["payload"]["params"] = params;
            let (status, event) = json_request(app.clone(), "POST", &path, Some(accepted)).await;
            assert_eq!(status, StatusCode::CREATED);
            assert_eq!(event["payload"][5], encoded);
        }
    }

    fn spectator_test_app() -> Router {
        let host = ErasureExecutionHostV1::open_verified_empty(
            StoreConfig::Memory,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .test_ok();
        let gw = Gateway::new_with_erasure_host(host).test_ok();
        spectator_router(AppState {
            gateway: gw,
            ledger_view: LedgerView::default(),
            ledger_write: LedgerWriteMode::Disabled,
        })
    }

    #[tokio::test]
    async fn owntracks_route_is_enabled_only_by_the_explicit_router() {
        let response = router_for_addr(
            "127.0.0.1:0".parse().test_ok(),
            AppState {
                gateway: Gateway::new_with_owntracks_ingress_for_test(
                    pos_store::memory::MemoryStore::new(),
                    [0; 32],
                ),
                ledger_view: LedgerView::default(),
                ledger_write: LedgerWriteMode::Disabled,
            },
        )
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/bridges/owntracks")
                .body(Body::empty())
                .test_ok(),
        )
        .await
        .test_ok();
        assert_eq!(response.status(), StatusCode::OK);
    }

    fn test_app_with_ledger_view(ledger_view: LedgerView) -> Router {
        router(AppState {
            gateway: Gateway::new(open_store(StoreConfig::Memory).test_ok()),
            ledger_view,
            ledger_write: LedgerWriteMode::Disabled,
        })
    }

    fn ledger_source_dir(label: &str, prediction: Option<&str>) -> PathBuf {
        let source = std::env::temp_dir().join(format!(
            "piglor-gw-ledger-lib-{label}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&source).test_ok();
        if let Some(prediction) = prediction {
            let predictions = source.join("predictions");
            std::fs::create_dir_all(&predictions).test_ok();
            std::fs::write(
                predictions.join("01J3B0Y5ZK2J6MGK8D7QW3N0P9.toml"),
                prediction,
            )
            .test_ok();
        }
        source
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ledger_config_rejects_missing_source() {
        let source = std::env::temp_dir().join(format!(
            "piglor-gw-ledger-lib-missing-{}",
            std::process::id()
        ));
        drop(std::fs::remove_dir_all(&source));
        let Err(error) = LedgerConfig::new(Some(source), false).load("2026-07-29") else {
            std::panic::resume_unwind(Box::new("a configured missing Ledger source must fail"));
        };
        assert!(error.to_string().contains("No such file or directory"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ledger_config_enables_writes_for_configured_source() {
        let source = ledger_source_dir("ready", None);
        let (_, write_mode) = LedgerConfig::new(Some(source.clone()), true)
            .load("2026-07-29")
            .test_ok();
        drop(std::fs::remove_dir_all(source));
        assert!(matches!(write_mode, LedgerWriteMode::Ready(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ledger_config_distinguishes_unset_source_write_mode() {
        let (view, disabled) = LedgerConfig::new(None, false).load("2026-07-29").test_ok();
        let (_, unconfigured) = LedgerConfig::new(None, true).load("2026-07-29").test_ok();
        assert!(view.entries.is_empty());
        assert!(matches!(disabled, LedgerWriteMode::Disabled));
        assert!(matches!(unconfigured, LedgerWriteMode::Unconfigured));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ledger_config_rejects_invalid_source_data() {
        let source = ledger_source_dir("invalid", Some("not valid = ["));
        let Err(error) = LedgerConfig::new(Some(source.clone()), false).load("2026-07-29") else {
            std::panic::resume_unwind(Box::new("invalid configured Ledger data must fail"));
        };
        drop(std::fs::remove_dir_all(source));
        assert!(error.to_string().contains("TOML"));
    }

    async fn json_request(
        app: Router,
        method: &str,
        uri: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let builder = Request::builder().method(method).uri(uri);
        let req = if let Some(b) = body {
            builder
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&b).test_ok()))
                .test_ok()
        } else {
            builder.body(Body::empty()).test_ok()
        };
        let response = app.oneshot(req).await.test_ok();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_ok();
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn root_redirects_to_ledger_page() {
        let response = test_app()
            .oneshot(Request::builder().uri("/").body(Body::empty()).test_ok())
            .await
            .test_ok();
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(response.headers()["location"], "/ledger");
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn root_redirects_relatively_to_ledger() {
        let app = test_app();
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).test_ok())
            .await
            .test_ok();
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(response.headers()[axum::http::header::LOCATION], "/ledger");
        let target = app
            .oneshot(
                Request::builder()
                    .uri("/ledger")
                    .body(Body::empty())
                    .test_ok(),
            )
            .await
            .test_ok();
        assert_eq!(target.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn ledger_page_returns_html() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/ledger")
                    .body(Body::empty())
                    .test_ok(),
            )
            .await
            .test_ok();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-security-policy")
                .and_then(|value| value.to_str().ok()),
            Some(piglor_ledger::CONTENT_SECURITY_POLICY)
        );
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_ok();
        let html = String::from_utf8_lossy(&body);
        assert!(
            html.contains("<!DOCTYPE html>"),
            "Ledger page should return HTML: {html}"
        );
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn spectator_router_keeps_only_public_ledger_routes() {
        let app = spectator_test_app();
        for uri in ["/ledger", "/health", "/v1/ledger"] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).test_ok())
                .await
                .test_ok();
            assert_eq!(response.status(), StatusCode::OK, "{uri} must stay public");
        }

        let (status, _) = json_request(
            app.clone(),
            "POST",
            "/v1/timelines",
            Some(json!({"name": "private"})),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = json_request(
            app.clone(),
            "GET",
            "/v1/timelines/01J38AE3E964B9281A2ADF6FDB/events",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = json_request(
            app.clone(),
            "POST",
            "/v1/timelines/01J38AE3E964B9281A2ADF6FDB/actions",
            Some(json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = json_request(
            app.clone(),
            "POST",
            "/v1/timelines/01J38AE3E964B9281A2ADF6FDB/signals",
            Some(json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) =
            json_request(app, "POST", "/v1/ledger/predictions", Some(json!({}))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn health_ok() {
        let host = ErasureExecutionHostV1::open_verified_empty(
            StoreConfig::Memory,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .test_ok();
        let gateway = Gateway::new_with_erasure_host(host).test_ok();
        let (status, json) = json_request(
            router(AppState {
                gateway,
                ledger_view: LedgerView::default(),
                ledger_write: LedgerWriteMode::Disabled,
            }),
            "GET",
            "/health",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["ok"], true);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn health_reports_closed_erasure_host_unready() {
        let gateway = Gateway::new(open_store(StoreConfig::Memory).test_ok());
        let (status, json) = json_request(
            router(AppState {
                gateway,
                ledger_view: LedgerView::default(),
                ledger_write: LedgerWriteMode::Disabled,
            }),
            "GET",
            "/health",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(json["ok"], false);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn health_reports_executor_unready_after_shutdown() {
        let host = ErasureExecutionHostV1::open_verified_empty(
            StoreConfig::Memory,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .test_ok();
        let gateway = Gateway::new_with_erasure_host(host).test_ok();
        gateway.shutdown().await.test_ok();
        let (status, json) = json_request(
            router(AppState {
                gateway: gateway.clone(),
                ledger_view: LedgerView::default(),
                ledger_write: LedgerWriteMode::Disabled,
            }),
            "GET",
            "/health",
            None,
        )
        .await;
        drop(gateway);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(json["ok"], false);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn configured_source_is_consistent_between_html_and_json() {
        const PREDICTION: &str = "prediction_id = \"01J3B0Y5ZK2J6MGK8D7QW3N0P9\"\n\
title = \"Configured source fixture\"\n\
statement = \"A test prediction\"\n\
predicted_outcome = \"Yes\"\n\
confidence = 0.7\n\
made_at = \"2026-07-25T12:00:00Z\"\n\
resolve_by = \"2026-08-01\"\n\
osf_link = \"https://osf.io/example\"\n";
        let dir = ledger_source_dir("http-configured", Some(PREDICTION));
        let (ledger_view, _) = LedgerConfig::new(Some(dir.clone()), false)
            .load("2026-07-29")
            .test_ok();
        let app = test_app_with_ledger_view(ledger_view);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ledger")
                    .body(Body::empty())
                    .test_ok(),
            )
            .await
            .test_ok();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_ok();
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains("Configured source fixture"));

        let (status, json) = json_request(app, "GET", "/v1/ledger", None).await;
        drop(std::fs::remove_dir_all(dir));
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["domain"], "piglor.com");
        assert_eq!(json["path"], "/ledger");
        assert_eq!(json["ledger"][0]["id"], "01J3B0Y5ZK2J6MGK8D7QW3N0P9");
        assert_eq!(json["ledger"][0]["title"], "Configured source fixture");
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn get_ledger_ok() {
        let (status, json) = json_request(test_app(), "GET", "/v1/ledger", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["domain"], "piglor.com");
        assert_eq!(json["path"], "/ledger");
        assert!(json["ledger"].as_array().test_ok().is_empty());
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn http_action_poll_flow() {
        let app = action_test_app();
        let (status, created) = json_request(
            app.clone(),
            "POST",
            "/v1/timelines",
            Some(json!({"name": "live"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = created["id"].as_str().test_ok().to_owned();

        let entity = test_action_actor().to_string();
        let body = test_world_body().to_string();
        let (status, committed) = json_request(
            app.clone(),
            "POST",
            &format!("/v1/timelines/{id}/actions"),
            Some(json!({
                "entity_id": entity,
                "capability": "world.action.v1.submit",
                "payload": world_action_payload(&entity, &body, 1)
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        assert_eq!(committed["seq"], 1);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/timelines/{id}/events?from_seq=0&limit=10"))
                    .header("x-piglor-actor-entity", entity.clone())
                    .body(Body::empty())
                    .test_ok(),
            )
            .await
            .test_ok();
        assert_eq!(response.status(), StatusCode::OK);
        let listed: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .test_ok(),
        )
        .test_ok();
        assert_eq!(listed["events"].as_array().test_ok().len(), 1);
        assert_eq!(listed["events"][0]["event_type"], "world.action.v1");
        assert_eq!(listed["events"][0]["payload"][4], "impulse");
        assert!(listed["next_from_seq"].is_null());
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn identified_http_action_retries_are_idempotent_and_conflicts_are_visible() {
        let app = action_test_app();
        let (status, created) = json_request(
            app.clone(),
            "POST",
            "/v1/timelines",
            Some(json!({"name": "identified"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = created["id"].as_str().test_ok();
        let entity = test_action_actor().to_string();
        let body = test_world_body().to_string();
        let request = json!({
            "entity_id": entity,
            "capability": "world.action.v1.submit",
            "ingress_id": "device-1-42",
            "payload": world_action_payload(&entity, &body, 1)
        });
        let (status, first) = json_request(
            app.clone(),
            "POST",
            &format!("/v1/timelines/{id}/actions"),
            Some(request.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, retry) = json_request(
            app.clone(),
            "POST",
            &format!("/v1/timelines/{id}/actions"),
            Some(request),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(retry["id"], first["id"]);
        let (status, error) = json_request(
            app,
            "POST",
            &format!("/v1/timelines/{id}/actions"),
            Some(json!({
                "entity_id": entity,
                "capability": "world.action.v1.submit",
                "ingress_id": "device-1-42",
                "payload": world_action_payload(&entity, &body, 2)
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(error["error"].as_str().test_ok().contains("conflicts"));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn poll_is_paginated_and_rejects_pages_larger_than_the_maximum() {
        let app = test_app();
        let (status, created) = json_request(
            app.clone(),
            "POST",
            "/v1/timelines",
            Some(json!({"name": "paged"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = created["id"].as_str().test_ok();
        let entity = test_action_actor().to_string();
        for value in [0.1, 0.2, 0.3] {
            let (status, _) = json_request(
                app.clone(),
                "POST",
                &format!("/v1/timelines/{id}/signals"),
                Some(json!({
                    "entity_id": entity,
                    "dimension": "trust",
                    "value": value
                })),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
        }

        let (status, first) = json_request(
            app.clone(),
            "GET",
            &format!("/v1/timelines/{id}/events?from_seq=0&limit=2"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["events"].as_array().test_ok().len(), 2);
        assert_eq!(first["events"][0]["seq"], 1);
        assert_eq!(first["events"][1]["seq"], 2);
        assert_eq!(first["next_from_seq"], 3);

        let (status, second) = json_request(
            app.clone(),
            "GET",
            &format!("/v1/timelines/{id}/events?from_seq=3&limit=2"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second["events"].as_array().test_ok().len(), 1);
        assert_eq!(second["events"][0]["seq"], 3);
        assert!(second["next_from_seq"].is_null());

        let (status, _) = json_request(
            app,
            "GET",
            &format!(
                "/v1/timelines/{id}/events?from_seq=0&limit={}",
                crate::MAX_EVENTS_PER_POLL + 1
            ),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _) = json_request(
            test_app(),
            "GET",
            &format!("/v1/timelines/{id}/events?limit=0"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn host_event_cursor_rejects_stale_generation_and_wrong_timeline() {
        let (gateway, app, id, actor) = host_cursor_fixture("cursor-owner").await;
        for marker in 1..=2 {
            gateway
                .append_action(
                    &id,
                    &actor,
                    crate::EVENT_TYPE_ACTION,
                    &json!({"marker": marker}),
                )
                .await
                .test_ok();
        }
        let (status, first) = json_request(
            app.clone(),
            "GET",
            &format!("/v1/timelines/{id}/events?limit=1"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let cursor = first["next_cursor"].as_str().test_ok();
        let (status, second) = json_request(
            app.clone(),
            "GET",
            &format!("/v1/timelines/{id}/events?cursor={cursor}&limit=1"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second["events"][0]["seq"], 2);

        let other = gateway.create_timeline("cursor-other").await.test_ok();
        assert!(gateway
            .read_events_page(&TimelineId::new().to_string(), 0, 1)
            .await
            .is_err());
        drop(gateway);
        let (status, _) = json_request(
            app.clone(),
            "GET",
            &format!("/v1/timelines/{id}/events?cursor={cursor}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let (status, _) = json_request(
            app.clone(),
            "GET",
            &format!("/v1/timelines/{}/events?cursor={cursor}", other.id()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        for invalid in [
            "bad".to_owned(),
            format!("v1.{}.{id}.2", "z".repeat(64)),
            format!("v1.{}z.{id}.2", "a".repeat(63)),
            format!("v1.{}.{id}.2", "a".repeat(63)),
            format!("v1.{}.{id}.0", "a".repeat(64)),
            format!("v2.{}.{id}.2", "a".repeat(64)),
        ] {
            let (status, _) = json_request(
                app.clone(),
                "GET",
                &format!("/v1/timelines/{id}/events?cursor={invalid}"),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        let (status, _) = json_request(
            app.clone(),
            "GET",
            &format!(
                "/v1/timelines/{id}/events?cursor=v1.{}.{id}.2",
                "A".repeat(64)
            ),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let (status, _) = json_request(
            app,
            "GET",
            &format!("/v1/timelines/{id}/events?cursor={cursor}&from_seq=2"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn public_gateway_cursor_rejects_stale_generation_and_wrong_timeline() {
        let (gateway, _, id, actor) = host_cursor_fixture("public-cursor-owner").await;
        for marker in 1..=2 {
            gateway
                .append_action(
                    &id,
                    &actor,
                    crate::EVENT_TYPE_ACTION,
                    &json!({"marker": marker}),
                )
                .await
                .test_ok();
        }
        let first = gateway.read_events_page(&id, 0, 1).await.test_ok();
        let cursor = first.next_cursor.test_ok();
        let second = gateway
            .read_events_page_after(&id, cursor, 1)
            .await
            .test_ok();
        assert_eq!(second.events[0].seq.as_u64(), 2);

        let other = gateway
            .create_timeline("public-cursor-other")
            .await
            .test_ok();
        assert!(matches!(
            gateway
                .read_events_page_after(&other.id().to_string(), cursor, 1)
                .await,
            Err(GatewayError::InvalidId(_))
        ));
        assert!(matches!(
            gateway.read_events_page_after(&id, cursor, 1).await,
            Err(GatewayError::StaleEventCursor)
        ));
    }

    #[tokio::test]
    async fn host_cursor_tracks_the_response_byte_limit() {
        let (gateway, app, id, actor) = host_cursor_fixture("cursor-byte-limit").await;
        let payload = "x".repeat(240 * 1024);
        for _ in 0..5 {
            gateway
                .append_action(
                    &id,
                    &actor,
                    crate::EVENT_TYPE_ACTION,
                    &json!({"data": &payload}),
                )
                .await
                .test_ok();
        }
        drop(gateway);
        let (status, first) =
            json_request(app, "GET", &format!("/v1/timelines/{id}/events"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["events"].as_array().test_ok().len(), 1);
        assert!(first["next_cursor"].is_string());
        assert_eq!(first["next_from_seq"], 2);
    }

    #[tokio::test]
    async fn admitted_boundary_event_remains_pollable_with_host_cursor() {
        let (gateway, app, id, actor) = host_cursor_fixture("cursor-admission-boundary").await;
        let mut boundary = None;
        for length in (MAX_EVENTS_RESPONSE_BYTES / 8 - 128)..=(MAX_EVENTS_RESPONSE_BYTES / 8) {
            let payload = json!({"data": "\0".repeat(length)});
            let bytes = crate::json_to_cbor(&payload);
            let view = EventView {
                id: "0".repeat(26),
                entity: actor.clone(),
                event_type: crate::EVENT_TYPE_ACTION.to_owned(),
                seq: u64::MAX,
                payload: Some(payload.clone()),
                payload_hex: crate::hex_encode(bytes.as_slice()),
            };
            // Keep the wire-size oracle independent of the cursor formatter.
            let worst_page = json!({
                "events": [view],
                "next_from_seq": u64::MAX,
                "next_cursor": format!("v1.{}.{}.{}", "f".repeat(64), "0".repeat(26), u64::MAX),
            });
            if serde_json::to_vec(&worst_page).test_ok().len() <= MAX_EVENTS_RESPONSE_BYTES {
                boundary = Some(payload);
            } else {
                break;
            }
        }
        let payload = boundary.test_ok();
        gateway
            .append_action(&id, &actor, crate::EVENT_TYPE_ACTION, &payload)
            .await
            .test_ok();
        gateway
            .append_action(
                &id,
                &actor,
                crate::EVENT_TYPE_ACTION,
                &json!({"marker": "next"}),
            )
            .await
            .test_ok();
        drop(gateway);
        let (status, first) = json_request(
            app,
            "GET",
            &format!("/v1/timelines/{id}/events?limit=1"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["events"].as_array().test_ok().len(), 1);
        assert_eq!(first["next_from_seq"], 2);
        assert!(first["next_cursor"].is_string());
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn malformed_event_queries_return_json_bad_request_envelopes() {
        let id = TimelineId::new();
        for query in [
            "from_seq=-1",
            "from_seq=18446744073709551616",
            "limit=-1",
            "limit=18446744073709551616",
            "limit=abc",
            "from_seq",
            "from_seq=0&from_seq=1",
            "unknown=1",
        ] {
            let (status, body) = json_request(
                test_app(),
                "GET",
                &format!("/v1/timelines/{id}/events?{query}"),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
            assert!(
                body["error"]
                    .as_str()
                    .is_some_and(|message| message.contains("query")),
                "{query}: {body}"
            );
        }
    }

    fn app_with_preloaded_bytes(payloads: Vec<Vec<u8>>) -> (Router, String) {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        Gateway::bind_test_erasure_gate(store.as_mut());
        let timeline = store.create_timeline("shared-writer").test_ok();
        let drafts: Vec<EventDraft> = payloads
            .into_iter()
            .map(|payload| {
                EventDraft::new(
                    EntityId::new(),
                    Kind::new("shared.event"),
                    CanonicalBytes::from_vec(payload),
                )
            })
            .collect();
        store.append(timeline.id(), &drafts).test_ok();
        let app = router(AppState {
            gateway: Gateway::new(store),
            ledger_view: LedgerView::default(),
            ledger_write: LedgerWriteMode::Disabled,
        });
        (app, timeline.id().to_string())
    }

    fn app_with_preloaded_payloads(payload_lengths: &[usize]) -> (Router, String) {
        app_with_preloaded_bytes(
            payload_lengths
                .iter()
                .map(|length| vec![0; *length])
                .collect(),
        )
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn response_byte_budget_paginates_events_from_shared_writers() {
        let (app, id) = app_with_preloaded_payloads(&[180 * 1024, 180 * 1024, 180 * 1024]);
        let (status, first) = json_request(
            app.clone(),
            "GET",
            &format!("/v1/timelines/{id}/events"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["events"].as_array().test_ok().len(), 2);
        assert_eq!(first["next_from_seq"], 3);
        assert!(serialized_len(&first) <= MAX_EVENTS_RESPONSE_BYTES);

        let (status, exhausted) = json_request(
            app,
            "GET",
            &format!("/v1/timelines/{id}/events?from_seq=3"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(exhausted["events"].as_array().test_ok().len(), 1);
        assert!(exhausted["next_from_seq"].is_null());
        assert!(serialized_len(&exhausted) <= MAX_EVENTS_RESPONSE_BYTES);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn single_shared_event_over_response_budget_returns_json_413() {
        let (app, id) = app_with_preloaded_payloads(&[600 * 1024]);
        let (status, body) =
            json_request(app, "GET", &format!("/v1/timelines/{id}/events"), None).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(body["error"]
            .as_str()
            .is_some_and(|message| message.contains("payload")));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn high_expansion_shared_event_under_payload_cap_returns_json_413() {
        let mut payload = Vec::new();
        ciborium::into_writer(&"\0".repeat(160 * 1024), &mut payload).test_ok();
        assert!(payload.len() <= crate::MAX_EVENT_PAYLOAD_BYTES);
        let (app, id) = app_with_preloaded_bytes(vec![payload]);
        let (status, body) =
            json_request(app, "GET", &format!("/v1/timelines/{id}/events"), None).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(body["error"]
            .as_str()
            .is_some_and(|message| message.contains("response")));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn http_signal_and_bad_action_type() {
        let app = action_test_app();
        let (status, created) = json_request(
            app.clone(),
            "POST",
            "/v1/timelines",
            Some(json!({"name": "s"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = created["id"].as_str().test_ok().to_owned();
        let entity = test_action_actor().to_string();

        let (status, _) = json_request(
            app.clone(),
            "POST",
            &format!("/v1/timelines/{id}/signals"),
            Some(json!({
                "entity_id": entity,
                "dimension": "trust",
                "value": 0.4
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        let (status, err) = json_request(
            app,
            "POST",
            &format!("/v1/timelines/{id}/actions"),
            Some(json!({
                "entity_id": test_action_actor().to_string(),
                "event_type": "world.observation",
                "capability": "world.action.v1.submit",
                "payload": {}
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(err["error"]
            .as_str()
            .test_ok()
            .contains("unknown event type"));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn invalid_timeline_id_is_bad_request() {
        let (status, _) =
            json_request(test_app(), "GET", "/v1/timelines/not-ulid/events", None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn missing_timeline_is_not_found() {
        let id = TimelineId::new().to_string();
        let (status, _) = json_request(
            test_app(),
            "GET",
            &format!("/v1/timelines/{id}/events"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn missing_timeline_action_and_signal_not_found() {
        let id = TimelineId::new().to_string();
        let entity = test_action_actor().to_string();
        let (status, _) = json_request(
            action_test_app(),
            "POST",
            &format!("/v1/timelines/{id}/actions"),
            Some(json!({
                "entity_id": entity,
                "capability": "world.action.v1.submit",
                "payload": world_action_payload(&entity, &test_world_body().to_string(), 1)
            })),
        )
        .await;
        // The host's erasure fence admits nothing for an unknown Timeline.
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        let (status, _) = json_request(
            test_app(),
            "POST",
            &format!("/v1/timelines/{id}/signals"),
            Some(json!({
                "entity_id": EntityId::new().to_string(),
                "dimension": "trust",
                "value": 0.1
            })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn authority_bound_read_requires_actor_header_and_uses_stable_errors() {
        let actor = test_action_actor();
        let app = authority_test_app(actor);
        let (_status, created) = json_request(
            app.clone(),
            "POST",
            "/v1/timelines",
            Some(json!({"name": "authority-read"})),
        )
        .await;
        let id = created["id"].as_str().test_ok();

        let (status, missing) = json_request(
            app.clone(),
            "GET",
            &format!("/v1/timelines/{id}/events?limit=1"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(missing["error"], "authorization unavailable");

        let request = Request::builder()
            .method("GET")
            .uri("/v1/timelines/not-a-timeline/events?limit=1")
            .header("x-piglor-actor-entity", actor.to_string())
            .body(Body::empty())
            .test_ok();
        let response = app.clone().oneshot(request).await.test_ok();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let wrong = EntityId::new().to_string();
        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/timelines/{id}/events?limit=1"))
            .header("x-piglor-actor-entity", wrong)
            .body(Body::empty())
            .test_ok();
        let response = app.clone().oneshot(request).await.test_ok();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let request = Request::builder()
            .method("GET")
            .uri(format!("/v1/timelines/{id}/events?limit=1"))
            .header("x-piglor-actor-entity", actor.to_string())
            .body(Body::empty())
            .test_ok();
        let response = app.oneshot(request).await.test_ok();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn malformed_json_body_is_rejected() {
        let app = action_test_app();
        let (status, created) = json_request(
            app.clone(),
            "POST",
            "/v1/timelines",
            Some(json!({"name": "m"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = created["id"].as_str().test_ok();

        let req = Request::builder()
            .method("POST")
            .uri(format!("/v1/timelines/{id}/actions"))
            .header("content-type", "application/json")
            .body(Body::from("{not json"))
            .test_ok();
        let response = app.oneshot(req).await.test_ok();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn create_timeline_store_error_maps() {
        use pos_core::{
            clock::Seq,
            event::EventDraft,
            ids::TimelineId,
            store::{EventStore, SeqRange},
            timeline::{Timeline, TimelineMeta},
            CoreError,
        };
        use tokio::sync::broadcast;

        struct FailCreate;
        impl EventStore for FailCreate {
            fn create_timeline(&mut self, _: &str) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("nope".into()))
            }
            fn append(
                &mut self,
                _: TimelineId,
                _: &[EventDraft],
            ) -> Result<Vec<pos_core::event::Event>, CoreError> {
                Ok(vec![])
            }
            fn read(
                &self,
                _: TimelineId,
                _: SeqRange,
            ) -> Result<Vec<pos_core::event::Event>, CoreError> {
                Ok(vec![])
            }
            fn fork(&mut self, _: TimelineId, _: Seq, _: &str) -> Result<Timeline, CoreError> {
                Ok(Timeline::new(TimelineMeta::root("f")))
            }
            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                Ok(vec![])
            }
            fn get_timeline(&self, _: TimelineId) -> Result<Option<Timeline>, CoreError> {
                Ok(None)
            }
        }

        let (status, _) = json_request(
            router(AppState {
                gateway: Gateway {
                    store: crate::executor::StoreExecutor::new(Box::new(FailCreate)),
                    bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
                    limits: crate::GatewayLimits::LOCAL_DEFAULT,
                    owntracks_enabled: false,
                    consent_authority: pos_core::ConsentAuthority::new(),
                    consent_history_locks: crate::new_consent_history_locks(),
                    pending_consent_cleanup: crate::new_pending_consent_cleanup(),
                    action_registry: crate::gateway_action_registry(),
                    authorization: None,
                },
                ledger_view: LedgerView::default(),
                ledger_write: LedgerWriteMode::Disabled,
            }),
            "POST",
            "/v1/timelines",
            Some(json!({"name": "x"})),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn signal_invalid_entity_is_bad_request() {
        let app = test_app();
        let (status, created) = json_request(
            app.clone(),
            "POST",
            "/v1/timelines",
            Some(json!({"name": "s"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = created["id"].as_str().test_ok().to_owned();
        let (status, _) = json_request(
            app,
            "POST",
            &format!("/v1/timelines/{id}/signals"),
            Some(json!({
                "entity_id": "not-a-ulid",
                "dimension": "trust",
                "value": 0.4
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn oversized_body_returns_payload_too_large() {
        let app = test_app_with_body_limit(32);
        let req = Request::builder()
            .method("POST")
            .uri("/v1/timelines")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"name":"this name is way too long for the limit"}"#,
            ))
            .test_ok();
        let response = app.oneshot(req).await.test_ok();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn into_response_status_mapping() {
        use axum::response::IntoResponse;
        let r = GatewayError::InvalidId("x".into()).into_response();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        let r = GatewayError::InvalidPageLimit {
            maximum: crate::MAX_EVENTS_PER_POLL,
        }
        .into_response();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        let r = GatewayError::InvalidEventsQuery("bad".into()).into_response();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        let r = GatewayError::InvalidAuthorizationRequest.into_response();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        let r = GatewayError::ConsentRevocationFenceMismatch.into_response();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        let r = GatewayError::TimelineLimitReached { maximum: 1 }.into_response();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        let r = GatewayError::EventLimitReached { maximum: 1 }.into_response();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        let r = GatewayError::StoreExecutorSaturated.into_response();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        let r = GatewayError::EventPayloadTooLarge { maximum: 1 }.into_response();
        assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let r = GatewayError::EventMetadataTooLarge {
            field: "event_type",
            maximum: 1,
        }
        .into_response();
        assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let r = GatewayError::ForkDepthTooLarge { maximum: 1 }.into_response();
        assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let r = GatewayError::EventResponseTooLarge { maximum: 1 }.into_response();
        assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let r = GatewayError::EventReadTimeExceeded { maximum_micros: 1 }.into_response();
        assert_eq!(r.status(), StatusCode::GATEWAY_TIMEOUT);
        let r = GatewayError::CompatibilityReadTruncated { maximum: 1 }.into_response();
        assert_eq!(r.status(), StatusCode::CONFLICT);
        let r = GatewayError::ResourceUnavailable.into_response();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        let r = GatewayError::Store(CoreError::Storage("boom".into())).into_response();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let r = GatewayError::Store(CoreError::ErasureContainmentUnavailable).into_response();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        let r = GatewayError::Store(CoreError::ErasureAccessFrozen).into_response();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let r = GatewayError::Store(CoreError::TimelineNotFound(TimelineId::new())).into_response();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        let r = GatewayError::StoreExecutorClosed.into_response();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        let r = GatewayError::LedgerWriteDisabled.into_response();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let r = GatewayError::ActionAuthorizationUnavailable.into_response();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let r = GatewayError::AuthorizationDenied.into_response();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let r = GatewayError::ActionRegistry(pos_runtime::RuntimeError::UnknownEventType(
            "world.unknown".into(),
        ))
        .into_response();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let r = GatewayError::LedgerUnavailable.into_response();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        let r = GatewayError::Ledger(pos_plugin_ledger::LedgerError::InvalidPrediction(
            "bad".into(),
        ))
        .into_response();
        assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let r = GatewayError::Ledger(pos_plugin_ledger::LedgerError::InvalidResolution(
            "bad".into(),
        ))
        .into_response();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let r = GatewayError::Ledger(pos_plugin_ledger::LedgerError::UnknownPrediction(
            "x".into(),
        ))
        .into_response();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn bus_capacity_constant_exposed() {
        const {
            assert!(EVENT_BUS_CAPACITY >= 16);
        }
    }

    fn sample_prediction_body() -> serde_json::Value {
        json!({
            "title": "Test",
            "statement": "Something will happen",
            "predicted_outcome": "Yes",
            "confidence": 0.75,
            "made_at": "2026-07-26T12:00:00Z",
            "resolve_by": "2026-08-01",
            "osf_link": "https://osf.io/test"
        })
    }

    fn test_app_with_ledger(store: Box<dyn LedgerStore + Send>) -> Router {
        router(AppState {
            gateway: Gateway::new(open_store(StoreConfig::Memory).test_ok()),
            ledger_view: LedgerView::default(),
            ledger_write: LedgerWriteMode::Ready(LedgerGateway::new(store)),
        })
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn post_ledger_prediction_gate_off_returns_403() {
        let app = test_app();
        let (status, _json) = json_request(
            app,
            "POST",
            "/v1/ledger/predictions",
            Some(sample_prediction_body()),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn post_ledger_prediction_gate_on_no_ledger_returns_503() {
        let app = router(AppState {
            gateway: Gateway::new(open_store(StoreConfig::Memory).test_ok()),
            ledger_view: LedgerView::default(),
            ledger_write: LedgerWriteMode::Unconfigured,
        });
        let (status, json) = json_request(
            app,
            "POST",
            "/v1/ledger/predictions",
            Some(sample_prediction_body()),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(json["error"]
            .as_str()
            .test_ok()
            .contains("ledger store not available"));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn post_ledger_prediction_validation_error_returns_422() {
        let dir = std::env::temp_dir().join(format!("piglor-gw-ledger-{}", std::process::id()));
        drop(std::fs::create_dir_all(&dir));
        let store: Box<dyn LedgerStore + Send> =
            Box::new(pos_plugin_ledger::TomlLedgerStore::new(dir.clone()));
        let app = test_app_with_ledger(store);
        let mut body = sample_prediction_body();
        body["title"] = json!("");
        let (status, _json) = json_request(app, "POST", "/v1/ledger/predictions", Some(body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        drop(std::fs::remove_dir_all(dir));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn post_ledger_prediction_success_returns_201() {
        let dir = std::env::temp_dir().join(format!("piglor-gw-ledger-ok-{}", std::process::id()));
        drop(std::fs::create_dir_all(&dir));
        let store: Box<dyn LedgerStore + Send> =
            Box::new(pos_plugin_ledger::TomlLedgerStore::new(dir.clone()));
        let app = test_app_with_ledger(store);
        let (status, json) = json_request(
            app,
            "POST",
            "/v1/ledger/predictions",
            Some(sample_prediction_body()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let prediction_id = json["prediction_id"].as_str().test_ok();
        assert!(!prediction_id.is_empty());
        drop(std::fs::remove_dir_all(dir));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn post_ledger_prediction_register_fails_returns_500() {
        struct FailRegister;
        impl LedgerStore for FailRegister {
            fn load(
                &self,
                _today: &str,
            ) -> Result<pos_plugin_ledger::Ledger, pos_plugin_ledger::LedgerError> {
                Ok(pos_plugin_ledger::Ledger::default())
            }
            fn register(
                &mut self,
                _prediction: NewPrediction,
            ) -> Result<String, pos_plugin_ledger::LedgerError> {
                Err(pos_plugin_ledger::LedgerError::Store(
                    "disk full".to_owned(),
                ))
            }
            fn find_resolve_status(
                &self,
                _prediction_id: &str,
            ) -> Result<pos_plugin_ledger::ResolveStatus, pos_plugin_ledger::LedgerError>
            {
                Ok(pos_plugin_ledger::ResolveStatus {
                    found_prediction: false,
                    already_resolved: false,
                })
            }
            fn persist_resolve(
                &mut self,
                _outcome: pos_plugin_ledger::LedgerOutcome,
            ) -> Result<(), pos_plugin_ledger::LedgerError> {
                Ok(())
            }
        }
        let app = test_app_with_ledger(Box::new(FailRegister));
        let (status, _json) = json_request(
            app,
            "POST",
            "/v1/ledger/predictions",
            Some(sample_prediction_body()),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn post_ledger_prediction_unknown_fields_ignored() {
        let dir = std::env::temp_dir().join(format!("piglor-gw-ledger-uf-{}", std::process::id()));
        drop(std::fs::create_dir_all(&dir));
        let store: Box<dyn LedgerStore + Send> =
            Box::new(pos_plugin_ledger::TomlLedgerStore::new(dir.clone()));
        let app = test_app_with_ledger(store);
        let mut body = sample_prediction_body();
        body["unknown_field"] = json!("ignored");
        let (status, _json) = json_request(app, "POST", "/v1/ledger/predictions", Some(body)).await;
        assert_eq!(status, StatusCode::CREATED);
        drop(std::fs::remove_dir_all(dir));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn post_ledger_prediction_error_response_has_error_field() {
        let dir = std::env::temp_dir().join(format!("piglor-gw-ledger-err-{}", std::process::id()));
        drop(std::fs::create_dir_all(&dir));
        let store: Box<dyn LedgerStore + Send> =
            Box::new(pos_plugin_ledger::TomlLedgerStore::new(dir.clone()));
        let app = test_app_with_ledger(store);

        let mut unknown_body = sample_prediction_body();
        unknown_body["confidence"] = json!(2.0);

        let (_status, err_resp) =
            json_request(app, "POST", "/v1/ledger/predictions", Some(unknown_body)).await;

        assert!(
            err_resp["error"].as_str().is_some(),
            "domain validation should produce an error field, got: {err_resp:?}"
        );
        drop(std::fs::remove_dir_all(dir));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn post_action_rejects_missing_or_invalid_capability() {
        let app = action_test_app();
        let (_status, created) = json_request(
            app.clone(),
            "POST",
            "/v1/timelines",
            Some(json!({"name": "actions-test"})),
        )
        .await;
        let id = created["id"].as_str().test_ok();
        let entity = test_action_actor().to_string();

        let (status, err) = json_request(
            app.clone(),
            "POST",
            &format!("/v1/timelines/{id}/actions"),
            Some(json!({
                "entity_id": entity,
                "capability": "wrong.capability",
                "payload": {"value": 1}
            })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(err["error"].as_str().test_ok().contains("capability"));

        let other_actor = EntityId::new().to_string();
        let (status, err) = json_request(
            app,
            "POST",
            &format!("/v1/timelines/{id}/actions"),
            Some(json!({
                "entity_id": other_actor,
                "capability": "world.action.v1.submit",
                "payload": world_action_payload(&other_actor, &test_world_body().to_string(), 7)
            })),
        )
        .await;
        // Another acting Entity is outside this Principal's authority; the
        // error is identical, so it does not enumerate which check failed.
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(err["error"], "authorization denied");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn action_rejected_into_response_status_mappings() {
        let cases = vec![
            (
                pos_core::ActionRejected::UnknownEventType,
                StatusCode::BAD_REQUEST,
            ),
            (
                pos_core::ActionRejected::CapabilityNotGranted,
                StatusCode::FORBIDDEN,
            ),
            (
                pos_core::ActionRejected::InvalidActorEntityId,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                pos_core::ActionRejected::DomainValidationFailed("err".into()),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                pos_core::ActionRejected::PayloadTooLarge {
                    size: 5000,
                    max: 4096,
                },
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ];

        for (rejected, expected_status) in cases {
            let resp = GatewayError::ActionRejected(rejected).into_response();
            assert_eq!(resp.status(), expected_status);
        }
    }
}
