//! Axum HTTP surface for [`crate::Gateway`] (WebSocket stream deferred — HTTP poll is MVP).

use crate::{
    ActionRequest, CreateTimelineRequest, EventView, EventsQuery, Gateway, GatewayError,
    LedgerEntryView, SignalRequest, MAX_HTTP_BODY_BYTES,
};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use pos_core::CoreError;
use serde_json::json;

/// Shared axum state.
#[derive(Clone)]
pub struct AppState {
    pub gateway: Gateway,
}

/// Build the MVP router (ADR-014 route table; WS deferred to follow-up).
pub fn router(state: AppState) -> Router {
    build_router(state, MAX_HTTP_BODY_BYTES)
}

fn build_router(state: AppState, max_body_bytes: usize) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/ledger", get(get_ledger))
        .route("/v1/timelines", post(create_timeline))
        .route("/v1/timelines/{id}/events", get(list_events))
        .route("/v1/timelines/{id}/actions", post(post_action))
        .route("/v1/timelines/{id}/signals", post(post_signal))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(json!({ "ok": true }))
}

async fn get_ledger() -> impl IntoResponse {
    let entries = vec![
        LedgerEntryView {
            id: "01J38AE3E964B9281A2ADF6FDB".to_owned(),
            scenario: "places".to_owned(),
            title: "Kyoto vs Osaka Weekend Decision Preview".to_owned(),
            predicted_outcome: "Kyoto".to_owned(),
            confidence: 0.875,
            status: "Resolved".to_owned(),
            brier_score: Some(0.30),
            verification_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_owned(),
            timestamp: "2026-07-22T15:40:00Z".to_owned(),
        },
        LedgerEntryView {
            id: "01J39CE3E964B92813CA8D8FC0".to_owned(),
            scenario: "work".to_owned(),
            title: "Remote-First vs Office-First Quarterly Work Structure".to_owned(),
            predicted_outcome: "Remote-First".to_owned(),
            confidence: 0.950,
            status: "Resolved".to_owned(),
            brier_score: Some(0.18),
            verification_hash: "f686771a109d4b0596e0f04a55ed394c87f2f1815ec2a34cccdc616bf1694eac"
                .to_owned(),
            timestamp: "2026-07-22T18:20:00Z".to_owned(),
        },
        LedgerEntryView {
            id: "01J3A4E3E964B92812FBB1CC9D".to_owned(),
            scenario: "policy".to_owned(),
            title: "Rapid Decentralized Pods vs Centralized Approval Shift".to_owned(),
            predicted_outcome: "Rapid Decentralized Pods".to_owned(),
            confidence: 0.880,
            status: "Pending".to_owned(),
            brier_score: None,
            verification_hash: "3a4e3e964b92812fbb1cc9d5a16d451b38ae3e964b9281a2adf6fdb6c97554b5"
                .to_owned(),
            timestamp: "2026-07-23T08:00:00Z".to_owned(),
        },
    ];
    Json(json!({
        "domain": "piglor.com",
        "path": "/ledger",
        "ledger": entries,
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
    Query(q): Query<EventsQuery>,
) -> Result<impl IntoResponse, GatewayError> {
    let events = state.gateway.read_events_from(&id, q.from_seq).await?;
    let views: Vec<EventView> = events.iter().map(EventView::from).collect();
    Ok(Json(json!({ "events": views })))
}

async fn post_action(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<ActionRequest>,
) -> Result<impl IntoResponse, GatewayError> {
    let event = state
        .gateway
        .append_action(&id, &body.entity_id, &body.event_type, &body.payload)
        .await?;
    Ok((StatusCode::CREATED, Json(EventView::from(&event))))
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
    Ok((StatusCode::CREATED, Json(EventView::from(&event))))
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let status = match &self {
            GatewayError::InvalidId(_) | GatewayError::UnsupportedAction(_) => {
                StatusCode::BAD_REQUEST
            }
            GatewayError::Store(CoreError::TimelineNotFound(_)) => StatusCode::NOT_FOUND,
            GatewayError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = Json(json!({ "error": self.to_string() }));
        (status, body).into_response()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::EVENT_BUS_CAPACITY;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use pos_core::ids::{EntityId, TimelineId};
    use pos_store::{open_store, StoreConfig};
    use tower::ServiceExt;

    fn test_app() -> Router {
        let gw = Gateway::new(open_store(StoreConfig::Memory).unwrap());
        router(AppState { gateway: gw })
    }

    fn test_app_with_body_limit(max_body_bytes: usize) -> Router {
        let gw = Gateway::new(open_store(StoreConfig::Memory).unwrap());
        build_router(AppState { gateway: gw }, max_body_bytes)
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
                .body(Body::from(serde_json::to_vec(&b).unwrap()))
                .unwrap()
        } else {
            builder.body(Body::empty()).unwrap()
        };
        let response = app.oneshot(req).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn health_ok() {
        let (status, json) = json_request(test_app(), "GET", "/health", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["ok"], true);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn get_ledger_ok() {
        let (status, json) = json_request(test_app(), "GET", "/v1/ledger", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["domain"], "piglor.com");
        assert_eq!(json["path"], "/ledger");
        assert_eq!(json["ledger"].as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn http_action_poll_flow() {
        let app = test_app();
        let (status, created) = json_request(
            app.clone(),
            "POST",
            "/v1/timelines",
            Some(json!({"name": "live"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = created["id"].as_str().unwrap().to_owned();

        let entity = EntityId::new().to_string();
        let (status, _) = json_request(
            app.clone(),
            "POST",
            &format!("/v1/timelines/{id}/actions"),
            Some(json!({
                "entity_id": entity,
                "payload": {"dx": 1}
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        let (status, listed) = json_request(
            app,
            "GET",
            &format!("/v1/timelines/{id}/events?from_seq=0"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed["events"].as_array().unwrap().len(), 1);
        assert_eq!(listed["events"][0]["payload"]["dx"], 1);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn http_signal_and_bad_action_type() {
        let app = test_app();
        let (status, created) = json_request(
            app.clone(),
            "POST",
            "/v1/timelines",
            Some(json!({"name": "s"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = created["id"].as_str().unwrap().to_owned();
        let entity = EntityId::new().to_string();

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
                "entity_id": EntityId::new().to_string(),
                "event_type": "world.observation",
                "payload": {}
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(err["error"].as_str().unwrap().contains("unsupported"));
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
        let entity = EntityId::new().to_string();
        let (status, _) = json_request(
            test_app(),
            "POST",
            &format!("/v1/timelines/{id}/actions"),
            Some(json!({
                "entity_id": entity,
                "payload": {}
            })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

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
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn malformed_json_body_is_rejected() {
        let app = test_app();
        let (status, created) = json_request(
            app.clone(),
            "POST",
            "/v1/timelines",
            Some(json!({"name": "m"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let id = created["id"].as_str().unwrap();

        let req = Request::builder()
            .method("POST")
            .uri(format!("/v1/timelines/{id}/actions"))
            .header("content-type", "application/json")
            .body(Body::from("{not json"))
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
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
        use std::sync::Arc;
        use tokio::sync::{broadcast, Mutex};

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

        let gw = Gateway {
            store: Arc::new(Mutex::new(Box::new(FailCreate))),
            bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
        };
        let app = router(AppState { gateway: gw });
        let (status, _) =
            json_request(app, "POST", "/v1/timelines", Some(json!({"name": "x"}))).await;
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
        let id = created["id"].as_str().unwrap().to_owned();
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
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn into_response_status_mapping() {
        use axum::response::IntoResponse;
        let r = GatewayError::InvalidId("x".into()).into_response();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        let r = GatewayError::Store(CoreError::Storage("boom".into())).into_response();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn bus_capacity_constant_exposed() {
        const {
            assert!(EVENT_BUS_CAPACITY >= 16);
        }
    }
}
