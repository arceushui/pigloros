//! Axum HTTP surface for [`crate::Gateway`] (WebSocket stream deferred — HTTP poll is MVP).

use crate::{
    ActionRequest, CreateTimelineRequest, EventView, EventsQuery, Gateway, GatewayError,
    SignalRequest, MAX_HTTP_BODY_BYTES,
};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use piglor_ledger::{render_html, LedgerView};
use pos_core::CoreError;
use pos_plugin_ledger::{LedgerStore, NewPrediction};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Shared handle for the mutable ledger store (curated or live tier).
pub(crate) type SharedLedgerStore = Arc<Mutex<Box<dyn LedgerStore + Send>>>;

/// Wraps a [`LedgerStore`] behind a mutex, matching the pattern of [`Gateway`].
#[derive(Clone)]
pub struct LedgerGateway {
    store: SharedLedgerStore,
}

impl LedgerGateway {
    /// Wrap a boxed [`LedgerStore`] in a shared, locked handle.
    #[must_use]
    pub fn new(store: Box<dyn LedgerStore + Send>) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
        }
    }

    /// Register a new prediction through the store, under lock.
    ///
    /// # Errors
    /// Returns [`GatewayError::Ledger`] on store failure.
    pub async fn register(&self, prediction: NewPrediction) -> Result<String, GatewayError> {
        let mut guard = self.store.lock().await;
        Ok(guard.register(prediction)?)
    }
}

/// Write-mode state machine — replaces the `bool`+`Option` pair.
#[derive(Clone)]
pub enum LedgerWriteMode {
    /// Gate off — return 403.
    Disabled,
    /// Gate on but no adapter plugged in — return 503.
    Unconfigured,
    /// Gate on with a live adapter behind a mutex.
    Ready(LedgerGateway),
}

/// Shared axum state.
#[derive(Clone)]
pub struct AppState {
    pub gateway: Gateway,
    pub ledger_view: LedgerView,
    pub ledger_write: LedgerWriteMode,
}

/// Build the MVP router (ADR-014 route table; WS deferred to follow-up).
pub fn router(state: AppState) -> Router {
    build_router(state, MAX_HTTP_BODY_BYTES)
}

fn build_router(state: AppState, max_body_bytes: usize) -> Router {
    Router::new()
        .route("/", get(root_page))
        .route("/health", get(health))
        .route("/v1/ledger", get(get_ledger))
        .route("/v1/ledger/predictions", post(post_ledger_prediction))
        .route("/v1/timelines", post(create_timeline))
        .route("/v1/timelines/{id}/events", get(list_events))
        .route("/v1/timelines/{id}/actions", post(post_action))
        .route("/v1/timelines/{id}/signals", post(post_signal))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .with_state(state)
}

async fn root_page(State(state): State<AppState>) -> impl IntoResponse {
    let html = render_html(&state.ledger_view, None);
    Html(html)
}

async fn health() -> impl IntoResponse {
    Json(json!({ "ok": true }))
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

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let status = match &self {
            GatewayError::InvalidId(_) | GatewayError::UnsupportedAction(_) => {
                StatusCode::BAD_REQUEST
            }
            GatewayError::Store(CoreError::TimelineNotFound(_)) => StatusCode::NOT_FOUND,
            GatewayError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
            GatewayError::LedgerWriteDisabled => StatusCode::FORBIDDEN,
            GatewayError::LedgerUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            GatewayError::Ledger(le) => match le {
                pos_plugin_ledger::LedgerError::InvalidPrediction(_) => {
                    StatusCode::UNPROCESSABLE_ENTITY
                }
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
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
        router(AppState {
            gateway: gw,
            ledger_view: LedgerView::default(),
            ledger_write: LedgerWriteMode::Disabled,
        })
    }

    fn test_app_with_body_limit(max_body_bytes: usize) -> Router {
        let gw = Gateway::new(open_store(StoreConfig::Memory).unwrap());
        build_router(
            AppState {
                gateway: gw,
                ledger_view: LedgerView::default(),
                ledger_write: LedgerWriteMode::Disabled,
            },
            max_body_bytes,
        )
    }

    fn test_app_with_ledger_view(ledger_view: LedgerView) -> Router {
        router(AppState {
            gateway: Gateway::new(open_store(StoreConfig::Memory).unwrap()),
            ledger_view,
            ledger_write: LedgerWriteMode::Disabled,
        })
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
    async fn root_page_returns_html() {
        let response = test_app()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let html = String::from_utf8_lossy(&body);
        assert!(
            html.contains("<!DOCTYPE html>"),
            "root page should return HTML: {html}"
        );
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
    async fn get_ledger_uses_configured_view() {
        let ledger_view = LedgerView {
            entries: vec![pos_plugin_ledger::LedgerEntryView {
                id: "configured-id".to_owned(),
                title: "Configured title".to_owned(),
                statement: "Configured statement".to_owned(),
                predicted_outcome: "Configured outcome".to_owned(),
                confidence: 0.75,
                scenario: Some("configured-scenario".to_owned()),
                status: "pending".to_owned(),
                brier_score: None,
                made_at: "2026-07-29T00:00:00Z".to_owned(),
                resolve_by: "2026-08-01".to_owned(),
                resolved_at: None,
                outcome: None,
                osf_link: "https://osf.io/configured".to_owned(),
            }],
            n_pending: 1,
            n_overdue: 0,
            n_resolved: 0,
            mean_brier: None,
            warnings: Vec::new(),
        };
        let (status, json) = json_request(
            test_app_with_ledger_view(ledger_view),
            "GET",
            "/v1/ledger",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["domain"], "piglor.com");
        assert_eq!(json["path"], "/ledger");
        assert_eq!(json["ledger"][0]["id"], "configured-id");
        assert_eq!(json["ledger"][0]["title"], "Configured title");
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
        let app = router(AppState {
            gateway: gw,
            ledger_view: LedgerView::default(),
            ledger_write: LedgerWriteMode::Disabled,
        });
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
        let r = GatewayError::LedgerWriteDisabled.into_response();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
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
            gateway: Gateway::new(open_store(StoreConfig::Memory).unwrap()),
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
            gateway: Gateway::new(open_store(StoreConfig::Memory).unwrap()),
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
            .unwrap()
            .contains("ledger store not available"));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn post_ledger_prediction_validation_error_returns_422() {
        let dir = std::env::temp_dir().join(format!("piglor-gw-ledger-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let store: Box<dyn LedgerStore + Send> =
            Box::new(pos_plugin_ledger::TomlLedgerStore::new(dir.clone()));
        let app = test_app_with_ledger(store);
        let mut body = sample_prediction_body();
        body["title"] = json!("");
        let (status, _json) = json_request(app, "POST", "/v1/ledger/predictions", Some(body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn post_ledger_prediction_success_returns_201() {
        let dir = std::env::temp_dir().join(format!("piglor-gw-ledger-ok-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
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
        let prediction_id = json["prediction_id"].as_str().unwrap();
        assert!(!prediction_id.is_empty());
        let _ = std::fs::remove_dir_all(dir);
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
        let _ = std::fs::create_dir_all(&dir);
        let store: Box<dyn LedgerStore + Send> =
            Box::new(pos_plugin_ledger::TomlLedgerStore::new(dir.clone()));
        let app = test_app_with_ledger(store);
        let mut body = sample_prediction_body();
        body["unknown_field"] = json!("ignored");
        let (status, _json) = json_request(app, "POST", "/v1/ledger/predictions", Some(body)).await;
        assert_eq!(status, StatusCode::CREATED);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn post_ledger_prediction_error_response_has_error_field() {
        let dir = std::env::temp_dir().join(format!("piglor-gw-ledger-err-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
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
        let _ = std::fs::remove_dir_all(dir);
    }
}
