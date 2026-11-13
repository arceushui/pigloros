//! The execution of the sub-cases (requirements sections 3 to 5): one fresh in-process Gateway
//! per sub-case, its exchanges sent as raw HTTP requests through the public `router` and
//! `spectator_router` of that Gateway, with no socket.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::Body;
use axum::http::{header, HeaderName, HeaderValue, Method, Request, Uri};
use axum::Router;
use piglor_gateway::local_principal::{
    local_gateway, provision_local_principal, LocalPrincipalProvisionV1,
};
use piglor_gateway::startup::{open_recovered_erasure_host, GatewayHostStoreV1};
use piglor_gateway::{
    router, spectator_router, AppState, Gateway, GatewayOperationV1, LedgerWriteMode,
};
use piglor_ledger::LedgerView;
use pos_core::{EntityId, ErasureRecoveryLimitsV1, PrincipalRefV1};
use pos_reference::evaluator::ResourceUsage;
use pos_runtime::{ErasureCoordinatorCompositionV1, ErasureExecutionHostV1};
use pos_store::{sqlite::SqliteStore, StoreConfig};
use serde_json::{json, Map, Value};
use tokio::runtime::Runtime;
use tower::ServiceExt;
use ulid::Ulid;

use super::payload::{CompositionV2, ExchangeV2, MethodV2, RouterV2, SubCaseV2, TIMELINE_SLOT};
use super::ACTOR_ENTITY_ID;
use crate::observation_v1;

/// The header an exchange with `actor` sends.
const ACTOR_HEADER: &str = "x-piglor-actor-entity";

/// The largest response body read; a Gateway response is at most 1 MiB.
const RESPONSE_LIMIT: usize = 2_097_152;

/// The executed sub-cases of one attempt.
pub(super) struct CaseRunV2 {
    records: Vec<Value>,
    matched: bool,
    usage: ResourceUsage,
}

impl CaseRunV2 {
    /// Whether every exchange of every sub-case matched and no canary was present.
    pub(super) const fn matched(&self) -> bool {
        self.matched
    }

    /// The measured usage of the attempt.
    pub(super) const fn usage(&self) -> ResourceUsage {
        self.usage
    }

    /// The `canonical-output` record of the attempt: RFC 8785 JSON and one LF.
    pub(super) fn output_record(&self, case_id: &str, family: &str) -> Vec<u8> {
        let record = json!({
            "case_id": case_id,
            "claim_layer": "gateway-client-conformance",
            "family": family,
            "oracle": {"kind": "canonical-output"},
            "output": {"subcases": self.records},
        });
        let mut bytes = record.to_string().into_bytes();
        bytes.push(b'\n');
        bytes
    }
}

/// One executed sub-case.
struct SubCaseRunV2 {
    record: Value,
    matched: bool,
    steps: u64,
    output_bytes: u64,
    events: u64,
}

/// Run every sub-case on its own Gateway. Without an async runtime nothing runs, and the
/// empty record set matches no oracle.
pub(super) fn run_case(
    subcases: &[SubCaseV2],
    capabilities: &[String],
    independent: bool,
) -> CaseRunV2 {
    let unavailable = CaseRunV2 {
        records: Vec::new(),
        matched: false,
        usage: ResourceUsage::default(),
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_or(unavailable, |runtime| {
            let runs: Vec<SubCaseRunV2> = subcases
                .iter()
                .map(|subcase| run_subcase(&runtime, subcase, capabilities, independent))
                .collect();
            CaseRunV2 {
                matched: runs.iter().all(|run| run.matched),
                usage: ResourceUsage {
                    execution_steps: runs.iter().map(|run| run.steps).sum(),
                    output_bytes: runs.iter().map(|run| run.output_bytes).sum(),
                    event_count: runs.iter().map(|run| run.events).sum(),
                    ..ResourceUsage::default()
                },
                records: runs.into_iter().map(|run| run.record).collect(),
            }
        })
}

fn run_subcase(
    runtime: &Runtime,
    subcase: &SubCaseV2,
    capabilities: &[String],
    independent: bool,
) -> SubCaseRunV2 {
    let unavailable = SubCaseRunV2 {
        record: json!({"id": subcase.id, "exchanges": []}),
        matched: false,
        steps: 0,
        output_bytes: 0,
        events: 0,
    };
    // The Gateway schedules its maintenance on the runtime it is built in.
    let composed = {
        let _context = runtime.enter();
        compose(subcase.composition)
    };
    composed.map_or(unavailable, |(gateway, _store)| {
        runtime.block_on(exchange_all(gateway, subcase, capabilities, independent))
    })
}

fn entity(text: &str) -> Option<EntityId> {
    Ulid::from_string(text).ok().map(EntityId::from_ulid)
}

fn host() -> Option<ErasureExecutionHostV1> {
    ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Memory,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )
    .ok()
}

/// The Gateway of a composition (requirements section 3), with the store file it serves when
/// it has one.
///
/// `open` is the unprotected in-process harness Gateway. `authorized` is the production serve
/// composition (#1361): a fixture Local Principal document is provisioned into a fresh SQLite
/// store with the production `provision_local_principal`, and the Gateway is composed over that
/// store by `local_gateway`, which requires the recorded Principal for every protected
/// operation.
fn compose(composition: CompositionV2) -> Option<(Gateway, Option<ScratchStore>)> {
    match composition {
        CompositionV2::Open => host()
            .and_then(|host| Gateway::unprotected_for_harness(host).ok())
            .map(|gateway| (gateway, None)),
        CompositionV2::Authorized => provisioned_store().and_then(|store| {
            open_recovered_erasure_host(
                StoreConfig::Sqlite {
                    path: store.path_text(),
                },
                GatewayHostStoreV1::Standard,
                &ErasureCoordinatorCompositionV1::closed(),
            )
            .and_then(|host| local_gateway(host, None))
            .ok()
            .map(|gateway| (gateway, Some(store)))
        }),
    }
}

/// A fresh SQLite store holding the fixture Local Principal of the `authorized` composition:
/// it may create Timelines and read their Events as the fixture actor, and holds no action or
/// signal grant. Only its document is fixture data.
fn provisioned_store() -> Option<ScratchStore> {
    let store = ScratchStore::new();
    PrincipalRefV1::try_new([1; 16], "gateway.fixture")
        .ok()
        .zip(entity(ACTOR_ENTITY_ID))
        .and_then(|(principal, actor)| {
            LocalPrincipalProvisionV1::try_new(
                &principal,
                [actor],
                [
                    GatewayOperationV1::CREATE_TIMELINE,
                    GatewayOperationV1::READ_EVENTS,
                ],
            )
            .ok()
        })
        .and_then(|provision| {
            SqliteStore::open(&store.path_text())
                .ok()
                .and_then(|mut opened| provision_local_principal(&mut opened, &provision).ok())
        })
        .map(|_| store)
}

/// One sub-case's SQLite file in the temporary directory, removed with its journal files when
/// the sub-case ends.
struct ScratchStore {
    path: PathBuf,
}

impl ScratchStore {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        Self {
            path: std::env::temp_dir().join(format!(
                "pos-gateway-conformance-{}-{unique}-{}.sqlite",
                std::process::id(),
                Ulid::new()
            )),
        }
    }

    fn path_text(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

impl Drop for ScratchStore {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let mut path = self.path.clone().into_os_string();
            path.push(suffix);
            drop(std::fs::remove_file(path));
        }
    }
}

/// The header that carries the idempotency key of every request.
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// The raw HTTP request of an exchange, with `{timeline}` replaced by the captured ID. Every
/// request carries the sub-case ID as its idempotency key; routes without one ignore it.
fn request(exchange: &ExchangeV2, timeline: Option<&str>, key: &str) -> Request<Body> {
    let body = exchange
        .body
        .as_ref()
        .map_or_else(Body::empty, |value| Body::from(value.to_string()));
    let mut request = Request::new(body);
    *request.method_mut() = match exchange.method {
        MethodV2::Get => Method::GET,
        MethodV2::Post => Method::POST,
    };
    let path = exchange
        .path
        .replace(TIMELINE_SLOT, timeline.unwrap_or_default());
    *request.uri_mut() = Uri::try_from(path).unwrap_or_default();
    if exchange.body.is_some() {
        request.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }
    if exchange.actor() {
        request
            .headers_mut()
            .insert(ACTOR_HEADER, HeaderValue::from_static(ACTOR_ENTITY_ID));
    }
    request.headers_mut().extend(
        HeaderValue::from_str(key)
            .ok()
            .map(|value| (HeaderName::from_static(IDEMPOTENCY_KEY_HEADER), value)),
    );
    request
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The loopback and public-listener routers of one Gateway.
fn routers(gateway: &Gateway) -> (Router, Router) {
    let state = AppState {
        gateway: gateway.clone(),
        ledger_view: LedgerView::default(),
        ledger_write: LedgerWriteMode::Disabled,
    };
    (router(state.clone()), spectator_router(state))
}

/// Send every exchange of a sub-case in order and record its observations.
async fn exchange_all(
    gateway: Gateway,
    subcase: &SubCaseV2,
    capabilities: &[String],
    independent: bool,
) -> SubCaseRunV2 {
    let (loopback, spectator) = routers(&gateway);
    let mut timeline: Option<String> = None;
    let mut observations = Vec::with_capacity(subcase.exchanges.len());
    let mut run = SubCaseRunV2 {
        record: Value::Null,
        matched: true,
        steps: 0,
        output_bytes: 0,
        events: 0,
    };
    let mut present = false;
    for exchange in &subcase.exchanges {
        let route = exchange.route();
        let observation = if capabilities.iter().any(|held| held == route.capability()) {
            let service = match exchange.router {
                RouterV2::Loopback => loopback.clone(),
                RouterV2::Spectator => spectator.clone(),
            };
            let Ok(response) = service
                .oneshot(request(exchange, timeline.as_deref(), &subcase.id))
                .await;
            let status = response.status().as_u16();
            let bytes = axum::body::to_bytes(response.into_body(), RESPONSE_LIMIT)
                .await
                .unwrap_or_default();
            run.steps += 1;
            run.output_bytes += u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            run.events += u64::from(status == 201 && route.commits());
            if exchange.router == RouterV2::Spectator {
                present |= subcase
                    .canary
                    .as_deref()
                    .is_some_and(|canary| contains(&bytes, canary.as_bytes()));
            }
            let parsed = serde_json::from_slice::<Value>(&bytes).ok();
            if exchange.captures() {
                timeline = parsed
                    .as_ref()
                    .and_then(|value| value.get("id"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
            observation_v1(status, parsed)
        } else {
            json!({"refused": "capability-denied"})
        };
        run.matched &= observation == exchange.expect;
        observations.push(observation);
    }
    drop(gateway.shutdown().await);
    let mut record = Map::new();
    record.insert("id".to_owned(), Value::from(subcase.id.as_str()));
    if subcase.canary.is_some() {
        record.insert("prohibited_data_present".to_owned(), Value::from(present));
    }
    if independent {
        let digest = blake3::hash(&serde_json::to_vec(&observations).unwrap_or_default());
        record.insert("digest".to_owned(), Value::from(digest.to_hex().as_str()));
    }
    record.insert("exchanges".to_owned(), Value::Array(observations));
    run.matched &= !present;
    run.record = Value::Object(record);
    run
}
