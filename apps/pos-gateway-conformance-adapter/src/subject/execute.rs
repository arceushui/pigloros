//! The execution of the sub-cases (requirements sections 3 to 5): one fresh in-process Gateway
//! per sub-case, its exchanges sent as raw HTTP requests through the public `router` and
//! `spectator_router` of that Gateway, with no socket.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderName, HeaderValue, Method, Request, Uri};
use axum::Router;
use piglor_gateway::{
    gateway_with_erasure_host_and_authorization, router, spectator_router, AppState, Gateway,
    GatewayAuthorization, LedgerWriteMode, LocalAuthenticationAdapter, VolatileDenialEvidence,
};
use piglor_ledger::LedgerView;
use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    AuthorityGranteeV1, AuthorityPersistenceHostV1, AuthorityPersistenceStateV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, CapabilityGrantDraftV1, CapabilityGrantV1,
    CapabilityScopeDraftV1, CapabilityScopeV1, EntityId, ErasureRecoveryLimitsV1, Hash,
    PrincipalRefV1, Seq, TimelineId, WallTime,
};
use pos_reference::evaluator::ResourceUsage;
use pos_runtime::ErasureExecutionHostV1;
use pos_store::StoreConfig;
use serde_json::{json, Map, Value};
use tokio::runtime::Runtime;
use tower::ServiceExt;
use ulid::Ulid;

use super::payload::{CompositionV2, ExchangeV2, MethodV2, RouterV2, SubCaseV2, TIMELINE_SLOT};
use super::{ACTOR_ENTITY_ID, BODY_ENTITY_ID};
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
    let gateway = {
        let _context = runtime.enter();
        compose(subcase.composition)
    };
    gateway.map_or(unavailable, |gateway| {
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

/// The Gateway of a composition (requirements section 3).
fn compose(composition: CompositionV2) -> Option<Gateway> {
    match composition {
        CompositionV2::Open => host().and_then(|host| Gateway::new_with_erasure_host(host).ok()),
        CompositionV2::Authorized => fixture_authorization()
            .zip(entity(BODY_ENTITY_ID))
            .zip(host())
            .and_then(|((authorization, body), host)| {
                gateway_with_erasure_host_and_authorization(host, [body], authorization).ok()
            }),
    }
}

/// The fixture-only authority of the `authorized` composition: one Principal whose single
/// grant lets the fixture actor read Timeline Events and grants no action. It is never a
/// source of production authority (ADR-108).
fn fixture_authorization() -> Option<GatewayAuthorization> {
    PrincipalRefV1::try_new([1; 16], "gateway.fixture")
        .ok()
        .zip(entity(ACTOR_ENTITY_ID))
        .and_then(|(principal, actor)| authenticated(&principal).zip(read_grant(principal, actor)))
        .and_then(|(authenticated, grant)| pinned_authorization(authenticated, &grant))
}

fn authenticated(principal: &PrincipalRefV1) -> Option<AuthenticatedPrincipalResultV1> {
    AssuranceLevelV1::try_new(1).ok().and_then(|assurance| {
        AuthenticatedPrincipalResultV1::try_from_draft(AuthenticatedPrincipalDraftV1 {
            principal: principal.clone(),
            adapter_id: "fixture".to_owned(),
            assurance,
            issued_at: WallTime::from_micros(1),
            expires_at: WallTime::from_micros(u64::MAX),
            binding_digest: Hash::from_bytes([2; 32]),
        })
        .ok()
    })
}

fn read_grant(principal: PrincipalRefV1, actor: EntityId) -> Option<CapabilityGrantV1> {
    CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: vec!["timeline.events".to_owned()],
        actions: vec!["read".to_owned()],
        purposes: vec!["read".to_owned()],
        audiences: vec!["gateway".to_owned()],
        actor_entity_ids: vec![actor],
        subject_ids: Vec::new(),
        participant_ids: Vec::new(),
        plugin_id: None,
        principal_roles: vec![AuthorityRoleV1::Actor],
        max_uses: 1,
        budget: 1,
        environment_constraints: Vec::new(),
    })
    .ok()
    .and_then(|scope| {
        CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
            grant_id: Hash::from_bytes([5; 32]),
            grantor: principal.clone(),
            grantee: AuthorityGranteeV1::Principal(principal),
            trust_domain: "gateway.fixture".to_owned(),
            scope,
            valid_from_position: Seq::from_u64(1),
            valid_until_position: Seq::from_u64(50),
            parent_grant_id: None,
            delegation_depth: 0,
            max_delegation_depth: 0,
            permitted_delegate_classes: Vec::new(),
            consent_references: Vec::new(),
            policy_revision: Hash::from_bytes([4; 32]),
            issuance_timeline: TimelineId::from_ulid(Ulid(1)),
            issuance_seq: Seq::from_u64(1),
            revocation_epoch: 0,
            revocation_fence: None,
            authority_registry_digest: Hash::from_bytes([3; 32]),
        })
        .ok()
    })
}

fn pinned_authorization(
    authenticated: AuthenticatedPrincipalResultV1,
    grant: &CapabilityGrantV1,
) -> Option<GatewayAuthorization> {
    grant
        .binding_digest()
        .ok()
        .and_then(|binding| {
            AuthorityRegistrySnapshotV1::try_new(
                Hash::from_bytes([3; 32]),
                vec![authenticated.registry_binding_digest()],
                vec![binding],
                Vec::new(),
            )
            .ok()
        })
        .and_then(|registry| {
            let host = AuthorityPersistenceHostV1::new(&registry);
            let mut state = AuthorityPersistenceStateV1::new();
            host.authorize_grant(grant)
                .ok()
                .and_then(|permit| state.issue_grant(permit, grant.clone()).ok())
                .and_then(|_| state.view(grant.grant_id()).ok())
                .map(|view| {
                    GatewayAuthorization::new(
                        Arc::new(LocalAuthenticationAdapter::new(authenticated)),
                        view,
                        registry,
                        Arc::new(VolatileDenialEvidence::default()),
                    )
                })
        })
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
