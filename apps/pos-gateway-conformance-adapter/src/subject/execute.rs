//! The execution of the sub-cases (requirements sections 3 to 5): one fresh in-process Gateway
//! per sub-case, its exchanges sent as raw HTTP requests through the public `router` and
//! `spectator_router` of that Gateway, with no socket.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::Body;
use axum::http::{header, HeaderName, HeaderValue, Method, Request, Uri};
use axum::Router;
use piglor_gateway::local_erasure_composition::LocalErasureServeV1;
use piglor_gateway::local_principal::{
    local_gateway, provision_on_host, LocalConsentDraftV1, LocalConsentGrantDraftV1,
    LocalPrincipalProvisionV1,
};
use piglor_gateway::mode_profile::{
    bind_gateway_mode_v1, GatewayModeBindingV1, GatewayModeProfileIdV1, GatewayServeCompositionV1,
};
use piglor_gateway::startup::{open_recovered_erasure_host, GatewayHostStoreV1};
use piglor_gateway::{
    router, spectator_router, AppState, Gateway, GatewayOperationV1, LedgerWriteMode,
};
use piglor_ledger::LedgerView;
use pos_core::{EntityId, ErasureRecoveryLimitsV1, PrincipalRefV1};
use pos_reference::evaluator::ResourceUsage;
use pos_runtime::{ErasureCoordinatorCompositionV1, ErasureExecutionHostV1};
use pos_store::StoreConfig;
use serde_json::{json, Map, Value};
use tokio::runtime::Runtime;
use tower::ServiceExt;
use ulid::Ulid;

use super::erasure_fixture::{hold_subject, local_erasure};
use super::payload::{
    CaptureV2, CompositionV2, ExchangeV2, MethodV2, RouteV2, RouterV2, SubCaseV2, CONSENT_SLOT,
    ERASURE_SLOT, ROOM_SLOT, TIMELINE_SLOT,
};
use super::{ACTOR_ENTITY_ID, GOVERNANCE_RECORD_ID};
use crate::{observation_v1, substitute_captured_v1};

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
/// it has one. The `authorized-erasure` compositions also compose the Local erasure authority
/// over that store (#1449), and `authorized-erasure-closed` the closed one.
///
/// `open` is the unprotected in-process harness Gateway. `authorized`,
/// `authorized-air-gapped`, `authorized-consented` and `authorized-rooms` are the production
/// serve composition (#1361, #1360, #309, #303): the first `serve` binds a fresh `SQLite` store
/// to the Local or the Air-Gapped execution mode, a fixture Local Principal document is
/// provisioned into it with the production `provision_on_host`, and the Gateway is composed
/// over that store by `local_gateway` under that binding, which requires the recorded
/// Principal for every protected operation.
fn compose(composition: CompositionV2) -> Option<(Gateway, Option<ScratchStore>)> {
    composition
        .mode()
        .map_or_else(open_gateway, |id| authorized_gateway(id, composition))
}

/// The unprotected in-process harness Gateway of the `open` composition.
fn open_gateway() -> Option<(Gateway, Option<ScratchStore>)> {
    host()
        .and_then(|host| Gateway::unprotected_for_harness(host).ok())
        .map(|gateway| (gateway, None))
}

/// The production serve composition over a fresh store bound to the execution mode `id`,
/// whose fixture Principal is the document of `composition`.
fn authorized_gateway(
    id: GatewayModeProfileIdV1,
    composition: CompositionV2,
) -> Option<(Gateway, Option<ScratchStore>)> {
    let store = ScratchStore::new();
    let closed = ErasureCoordinatorCompositionV1::closed();
    store_host(&store, &closed)
        .and_then(|mut host| bind_mode(&mut host, id))
        .and_then(|_| provision_store(&store, composition))
        .and_then(|()| erasure_authority(&store, composition))
        .and_then(|erasure| store_host(&store, erasure.composition()))
        .and_then(|mut host| {
            bind_mode(&mut host, id)
                .filter(|_| !composition.holds_erasure() || hold_fixture_subject(&mut host))
                .and_then(|mode| local_gateway(host, None, &mode).ok())
        })
        .map(|gateway| (gateway, Some(store)))
}

/// The erasure authority of `composition` over `store`: the Local erasure authority under
/// the fixture bundle of an `authorized-erasure` composition (#1449), else the closed one.
fn erasure_authority(
    store: &ScratchStore,
    composition: CompositionV2,
) -> Option<LocalErasureServeV1> {
    composition.erasure_bundle_expiry().map_or_else(
        || Some(LocalErasureServeV1::closed()),
        |expiry| {
            std::fs::create_dir(store.directory())
                .ok()
                .and_then(|()| local_erasure(&store.path_text(), &store.directory(), expiry))
        },
    )
}

/// Admit one erasure of the fixture actor's subject on `host` before it serves.
fn hold_fixture_subject(host: &mut ErasureExecutionHostV1) -> bool {
    fixture_principal()
        .zip(entity(ACTOR_ENTITY_ID))
        .and_then(|(principal, actor)| hold_subject(host, &principal, actor))
        .is_some()
}

/// The fixture Local Principal.
fn fixture_principal() -> Option<PrincipalRefV1> {
    PrincipalRefV1::try_new([1; 16], "gateway.fixture").ok()
}

/// The recovered production host of `store` with the erasure authority `composition`.
fn store_host(
    store: &ScratchStore,
    composition: &ErasureCoordinatorCompositionV1,
) -> Option<ErasureExecutionHostV1> {
    open_recovered_erasure_host(
        StoreConfig::Sqlite {
            path: store.path_text(),
        },
        GatewayHostStoreV1::Standard,
        composition,
    )
    .ok()
}

/// Bind the store of `host` to the execution mode `id` over a loopback composition, as every
/// `serve` does: the first binds the empty store, a later one attaches to that binding.
fn bind_mode(
    host: &mut ErasureExecutionHostV1,
    id: GatewayModeProfileIdV1,
) -> Option<GatewayModeBindingV1> {
    bind_gateway_mode_v1(
        id,
        GatewayServeCompositionV1 {
            tcp_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            owntracks_owner_key: None,
            fork_admission_socket: None,
            ledger_source: None,
            network_grants: BTreeSet::new(),
        },
        host,
    )
    .ok()
}

/// The fixture Local Principal document of an authorized composition, as the fixture actor:
/// its operations, its one consent and its governance record.
///
/// `authorized` and `authorized-air-gapped` may create Timelines, read their Events and read
/// their own Session, and hold no action, signal or network grant. `authorized-consented` may
/// also revoke a consent, and its one consent, by the fixture actor to itself, governs Timeline
/// creation. `authorized-rooms` may create Timelines, read its Session, revoke a consent and
/// create, derive and read Scenario Rooms; it records the fixture governance record, and its
/// one consent governs Timeline creation and permits export, so a room may name it as its
/// `privacy_export_ref`. The `authorized-erasure` compositions (#1449) may request and read
/// their own erasures and nothing else.
fn document(composition: CompositionV2, actor: EntityId) -> FixtureDocument {
    let consent = |export_permitted| LocalConsentDraftV1 {
        subject: actor,
        grantee: actor,
        grants: vec![LocalConsentGrantDraftV1 {
            purpose: "operation".to_owned(),
            data_categories: vec!["timeline".to_owned()],
            export_permitted,
        }],
    };
    match composition {
        CompositionV2::AuthorizedConsented | CompositionV2::AuthorizedRooms => {
            consented_document(composition == CompositionV2::AuthorizedRooms, &consent)
        }
        CompositionV2::AuthorizedErasure
        | CompositionV2::AuthorizedErasureHeld
        | CompositionV2::AuthorizedErasureExpired
        | CompositionV2::AuthorizedErasureClosed => (
            vec![
                GatewayOperationV1::REQUEST_ERASURE,
                GatewayOperationV1::READ_ERASURE,
            ],
            None,
            None,
        ),
        CompositionV2::Open | CompositionV2::Authorized | CompositionV2::AuthorizedAirGapped => (
            vec![
                GatewayOperationV1::CREATE_TIMELINE,
                GatewayOperationV1::READ_EVENTS,
                GatewayOperationV1::READ_SESSION,
            ],
            None,
            None,
        ),
    }
}

/// The document of `authorized-rooms` if `rooms`, else of `authorized-consented`, with its
/// one consent from `consent` given whether it permits export.
fn consented_document(
    rooms: bool,
    consent: &dyn Fn(bool) -> LocalConsentDraftV1,
) -> FixtureDocument {
    if rooms {
        (
            vec![
                GatewayOperationV1::CREATE_TIMELINE,
                GatewayOperationV1::READ_SESSION,
                GatewayOperationV1::REVOKE_CONSENT,
                GatewayOperationV1::CREATE_SCENARIO_ROOM,
                GatewayOperationV1::DERIVE_SCENARIO_ROOM,
                GatewayOperationV1::READ_SCENARIO_ROOM,
            ],
            Some(consent(true)),
            entity(GOVERNANCE_RECORD_ID),
        )
    } else {
        (
            vec![
                GatewayOperationV1::CREATE_TIMELINE,
                GatewayOperationV1::READ_EVENTS,
                GatewayOperationV1::READ_SESSION,
                GatewayOperationV1::REVOKE_CONSENT,
            ],
            Some(consent(false)),
            None,
        )
    }
}

/// The operations, consent and governance record of a fixture Local Principal document.
type FixtureDocument = (
    Vec<GatewayOperationV1>,
    Option<LocalConsentDraftV1>,
    Option<EntityId>,
);

/// Provision the fixture Local Principal of `composition` into `store`. Only its document is
/// fixture data.
fn provision_store(store: &ScratchStore, composition: CompositionV2) -> Option<()> {
    fixture_principal()
        .zip(entity(ACTOR_ENTITY_ID))
        .and_then(|(principal, actor)| {
            let (operations, consent, governance) = document(composition, actor);
            LocalPrincipalProvisionV1::try_new_provisioned(
                &principal,
                [actor],
                operations,
                consent.as_ref(),
                governance,
            )
            .ok()
        })
        .and_then(|provision| {
            store_host(store, &ErasureCoordinatorCompositionV1::closed())
                .and_then(|mut host| provision_on_host(&mut host, &provision).ok())
        })
}

/// One sub-case's `SQLite` file in the temporary directory, removed with its journal files when
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
                Ulid::generate()
            )),
        }
    }

    fn path_text(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }

    /// The directory beside the store an `authorized-erasure` composition keeps its fixture
    /// trust state, bundle and credentials in.
    fn directory(&self) -> PathBuf {
        let mut directory = self.path.clone().into_os_string();
        directory.push("-erasure");
        PathBuf::from(directory)
    }
}

impl Drop for ScratchStore {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm", ".gateway-mode.lock"] {
            let mut path = self.path.clone().into_os_string();
            path.push(suffix);
            drop(std::fs::remove_file(path));
        }
        drop(std::fs::remove_dir_all(self.directory()));
    }
}

/// The header that carries the idempotency key of every request.
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// The raw HTTP request of an exchange, with `{timeline}` and `{room}` replaced by the captured
/// Timeline and room IDs and `{consent}` by the captured consent. Every request carries the sub-case ID as its
/// idempotency key; routes without one ignore it.
fn request(exchange: &ExchangeV2, slots: &Slots, key: &str) -> Request<Body> {
    let body = exchange.body.as_ref().map_or_else(Body::empty, |value| {
        Body::from(
            value
                .to_string()
                .replace(CONSENT_SLOT, slots.consent.as_deref().unwrap_or_default()),
        )
    });
    let mut request = Request::new(body);
    *request.method_mut() = match exchange.method {
        MethodV2::Get => Method::GET,
        MethodV2::Post => Method::POST,
    };
    let path = exchange
        .path
        .replace(TIMELINE_SLOT, slots.timeline.as_deref().unwrap_or_default())
        .replace(ROOM_SLOT, slots.room.as_deref().unwrap_or_default())
        .replace(ERASURE_SLOT, slots.erasure.as_deref().unwrap_or_default());
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

/// The captured values a sub-case's later exchanges name.
#[derive(Default)]
struct Slots {
    timeline: Option<String>,
    consent: Option<String>,
    room: Option<String>,
    erasure: Option<String>,
}

impl Slots {
    /// The `(slot, value)` pairs of the captured consent and room that later responses echo.
    fn captured(&self) -> Vec<(&'static str, &str)> {
        [
            (CONSENT_SLOT, self.consent.as_deref()),
            (ROOM_SLOT, self.room.as_deref()),
            (ERASURE_SLOT, self.erasure.as_deref()),
        ]
        .into_iter()
        .filter_map(|(slot, value)| value.map(|value| (slot, value)))
        .collect()
    }

    /// Fill the slot `capture` names from the response `parsed`.
    fn capture(&mut self, capture: Option<CaptureV2>, parsed: Option<&Value>) {
        if let Some(capture) = capture {
            let (slot, pointer) = self.slot(capture);
            *slot = parsed
                .and_then(|value| value.pointer(pointer))
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
    }

    /// The slot `capture` fills and the JSON pointer of its value in the response.
    const fn slot(&mut self, capture: CaptureV2) -> (&mut Option<String>, &'static str) {
        match capture {
            CaptureV2::Timeline => (&mut self.timeline, "/id"),
            CaptureV2::Room => (&mut self.room, "/id"),
            CaptureV2::Erasure => (&mut self.erasure, "/request_id"),
            CaptureV2::Consent => (&mut self.consent, "/consents/0/consent_ref"),
        }
    }
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
    let mut slots = Slots::default();
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
        let held =
            route.is_some_and(|route| capabilities.iter().any(|held| held == route.capability()));
        let observation = if held {
            let service = match exchange.router {
                RouterV2::Loopback => loopback.clone(),
                RouterV2::Spectator => spectator.clone(),
            };
            let Ok(response) = service
                .oneshot(request(exchange, &slots, &subcase.id))
                .await;
            let status = response.status().as_u16();
            let bytes = axum::body::to_bytes(response.into_body(), RESPONSE_LIMIT)
                .await
                .unwrap_or_default();
            run.steps += 1;
            run.output_bytes += u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            run.events += route.filter(|_| status == 201).map_or(0, RouteV2::events);
            if exchange.router == RouterV2::Spectator {
                present |= subcase
                    .canary
                    .as_deref()
                    .is_some_and(|canary| contains(&bytes, canary.as_bytes()));
            }
            let parsed = serde_json::from_slice::<Value>(&bytes).ok();
            slots.capture(exchange.capture(), parsed.as_ref());
            observation_v1(
                status,
                parsed.map(|value| substitute_captured_v1(value, &slots.captured())),
            )
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{compose, ScratchStore};
    use crate::subject::payload::CompositionV2;
    use pos_core::ErasureInventoryPersistencePortV1 as _;
    use pos_store::sqlite::SqliteStore;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Only the compositions with a fixture erasure bundle record an erasure identity.
    ///
    /// ADR-136 acceptance test 11 does not apply to the adapter: it never
    /// acts as a key-less root (D21). This test proves that every
    /// composition without a fixture erasure bundle serves a store that
    /// records no erasure identity, under the closed composition, so it has
    /// no ERQ1 to recover. The `authorized-erasure` compositions do record
    /// one; they compose through the `serve` loader, which refuses to start
    /// without the signer credential, so they hold the signer.
    ///
    /// It holds in any environment. On a networked host
    /// `authorized-air-gapped` does not compose: `bind_gateway_mode_v1`
    /// refuses it at predicate 6, `air-gapped-no-route`. The adapter's
    /// existing namespace tests cover the case where it composes.
    #[test]
    fn only_the_erasure_bundle_compositions_record_an_erasure_identity() -> TestResult {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        for (index, composition) in [
            CompositionV2::Open,
            CompositionV2::Authorized,
            CompositionV2::AuthorizedAirGapped,
            CompositionV2::AuthorizedConsented,
            CompositionV2::AuthorizedRooms,
            CompositionV2::AuthorizedErasure,
            CompositionV2::AuthorizedErasureHeld,
            CompositionV2::AuthorizedErasureExpired,
            CompositionV2::AuthorizedErasureClosed,
        ]
        .into_iter()
        .enumerate()
        {
            let composed = {
                let _context = runtime.enter();
                compose(composition)
            };
            // `authorized-air-gapped` either does not compose (predicate 6
            // refuses a networked host) or composes a store without an
            // erasure identity; every other composition composes.
            let Some((gateway, store)) = composed else {
                assert!(
                    composition == CompositionV2::AuthorizedAirGapped,
                    "composition {index} is unavailable"
                );
                continue;
            };
            runtime.block_on(gateway.shutdown())?;
            drop(gateway);
            let identity = match &store {
                Some(store) => SqliteStore::open(&store.path_text())?.erasure_store_identity()?,
                None => None,
            };
            assert_eq!(
                identity.is_some(),
                composition.erasure_bundle_expiry().is_some(),
                "composition {index}"
            );
            drop(store);
        }
        Ok(())
    }

    #[test]
    fn a_scratch_store_removes_its_files() -> Result<(), Box<dyn std::error::Error>> {
        let store = ScratchStore::new();
        let path = store.path.clone();
        assert_eq!(std::path::Path::new(&store.path_text()), path.as_path());
        assert!(path.starts_with(std::env::temp_dir()));
        std::fs::write(&path, b"store")?;
        let mut journal = path.clone().into_os_string();
        journal.push("-wal");
        std::fs::write(&journal, b"journal")?;
        let directory = store.directory();
        std::fs::create_dir(&directory)?;
        std::fs::write(directory.join("credential"), b"credential")?;
        drop(store);
        assert!(!path.exists());
        assert!(!std::path::Path::new(&journal).exists());
        assert!(!directory.exists());
        Ok(())
    }
}
