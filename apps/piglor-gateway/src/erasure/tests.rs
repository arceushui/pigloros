//! `requestErasure` and `getErasure` through the served router (#1449):
//! ADR-136 acceptance tests 8 and 9 and the Gateway parts of test 2.
//!
//! The lifecycle suite runs in every serve mode of acceptance test 11
//! (#1471): `in_every_serve_mode!` gives each suite function one test per
//! `ServeMode`.

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::{
    body::Body,
    http::{HeaderMap, Request, StatusCode},
    Router,
};
use piglor_ledger::LedgerView;
use pos_core::{
    local_erasure_id_v1, local_erasure_request_v1, EntityId, ErasureInventoryPersistencePortV1,
    ErasureLifecycleV1, ErasureRecoveryLimitsV1, ErasureReferenceV1, ErasureReplayClaimV1,
    ErasureScopeV1, LocalErasureAdmissionV1, LocalErasureBundleV1,
    ERASURE_RETAINED_OBJECT_MAX_BYTES_V1,
};
use pos_runtime::{
    ErasureExecutionHostV1, LocalErasureSubmitErrorV1, LOCAL_ERASURE_POLICY_REFERENCE_V1,
};
use pos_store::sqlite::SqliteStore;
use pos_store::StoreConfig;
use serde_json::{json, Value};
use tower::ServiceExt;
use ulid::Ulid;

use super::{lifecycle_name, replay_claim_name, scope_name, submit_refusal};
use crate::authorization::GatewayOperationV1;
use crate::http::{router, AppState};
use crate::local_erasure_composition::tests::{
    actor, erasure_world_granting, erasure_world_provisioned, other_actor, principal, World,
};
use crate::local_erasure_composition::{
    LocalErasureDriverTaskV1, LocalErasureServeV1, LocalErasureStartV1,
};
use crate::local_erasure_signing_fixture::{TestResult, SIGNER_SEED};
use crate::local_fork_service::tests::{
    managed_credentials_for_test, provision_current_peer_for_test, start_managed_for_test,
};
use crate::local_fork_service::LocalForkAdmissionListenerV1;
use crate::local_principal::{local_gateway, LocalPrincipalProvisionV1};
use crate::mode_profile::{test_attach_host, test_binding, GatewayModeProfileIdV1};
use crate::operation::ACTOR_ENTITY_HEADER;
use crate::{Gateway, LedgerWriteMode};

/// Both erasure operations, Timeline creation and Event reads.
const SERVED: [GatewayOperationV1; 4] = [
    GatewayOperationV1::CREATE_TIMELINE,
    GatewayOperationV1::READ_EVENTS,
    GatewayOperationV1::REQUEST_ERASURE,
    GatewayOperationV1::READ_ERASURE,
];

/// How long a test waits for the driver.
const DRIVE_DEADLINE: Duration = Duration::from_mins(1);

/// The serve modes of ADR-136 acceptance test 11, each composed as its
/// production `serve` composes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServeMode {
    /// `serve --profile gateway-mode-local-v1 --require-local-erasure`.
    Local,
    /// The managed Local Fork admission deployment.
    ///
    /// `--require-local-fork-authority --require-local-erasure`: the
    /// erasure credentials share the unit directory with the Fork ones.
    ManagedLocalForkAdmission,
    /// `serve --profile gateway-mode-air-gapped-v1 --require-local-erasure`.
    ///
    /// Its store is bound to the Air-Gapped mode. Its deployment seeds the
    /// trust state store with its bundled TPS1 (D17), which the world's
    /// trust state stands for.
    AirGapped,
}

impl ServeMode {
    /// The execution mode the served store is bound to.
    const fn profile(self) -> GatewayModeProfileIdV1 {
        match self {
            Self::Local | Self::ManagedLocalForkAdmission => GatewayModeProfileIdV1::Local,
            Self::AirGapped => GatewayModeProfileIdV1::AirGapped,
        }
    }

    /// A world for this mode whose root grant covers both fixture actors
    /// for `operations`.
    fn world(self, operations: &[GatewayOperationV1]) -> TestResult<World> {
        self.provisioned(&LocalPrincipalProvisionV1::try_new(
            &principal()?,
            [actor()?, other_actor()?],
            operations.iter().copied(),
        )?)
    }

    /// A world for this mode provisioned with `provision`.
    ///
    /// Its store is bound to [`Self::profile`], and the managed mode also
    /// provisions the FAH1 of its Fork admission authority.
    fn provisioned(self, provision: &LocalPrincipalProvisionV1) -> TestResult<World> {
        let world = erasure_world_provisioned(provision, self.profile())?;
        if self == Self::ManagedLocalForkAdmission {
            provision_current_peer_for_test(&world.fixture.path)?;
        }
        Ok(world)
    }
}

/// One `#[tokio::test]` per [`ServeMode`] for each suite function
/// `suite(mode)`, in a module named after it (acceptance test 11).
macro_rules! in_every_serve_mode {
    ($($suite:ident),+ $(,)?) => {$(
        mod $suite {
            use super::{ServeMode, TestResult};

            #[tokio::test]
            async fn local() -> TestResult {
                super::$suite(ServeMode::Local).await
            }

            #[tokio::test]
            async fn managed_local_fork_admission() -> TestResult {
                super::$suite(ServeMode::ManagedLocalForkAdmission).await
            }

            #[tokio::test]
            async fn air_gapped() -> TestResult {
                super::$suite(ServeMode::AirGapped).await
            }
        }
    )+};
}

/// The Fork-admission socket of `world`'s managed serve, in the runtime
/// directory of mode `0750` the listener requires.
fn socket_of(world: &World) -> TestResult<PathBuf> {
    let runtime = world.fixture.directory.path().join("run");
    std::fs::create_dir_all(&runtime)?;
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o750))?;
    Ok(runtime.join("fork-admission.sock"))
}

/// A served Local erasure Gateway, the world it serves and its router.
struct Served {
    world: World,
    gateway: Gateway,
    app: Router,
    /// The Fork admission listener of the managed mode.
    listener: Option<LocalForkAdmissionListenerV1>,
}

impl Served {
    /// Serve, in `mode`, a world whose root grant covers `operations`.
    ///
    /// The Local erasure authority runs over a host recovered with
    /// `limits`, and its driver on a tick far beyond any test, so only the
    /// startup run and the admission hook wake it.
    fn serve(
        mode: ServeMode,
        operations: &[GatewayOperationV1],
        limits: ErasureRecoveryLimitsV1,
    ) -> TestResult<(Self, LocalErasureDriverTaskV1)> {
        Self::over(mode.world(operations)?, mode, limits)
    }

    /// [`Self::serve`] over `world`, which `mode` provisioned.
    ///
    /// Local and Air-Gapped compose as `serve_http` does, under a binding
    /// whose predicates the test vouches for (the Air-Gapped `no-route`
    /// predicate cannot hold on a networked test host).
    fn over(
        world: World,
        mode: ServeMode,
        limits: ErasureRecoveryLimitsV1,
    ) -> TestResult<(Self, LocalErasureDriverTaskV1)> {
        // Each serve reads its own credential directory, as a restart may
        // serve the same world again.
        static SERVES: AtomicU64 = AtomicU64::new(0);
        let serve = SERVES.fetch_add(1, Ordering::Relaxed);
        let name = format!("credentials-{serve}");
        if mode == ServeMode::ManagedLocalForkAdmission {
            return Self::managed(world, &name, limits);
        }
        let credentials = world.credentials(&name, &SIGNER_SEED, &[])?;
        let erasure = LocalErasureServeV1::for_serve(Some(world.inputs(&credentials)))?;
        let binding = test_binding(mode.profile(), []);
        let mut host = test_attach_host(
            ErasureExecutionHostV1::open_with_authority(
                StoreConfig::Sqlite {
                    path: world.fixture.path.clone(),
                },
                erasure.composition(),
                limits,
            )?,
            &binding,
        );
        let started = erasure.start(&mut host);
        let gateway = local_gateway(host, None, &binding)?;
        Ok(Self::driven(world, (gateway, None), started))
    }

    /// The managed Local Fork admission serve of `world`.
    ///
    /// Its unit directory `name` holds the four erasure and the three Fork
    /// admission credentials; its mode binding is the production one.
    fn managed(
        world: World,
        name: &str,
        limits: ErasureRecoveryLimitsV1,
    ) -> TestResult<(Self, LocalErasureDriverTaskV1)> {
        let managed = managed_credentials_for_test()?;
        let fork = managed
            .iter()
            .map(|(credential, bytes)| (*credential, bytes.as_slice()))
            .collect::<Vec<_>>();
        let credentials = world.credentials(name, &SIGNER_SEED, &fork)?;
        let (gateway, listener, started) = start_managed_for_test(
            &world.fixture.path,
            (
                credentials.as_path(),
                world.inputs(&credentials).trust_state,
            ),
            &socket_of(&world)?,
            limits,
        )?;
        Ok(Self::driven(world, (gateway, Some(listener)), started))
    }

    /// `gateway` serving `world`, with its Fork admission `listener` and
    /// the driver of `started` running.
    fn driven(
        world: World,
        (gateway, listener): (Gateway, Option<LocalForkAdmissionListenerV1>),
        started: LocalErasureStartV1,
    ) -> (Self, LocalErasureDriverTaskV1) {
        let driver =
            LocalErasureDriverTaskV1::spawn_every(&gateway, started, Duration::from_hours(1));
        let served = Self {
            listener,
            ..Self::routed(world, gateway)
        };
        (served, driver)
    }

    /// A world whose root grant covers `operations`, served with the closed
    /// erasure authority.
    fn closed(operations: &[GatewayOperationV1]) -> TestResult<Self> {
        let world = erasure_world_granting(operations)?;
        let erasure = LocalErasureServeV1::closed();
        let host = world.host(erasure.composition())?;
        let gateway = local_gateway(host, None, &test_binding(GatewayModeProfileIdV1::Local, []))?;
        Ok(Self::routed(world, gateway))
    }

    fn routed(world: World, gateway: Gateway) -> Self {
        let app = routed(&gateway);
        Self {
            world,
            gateway,
            app,
            listener: None,
        }
    }

    /// Send one request as `actor`, with `key` as its Idempotency-Key and
    /// `body` as JSON.
    async fn send(
        &self,
        method: &str,
        uri: &str,
        actor: EntityId,
        key: Option<&str>,
        body: Option<Value>,
    ) -> TestResult<Answer> {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(ACTOR_ENTITY_HEADER, actor.to_string());
        if let Some(key) = key {
            request = request.header("idempotency-key", key);
        }
        let body = match body {
            Some(body) => {
                request = request.header("content-type", "application/json");
                Body::from(serde_json::to_vec(&body)?)
            }
            None => Body::empty(),
        };
        // Each `?` runs in its own statement, before any later await, so no
        // non-`Send` error is held across an await (`future_not_send`).
        let request = request.body(body)?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        // #1407: every answer, success or problem, is marked `no-store`.
        if !stores_nothing(&headers) {
            return Err(format!("{method} {uri} answered {status} without no-store").into());
        }
        Ok(Answer {
            status,
            headers,
            bytes: bytes.to_vec(),
        })
    }

    /// `requestErasure` by `actor` under `key` for `scope`.
    async fn request(&self, actor: EntityId, key: &str, scope: &str) -> TestResult<Answer> {
        self.send(
            "POST",
            "/v1/me/erasures",
            actor,
            Some(key),
            Some(json!({"scope": scope, "impact_acknowledged": true})),
        )
        .await
    }

    /// `getErasure` of `id` by `actor`.
    async fn read(&self, actor: EntityId, id: &str) -> TestResult<Answer> {
        self.send("GET", &format!("/v1/me/erasures/{id}"), actor, None, None)
            .await
    }

    /// Wait until `actor`'s erasure `id` has its first receipt, and return
    /// every projection observed on the way.
    async fn receipted(&self, actor: EntityId, id: &str) -> TestResult<Vec<Value>> {
        let deadline = tokio::time::Instant::now() + DRIVE_DEADLINE;
        let mut observed = Vec::new();
        loop {
            let body = self.read(actor, id).await?.json()?;
            let state = body["state"].as_str().unwrap_or_default().to_owned();
            observed.push(body);
            if matches!(state.as_str(), "partial-failure" | "complete") {
                return Ok(observed);
            }
            if tokio::time::Instant::now() > deadline {
                return Err(format!("the driver left the erasure {state}").into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Stop `driver`, the Fork admission listener and the Gateway, in the
    /// order of a serve's shutdown.
    async fn stop(self, driver: LocalErasureDriverTaskV1) -> TestResult<World> {
        driver.stop().await;
        self.shut_down().await
    }

    /// Stop the Fork admission listener, then the Gateway, as a serve's
    /// shutdown does once its driver has stopped.
    async fn shut_down(self) -> TestResult<World> {
        if let Some(listener) = self.listener {
            listener.stop().await?;
        }
        self.gateway.shutdown().await?;
        drop(self.gateway);
        Ok(self.world)
    }
}

/// Whether `headers` carry exactly `Cache-Control: no-store` (#1407).
fn stores_nothing(headers: &HeaderMap) -> bool {
    headers
        .get_all("cache-control")
        .iter()
        .map(axum::http::HeaderValue::as_bytes)
        .eq([b"no-store".as_slice()])
}

/// One answered request.
struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    bytes: Vec<u8>,
}

impl Answer {
    fn json(&self) -> TestResult<Value> {
        Ok(serde_json::from_slice(&self.bytes)?)
    }

    /// The problem `code` and `retryable` of a failure.
    fn problem(&self) -> TestResult<(StatusCode, String, bool)> {
        let body = self.json()?;
        Ok((
            self.status,
            body["code"].as_str().unwrap_or_default().to_owned(),
            body["retryable"].as_bool().unwrap_or_default(),
        ))
    }
}

/// The served limits.
fn compiled() -> ErasureRecoveryLimitsV1 {
    ErasureRecoveryLimitsV1::compiled_maximum()
}

/// The `erasure_id` the host derives for `actor`'s key `key` (D6).
fn erasure_id(actor: EntityId, key: &str) -> TestResult<Ulid> {
    let principal_ref = ErasureReferenceV1::from_digest(
        *pos_core::fork_authentication::principal_digest_v1(&principal()?)
            .map_err(|error| format!("{error:?}"))?
            .as_bytes(),
    );
    Ok(local_erasure_id_v1(principal_ref, actor, key_digest(key))?)
}

/// D6: BLAKE3 of the key bytes.
fn key_digest(key: &str) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest(*blake3::hash(key.as_bytes()).as_bytes())
}

fn hex(digest: ErasureReferenceV1) -> String {
    blake3::Hash::from_bytes(digest.digest())
        .to_hex()
        .to_string()
}

/// ADR-136 §7 and acceptance test 8: the 202 binds the request's own ids,
/// the key digest and the policy, bundle and mode profile of the
/// submission; an exact retry, also after a restart, answers the same
/// bytes; the key with another scope is an idempotency conflict, and a
/// missing key is invalid.
async fn an_exact_retry_answers_the_same_receipt_bytes(mode: ServeMode) -> TestResult {
    let (served, driver) = Served::serve(mode, &SERVED, compiled())?;
    let actor = actor()?;
    let missing = served
        .send(
            "POST",
            "/v1/me/erasures",
            actor,
            None,
            Some(json!({"scope": "private-subject-data", "impact_acknowledged": true})),
        )
        .await?;
    assert_eq!(
        missing.problem()?,
        (StatusCode::BAD_REQUEST, "invalid-request".to_owned(), false)
    );
    let admitted = served
        .request(actor, "erasure-1", "private-subject-data")
        .await?;
    assert_eq!(admitted.status, StatusCode::ACCEPTED);
    let id = erasure_id(actor, "erasure-1")?.to_string();
    let read = served.read(actor, &id).await?.json()?;
    let bundle = LocalErasureBundleV1::from_canonical_cbor(&served.world.bundle)?;
    assert_eq!(
        admitted.json()?,
        json!({
            "schema_id": "urn:pigloros:gateway:v1:schema:admission-receipt",
            "request_id": id,
            "operation_id": id,
            "state": "admitted",
            "operation_url": format!("/v1/me/erasures/{id}"),
            "idempotency_key_digest": hex(key_digest("erasure-1")),
            "bound_inputs": {
                "policy": hex(LOCAL_ERASURE_POLICY_REFERENCE_V1),
                "trust": hex(bundle.reference()?),
                "mode_profile": read["mode_profile"]["mode_profile_digest"],
            },
        })
    );
    let retried = served
        .request(actor, "erasure-1", "private-subject-data")
        .await?;
    assert_eq!(
        (retried.status, &retried.bytes),
        (StatusCode::ACCEPTED, &admitted.bytes)
    );
    let conflict = served
        .request(actor, "erasure-1", "consented-shared-data")
        .await?;
    assert_eq!(
        conflict.problem()?,
        (
            StatusCode::CONFLICT,
            "idempotency-conflict".to_owned(),
            false
        )
    );
    // A restarted Gateway answers the same bytes from the retained ELADM1.
    let world = served.stop(driver).await?;
    let (served, driver) = Served::over(world, mode, compiled())?;
    let restarted = served
        .request(actor, "erasure-1", "private-subject-data")
        .await?;
    assert_eq!(
        (restarted.status, &restarted.bytes),
        (StatusCode::ACCEPTED, &admitted.bytes)
    );
    served.stop(driver).await?;
    Ok(())
}

/// Acceptance test 8: each erasure operation needs its own grant. An
/// `erasure.read`-only grant is refused on `requestErasure` (`403`), and an
/// `erasure.request`-only grant reads only the `404` of an unknown id.
async fn each_erasure_operation_needs_its_own_grant(mode: ServeMode) -> TestResult {
    let actor = actor()?;
    let (reader, driver) = Served::serve(mode, &[GatewayOperationV1::READ_ERASURE], compiled())?;
    let refused = reader
        .request(actor, "erasure-1", "private-subject-data")
        .await?;
    assert_eq!(
        refused.problem()?,
        (StatusCode::FORBIDDEN, "unauthorized".to_owned(), false)
    );
    let unknown = reader.read(actor, &Ulid::nil().to_string()).await?;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    reader.stop(driver).await?;
    let (requester, driver) =
        Served::serve(mode, &[GatewayOperationV1::REQUEST_ERASURE], compiled())?;
    let admitted = requester
        .request(actor, "erasure-1", "private-subject-data")
        .await?;
    assert_eq!(admitted.status, StatusCode::ACCEPTED);
    // Past the per-Principal denial-record bound of 60 per window, the
    // refused read still answers the same 404, never the bound's 429.
    for _ in 0..61 {
        let refused = requester.read(actor, &Ulid::nil().to_string()).await?;
        assert_eq!(
            (refused.status, &refused.bytes),
            (unknown.status, &unknown.bytes)
        );
    }
    let id = erasure_id(actor, "erasure-1")?.to_string();
    let ungranted = requester.read(actor, &id).await?;
    assert_eq!(
        (ungranted.status, &ungranted.bytes),
        (unknown.status, &unknown.bytes)
    );
    requester.stop(driver).await?;
    Ok(())
}

/// Acceptance test 9: an unknown id, another subject's id and a missing
/// grant are the same `404` bytes; the subject's own projection carries no
/// Timeline, Fork or owner value; a malformed id is invalid.
async fn get_erasure_answers_one_not_found(mode: ServeMode) -> TestResult {
    let (served, driver) = Served::serve(mode, &SERVED, compiled())?;
    // The 202 wakes the driver (D7); stopped, it leaves the erasure submitted.
    driver.stop().await;
    let (actor, other) = (actor()?, other_actor()?);
    let created = served
        .send(
            "POST",
            "/v1/timelines",
            actor,
            None,
            Some(json!({"name": "owned"})),
        )
        .await?
        .json()?;
    assert_eq!(
        served
            .request(actor, "erasure-1", "private-subject-data")
            .await?
            .status,
        StatusCode::ACCEPTED
    );
    let id = erasure_id(actor, "erasure-1")?.to_string();
    let own = served.read(actor, &id).await?;
    assert_eq!(own.status, StatusCode::OK);
    let body = own.json()?;
    assert_eq!(body["schema_id"], "urn:pigloros:gateway:v1:schema:erasure");
    assert_eq!(body["id"], id.as_str());
    assert_eq!(body["state"], "submitted");
    assert_eq!(body["generation"], 0);
    assert_eq!(body["scope"], "private-subject-data");
    assert_eq!(body["replay_claim"], "exact");
    assert_eq!(body["provenance"]["origin"], "host-derived");
    assert_eq!(
        body["mode_profile"]["mode_profile_id"],
        mode.profile().as_str()
    );
    assert_eq!(body["mode_profile"]["binding_epoch"], 1);
    assert_eq!(
        body["retained_classes"],
        json!(["public-record", "aggregate", "structural-audit-metadata"])
    );
    assert_eq!(
        body["acknowledgements"],
        json!({"required": 0, "positive": 0, "classes": []})
    );
    assert_eq!(body["external_copies"], "not-covered");
    // #1407: a served projection always carries the store's redaction
    // generation, 0 before any ELCG1 commits.
    assert_eq!(body["redaction_generation"], 0);
    let text = String::from_utf8(own.bytes.clone())?;
    let owned = created["id"].as_str().ok_or("no Timeline id")?.to_owned();
    for withheld in [owned, actor.to_string(), other.to_string()] {
        assert!(!text.contains(&withheld), "{withheld}");
    }
    let foreign = served.read(other, &id).await?;
    let unknown = served.read(actor, &Ulid::nil().to_string()).await?;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND);
    assert_eq!(foreign.bytes, unknown.bytes);
    let malformed = served.read(actor, "not-an-erasure").await?;
    assert_eq!(
        malformed.problem()?,
        (StatusCode::BAD_REQUEST, "invalid-request".to_owned(), false)
    );
    served.shut_down().await?;
    // A missing grant answers the same bytes.
    let (ungranted, driver) =
        Served::serve(mode, &[GatewayOperationV1::REQUEST_ERASURE], compiled())?;
    let refused = ungranted.read(actor, &Ulid::nil().to_string()).await?;
    assert_eq!(refused.bytes, unknown.bytes);
    ungranted.stop(driver).await?;
    Ok(())
}

/// Acceptance test 8 and D22: of two parallel requests of one subject, with
/// different keys and classes, exactly one is admitted and the other is a
/// retryable `429` without `Retry-After`.
async fn parallel_requests_of_one_subject_admit_one(mode: ServeMode) -> TestResult {
    let (served, driver) = Served::serve(mode, &SERVED, compiled())?;
    // No driver may take the admitted request to its receipt in between.
    driver.stop().await;
    let actor = actor()?;
    // Each joined answer carries its error as a `String`: `tokio::join!`
    // keeps the first output while it awaits the second, and a
    // `Box<dyn Error>` there is not `Send` (`future_not_send`).
    let shared = &served;
    let answer = move |key: &'static str, scope: &'static str| async move {
        shared
            .request(actor, key, scope)
            .await
            .map_err(|error| error.to_string())
    };
    let (first, second) = tokio::join!(
        answer("erasure-a", "private-subject-data"),
        answer("erasure-b", "consented-shared-data"),
    );
    let mut answers = [first?, second?];
    answers.sort_by_key(|answer| answer.status.as_u16());
    assert_eq!(answers[0].status, StatusCode::ACCEPTED);
    assert_eq!(
        answers[1].problem()?,
        (
            StatusCode::TOO_MANY_REQUESTS,
            "resource-limit-exceeded".to_owned(),
            true
        )
    );
    assert!(!answers[1].headers.contains_key("retry-after"));
    served.shut_down().await?;
    Ok(())
}

/// D4 and the request rules: the decision comes first, then a retained-only
/// scope is `400 erasure-scope-retained`; an unacknowledged impact, an
/// unknown member and the Draft's `scopes` are invalid before the decision.
async fn a_retained_only_scope_is_refused_after_the_decision(mode: ServeMode) -> TestResult {
    let actor = actor()?;
    let (served, driver) = Served::serve(mode, &SERVED, compiled())?;
    for scope in ["public-record", "aggregate", "structural-audit-metadata"] {
        let refused = served.request(actor, "erasure-1", scope).await?;
        assert_eq!(
            refused.problem()?,
            (
                StatusCode::BAD_REQUEST,
                "erasure-scope-retained".to_owned(),
                false
            ),
            "{scope}"
        );
    }
    for body in [
        json!({"scope": "private-subject-data", "impact_acknowledged": false}),
        json!({"scope": "private-subject-data", "impact_acknowledged": true, "extra": 1}),
        json!({"scopes": ["private-subject-data"], "impact_acknowledged": true}),
        json!({"scope": "everything", "impact_acknowledged": true}),
    ] {
        let invalid = served
            .send(
                "POST",
                "/v1/me/erasures",
                actor,
                Some("erasure-1"),
                Some(body),
            )
            .await?;
        assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
        assert_eq!(invalid.json()?["code"], "invalid-request");
    }
    served.stop(driver).await?;
    // Without the grant the decision answers first.
    let (ungranted, driver) = Served::serve(mode, &[GatewayOperationV1::READ_ERASURE], compiled())?;
    assert_eq!(
        ungranted
            .request(actor, "erasure-1", "public-record")
            .await?
            .status,
        StatusCode::FORBIDDEN
    );
    ungranted.stop(driver).await?;
    Ok(())
}

/// D9: with the closed erasure authority `requestErasure` is `503` and
/// `getErasure` is `404`.
#[tokio::test]
async fn a_closed_gateway_serves_no_erasure() -> TestResult {
    let served = Served::closed(&SERVED)?;
    let actor = actor()?;
    let refused = served
        .request(actor, "erasure-1", "private-subject-data")
        .await?;
    assert_eq!(
        refused.problem()?,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily-unavailable".to_owned(),
            false
        )
    );
    let unknown = served
        .read(actor, &erasure_id(actor, "erasure-1")?.to_string())
        .await?;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    served.gateway.shutdown().await?;
    drop(served);
    Ok(())
}

/// The id of a Timeline `actor` creates on `served` under `name`.
async fn created_timeline(served: &Served, actor: EntityId, name: &str) -> TestResult<String> {
    let answer = served
        .send(
            "POST",
            "/v1/timelines",
            actor,
            None,
            Some(json!({ "name": name })),
        )
        .await?
        .json()?;
    Ok(answer["id"].as_str().unwrap_or_default().to_owned())
}

/// The acknowledgements of a partial failure whose closure is the store
/// target's cache signal and replica and one Timeline payload: three are
/// required, the cache signal is positive and the payload is not.
fn assert_cache_signal_alone_positive(last: &Value) -> TestResult {
    let acknowledgements = &last["acknowledgements"];
    assert_eq!(acknowledgements["required"], 3);
    let classes = acknowledgements["classes"]
        .as_array()
        .ok_or("no classes")?
        .iter()
        .map(|class| {
            (
                class["class"].as_str().unwrap_or_default().to_owned(),
                class["positive"].as_u64().unwrap_or_default(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(classes[0], ("client-cache-signal".to_owned(), 1));
    assert_eq!(classes[1].0, "local-replica");
    assert_eq!(classes[2], ("timeline-payload".to_owned(), 0));
    assert_eq!(classes.len(), 3);
    Ok(())
}

/// D7, acceptance tests 8 and 9 and the Gateway parts of test 2.
///
/// After each `202` the driver is woken, so with a tick far beyond the test a request admitted
/// after the startup run still reaches its first receipt. The actor's own root Timeline is then
/// frozen while another actor's stays readable; the projection's generation only rises and its
/// claim only weakens; and after the partial failure the subject's next request is admitted and
/// driven too.
///
/// #1407 (ADR-136 follow-up F2): once each request reaches its first receipt
/// its ELCG1 has committed, so the store's `redaction_generation` has risen
/// by one; across the successive reads and a restart it never decreases,
/// the claim stays weakened and the frozen Timeline's Events stay
/// `403 deleted`, every answer marked `no-store`.
async fn each_admission_wakes_the_driver_and_a_partial_failure_admits_the_next(
    mode: ServeMode,
) -> TestResult {
    let (served, driver) = Served::serve(mode, &SERVED, compiled())?;
    let (actor, other) = (actor()?, other_actor()?);
    let owned = created_timeline(&served, actor, "owned").await?;
    let others = created_timeline(&served, other, "others").await?;
    let events = |timeline: &str| format!("/v1/timelines/{timeline}/events");
    let deleted = (StatusCode::FORBIDDEN, "deleted".to_owned(), false);
    let redaction = |body: &Value| body["redaction_generation"].as_u64();
    let mut redacted = 0;
    for (key, receipts) in [("erasure-1", 1), ("erasure-2", 2)] {
        assert_eq!(
            served
                .request(actor, key, "private-subject-data")
                .await?
                .status,
            StatusCode::ACCEPTED
        );
        let id = erasure_id(actor, key)?.to_string();
        let observed = served.receipted(actor, &id).await?;
        let generations = observed
            .iter()
            .map(|body| body["generation"].as_u64().unwrap_or_default())
            .collect::<Vec<_>>();
        assert!(
            generations.windows(2).all(|pair| pair[0] <= pair[1]),
            "{generations:?}"
        );
        // Every projection carries the store-wide redaction generation,
        // which never decreases and, at the first receipt, counts one ELCG1
        // per request driven so far.
        let redactions = observed.iter().map(redaction).collect::<Vec<_>>();
        assert!(
            redactions.iter().all(Option::is_some)
                && redactions.windows(2).all(|pair| pair[0] <= pair[1])
                && redactions.first().copied().flatten() >= Some(redacted),
            "{redactions:?}"
        );
        redacted = redactions.last().copied().flatten().unwrap_or_default();
        assert_eq!(redacted, receipts);
        // Once the generation commits, the subject's own Timeline is a
        // wholly erased resource: its Events are refused `deleted`.
        assert_eq!(
            served
                .send("GET", &events(&owned), actor, None, None)
                .await?
                .problem()?,
            deleted
        );
        // The actor has no role-0 key, so its closure is the store target's
        // cache signal and replica and its one Timeline's payload, which
        // no Local owner can destroy: the erasure ends in a partial
        // failure, and the positive cache signal redacts the views.
        let last = observed.last().ok_or("no projection")?;
        assert_eq!(last["state"], "partial-failure");
        assert_eq!(
            last["replay_claim"],
            "exact-authoritative-with-redacted-views"
        );
        assert_cache_signal_alone_positive(last)?;
    }
    let readable = served
        .send("GET", &events(&others), other, None, None)
        .await?;
    assert_eq!(readable.status, StatusCode::OK);
    // A restarted Gateway reads the same durable generation for both
    // requests, still with the weakened claim, and the Timeline stays
    // refused.
    let world = served.stop(driver).await?;
    let (served, driver) = Served::over(world, mode, compiled())?;
    for key in ["erasure-1", "erasure-2"] {
        let id = erasure_id(actor, key)?.to_string();
        let body = served.read(actor, &id).await?.json()?;
        assert!(redaction(&body) >= Some(redacted), "{key}: {body}");
        assert_eq!(
            body["replay_claim"],
            "exact-authoritative-with-redacted-views"
        );
    }
    assert_eq!(
        served
            .send("GET", &events(&owned), actor, None, None)
            .await?
            .problem()?,
        deleted
    );
    served.stop(driver).await?;
    Ok(())
}

/// Acceptance test 8 with lowered, test-only limits (D11): with two actors
/// and 514 request heads `q_subject` is `(514 - 512) / 2 = 1`, so the
/// subject's first request is admitted and its next is
/// `409 erasure-quota-exhausted`; after a restart the store recovers and
/// the other actor still has its own share.
async fn a_subject_past_its_quota_is_refused_for_good(mode: ServeMode) -> TestResult {
    let limits = ErasureRecoveryLimitsV1::from_maximum_requests(514)?;
    let (served, driver) = Served::serve(mode, &SERVED, limits)?;
    let (actor, other) = (actor()?, other_actor()?);
    assert_eq!(
        served
            .request(actor, "erasure-1", "private-subject-data")
            .await?
            .status,
        StatusCode::ACCEPTED
    );
    let id = erasure_id(actor, "erasure-1")?.to_string();
    served.receipted(actor, &id).await?;
    let exhausted = served
        .request(actor, "erasure-2", "private-subject-data")
        .await?;
    assert_eq!(
        exhausted.problem()?,
        (
            StatusCode::CONFLICT,
            "erasure-quota-exhausted".to_owned(),
            false
        )
    );
    let world = served.stop(driver).await?;
    let (served, driver) = Served::over(world, mode, limits)?;
    assert_eq!(
        served
            .request(other, "erasure-1", "consented-shared-data")
            .await?
            .status,
        StatusCode::ACCEPTED
    );
    served.stop(driver).await?;
    Ok(())
}

/// The refusals no served composition reaches in a test, by their mapping:
/// closed admissions (D3) are a non-retryable `503`, and a host failure a
/// retryable one.
#[test]
fn every_submit_refusal_has_its_answer() {
    use crate::problem::ProblemCodeV1 as Code;
    let answer = |error| {
        let problem = submit_refusal(error);
        (
            problem.status(),
            problem.code(),
            problem.body("/")["retryable"].clone(),
        )
    };
    assert_eq!(
        answer(LocalErasureSubmitErrorV1::AdmissionsClosed),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Code::TemporarilyUnavailable,
            json!(false)
        )
    );
    assert_eq!(
        answer(LocalErasureSubmitErrorV1::OperatorClosed),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Code::ErasureAdmissionsClosed,
            json!(false)
        )
    );
    assert_eq!(
        answer(LocalErasureSubmitErrorV1::ScopeTooLarge),
        (
            StatusCode::BAD_REQUEST,
            Code::ErasureScopeTooLarge,
            json!(false)
        )
    );
    assert_eq!(
        answer(LocalErasureSubmitErrorV1::Host(
            pos_core::ErasureHostErrorV1::AdapterFailure
        )),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Code::TemporarilyUnavailable,
            json!(true)
        )
    );
}

/// Every lifecycle, claim and scope has its wire name.
#[test]
fn every_lifecycle_claim_and_scope_has_its_wire_name() {
    for (lifecycle, name) in [
        (ErasureLifecycleV1::Submitted, "submitted"),
        (ErasureLifecycleV1::Authorized, "authorized"),
        (ErasureLifecycleV1::AccessFrozen, "access-frozen"),
        (
            ErasureLifecycleV1::DestructionDispatched,
            "destruction-dispatched",
        ),
        (
            ErasureLifecycleV1::AwaitingAcknowledgements,
            "awaiting-acknowledgements",
        ),
        (ErasureLifecycleV1::Complete, "complete"),
        (ErasureLifecycleV1::PartialFailure, "partial-failure"),
        (ErasureLifecycleV1::Rejected, "rejected"),
    ] {
        assert_eq!(lifecycle_name(lifecycle), name);
    }
    for (claim, name) in [
        (ErasureReplayClaimV1::Exact, "exact"),
        (
            ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
            "exact-authoritative-with-redacted-views",
        ),
        (ErasureReplayClaimV1::StructuralOnly, "structural-only"),
        (
            ErasureReplayClaimV1::UnverifiableArtifactsMissing,
            "unverifiable-artifacts-missing",
        ),
        (
            ErasureReplayClaimV1::IncompatibleProfile,
            "incompatible-profile",
        ),
    ] {
        assert_eq!(replay_claim_name(claim), name);
    }
    assert_eq!(
        scope_name(ErasureScopeV1::ConsentedSharedData),
        "consented-shared-data"
    );
    assert_eq!(
        scope_name(ErasureScopeV1::PrivateSubjectData),
        "private-subject-data"
    );
}

/// D5: an ELADM1 a crash left before its ERQ1 committed binds the
/// resubmission of that key, here one naming an execution mode this Gateway
/// does not compile: the request is admitted under that binding, and its
/// projection, which cannot disclose the mode, is an internal failure.
#[tokio::test]
async fn a_crash_left_admission_binds_the_resubmission() -> TestResult {
    let world = erasure_world_granting(&SERVED)?;
    let actor = actor()?;
    let foreign = ErasureReferenceV1::from_digest([0x99; 32]);
    let left = LocalErasureAdmissionV1 {
        request: local_erasure_request_v1(erasure_id(actor, "erasure-1")?)?,
        trust: ErasureReferenceV1::from_digest([0x98; 32]),
        mode_profile: foreign,
        binding_epoch: 1,
    };
    SqliteStore::open(&world.fixture.path)?.retain_erasure_object(
        &left.to_canonical_cbor()?,
        ERASURE_RETAINED_OBJECT_MAX_BYTES_V1,
    )?;
    let (served, driver) = Served::over(world, ServeMode::Local, compiled())?;
    let admitted = served
        .request(actor, "erasure-1", "private-subject-data")
        .await?;
    assert_eq!(admitted.status, StatusCode::ACCEPTED);
    assert_eq!(
        admitted.json()?["bound_inputs"]["mode_profile"],
        hex(foreign).as_str()
    );
    let unrenderable = served
        .read(actor, &erasure_id(actor, "erasure-1")?.to_string())
        .await?;
    assert_eq!(
        unrenderable.problem()?,
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal-safe-failure".to_owned(),
            false
        )
    );
    served.stop(driver).await?;
    Ok(())
}

/// Both erasure operations are consent-exempt (ADR-136 §3), so a revoked
/// consent never refuses them.
#[test]
fn both_erasure_operations_are_consent_exempt() {
    assert!(GatewayOperationV1::REQUEST_ERASURE.consent_exempt());
    assert!(GatewayOperationV1::READ_ERASURE.consent_exempt());
    assert_ne!(
        GatewayOperationV1::REQUEST_ERASURE.resource(),
        GatewayOperationV1::READ_ERASURE.resource()
    );
}

/// A router over `gateway`.
fn routed(gateway: &Gateway) -> Router {
    router(AppState {
        gateway: gateway.clone(),
        ledger_view: LedgerView::default(),
        ledger_write: LedgerWriteMode::Disabled,
    })
}

/// One raw request without an actor or body.
async fn status_of(app: &Router, method: &str, uri: &str, key: bool) -> TestResult<StatusCode> {
    let mut request = Request::builder().method(method).uri(uri);
    if key {
        request = request
            .header("idempotency-key", "erasure-1")
            .header("content-type", "application/json");
    }
    let body = if key {
        Body::from(r#"{"scope":"private-subject-data","impact_acknowledged":true}"#)
    } else {
        Body::empty()
    };
    let request = request.body(body)?;
    let response = app.clone().oneshot(request).await?;
    if !stores_nothing(response.headers()) {
        return Err(format!("{method} {uri} was answered without no-store").into());
    }
    Ok(response.status())
}

/// A Gateway that protects nothing decides no subject, so it serves no
/// erasure: both operations are `401`. So is a request without an actor.
#[tokio::test]
async fn an_erasure_needs_a_decided_subject() -> TestResult {
    let gateway = Gateway::unprotected_for_harness(ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Memory,
        compiled(),
    )?)?;
    let app = routed(&gateway);
    let id = Ulid::nil().to_string();
    assert_eq!(
        status_of(&app, "POST", "/v1/me/erasures", true).await?,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status_of(&app, "GET", &format!("/v1/me/erasures/{id}"), false).await?,
        StatusCode::UNAUTHORIZED
    );
    gateway.shutdown().await?;
    drop(gateway);
    let served = Served::closed(&SERVED)?;
    assert_eq!(
        status_of(&served.app, "GET", &format!("/v1/me/erasures/{id}"), false).await?,
        StatusCode::UNAUTHORIZED
    );
    served.gateway.shutdown().await?;
    drop(served);
    Ok(())
}

/// A decision whose store command cannot run answers the executor's
/// failure: the authorizer here reads no store, so the decision admits the
/// request after the executor stopped.
#[tokio::test]
async fn a_stopped_executor_answers_unavailable() -> TestResult {
    let actor = EntityId::new();
    let served = Served::routed(
        erasure_world_granting(&SERVED)?,
        crate::gateway_with_erasure_host_and_authorization(
            ErasureExecutionHostV1::open_verified_empty(StoreConfig::Memory, compiled())?,
            [],
            crate::authorization::test_erasure_authorization_for(actor),
        )?,
    );
    served.gateway.shutdown().await?;
    let refused = served
        .request(actor, "erasure-1", "private-subject-data")
        .await?;
    let unread = served.read(actor, &Ulid::nil().to_string()).await?;
    drop(served);
    for answer in [refused, unread] {
        assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(answer.json()?["code"], "temporarily-unavailable");
    }
    Ok(())
}

/// A request whose ELADM1 is gone cannot be projected: `getErasure` is a
/// retryable `503`, never a guess at its binding.
#[tokio::test]
async fn a_request_without_its_admission_is_unavailable() -> TestResult {
    let (served, driver) = Served::serve(ServeMode::Local, &SERVED, compiled())?;
    let actor = actor()?;
    assert_eq!(
        served
            .request(actor, "erasure-1", "private-subject-data")
            .await?
            .status,
        StatusCode::ACCEPTED
    );
    // Stop the driver first, so the request stays where it is.
    driver.stop().await;
    assert_eq!(
        SqliteStore::open(&served.world.fixture.path)?.sweep_unreferenced_erasure_objects(
            &["ELADM1"],
            &[],
            16
        )?,
        1
    );
    let unavailable = served
        .read(actor, &erasure_id(actor, "erasure-1")?.to_string())
        .await?;
    assert_eq!(
        unavailable.problem()?,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily-unavailable".to_owned(),
            true
        )
    );
    served.shut_down().await?;
    Ok(())
}

/// `erasure-admissions <verb>` on `world`'s store, which no serve holds.
fn admissions(world: &World, verb: &str) -> TestResult<String> {
    Ok(crate::erasure_admissions::execute(&[
        verb.to_owned(),
        world.fixture.path.clone(),
    ])?)
}

/// #1408 (ADR-136 follow-up F3): the operator closes admissions with
/// `erasure-admissions close` while the Gateway is stopped. Served again, a
/// fresh request is a non-retryable `503 erasure-admissions-closed`, before
/// the subject checks, while the exact retry of the admitted request
/// answers its receipt, `getErasure` answers it and the driver takes it to
/// its first receipt. After another restart the request is still answered
/// and a fresh one still refused; reopened, the next request is admitted.
#[tokio::test]
async fn closed_admissions_refuse_new_erasures_and_finish_admitted_ones() -> TestResult {
    let mode = ServeMode::Local;
    let actor = actor()?;
    let closed = (
        StatusCode::SERVICE_UNAVAILABLE,
        "erasure-admissions-closed".to_owned(),
        false,
    );
    let (served, driver) = Served::serve(mode, &SERVED, compiled())?;
    let admitted = served
        .request(actor, "erasure-1", "private-subject-data")
        .await?;
    assert_eq!(admitted.status, StatusCode::ACCEPTED);
    let world = served.stop(driver).await?;
    assert_eq!(
        admissions(&world, "close")?,
        "Erasure admissions closed (were open)"
    );
    let (served, driver) = Served::over(world, mode, compiled())?;
    // Request 1 may still hold the subject: the closed record answers
    // before the subject checks would answer `429`.
    let refused = served
        .request(actor, "erasure-2", "consented-shared-data")
        .await?;
    assert_eq!(refused.problem()?, closed);
    assert!(!refused.headers.contains_key("retry-after"));
    let retried = served
        .request(actor, "erasure-1", "private-subject-data")
        .await?;
    assert_eq!(
        (retried.status, &retried.bytes),
        (StatusCode::ACCEPTED, &admitted.bytes)
    );
    let id = erasure_id(actor, "erasure-1")?.to_string();
    assert_eq!(served.read(actor, &id).await?.status, StatusCode::OK);
    let observed = served.receipted(actor, &id).await?;
    // The actor owns no Timeline, so every target of its closure is one a
    // Local owner destroys and the request completes.
    assert_eq!(observed.last().ok_or("no projection")?["state"], "complete");
    // The subject is released, and the record still refuses.
    let refused = served
        .request(actor, "erasure-2", "consented-shared-data")
        .await?;
    assert_eq!(refused.problem()?, closed);
    let world = served.stop(driver).await?;
    let (served, driver) = Served::over(world, mode, compiled())?;
    let read = served.read(actor, &id).await?;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.json()?["id"], id.as_str());
    let refused = served
        .request(actor, "erasure-2", "consented-shared-data")
        .await?;
    assert_eq!(refused.problem()?, closed);
    let world = served.stop(driver).await?;
    assert_eq!(
        admissions(&world, "open")?,
        "Erasure admissions opened (were closed)"
    );
    let (served, driver) = Served::over(world, mode, compiled())?;
    assert_eq!(
        served
            .request(actor, "erasure-2", "consented-shared-data")
            .await?
            .status,
        StatusCode::ACCEPTED
    );
    served.stop(driver).await?;
    Ok(())
}

in_every_serve_mode!(
    an_exact_retry_answers_the_same_receipt_bytes,
    each_erasure_operation_needs_its_own_grant,
    get_erasure_answers_one_not_found,
    parallel_requests_of_one_subject_admit_one,
    a_retained_only_scope_is_refused_after_the_decision,
    each_admission_wakes_the_driver_and_a_partial_failure_admits_the_next,
    a_subject_past_its_quota_is_refused_for_good,
);

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod acceptance;
