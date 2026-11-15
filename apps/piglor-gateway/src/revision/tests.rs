//! Public-seam tests of the Preference and OptionSpec resources (#304).

use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use piglor_ledger::LedgerView;
use pos_core::{
    GatewayModeProfileRefV1, GatewayRevisionErasureHostV1, GatewayRevisionTombstoneV1,
    PrincipalRefV1,
};
use pos_runtime::{ErasureCoordinatorCompositionV1, ErasureExecutionHostV1};
use pos_store::{sqlite::SqliteStore, StoreConfig};
use tower::ServiceExt;

use crate::{
    local_principal::{local_gateway, provision_local_principal, LocalPrincipalProvisionV1},
    mode_profile::{bind_test_store, test_attach_host, test_binding},
    operation::ACTOR_ENTITY_HEADER,
    router,
    startup::{open_recovered_erasure_host, GatewayHostStoreV1},
    AppState, GatewayOperationV1, LedgerWriteMode,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const PRINCIPAL: &str = "01JC0GATEWAYW90PR1NC1PA1A1";
/// The subject of the golden examples.
const SUBJECT: &str = "01JC0GATEWAYF1XTVREACT0R00";
/// Another entity the same Principal may act as.
const OTHER: &str = "01JC0GATEWAYQ0CA1ACT0R0000";
const LOCAL_MODE_DIGEST: &str = "26d6c7e75b11df673a1ef2d3210733b4ca431648eab0b9ae93bf4a6f6e69da3f";

const PREFERENCES: &str = "/v1/preferences";
const OPTION_SPECS: &str = "/v1/option-specs";

const EXAMPLE_PREFERENCE_CREATE: &str =
    include_str!("../../../../contracts/gateway/v1/examples/preference-create.json");
const EXAMPLE_OPTION_SPEC_CREATE: &str =
    include_str!("../../../../contracts/gateway/v1/examples/option-spec-create.json");

const ALL_REVISION_OPERATIONS: [GatewayOperationV1; 4] = [
    GatewayOperationV1::CREATE_PREFERENCE,
    GatewayOperationV1::READ_PREFERENCE,
    GatewayOperationV1::CREATE_OPTION_SPEC,
    GatewayOperationV1::READ_OPTION_SPEC,
];

fn entity(text: &str) -> TestResult<EntityId> {
    Ok(EntityId::from_ulid(Ulid::from_string(text)?))
}

fn example(text: &str) -> TestResult<Value> {
    Ok(serde_json::from_str(text)?)
}

/// A `SQLite` store bound to the Local mode, provisioned with one Local
/// Principal that acts as [`SUBJECT`] and [`OTHER`], and served by the
/// production composition.
struct Served {
    directory: tempfile::TempDir,
    gateway: Gateway,
    app: Router,
}

fn store_path(directory: &tempfile::TempDir) -> TestResult<String> {
    Ok(directory
        .path()
        .join("gateway.db")
        .to_str()
        .ok_or("temporary path is not UTF-8")?
        .to_owned())
}

fn compose(path: &str) -> TestResult<Gateway> {
    let binding = test_binding(GatewayModeProfileIdV1::Local, []);
    let host = open_recovered_erasure_host(
        StoreConfig::Sqlite {
            path: path.to_owned(),
        },
        GatewayHostStoreV1::Standard,
        &ErasureCoordinatorCompositionV1::closed(),
    )?;
    Ok(local_gateway(
        test_attach_host(host, &binding),
        None,
        &binding,
    )?)
}

fn app_of(gateway: &Gateway) -> Router {
    router(AppState {
        gateway: gateway.clone(),
        ledger_view: LedgerView::default(),
        ledger_write: LedgerWriteMode::Disabled,
    })
}

fn served(operations: impl IntoIterator<Item = GatewayOperationV1>) -> TestResult<Served> {
    let directory = tempfile::tempdir()?;
    let path = store_path(&directory)?;
    bind_test_store(
        &mut SqliteStore::open(&path)?,
        GatewayModeProfileIdV1::Local,
    )?;
    let principal = PrincipalRefV1::try_new(Ulid::from_string(PRINCIPAL)?.to_bytes(), "local")?;
    let provision = LocalPrincipalProvisionV1::try_new(
        &principal,
        [entity(SUBJECT)?, entity(OTHER)?],
        operations,
    )?;
    provision_local_principal(&mut SqliteStore::open(&path)?, &provision)?;
    let gateway = compose(&path)?;
    Ok(Served {
        app: app_of(&gateway),
        directory,
        gateway,
    })
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    actor: Option<&str>,
    key: Option<&str>,
    body: Option<&Value>,
) -> TestResult<(StatusCode, Value)> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(actor) = actor {
        builder = builder.header(ACTOR_ENTITY_HEADER, actor);
    }
    if let Some(key) = key {
        builder = builder.header("idempotency-key", key);
    }
    let request =
        builder.body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))?;
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await?;
    Ok((
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    ))
}

async fn post(
    served: &Served,
    collection: &str,
    actor: &str,
    key: &str,
    body: &Value,
) -> TestResult<(StatusCode, Value)> {
    send(
        &served.app,
        "POST",
        collection,
        Some(actor),
        Some(key),
        Some(body),
    )
    .await
}

async fn get(served: &Served, uri: &str, actor: &str) -> TestResult<(StatusCode, Value)> {
    send(&served.app, "GET", uri, Some(actor), None, None).await
}

fn revision_uri(collection: &str, body: &Value) -> String {
    format!(
        "{collection}/{}/revisions/{}",
        body["id"].as_str().unwrap_or_default(),
        body["revision"]
    )
}

fn preference(weights: Value) -> Value {
    json!({"schema_version": 1, "weights": weights})
}

fn option(key: &str) -> Value {
    json!({"key": key, "label": "An option", "tags": []})
}

fn option_spec(options: Value) -> Value {
    json!({"schema_version": 1, "options": options})
}

fn two_options() -> Value {
    option_spec(json!([option("coast"), option("city")]))
}

fn with_parent(mut body: Value, parent: &Value) -> Value {
    body["parent"] = json!({"id": parent["id"], "revision": parent["revision"]});
    body
}

fn code(problem: &Value) -> &str {
    problem["code"].as_str().unwrap_or_default()
}

async fn finish(served: Served) -> TestResult {
    served.gateway.shutdown().await?;
    drop(served);
    Ok(())
}

/// The served body of `example`'s request equals its golden response once
/// the server-chosen `id` and the digests bound to it are replaced, and the
/// golden digests are the documented recomputation of the golden content.
async fn assert_golden_create<F: GatewayRevisionFamilyV1>(
    served: &Served,
    collection: &str,
    golden: &Value,
) -> TestResult {
    let (status, body) = post(
        served,
        collection,
        SUBJECT,
        "golden-create",
        &golden["request"]["body"],
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED);
    let expected_body = &golden["response"]["body"];
    let mut normalized = body.clone();
    normalized["id"] = expected_body["id"].clone();
    normalized["digest"] = expected_body["digest"].clone();
    normalized["provenance"]["digest"] = expected_body["provenance"]["digest"].clone();
    assert_eq!(&normalized, expected_body);
    // The golden digests recompute from the golden content.
    let id = Ulid::from_string(expected_body["id"].as_str().ok_or("golden id")?)?;
    let request: F::Request = serde_json::from_value(golden["request"]["body"].clone())?;
    let (entries, _) = F::admit(request).map_err(|problem| format!("{problem:?}"))?;
    let content = content_bytes::<F>(id, NonZeroU64::MIN, None, entity(SUBJECT)?, entries);
    let digest = domain_digest(F::DIGEST_DOMAIN, &content);
    assert_eq!(json!(hex(digest)), expected_body["digest"]);
    let record = GatewayRevisionRecordV1::new(
        GatewayRevisionTombstoneV1::new(
            GatewayRevisionKeyV1::new(F::KIND, id.to_bytes(), NonZeroU64::MIN),
            entity(SUBJECT)?,
            digest,
        ),
        Ulid::from_string(PRINCIPAL)?.to_bytes(),
        local_mode(1)?,
        content,
    );
    assert_eq!(
        json!(hex(provenance_digest(&record))),
        expected_body["provenance"]["digest"]
    );
    assert_eq!(
        render::<F>(&record).map_err(|problem| format!("{problem:?}"))?,
        *expected_body
    );
    Ok(())
}

fn local_mode(epoch: u64) -> TestResult<GatewayModeBindingRecordV1> {
    let digest = blake3::Hash::from_hex(LOCAL_MODE_DIGEST)?;
    Ok(GatewayModeBindingRecordV1::new(
        GatewayModeProfileRefV1::try_new("gateway-mode-local-v1", *digest.as_bytes())?,
        NonZeroU64::new(epoch).ok_or("a positive epoch")?,
    ))
}

#[tokio::test]
async fn golden_creates_are_served_exactly() -> TestResult {
    let served = served(ALL_REVISION_OPERATIONS)?;
    assert_golden_create::<PreferenceFamily>(
        &served,
        PREFERENCES,
        &example(EXAMPLE_PREFERENCE_CREATE)?,
    )
    .await?;
    assert_golden_create::<OptionSpecFamily>(
        &served,
        OPTION_SPECS,
        &example(EXAMPLE_OPTION_SPEC_CREATE)?,
    )
    .await?;
    finish(served).await
}

#[tokio::test]
async fn a_revision_is_immutable_and_answered_only_to_its_subject() -> TestResult {
    let served = served(ALL_REVISION_OPERATIONS)?;
    for (collection, body) in [
        (
            PREFERENCES,
            preference(json!([{"dimension": "nature", "weight_micro": 5}])),
        ),
        (OPTION_SPECS, two_options()),
    ] {
        let (status, created) = post(&served, collection, SUBJECT, "create-1", &body).await?;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created["revision"], 1);
        assert_eq!(created["parent_revision"], Value::Null);
        assert_eq!(created["subject_entity_id"], SUBJECT);
        assert_eq!(created["schema_version"], 1);
        let uri = revision_uri(collection, &created);
        assert_eq!(
            get(&served, &uri, SUBJECT).await?,
            (StatusCode::OK, created.clone())
        );
        // An exact retry answers the original revision; another request
        // under the same key conflicts.
        assert_eq!(
            post(&served, collection, SUBJECT, "create-1", &body).await?,
            (StatusCode::OK, created.clone())
        );
        let other = if collection == PREFERENCES {
            preference(json!([{"dimension": "nature", "weight_micro": 6}]))
        } else {
            option_spec(json!([option("coast"), option("hills")]))
        };
        let (status, problem) = post(&served, collection, SUBJECT, "create-1", &other).await?;
        assert_eq!(
            (status, code(&problem)),
            (StatusCode::CONFLICT, "idempotency-conflict")
        );
        // Another entity of the same Principal sees the same answer as for
        // an unknown revision, which never enumerates.
        let (status, problem) = get(&served, &uri, OTHER).await?;
        assert_eq!(
            (status, code(&problem)),
            (StatusCode::NOT_FOUND, "not-found-or-unavailable")
        );
        let unknown = format!("{collection}/{}/revisions/1", Ulid::new());
        assert_eq!(
            get(&served, &unknown, SUBJECT).await?.0,
            StatusCode::NOT_FOUND
        );
        let next = format!(
            "{collection}/{}/revisions/2",
            created["id"].as_str().unwrap_or_default()
        );
        assert_eq!(get(&served, &next, SUBJECT).await?.0, StatusCode::NOT_FOUND);
        // Identical content is never deduplicated: a fresh key is a new
        // resource.
        let (status, again) = post(&served, collection, SUBJECT, "create-2", &body).await?;
        assert_eq!(status, StatusCode::CREATED);
        assert_ne!(again["id"], created["id"]);
        assert_ne!(again["digest"], created["digest"]);
    }
    finish(served).await
}

#[tokio::test]
async fn a_revision_names_the_head_of_its_own_subject_as_parent() -> TestResult {
    let served = served(ALL_REVISION_OPERATIONS)?;
    for (collection, body) in [
        (
            PREFERENCES,
            preference(json!([{"dimension": "nature", "weight_micro": 5}])),
        ),
        (OPTION_SPECS, two_options()),
    ] {
        let (_, first) = post(&served, collection, SUBJECT, "head-1", &body).await?;
        let (status, second) = post(
            &served,
            collection,
            SUBJECT,
            "head-2",
            &with_parent(body.clone(), &first),
        )
        .await?;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(second["id"], first["id"]);
        assert_eq!(second["revision"], 2);
        assert_eq!(second["parent_revision"], 1);
        // Revision 1 is unchanged.
        assert_eq!(
            get(&served, &revision_uri(collection, &first), SUBJECT).await?,
            (StatusCode::OK, first.clone())
        );
        // The head moved: naming revision 1 again is an append conflict.
        let (status, problem) = post(
            &served,
            collection,
            SUBJECT,
            "head-3",
            &with_parent(body.clone(), &first),
        )
        .await?;
        assert_eq!(
            (status, code(&problem)),
            (StatusCode::CONFLICT, "append-conflict")
        );
        // A parent of another subject, or an unknown one, is unavailable.
        let (status, problem) = post(
            &served,
            collection,
            OTHER,
            "head-4",
            &with_parent(body.clone(), &second),
        )
        .await?;
        assert_eq!(
            (status, code(&problem)),
            (StatusCode::NOT_FOUND, "not-found-or-unavailable")
        );
        let unknown = json!({"id": Ulid::new().to_string(), "revision": 1});
        let (status, _) = post(
            &served,
            collection,
            SUBJECT,
            "head-5",
            &with_parent(body.clone(), &unknown),
        )
        .await?;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    finish(served).await
}

#[tokio::test]
async fn erasure_leaves_a_tombstone_answered_deleted_only_to_its_subject() -> TestResult {
    let served = served(ALL_REVISION_OPERATIONS)?;
    let body = preference(json!([{"dimension": "nature", "weight_micro": 5}]));
    let (_, created) = post(&served, PREFERENCES, SUBJECT, "erase-1", &body).await?;
    let id = Ulid::from_string(created["id"].as_str().ok_or("created id")?)?;
    let key = GatewayRevisionKeyV1::new(PreferenceFamily::KIND, id.to_bytes(), NonZeroU64::MIN);
    let erase = |key: GatewayRevisionKeyV1| {
        let gateway = served.gateway.clone();
        async move {
            gateway
                .store
                .gateway_revision(move |port| {
                    port.erase_gateway_revision(
                        GatewayRevisionErasureHostV1::new().authorize_erasure(key),
                    )
                })
                .await
                .map_err(|error| format!("{error:?}"))
        }
    };
    let tombstone = erase(key).await?.map_err(|error| error.to_string())?;
    assert_eq!(
        tombstone.map(|tombstone| tombstone.subject()),
        Some(entity(SUBJECT)?)
    );
    // Erasing again returns the same tombstone; an unknown revision has none.
    assert_eq!(
        erase(key).await?.map_err(|error| error.to_string())?,
        tombstone
    );
    let unknown = GatewayRevisionKeyV1::new(PreferenceFamily::KIND, [0; 16], NonZeroU64::MIN);
    assert_eq!(
        erase(unknown).await?.map_err(|error| error.to_string())?,
        None
    );
    let uri = revision_uri(PREFERENCES, &created);
    let (status, problem) = get(&served, &uri, SUBJECT).await?;
    assert_eq!((status, code(&problem)), (StatusCode::GONE, "deleted"));
    assert_eq!(get(&served, &uri, OTHER).await?.0, StatusCode::NOT_FOUND);
    // A retry of the erased request is deleted too, and the erased revision
    // can no longer be a parent.
    assert_eq!(
        code(
            &post(&served, PREFERENCES, SUBJECT, "erase-1", &body)
                .await?
                .1
        ),
        "deleted"
    );
    let (status, _) = post(
        &served,
        PREFERENCES,
        SUBJECT,
        "erase-2",
        &with_parent(body, &created),
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    finish(served).await
}

#[tokio::test]
async fn a_revision_survives_a_restart_of_its_store() -> TestResult {
    let served = served(ALL_REVISION_OPERATIONS)?;
    let (_, created) = post(&served, OPTION_SPECS, SUBJECT, "restart", &two_options()).await?;
    let path = store_path(&served.directory)?;
    served.gateway.shutdown().await?;
    let gateway = compose(&path)?;
    let app = app_of(&gateway);
    let read = send(
        &app,
        "GET",
        &revision_uri(OPTION_SPECS, &created),
        Some(SUBJECT),
        None,
        None,
    )
    .await?;
    assert_eq!(read, (StatusCode::OK, created));
    gateway.shutdown().await?;
    drop(served);
    Ok(())
}

#[tokio::test]
async fn an_unsupported_schema_version_or_a_malformed_preference_fails_before_commit() -> TestResult
{
    let served = served(ALL_REVISION_OPERATIONS)?;
    let weight = |dimension: &str, weight_micro: i64| json!({"dimension": dimension, "weight_micro": weight_micro});
    let too_many = (0..65)
        .map(|index| weight(&format!("d{index}"), 1))
        .collect::<Vec<_>>();
    for (body, expected) in [
        (
            json!({"schema_version": 2, "weights": [weight("nature", 1)]}),
            "unsupported-version",
        ),
        (json!({"weights": [weight("nature", 1)]}), "invalid-request"),
        (
            json!({"schema_version": 1, "weights": [weight("nature", 1)], "extra": true}),
            "invalid-request",
        ),
        (preference(json!([])), "invalid-request"),
        (preference(json!(too_many)), "invalid-request"),
        (preference(json!([weight("Nature", 1)])), "invalid-request"),
        (preference(json!([weight("", 1)])), "invalid-request"),
        (
            preference(json!([weight(&"a".repeat(129), 1)])),
            "invalid-request",
        ),
        (
            preference(json!([weight("nature", 1_000_001)])),
            "invalid-request",
        ),
        (
            preference(json!([weight("nature", -1_000_001)])),
            "invalid-request",
        ),
        (
            preference(json!([weight("nature", 1), weight("nature", 2)])),
            "invalid-request",
        ),
        (
            json!({"schema_version": 1, "weights": [weight("nature", 1)],
                   "parent": {"id": "not-a-ulid", "revision": 1}}),
            "invalid-request",
        ),
        (
            json!({"schema_version": 1, "weights": [weight("nature", 1)],
                   "parent": {"id": Ulid::new().to_string().to_lowercase(), "revision": 1}}),
            "invalid-request",
        ),
        (
            json!({"schema_version": 1, "weights": [weight("nature", 1)],
                   "parent": {"id": Ulid::new().to_string(), "revision": 0}}),
            "invalid-request",
        ),
        (
            json!({"schema_version": 1, "weights": [weight("nature", 1)],
                   "parent": {"id": Ulid::new().to_string(), "revision": 9_007_199_254_740_992_u64}}),
            "invalid-request",
        ),
    ] {
        let (status, problem) = post(&served, PREFERENCES, SUBJECT, "malformed", &body).await?;
        assert_eq!(
            (status, code(&problem)),
            (StatusCode::BAD_REQUEST, expected),
            "{body}"
        );
        assert_eq!(problem["instance"], PREFERENCES);
    }
    // Nothing above committed: the malformed key was never recorded.
    let body = preference(json!([weight("nature", 1)]));
    let (status, _) = post(&served, PREFERENCES, SUBJECT, "malformed", &body).await?;
    assert_eq!(status, StatusCode::CREATED);
    finish(served).await
}

#[tokio::test]
async fn a_malformed_option_spec_fails_before_commit() -> TestResult {
    let served = served(ALL_REVISION_OPERATIONS)?;
    let labelled = |label: &str| json!({"key": "coast", "label": label, "tags": []});
    let tagged = |tags: Value| json!({"key": "coast", "label": "Coast", "tags": tags});
    let leaning =
        |lean: i64| json!({"key": "coast", "label": "Coast", "tags": [], "lean_hint_micro": lean});
    let placed = |x_micro: i64, z_micro: i64| {
        json!({"key": "coast", "label": "Coast", "tags": [],
               "coordinates": {"x_micro": x_micro, "z_micro": z_micro}})
    };
    let too_many_tags = (0..17).map(|index| format!("t{index}")).collect::<Vec<_>>();
    let too_many_options = (0..17)
        .map(|index| option(&format!("o{index}")))
        .collect::<Vec<_>>();
    for (body, expected) in [
        (
            json!({"schema_version": 7, "options": [option("coast"), option("city")]}),
            "unsupported-version",
        ),
        (option_spec(json!([option("coast")])), "invalid-request"),
        (option_spec(json!(too_many_options)), "invalid-request"),
        (
            option_spec(json!([option("Coast"), option("city")])),
            "invalid-request",
        ),
        (
            option_spec(json!([labelled(""), option("city")])),
            "invalid-request",
        ),
        (
            option_spec(json!([labelled(&"é".repeat(65)), option("city")])),
            "invalid-request",
        ),
        (
            option_spec(json!([labelled("tab\there"), option("city")])),
            "invalid-request",
        ),
        (
            option_spec(json!([labelled("del\u{7f}"), option("city")])),
            "invalid-request",
        ),
        (
            option_spec(json!([tagged(json!(too_many_tags)), option("city")])),
            "invalid-request",
        ),
        (
            option_spec(json!([tagged(json!(["Bad"])), option("city")])),
            "invalid-request",
        ),
        (
            option_spec(json!([tagged(json!(["a", "a"])), option("city")])),
            "invalid-request",
        ),
        (
            option_spec(json!([leaning(1_000_001), option("city")])),
            "invalid-request",
        ),
        (
            option_spec(json!([placed(9_007_199_254_740_992, 0), option("city")])),
            "invalid-request",
        ),
        (
            option_spec(json!([placed(0, -9_007_199_254_740_992), option("city")])),
            "invalid-request",
        ),
        (
            option_spec(json!([option("coast"), option("coast")])),
            "invalid-request",
        ),
    ] {
        let (status, problem) = post(&served, OPTION_SPECS, SUBJECT, "malformed", &body).await?;
        assert_eq!(
            (status, code(&problem)),
            (StatusCode::BAD_REQUEST, expected),
            "{body}"
        );
    }
    let (status, _) = post(&served, OPTION_SPECS, SUBJECT, "malformed", &two_options()).await?;
    assert_eq!(status, StatusCode::CREATED);
    finish(served).await
}

#[tokio::test]
async fn extreme_values_pass_and_a_missing_key_or_a_bad_path_fails() -> TestResult {
    let served = served(ALL_REVISION_OPERATIONS)?;
    // The extreme values are accepted and answered unchanged; tags are a
    // set, answered in byte order.
    let (status, created) = post(
        &served,
        OPTION_SPECS,
        SUBJECT,
        "extremes",
        &option_spec(json!([
            {"key": "coast", "label": "é".repeat(64), "tags": ["quiet", "nature"],
             "lean_hint_micro": -1_000_000,
             "coordinates": {"x_micro": -9_007_199_254_740_991_i64, "z_micro": 9_007_199_254_740_991_i64}},
            option("city"),
        ])),
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["options"][0]["tags"], json!(["nature", "quiet"]));
    assert_eq!(created["options"][0]["lean_hint_micro"], -1_000_000);
    assert_eq!(
        created["options"][0]["coordinates"]["z_micro"],
        9_007_199_254_740_991_i64
    );
    // A missing Idempotency-Key and a non-canonical path are invalid.
    let (status, problem) = send(
        &served.app,
        "POST",
        PREFERENCES,
        Some(SUBJECT),
        None,
        Some(&preference(
            json!([{"dimension": "nature", "weight_micro": 1}]),
        )),
    )
    .await?;
    assert_eq!(
        (status, code(&problem)),
        (StatusCode::BAD_REQUEST, "invalid-request")
    );
    for uri in [
        format!("{PREFERENCES}/not-a-ulid/revisions/1"),
        format!("{OPTION_SPECS}/{}/revisions/0", Ulid::new()),
    ] {
        let (status, problem) = get(&served, &uri, SUBJECT).await?;
        assert_eq!(
            (status, code(&problem)),
            (StatusCode::BAD_REQUEST, "invalid-request")
        );
    }
    finish(served).await
}

#[tokio::test]
async fn every_operation_needs_its_own_grant() -> TestResult {
    let served = served([GatewayOperationV1::READ_SESSION])?;
    let body = preference(json!([{"dimension": "nature", "weight_micro": 1}]));
    for (method, uri, payload) in [
        ("POST", PREFERENCES.to_owned(), Some(body)),
        ("POST", OPTION_SPECS.to_owned(), Some(two_options())),
        (
            "GET",
            format!("{PREFERENCES}/{}/revisions/1", Ulid::new()),
            None,
        ),
        (
            "GET",
            format!("{OPTION_SPECS}/{}/revisions/1", Ulid::new()),
            None,
        ),
    ] {
        let (status, problem) = send(
            &served.app,
            method,
            &uri,
            Some(SUBJECT),
            Some("grant"),
            payload.as_ref(),
        )
        .await?;
        assert_eq!(
            (status, code(&problem)),
            (StatusCode::FORBIDDEN, "unauthorized"),
            "{uri}"
        );
        // A request without an actor is unauthenticated.
        let (status, _) = send(
            &served.app,
            method,
            &uri,
            None,
            Some("grant"),
            payload.as_ref(),
        )
        .await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
    }
    finish(served).await
}

#[tokio::test]
async fn a_composition_without_a_principal_or_a_store_fails_closed() -> TestResult {
    // A harness Gateway that protects nothing has no Principal to scope a
    // revision to.
    let host = ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Memory,
        pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    let open = Gateway::unprotected_for_harness(host)?;
    let app = app_of(&open);
    let body = preference(json!([{"dimension": "nature", "weight_micro": 1}]));
    for (method, uri, payload) in [
        ("POST", PREFERENCES.to_owned(), Some(&body)),
        (
            "GET",
            format!("{PREFERENCES}/{}/revisions/1", Ulid::new()),
            None,
        ),
    ] {
        let (status, problem) =
            send(&app, method, &uri, Some(SUBJECT), Some("open"), payload).await?;
        assert_eq!(
            (status, code(&problem)),
            (StatusCode::UNAUTHORIZED, "unauthenticated")
        );
    }
    open.shutdown().await?;
    // A store without the revision port answers unavailable.
    let generic = Gateway::new(pos_store::open_store(StoreConfig::Memory)?);
    let key = GatewayRevisionKeyV1::new(PreferenceFamily::KIND, [1; 16], NonZeroU64::MIN);
    assert_eq!(
        generic
            .store
            .gateway_revision(move |port| port.load_gateway_revision(key))
            .await
            .map_err(|error| format!("{error:?}"))?,
        Err(GatewayRevisionErrorV1::Unavailable)
    );
    generic.shutdown().await?;
    Ok(())
}

#[test]
fn every_store_failure_has_its_public_answer() {
    for (error, status) in [
        (
            GatewayRevisionErrorV1::IdempotencyConflict,
            StatusCode::CONFLICT,
        ),
        (GatewayRevisionErrorV1::ParentNotHead, StatusCode::CONFLICT),
        (
            GatewayRevisionErrorV1::ParentUnavailable,
            StatusCode::NOT_FOUND,
        ),
        (
            GatewayRevisionErrorV1::ModeBindingStale,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            GatewayRevisionErrorV1::InvalidRecord,
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            GatewayRevisionErrorV1::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    ] {
        assert_eq!(store_failure(error).status(), status, "{error:?}");
    }
    // A store command that never ran answers as every other Gateway
    // operation does.
    for (error, status) in [
        (StoreExecutorError::Saturated, StatusCode::TOO_MANY_REQUESTS),
        (StoreExecutorError::Closed, StatusCode::SERVICE_UNAVAILABLE),
        (
            StoreExecutorError::Unhealthy,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    ] {
        assert_eq!(executor_failure(error).status(), status);
    }
    assert_eq!(
        settled::<()>(Err(StoreExecutorError::DeadlineExceeded))
            .map_err(|response| response.status()),
        Err(StatusCode::SERVICE_UNAVAILABLE)
    );
    // A stale binding marks the response, so the serve loop stops.
    assert!(store_failure(GatewayRevisionErrorV1::ModeBindingStale)
        .extensions()
        .get::<crate::mode_profile::ModeBindingStaleResponseV1>()
        .is_some());
}

#[test]
fn a_record_this_gateway_cannot_decode_is_an_internal_failure() -> TestResult {
    let tombstone = GatewayRevisionTombstoneV1::new(
        GatewayRevisionKeyV1::new(PreferenceFamily::KIND, [1; 16], NonZeroU64::MIN),
        entity(SUBJECT)?,
        [2; 32],
    );
    let undecodable = GatewayRevisionRecordV1::new(tombstone, [3; 16], local_mode(1)?, vec![0xff]);
    let unknown_mode = GatewayRevisionRecordV1::new(
        tombstone,
        [3; 16],
        GatewayModeBindingRecordV1::new(
            GatewayModeProfileRefV1::try_new("gateway-mode-other-v1", [4; 32])?,
            NonZeroU64::MIN,
        ),
        content_bytes::<PreferenceFamily>(
            Ulid::new(),
            NonZeroU64::MIN,
            None,
            entity(SUBJECT)?,
            vec![WeightV1("nature".to_owned(), 1)],
        ),
    );
    for record in [undecodable, unknown_mode] {
        assert_eq!(
            render::<PreferenceFamily>(&record).map_err(|problem| problem.status()),
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        );
        assert_eq!(
            answer::<PreferenceFamily>(StatusCode::OK, &record).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
    Ok(())
}

#[test]
fn keys_labels_and_identifiers_follow_the_contract_patterns() {
    assert!(domain_key("a"));
    assert!(domain_key("a0_.-z"));
    assert!(domain_key(&"a".repeat(128)));
    for invalid in ["", "0a", "_a", "aB", "a b", "a/b"] {
        assert!(!domain_key(invalid), "{invalid}");
    }
    assert!(!domain_key(&"a".repeat(129)));
    assert!(label("Move to the coast"));
    assert!(label(&"a".repeat(128)));
    assert!(!label(&"a".repeat(129)));
    assert!(!label("\u{0}"));
    assert!(label("\u{80}"));
    assert!(unique(["a", "b"].into_iter()));
    assert!(!unique(["b", "a", "b"].into_iter()));
    let id = Ulid::new();
    assert_eq!(canonical_ulid(&id.to_string()), Some(id));
    assert_eq!(canonical_ulid(&id.to_string().to_lowercase()), None);
    assert_eq!(revision_number(0), None);
    assert_eq!(revision_number(1), Some(NonZeroU64::MIN));
    assert!(revision_number(9_007_199_254_740_991).is_some());
    assert_eq!(revision_number(9_007_199_254_740_992), None);
}
