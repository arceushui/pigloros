//! The provenance digests of the Scenario Room golden examples come from
//! the Gateway's own derivation (#1398).

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn the_golden_examples_carry_the_derived_provenance_digest() -> TestResult {
    for example in [
        include_str!("../../../../contracts/gateway/v1/examples/draft-scenario-room-create.json"),
        include_str!("../../../../contracts/gateway/v1/examples/draft-scenario-room-get.json"),
        include_str!("../../../../contracts/gateway/v1/examples/draft-scenario-room-derive.json"),
    ] {
        let body = &serde_json::from_str::<serde_json::Value>(example)?["response"]["body"];
        let hex = body["descriptor"]["descriptor_hash"]
            .as_str()
            .ok_or("descriptor_hash")?;
        let mut descriptor_hash = [0; 32];
        for (byte, pair) in descriptor_hash
            .iter_mut()
            .zip(hex.as_bytes().chunks_exact(2))
        {
            *byte = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
        }
        let event_id = EventId::from_ulid(ulid::Ulid::from_string(
            body["commit"]["event_id"].as_str().ok_or("event_id")?,
        )?);
        assert_eq!(
            body["provenance"]["digest"].as_str(),
            Some(
                revision_provenance_digest_v1(&Hash::from_bytes(descriptor_hash), event_id)
                    .as_str()
            )
        );
    }
    Ok(())
}

mod served {
    //! The served Scenario Room routes on the production composition: a
    //! bound `SQLite` store, a provisioned Local Principal and the router.

    use axum::{body::Body, http::Request, Router};
    use piglor_ledger::LedgerView;
    use pos_core::{EntityId, PrincipalRefV1};
    use pos_runtime::{ErasureCoordinatorCompositionV1, ScenarioRoomLimitV1};
    use pos_store::{sqlite::SqliteStore, StoreConfig};
    use serde_json::{json, Value};
    use tower::ServiceExt;
    use ulid::Ulid;

    use super::super::*;
    use crate::{
        executor::scenario_room::RoomStoreErrorV1,
        local_principal::{
            load_local_principal, local_gateway, provision_local_principal,
            LocalPrincipalProvisionV1,
        },
        mode_profile::{bind_test_store, test_attach_host, test_binding, GatewayModeProfileIdV1},
        operation::ACTOR_ENTITY_HEADER,
        router,
        startup::{open_recovered_erasure_host, GatewayHostStoreV1},
        AppState, GatewayOperationV1, LedgerWriteMode,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    const ACTOR: &str = "01JC0GATEWAYF1XTVREACT0R00";
    const GOVERNANCE: &str = "01JC0GATEWAYW90G0VERN00001";
    const ROOMS: [GatewayOperationV1; 3] = [
        GatewayOperationV1::CREATE_SCENARIO_ROOM,
        GatewayOperationV1::DERIVE_SCENARIO_ROOM,
        GatewayOperationV1::READ_SCENARIO_ROOM,
    ];

    fn id(text: &str) -> TestResult<EntityId> {
        Ok(EntityId::from_ulid(Ulid::from_string(text)?))
    }

    fn provision(
        operations: &[GatewayOperationV1],
        governance: Option<EntityId>,
    ) -> TestResult<LocalPrincipalProvisionV1> {
        Ok(LocalPrincipalProvisionV1::try_new_governed(
            &PrincipalRefV1::try_new([7; 16], "local")?,
            [id(ACTOR)?],
            operations.iter().copied(),
            governance,
        )?)
    }

    /// A served Gateway over a bound `SQLite` store; keep the directory alive.
    fn served(
        provision: &LocalPrincipalProvisionV1,
    ) -> TestResult<(Gateway, Router, tempfile::TempDir)> {
        let directory = tempfile::tempdir()?;
        let path = directory
            .path()
            .join("gateway.db")
            .to_str()
            .ok_or("temporary path is not UTF-8")?
            .to_owned();
        bind_test_store(
            &mut SqliteStore::open(&path)?,
            GatewayModeProfileIdV1::Local,
        )?;
        provision_local_principal(&mut SqliteStore::open(&path)?, provision)?;
        let binding = test_binding(GatewayModeProfileIdV1::Local, []);
        let host = open_recovered_erasure_host(
            StoreConfig::Sqlite { path },
            GatewayHostStoreV1::Standard,
            &ErasureCoordinatorCompositionV1::closed(),
        )?;
        let gateway = local_gateway(test_attach_host(host, &binding), None, &binding)?;
        let app = router(AppState {
            gateway: gateway.clone(),
            ledger_view: LedgerView::default(),
            ledger_write: LedgerWriteMode::Disabled,
        });
        Ok((gateway, app, directory))
    }

    async fn send(
        app: &Router,
        method: &str,
        uri: &str,
        key: Option<&str>,
        body: Option<&Value>,
    ) -> TestResult<(StatusCode, Value)> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(ACTOR_ENTITY_HEADER, ACTOR)
            .header("content-type", "application/json");
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

    fn descriptor(value_micro: i64) -> Value {
        json!({
            "schema_version": 1,
            "tick_duration_ms": 100,
            "max_ticks": 600,
            "scheduler_seed": "04".repeat(32),
            "scheduler_policy": 0,
            "intervention_policy": 1,
            "plugins": [{"plugin_id": "gateway-world-actions", "version": "0.1.0"}],
            "rules": [{"rule_id": "gateway-world-actions.impulse.scale", "value_micro": value_micro}],
            "participants": [
                {"entity_id": "01JC0GATEWAYW90S0C1ETY0001", "kind": "society"},
                {"entity_id": ACTOR, "kind": "persona"},
            ],
            "initial_conditions": [
                {"entity_id": "01JC0GATEWAYW90S0C1ETY0001", "dimension": "trust", "value_micro": 600_000},
            ],
            "governance_ref": GOVERNANCE,
            "privacy_export_ref": GOVERNANCE,
        })
    }

    #[tokio::test]
    async fn a_room_is_created_retried_read_and_derived_over_http() -> TestResult {
        let (gateway, app, _directory) = served(&provision(&ROOMS, Some(id(GOVERNANCE)?))?)?;
        let create = json!({"descriptor": descriptor(250_000)});
        let (status, created) = send(
            &app,
            "POST",
            "/v1/scenario-rooms",
            Some("k-1"),
            Some(&create),
        )
        .await?;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(created["schema_id"], REVISION_SCHEMA_ID);
        assert_eq!(created["revision"], 1);
        assert_eq!(created["parent_revision"], Value::Null);
        assert_eq!(
            created["mode_profile"]["mode_profile_id"],
            "gateway-mode-local-v1"
        );
        assert_eq!(created["mode_profile"]["binding_epoch"], 1);
        assert_eq!(created["commit"]["event_schema_id"], "room.revision.v1");
        assert_eq!(created["descriptor"]["participants"][0]["entity_id"], ACTOR);
        let room = created["id"].as_str().ok_or("room id")?.to_owned();
        // An exact retry, with other member order, returns the same body.
        let (status, retried) = send(
            &app,
            "POST",
            "/v1/scenario-rooms",
            Some("k-1"),
            Some(&create),
        )
        .await?;
        assert_eq!((status, &retried), (StatusCode::OK, &created));
        let other = json!({"descriptor": descriptor(1)});
        let (status, conflict) = send(
            &app,
            "POST",
            "/v1/scenario-rooms",
            Some("k-1"),
            Some(&other),
        )
        .await?;
        assert_eq!(
            (status, &conflict["code"]),
            (StatusCode::CONFLICT, &json!("idempotency-conflict"))
        );
        let read = format!("/v1/scenario-rooms/{room}/revisions/1");
        let (status, body) = send(&app, "GET", &read, None, None).await?;
        assert_eq!((status, &body), (StatusCode::OK, &created));
        let missing = format!("/v1/scenario-rooms/{room}/revisions/9");
        let (status, body) = send(&app, "GET", &missing, None, None).await?;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::NOT_FOUND, &json!("not-found-or-unavailable"))
        );
        let (status, body) = send(
            &app,
            "GET",
            "/v1/scenario-rooms/lower/revisions/1",
            None,
            None,
        )
        .await?;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::BAD_REQUEST, &json!("invalid-request"))
        );
        let revisions = format!("/v1/scenario-rooms/{room}/revisions");
        let derive = json!({"parent_revision": 1, "descriptor": descriptor(500_000)});
        let (status, derived) = send(&app, "POST", &revisions, Some("k-2"), Some(&derive)).await?;
        assert_eq!(
            (status, &derived["revision"]),
            (StatusCode::CREATED, &json!(2))
        );
        assert_eq!(derived["parent_revision"], 1);
        let (status, duplicate) =
            send(&app, "POST", &revisions, Some("k-3"), Some(&derive)).await?;
        assert_eq!((status, &duplicate), (StatusCode::OK, &derived));
        let stale = json!({"parent_revision": 1, "descriptor": descriptor(750_000)});
        let (status, body) = send(&app, "POST", &revisions, Some("k-4"), Some(&stale)).await?;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::CONFLICT, &json!("append-conflict"))
        );
        let (status, body) = send(
            &app,
            "POST",
            &format!("/v1/scenario-rooms/{}/revisions", EntityId::new()),
            Some("k-5"),
            Some(&derive),
        )
        .await?;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        let (status, body) = send(
            &app,
            "POST",
            "/v1/scenario-rooms/lower/revisions",
            Some("k-6"),
            Some(&derive),
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        gateway.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn malformed_uncovered_and_ungoverned_rooms_are_refused() -> TestResult {
        let (gateway, app, _directory) = served(&provision(&ROOMS, Some(id(GOVERNANCE)?))?)?;
        let with = |edit: fn(&mut Value)| {
            let mut body = json!({"descriptor": descriptor(1)});
            edit(&mut body["descriptor"]);
            body
        };
        let cases: [(Value, StatusCode, &str); 11] = [
            (
                with(|d| d["correlation_id"] = json!("5f".repeat(16))),
                StatusCode::BAD_REQUEST,
                "invalid-request",
            ),
            (
                with(|d| d["schema_version"] = json!(2)),
                StatusCode::BAD_REQUEST,
                "unsupported-version",
            ),
            (
                with(|d| d["scheduler_seed"] = json!("0g".repeat(32))),
                StatusCode::BAD_REQUEST,
                "invalid-request",
            ),
            (
                with(|d| d["governance_ref"] = json!(GOVERNANCE.to_lowercase())),
                StatusCode::BAD_REQUEST,
                "invalid-request",
            ),
            (
                with(|d| d["participants"][0]["kind"] = json!("robot")),
                StatusCode::BAD_REQUEST,
                "invalid-request",
            ),
            (
                with(|d| d["initial_conditions"][0]["entity_id"] = json!("x")),
                StatusCode::BAD_REQUEST,
                "invalid-request",
            ),
            (
                with(|d| d["tick_duration_ms"] = json!(0)),
                StatusCode::BAD_REQUEST,
                "invalid-request",
            ),
            (
                with(|d| {
                    d["plugins"] = json!((0..33)
                        .map(|n| json!({"plugin_id": format!("p{n}"), "version": "0.1.0"}))
                        .collect::<Vec<_>>())
                }),
                StatusCode::PAYLOAD_TOO_LARGE,
                "resource-limit-exceeded",
            ),
            (
                with(|d| d["plugins"][0]["version"] = json!("9.9.9")),
                StatusCode::UNPROCESSABLE_ENTITY,
                "admission-rejected",
            ),
            (
                with(|d| d["governance_ref"] = json!(ACTOR)),
                StatusCode::UNPROCESSABLE_ENTITY,
                "admission-rejected",
            ),
            (
                with(|d| d["participants"][1]["entity_id"] = json!("01JC0GATEWAYW90S0C1ETY0009")),
                StatusCode::FORBIDDEN,
                "unauthorized",
            ),
        ];
        for (index, (body, status, code)) in cases.into_iter().enumerate() {
            let key = format!("refused-{index}");
            let (answered, problem) =
                send(&app, "POST", "/v1/scenario-rooms", Some(&key), Some(&body)).await?;
            assert_eq!(
                (answered, problem["code"].as_str()),
                (status, Some(code)),
                "{index}: {problem}"
            );
        }
        let (status, problem) = send(
            &app,
            "POST",
            "/v1/scenario-rooms",
            None,
            Some(&json!({"descriptor": descriptor(1)})),
        )
        .await?;
        assert_eq!(
            (status, &problem["code"]),
            (StatusCode::BAD_REQUEST, &json!("invalid-request"))
        );
        let room = EntityId::new();
        let (status, _) = send(
            &app,
            "POST",
            &format!("/v1/scenario-rooms/{room}/revisions"),
            Some("bad-derive"),
            Some(&json!({"descriptor": descriptor(1)})),
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        gateway.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn a_room_needs_its_grant_and_the_host_governance_record() -> TestResult {
        let create = json!({"descriptor": descriptor(1)});
        let (gateway, app, _directory) = served(&provision(
            &[GatewayOperationV1::READ_SESSION],
            Some(id(GOVERNANCE)?),
        )?)?;
        let (status, problem) =
            send(&app, "POST", "/v1/scenario-rooms", Some("k"), Some(&create)).await?;
        assert_eq!(
            (status, &problem["code"]),
            (StatusCode::FORBIDDEN, &json!("unauthorized"))
        );
        gateway.shutdown().await?;
        let (gateway, app, _directory) = served(&provision(&ROOMS, None)?)?;
        let (status, problem) =
            send(&app, "POST", "/v1/scenario-rooms", Some("k"), Some(&create)).await?;
        assert_eq!(
            (status, &problem["code"]),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                &json!("admission-rejected")
            )
        );
        gateway.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn a_store_without_an_erasure_host_cannot_hold_a_room() -> TestResult {
        let gateway = Gateway::new(pos_store::open_store(StoreConfig::Memory)?);
        let app = router(AppState {
            gateway: gateway.clone(),
            ledger_view: LedgerView::default(),
            ledger_write: LedgerWriteMode::Disabled,
        });
        let create = json!({"descriptor": descriptor(1)});
        let (status, problem) =
            send(&app, "POST", "/v1/scenario-rooms", Some("k"), Some(&create)).await?;
        assert_eq!(
            (status, &problem["code"]),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                &json!("temporarily-unavailable")
            )
        );
        gateway.shutdown().await?;
        Ok(())
    }

    #[test]
    fn every_store_refusal_has_its_problem() {
        for (error, status) in [
            (
                RoomStoreErrorV1::LimitReached,
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                RoomStoreErrorV1::ModeUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (RoomStoreErrorV1::NotFound, StatusCode::NOT_FOUND),
            (
                RoomStoreErrorV1::Room(ScenarioRoomErrorV1::LimitExceeded(
                    ScenarioRoomLimitV1::Revision,
                )),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                RoomStoreErrorV1::Room(ScenarioRoomErrorV1::EntropyUnavailable),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                RoomStoreErrorV1::Room(ScenarioRoomErrorV1::RuleWithoutPlugin),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ] {
            assert_eq!(
                ProblemV1::from(RoomFailureV1::Store(error)).status(),
                status
            );
        }
    }

    #[test]
    fn the_provisioning_document_records_one_governance_record() -> TestResult {
        let document = |extra: &str| {
            format!(
                "principal_id = \"01JC0GATEWAYQ0CA1PR1NC1PA1\"\ntrust_domain = \"local\"\n\
                 actor_entity_ids = [\"{ACTOR}\"]\noperations = [\"scenario-room.create\"]\n{extra}"
            )
        };
        let loaded = |text: &str| -> TestResult<Option<EntityId>> {
            let provision = LocalPrincipalProvisionV1::from_toml(text)?;
            let mut store = pos_store::memory::MemoryStore::new();
            provision_local_principal(&mut store, &provision)?;
            Ok(load_local_principal(&store)?
                .ok_or("a provisioned store recomposes")?
                .governance_record())
        };
        assert_eq!(
            loaded(&document(&format!(
                "governance_record_id = \"{GOVERNANCE}\"\n"
            )))?,
            Some(id(GOVERNANCE)?)
        );
        assert_eq!(loaded(&document(""))?, None);
        assert!(LocalPrincipalProvisionV1::from_toml(&document(
            "governance_record_id = \"not-a-ulid\"\n"
        ))
        .is_err());
        Ok(())
    }
}
