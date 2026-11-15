//! The provenance digests of the Scenario Room golden examples come from
//! the Gateway's own derivation (#1398).

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn the_golden_examples_carry_the_derived_provenance_digest() -> TestResult {
    for example in [
        include_str!("../../../../contracts/gateway/v1/examples/scenario-room-create.json"),
        include_str!("../../../../contracts/gateway/v1/examples/scenario-room-get.json"),
        include_str!("../../../../contracts/gateway/v1/examples/scenario-room-derive.json"),
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
    use pos_core::{
        AuthorityPersistencePortV1, AuthorizationDenialEvidenceV1, AuthorizationOutcomeV1,
        EntityId, PrincipalRefV1,
    };
    use pos_runtime::{ErasureCoordinatorCompositionV1, ScenarioRoomLimitV1};
    use pos_store::{sqlite::SqliteStore, StoreConfig};
    use serde_json::{json, Value};
    use tower::ServiceExt;
    use ulid::Ulid;

    use super::super::*;
    use crate::{
        executor::scenario_room::{RoomOutcomeV1, RoomStoreErrorV1},
        local_principal::{
            load_local_principal, local_gateway, provision_local_principal, provision_on_host,
            LocalConsentDraftV1, LocalConsentGrantDraftV1, LocalPrincipalProvisionV1,
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

    /// The Principal of the room tests: `operations`, the Session read and
    /// consent revocation, and one consent (#309) that governs Timeline
    /// creation, so it can be named as a room's `privacy_export_ref`.
    fn provision(
        operations: &[GatewayOperationV1],
        governance: Option<EntityId>,
    ) -> TestResult<LocalPrincipalProvisionV1> {
        Ok(LocalPrincipalProvisionV1::try_new_provisioned(
            &PrincipalRefV1::try_new([7; 16], "local")?,
            [id(ACTOR)?],
            operations.iter().copied().chain([
                GatewayOperationV1::READ_SESSION,
                GatewayOperationV1::REVOKE_CONSENT,
                GatewayOperationV1::CREATE_TIMELINE,
                GatewayOperationV1::READ_EVENTS,
            ]),
            Some(&LocalConsentDraftV1 {
                subject: id(ACTOR)?,
                grantee: id(ACTOR)?,
                grants: vec![LocalConsentGrantDraftV1 {
                    purpose: "operation".to_owned(),
                    data_categories: vec!["timeline".to_owned()],
                    export_permitted: true,
                }],
            }),
            governance,
        )?)
    }

    /// A served Gateway over a bound `SQLite` store, its router, the
    /// directory to keep alive and the store's path.
    struct Served {
        gateway: Gateway,
        app: Router,
        _directory: tempfile::TempDir,
        path: String,
        /// The `consent_ref` of the Principal's consent.
        consent: String,
    }

    impl Served {
        fn descriptor(&self, value_micro: i64) -> Value {
            descriptor(value_micro, &self.consent)
        }
    }

    async fn served(provision: &LocalPrincipalProvisionV1) -> TestResult<Served> {
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
        let host = || {
            open_recovered_erasure_host(
                StoreConfig::Sqlite { path: path.clone() },
                GatewayHostStoreV1::Standard,
                &ErasureCoordinatorCompositionV1::closed(),
            )
        };
        provision_on_host(&mut host()?, provision)?;
        let binding = test_binding(GatewayModeProfileIdV1::Local, []);
        let host = host()?;
        let gateway = local_gateway(test_attach_host(host, &binding), None, &binding)?;
        let app = router(AppState {
            gateway: gateway.clone(),
            ledger_view: LedgerView::default(),
            ledger_write: LedgerWriteMode::Disabled,
        });
        let (_, session) = send(&app, "GET", "/v1/session", None, None).await?;
        let consent = session["consents"][0]["consent_ref"]
            .as_str()
            .ok_or("the Principal discloses its consent")?
            .to_owned();
        Ok(Served {
            gateway,
            app,
            _directory: directory,
            path,
            consent,
        })
    }

    async fn send(
        app: &Router,
        method: &str,
        uri: &str,
        key: Option<&str>,
        body: Option<&str>,
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
            builder.body(body.map_or_else(Body::empty, |body| Body::from(body.to_owned())))?;
        let response = app.clone().oneshot(request).await?;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20).await?;
        Ok((
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        ))
    }

    async fn post(
        app: &Router,
        uri: &str,
        key: Option<&str>,
        body: &Value,
    ) -> TestResult<(StatusCode, Value)> {
        send(app, "POST", uri, key, Some(&body.to_string())).await
    }

    fn descriptor(value_micro: i64, consent: &str) -> Value {
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
            "privacy_export_ref": consent,
        })
    }

    /// The JSON type of `value`, and of each member or item below it: the
    /// served body and a frozen golden example must agree on every member
    /// and type (the contract checker validates the golden example against
    /// the frozen schema).
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

    fn golden(name: &str) -> TestResult<Value> {
        let path = format!(
            "{}/../../contracts/gateway/v1/compatibility/examples/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let example: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        Ok(example["response"]["body"].clone())
    }

    #[tokio::test]
    async fn a_room_is_created_retried_read_and_derived_over_http() -> TestResult {
        let served = served(&provision(&ROOMS, Some(id(GOVERNANCE)?))?).await?;
        let app = &served.app;
        // The golden example's own request, so the served body has its shape.
        let example: Value = serde_json::from_str(include_str!(
            "../../../../contracts/gateway/v1/compatibility/examples/scenario-room-create.json"
        ))?;
        let mut create = example["request"]["body"].clone();
        create["descriptor"]["privacy_export_ref"] = json!(served.consent);
        let (status, created) = post(app, "/v1/scenario-rooms", Some("k-1"), &create).await?;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(shape(&created), shape(&golden("scenario-room-create")?));
        assert_eq!(
            created["descriptor"]["rule_set_hash"],
            golden("scenario-room-create")?["descriptor"]["rule_set_hash"]
        );
        assert_eq!(
            created["descriptor"]["plugin_composition_hash"],
            "361f956939882f237b9bedde8cfb696bafed4edc7102abc753100eeea2b28842"
        );
        assert_eq!(created["parent_revision"], Value::Null);
        // Revision 1 is the room Timeline's first Event; its cursor observes
        // the next one.
        assert_eq!(created["commit"]["seq"], 1);
        assert!(created["commit"]["next_cursor"]
            .as_str()
            .is_some_and(|cursor| cursor.ends_with(".2")));
        assert_eq!(
            created["mode_profile"]["mode_profile_id"],
            "gateway-mode-local-v1"
        );
        assert_eq!(created["mode_profile"]["binding_epoch"], 1);
        let room = created["id"].as_str().ok_or("room id")?.to_owned();
        // An exact retry, with its members reordered and other whitespace,
        // returns the same body.
        let members: Vec<String> = create["descriptor"]
            .as_object()
            .ok_or("the descriptor is an object")?
            .iter()
            .rev()
            .map(|(name, member)| format!("{} : {member}", json!(name)))
            .collect();
        let reordered = format!("{{ \"descriptor\" : {{ {} }} }}", members.join(" , "));
        let (status, retried) = send(
            app,
            "POST",
            "/v1/scenario-rooms",
            Some("k-1"),
            Some(&reordered),
        )
        .await?;
        assert_eq!((status, &retried), (StatusCode::OK, &created));
        let (status, conflict) = post(
            app,
            "/v1/scenario-rooms",
            Some("k-1"),
            &json!({"descriptor": served.descriptor(1)}),
        )
        .await?;
        assert_eq!(
            (status, &conflict["code"]),
            (StatusCode::CONFLICT, &json!("idempotency-conflict"))
        );
        let read = format!("/v1/scenario-rooms/{room}/revisions/1");
        let (status, body) = send(app, "GET", &read, None, None).await?;
        assert_eq!((status, &body), (StatusCode::OK, &created));
        let missing = format!("/v1/scenario-rooms/{room}/revisions/9");
        let (status, body) = send(app, "GET", &missing, None, None).await?;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::NOT_FOUND, &json!("not-found-or-unavailable"))
        );
        let (status, body) = send(
            app,
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
        let derive = json!({"parent_revision": 1, "descriptor": served.descriptor(500_000)});
        let (status, derived) = post(app, &revisions, Some("k-2"), &derive).await?;
        assert_eq!(
            (status, &derived["revision"], &derived["parent_revision"]),
            (StatusCode::CREATED, &json!(2), &json!(1))
        );
        // A derive claims on the room Timeline, so revision 2 is its third
        // Event, as the frozen golden example shows.
        let golden_derive = golden("scenario-room-derive")?;
        assert_eq!(derived["commit"]["seq"], golden_derive["commit"]["seq"]);
        assert_eq!(derived["commit"]["seq"], 3);
        assert!(derived["commit"]["next_cursor"]
            .as_str()
            .is_some_and(|cursor| cursor.ends_with(".4")));
        assert_eq!(shape(&derived), shape(&golden("scenario-room-derive")?));
        let (status, duplicate) = post(app, &revisions, Some("k-3"), &derive).await?;
        assert_eq!((status, &duplicate), (StatusCode::OK, &derived));
        let stale = json!({"parent_revision": 1, "descriptor": served.descriptor(750_000)});
        let (status, body) = post(app, &revisions, Some("k-4"), &stale).await?;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::CONFLICT, &json!("append-conflict"))
        );
        // The room Timeline is an ordinary Timeline: its revisions and the
        // derive's claim read through the events route.
        let events = format!(
            "/v1/timelines/{}/events",
            created["commit"]["timeline_id"]
                .as_str()
                .ok_or("timeline")?
        );
        let (status, page) = send(app, "GET", &events, None, None).await?;
        assert_eq!(status, StatusCode::OK, "{page}");
        let types = page["events"]
            .as_array()
            .ok_or("events")?
            .iter()
            .map(|event| event["event_type"].as_str().unwrap_or_default().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            types,
            ["room.revision.v1", "room.request.v1", "room.revision.v1"]
        );
        let unknown = format!("/v1/scenario-rooms/{}/revisions", EntityId::new());
        let (status, body) = post(app, &unknown, Some("k-5"), &derive).await?;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::NOT_FOUND, &json!("not-found-or-unavailable"))
        );
        let (status, body) = post(
            app,
            "/v1/scenario-rooms/lower/revisions",
            Some("k-6"),
            &derive,
        )
        .await?;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::BAD_REQUEST, &json!("invalid-request"))
        );
        served.gateway.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn malformed_and_ungoverned_rooms_are_refused() -> TestResult {
        let served = served(&provision(&ROOMS, Some(id(GOVERNANCE)?))?).await?;
        let with = |edit: fn(&mut Value)| {
            let mut body = json!({"descriptor": served.descriptor(1)});
            edit(&mut body["descriptor"]);
            body
        };
        let too_many = json!((0..33)
            .map(|n| json!({"plugin_id": format!("p{n}"), "version": "0.1.0"}))
            .collect::<Vec<_>>());
        let mut plugins = with(|_| {});
        plugins["descriptor"]["plugins"] = too_many;
        let cases = [
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
                plugins,
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
        ];
        for (index, (body, status, code)) in cases.into_iter().enumerate() {
            let key = format!("refused-{index}");
            let (answered, problem) =
                post(&served.app, "/v1/scenario-rooms", Some(&key), &body).await?;
            assert_eq!(
                (answered, problem["code"].as_str()),
                (status, Some(code)),
                "{index}: {problem}"
            );
        }
        let body = json!({"descriptor": served.descriptor(1)});
        let (status, problem) = post(&served.app, "/v1/scenario-rooms", None, &body).await?;
        assert_eq!(
            (status, &problem["code"]),
            (StatusCode::BAD_REQUEST, &json!("invalid-request"))
        );
        let derive = format!("/v1/scenario-rooms/{}/revisions", EntityId::new());
        let (status, _) = post(&served.app, &derive, Some("bad-derive"), &body).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        served.gateway.shutdown().await?;
        Ok(())
    }

    /// An uncovered persona is a recorded `403 unauthorized`: its ADN1
    /// denial evidence is in the authority store before the answer.
    #[tokio::test]
    async fn an_uncovered_persona_is_a_recorded_denial() -> TestResult {
        let served = served(&provision(&ROOMS, Some(id(GOVERNANCE)?))?).await?;
        let mut body = json!({"descriptor": served.descriptor(1)});
        body["descriptor"]["participants"][1]["entity_id"] = json!("01JC0GATEWAYW90S0C1ETY0009");
        let (status, problem) =
            post(&served.app, "/v1/scenario-rooms", Some("persona"), &body).await?;
        assert_eq!(
            (status, &problem["code"]),
            (StatusCode::FORBIDDEN, &json!("unauthorized"))
        );
        served.gateway.shutdown().await?;
        let denials = SqliteStore::open(&served.path)?
            .load_authorization_denials(0, pos_core::MAX_AUTHORIZATION_DENIALS_PER_READ)?;
        assert!(
            matches!(
                denials.as_slice(),
                [(1, AuthorizationDenialEvidenceV1::Denial(_))]
            ),
            "{denials:?}"
        );
        Ok(())
    }

    /// Each route needs its own grant, and a room the host's governance
    /// record does not name is refused.
    #[tokio::test]
    async fn every_room_operation_needs_its_grant_and_the_governance_record() -> TestResult {
        let create = |served: &Served| json!({"descriptor": served.descriptor(1)});
        let full = served(&provision(&ROOMS, Some(id(GOVERNANCE)?))?).await?;
        let (_, created) = post(&full.app, "/v1/scenario-rooms", Some("k"), &create(&full)).await?;
        let room = created["id"].as_str().ok_or("room id")?.to_owned();
        full.gateway.shutdown().await?;
        for granted in [&ROOMS[1..], &[ROOMS[0], ROOMS[2]][..], &ROOMS[..2]] {
            let served = served(&provision(granted, Some(id(GOVERNANCE)?))?).await?;
            let derive = json!({"parent_revision": 1, "descriptor": served.descriptor(2)});
            let answers = [
                post(
                    &served.app,
                    "/v1/scenario-rooms",
                    Some("k"),
                    &create(&served),
                )
                .await?,
                post(
                    &served.app,
                    &format!("/v1/scenario-rooms/{room}/revisions"),
                    Some("d"),
                    &derive,
                )
                .await?,
                send(
                    &served.app,
                    "GET",
                    &format!("/v1/scenario-rooms/{room}/revisions/1"),
                    None,
                    None,
                )
                .await?,
            ];
            let refused = answers
                .iter()
                .filter(|(status, problem)| {
                    *status == StatusCode::FORBIDDEN && problem["code"] == "unauthorized"
                })
                .count();
            assert_eq!(refused, 1, "{answers:?}");
            served.gateway.shutdown().await?;
        }
        let ungoverned = served(&provision(&ROOMS, None)?).await?;
        let (status, problem) = post(
            &ungoverned.app,
            "/v1/scenario-rooms",
            Some("k"),
            &create(&ungoverned),
        )
        .await?;
        assert_eq!(
            (status, &problem["code"]),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                &json!("admission-rejected")
            )
        );
        ungoverned.gateway.shutdown().await?;
        Ok(())
    }

    /// #303 decision 2a: `privacy_export_ref` must name a consent the acting
    /// Principal holds; a consent it does not hold is `403 consent-invalid`
    /// and a revoked one `403 revoked`, for a create and a derive alike. A
    /// revocation racing an admitted create waits for its permit, so the
    /// create commits and the next one is refused.
    #[tokio::test]
    async fn a_room_names_a_held_unrevoked_consent() -> TestResult {
        let served = served(&provision(&ROOMS, Some(id(GOVERNANCE)?))?).await?;
        let (status, created) = post(
            &served.app,
            "/v1/scenario-rooms",
            Some("held"),
            &json!({"descriptor": served.descriptor(1)}),
        )
        .await?;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let room = created["id"].as_str().ok_or("room id")?.to_owned();
        let unheld = descriptor(1, &EntityId::new().to_string());
        let (status, problem) = post(
            &served.app,
            "/v1/scenario-rooms",
            Some("unheld"),
            &json!({"descriptor": unheld}),
        )
        .await?;
        assert_eq!(
            (status, &problem["code"]),
            (StatusCode::FORBIDDEN, &json!("consent-invalid"))
        );
        let (status, problem) = post(
            &served.app,
            &format!("/v1/scenario-rooms/{room}/revisions"),
            Some("unheld-derive"),
            &json!({"parent_revision": 1, "descriptor": unheld}),
        )
        .await?;
        assert_eq!(
            (status, &problem["code"]),
            (StatusCode::FORBIDDEN, &json!("consent-invalid"))
        );
        // A create admitted before the revocation holds its permit. The
        // revocation reaches the commit fence and waits there: a writer is
        // queued behind the permit's read guard. The create still commits
        // on its pin, and releasing its permit lets the revocation through.
        let permit = served
            .gateway
            .authorize_operation(
                GatewayOperationV1::CREATE_SCENARIO_ROOM,
                Some(id(ACTOR)?),
                None,
                None,
            )
            .await?;
        let authorization = served
            .gateway
            .authorization
            .clone()
            .ok_or("the composition has an authorizer")?;
        let app = served.app.clone();
        let consent = served.consent.clone();
        let revocation = tokio::spawn(async move {
            post(
                &app,
                "/v1/me/consent-revocations",
                Some("revoke"),
                &json!({"consent_ref": consent}),
            )
            .await
            .map(|(status, _)| status)
            .map_err(|error| error.to_string())
        });
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while !authorization.fence_writer_waits() {
                assert!(
                    !revocation.is_finished(),
                    "the revocation finished without waiting for the create's permit"
                );
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| "the revocation never reached the commit fence")?;
        let body = json!({"descriptor": served.descriptor(2)});
        let admitted = served
            .gateway
            .create_scenario_room(
                permit,
                "admitted",
                parse_create(&body).map_err(|_| "parse")?,
            )
            .await;
        assert!(matches!(admitted, Ok(RoomOutcomeV1::Committed(_))));
        assert_eq!(revocation.await??, StatusCode::CREATED);
        // Fail-closed: even an exact retry of the first create is refused
        // once its consent is revoked.
        let (status, problem) = post(
            &served.app,
            "/v1/scenario-rooms",
            Some("held"),
            &json!({"descriptor": served.descriptor(1)}),
        )
        .await?;
        assert_eq!(
            (status, &problem["code"]),
            (StatusCode::FORBIDDEN, &json!("revoked"))
        );
        let (status, problem) = post(
            &served.app,
            "/v1/scenario-rooms",
            Some("revoked"),
            &json!({"descriptor": served.descriptor(3)}),
        )
        .await?;
        assert_eq!(
            (status, &problem["code"]),
            (StatusCode::FORBIDDEN, &json!("revoked"))
        );
        let (status, problem) = post(
            &served.app,
            &format!("/v1/scenario-rooms/{room}/revisions"),
            Some("revoked-derive"),
            &json!({"parent_revision": 1, "descriptor": served.descriptor(4)}),
        )
        .await?;
        assert_eq!(
            (status, &problem["code"]),
            (StatusCode::FORBIDDEN, &json!("revoked"))
        );
        served.gateway.shutdown().await?;
        // Each consent refusal left its ADN1 record before it was answered.
        let outcomes = SqliteStore::open(&served.path)?
            .load_authorization_denials(0, pos_core::MAX_AUTHORIZATION_DENIALS_PER_READ)?
            .into_iter()
            .filter_map(|(_, evidence)| match evidence {
                AuthorizationDenialEvidenceV1::Denial(record) => Some(record.outcome()),
                AuthorizationDenialEvidenceV1::Suppressed(_) => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes,
            [
                AuthorizationOutcomeV1::ConsentMissing,
                AuthorizationOutcomeV1::ConsentMissing,
                AuthorizationOutcomeV1::RevokedAtFence,
                AuthorizationOutcomeV1::RevokedAtFence,
                AuthorizationOutcomeV1::RevokedAtFence,
            ]
        );
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
        // The harness composition protects nothing and checks no consent;
        // its write and its read both reach the store, which cannot hold a
        // room.
        let create = json!({"descriptor": descriptor(1, &EntityId::new().to_string())});
        let (status, problem) = post(&app, "/v1/scenario-rooms", Some("k"), &create).await?;
        assert_eq!(
            (status, &problem["code"]),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                &json!("temporarily-unavailable")
            )
        );
        let read = format!("/v1/scenario-rooms/{}/revisions/1", EntityId::new());
        let (status, problem) = send(&app, "GET", &read, None, None).await?;
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
        for (error, status, retryable) in [
            (
                RoomStoreErrorV1::TimelineCeiling,
                StatusCode::TOO_MANY_REQUESTS,
                false,
            ),
            (
                RoomStoreErrorV1::EventCeiling,
                StatusCode::TOO_MANY_REQUESTS,
                false,
            ),
            (
                RoomStoreErrorV1::ModeUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                true,
            ),
            (RoomStoreErrorV1::NotFound, StatusCode::NOT_FOUND, false),
            (
                RoomStoreErrorV1::Room(ScenarioRoomErrorV1::LimitExceeded(
                    ScenarioRoomLimitV1::Revision,
                )),
                StatusCode::PAYLOAD_TOO_LARGE,
                false,
            ),
            (
                RoomStoreErrorV1::Room(ScenarioRoomErrorV1::EntropyUnavailable),
                StatusCode::INTERNAL_SERVER_ERROR,
                false,
            ),
            (
                RoomStoreErrorV1::Room(ScenarioRoomErrorV1::RuleWithoutPlugin),
                StatusCode::UNPROCESSABLE_ENTITY,
                false,
            ),
        ] {
            let problem = ProblemV1::from(RoomFailureV1::Store(error));
            assert_eq!(problem.status(), status);
            assert_eq!(problem.body("/")["retryable"], retryable, "{status}");
        }
    }

    #[test]
    fn the_request_digest_is_canonical() -> TestResult {
        let ordered: Value = serde_json::from_str(r#"{"a":[1,{"b":true,"c":null}],"z":"é"}"#)?;
        let reordered: Value = serde_json::from_str(r#"{ "z":"é", "a":[1,{"c":null,"b":true}] }"#)?;
        let mut text = String::new();
        canonical_json(&ordered, &mut text);
        assert_eq!(text, r#"{"a":[1,{"b":true,"c":null}],"z":"é"}"#);
        assert_eq!(
            request_digest("create", None, &ordered),
            request_digest("create", None, &reordered)
        );
        assert_ne!(
            request_digest("create", None, &ordered),
            request_digest("derive", None, &ordered)
        );
        Ok(())
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
