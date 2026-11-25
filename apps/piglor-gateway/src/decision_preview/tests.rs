//! The Decision Preview admission and read on the production composition
//! (ADR-140 C2): a bound `SQLite` store, a provisioned Local Principal with
//! one consent, and the release or the seam installed-profile port.

use std::fmt::Debug;

use axum::{body::Body, http::Request, http::StatusCode, Router};
use piglor_ledger::LedgerView;
use pos_core::{
    store::{EventReadBounds, SeqRange},
    AuthorityPersistencePortV1, AuthorizationDenialEvidenceV1, AuthorizationOutcomeV1,
    PrincipalRefV1,
};
use pos_runtime::ErasureCoordinatorCompositionV1;
use pos_store::{sqlite::SqliteStore, StoreConfig};
use serde_json::{json, Value};
use tower::ServiceExt;

use super::{
    test_seam::{SeamInstalledProfilesV1, SEAM_PROFILE_DIGEST},
    *,
};
use crate::{
    executor::decision_preview::tests::{
        actor, entity, interrupted, raw_revision, seeded, ACTOR, PRINCIPAL,
    },
    local_principal::{
        local_gateway, provision_on_host, LocalConsentDraftV1, LocalConsentGrantDraftV1,
        LocalPrincipalProvisionV1,
    },
    mode_profile::{bind_test_store, test_attach_host, test_binding},
    operation::ACTOR_ENTITY_HEADER,
    router,
    startup::{open_recovered_erasure_host, GatewayHostStoreV1},
    AppState, GatewayOperationV1, LedgerWriteMode,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A served Gateway over a bound `SQLite` store, its router and the
/// `consent_ref` of its Principal's consent. The caller keeps the store's
/// directory.
struct Served {
    gateway: Gateway,
    app: Router,
    consent: EntityId,
}

fn store_path(directory: &tempfile::TempDir) -> TestResult<String> {
    Ok(directory
        .path()
        .join("gateway.db")
        .to_str()
        .ok_or("temporary path is not UTF-8")?
        .to_owned())
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

/// The Local Principal of the fixture actor, with one consent the actor
/// grants itself, and the operations the tests use: a stand-in for the
/// Decision Preview grants, which the route layer adds (#305 C3). The
/// timeline creation is the operation the consent governs; a consent that
/// governs no operation is not provisionable.
fn provision() -> TestResult<LocalPrincipalProvisionV1> {
    let actor = actor()?;
    Ok(LocalPrincipalProvisionV1::try_new_provisioned(
        &PrincipalRefV1::try_new(PRINCIPAL, "local")?,
        [actor],
        [
            GatewayOperationV1::CREATE_TIMELINE,
            GatewayOperationV1::READ_SCENARIO_ROOM,
            GatewayOperationV1::READ_SESSION,
            GatewayOperationV1::REVOKE_CONSENT,
        ],
        Some(&LocalConsentDraftV1 {
            subject: actor,
            grantee: actor,
            grants: vec![LocalConsentGrantDraftV1 {
                purpose: "operation".to_owned(),
                data_categories: vec!["timeline".to_owned()],
                export_permitted: true,
            }],
        }),
        None,
    )?)
}

async fn served(directory: &tempfile::TempDir) -> TestResult<Served> {
    let path = store_path(directory)?;
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
    provision_on_host(&mut host()?, &provision()?)?;
    let binding = test_binding(GatewayModeProfileIdV1::Local, []);
    let gateway = local_gateway(test_attach_host(host()?, &binding), None, &binding)?;
    let app = router(AppState {
        gateway: gateway.clone(),
        ledger_view: LedgerView::default(),
        ledger_write: LedgerWriteMode::Disabled,
    });
    let (_, session) = send(&app, "GET", "/v1/session", None, None).await?;
    let consent = session["consents"][0]["consent_ref"]
        .as_str()
        .ok_or("the Principal discloses its consent")?;
    Ok(Served {
        consent: entity(consent)?,
        gateway,
        app,
    })
}

/// Run `operation` on the Gateway's host as one store command.
async fn on_host<T: Send + 'static>(
    gateway: &Gateway,
    operation: impl FnOnce(&mut ErasureExecutionHostV1) -> Result<T, String> + Send + 'static,
) -> TestResult<T> {
    Ok(gateway
        .store
        .decision_preview(move |host| Ok(operation(host)))
        .await
        .map_err(|error| format!("{error:?}"))?
        .map_err(|error| format!("{error:?}"))??)
}

/// The worked example's inputs over the Principal's consent.
async fn seed(served: &Served) -> TestResult<PreviewRequestV1> {
    let consent = served.consent;
    on_host(&served.gateway, move |host| seeded(host, consent)).await
}

/// The Events of the `decision-previews` Timeline.
async fn previews_events(gateway: &Gateway) -> TestResult<usize> {
    on_host(gateway, |host| {
        host.read_sender()
            .and_then(|mut reads| {
                reads.read_bounded(
                    decision_previews_timeline(),
                    SeqRange::all(),
                    EventReadBounds::new(1_024, 32, 0, usize::MAX),
                )
            })
            .map(|events| events.len())
            .map_err(|error| format!("{error:?}"))
    })
    .await
}

/// A permit of the fixture actor, as the route's authority decision issues
/// it.
async fn permit(gateway: &Gateway) -> TestResult<GatewayOperationPermitV1> {
    Ok(gateway
        .authorize_operation(
            GatewayOperationV1::READ_SCENARIO_ROOM,
            Some(actor()?),
            None,
            None,
        )
        .await?)
}

fn refused<T: Debug>(result: Result<T, DecisionPreviewErrorV1>) -> String {
    result
        .err()
        .map_or_else(String::new, |error| format!("{error:?}"))
}

fn admitted<T>(result: Result<T, DecisionPreviewErrorV1>) -> Result<T, String> {
    result.map_err(|error| format!("{error:?}"))
}

fn seam(gateway: &Gateway) -> Gateway {
    gateway
        .clone()
        .with_installed_profiles_for_test(Arc::new(SeamInstalledProfilesV1))
}

#[tokio::test]
async fn a_preview_is_admitted_retried_and_read_through_the_seam() -> TestResult {
    let directory = tempfile::tempdir()?;
    let served = served(&directory).await?;
    let request = seed(&served).await?;
    let gateway = seam(&served.gateway);
    let receipt = admitted(
        gateway
            .create_decision_preview(permit(&gateway).await?, "k-1", request.clone())
            .await,
    )?;
    assert_eq!(
        receipt.idempotency_key_digest,
        *blake3::hash(b"k-1").as_bytes()
    );
    assert_eq!(receipt.claim.request, request);
    assert_eq!(receipt.claim.profile_digest, SEAM_PROFILE_DIGEST);
    assert_eq!(receipt.claim.consent_ref, served.consent);
    // An exact retry is answered with the identical receipt.
    let retried = admitted(
        gateway
            .create_decision_preview(permit(&gateway).await?, "k-1", request.clone())
            .await,
    )?;
    assert_eq!(retried, receipt);
    // The same key with another request conflicts before the profile gate,
    // here the release port's.
    let other = PreviewRequestV1 {
        profile_id: "replay-v1".to_owned(),
        ..request.clone()
    };
    assert_eq!(
        refused(
            served
                .gateway
                .create_decision_preview(permit(&gateway).await?, "k-1", other)
                .await
        ),
        "IdempotencyConflict"
    );
    let preview = admitted(
        gateway
            .read_decision_preview(permit(&gateway).await?, receipt.preview_id)
            .await,
    )?;
    assert!(matches!(
        preview.state,
        DecisionPreviewStateV1::Committed { .. }
    ));
    assert_eq!(preview.claim, receipt.claim);
    assert_eq!(
        refused(
            gateway
                .read_decision_preview(permit(&gateway).await?, EventId::new())
                .await
        ),
        "NotFound"
    );
    assert_eq!(previews_events(&gateway).await?, 2);
    drop(gateway);
    served.gateway.shutdown().await?;
    drop(served);
    Ok(())
}

/// ADR-140 D1: the release port installs no EPF1, so a fresh request is
/// `409 incompatible-profile` and nothing is recorded.
#[tokio::test]
async fn the_release_port_refuses_every_fresh_request() -> TestResult {
    let directory = tempfile::tempdir()?;
    let served = served(&directory).await?;
    let request = seed(&served).await?;
    assert_eq!(
        refused(
            served
                .gateway
                .create_decision_preview(permit(&served.gateway).await?, "k-1", request)
                .await
        ),
        "IncompatibleProfile"
    );
    let recorded = on_host(&served.gateway, |host| {
        host.command_sender()
            .and_then(|mut commands| commands.records_timeline(decision_previews_timeline()))
            .map_err(|error| format!("{error:?}"))
    })
    .await?;
    assert!(!recorded);
    served.gateway.shutdown().await?;
    drop(served);
    Ok(())
}

/// An attempt the host interrupted between its two appends is finished by
/// an exact retry, even under the release port: a retry never consults it.
#[tokio::test]
async fn an_exact_retry_finishes_an_interrupted_preview() -> TestResult {
    let directory = tempfile::tempdir()?;
    let served = served(&directory).await?;
    let request = seed(&served).await?;
    let consent = served.consent;
    let claimed = request.clone();
    let preview_id = on_host(&served.gateway, move |host| {
        interrupted(host, &claimed, "k-1", consent, None)
    })
    .await?;
    let read = admitted(
        served
            .gateway
            .read_decision_preview(permit(&served.gateway).await?, preview_id)
            .await,
    )?;
    assert_eq!(read.state, DecisionPreviewStateV1::Admitted);
    let receipt = admitted(
        served
            .gateway
            .create_decision_preview(permit(&served.gateway).await?, "k-1", request)
            .await,
    )?;
    assert_eq!(receipt.preview_id, preview_id);
    let read = admitted(
        served
            .gateway
            .read_decision_preview(permit(&served.gateway).await?, preview_id)
            .await,
    )?;
    assert!(matches!(
        read.state,
        DecisionPreviewStateV1::Committed { .. }
    ));
    assert_eq!(previews_events(&served.gateway).await?, 2);
    served.gateway.shutdown().await?;
    drop(served);
    Ok(())
}

/// ADR-140 D6: once the bound room's consent is revoked, an exact retry, a
/// read and a fresh request are each `403 revoked`, recorded as ADN1
/// evidence first, and a retry of an interrupted preview appends no result.
#[tokio::test]
async fn a_revoked_consent_refuses_retries_reads_and_fresh_requests() -> TestResult {
    let directory = tempfile::tempdir()?;
    let served = served(&directory).await?;
    let request = seed(&served).await?;
    let gateway = seam(&served.gateway);
    let receipt = admitted(
        gateway
            .create_decision_preview(permit(&gateway).await?, "k-1", request.clone())
            .await,
    )?;
    let consent = served.consent;
    let claimed = request.clone();
    on_host(&gateway, move |host| {
        interrupted(host, &claimed, "k-2", consent, None)
    })
    .await?;
    let (status, _) = send(
        &served.app,
        "POST",
        "/v1/me/consent-revocations",
        Some("revoke"),
        Some(&json!({"consent_ref": served.consent.to_string()})),
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED);
    for (key, refusal) in [
        (
            "k-1",
            gateway
                .create_decision_preview(permit(&gateway).await?, "k-1", request.clone())
                .await
                .map(drop),
        ),
        (
            "k-2",
            gateway
                .create_decision_preview(permit(&gateway).await?, "k-2", request.clone())
                .await
                .map(drop),
        ),
        (
            "k-3",
            gateway
                .create_decision_preview(permit(&gateway).await?, "k-3", request.clone())
                .await
                .map(drop),
        ),
        (
            "read",
            gateway
                .read_decision_preview(permit(&gateway).await?, receipt.preview_id)
                .await
                .map(drop),
        ),
    ] {
        assert!(
            matches!(
                refusal,
                Err(DecisionPreviewErrorV1::Gateway(
                    GatewayError::AuthorizationDenied(_)
                ))
            ),
            "{key}: {refusal:?}"
        );
    }
    // Two Events of the first preview and the unfinished claim: no result.
    assert_eq!(previews_events(&gateway).await?, 3);
    drop(gateway);
    served.gateway.shutdown().await?;
    drop(served);
    let outcomes = SqliteStore::open(&store_path(&directory)?)?
        .load_authorization_denials(0, pos_core::MAX_AUTHORIZATION_DENIALS_PER_READ)?
        .into_iter()
        .filter_map(|(_, evidence)| match evidence {
            AuthorizationDenialEvidenceV1::Denial(record) => Some(record.outcome()),
            AuthorizationDenialEvidenceV1::Suppressed(_) => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(outcomes, [AuthorizationOutcomeV1::RevokedAtFence; 4]);
    Ok(())
}

/// ADR-140 D6 and P29: stored content is decoded only after the consent
/// check, so a corrupt input is the internal-failure arm while the consent
/// holds, and a recorded `403 revoked` once it is revoked.
#[tokio::test]
async fn the_consent_check_comes_before_the_internal_failure_arm() -> TestResult {
    let directory = tempfile::tempdir()?;
    let served = served(&directory).await?;
    let mut request = seed(&served).await?;
    request.preference = on_host(&served.gateway, |host| {
        let actor = actor()?;
        raw_revision(
            host,
            pos_core::GatewayRevisionKindV1::Preference,
            EntityId::new().inner(),
            actor,
            vec![0xff],
        )
    })
    .await?;
    let gateway = seam(&served.gateway);
    assert_eq!(
        refused(
            gateway
                .create_decision_preview(permit(&gateway).await?, "k-1", request.clone())
                .await
        ),
        "Internal"
    );
    let (status, _) = send(
        &served.app,
        "POST",
        "/v1/me/consent-revocations",
        Some("revoke"),
        Some(&json!({"consent_ref": served.consent.to_string()})),
    )
    .await?;
    assert_eq!(status, StatusCode::CREATED);
    let refusal = gateway
        .create_decision_preview(permit(&gateway).await?, "k-1", request)
        .await;
    drop(gateway);
    assert!(
        matches!(
            refusal,
            Err(DecisionPreviewErrorV1::Gateway(
                GatewayError::AuthorizationDenied(_)
            ))
        ),
        "{refusal:?}"
    );
    // Neither refusal appended anything.
    let recorded = on_host(&served.gateway, |host| {
        host.command_sender()
            .and_then(|mut commands| commands.records_timeline(decision_previews_timeline()))
            .map_err(|error| format!("{error:?}"))
    })
    .await?;
    assert!(!recorded);
    served.gateway.shutdown().await?;
    drop(served);
    Ok(())
}

/// ADR-140 P35: a Principal has at most four requests in flight; a slot is
/// released when its request is answered, refused or not.
#[tokio::test]
async fn the_in_flight_slot_bounds_concurrent_requests() -> TestResult {
    let directory = tempfile::tempdir()?;
    let served = served(&directory).await?;
    let request = seed(&served).await?;
    let in_flight = &served.gateway.decision_previews.in_flight;
    let mut slots = (0..MAX_IN_FLIGHT_PER_PRINCIPAL)
        .map(|_| InFlightSlotV1::take(in_flight, PRINCIPAL))
        .collect::<Option<Vec<_>>>()
        .ok_or("the Principal has four slots")?;
    assert!(InFlightSlotV1::take(in_flight, PRINCIPAL).is_none());
    // Another Principal has its own slots.
    assert!(InFlightSlotV1::take(in_flight, [8; 16]).is_some());
    assert_eq!(
        refused(
            served
                .gateway
                .create_decision_preview(permit(&served.gateway).await?, "k-1", request.clone())
                .await
        ),
        "InFlightLimit"
    );
    drop(slots.pop());
    assert_eq!(
        refused(
            served
                .gateway
                .create_decision_preview(permit(&served.gateway).await?, "k-1", request)
                .await
        ),
        "IncompatibleProfile"
    );
    drop(slots);
    assert!(in_flight
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .is_empty());
    served.gateway.shutdown().await?;
    drop(served);
    Ok(())
}

/// A permit without a decision, as a composition that protects nothing
/// issues it, names no Principal: both operations fail closed. A store
/// without an erasure host cannot hold a preview, and a stopped store
/// executor answers as every Gateway operation.
#[tokio::test]
async fn a_preview_fails_closed_without_a_decision_a_host_or_an_executor() -> TestResult {
    let directory = tempfile::tempdir()?;
    let served = served(&directory).await?;
    let request = seed(&served).await?;
    let open = Gateway::new(pos_store::open_store(StoreConfig::Memory)?);
    let undecided = || {
        open.authorize_operation(
            GatewayOperationV1::READ_SCENARIO_ROOM,
            Some(EntityId::new()),
            None,
            None,
        )
    };
    let gateway = &served.gateway;
    assert_eq!(
        refused(
            gateway
                .create_decision_preview(undecided().await?, "k-1", request.clone())
                .await
        ),
        "Gateway(AuthorizationUnavailable)"
    );
    assert_eq!(
        refused(
            gateway
                .read_decision_preview(undecided().await?, EventId::new())
                .await
        ),
        "Gateway(AuthorizationUnavailable)"
    );
    let hostless = open.store.decision_preview(|_| Ok(())).await;
    assert_eq!(
        format!("{hostless:?}"),
        format!(
            "{:?}",
            Ok::<Result<(), DecisionPreviewErrorV1>, ()>(Err(DecisionPreviewErrorV1::Store(
                CoreError::ErasureContainmentUnavailable
            )))
        )
    );
    open.shutdown().await?;
    drop(open);
    let outcome = {
        let permit = permit(gateway).await?;
        gateway
            .store
            .shutdown()
            .await
            .map_err(|error| format!("{error:?}"))?;
        refused(
            gateway
                .create_decision_preview(permit, "k-1", request)
                .await,
        )
    };
    assert_eq!(outcome, "Gateway(StoreExecutorClosed)");
    drop(served);
    Ok(())
}

#[test]
fn the_generation_counts_the_preview_events() {
    assert_eq!(DecisionPreviewStateV1::Admitted.generation(), 1);
    assert_eq!(
        DecisionPreviewStateV1::Failed {
            code: PreviewFailureCodeV1::input_deleted()
        }
        .generation(),
        2
    );
}
