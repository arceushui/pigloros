//! ADR-136 acceptance matrix, slices C6b (#1470) and C6c (#1471): the
//! Gateway parts of acceptance tests 2, 8 and 9 through the served router,
//! in every serve mode of acceptance test 11.
//!
//! `docs/erasure/adr-136-acceptance-matrix.md` maps every bullet to its
//! test. Each test serves a `SQLite` world, as the Gateway serves only
//! `SQLite` with the Local erasure authority.

use std::path::Path;
use std::sync::Arc;

use pos_core::store::{import_timeline_with_id, TimelineExport};
use pos_core::{ErasureContainmentGateV1, EventStore as _, TimelineId, TimelineMeta};
use pos_local_erasure_loader::local_principal::local_principal_authority_timeline;
use pos_store::memory::MemoryStore;

use super::*;
use crate::local_erasure_signing_fixture::SIGNER_OWNER;
use crate::local_fork_service::tests::{
    bind_payload, fork_payload, fork_result, rejected, request, BIND_OK,
};
use crate::local_principal::{LocalConsentDraftV1, LocalConsentGrantDraftV1};

/// The Timelines seeded into a served store before the Gateway opens it.
struct Seeded {
    /// An unowned root.
    unowned: TimelineId,
    /// The identity-preserving import of a Timeline the actor owns.
    own_import: TimelineId,
    /// The identity-preserving import of a Timeline the other actor owns.
    other_import: TimelineId,
    /// The identity-preserving import of an unowned Timeline.
    unowned_import: TimelineId,
}

/// The identity-preserving export of an empty root that `owner` owns on
/// another store.
fn export_of(owner: Option<EntityId>) -> TestResult<TimelineExport> {
    let mut source = MemoryStore::new();
    source.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let timeline = source
        .create_timeline_with_meta(TimelineMeta {
            owner,
            ..TimelineMeta::root("exported")
        })?
        .id();
    let timeline = source
        .get_timeline(timeline)?
        .ok_or("no exported Timeline")?;
    drop(source);
    Ok(TimelineExport {
        timeline,
        events: Vec::new(),
        parent_fork_hash: None,
    })
}

/// Seed the store at `path` with an unowned root and three imports that
/// keep their exported owner (owner decision of 2026-11-20: ownership
/// follows the data).
fn seed(path: &str) -> TestResult<Seeded> {
    let mut store = SqliteStore::open(path)?;
    store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
    let unowned = store
        .create_timeline_with_meta(TimelineMeta::root("unowned"))?
        .id();
    let mut import = |owner: Option<EntityId>| -> TestResult<TimelineId> {
        let imported = import_timeline_with_id(&mut store, export_of(owner)?)?;
        assert_eq!(imported.meta.owner, owner);
        Ok(imported.id())
    };
    let seeded = Seeded {
        unowned,
        own_import: import(Some(actor()?))?,
        other_import: import(Some(other_actor()?))?,
        unowned_import: import(None)?,
    };
    drop(store);
    Ok(seeded)
}

/// Every replay claim, strongest first.
const CLAIMS: [ErasureReplayClaimV1; 5] = [
    ErasureReplayClaimV1::Exact,
    ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews,
    ErasureReplayClaimV1::StructuralOnly,
    ErasureReplayClaimV1::UnverifiableArtifactsMissing,
    ErasureReplayClaimV1::IncompatibleProfile,
];

/// Acceptance test 9: along the projections `observed`, in order, the
/// `generation` never decreases and the replay claim never strengthens.
fn assert_monotonic(observed: &[Value]) -> TestResult {
    let mut previous: Option<(u64, ErasureReplayClaimV1)> = None;
    for body in observed {
        let generation = body["generation"].as_u64().ok_or("no generation")?;
        let name = body["replay_claim"].as_str().ok_or("no replay claim")?;
        let claim = CLAIMS
            .into_iter()
            .find(|claim| replay_claim_name(*claim) == name)
            .ok_or("an unknown replay claim")?;
        if let Some((earlier_generation, earlier_claim)) = previous {
            assert!(earlier_generation <= generation, "{observed:?}");
            // `weakened_to` returns the later claim only when it is not
            // stronger than the earlier one, and the earlier claim otherwise.
            assert_eq!(earlier_claim.weakened_to(claim), claim, "{observed:?}");
        }
        previous = Some((generation, claim));
    }
    Ok(())
}

/// The values an erasure answer may disclose (acceptance test 9).
struct Disclosure {
    /// The declared digests: the key digests, the policy, the bundle and
    /// the mode profile a receipt binds.
    declared: Vec<String>,
    /// The ids a request named: its `erasure_id`s.
    ids: Vec<String>,
}

impl Disclosure {
    /// The digests `receipt` declares, and `ids`.
    fn of(receipt: &Value, ids: &[String]) -> TestResult<Self> {
        let bound = &receipt["bound_inputs"];
        let declared = [
            &receipt["idempotency_key_digest"],
            &bound["policy"],
            &bound["trust"],
            &bound["mode_profile"],
        ]
        .into_iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or("no declared digest")
        })
        .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            declared,
            ids: ids.to_vec(),
        })
    }

    /// The golden check of one answer, its headers included: every 64-hex
    /// token is a declared digest or the body's own `provenance.digest`,
    /// every ULID token is an id the request named, and no owner name
    /// appears. No Timeline, actor, owner, store identity or other state
    /// digest therefore does.
    fn check(&self, answer: &Answer) -> TestResult {
        let mut text = String::from_utf8(answer.bytes.clone())?;
        for value in answer.headers.values() {
            text.push(' ');
            text.push_str(value.to_str()?);
        }
        let body = serde_json::from_slice::<Value>(&answer.bytes).unwrap_or_default();
        self.check_text(&text, body["provenance"]["digest"].as_str());
        Ok(())
    }

    /// [`Self::check`] of one projection body.
    fn check_body(&self, body: &Value) {
        self.check_text(&body.to_string(), body["provenance"]["digest"].as_str());
    }

    fn check_text(&self, text: &str, provenance: Option<&str>) {
        for withheld in [SIGNER_OWNER, "subject:"] {
            assert!(!text.contains(withheld), "{withheld} in {text}");
        }
        for token in text.split(|character: char| !character.is_ascii_alphanumeric()) {
            if token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                assert!(
                    self.declared.iter().any(|digest| digest == token) || provenance == Some(token),
                    "an undeclared digest {token} in {text}"
                );
            }
            if token.len() == 26 && Ulid::from_string(token).is_ok() {
                assert!(
                    self.ids.iter().any(|id| id == token),
                    "an undeclared id {token} in {text}"
                );
            }
        }
    }
}

impl Served {
    /// `POST /v1/timelines` by `actor`: the new root's id.
    async fn create(&self, actor: EntityId, name: &str) -> TestResult<String> {
        let created = self
            .send(
                "POST",
                "/v1/timelines",
                actor,
                None,
                Some(json!({"name": name})),
            )
            .await?;
        assert_eq!(created.status, StatusCode::CREATED);
        let body = created.json()?;
        let id = body["id"].as_str().ok_or("no Timeline id")?.to_owned();
        Ok(id)
    }

    /// The status and problem code of `actor`'s Event read of `timeline`.
    async fn events(&self, actor: EntityId, timeline: &str) -> TestResult<(StatusCode, Value)> {
        let read = self
            .send(
                "GET",
                &format!("/v1/timelines/{timeline}/events"),
                actor,
                None,
                None,
            )
            .await?;
        let code = read.json()?["code"].clone();
        Ok((read.status, code))
    }

    /// The owner the Gateway's store records for `timeline`.
    async fn owner(&self, timeline: TimelineId) -> TestResult<Option<EntityId>> {
        let held = self
            .gateway
            .store
            .timeline(timeline)
            .await
            .map_err(crate::GatewayError::from)?;
        Ok(held.ok_or("no Timeline")?.meta.owner)
    }

    /// Whether the Gateway's store holds, unfrozen, the Consent Timeline
    /// and the Erasure Host Timeline.
    async fn holds_the_consent_and_erasure_host_timelines(&self) -> TestResult<bool> {
        let consents = crate::local_principal::local_principal_consent_timeline();
        let roots = self.gateway.host_timelines().roots();
        assert_eq!(roots.len(), 3, "the Erasure Host Timeline is recorded");
        let erasure_host = roots
            .iter()
            .copied()
            .find(|root| *root != consents && *root != local_principal_authority_timeline())
            .ok_or("no Erasure Host Timeline")?;
        for root in [consents, erasure_host] {
            let held = self
                .gateway
                .store
                .timeline(root)
                .await
                .map_err(crate::GatewayError::from)?;
            if held.is_none() {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// The `timeline-payload` class row of a projection.
fn payload_class(projection: &Value) -> TestResult<Value> {
    Ok(projection["acknowledgements"]["classes"]
        .as_array()
        .ok_or("no classes")?
        .iter()
        .find(|class| class["class"] == "timeline-payload")
        .ok_or("no timeline-payload class")?
        .clone())
}

/// Acceptance test 2 at the Gateway, with the golden check of test 9.
///
/// The actor's erasure freezes its own root and the import of a Timeline it
/// owns (owner decision of 2026-11-20); another actor's root, an unowned
/// root and the imports of another owner's and of an unowned Timeline stay
/// readable through the served router. Every erasure answer discloses only
/// its declared digests and ids, and the projection's generation only rises
/// while its claim only weakens.
async fn the_served_partition_freezes_only_the_actors_lineage(mode: ServeMode) -> TestResult {
    let world = mode.world(&SERVED)?;
    let seeded = seed(&world.fixture.path)?;
    let (served, driver) = Served::over(world, mode, compiled())?;
    let (actor, other) = (actor()?, other_actor()?);
    let owned = served.create(actor, "owned").await?;
    let others = served.create(other, "others").await?;
    let admitted = served
        .request(actor, "erasure-1", "private-subject-data")
        .await?;
    assert_eq!(admitted.status, StatusCode::ACCEPTED);
    let id = erasure_id(actor, "erasure-1")?.to_string();
    let observed = served.receipted(actor, &id).await?;
    assert_monotonic(&observed)?;
    let last = observed.last().ok_or("no projection")?;
    assert_eq!(last["state"], "partial-failure");
    // Two affected Timelines: the actor's root and its own import.
    assert_eq!(payload_class(last)?["required"], 2);
    for frozen in [owned, seeded.own_import.to_string()] {
        assert_eq!(
            served.events(actor, &frozen).await?,
            (StatusCode::FORBIDDEN, json!("deleted")),
            "{frozen}"
        );
    }
    for open in [
        others,
        seeded.unowned.to_string(),
        seeded.other_import.to_string(),
        seeded.unowned_import.to_string(),
    ] {
        assert_eq!(
            served.events(other, &open).await?.0,
            StatusCode::OK,
            "{open}"
        );
    }
    // Acceptance test 9: the receipt, its exact retry, every projection,
    // the idempotency conflict, the subject's own read and the 404s.
    let disclosure = Disclosure::of(&admitted.json()?, &[id.clone(), Ulid::nil().to_string()])?;
    disclosure.check(&admitted)?;
    for body in &observed {
        disclosure.check_body(body);
    }
    // Each answer is bound before the next await, so no `?` result is
    // held across one (`future_not_send`).
    let retried = served
        .request(actor, "erasure-1", "private-subject-data")
        .await?;
    let conflict = served
        .request(actor, "erasure-1", "consented-shared-data")
        .await?;
    let own = served.read(actor, &id).await?;
    let foreign = served.read(other, &id).await?;
    let unknown = served.read(actor, &Ulid::nil().to_string()).await?;
    for answer in [retried, conflict, own, foreign, unknown] {
        disclosure.check(&answer)?;
    }
    served.stop(driver).await?;
    Ok(())
}

/// Acceptance test 8 with lowered, test-only limits (D11): with two actors
/// and 514 request heads `q_subject` is `(514 - 512) / 2 = 1`. Once every
/// actor has used its share, a restarted Gateway recovers the store; each
/// exact retry still answers its original receipt bytes and each actor's
/// next request is `409 erasure-quota-exhausted`, so the store holds
/// exactly `maximum_requests - reserve = 2` requests.
async fn every_actors_used_quota_holds_across_a_restart(mode: ServeMode) -> TestResult {
    let limits = ErasureRecoveryLimitsV1::from_maximum_requests(514)?;
    let (served, driver) = Served::serve(mode, &SERVED, limits)?;
    let subjects = [actor()?, other_actor()?];
    let mut receipts = Vec::new();
    for subject in subjects {
        let admitted = served
            .request(subject, "erasure-1", "private-subject-data")
            .await?;
        assert_eq!(admitted.status, StatusCode::ACCEPTED);
        let id = erasure_id(subject, "erasure-1")?.to_string();
        served.receipted(subject, &id).await?;
        receipts.push(admitted.bytes);
    }
    let world = served.stop(driver).await?;
    let (served, driver) = Served::over(world, mode, limits)?;
    // Each recovered request reads at its first receipt again, and the
    // driver is then stopped, so nothing advances under the requests below.
    for subject in subjects {
        let id = erasure_id(subject, "erasure-1")?.to_string();
        served.receipted(subject, &id).await?;
    }
    driver.stop().await;
    // Why `409` and never `429`: `local_subject_admission` answers
    // `Concurrent` only for a request that is pre-terminal or has an active
    // attempt. Each request is past its first receipt, and its closure (the
    // store target's cache signal and replica) has no transient negative
    // without a held `SQLite` reader, so no retry attempt is ever admitted
    // and none is active. The scan then counts one request against
    // `q_subject = 1`, which is `QuotaExhausted`. The exact retry is
    // answered before that check.
    for (subject, receipt) in subjects.into_iter().zip(&receipts) {
        let retried = served
            .request(subject, "erasure-1", "private-subject-data")
            .await?;
        assert_eq!(
            (retried.status, &retried.bytes),
            (StatusCode::ACCEPTED, receipt)
        );
        let exhausted = served
            .request(subject, "erasure-2", "consented-shared-data")
            .await?;
        assert_eq!(
            exhausted.problem()?,
            (
                StatusCode::CONFLICT,
                "erasure-quota-exhausted".to_owned(),
                false
            )
        );
    }
    served.shut_down().await?;
    Ok(())
}

/// The operations of the consent test: one consent governs Timeline
/// creation; the Session, the revocation and both erasure operations are
/// governed by none.
const CONSENTED: [GatewayOperationV1; 6] = [
    GatewayOperationV1::CREATE_TIMELINE,
    GatewayOperationV1::READ_EVENTS,
    GatewayOperationV1::READ_SESSION,
    GatewayOperationV1::REVOKE_CONSENT,
    GatewayOperationV1::REQUEST_ERASURE,
    GatewayOperationV1::READ_ERASURE,
];

/// A Local erasure world for `mode` whose Principal binds one consent of
/// the actor, governing Timeline creation.
fn consented_world(mode: ServeMode) -> TestResult<World> {
    mode.provisioned(&LocalPrincipalProvisionV1::try_new_with_consent(
        &principal()?,
        [actor()?, other_actor()?],
        CONSENTED,
        Some(&LocalConsentDraftV1 {
            subject: actor()?,
            grantee: actor()?,
            grants: vec![LocalConsentGrantDraftV1 {
                purpose: "operation".to_owned(),
                data_categories: vec!["timeline".to_owned()],
                export_permitted: false,
            }],
        }),
    )?)
}

/// `POST /v1/me/consent-revocations` of `consent` by `actor` under `key`.
async fn revoke(
    served: &Served,
    actor: EntityId,
    consent: &Value,
    key: &str,
) -> TestResult<Answer> {
    served
        .send(
            "POST",
            "/v1/me/consent-revocations",
            actor,
            Some(key),
            Some(json!({"consent_ref": consent})),
        )
        .await
}

/// Acceptance tests 8 and 2 at the Gateway: after the actor revoked its
/// consent, which then refuses the Timeline creation it governed,
/// `requestErasure` is still `202` (both erasure operations are
/// consent-exempt). The consent-subject actor's erasure leaves the Consent
/// Timeline and the Erasure Host Timeline unaffected and available: the
/// closure holds only the actor's root, the Session still reads the
/// revoked consent and the revocation's exact retry still answers its
/// original bytes.
async fn a_revoked_consent_still_admits_an_erasure_that_spares_the_host_timelines(
    mode: ServeMode,
) -> TestResult {
    // The answers are the same in every mode. An Air-Gapped binding only
    // fixes the authorizer's revocation-freshness claim to current
    // (`with_mode_binding`, D10), and every serve composition already
    // recomposes the Local Principal from its store with the claim current
    // (`every_serve_composition_binds_the_served_mode`). The consent
    // revocation is a Consent Timeline record that both read alike.
    let (served, driver) = Served::over(consented_world(mode)?, mode, compiled())?;
    let actor = actor()?;
    served.create(actor, "owned").await?;
    let session = served
        .send("GET", "/v1/session", actor, None, None)
        .await?
        .json()?;
    let consent = session["consents"][0]["consent_ref"].clone();
    let revoked = revoke(&served, actor, &consent, "revoke-1").await?;
    assert_eq!(revoked.status, StatusCode::CREATED);
    let refused = served
        .send(
            "POST",
            "/v1/timelines",
            actor,
            None,
            Some(json!({"name": "after-revocation"})),
        )
        .await?;
    assert_eq!(
        (refused.status, refused.json()?["code"].clone()),
        (StatusCode::FORBIDDEN, json!("revoked"))
    );
    let admitted = served
        .request(actor, "erasure-1", "private-subject-data")
        .await?;
    assert_eq!(admitted.status, StatusCode::ACCEPTED);
    let id = erasure_id(actor, "erasure-1")?.to_string();
    let observed = served.receipted(actor, &id).await?;
    assert_monotonic(&observed)?;
    let last = observed.last().ok_or("no projection")?;
    assert_eq!(last["acknowledgements"]["required"], 3);
    assert_eq!(payload_class(last)?["required"], 1);
    let after = served
        .send("GET", "/v1/session", actor, None, None)
        .await?
        .json()?;
    assert_eq!(after["consents"][0]["consent_ref"], consent);
    assert_eq!(after["consents"][0]["state"], "revoked");
    let retried = revoke(&served, actor, &consent, "revoke-1").await?;
    assert_eq!(retried.status, StatusCode::OK);
    assert_eq!(retried.json()?, revoked.json()?);
    assert!(
        served
            .holds_the_consent_and_erasure_host_timelines()
            .await?
    );
    served.stop(driver).await?;
    Ok(())
}

in_every_serve_mode!(
    the_served_partition_freezes_only_the_actors_lineage,
    every_actors_used_quota_holds_across_a_restart,
    a_revoked_consent_still_admits_an_erasure_that_spares_the_host_timelines,
);

/// The FAL1 Fork of `parent` with the operation byte `operation`, sent to
/// the managed listener at `socket`: the FARL1 answer.
fn fork(socket: &Path, operation: u8, parent: &str) -> TestResult<Vec<u8>> {
    let parent = TimelineId::from_ulid(Ulid::from_string(parent)?);
    Ok(request(socket, &fork_payload(operation, parent)?, false)?)
}

/// Acceptance tests 2 and 11 through the Fork admission service of the
/// managed mode.
///
/// A Fork the service admits of the actor's root, for the service's own
/// principal, is a descendant of that root, so the actor's erasure freezes
/// it with the root: two `timeline-payload` targets. After the freeze the
/// service refuses a Fork of the frozen root with code 5, the ADR-106
/// containment answer for a parent an active request covers, and still
/// admits a Fork of another actor's root, which stays readable.
#[tokio::test]
async fn the_fork_admission_service_forks_into_and_beside_an_erasure() -> TestResult {
    let mode = ServeMode::ManagedLocalForkAdmission;
    let (served, driver) = Served::serve(mode, &SERVED, compiled())?;
    let (actor, other) = (actor()?, other_actor()?);
    let owned = served.create(actor, "owned").await?;
    let others = served.create(other, "others").await?;
    let socket = socket_of(&served.world)?;
    // The FCC1 needs only the POC1 binding of the service's own principal
    // (`admitted_fork_binding` looks it up by principal digest) and a
    // visible parent; it never compares the parent's Timeline owner, so the
    // actor's HTTP-created root is a valid parent.
    assert_eq!(&request(&socket, &bind_payload(60), false)?[..10], &BIND_OK);
    let (child, _) = fork_result(&fork(&socket, 61, &owned)?)?;
    // ADR-136 §1 (#1477): the FCC1 child inherits its parent's owner, the
    // actor, although the service's own principal made the Fork.
    assert_eq!(served.owner(child).await?, Some(actor));
    let descendant = child.to_string();
    assert_eq!(served.events(actor, &descendant).await?.0, StatusCode::OK);
    let admitted = served
        .request(actor, "erasure-1", "private-subject-data")
        .await?;
    assert_eq!(admitted.status, StatusCode::ACCEPTED);
    let observed = served
        .receipted(actor, &erasure_id(actor, "erasure-1")?.to_string())
        .await?;
    assert_monotonic(&observed)?;
    let last = observed.last().ok_or("no projection")?;
    assert_eq!(last["state"], "partial-failure");
    // The actor owns the child, so the Local freeze (`affected_timelines`)
    // takes it with the actor's root, and the closure has one
    // `timeline-payload` target per affected Timeline: the root and the
    // child.
    assert_eq!(payload_class(last)?["required"], 2);
    for frozen in [&owned, &descendant] {
        assert_eq!(
            served.events(actor, frozen).await?,
            (StatusCode::FORBIDDEN, json!("deleted")),
            "{frozen}"
        );
    }
    // ADR errata (owner 2026-11-20): the service refuses a Fork of a parent
    // an active request covers (ADR-106 r3 containment); joining the frozen
    // scope holds at the runtime seam.
    assert_eq!(fork(&socket, 62, &owned)?, rejected(5));
    let (beside, _) = fork_result(&fork(&socket, 63, &others)?)?;
    assert_eq!(served.owner(beside).await?, Some(other));
    assert_eq!(
        served.events(other, &beside.to_string()).await?.0,
        StatusCode::OK
    );
    served.stop(driver).await?;
    Ok(())
}
