//! Public Gateway seam tests for ADR-021 human action admission (#319).
//!
//! Every case runs against the host-owned `MemoryStore` and `SQLite`
//! adapters, so authorization, domain approval, host admission, and commit are
//! exercised through the same store command the production Gateway uses.

use std::{num::NonZeroUsize, sync::Arc};

use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    AuthorityGranteeV1, AuthorityPersistenceHostV1, AuthorityPersistenceStateV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, AuthorityViewV1, AuthorizationDenialEvidenceV1,
    AuthorizationDenialRecordV1, AuthorizationDenialScopeV1, AuthorizationDenialSuppressionV1,
    CanonicalBytes, CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityRevocationDraftV1,
    CapabilityRevocationV1, CapabilityScopeDraftV1, CapabilityScopeV1, EntityId,
    ErasureRecoveryLimitsV1, Hash, Kind, PrincipalRefV1, ProposedAction, Seq, TimelineId, WallTime,
};
use pos_runtime::ErasureExecutionHostV1;
use pos_store::StoreConfig;
use tokio::sync::broadcast;

use crate::{
    authorization::{
        test_authorization_for, test_authorization_reject_after_first_for,
        test_expired_authorization_for, test_expired_grant_authorization_for,
        test_revoked_authority_for, GatewayAuthorizationRequest, LocalAuthenticationAdapter,
    },
    executor, gateway_empty_action_registry, gateway_with_erasure_host_and_authorization,
    AdmittedAction, Gateway, GatewayAuthorityDenial, GatewayAuthorization, GatewayError,
    GatewayLimits, HumanActionRequest, EVENT_BUS_CAPACITY, EVENT_TYPE_ACTION,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const CAPABILITY: &str = "world.action.v1.submit";

/// One host-owned store configuration; the directory keeps a file alive.
struct Backend {
    name: &'static str,
    config: StoreConfig,
    _directory: Option<tempfile::TempDir>,
}

fn backends() -> TestResult<Vec<Backend>> {
    let directory = tempfile::tempdir()?;
    let path = directory
        .path()
        .join("human-action.sqlite")
        .to_str()
        .ok_or("temporary path is not UTF-8")?
        .to_owned();
    Ok(vec![
        Backend {
            name: "memory",
            config: StoreConfig::Memory,
            _directory: None,
        },
        Backend {
            name: "sqlite",
            config: StoreConfig::Sqlite { path },
            _directory: Some(directory),
        },
    ])
}

/// Open or reopen a host the way the production Gateway startup does.
fn host(config: &StoreConfig) -> TestResult<ErasureExecutionHostV1> {
    Ok(ErasureExecutionHostV1::open_with_authority(
        config.clone(),
        &pos_runtime::ErasureCoordinatorCompositionV1::closed(),
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )?)
}

struct Fixture {
    gateway: Gateway,
    authorization: GatewayAuthorization,
    timeline: TimelineId,
    actor: EntityId,
    body: EntityId,
}

async fn fixture_with(
    host: ErasureExecutionHostV1,
    authorization: GatewayAuthorization,
    actor: EntityId,
    body: EntityId,
) -> TestResult<Fixture> {
    let gateway = gateway_with_erasure_host_and_authorization(host, [body], authorization.clone())?;
    let timeline = gateway.create_timeline("human-action").await?.id();
    Ok(Fixture {
        gateway,
        authorization,
        timeline,
        actor,
        body,
    })
}

async fn fixture(config: &StoreConfig) -> TestResult<Fixture> {
    let actor = EntityId::new();
    fixture_with(
        host(config)?,
        test_authorization_for(actor),
        actor,
        EntityId::new(),
    )
    .await
}

fn payload(actor: EntityId, body: EntityId, tick: u64) -> serde_json::Value {
    serde_json::json!({
        "actor_entity_id": actor,
        "body_entity_id": body,
        "action_kind": "impulse",
        "params": [1.0, 0.0],
        "action_scope": 0,
        "catalogue_version": 1,
        "tick": tick
    })
}

fn proposal(fixture: &Fixture, tick: u64) -> TestResult<ProposedAction> {
    Ok(crate::build_proposed_action(
        fixture.actor,
        EVENT_TYPE_ACTION,
        &payload(fixture.actor, fixture.body, tick),
        CAPABILITY,
    )?)
}

async fn submit(
    fixture: &Fixture,
    tick: u64,
    key: Option<&str>,
    observed_through: Option<u64>,
) -> TestResult<Result<AdmittedAction, GatewayError>> {
    let timeline = fixture.timeline.to_string();
    Ok(fixture
        .gateway
        .submit_human_action(HumanActionRequest {
            timeline_id: &timeline,
            proposal: proposal(fixture, tick)?,
            idempotency_key: key,
            observed_through,
        })
        .await)
}

async fn committed_events(fixture: &Fixture) -> TestResult<u64> {
    Ok(fixture
        .gateway
        .store
        .protected_logical_head(fixture.timeline)
        .await
        .map_err(|error| format!("{error:?}"))?
        .as_u64())
}

fn admitted(result: Result<AdmittedAction, GatewayError>) -> TestResult<AdmittedAction> {
    result.map_err(|error| format!("expected an admitted action, got {error:?}").into())
}

fn rejected(result: Result<AdmittedAction, GatewayError>) -> TestResult<GatewayError> {
    result
        .err()
        .ok_or_else(|| "expected a typed rejection".into())
}

#[tokio::test]
async fn a_human_action_commits_only_through_admission_with_its_receipt() -> TestResult {
    for backend in backends()? {
        let name = backend.name;
        let fixture = fixture(&backend.config).await?;
        let mut notices = fixture.gateway.subscribe();

        let action = admitted(submit(&fixture, 1, Some("first"), Some(0)).await?)?;

        let receipt = action.receipt();
        assert_eq!(receipt.timeline_id(), fixture.timeline, "{name}");
        assert_eq!(receipt.committed_events().len(), 1, "{name}");
        assert_eq!(receipt.committed_events()[0].event_id(), action.event().id);
        assert_eq!(receipt.committed_events()[0].seq(), Seq::from_u64(1));
        assert_eq!(action.event().seq, Seq::from_u64(1), "{name}");
        assert_eq!(action.event().entity, fixture.actor, "{name}");
        assert!(!action.duplicate(), "{name}");
        assert_eq!(notices.recv().await?.seq, 1, "{name}");
        assert_eq!(committed_events(&fixture).await?, 1, "{name}");

        // The audit names the authenticated Principal and the acting Entity
        // separately; neither stands in for the other.
        let audits = fixture.authorization.audits();
        assert_eq!(audits.len(), 1, "{name}");
        assert_eq!(audits[0].event_id(), Some(action.event().id), "{name}");
        assert_eq!(audits[0].actor_entity_id(), fixture.actor, "{name}");
        assert_eq!(audits[0].principal().trust_domain(), "gateway.test");
        assert_ne!(
            audits[0].principal().principal_id(),
            &fixture.actor.inner().to_bytes(),
            "{name}"
        );

        // A request without a key or cursor binds the current Logical Head.
        let unkeyed = admitted(submit(&fixture, 2, None, None).await?)?;
        assert_eq!(unkeyed.event().seq, Seq::from_u64(2), "{name}");
        fixture.gateway.shutdown().await?;
        drop(fixture);
    }
    Ok(())
}

#[tokio::test]
async fn an_exact_retry_recovers_the_committed_receipt_without_readmission() -> TestResult {
    for backend in backends()? {
        let name = backend.name;
        let fixture = fixture(&backend.config).await?;
        let first = admitted(submit(&fixture, 1, Some("retry"), Some(0)).await?)?;
        admitted(submit(&fixture, 2, Some("other"), Some(1)).await?)?;
        let mut notices = fixture.gateway.subscribe();

        // The retry's cursor is now stale, so any re-approval or re-admission
        // would be rejected; only the retained receipt can answer it.
        let retry = admitted(submit(&fixture, 1, Some("retry"), Some(0)).await?)?;

        assert!(retry.duplicate(), "{name}");
        assert_eq!(retry.receipt(), first.receipt(), "{name}");
        assert_eq!(retry.event(), first.event(), "{name}");
        assert_eq!(committed_events(&fixture).await?, 2, "{name}");
        assert!(
            notices.try_recv().is_err(),
            "{name}: a recovered receipt is not announced again"
        );
        assert_eq!(fixture.authorization.audits().len(), 3, "{name}");
        fixture.gateway.shutdown().await?;
        drop(fixture);
    }
    Ok(())
}

#[tokio::test]
async fn a_reused_key_for_another_request_is_a_typed_conflict() -> TestResult {
    for backend in backends()? {
        let name = backend.name;
        let fixture = fixture(&backend.config).await?;
        admitted(submit(&fixture, 1, Some("shared"), None).await?)?;

        let changed_payload = rejected(submit(&fixture, 2, Some("shared"), None).await?)?;
        let changed_cursor = rejected(submit(&fixture, 1, Some("shared"), Some(1)).await?)?;

        assert!(
            matches!(changed_payload, GatewayError::IngressConflict),
            "{name}"
        );
        assert!(
            matches!(changed_cursor, GatewayError::IngressConflict),
            "{name}"
        );
        assert_eq!(committed_events(&fixture).await?, 1, "{name}");
        fixture.gateway.shutdown().await?;
        drop(fixture);
    }
    Ok(())
}

#[tokio::test]
async fn a_stale_or_unobserved_cursor_commits_nothing_and_enumerates_nothing() -> TestResult {
    for backend in backends()? {
        let name = backend.name;
        let fixture = fixture(&backend.config).await?;

        let ahead = rejected(submit(&fixture, 1, Some("ahead"), Some(5)).await?)?;
        admitted(submit(&fixture, 2, Some("current"), Some(0)).await?)?;
        let behind = rejected(submit(&fixture, 3, Some("behind"), Some(0)).await?)?;

        assert!(
            matches!(ahead, GatewayError::ActionObservationStale),
            "{name}"
        );
        assert!(
            matches!(behind, GatewayError::ActionObservationStale),
            "{name}"
        );
        assert_eq!(ahead.to_string(), behind.to_string(), "{name}");
        assert_eq!(committed_events(&fixture).await?, 1, "{name}");

        // A rejected attempt is never retried for the caller: resubmitting
        // the same stale request is evaluated afresh and rejected again.
        let resubmitted = rejected(submit(&fixture, 3, Some("behind"), Some(0)).await?)?;
        assert!(
            matches!(resubmitted, GatewayError::ActionObservationStale),
            "{name}"
        );
        assert_eq!(committed_events(&fixture).await?, 1, "{name}");
        fixture.gateway.shutdown().await?;
        drop(fixture);
    }
    Ok(())
}

#[tokio::test]
async fn domain_denial_and_a_missing_plugin_commit_nothing() -> TestResult {
    for backend in backends()? {
        let name = backend.name;
        let fixture = fixture(&backend.config).await?;
        let timeline = fixture.timeline.to_string();
        let foreign_body = crate::build_proposed_action(
            fixture.actor,
            EVENT_TYPE_ACTION,
            &payload(fixture.actor, EntityId::new(), 1),
            CAPABILITY,
        )?;

        let denied = fixture
            .gateway
            .submit_human_action(HumanActionRequest {
                timeline_id: &timeline,
                proposal: foreign_body,
                idempotency_key: Some("denied"),
                observed_through: None,
            })
            .await;

        assert!(
            matches!(
                denied,
                Err(GatewayError::ActionRejected(
                    pos_core::ActionRejected::DomainValidationFailed(_)
                ))
            ),
            "{name}: {denied:?}"
        );
        assert_eq!(committed_events(&fixture).await?, 0, "{name}");
        assert!(fixture.authorization.audits().is_empty(), "{name}");
        fixture.gateway.shutdown().await?;
        drop(fixture);

        // The same authorized request against a host with no registered
        // owning Plugin fails closed instead of falling back.
        let actor = EntityId::new();
        let missing = missing_plugin_gateway(host(&StoreConfig::Memory)?, actor)?;
        let missing_timeline = missing.create_timeline("missing-plugin").await?;
        let outcome = missing
            .submit_proposed_action(
                &missing_timeline.id().to_string(),
                ProposedAction::new(
                    Kind::new(EVENT_TYPE_ACTION),
                    actor,
                    CanonicalBytes::from_static(b"payload"),
                    Kind::new(CAPABILITY),
                ),
            )
            .await;
        assert!(
            matches!(
                outcome,
                Err(GatewayError::ActionRejected(
                    pos_core::ActionRejected::UnknownEventType
                ))
            ),
            "{name}: {outcome:?}"
        );
        assert_eq!(
            missing
                .store
                .protected_logical_head(missing_timeline.id())
                .await
                .map_err(|error| format!("{error:?}"))?,
            Seq::ZERO
        );
        missing.shutdown().await?;
        drop(missing);
    }
    Ok(())
}

fn missing_plugin_gateway(host: ErasureExecutionHostV1, actor: EntityId) -> TestResult<Gateway> {
    let gate = host.containment_gate();
    let consent_authority = pos_core::ConsentAuthority::new();
    let store =
        executor::StoreExecutor::new_with_erasure_host(host, consent_authority.append_permit())?;
    Ok(Gateway::from_host_components(
        store,
        broadcast::channel(EVENT_BUS_CAPACITY).0,
        GatewayLimits::LOCAL_DEFAULT,
        false,
        Ok(gateway_empty_action_registry(
            consent_authority.clone(),
            gate,
        )),
        consent_authority,
        Some(Arc::new(test_authorization_for(actor))),
    )?)
}

#[tokio::test]
async fn authorization_precedes_approval_and_late_authority_failures_commit_nothing() -> TestResult
{
    for backend in backends()? {
        let name = backend.name;
        let fixture = fixture(&backend.config).await?;
        let timeline = fixture.timeline.to_string();

        // Principal authorization fails before the ActionApprover runs.
        let other_actor = fixture
            .gateway
            .submit_json_action(
                &timeline,
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &payload(fixture.actor, fixture.body, 1),
                CAPABILITY,
            )
            .await;
        assert!(
            matches!(
                other_actor,
                Err(GatewayError::AuthorizationDenied(denial)) if denial.denial() == GatewayAuthorityDenial::Unauthorized
            ),
            "{name}"
        );

        // A revocation installed after an earlier commit denies the next one.
        admitted(submit(&fixture, 1, Some("before-revocation"), None).await?)?;
        fixture
            .authorization
            .replace_authority(test_revoked_authority_for(fixture.actor))
            .await?;
        let revoked = rejected(submit(&fixture, 2, Some("after-revocation"), None).await?)?;
        assert!(
            matches!(
                revoked,
                GatewayError::AuthorizationDenied(denial) if denial.denial() == GatewayAuthorityDenial::Revoked
            ),
            "{name}"
        );
        assert_eq!(revoked.to_string(), "authority revoked", "{name}");
        // An exact retry of the committed request is authorized again first,
        // so it is denied rather than handed the retained receipt.
        let retry = rejected(submit(&fixture, 1, Some("before-revocation"), None).await?)?;
        assert!(
            matches!(
                retry,
                GatewayError::AuthorizationDenied(denial) if denial.denial() == GatewayAuthorityDenial::Revoked
            ),
            "{name}"
        );
        assert_eq!(committed_events(&fixture).await?, 1, "{name}");
        fixture.gateway.shutdown().await?;
        drop(fixture);
    }

    // Authentication that lapses between the request check and the commit
    // fence recheck, and expired Principal evidence, both fail closed.
    let actor = EntityId::new();
    let late = fixture_with(
        host(&StoreConfig::Memory)?,
        test_authorization_reject_after_first_for(actor),
        actor,
        EntityId::new(),
    )
    .await?;
    let lapsed = rejected(submit(&late, 1, Some("lapsed"), None).await?)?;
    assert!(matches!(lapsed, GatewayError::AuthorizationUnavailable));
    assert_eq!(committed_events(&late).await?, 0);
    assert!(late.authorization.audits().is_empty());
    late.gateway.shutdown().await?;
    drop(late);

    let expired = fixture_with(
        host(&StoreConfig::Memory)?,
        test_expired_authorization_for(actor),
        actor,
        EntityId::new(),
    )
    .await?;
    let outcome = rejected(submit(&expired, 1, Some("expired"), None).await?)?;
    assert!(matches!(
        outcome,
        GatewayError::AuthorizationDenied(denial) if denial.denial() == GatewayAuthorityDenial::Unauthenticated
    ));
    assert_eq!(committed_events(&expired).await?, 0);
    expired.gateway.shutdown().await?;
    drop(expired);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_race_never_commits_after_the_revocation_is_installed() -> TestResult {
    for backend in backends()? {
        let name = backend.name;
        let fixture = Arc::new(fixture(&backend.config).await?);
        let attempts = (0..16_u64)
            .map(|tick| {
                let fixture = Arc::clone(&fixture);
                tokio::spawn(async move {
                    let key = format!("race-{tick}");
                    submit(&fixture, tick, Some(&key), None)
                        .await
                        .map_err(|error| error.to_string())
                })
            })
            .collect::<Vec<_>>();
        fixture
            .authorization
            .replace_authority(test_revoked_authority_for(fixture.actor))
            .await?;
        let after = rejected(submit(&fixture, 99, Some("after-race"), None).await?)?;

        let mut committed = 0_u64;
        for attempt in attempts {
            let outcome = attempt.await??;
            match outcome {
                Ok(action) => {
                    committed += 1;
                    assert!(!action.duplicate(), "{name}");
                }
                Err(error) => {
                    assert!(
                        matches!(
                            error,
                            GatewayError::AuthorizationDenied(denial) if denial.denial() == GatewayAuthorityDenial::Revoked
                        ),
                        "{name}"
                    );
                }
            }
        }
        assert!(
            matches!(
                after,
                GatewayError::AuthorizationDenied(denial) if denial.denial() == GatewayAuthorityDenial::Revoked
            ),
            "{name}"
        );
        assert_eq!(committed_events(&fixture).await?, committed, "{name}");
        assert_eq!(
            u64::try_from(fixture.authorization.audits().len())?,
            committed,
            "{name}"
        );
        fixture.gateway.shutdown().await?;
        drop(fixture);
    }
    Ok(())
}

#[tokio::test]
async fn a_disconnect_after_commit_recovers_the_receipt_after_restart() -> TestResult {
    let directory = tempfile::tempdir()?;
    let config = StoreConfig::Sqlite {
        path: directory
            .path()
            .join("disconnect.sqlite")
            .to_str()
            .ok_or("temporary path is not UTF-8")?
            .to_owned(),
    };
    let actor = EntityId::new();
    let body = EntityId::new();
    let authorization = test_authorization_for(actor);
    let first = fixture_with(host(&config)?, authorization.clone(), actor, body).await?;
    // The caller never observes this receipt: the Gateway process stops.
    let lost = admitted(submit(&first, 1, Some("disconnect"), Some(0)).await?)?;
    first.gateway.shutdown().await?;
    drop(first);

    let restarted = Fixture {
        gateway: gateway_with_erasure_host_and_authorization(
            host(&config)?,
            [body],
            authorization.clone(),
        )?,
        authorization,
        timeline: lost.receipt().timeline_id(),
        actor,
        body,
    };
    let recovered = admitted(submit(&restarted, 1, Some("disconnect"), Some(0)).await?)?;

    assert!(recovered.duplicate());
    assert_eq!(recovered.receipt(), lost.receipt());
    assert_eq!(recovered.event(), lost.event());
    assert_eq!(committed_events(&restarted).await?, 1);
    restarted.gateway.shutdown().await?;
    drop(restarted);
    Ok(())
}

#[tokio::test]
async fn budget_exhaustion_is_typed_and_a_committed_retry_still_recovers() -> TestResult {
    for backend in backends()? {
        let name = backend.name;
        let mut fixture = fixture(&backend.config).await?;
        fixture.gateway.limits.max_events_per_timeline = 1;
        let first = admitted(submit(&fixture, 1, Some("budget"), None).await?)?;

        let exhausted = rejected(submit(&fixture, 2, Some("over-budget"), None).await?)?;
        let retry = admitted(submit(&fixture, 1, Some("budget"), None).await?)?;

        assert!(
            matches!(exhausted, GatewayError::EventLimitReached { maximum: 1 }),
            "{name}"
        );
        assert!(retry.duplicate(), "{name}");
        assert_eq!(retry.receipt(), first.receipt(), "{name}");
        assert_eq!(committed_events(&fixture).await?, 1, "{name}");
        fixture.gateway.shutdown().await?;
        drop(fixture);
    }
    Ok(())
}

#[tokio::test]
async fn an_authority_the_store_cannot_persist_is_indeterminate() -> TestResult {
    let mut foreign = host(&StoreConfig::Memory)?;
    let registry = AuthorityRegistrySnapshotV1::try_new(
        Hash::from_bytes([9; 32]),
        vec![Hash::from_bytes([10; 32])],
        vec![Hash::from_bytes([11; 32])],
        Vec::new(),
    )?;
    let other_host = AuthorityPersistenceHostV1::new(&registry);
    foreign
        .command_sender()?
        .with_scheduled_admission(|ports| {
            ports.bind_authority_persistence(other_host.persistence_binding())
        })??;
    let actor = EntityId::new();
    let fixture = fixture_with(
        foreign,
        test_authorization_for(actor),
        actor,
        EntityId::new(),
    )
    .await?;

    let outcome = rejected(submit(&fixture, 1, Some("foreign"), None).await?)?;

    assert!(matches!(outcome, GatewayError::AuthorizationUnavailable));
    assert_eq!(committed_events(&fixture).await?, 0);
    fixture.gateway.shutdown().await?;
    drop(fixture);
    Ok(())
}

#[tokio::test]
async fn a_store_without_an_admission_port_has_no_human_action_path() -> TestResult {
    let actor = EntityId::new();
    let body = EntityId::new();
    let gateway = Gateway::new_with_world_bodies_and_authorization(
        Box::new(pos_store::memory::MemoryStore::new()),
        [body],
        test_authorization_for(actor),
    );
    let timeline = gateway.create_timeline("no-admission-port").await?;

    let outcome = gateway
        .submit_json_action(
            &timeline.id().to_string(),
            &actor.to_string(),
            EVENT_TYPE_ACTION,
            &payload(actor, body, 1),
            CAPABILITY,
        )
        .await;

    assert!(matches!(
        outcome,
        Err(GatewayError::ActionAuthorizationUnavailable)
    ));
    assert!(gateway
        .purge_expired_action_receipts(NonZeroUsize::MIN)
        .await
        .is_err());
    gateway.shutdown().await?;
    drop(gateway);
    Ok(())
}

#[tokio::test]
async fn unexpired_receipts_survive_a_bounded_purge() -> TestResult {
    for backend in backends()? {
        let name = backend.name;
        let fixture = fixture(&backend.config).await?;
        let first = admitted(submit(&fixture, 1, Some("purge"), None).await?)?;

        let purged = fixture
            .gateway
            .purge_expired_action_receipts(NonZeroUsize::MIN)
            .await?;
        let retry = admitted(submit(&fixture, 1, Some("purge"), None).await?)?;

        assert_eq!(purged.removed, 0, "{name}");
        assert!(retry.duplicate(), "{name}");
        assert_eq!(retry.receipt(), first.receipt(), "{name}");
        fixture.gateway.shutdown().await?;
        drop(fixture);
    }
    Ok(())
}

#[tokio::test]
async fn a_fork_admits_at_its_logical_head() -> TestResult {
    let mut forked = host(&StoreConfig::Memory)?;
    let (root, child) = {
        let mut sender = forked.command_sender()?;
        let root = sender.create_timeline("logical-root")?.id();
        let entity = EntityId::new();
        sender.append(
            root,
            &[
                pos_core::EventDraft::new(
                    entity,
                    Kind::new(EVENT_TYPE_ACTION),
                    CanonicalBytes::from_static(b"r1"),
                ),
                pos_core::EventDraft::new(
                    entity,
                    Kind::new(EVENT_TYPE_ACTION),
                    CanonicalBytes::from_static(b"r2"),
                ),
            ],
        )?;
        let child = sender.fork_timeline(root, Seq::from_u64(2), "logical-child")?;
        (root, child.id())
    };
    let actor = EntityId::new();
    let mut fixture = fixture_with(
        forked,
        test_authorization_for(actor),
        actor,
        EntityId::new(),
    )
    .await?;
    fixture.timeline = child;
    // The owned budget counts only the child's own Events.
    fixture.gateway.limits.max_events_per_timeline = 1;

    let action = admitted(submit(&fixture, 1, Some("child"), Some(2)).await?)?;

    assert_eq!(action.event().seq, Seq::from_u64(3));
    assert_eq!(
        action.receipt().committed_events()[0].seq(),
        Seq::from_u64(3)
    );
    assert_eq!(committed_events(&fixture).await?, 3);
    assert_eq!(
        fixture
            .gateway
            .store
            .protected_logical_head(root)
            .await
            .map_err(|error| format!("{error:?}"))?,
        Seq::from_u64(2)
    );
    fixture.gateway.shutdown().await?;
    drop(fixture);
    Ok(())
}

#[test]
fn every_not_admitted_outcome_maps_to_a_stable_gateway_error() {
    use pos_core::PipelineOutcomeV1;
    let cases = [
        (
            PipelineOutcomeV1::AuthorityRevoked,
            "human action admission is unavailable",
        ),
        (
            PipelineOutcomeV1::AuthorityExpired,
            "human action admission is unavailable",
        ),
        (
            PipelineOutcomeV1::PolicyIndeterminate,
            "authorization unavailable",
        ),
        (
            PipelineOutcomeV1::ResourceExhausted,
            "event limit of 7 reached",
        ),
        (
            PipelineOutcomeV1::InvalidObservation,
            "action observation is stale",
        ),
        (
            PipelineOutcomeV1::AdmissionConflict,
            "action observation is stale",
        ),
        (
            PipelineOutcomeV1::DomainConflict,
            "action observation is stale",
        ),
        (PipelineOutcomeV1::Rejected, "action was not admitted"),
        (
            PipelineOutcomeV1::InvalidPluginResult,
            "action was not admitted",
        ),
        (
            PipelineOutcomeV1::InvalidProviderResult,
            "action was not admitted",
        ),
        (
            PipelineOutcomeV1::InvalidDependencyDeclaration,
            "human action admission is unavailable",
        ),
        (
            PipelineOutcomeV1::DependencySetExhausted,
            "timeline dependency set is exhausted",
        ),
    ];
    for (outcome, expected) in cases {
        let error = crate::action_command_error(
            executor::ActionCommandError::Admission(
                pos_runtime::HumanActionAdmissionErrorV1::NotAdmitted(Box::new(outcome)),
            ),
            7,
        );
        assert!(error.to_string().contains(expected), "{error}");
    }
    assert!(matches!(
        crate::action_command_error(
            executor::ActionCommandError::Admission(
                pos_runtime::HumanActionAdmissionErrorV1::IdempotencyConflict
            ),
            7
        ),
        GatewayError::IngressConflict
    ));
    assert!(matches!(
        crate::action_command_error(
            executor::ActionCommandError::Admission(
                pos_runtime::HumanActionAdmissionErrorV1::Contract(
                    pos_core::PipelineContractErrorV1::EmptyBatch
                )
            ),
            7
        ),
        GatewayError::ActionRejected(_)
    ));
    // A host derivation fault is unavailable, never a domain rejection.
    let host_fault = pos_runtime::HumanActionAdmissionErrorV1::HostContract(
        pos_core::PipelineContractErrorV1::EmptyBatch,
    );
    assert!(host_fault.to_string().contains("host admission inputs"));
    assert!(matches!(
        crate::action_command_error(executor::ActionCommandError::Admission(host_fault), 7),
        GatewayError::ActionAdmissionUnavailable
    ));
    assert!(matches!(
        crate::action_command_error(
            executor::ActionCommandError::Admission(
                pos_runtime::HumanActionAdmissionErrorV1::Store(
                    pos_core::CoreError::StorageOutcomeUnknown("lost".to_owned())
                )
            ),
            7
        ),
        GatewayError::Store(pos_core::CoreError::StorageOutcomeUnknown(_))
    ));
}

#[test]
fn an_exhausted_dependency_set_is_a_permanent_limit() {
    let error = pos_runtime::HumanActionAdmissionErrorV1::DependencyDeclaration(
        pos_core::FactualDependencyErrorV1::SetExhausted,
    );
    assert!(error.to_string().contains("exhausted"), "{error}");
    assert!(matches!(
        crate::action_command_error(executor::ActionCommandError::Admission(error), 7),
        GatewayError::DependencySetExhausted
    ));
}

#[test]
fn any_other_dependency_declaration_fault_is_unavailable() {
    let error = pos_runtime::HumanActionAdmissionErrorV1::DependencyDeclaration(
        pos_core::FactualDependencyErrorV1::UnresolvedInput,
    );
    assert!(matches!(
        crate::action_command_error(executor::ActionCommandError::Admission(error), 7),
        GatewayError::ActionAdmissionUnavailable
    ));
}

#[test]
fn every_authorization_failure_maps_to_a_stable_gateway_error() {
    use crate::GatewayAuthorizationError as Failure;
    let mapped = |failure| {
        crate::action_command_error(executor::ActionCommandError::Authorization(failure), 7)
    };
    assert!(matches!(
        mapped(Failure::AuthenticationUnavailable),
        GatewayError::AuthorizationUnavailable
    ));
    assert!(matches!(
        mapped(Failure::AuthorityUnavailable),
        GatewayError::AuthorizationUnavailable
    ));
    assert!(matches!(
        mapped(Failure::RequestUnavailable),
        GatewayError::InvalidAuthorizationRequest
    ));
    // A denial that never reached its store record is not answered as one.
    let actor = EntityId::new();
    let Err(Failure::Denied(pending)) =
        test_authorization_for(actor).authorize(GatewayAuthorizationRequest::action(
            EntityId::new(),
            TimelineId::new(),
            EVENT_TYPE_ACTION,
            CAPABILITY,
            WallTime::now(),
        ))
    else {
        std::panic::resume_unwind(Box::new("an unknown actor is denied"));
    };
    assert!(matches!(
        mapped(Failure::Denied(pending)),
        GatewayError::AuthorizationEvidenceUnavailable
    ));
}

#[test]
fn only_a_store_revocation_or_expiry_is_an_authority_denial_at_the_commit_fence() {
    use pos_core::{AuthorityErrorV1, AuthorizationOutcomeV1, PipelineOutcomeV1};
    assert_eq!(
        executor::commit_fence_authority(&PipelineOutcomeV1::AuthorityRevoked),
        Some((
            AuthorizationOutcomeV1::RevokedAtFence,
            Some(AuthorityErrorV1::RevokedAtFence)
        ))
    );
    assert_eq!(
        executor::commit_fence_authority(&PipelineOutcomeV1::AuthorityExpired),
        Some((AuthorizationOutcomeV1::Expired, None))
    );
    for outcome in [
        PipelineOutcomeV1::PolicyIndeterminate,
        PipelineOutcomeV1::Rejected,
        PipelineOutcomeV1::InvalidObservation,
        PipelineOutcomeV1::ResourceExhausted,
        PipelineOutcomeV1::InvalidPluginResult,
        PipelineOutcomeV1::InvalidProviderResult,
        PipelineOutcomeV1::DomainConflict,
        PipelineOutcomeV1::AdmissionConflict,
        PipelineOutcomeV1::InvalidDependencyDeclaration,
        PipelineOutcomeV1::DependencySetExhausted,
    ] {
        assert_eq!(
            executor::commit_fence_authority(&outcome),
            None,
            "{outcome:?}"
        );
    }
}

#[tokio::test]
async fn an_unknown_timeline_is_not_found_rather_than_unavailable() -> TestResult {
    for backend in backends()? {
        let name = backend.name;
        let mut fixture = fixture(&backend.config).await?;
        let existing = fixture.timeline;
        fixture.timeline = TimelineId::new();

        let outcome = rejected(submit(&fixture, 1, Some("unknown"), None).await?)?;

        assert!(
            matches!(
                outcome,
                GatewayError::Store(pos_core::CoreError::TimelineNotFound(timeline))
                    if timeline == fixture.timeline
            ),
            "{name}: {outcome:?}"
        );
        fixture.timeline = existing;
        assert_eq!(committed_events(&fixture).await?, 0, "{name}");
        fixture.gateway.shutdown().await?;
        drop(fixture);
    }
    Ok(())
}

#[tokio::test]
async fn a_stopped_store_executor_reports_its_stable_error() -> TestResult {
    let fixture = fixture(&StoreConfig::Memory).await?;
    fixture.gateway.shutdown().await?;

    let outcome = rejected(submit(&fixture, 1, Some("stopped"), None).await?)?;

    assert!(matches!(outcome, GatewayError::StoreExecutorClosed));
    drop(fixture);
    Ok(())
}

const HISTORY_REGISTRY: Hash = Hash::from_bytes([3; 32]);
const HISTORY_POLICY: Hash = Hash::from_bytes([4; 32]);

/// One authority history shared by the Gateway and another host (#483): a
/// root grant for the actor and an unrelated sibling root on the same
/// authority Timeline, both attested by one registry.
struct AuthorityHistory {
    authenticated: AuthenticatedPrincipalResultV1,
    root: CapabilityGrantV1,
    sibling: CapabilityGrantV1,
    registry: AuthorityRegistrySnapshotV1,
}

fn history_grant(
    actor: EntityId,
    principal: &PrincipalRefV1,
    timeline: TimelineId,
    id: u8,
    issuance: u64,
) -> TestResult<CapabilityGrantV1> {
    Ok(CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: Hash::from_bytes([id; 32]),
        grantor: principal.clone(),
        grantee: AuthorityGranteeV1::Principal(principal.clone()),
        trust_domain: "gateway.test".to_owned(),
        scope: CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
            resources: vec!["timeline.events".to_owned(), EVENT_TYPE_ACTION.to_owned()],
            actions: vec!["read".to_owned(), CAPABILITY.to_owned()],
            purposes: vec!["action".to_owned(), "read".to_owned()],
            audiences: vec!["gateway".to_owned()],
            actor_entity_ids: vec![actor],
            subject_ids: Vec::new(),
            participant_ids: Vec::new(),
            plugin_id: None,
            principal_roles: vec![AuthorityRoleV1::Actor],
            max_uses: 1,
            budget: 1,
            environment_constraints: Vec::new(),
        })?,
        valid_from_position: Seq::from_u64(issuance),
        valid_until_position: Seq::from_u64(50),
        parent_grant_id: None,
        delegation_depth: 0,
        max_delegation_depth: 0,
        permitted_delegate_classes: Vec::new(),
        consent_references: Vec::new(),
        policy_revision: HISTORY_POLICY,
        issuance_timeline: timeline,
        issuance_seq: Seq::from_u64(issuance),
        revocation_epoch: 0,
        revocation_fence: None,
        authority_registry_digest: HISTORY_REGISTRY,
    })?)
}

fn history_registry(
    authenticated: &AuthenticatedPrincipalResultV1,
    mut bindings: Vec<Hash>,
) -> TestResult<AuthorityRegistrySnapshotV1> {
    bindings.sort_unstable();
    Ok(AuthorityRegistrySnapshotV1::try_new(
        HISTORY_REGISTRY,
        vec![authenticated.registry_binding_digest()],
        bindings,
        Vec::new(),
    )?)
}

impl AuthorityHistory {
    fn new(actor: EntityId) -> TestResult<Self> {
        let principal = PrincipalRefV1::try_new([1; 16], "gateway.test")?;
        let authenticated =
            AuthenticatedPrincipalResultV1::try_from_draft(AuthenticatedPrincipalDraftV1 {
                principal: principal.clone(),
                adapter_id: "fixture".to_owned(),
                assurance: AssuranceLevelV1::try_new(1)?,
                issued_at: WallTime::from_micros(1),
                expires_at: WallTime::from_micros(u64::MAX),
                binding_digest: Hash::from_bytes([2; 32]),
            })?;
        let timeline = TimelineId::new();
        let root = history_grant(actor, &principal, timeline, 5, 1)?;
        let sibling = history_grant(actor, &principal, timeline, 6, 2)?;
        let issued = vec![root.binding_digest()?, sibling.binding_digest()?];
        let mut history = Self {
            registry: history_registry(&authenticated, issued.clone())?,
            authenticated,
            root,
            sibling,
        };
        history.registry = history.registry_attesting_resolved(issued)?;
        Ok(history)
    }

    /// The evaluator trusts the exact resolved records it evaluates, so the
    /// registry also attests the root as resolved after the sibling's
    /// revocation advanced the Timeline's epoch.
    fn registry_attesting_resolved(
        &self,
        issued: Vec<Hash>,
    ) -> TestResult<AuthorityRegistrySnapshotV1> {
        let resolved =
            self.view(&[&self.sibling])?.authority().chain().grants()[0].binding_digest()?;
        history_registry(
            &self.authenticated,
            issued.into_iter().chain([resolved]).collect(),
        )
    }

    /// The root's view after the grants were issued and `revoked` revoked at
    /// fences 3, 4, … with epochs 1, 2, ….
    fn view(&self, revoked: &[&CapabilityGrantV1]) -> TestResult<AuthorityViewV1> {
        let host = AuthorityPersistenceHostV1::new(&self.registry);
        let mut state = AuthorityPersistenceStateV1::new();
        for grant in [&self.root, &self.sibling] {
            state.issue_grant(host.authorize_grant(grant)?, grant.clone())?;
        }
        for (offset, grant) in (0_u64..).zip(revoked) {
            let revocation = CapabilityRevocationV1::try_from_draft(CapabilityRevocationDraftV1 {
                grant_id: grant.grant_id(),
                authority_timeline: grant.issuance_timeline(),
                fence_position: Seq::from_u64(3 + offset),
                revocation_epoch: 1 + offset,
                policy_revision: HISTORY_POLICY,
                authority_registry_digest: HISTORY_REGISTRY,
            })?;
            state.revoke_grant(host.authorize_revocation(grant, &revocation)?, revocation)?;
        }
        Ok(state.view(self.root.grant_id())?)
    }

    fn authorization(&self, view: AuthorityViewV1) -> GatewayAuthorization {
        GatewayAuthorization::new(
            Arc::new(LocalAuthenticationAdapter::new(self.authenticated.clone())),
            view,
            self.registry.clone(),
        )
    }
}

#[tokio::test]
async fn a_revocation_the_host_learned_is_persisted_with_the_admission() -> TestResult {
    for backend in backends()? {
        let name = backend.name;
        let actor = EntityId::new();
        let history = AuthorityHistory::new(actor)?;
        let learned = history.view(&[&history.sibling])?;
        assert_eq!(learned.authority().revocations().len(), 1, "{name}");
        let fixture = fixture_with(
            host(&backend.config)?,
            history.authorization(learned.clone()),
            actor,
            EntityId::new(),
        )
        .await?;

        // The view's revocation record is replayed under host permits before
        // the fence is published, so the admission commits against it.
        admitted(submit(&fixture, 1, Some("learned"), None).await?)?;
        assert_eq!(committed_events(&fixture).await?, 1, "{name}");
        fixture.gateway.shutdown().await?;
        drop(fixture);

        // Another process reading the same store finds the persisted record.
        if matches!(backend.config, StoreConfig::Sqlite { .. }) {
            let persisted = host(&backend.config)?
                .command_sender()?
                .with_scheduled_admission(|ports| {
                    ports.load_authority(history.root.grant_id())
                })??;
            assert_eq!(&persisted, learned.authority(), "{name}");
        }
    }
    Ok(())
}

/// The ADN1 denial records a fresh process finds in the authority store.
fn denials_after_restart(
    config: &StoreConfig,
) -> TestResult<Vec<(u64, AuthorizationDenialEvidenceV1)>> {
    Ok(host(config)?
        .command_sender()?
        .with_scheduled_admission(|ports| {
            ports.load_authorization_denials(0, pos_core::MAX_AUTHORIZATION_DENIALS_PER_READ)
        })??)
}

/// The one ADN1 denial a log holds, or an error naming what it holds.
fn only_denial(
    records: &[(u64, AuthorizationDenialEvidenceV1)],
) -> TestResult<AuthorizationDenialRecordV1> {
    match records {
        [(1, AuthorizationDenialEvidenceV1::Denial(record))] => Ok(*record),
        other => Err(format!("expected exactly one denial record, got {other:?}").into()),
    }
}

fn sqlite_config(directory: &tempfile::TempDir, name: &str) -> TestResult<StoreConfig> {
    Ok(StoreConfig::Sqlite {
        path: directory
            .path()
            .join(name)
            .to_str()
            .ok_or("temporary path is not UTF-8")?
            .to_owned(),
    })
}

#[tokio::test]
async fn a_revocation_another_host_persisted_is_rejected_by_the_store() -> TestResult {
    let directory = tempfile::tempdir()?;
    let config = sqlite_config(&directory, "shared-authority.sqlite")?;
    let actor = EntityId::new();
    let body = EntityId::new();
    let history = AuthorityHistory::new(actor)?;
    let authorization = history.authorization(history.view(&[])?);
    let first = fixture_with(host(&config)?, authorization.clone(), actor, body).await?;
    admitted(submit(&first, 1, Some("before"), None).await?)?;
    let timeline = first.timeline;
    first.gateway.shutdown().await?;
    drop(first);

    // Another host process persists a revocation of the Gateway's root grant
    // in the same store, under its own persistence identity.
    let revoked = history.view(&[&history.root])?;
    let other = AuthorityPersistenceHostV1::new(&history.registry);
    let persisted = host(&config)?
        .command_sender()?
        .with_scheduled_admission(|ports| other.persist_authority(ports, &revoked))??;
    assert_eq!(&persisted, revoked.authority());

    let restarted = Fixture {
        gateway: gateway_with_erasure_host_and_authorization(
            host(&config)?,
            [body],
            authorization.clone(),
        )?,
        authorization,
        timeline,
        actor,
        body,
    };
    // The Gateway's own view still authorizes the request in memory, so only
    // the store's composition of the persisted revocation at the commit
    // fence can reject it.
    assert!(restarted
        .authorization
        .authorize(GatewayAuthorizationRequest::action(
            actor,
            timeline,
            EVENT_TYPE_ACTION,
            CAPABILITY,
            WallTime::from_micros(10),
        ))
        .is_ok());
    let outcome = rejected(submit(&restarted, 2, Some("after"), None).await?)?;
    assert!(matches!(
        outcome,
        GatewayError::AuthorizationDenied(denial) if denial.denial() == GatewayAuthorityDenial::Revoked
    ));
    assert_eq!(committed_events(&restarted).await?, 1);
    assert_eq!(restarted.authorization.audits().len(), 1);
    restarted.gateway.shutdown().await?;
    drop(restarted);

    // The denial was committed in the authority store before the answer and
    // survives the restart.
    let record = only_denial(&denials_after_restart(&config)?)?;
    assert_eq!(
        record.outcome(),
        pos_core::AuthorizationOutcomeV1::RevokedAtFence
    );
    assert_eq!(
        record.error(),
        Some(pos_core::AuthorityErrorV1::RevokedAtFence)
    );
    Ok(())
}

/// Submit one action through a Gateway whose authority denies it, then
/// restart and return the typed denial with the records the log still holds.
async fn denied_with_durable_evidence(
    authorization: impl FnOnce(EntityId) -> GatewayAuthorization,
) -> TestResult<(GatewayError, Vec<(u64, AuthorizationDenialEvidenceV1)>)> {
    let directory = tempfile::tempdir()?;
    let config = sqlite_config(&directory, "denied.sqlite")?;
    let actor = EntityId::new();
    let fixture =
        fixture_with(host(&config)?, authorization(actor), actor, EntityId::new()).await?;
    let outcome = rejected(submit(&fixture, 1, Some("denied"), None).await?)?;
    assert_eq!(committed_events(&fixture).await?, 0);
    assert!(fixture.authorization.audits().is_empty());
    fixture.gateway.shutdown().await?;
    drop(fixture);
    Ok((outcome, denials_after_restart(&config)?))
}

#[tokio::test]
async fn expired_authentication_evidence_is_unauthenticated_with_durable_evidence() -> TestResult {
    let (outcome, records) = denied_with_durable_evidence(test_expired_authorization_for).await?;
    assert!(matches!(
        outcome,
        GatewayError::AuthorizationDenied(denial) if denial.denial() == GatewayAuthorityDenial::Unauthenticated
    ));
    let record = only_denial(&records)?;
    assert_eq!(record.outcome(), pos_core::AuthorizationOutcomeV1::Expired);
    assert_eq!(record.error(), None);
    Ok(())
}

#[tokio::test]
async fn an_expired_grant_is_revoked_with_durable_evidence() -> TestResult {
    let (outcome, records) =
        denied_with_durable_evidence(test_expired_grant_authorization_for).await?;
    assert!(matches!(
        outcome,
        GatewayError::AuthorizationDenied(denial) if denial.denial() == GatewayAuthorityDenial::Revoked
    ));
    let record = only_denial(&records)?;
    assert_eq!(record.outcome(), pos_core::AuthorizationOutcomeV1::Expired);
    assert_eq!(record.error(), None);
    Ok(())
}

#[tokio::test]
async fn a_store_that_refuses_the_denial_record_never_answers_the_denial() -> TestResult {
    let mut foreign = host(&StoreConfig::Memory)?;
    let registry = AuthorityRegistrySnapshotV1::try_new(
        Hash::from_bytes([9; 32]),
        vec![Hash::from_bytes([10; 32])],
        vec![Hash::from_bytes([11; 32])],
        Vec::new(),
    )?;
    let other_host = AuthorityPersistenceHostV1::new(&registry);
    foreign
        .command_sender()?
        .with_scheduled_admission(|ports| {
            ports.bind_authority_persistence(other_host.persistence_binding())
        })??;
    let actor = EntityId::new();
    let fixture = fixture_with(
        foreign,
        test_authorization_for(actor),
        actor,
        EntityId::new(),
    )
    .await?;
    let timeline = fixture.timeline.to_string();

    let outcome = fixture
        .gateway
        .read_events_page_authorized(
            &timeline,
            0,
            1,
            GatewayAuthorizationRequest::read(
                EntityId::new(),
                fixture.timeline,
                0,
                1,
                WallTime::now(),
            ),
        )
        .await;

    assert!(matches!(
        outcome,
        Err(GatewayError::AuthorizationEvidenceUnavailable)
    ));
    fixture.gateway.shutdown().await?;
    drop(fixture);
    Ok(())
}

#[tokio::test]
async fn a_denial_flood_is_bounded_and_counted_in_one_marker() -> TestResult {
    let directory = tempfile::tempdir()?;
    let config = sqlite_config(&directory, "flood.sqlite")?;
    let fixture = fixture(&config).await?;
    let timeline = fixture.timeline.to_string();
    let outsider = EntityId::new();
    let read = || {
        fixture.gateway.read_events_page_authorized(
            &timeline,
            0,
            1,
            GatewayAuthorizationRequest::read(outsider, fixture.timeline, 0, 1, WallTime::now()),
        )
    };
    for _ in 0..crate::MAX_DENIAL_RECORDS_PER_PRINCIPAL_PER_MINUTE {
        assert!(matches!(
            read().await,
            Err(GatewayError::AuthorizationDenied(denial))
                if denial.denial() == GatewayAuthorityDenial::Unauthorized
        ));
    }
    for _ in 0..3 {
        assert!(matches!(
            read().await,
            Err(GatewayError::DenialRecordLimitReached {
                retry_after_seconds: 1..=60
            })
        ));
    }
    // The shutdown closes the open window and records its suppressed count.
    fixture.gateway.shutdown().await?;
    drop(fixture);

    let records = denials_after_restart(&config)?;
    let limit = usize::try_from(crate::MAX_DENIAL_RECORDS_PER_PRINCIPAL_PER_MINUTE)?;
    assert_eq!(records.len(), limit + 1);
    assert!(records[..limit]
        .iter()
        .all(|(_, evidence)| matches!(evidence, AuthorizationDenialEvidenceV1::Denial(_))));
    assert_eq!(
        records[limit].1,
        AuthorizationDenialEvidenceV1::Suppressed(
            AuthorizationDenialSuppressionV1::try_new(AuthorizationDenialScopeV1::Principal, 3)
                .ok_or("marker")?
        )
    );
    assert_eq!(records[limit].0, u64::try_from(limit + 1)?);
    Ok(())
}

#[tokio::test]
async fn a_denial_whose_store_command_cannot_run_is_answered_with_the_store_error() -> TestResult {
    let fixture = fixture(&StoreConfig::Memory).await?;
    fixture.gateway.shutdown().await?;
    let lapsed = fixture
        .gateway
        .read_events_page_authorized(
            &fixture.timeline.to_string(),
            0,
            1,
            GatewayAuthorizationRequest::read(
                EntityId::new(),
                fixture.timeline,
                0,
                1,
                WallTime::now(),
            ),
        )
        .await;
    assert!(matches!(lapsed, Err(GatewayError::StoreExecutorClosed)));
    drop(fixture);
    Ok(())
}

/// Deny `count` reads by one outside actor; the pinned Principal is the same
/// for every actor, so its denial-record bound applies to all of them.
async fn deny_reads(fixture: &Fixture, count: u32) -> TestResult<Vec<GatewayError>> {
    let mut outcomes = Vec::new();
    for _ in 0..count {
        outcomes.push(
            fixture
                .gateway
                .read_events_page_authorized(
                    &fixture.timeline.to_string(),
                    0,
                    1,
                    GatewayAuthorizationRequest::read(
                        EntityId::new(),
                        fixture.timeline,
                        0,
                        1,
                        WallTime::now(),
                    ),
                )
                .await
                .err()
                .ok_or("a read by an outside actor is denied")?,
        );
    }
    Ok(outcomes)
}

#[tokio::test]
async fn a_flood_then_silence_is_counted_when_the_window_expires() -> TestResult {
    let directory = tempfile::tempdir()?;
    let config = sqlite_config(&directory, "silence.sqlite")?;
    let fixture = fixture(&config).await?;
    let limit = crate::MAX_DENIAL_RECORDS_PER_PRINCIPAL_PER_MINUTE;
    let outcomes = deny_reads(&fixture, limit + 2).await?;
    assert!(outcomes[..usize::try_from(limit)?]
        .iter()
        .all(|outcome| matches!(outcome, GatewayError::AuthorizationDenied(_))));
    assert!(outcomes[usize::try_from(limit)?..]
        .iter()
        .all(|outcome| matches!(outcome, GatewayError::DenialRecordLimitReached { .. })));

    // No further denial arrives. The window's armed timer runs this exact
    // flush at the window's end; running it with an expired deadline makes
    // the expiry deterministic instead of waiting on the wall clock.
    crate::flush_expired_denial_window(
        &fixture.gateway.store.downgrade(),
        &Arc::new(fixture.authorization.clone()),
        std::time::Instant::now(),
    )
    .await;
    assert!(!fixture.authorization.denial_markers_pending());
    fixture.gateway.shutdown().await?;
    drop(fixture);

    let records = denials_after_restart(&config)?;
    assert_eq!(records.len(), usize::try_from(limit)? + 1);
    assert_eq!(
        records[usize::try_from(limit)?].1,
        AuthorizationDenialEvidenceV1::Suppressed(
            AuthorizationDenialSuppressionV1::try_new(AuthorizationDenialScopeV1::Principal, 2)
                .ok_or("marker")?
        )
    );
    Ok(())
}

#[tokio::test]
async fn a_shutdown_flush_the_store_cannot_take_keeps_the_count_pending() -> TestResult {
    let fixture = fixture(&StoreConfig::Memory).await?;
    let limit = crate::MAX_DENIAL_RECORDS_PER_PRINCIPAL_PER_MINUTE;
    deny_reads(&fixture, limit + 1).await?;
    fixture
        .gateway
        .store
        .shutdown()
        .await
        .map_err(|error| format!("{error:?}"))?;

    // The flush meets a closed executor, so its count stays pending.
    drop(fixture.gateway.shutdown().await);
    assert_eq!(
        fixture.authorization.take_denial_markers().markers(),
        &[
            AuthorizationDenialSuppressionV1::try_new(AuthorizationDenialScopeV1::Principal, 1)
                .ok_or("marker")?
        ]
    );
    drop(fixture);
    Ok(())
}

#[tokio::test]
async fn a_window_flush_the_store_refuses_retries_once_and_keeps_the_count() -> TestResult {
    let actor = EntityId::new();
    let authorization = test_authorization_for(actor);
    // A store without authority ports refuses every denial-evidence record.
    let gateway = Gateway::new_with_world_bodies_and_authorization(
        Box::new(pos_store::memory::MemoryStore::new()),
        [],
        authorization.clone(),
    );
    let timeline = gateway.create_timeline("refused-flush").await?.id();
    for _ in 0..=crate::MAX_DENIAL_RECORDS_PER_PRINCIPAL_PER_MINUTE {
        let outcome = gateway
            .read_events_page_authorized(
                &timeline.to_string(),
                0,
                1,
                GatewayAuthorizationRequest::read(EntityId::new(), timeline, 0, 1, WallTime::now()),
            )
            .await;
        assert!(outcome.is_err());
    }
    assert!(authorization.denial_markers_pending());

    crate::flush_expired_denial_window(
        &gateway.store.downgrade(),
        &Arc::new(authorization.clone()),
        std::time::Instant::now(),
    )
    .await;

    // Both attempts were refused, so the count is still pending, once.
    assert_eq!(
        authorization.take_denial_markers().markers(),
        &[
            AuthorizationDenialSuppressionV1::try_new(AuthorizationDenialScopeV1::Principal, 1)
                .ok_or("marker")?
        ]
    );
    gateway.shutdown().await?;
    drop(gateway);
    Ok(())
}

#[tokio::test]
async fn a_disconnect_mid_write_neither_strands_nor_duplicates_a_count() -> TestResult {
    let directory = tempfile::tempdir()?;
    let config = sqlite_config(&directory, "disconnect.sqlite")?;
    let fixture = fixture(&config).await?;
    let limit = crate::MAX_DENIAL_RECORDS_PER_PRINCIPAL_PER_MINUTE;
    deny_reads(&fixture, limit + 1).await?;
    assert!(fixture.authorization.denial_markers_pending());

    // The next denial opens a new window and carries the marker; the client
    // disconnects while its write waits behind a blocked store worker.
    let _shortened = fixture
        .authorization
        .clone()
        .with_denial_window(std::time::Duration::ZERO);
    let release = fixture
        .gateway
        .store
        .block_worker_for_test()
        .map_err(|error| format!("{error:?}"))?;
    let disconnected = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        deny_reads(&fixture, 1),
    )
    .await;
    assert!(disconnected.is_err());
    // The handed-out count is in flight, not pending and not lost.
    assert!(!fixture.authorization.denial_markers_pending());
    assert!(release.send(()).is_ok());

    // The detached write still commits (the shutdown drains it) and settles
    // the marker exactly once; nothing is pending for the shutdown flush.
    fixture.gateway.shutdown().await?;
    assert!(!fixture.authorization.denial_markers_pending());
    drop(fixture);

    let records = denials_after_restart(&config)?;
    let markers = records
        .iter()
        .filter(|(_, evidence)| matches!(evidence, AuthorizationDenialEvidenceV1::Suppressed(_)))
        .map(|(_, evidence)| *evidence)
        .collect::<Vec<_>>();
    assert_eq!(
        markers,
        vec![AuthorizationDenialEvidenceV1::Suppressed(
            AuthorizationDenialSuppressionV1::try_new(AuthorizationDenialScopeV1::Principal, 1)
                .ok_or("marker")?
        )]
    );
    // Every admitted denial, the disconnected one included, was recorded.
    assert_eq!(records.len(), usize::try_from(limit)? + 2);
    Ok(())
}

/// Wait, in real time, until the authorizer has settled every handed-out
/// suppression count.
async fn settled(authorization: &GatewayAuthorization) -> TestResult {
    for _ in 0..500 {
        if !authorization.denial_markers_in_flight() && !authorization.denial_markers_pending() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Err("suppression counts were not settled".into())
}

#[tokio::test]
async fn the_window_timer_records_a_flood_followed_by_silence_by_itself() -> TestResult {
    let directory = tempfile::tempdir()?;
    let config = sqlite_config(&directory, "timer.sqlite")?;
    let actor = EntityId::new();
    // A paused Tokio clock would also move every executor deadline, which
    // the store worker measures on the system clock, so the timer runs in
    // real time on a short window instead. The flood takes milliseconds, far
    // inside the window; the outcome checks below would fail if it did not.
    let window = std::time::Duration::from_secs(3);
    let fixture = fixture_with(
        host(&config)?,
        test_authorization_for(actor).with_denial_window(window),
        actor,
        EntityId::new(),
    )
    .await?;
    let limit = crate::MAX_DENIAL_RECORDS_PER_PRINCIPAL_PER_MINUTE;
    let outcomes = deny_reads(&fixture, limit + 2).await?;
    let limit_index = usize::try_from(limit)?;
    assert!(outcomes[..limit_index]
        .iter()
        .all(|outcome| matches!(outcome, GatewayError::AuthorizationDenied(_))));
    assert!(outcomes[limit_index..]
        .iter()
        .all(|outcome| matches!(outcome, GatewayError::DenialRecordLimitReached { .. })));
    assert!(fixture.authorization.denial_markers_pending());

    // No flush is called here: only the timer armed by the first suppression
    // can write the marker, at the window's end.
    tokio::time::sleep(window).await;
    settled(&fixture.authorization).await?;
    fixture.gateway.shutdown().await?;
    drop(fixture);

    let records = denials_after_restart(&config)?;
    assert_eq!(records.len(), limit_index + 1);
    assert_eq!(
        records[limit_index].1,
        AuthorizationDenialEvidenceV1::Suppressed(
            AuthorizationDenialSuppressionV1::try_new(AuthorizationDenialScopeV1::Principal, 2)
                .ok_or("marker")?
        )
    );
    Ok(())
}

#[tokio::test]
async fn a_suppression_during_a_committed_flush_does_not_trigger_a_retry() -> TestResult {
    let fixture = fixture(&StoreConfig::Memory).await?;
    let limit = crate::MAX_DENIAL_RECORDS_PER_PRINCIPAL_PER_MINUTE;
    deny_reads(&fixture, limit + 1).await?;
    let authorization = Arc::new(fixture.authorization.clone());
    let release = fixture
        .gateway
        .store
        .block_worker_for_test()
        .map_err(|error| format!("{error:?}"))?;

    // The flush hands out its marker and waits on the blocked worker; a new
    // suppression arrives meanwhile, then the worker is released.
    let (flushed, suppressed) = tokio::join!(
        crate::flush_denial_markers(&fixture.gateway.store, &authorization),
        async {
            let outcome = deny_reads(&fixture, 1).await;
            assert!(release.send(()).is_ok());
            outcome
        }
    );

    assert!(flushed, "every marker this flush handed out committed");
    assert!(matches!(
        suppressed?.as_slice(),
        [GatewayError::DenialRecordLimitReached { .. }]
    ));
    // The later suppression is pending for its own marker.
    assert_eq!(
        authorization.take_denial_markers().markers(),
        &[
            AuthorizationDenialSuppressionV1::try_new(AuthorizationDenialScopeV1::Principal, 1)
                .ok_or("marker")?
        ]
    );
    fixture.gateway.shutdown().await?;
    drop(fixture);
    Ok(())
}

#[tokio::test]
async fn a_window_timer_outliving_its_gateway_writes_nothing() -> TestResult {
    let actor = EntityId::new();
    let authorization = test_authorization_for(actor);
    let gateway = Gateway::new_with_world_bodies_and_authorization(
        Box::new(pos_store::memory::MemoryStore::new()),
        [],
        authorization.clone(),
    );
    let timeline = gateway.create_timeline("dropped-gateway").await?.id();
    for _ in 0..=crate::MAX_DENIAL_RECORDS_PER_PRINCIPAL_PER_MINUTE {
        assert!(gateway
            .read_events_page_authorized(
                &timeline.to_string(),
                0,
                1,
                GatewayAuthorizationRequest::read(EntityId::new(), timeline, 0, 1, WallTime::now()),
            )
            .await
            .is_err());
    }
    let store = gateway.store.downgrade();
    // Dropped without a shutdown: the weak timer handle keeps nothing alive.
    drop(gateway);
    assert!(store.upgrade().is_none());

    crate::flush_expired_denial_window(
        &store,
        &Arc::new(authorization.clone()),
        std::time::Instant::now(),
    )
    .await;
    assert!(authorization.denial_markers_pending());
    assert!(!authorization.denial_markers_in_flight());
    Ok(())
}
