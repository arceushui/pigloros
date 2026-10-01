//! ADR-021 admitted-batch contract shared by `MemoryStore` and `SqliteStore`.

use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use pos_core::{
    pipeline_authority_revision_v1, AdmissionClock, AppendDedupKey, AppendDedupScope,
    AppendIdentity, AuthorityGranteeV1, AuthorityPersistenceHostV1, AuthorityPersistencePortV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, CanonicalBytes, CapabilityGrantDraftV1,
    CapabilityGrantV1, CapabilityRevocationDraftV1, CapabilityRevocationV1, CapabilityScopeDraftV1,
    CapabilityScopeV1, CoreError, DelegateClassV1, EntityId, ErasureContainmentGateV1, EventDraft,
    EventStore, Hash, Kind, PipelineAdmissionBasisDraftV1, PipelineAdmissionBasisV1,
    PipelineAdmissionFenceV1, PipelineAdmissionPortV1, PipelineAttemptDraftV1, PipelineAttemptIdV1,
    PipelineAttemptV1, PipelineCommitReceiptV1, PipelineDraftBatchV1, PipelineEvidenceRefV1,
    PipelineIngressV1, PipelineObservationAnchorV1, PipelineOutcomeV1, PipelinePreconditionV1,
    PipelineSecurityRevisionsDraftV1, PipelineSecurityRevisionsV1, PrincipalRefV1, Seq, SeqRange,
    TentativePipelineResultV1, TimelineId, WallTime, APPEND_IDENTITY_RETENTION_MICROS,
    DELEGATE_ACTION_V1, GEOGRAPHIC_EVENT_TYPE, PIPELINE_CONTRACT_VERSION_V1,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};
use tempfile::tempdir;
use ulid::Ulid;

trait Harness: EventStore + PipelineAdmissionPortV1 + AuthorityPersistencePortV1 {}

impl<T: EventStore + PipelineAdmissionPortV1 + AuthorityPersistencePortV1> Harness for T {}

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
    })
}

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

fn entity(value: u128) -> EntityId {
    EntityId::from_ulid(Ulid::from(value))
}

fn timeline_id(value: u128) -> TimelineId {
    TimelineId::from_ulid(Ulid::from(value))
}

#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);

impl TestClock {
    fn at(micros: u64) -> Self {
        Self(Arc::new(AtomicU64::new(micros)))
    }

    fn advance(&self, micros: u64) {
        self.0.fetch_add(micros, Ordering::SeqCst);
    }
}

impl AdmissionClock for TestClock {
    fn now(&mut self) -> Result<WallTime, CoreError> {
        Ok(WallTime::from_micros(self.0.load(Ordering::SeqCst)))
    }
}

fn stores(clock: &TestClock) -> Vec<(&'static str, Box<dyn Harness>)> {
    vec![
        (
            "memory",
            Box::new(MemoryStore::with_clock(Box::new(clock.clone()))),
        ),
        (
            "sqlite",
            Box::new(ok(SqliteStore::open_with_clock(
                ":memory:",
                Box::new(clock.clone()),
            ))),
        ),
    ]
}

fn open_file(path: &Path, clock: &TestClock) -> SqliteStore {
    let mut store = ok(SqliteStore::open_with_clock(
        path.to_str().unwrap_or_default(),
        Box::new(clock.clone()),
    ));
    ok(store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open())));
    store
}

fn principal(value: u8) -> PrincipalRefV1 {
    ok(PrincipalRefV1::try_new([value; 16], "local.test"))
}

fn grant(id: u8, issuance: u64, valid_until: u64) -> CapabilityGrantV1 {
    ok(CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: hash(id),
        grantor: principal(1),
        grantee: AuthorityGranteeV1::Principal(principal(2)),
        trust_domain: "local.test".to_owned(),
        scope: ok(CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
            resources: vec!["world".to_owned()],
            actions: vec![DELEGATE_ACTION_V1.to_owned(), "act".to_owned()],
            purposes: vec!["simulation".to_owned()],
            audiences: vec!["local-host".to_owned()],
            actor_entity_ids: vec![entity(10)],
            subject_ids: vec![entity(50)],
            participant_ids: vec![entity(20)],
            plugin_id: None,
            principal_roles: vec![AuthorityRoleV1::Actor],
            max_uses: 10,
            budget: 100,
            environment_constraints: vec!["local-only".to_owned()],
        })),
        valid_from_position: Seq::from_u64(issuance),
        valid_until_position: Seq::from_u64(valid_until),
        parent_grant_id: None,
        delegation_depth: 0,
        max_delegation_depth: 2,
        permitted_delegate_classes: vec![DelegateClassV1::Principal],
        consent_references: vec![hash(8)],
        policy_revision: hash(9),
        issuance_timeline: timeline_id(30),
        issuance_seq: Seq::from_u64(issuance),
        revocation_epoch: 0,
        revocation_fence: None,
        authority_registry_digest: hash(7),
    }))
}

fn root_grant() -> CapabilityGrantV1 {
    grant(1, 1, 2)
}

fn sibling_grant() -> CapabilityGrantV1 {
    grant(2, 2, 100)
}

fn authority_host() -> AuthorityPersistenceHostV1 {
    let mut bindings = [root_grant(), sibling_grant()]
        .iter()
        .map(|grant| ok(grant.binding_digest()))
        .collect::<Vec<_>>();
    bindings.sort_unstable();
    AuthorityPersistenceHostV1::new(&ok(AuthorityRegistrySnapshotV1::try_new(
        hash(7),
        vec![hash(200)],
        bindings,
        vec![],
    )))
}

fn root_revocation() -> CapabilityRevocationV1 {
    ok(CapabilityRevocationV1::try_from_draft(
        CapabilityRevocationDraftV1 {
            grant_id: hash(1),
            authority_timeline: timeline_id(30),
            fence_position: Seq::from_u64(3),
            revocation_epoch: 1,
            policy_revision: hash(9),
            authority_registry_digest: hash(7),
        },
    ))
}

fn revisions_with(authority: Hash) -> PipelineSecurityRevisionsV1 {
    ok(PipelineSecurityRevisionsV1::try_from_draft(
        PipelineSecurityRevisionsDraftV1 {
            authority,
            consent: hash(11),
            capability: hash(12),
            delegation: hash(13),
            policy: hash(14),
            execution_profile: hash(15),
            erasure: hash(16),
        },
    ))
}

fn fence_for(revisions: PipelineSecurityRevisionsV1, grant: Hash) -> PipelineAdmissionFenceV1 {
    ok(PipelineAdmissionFenceV1::try_new(
        grant,
        revisions,
        Some(hash(40)),
        10,
    ))
}

struct Fixture {
    timeline: TimelineId,
    gate: Arc<ErasureContainmentGateV1>,
    host: AuthorityPersistenceHostV1,
    revisions: PipelineSecurityRevisionsV1,
    fence: PipelineAdmissionFenceV1,
}

fn prepare(store: &mut dyn Harness) -> Fixture {
    let timeline = ok(store.create_timeline("pipeline-admission")).id();
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    ok(store.bind_erasure_gate(Arc::clone(&gate)));
    let host = authority_host();
    ok(store.bind_authority_persistence(host.persistence_binding()));
    let root = root_grant();
    ok(store.issue_capability_grant(ok(host.authorize_grant(&root)), &root));
    let revisions = revisions_with(pipeline_authority_revision_v1(&ok(
        store.load_authority(hash(1))
    )));
    let fence = fence_for(revisions, hash(1));
    ok(store.set_pipeline_admission_fence(timeline, fence));
    Fixture {
        timeline,
        gate,
        host,
        revisions,
        fence,
    }
}

fn drafts(payloads: &[&[u8]]) -> Vec<EventDraft> {
    payloads
        .iter()
        .map(|payload| {
            EventDraft::new(
                entity(5),
                Kind::new("world.action"),
                CanonicalBytes::from_vec(payload.to_vec()),
            )
        })
        .collect()
}

#[derive(Clone)]
struct Attempt {
    timeline: TimelineId,
    key: u8,
    ingress: PipelineIngressV1,
    observed_through: u64,
    precondition: PipelinePreconditionV1,
    revisions: PipelineSecurityRevisionsV1,
    drafts: Vec<EventDraft>,
}

fn attempt(fixture: &Fixture, key: u8, head: u64) -> Attempt {
    Attempt {
        timeline: fixture.timeline,
        key,
        ingress: PipelineIngressV1::HumanProposedAction,
        observed_through: head,
        precondition: PipelinePreconditionV1::ExpectedLogicalHead(Seq::from_u64(head)),
        revisions: fixture.revisions,
        drafts: drafts(&[b"first", b"second", b"third"]),
    }
}

fn basis(attempt: &Attempt) -> PipelineAdmissionBasisV1 {
    let evidence = ok(PipelineEvidenceRefV1::try_new(hash(60)));
    let tentative_result = match attempt.ingress {
        PipelineIngressV1::HumanProposedAction => {
            TentativePipelineResultV1::HumanDomainApproval(evidence)
        }
        PipelineIngressV1::ScheduledAiDriver => {
            TentativePipelineResultV1::AiProviderValidation(evidence)
        }
    };
    ok(PipelineAdmissionBasisV1::try_from_draft(
        PipelineAdmissionBasisDraftV1 {
            contract_version: PIPELINE_CONTRACT_VERSION_V1,
            attempt: Some(ok(PipelineAttemptV1::try_from_draft(
                PipelineAttemptDraftV1 {
                    contract_version: PIPELINE_CONTRACT_VERSION_V1,
                    attempt_id: Some(ok(PipelineAttemptIdV1::try_new([attempt.key; 16]))),
                    ingress: Some(attempt.ingress),
                    observation: Some(ok(PipelineObservationAnchorV1::try_new(
                        attempt.timeline,
                        Seq::from_u64(attempt.observed_through),
                        hash(61),
                    ))),
                    idempotency: Some(AppendIdentity::new(
                        AppendDedupKey::from_keyed_hash([attempt.key; 32]),
                        AppendDedupScope::from_keyed_hash([62; 32]),
                    )),
                },
            ))),
            tentative_result: Some(tentative_result),
            precondition: Some(attempt.precondition),
            security_revisions: Some(attempt.revisions),
            batch: Some(ok(PipelineDraftBatchV1::try_new(attempt.drafts.clone()))),
        },
    ))
}

fn admit(store: &mut dyn Harness, attempt: &Attempt) -> Result<PipelineOutcomeV1, CoreError> {
    store.admit_pipeline_batch(&basis(attempt))
}

fn committed(outcome: PipelineOutcomeV1) -> PipelineCommitReceiptV1 {
    match outcome {
        PipelineOutcomeV1::Committed(receipt) => receipt,
        other => std::panic::resume_unwind(Box::new(format!("expected a commit, got {other:?}"))),
    }
}

fn event_count(store: &dyn Harness, timeline: TimelineId) -> usize {
    ok(store.read(timeline, SeqRange::all())).len()
}

fn remaining_budget(store: &dyn Harness, timeline: TimelineId) -> Option<u64> {
    ok(store.pipeline_admission_fence(timeline))
        .as_ref()
        .map(PipelineAdmissionFenceV1::remaining_event_budget)
}

fn receipt_positions(receipt: &PipelineCommitReceiptV1) -> Vec<u64> {
    receipt
        .committed_events()
        .iter()
        .map(|event| event.seq().as_u64())
        .collect()
}

#[test]
fn admitted_batch_commits_in_order_with_its_exact_receipt_and_budget() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        let fixture = prepare(store.as_mut());
        let first = attempt(&fixture, 1, 0);
        let receipt = committed(ok(admit(store.as_mut(), &first)));

        let events = ok(store.read(fixture.timeline, SeqRange::all()));
        assert_eq!(
            receipt
                .committed_events()
                .iter()
                .map(|event| (event.event_id(), event.seq()))
                .collect::<Vec<_>>(),
            events
                .iter()
                .map(|event| (event.id, event.seq))
                .collect::<Vec<_>>(),
            "{name}"
        );
        assert_eq!(receipt_positions(&receipt), [1, 2, 3], "{name}");
        assert_eq!(
            events
                .iter()
                .map(|event| event.payload.as_slice().to_vec())
                .collect::<Vec<_>>(),
            [b"first".to_vec(), b"second".to_vec(), b"third".to_vec()],
            "{name}"
        );
        assert_eq!(receipt.timeline_id(), fixture.timeline, "{name}");
        assert_eq!(receipt.attempt_id().as_bytes(), [1; 16], "{name}");
        assert_eq!(
            receipt.draft_batch_digest(),
            basis(&first).batch().digest(),
            "{name}"
        );
        assert_eq!(remaining_budget(store.as_ref(), fixture.timeline), Some(7));

        let next = committed(ok(admit(store.as_mut(), &attempt(&fixture, 2, 3))));
        assert_eq!(receipt_positions(&next), [4, 5, 6], "{name}");
        assert_eq!(
            ok(admit(store.as_mut(), &attempt(&fixture, 3, 3))),
            PipelineOutcomeV1::AdmissionConflict,
            "{name}"
        );
        assert_eq!(event_count(store.as_ref(), fixture.timeline), 6, "{name}");
        assert_eq!(remaining_budget(store.as_ref(), fixture.timeline), Some(4));
    }
}

#[test]
fn exact_retry_recovers_the_original_receipt_without_recommitting() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        let fixture = prepare(store.as_mut());
        let first = attempt(&fixture, 1, 0);
        let receipt = committed(ok(admit(store.as_mut(), &first)));
        let revocation = root_revocation();
        ok(store.revoke_capability_grant(
            ok(fixture
                .host
                .authorize_revocation(&root_grant(), &revocation)),
            &revocation,
        ));

        assert_eq!(
            ok(admit(store.as_mut(), &first)),
            PipelineOutcomeV1::RecoveredDuplicate(receipt),
            "{name}"
        );
        let mut changed = first.clone();
        changed.drafts = drafts(&[b"changed"]);
        assert_eq!(
            ok(admit(store.as_mut(), &changed)),
            PipelineOutcomeV1::AdmissionConflict,
            "{name}"
        );
        let other = ok(store.create_timeline("other-timeline")).id();
        let mut moved = first;
        moved.timeline = other;
        assert_eq!(
            ok(admit(store.as_mut(), &moved)),
            PipelineOutcomeV1::AdmissionConflict,
            "{name}"
        );
        assert_eq!(event_count(store.as_ref(), fixture.timeline), 3, "{name}");
        assert_eq!(event_count(store.as_ref(), other), 0, "{name}");
        assert_eq!(remaining_budget(store.as_ref(), fixture.timeline), Some(7));
    }
}

#[test]
fn every_failed_comparison_commits_no_event_and_no_receipt() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        let fixture = prepare(store.as_mut());
        let valid = attempt(&fixture, 9, 0);
        let unfenced = ok(store.create_timeline("unfenced")).id();
        let cases = rejection_cases(&valid, unfenced);
        for (case, rejected, expected) in &cases {
            assert_eq!(
                &ok(admit(store.as_mut(), rejected)),
                expected,
                "{name}: {case}"
            );
            assert_eq!(event_count(store.as_ref(), fixture.timeline), 0, "{name}");
            assert_eq!(event_count(store.as_ref(), unfenced), 0, "{name}");
            assert_eq!(
                ok(store.pipeline_admission_fence(fixture.timeline)),
                Some(fixture.fence),
                "{name}: {case}"
            );
        }

        let domain_attempt = Attempt {
            precondition: domain_precondition(40),
            ..valid
        };
        let receipt = committed(ok(admit(store.as_mut(), &domain_attempt)));
        assert_eq!(receipt_positions(&receipt), [1, 2, 3], "{name}");
    }
}

fn domain_precondition(value: u8) -> PipelinePreconditionV1 {
    ok(PipelinePreconditionV1::try_domain_state_revision(hash(
        value,
    )))
}

fn rejection_cases(
    valid: &Attempt,
    unfenced: TimelineId,
) -> Vec<(&'static str, Attempt, PipelineOutcomeV1)> {
    vec![
        (
            "missing fence",
            Attempt {
                timeline: unfenced,
                ..valid.clone()
            },
            PipelineOutcomeV1::PolicyIndeterminate,
        ),
        (
            "stale security revisions",
            Attempt {
                revisions: revisions_with(hash(99)),
                ..valid.clone()
            },
            PipelineOutcomeV1::AdmissionConflict,
        ),
        (
            "observation beyond the Logical Head",
            Attempt {
                observed_through: 1,
                precondition: domain_precondition(40),
                ..valid.clone()
            },
            PipelineOutcomeV1::InvalidObservation,
        ),
        (
            "stale Logical Head",
            Attempt {
                precondition: PipelinePreconditionV1::ExpectedLogicalHead(Seq::from_u64(1)),
                ..valid.clone()
            },
            PipelineOutcomeV1::AdmissionConflict,
        ),
        (
            "stale domain state",
            Attempt {
                precondition: domain_precondition(41),
                ..valid.clone()
            },
            PipelineOutcomeV1::DomainConflict,
        ),
        (
            "exceeded Event budget",
            Attempt {
                drafts: drafts(&[b"x".as_slice(); 11]),
                ..valid.clone()
            },
            PipelineOutcomeV1::ResourceExhausted,
        ),
        (
            "invalid approved member",
            Attempt {
                drafts: {
                    let mut members = drafts(&[b"before", b"invalid", b"after"]);
                    members[1].event_type = Kind::new("consent.grant");
                    members
                },
                ..valid.clone()
            },
            PipelineOutcomeV1::InvalidPluginResult,
        ),
        (
            "invalid provider member",
            Attempt {
                ingress: PipelineIngressV1::ScheduledAiDriver,
                drafts: {
                    let mut members = drafts(&[b"before", b"invalid"]);
                    members[1].event_type = Kind::new(GEOGRAPHIC_EVENT_TYPE);
                    members
                },
                ..valid.clone()
            },
            PipelineOutcomeV1::InvalidProviderResult,
        ),
    ]
}

#[test]
fn persisted_authority_is_composed_at_commit() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        let fixture = prepare(store.as_mut());
        let valid = attempt(&fixture, 1, 0);

        ok(store.set_pipeline_admission_fence(
            fixture.timeline,
            fence_for(fixture.revisions, hash(77)),
        ));
        assert_eq!(
            ok(admit(store.as_mut(), &valid)),
            PipelineOutcomeV1::PolicyIndeterminate,
            "{name}"
        );

        let forged = revisions_with(hash(99));
        ok(store.set_pipeline_admission_fence(fixture.timeline, fence_for(forged, hash(1))));
        assert_eq!(
            ok(admit(
                store.as_mut(),
                &Attempt {
                    revisions: forged,
                    ..valid.clone()
                }
            )),
            PipelineOutcomeV1::AdmissionConflict,
            "{name}"
        );

        ok(store.set_pipeline_admission_fence(fixture.timeline, fixture.fence));
        let sibling = sibling_grant();
        ok(store.issue_capability_grant(ok(fixture.host.authorize_grant(&sibling)), &sibling));
        assert_eq!(
            ok(admit(store.as_mut(), &valid)),
            PipelineOutcomeV1::AuthorityExpired,
            "{name}"
        );

        let revocation = root_revocation();
        ok(store.revoke_capability_grant(
            ok(fixture
                .host
                .authorize_revocation(&root_grant(), &revocation)),
            &revocation,
        ));
        assert_eq!(
            ok(admit(store.as_mut(), &valid)),
            PipelineOutcomeV1::AuthorityRevoked,
            "{name}"
        );
        assert_eq!(event_count(store.as_ref(), fixture.timeline), 0, "{name}");
        assert_eq!(remaining_budget(store.as_ref(), fixture.timeline), Some(10));
    }
}

#[test]
fn frozen_erasure_scope_rejects_before_commit() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        let fixture = prepare(store.as_mut());
        fixture.gate.freeze_timeline_for_test(fixture.timeline);

        assert!(
            matches!(
                admit(store.as_mut(), &attempt(&fixture, 1, 0)),
                Err(CoreError::ErasureAccessFrozen)
            ),
            "{name}"
        );
        assert_eq!(remaining_budget(store.as_ref(), fixture.timeline), Some(10));
    }
}

#[test]
fn fork_history_and_concurrent_attempts_serialize_on_the_logical_head() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        let fixture = prepare(store.as_mut());
        committed(ok(admit(store.as_mut(), &attempt(&fixture, 1, 0))));
        let child = ok(store.fork(fixture.timeline, Seq::from_u64(2), "admission-child")).id();
        ok(store.set_pipeline_admission_fence(child, fixture.fence));
        let child_attempt = |key: u8, head: u64| Attempt {
            timeline: child,
            ..attempt(&fixture, key, head)
        };

        let receipt = committed(ok(admit(store.as_mut(), &child_attempt(2, 2))));
        assert_eq!(receipt_positions(&receipt), [3, 4, 5], "{name}");
        assert_eq!(event_count(store.as_ref(), child), 5, "{name}");
        assert_eq!(event_count(store.as_ref(), fixture.timeline), 3, "{name}");

        let shared = Arc::new(Mutex::new(store));
        let barrier = Arc::new(Barrier::new(2));
        let handles = [3_u8, 4].map(|key| {
            let shared = Arc::clone(&shared);
            let barrier = Arc::clone(&barrier);
            let contender = child_attempt(key, 5);
            std::thread::spawn(move || {
                barrier.wait();
                let mut guard = ok(shared.lock());
                ok(admit(guard.as_mut(), &contender))
            })
        });
        let outcomes = handles.map(|handle| ok(handle.join()));

        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, PipelineOutcomeV1::Committed(_)))
                .count(),
            1,
            "{name}"
        );
        assert!(
            outcomes.contains(&PipelineOutcomeV1::AdmissionConflict),
            "{name}"
        );
        let store = ok(shared.lock());
        assert_eq!(event_count(store.as_ref(), child), 8, "{name}");
    }
}

#[test]
fn expired_receipts_release_their_key_and_are_purged_in_bounds() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        let fixture = prepare(store.as_mut());
        let first = attempt(&fixture, 1, 0);
        committed(ok(admit(store.as_mut(), &first)));
        committed(ok(admit(store.as_mut(), &attempt(&fixture, 2, 3))));
        clock.advance(APPEND_IDENTITY_RETENTION_MICROS);

        assert_eq!(
            ok(admit(store.as_mut(), &first)),
            PipelineOutcomeV1::AdmissionConflict,
            "{name}"
        );
        let reused = committed(ok(admit(store.as_mut(), &attempt(&fixture, 1, 6))));
        assert_eq!(receipt_positions(&reused), [7, 8, 9], "{name}");

        let limit = ok(NonZeroUsize::new(1).ok_or("limit"));
        let purged = ok(store.purge_expired_pipeline_receipts_bounded(limit));
        assert_eq!(
            (purged.removed, purged.more_may_remain),
            (1, true),
            "{name}"
        );
        let drained = ok(store.purge_expired_pipeline_receipts_bounded(limit));
        assert_eq!(
            (drained.removed, drained.more_may_remain),
            (0, false),
            "{name}"
        );
        assert_eq!(
            ok(admit(store.as_mut(), &attempt(&fixture, 1, 6))),
            PipelineOutcomeV1::RecoveredDuplicate(reused),
            "{name}"
        );
    }
}

#[test]
fn deleting_a_timeline_removes_its_admission_state() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        let fixture = prepare(store.as_mut());
        committed(ok(admit(store.as_mut(), &attempt(&fixture, 1, 0))));

        ok(store.delete_timeline(fixture.timeline));

        assert_eq!(
            ok(store.pipeline_admission_fence(fixture.timeline)),
            None,
            "{name}"
        );
        assert!(
            matches!(
                store.set_pipeline_admission_fence(fixture.timeline, fixture.fence),
                Err(CoreError::TimelineNotFound(_))
            ),
            "{name}"
        );
    }
}

fn execute(path: &Path, sql: &str) {
    let connection = ok(rusqlite::Connection::open(path));
    ok(connection.execute_batch(sql));
}

#[test]
fn sqlite_reopen_recovers_the_receipt_and_persisted_fence() {
    let clock = TestClock::at(1_000);
    let directory = ok(tempdir());
    let path = directory.path().join("admission.db");
    let (first, receipt) = {
        let mut store = ok(SqliteStore::open_with_clock(
            path.to_str().unwrap_or_default(),
            Box::new(clock.clone()),
        ));
        let fixture = prepare(&mut store);
        let first = attempt(&fixture, 1, 0);
        let receipt = committed(ok(admit(&mut store, &first)));
        (first, receipt)
    };

    let mut reopened = open_file(&path, &clock);
    assert_eq!(remaining_budget(&reopened, first.timeline), Some(7));
    assert_eq!(
        ok(admit(&mut reopened, &first)),
        PipelineOutcomeV1::RecoveredDuplicate(receipt)
    );
    assert_eq!(event_count(&reopened, first.timeline), 3);
}

#[test]
fn sqlite_faults_roll_back_the_complete_batch_and_receipt() {
    let clock = TestClock::at(1_000);
    let directory = ok(tempdir());
    let path = directory.path().join("admission-faults.db");
    let first = {
        let mut store = ok(SqliteStore::open_with_clock(
            path.to_str().unwrap_or_default(),
            Box::new(clock.clone()),
        ));
        attempt(&prepare(&mut store), 1, 0)
    };

    for trigger in [
        "CREATE TRIGGER injected_fault BEFORE INSERT ON events WHEN NEW.seq = 2
         BEGIN SELECT RAISE(ABORT, 'injected member fault'); END;",
        "CREATE TRIGGER injected_fault BEFORE INSERT ON pipeline_admission_receipts
         BEGIN SELECT RAISE(ABORT, 'injected receipt fault'); END;",
    ] {
        execute(&path, trigger);
        let mut faulted = open_file(&path, &clock);
        assert!(admit(&mut faulted, &first).is_err());
        assert_eq!(event_count(&faulted, first.timeline), 0);
        assert_eq!(remaining_budget(&faulted, first.timeline), Some(10));
        drop(faulted);
        execute(&path, "DROP TRIGGER injected_fault;");
    }

    let receipt = committed(ok(admit(&mut open_file(&path, &clock), &first)));
    assert_eq!(receipt_positions(&receipt), [1, 2, 3]);

    execute(
        &path,
        "UPDATE pipeline_admission_receipts SET event_count = 2;",
    );
    assert!(admit(&mut open_file(&path, &clock), &first).is_err());
    execute(
        &path,
        "UPDATE pipeline_admission_receipts SET event_count = 3;",
    );

    execute(
        &path,
        "CREATE TRIGGER blocked_cleanup BEFORE DELETE ON pipeline_admission_receipts
         BEGIN SELECT RAISE(ABORT, 'injected cleanup fault'); END;",
    );
    let mut blocked = open_file(&path, &clock);
    assert!(blocked.delete_timeline(first.timeline).is_err());
    assert_eq!(event_count(&blocked, first.timeline), 3);
    drop(blocked);

    execute(
        &path,
        "UPDATE pipeline_admission_fences SET fence_bytes = X'02' || substr(fence_bytes, 2);",
    );
    let mut corrupted = open_file(&path, &clock);
    assert!(corrupted.pipeline_admission_fence(first.timeline).is_err());
    assert!(admit(&mut corrupted, &attempt_after(&first, 2, 3)).is_err());
    assert_eq!(event_count(&corrupted, first.timeline), 3);
}

fn attempt_after(previous: &Attempt, key: u8, head: u64) -> Attempt {
    Attempt {
        key,
        observed_through: head,
        precondition: PipelinePreconditionV1::ExpectedLogicalHead(Seq::from_u64(head)),
        ..previous.clone()
    }
}
