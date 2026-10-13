//! ADR-021 admitted-batch contract shared by `MemoryStore` and `SqliteStore`.

use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use pos_core::output_policy::OutputAuthorityV1;
use pos_core::{
    assemble_factual_tick, pipeline_authority_revision_v1, pipeline_delegation_revision_v1,
    pipeline_erasure_revision_v1, AdmissionClock, AppendDedupKey, AppendDedupScope, AppendIdentity,
    AuthorityGranteeV1, AuthorityPersistenceHostV1, AuthorityPersistencePortV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, CanonicalBytes, CapabilityGrantDraftV1,
    CapabilityGrantV1, CapabilityRevocationDraftV1, CapabilityRevocationV1, CapabilityScopeDraftV1,
    CapabilityScopeV1, CoreError, CounterfactualDependencyReadPortV1, DelegateClassV1,
    DependencyEdgeRecordV1, DependencyNodeCoordinateV1, DependencyNodeRecordV1,
    DependencyPageRequestV1, DependencyReadScopeV1, EntityId, ErasureContainmentGateV1, Event,
    EventDraft, EventStore, FactualCutV1, FactualDriverStepV1, FactualHeadV1, FactualIngressEventV1,
    FactualInputV1, FactualOutputV1, FactualOwnerIdV1, FactualPrefixReadPortV1, FactualPriorNodeV1,
    FactualScheduledTickV1, FactualTickContextV1, FactualTickDependenciesV1, FactualTickShapeV1,
    Hash, Kind, OutputNodeBindingV1, PipelineAdmissionBasisDraftV1, PipelineAdmissionBasisV1,
    PipelineAdmissionFencePublisherV1, PipelineAdmissionFenceV1, PipelineAdmissionPortV1,
    PipelineAttemptDraftV1, PipelineAttemptIdV1, PipelineAttemptV1, PipelineCommitReceiptV1,
    PipelineDraftBatchV1, PipelineEvidenceRefV1, PipelineIngressV1, PipelineObservationAnchorV1,
    PipelineOutcomeV1, PipelinePreconditionV1, PipelineReceiptLookupV1,
    PipelineSecurityRevisionsDraftV1, PipelineSecurityRevisionsV1, PrincipalRefV1,
    RecordedDependencyClassV1, RecordedNodeOriginV1, RecordedSetCountsV1, Seq, SeqRange,
    TentativePipelineResultV1, TickDependencyRecordV1, TimelineId, WallTime,
    APPEND_IDENTITY_RETENTION_MICROS, DELEGATE_ACTION_V1, GEOGRAPHIC_EVENT_TYPE,
    MAX_DEPENDENCY_PAGE_ROWS_V1, PIPELINE_CONTRACT_VERSION_V1,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};
use tempfile::tempdir;
use ulid::Ulid;

trait Harness:
    EventStore
    + PipelineAdmissionPortV1
    + PipelineAdmissionFencePublisherV1
    + AuthorityPersistencePortV1
{
}

impl<T> Harness for T where
    T: EventStore
        + PipelineAdmissionPortV1
        + PipelineAdmissionFencePublisherV1
        + AuthorityPersistencePortV1
{
}

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
            actions: vec!["act".to_owned(), DELEGATE_ACTION_V1.to_owned()],
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

fn revisions_with(authority: Hash, delegation: Hash, erasure: Hash) -> PipelineSecurityRevisionsV1 {
    ok(PipelineSecurityRevisionsV1::try_from_draft(
        PipelineSecurityRevisionsDraftV1 {
            authority,
            consent: hash(11),
            capability: hash(12),
            delegation,
            policy: hash(14),
            execution_profile: hash(15),
            erasure,
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
    let authority = ok(store.load_authority(hash(1)));
    let revisions = revisions_with(
        pipeline_authority_revision_v1(&authority),
        pipeline_delegation_revision_v1(&authority),
        pipeline_erasure_revision_v1(gate.inventory_generation().ok()),
    );
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
    /// The factual Tick the attempt declares: the next Tick of its Timeline.
    tick: u64,
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
        tick: 1,
    }
}

fn scheduled_shape(drafts: &[EventDraft]) -> FactualTickShapeV1 {
    let outputs = drafts
        .iter()
        .map(|draft| FactualOutputV1 {
            draft: draft.clone(),
            authority: OutputAuthorityV1::Authoritative,
            direct_inputs: Vec::new(),
        })
        .collect();
    let driver = FactualDriverStepV1 {
        owner: FactualOwnerIdV1::new("plugin:test".to_owned()),
        policy_identity: hash(8),
        step_inputs: Vec::new(),
        outputs,
    };
    FactualTickShapeV1::Scheduled(FactualScheduledTickV1 {
        snapshot_digest: hash(61),
        prefix_contents: Vec::new(),
        history_contents: Vec::new(),
        ingress_events: Vec::new(),
        drivers: vec![driver],
    })
}

/// The factual Tick declaration of a hand-built attempt: a real record for
/// the Tick the attempt names, under the fence's authority grant.
fn tick_dependencies(attempt: &Attempt) -> FactualTickDependenciesV1 {
    let context = FactualTickContextV1 {
        timeline_id: attempt.timeline,
        tick: attempt.tick,
        attempt_id: ok(PipelineAttemptIdV1::try_new([attempt.key; 16])),
        evidence_digest: hash(60),
        authority_grant: hash(1),
    };
    let drafts = &attempt.drafts;
    let shape = match attempt.ingress {
        PipelineIngressV1::HumanProposedAction => FactualTickShapeV1::Human(drafts.clone()),
        PipelineIngressV1::ScheduledAiDriver => scheduled_shape(drafts),
    };
    ok(assemble_factual_tick(&context, &shape))
}

fn basis(attempt: &Attempt) -> PipelineAdmissionBasisV1 {
    basis_declaring(attempt, tick_dependencies(attempt))
}

/// The basis of a hand-built attempt that declares `dependencies`.
fn basis_declaring(
    attempt: &Attempt,
    dependencies: FactualTickDependenciesV1,
) -> PipelineAdmissionBasisV1 {
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
            dependencies,
        },
    ))
}

fn admit(store: &mut dyn Harness, attempt: &Attempt) -> Result<PipelineOutcomeV1, CoreError> {
    store.admit_pipeline_batch(&basis(attempt))
}

fn error_text<T>(result: Result<T, CoreError>) -> Option<String> {
    result.err().map(|error| error.to_string())
}

const fn receipt_of(outcome: &PipelineOutcomeV1) -> Option<&PipelineCommitReceiptV1> {
    match outcome {
        PipelineOutcomeV1::Committed(receipt) => Some(receipt),
        _ => None,
    }
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

        let next = committed(ok(admit(store.as_mut(), &attempt_after(&first, 2, 3))));
        assert_eq!(receipt_positions(&next), [4, 5, 6], "{name}");
        assert_eq!(
            ok(admit(store.as_mut(), &attempt_after(&first, 3, 3))),
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
                revisions: revisions_with(
                    hash(99),
                    valid.revisions.as_draft().delegation,
                    valid.revisions.as_draft().erasure,
                ),
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
fn persisted_authority_and_erasure_are_composed_at_commit() {
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

        let erasure = fixture.revisions.as_draft().erasure;
        let delegation = fixture.revisions.as_draft().delegation;
        let forged = revisions_with(hash(99), delegation, erasure);
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

        // The host fence and the basis agree, but neither names the persisted
        // erasure inventory generation, so the comparison fails closed.
        let authority = fixture.revisions.as_draft().authority;
        let stale_erasure = revisions_with(authority, delegation, hash(16));
        assert_ne!(stale_erasure.as_draft().erasure, erasure, "{name}");
        ok(store.set_pipeline_admission_fence(fixture.timeline, fence_for(stale_erasure, hash(1))));
        assert_eq!(
            ok(admit(
                store.as_mut(),
                &Attempt {
                    revisions: stale_erasure,
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
        let frozen = Some(CoreError::ErasureAccessFrozen.to_string());

        assert_eq!(
            error_text(admit(store.as_mut(), &attempt(&fixture, 1, 0))),
            frozen,
            "{name}"
        );
        let replacement = ok(fixture.fence.after_commit(1).ok_or("budget"));
        assert_eq!(
            error_text(store.set_pipeline_admission_fence(fixture.timeline, replacement)),
            frozen,
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
        // The child forks inside the parent's first Tick, so its own first Tick
        // is Tick 1 and the contenders for the next one declare Tick 2.
        let child_attempt = |key: u8, head: u64, tick: u64| Attempt {
            timeline: child,
            tick,
            ..attempt(&fixture, key, head)
        };

        let receipt = committed(ok(admit(store.as_mut(), &child_attempt(2, 2, 1))));
        assert_eq!(receipt_positions(&receipt), [3, 4, 5], "{name}");
        assert_eq!(event_count(store.as_ref(), child), 5, "{name}");
        assert_eq!(event_count(store.as_ref(), fixture.timeline), 3, "{name}");

        let shared = Arc::new(Mutex::new(store));
        let barrier = Arc::new(Barrier::new(2));
        let handles = [3_u8, 4].map(|key| {
            let shared = Arc::clone(&shared);
            let barrier = Arc::clone(&barrier);
            let contender = child_attempt(key, 5, 2);
            std::thread::spawn(move || {
                barrier.wait();
                let mut guard = ok(shared.lock());
                ok(admit(guard.as_mut(), &contender))
            })
        });
        let outcomes = handles.map(|handle| ok(handle.join()));

        assert_eq!(outcomes.iter().filter_map(receipt_of).count(), 1, "{name}");
        assert!(
            outcomes.contains(&PipelineOutcomeV1::AdmissionConflict),
            "{name}"
        );
        assert_eq!(event_count(ok(shared.lock()).as_ref(), child), 8, "{name}");
    }
}

#[test]
fn expired_receipts_release_their_key_and_are_purged_in_bounds() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        let fixture = prepare(store.as_mut());
        let first = attempt(&fixture, 1, 0);
        committed(ok(admit(store.as_mut(), &first)));
        let second = attempt_after(&first, 2, 3);
        committed(ok(admit(store.as_mut(), &second)));
        clock.advance(APPEND_IDENTITY_RETENTION_MICROS);

        // A rejected attempt under an expired key leaves its receipt retained.
        assert_eq!(
            ok(admit(store.as_mut(), &first)),
            PipelineOutcomeV1::AdmissionConflict,
            "{name}"
        );
        // A successful commit under an expired key replaces its receipt.
        let third = attempt_after(&second, 2, 6);
        let reused = committed(ok(admit(store.as_mut(), &third)));
        assert_eq!(receipt_positions(&reused), [7, 8, 9], "{name}");

        let limit = ok(NonZeroUsize::new(1).ok_or("limit"));
        let purged = ok(store.purge_expired_pipeline_receipts_bounded(limit));
        assert_eq!(
            (purged.removed, purged.more_may_remain),
            (1, true),
            "{name}: the rejected key's expired receipt was retained"
        );
        let drained = ok(store.purge_expired_pipeline_receipts_bounded(NonZeroUsize::MAX));
        assert_eq!(
            (drained.removed, drained.more_may_remain),
            (0, false),
            "{name}"
        );
        assert_eq!(
            ok(admit(store.as_mut(), &third)),
            PipelineOutcomeV1::RecoveredDuplicate(reused),
            "{name}"
        );
        let fresh = Attempt {
            drafts: drafts(&[b"fresh"]),
            ..attempt_after(&third, 1, 9)
        };
        let fresh_receipt = committed(ok(admit(store.as_mut(), &fresh)));
        assert_eq!(
            receipt_positions(&fresh_receipt),
            [10],
            "{name}: a purged key admits a fresh batch"
        );
    }
}

fn lookup(
    store: &mut dyn Harness,
    timeline: TimelineId,
    key: u8,
    attempt: u8,
) -> Result<PipelineReceiptLookupV1, CoreError> {
    store.lookup_pipeline_receipt(
        timeline,
        AppendDedupKey::from_keyed_hash([key; 32]),
        ok(PipelineAttemptIdV1::try_new([attempt; 16])),
    )
}

#[test]
fn basis_free_lookup_recovers_only_the_exact_retained_attempt() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        let fixture = prepare(store.as_mut());
        assert_eq!(
            ok(lookup(store.as_mut(), fixture.timeline, 1, 1)),
            PipelineReceiptLookupV1::Absent,
            "{name}"
        );
        let first = attempt(&fixture, 1, 0);
        let receipt = committed(ok(admit(store.as_mut(), &first)));

        assert_eq!(
            ok(lookup(store.as_mut(), fixture.timeline, 1, 1)),
            PipelineReceiptLookupV1::Retained(receipt.clone()),
            "{name}"
        );
        assert_eq!(
            ok(lookup(store.as_mut(), fixture.timeline, 1, 9)),
            PipelineReceiptLookupV1::Conflict,
            "{name}: another attempt under the same key"
        );
        let other = ok(store.create_timeline("other-admission")).id();
        assert_eq!(
            ok(lookup(store.as_mut(), other, 1, 1)),
            PipelineReceiptLookupV1::Conflict,
            "{name}: the same key on another Timeline"
        );
        assert_eq!(
            error_text(lookup(store.as_mut(), timeline_id(99), 1, 1)),
            Some(CoreError::TimelineNotFound(timeline_id(99)).to_string()),
            "{name}"
        );

        let child = ok(store.fork(fixture.timeline, Seq::from_u64(3), "lookup-child")).id();
        ok(store.set_pipeline_admission_fence(child, fixture.fence));
        let child_receipt = committed(ok(admit(
            store.as_mut(),
            &Attempt {
                timeline: child,
                ..attempt_after(&first, 2, 3)
            },
        )));
        assert_eq!(receipt_positions(&child_receipt), [4, 5, 6], "{name}");
        assert_eq!(
            ok(lookup(store.as_mut(), child, 2, 2)),
            PipelineReceiptLookupV1::Retained(child_receipt),
            "{name}: the receipt keeps logical Fork positions"
        );

        clock.advance(APPEND_IDENTITY_RETENTION_MICROS);
        assert_eq!(
            ok(lookup(store.as_mut(), child, 2, 2)),
            PipelineReceiptLookupV1::Absent,
            "{name}: an expired receipt releases its key"
        );

        fixture.gate.freeze_timeline_for_test(fixture.timeline);
        assert_eq!(
            error_text(lookup(store.as_mut(), fixture.timeline, 1, 1)),
            Some(CoreError::ErasureAccessFrozen.to_string()),
            "{name}"
        );
    }
}

#[test]
fn subject_scoped_cleanup_releases_admitted_receipts_in_bounds() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        let fixture = prepare(store.as_mut());
        let first_attempt = attempt(&fixture, 1, 0);
        let first = committed(ok(admit(store.as_mut(), &first_attempt)));
        let second_attempt = attempt_after(&first_attempt, 2, 3);
        committed(ok(admit(store.as_mut(), &second_attempt)));
        let scope = AppendDedupScope::from_keyed_hash([62; 32]);
        let one = ok(NonZeroUsize::new(1).ok_or("limit"));

        let partial = ok(store.remove_append_identities_bounded(scope, one));
        assert_eq!(
            (partial.removed, partial.more_may_remain),
            (1, true),
            "{name}"
        );
        assert_eq!(
            ok(store.pending_append_identity_cleanup()),
            Some(scope),
            "{name}: the remaining receipt keeps the cleanup pending"
        );
        let rest = ok(store.remove_append_identities_bounded(scope, NonZeroUsize::MAX));
        assert_eq!((rest.removed, rest.more_may_remain), (1, false), "{name}");
        assert_eq!(ok(store.pending_append_identity_cleanup()), None, "{name}");
        assert_eq!(
            ok(lookup(store.as_mut(), fixture.timeline, 1, 1)),
            PipelineReceiptLookupV1::Absent,
            "{name}: a released key no longer recovers {first:?}"
        );
        assert_eq!(event_count(store.as_ref(), fixture.timeline), 6, "{name}");
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
        assert_eq!(
            error_text(store.set_pipeline_admission_fence(fixture.timeline, fixture.fence)),
            Some(CoreError::TimelineNotFound(fixture.timeline).to_string()),
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
        ok(lookup(&mut reopened, first.timeline, 1, 1)),
        PipelineReceiptLookupV1::Retained(receipt.clone())
    );
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
        "UPDATE pipeline_admission_receipts SET expires_at = -expires_at;",
    );
    assert!(
        error_text(admit(&mut open_file(&path, &clock), &first))
            .is_some_and(|text| text.contains("outside its storage range")),
        "an out-of-range persisted integer is a storage error, not a clamp"
    );
    assert!(
        error_text(lookup(&mut open_file(&path, &clock), first.timeline, 1, 1))
            .is_some_and(|text| text.contains("outside its storage range")),
        "a basis-free lookup reads the same validated row"
    );
    execute(
        &path,
        "UPDATE pipeline_admission_receipts SET expires_at = -expires_at;",
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
        "UPDATE pipeline_admission_fences
         SET fence_bytes = CAST(X'02' || substr(fence_bytes, 2) AS BLOB);",
    );
    let mut corrupted = open_file(&path, &clock);
    assert!(corrupted.pipeline_admission_fence(first.timeline).is_err());
    assert!(admit(&mut corrupted, &attempt_after(&first, 2, 3)).is_err());
    assert_eq!(event_count(&corrupted, first.timeline), 3);
}

/// The attempt that follows a committed `previous` one: the next Tick.
fn attempt_after(previous: &Attempt, key: u8, head: u64) -> Attempt {
    Attempt {
        key,
        observed_through: head,
        precondition: PipelinePreconditionV1::ExpectedLogicalHead(Seq::from_u64(head)),
        tick: previous.tick + 1,
        ..previous.clone()
    }
}

#[test]
fn sqlite_connections_racing_on_one_logical_head_commit_at_most_once() {
    let clock = TestClock::at(1_000);
    let directory = ok(tempdir());
    let path = directory.path().join("admission-race.db");
    let (fixture_attempt, initial) = {
        let mut store = ok(SqliteStore::open_with_clock(
            path.to_str().unwrap_or_default(),
            Box::new(clock.clone()),
        ));
        let fixture = prepare(&mut store);
        (
            attempt(&fixture, 1, 0),
            event_count(&store, fixture.timeline),
        )
    };

    // Two independent connections race the same Logical Head. The immediate
    // transaction serializes them; the loser either waits and observes the
    // winner's write as a changed erasure inventory, or loses on contention.
    // Either way it fails closed and commits nothing.
    let barrier = Arc::new(Barrier::new(2));
    let handles = [2_u8, 3].map(|key| {
        let barrier = Arc::clone(&barrier);
        let mut store = open_file(&path, &clock);
        // Nothing committed before the race: both contenders declare Tick 1.
        let contender = Attempt {
            key,
            ..fixture_attempt.clone()
        };
        std::thread::spawn(move || {
            barrier.wait();
            admit(&mut store, &contender)
        })
    });
    let outcomes = handles.map(|handle| ok(handle.join()));

    let winners = outcomes
        .iter()
        .filter_map(|outcome| outcome.as_ref().ok().and_then(receipt_of))
        .collect::<Vec<_>>();
    assert_eq!(winners.len(), 1);
    assert_eq!(receipt_positions(winners[0]), [1, 2, 3]);
    let reopened = open_file(&path, &clock);
    assert_eq!(
        event_count(&reopened, fixture_attempt.timeline),
        initial + 3
    );
    assert_eq!(
        remaining_budget(&reopened, fixture_attempt.timeline),
        Some(7)
    );
}

#[test]
fn sqlite_hosts_republishing_one_fence_fail_closed_when_interleaved() {
    let clock = TestClock::at(1_000);
    let directory = ok(tempdir());
    let path = directory.path().join("admission-shared-fence.db");
    let gateway_attempt = {
        let mut store = ok(SqliteStore::open_with_clock(
            path.to_str().unwrap_or_default(),
            Box::new(clock.clone()),
        ));
        attempt(&prepare(&mut store), 1, 0)
    };
    let timeline = gateway_attempt.timeline;
    let session_revisions = ok(PipelineSecurityRevisionsV1::try_from_draft(
        PipelineSecurityRevisionsDraftV1 {
            execution_profile: hash(16),
            ..gateway_attempt.revisions.as_draft()
        },
    ));
    let session_attempt = Attempt {
        key: 2,
        revisions: session_revisions,
        ..gateway_attempt.clone()
    };

    // A Gateway and an experiment session share one file and each republish
    // the Timeline's fence from their own revisions; the session writes last.
    let mut gateway = open_file(&path, &clock);
    ok(gateway
        .set_pipeline_admission_fence(timeline, fence_for(gateway_attempt.revisions, hash(1))));
    let mut session = open_file(&path, &clock);
    ok(session.set_pipeline_admission_fence(timeline, fence_for(session_revisions, hash(1))));

    // The open Gateway connection observes the foreign write and rejects
    // before comparing.
    assert!(admit(&mut gateway, &gateway_attempt).is_err());
    drop(gateway);
    drop(session);
    // A fresh Gateway connection compares its basis with the replaced fence.
    assert_eq!(
        ok(admit(&mut open_file(&path, &clock), &gateway_attempt)),
        PipelineOutcomeV1::AdmissionConflict
    );
    assert_eq!(
        ok(lookup(&mut open_file(&path, &clock), timeline, 1, 1)),
        PipelineReceiptLookupV1::Absent
    );
    assert_eq!(event_count(&open_file(&path, &clock), timeline), 0);

    // Only the host whose fence is current commits.
    let receipt = committed(ok(admit(&mut open_file(&path, &clock), &session_attempt)));
    assert_eq!(receipt_positions(&receipt), [1, 2, 3]);
}

#[test]
fn sqlite_rejects_an_unreleased_receipt_table_or_index_shape_closed() {
    let clock = TestClock::at(1_000);
    let directory = ok(tempdir());
    let path = directory.path().join("admission-schema.db");
    let path_text = path.to_str().unwrap_or_default();
    drop(ok(SqliteStore::open_with_clock(
        path_text,
        Box::new(clock.clone()),
    )));
    let open_read_only = || error_text(SqliteStore::open_read_only(path_text));
    let open_writable = || {
        error_text(SqliteStore::open_with_clock(
            path_text,
            Box::new(clock.clone()),
        ))
    };

    execute(&path, "DROP INDEX idx_pipeline_admission_receipts_scope;");
    assert!(open_read_only()
        .is_some_and(|text| text.contains("idx_pipeline_admission_receipts_scope index")));
    // A writable open recreates a missing index.
    assert_eq!(open_writable(), None);
    assert_eq!(open_read_only(), None);

    execute(
        &path,
        "DROP INDEX idx_pipeline_admission_receipts_scope;
         CREATE INDEX idx_pipeline_admission_receipts_scope
         ON pipeline_admission_receipts(scope_key);",
    );
    assert!(open_writable()
        .is_some_and(|text| text.contains("idx_pipeline_admission_receipts_scope index")));

    // The receipt shape before #319 has no migration and is rejected closed.
    execute(
        &path,
        "DROP TABLE pipeline_admission_receipts;
         CREATE TABLE pipeline_admission_receipts (
             dedup_key BLOB PRIMARY KEY NOT NULL CHECK (length(dedup_key) = 32),
             timeline_id TEXT NOT NULL,
             basis_digest BLOB NOT NULL CHECK (length(basis_digest) = 32),
             first_local_seq INTEGER NOT NULL CHECK (first_local_seq >= 1),
             event_count INTEGER NOT NULL CHECK (event_count >= 1),
             expires_at INTEGER NOT NULL
         );",
    );
    assert!(open_read_only().is_some_and(|text| text.contains("pipeline_admission_receipts table")));
    assert!(open_writable().is_some());
    assert!(open_read_only().is_some_and(|text| text.contains("pipeline_admission_receipts table")));
}

// ── Recorded factual Ticks (ADR-064 Revision 3, R3.7.2, R3.7.4, R3.7.5) ────
//
// `MemoryStore` checks the Tick declaration and records its rows with the
// Events. `SqliteStore` accepts the declaration and records nothing until its
// own slice: that slice adds the adapter to `recording_stores` and every case
// below runs against it unchanged.

trait RecordingHarness:
    Harness + CounterfactualDependencyReadPortV1 + FactualPrefixReadPortV1
{
}

impl<T> RecordingHarness for T where
    T: Harness + CounterfactualDependencyReadPortV1 + FactualPrefixReadPortV1
{
}

/// The adapters that record factual Ticks.
fn recording_stores(clock: &TestClock) -> Vec<(&'static str, Box<dyn RecordingHarness>)> {
    vec![(
        "memory",
        Box::new(MemoryStore::with_clock(Box::new(clock.clone()))),
    )]
}

fn recorded_nodes(
    store: &dyn RecordingHarness,
    timeline: TimelineId,
) -> Vec<DependencyNodeRecordV1> {
    let scope = DependencyReadScopeV1::ParentPrefix {
        timeline,
        through_tick: u64::MAX,
    };
    let request = ok(DependencyPageRequestV1::try_new(
        scope,
        None,
        MAX_DEPENDENCY_PAGE_ROWS_V1,
    ));
    ok(store.read_dependency_nodes(&request)).items().to_vec()
}

fn recorded_edges(
    store: &dyn RecordingHarness,
    timeline: TimelineId,
) -> Vec<DependencyEdgeRecordV1> {
    let scope = DependencyReadScopeV1::ParentPrefix {
        timeline,
        through_tick: u64::MAX,
    };
    let request = ok(DependencyPageRequestV1::try_new(
        scope,
        None,
        MAX_DEPENDENCY_PAGE_ROWS_V1,
    ));
    ok(store.read_dependency_edges(&request)).items().to_vec()
}

const fn head(tick: u64, last_seq: u64) -> FactualHeadV1 {
    FactualHeadV1 {
        tick,
        last_seq: Seq::from_u64(last_seq),
    }
}

fn head_of(store: &dyn RecordingHarness, timeline: TimelineId) -> FactualHeadV1 {
    ok(store.last_committed_factual_tick(timeline))
}

/// What a refused attempt must leave as it found it: the factual head, the
/// recorded row counts, the Events and the fence budget.
fn state_of(
    store: &dyn RecordingHarness,
    timeline: TimelineId,
) -> (FactualHeadV1, RecordedSetCountsV1, usize, Option<u64>) {
    (
        head_of(store, timeline),
        ok(store.factual_set_counts(timeline)),
        event_count(store, timeline),
        remaining_budget(store, timeline),
    )
}

/// The attempt that follows a committed `previous` one on the scheduled path.
fn scheduled_after(previous: &Attempt, key: u8, head: u64) -> Attempt {
    Attempt {
        ingress: PipelineIngressV1::ScheduledAiDriver,
        ..attempt_after(previous, key, head)
    }
}

/// The shape of a scheduled Tick whose one Driver outputs `drafts` and
/// consumes the ingress node this Tick records for each of `ingress_events`,
/// besides the `extra` inputs.
fn scheduled_shape_of(
    drafts: &[EventDraft],
    snapshot: Hash,
    ingress_events: Vec<FactualIngressEventV1>,
    extra: Vec<FactualInputV1>,
) -> FactualTickShapeV1 {
    let outputs = drafts
        .iter()
        .map(|draft| FactualOutputV1 {
            draft: draft.clone(),
            authority: OutputAuthorityV1::Authoritative,
            direct_inputs: Vec::new(),
        })
        .collect();
    let step_inputs = ingress_events
        .iter()
        .map(|event| FactualInputV1::IngressEvent(event.seq))
        .chain(extra)
        .collect();
    let driver = FactualDriverStepV1 {
        owner: FactualOwnerIdV1::new("plugin:test".to_owned()),
        policy_identity: hash(8),
        step_inputs,
        outputs,
    };
    FactualTickShapeV1::Scheduled(FactualScheduledTickV1 {
        snapshot_digest: snapshot,
        prefix_contents: Vec::new(),
        history_contents: Vec::new(),
        ingress_events,
        drivers: vec![driver],
    })
}

/// The declaration of `shape` for the Tick `attempt` names, under `grant`.
fn declared(
    attempt: &Attempt,
    grant: Hash,
    shape: &FactualTickShapeV1,
) -> FactualTickDependenciesV1 {
    let context = FactualTickContextV1 {
        timeline_id: attempt.timeline,
        tick: attempt.tick,
        attempt_id: ok(PipelineAttemptIdV1::try_new([attempt.key; 16])),
        evidence_digest: hash(60),
        authority_grant: grant,
    };
    ok(assemble_factual_tick(&context, shape))
}

/// The correct declaration of a scheduled attempt that records ingress nodes
/// for `ingress_events`.
fn valid_declaration(
    attempt: &Attempt,
    ingress_events: Vec<FactualIngressEventV1>,
) -> FactualTickDependenciesV1 {
    let shape = scheduled_shape_of(&attempt.drafts, hash(61), ingress_events, Vec::new());
    declared(attempt, hash(1), &shape)
}

fn ingress_event(event: &Event) -> FactualIngressEventV1 {
    FactualIngressEventV1 {
        seq: event.seq,
        event_type: event.event_type.as_str().to_owned(),
        payload_hash: event.payload_hash,
    }
}

/// The declaration with another record, bindings unchanged.
fn with_record(
    declaration: &FactualTickDependenciesV1,
    record: TickDependencyRecordV1,
) -> FactualTickDependenciesV1 {
    FactualTickDependenciesV1::new(
        declaration.tick(),
        record,
        declaration.output_bindings().to_vec(),
        declaration.event_nodes().to_vec(),
    )
}

/// The record rebuilt through `try_new`: every node with the input list
/// `inputs_of` names and the origin `origin`, and the edges `keep_edge` keeps.
fn rebuilt(
    record: &TickDependencyRecordV1,
    origin: RecordedNodeOriginV1,
    inputs_of: impl Fn(&DependencyNodeRecordV1) -> Vec<Hash>,
    keep_edge: impl Fn(&DependencyEdgeRecordV1) -> bool,
) -> TickDependencyRecordV1 {
    let nodes = record
        .nodes()
        .iter()
        .map(|node| {
            ok(DependencyNodeRecordV1::try_new(
                node.coordinate().clone(),
                node.class(),
                origin,
                inputs_of(node),
                node.provenance_digest(),
            ))
        })
        .collect();
    let edges = record
        .edges()
        .iter()
        .filter(|edge| keep_edge(edge))
        .cloned()
        .collect();
    ok(TickDependencyRecordV1::try_new(
        record.tick(),
        origin,
        nodes,
        edges,
    ))
}

fn inputs_unchanged(node: &DependencyNodeRecordV1) -> Vec<Hash> {
    node.input_digests().to_vec()
}

/// Whether the node is the step node (ordinal zero) or the output node of
/// that ordinal of the test Driver.
fn is_driver_node(node: &DependencyNodeRecordV1, ordinal: u32) -> bool {
    node.coordinate().owner_id() == "plugin:test" && node.coordinate().output_ordinal() == ordinal
}

fn consumes_as(edge: &DependencyEdgeRecordV1, ordinal: u32) -> bool {
    edge.consumer().owner_id() == "plugin:test" && edge.consumer().output_ordinal() == ordinal
}

/// The artifact digest of the node of `owner` at ordinal zero.
fn digest_of_host(record: &TickDependencyRecordV1, owner: &str) -> Hash {
    let found = record
        .nodes()
        .iter()
        .find(|node| node.coordinate().owner_id() == owner)
        .map(|node| node.coordinate().artifact_digest());
    found.unwrap_or_else(|| std::panic::resume_unwind(Box::new("no such host node")))
}

/// Offer `declaration` for `attempt` and require the refusal `expected`, with
/// the store exactly as it was.
fn assert_refused(
    name: &str,
    case: &str,
    store: &mut dyn RecordingHarness,
    attempt: &Attempt,
    declaration: FactualTickDependenciesV1,
    expected: &PipelineOutcomeV1,
) {
    let before = state_of(store, attempt.timeline);
    let outcome = ok(store.admit_pipeline_batch(&basis_declaring(attempt, declaration)));
    assert_eq!(&outcome, expected, "{name}: {case}");
    assert_eq!(state_of(store, attempt.timeline), before, "{name}: {case}");
}

/// One refused declaration: the case, the attempt, what it declares and the
/// outcome the store answers.
type RefusalCase = (
    &'static str,
    Attempt,
    FactualTickDependenciesV1,
    PipelineOutcomeV1,
);

/// Every way the declaration of `second` can be wrong that R3.7.2 names, over
/// a Timeline whose Tick 1 recorded Events 1 to 3 and whose Event 4 is
/// unbound. `stored` holds the nodes Tick 1 recorded.
#[allow(clippy::too_many_lines)]
fn refusal_cases(
    second: &Attempt,
    events: &[Event],
    stored: &[DependencyNodeRecordV1],
) -> Vec<RefusalCase> {
    let invalid = PipelineOutcomeV1::InvalidDependencyDeclaration;
    let valid = valid_declaration(second, vec![ingress_event(&events[3])]);
    let record = valid.record();
    let drafts = &second.drafts;
    let shaped = |ingress_events: Vec<FactualIngressEventV1>, extra: Vec<FactualInputV1>| {
        let shape = scheduled_shape_of(drafts, hash(61), ingress_events, extra);
        declared(second, hash(1), &shape)
    };
    let real = vec![ingress_event(&events[3])];
    let absent = FactualIngressEventV1 {
        seq: Seq::from_u64(99),
        event_type: "world.action".to_owned(),
        payload_hash: hash(70),
    };
    let wrong_hash = FactualIngressEventV1 {
        payload_hash: hash(77),
        ..ingress_event(&events[3])
    };
    let ghost = ok(DependencyNodeCoordinateV1::try_new(
        1,
        1,
        "plugin:ghost".to_owned(),
        0,
        7,
        hash(0xee),
    ));
    let nowhere = FactualInputV1::Prior(FactualPriorNodeV1::new(
        ghost,
        RecordedDependencyClassV1::EndogenousRecomputed,
    ));
    let mut swapped = valid.output_bindings().to_vec();
    let (left, right) = (swapped[0].node_index, swapped[1].node_index);
    swapped[0].node_index = right;
    swapped[1].node_index = left;
    let snapshot = digest_of_host(record, "host.observation");
    let origin = RecordedNodeOriginV1::Committed;

    // A record that repeats a node Tick 1 recorded, beside its own human node.
    let human = Attempt {
        ingress: PipelineIngressV1::HumanProposedAction,
        drafts: drafts[..1].to_vec(),
        ..second.clone()
    };
    let own = declared(
        &human,
        hash(1),
        &FactualTickShapeV1::Human(human.drafts.clone()),
    );
    let repeated = ok(TickDependencyRecordV1::try_new(
        2,
        origin,
        vec![stored[0].clone(), own.record().nodes()[0].clone()],
        Vec::new(),
    ));
    let repeating = FactualTickDependenciesV1::new(
        2,
        repeated,
        vec![OutputNodeBindingV1 {
            draft_index: 0,
            node_index: 1,
        }],
        Vec::new(),
    );

    vec![
        (
            "stale fence grant",
            second.clone(),
            declared(
                second,
                hash(2),
                &scheduled_shape_of(drafts, hash(61), real.clone(), Vec::new()),
            ),
            PipelineOutcomeV1::AdmissionConflict,
        ),
        (
            "wrong Tick",
            Attempt {
                tick: 3,
                ..second.clone()
            },
            valid_declaration(
                &Attempt {
                    tick: 3,
                    ..second.clone()
                },
                real.clone(),
            ),
            invalid.clone(),
        ),
        (
            "asserted Tick differs from the record",
            second.clone(),
            FactualTickDependenciesV1::new(
                3,
                record.clone(),
                valid.output_bindings().to_vec(),
                valid.event_nodes().to_vec(),
            ),
            invalid.clone(),
        ),
        (
            "provisional record",
            second.clone(),
            with_record(
                &valid,
                rebuilt(
                    record,
                    RecordedNodeOriginV1::Provisional,
                    inputs_unchanged,
                    |_| true,
                ),
            ),
            invalid.clone(),
        ),
        (
            "wrong snapshot digest",
            second.clone(),
            declared(
                second,
                hash(1),
                &scheduled_shape_of(drafts, hash(99), real.clone(), Vec::new()),
            ),
            invalid.clone(),
        ),
        (
            "output binding names another draft's node",
            second.clone(),
            FactualTickDependenciesV1::new(
                valid.tick(),
                record.clone(),
                swapped,
                valid.event_nodes().to_vec(),
            ),
            invalid.clone(),
        ),
        (
            "missing output binding",
            second.clone(),
            FactualTickDependenciesV1::new(
                valid.tick(),
                record.clone(),
                valid.output_bindings()[..2].to_vec(),
                valid.event_nodes().to_vec(),
            ),
            invalid.clone(),
        ),
        (
            "binding of an Event that does not exist",
            second.clone(),
            shaped(vec![absent], Vec::new()),
            invalid.clone(),
        ),
        (
            "binding of an Event a Tick already bound",
            second.clone(),
            shaped(vec![ingress_event(&events[1])], Vec::new()),
            invalid.clone(),
        ),
        (
            "binding with the wrong payload digest",
            second.clone(),
            shaped(vec![wrong_hash], Vec::new()),
            invalid.clone(),
        ),
        (
            "node repeated from an earlier Tick",
            human,
            repeating,
            invalid.clone(),
        ),
        (
            "edge source that resolves nowhere",
            second.clone(),
            shaped(real, vec![nowhere]),
            invalid.clone(),
        ),
        (
            "omitted required edge",
            second.clone(),
            with_record(
                &valid,
                rebuilt(record, origin, inputs_unchanged, |edge| {
                    !consumes_as(edge, 1)
                }),
            ),
            invalid.clone(),
        ),
        (
            "output without its step node",
            second.clone(),
            with_record(
                &valid,
                rebuilt(
                    record,
                    origin,
                    |node| {
                        if is_driver_node(node, 1) {
                            Vec::new()
                        } else {
                            inputs_unchanged(node)
                        }
                    },
                    |edge| !consumes_as(edge, 1),
                ),
            ),
            invalid.clone(),
        ),
        (
            "step node without the snapshot node",
            second.clone(),
            with_record(
                &valid,
                rebuilt(
                    record,
                    origin,
                    |node| {
                        if is_driver_node(node, 0) {
                            let kept = node.input_digests().iter().copied();
                            kept.filter(|digest| *digest != snapshot).collect()
                        } else {
                            inputs_unchanged(node)
                        }
                    },
                    |edge| !(consumes_as(edge, 0) && edge.source_digest() == snapshot),
                ),
            ),
            invalid,
        ),
    ]
}

#[test]
fn a_commit_records_nodes_edges_range_and_bindings_with_its_events() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in recording_stores(&clock) {
        let fixture = prepare(store.as_mut());
        let timeline = fixture.timeline;
        assert_eq!(head_of(store.as_ref(), timeline), head(0, 0), "{name}");

        // A human action: one human-ingress node per Event and no edge.
        let first = attempt(&fixture, 1, 0);
        committed(ok(admit(store.as_mut(), &first)));
        let nodes = recorded_nodes(store.as_ref(), timeline);
        assert_eq!(nodes.len(), 3, "{name}");
        assert!(recorded_edges(store.as_ref(), timeline).is_empty(), "{name}");
        assert_eq!(head_of(store.as_ref(), timeline), head(1, 3), "{name}");
        let seqs = [1, 2, 3, 4].map(Seq::from_u64);
        let bound = ok(store.nodes_for_committed_events(timeline, &seqs));
        assert_eq!(bound[..3], [0_usize, 1, 2].map(|at| Some(nodes[at].clone())), "{name}");
        assert_eq!(bound[3], None, "{name}");

        // A scheduled Tick: a snapshot, a step and three outputs, joined by
        // four edges that all carry the fence's authority grant.
        let second = scheduled_after(&first, 2, 3);
        committed(ok(admit(store.as_mut(), &second)));
        let counts = RecordedSetCountsV1 {
            nodes: 8,
            edges: 4,
            inputs: 4,
        };
        assert_eq!(ok(store.factual_set_counts(timeline)), counts, "{name}");
        assert_eq!(head_of(store.as_ref(), timeline), head(2, 6), "{name}");
        let edges = recorded_edges(store.as_ref(), timeline);
        assert!(
            edges
                .iter()
                .all(|edge| edge.authorization_digest() == Some(hash(1))),
            "{name}"
        );
        let output_seqs = [4, 5, 6].map(Seq::from_u64);
        let outputs = ok(store.nodes_for_committed_events(timeline, &output_seqs));
        for (ordinal, output) in (1_u32..).zip(&outputs) {
            let coordinate = output.as_ref().map(DependencyNodeRecordV1::coordinate);
            let found = coordinate.map(DependencyNodeCoordinateV1::output_ordinal);
            assert_eq!(found, Some(ordinal), "{name}");
            let owner = coordinate.map(DependencyNodeCoordinateV1::owner_id);
            assert_eq!(owner, Some("plugin:test"), "{name}");
        }
    }
}

#[test]
fn the_store_refuses_a_malformed_declaration_and_records_nothing() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in recording_stores(&clock) {
        let fixture = prepare(store.as_mut());
        let timeline = fixture.timeline;
        let first = attempt(&fixture, 1, 0);
        committed(ok(admit(store.as_mut(), &first)));
        // An Event appended outside the Tick path has no node yet.
        ok(store.append(timeline, &drafts(&[b"raw"])));
        let events = ok(store.read(timeline, SeqRange::all()));
        let stored = recorded_nodes(store.as_ref(), timeline);
        let second = scheduled_after(&first, 2, 4);

        for (case, rejected, declaration, expected) in refusal_cases(&second, &events, &stored) {
            assert_refused(
                name,
                case,
                store.as_mut(),
                &rejected,
                declaration,
                &expected,
            );
        }

        // Nothing a refusal touched was consumed: the correct Tick commits and
        // records the ingress node of Event 4 once, beside its outputs.
        let valid = valid_declaration(&second, vec![ingress_event(&events[3])]);
        let outcome = ok(store.admit_pipeline_batch(&basis_declaring(&second, valid)));
        let receipt = committed(outcome);
        assert_eq!(receipt_positions(&receipt), [5, 6, 7], "{name}");
        assert_eq!(head_of(store.as_ref(), timeline), head(2, 7), "{name}");
        let counts = RecordedSetCountsV1 {
            nodes: 9,
            edges: 5,
            inputs: 5,
        };
        assert_eq!(ok(store.factual_set_counts(timeline)), counts, "{name}");
        let ingress = ok(store.nodes_for_committed_events(timeline, &[Seq::from_u64(4)]));
        let owner = ingress[0].as_ref().map(|node| node.coordinate().owner_id());
        assert_eq!(owner, Some("host.ingress"), "{name}");
    }
}

/// R3.7.2 (i): an edge that names another authority grant than the persisted
/// fence's is the conflict of a moved fence. A human record has no edge, so the
/// check is vacuous there.
#[test]
fn a_stale_fence_grant_is_a_conflict_and_commits_nothing() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in recording_stores(&clock) {
        let fixture = prepare(store.as_mut());
        let base = Attempt {
            ingress: PipelineIngressV1::ScheduledAiDriver,
            ..attempt(&fixture, 1, 0)
        };
        let shape = scheduled_shape_of(&base.drafts, hash(61), Vec::new(), Vec::new());
        let stale = declared(&base, hash(2), &shape);
        let conflict = PipelineOutcomeV1::AdmissionConflict;
        assert_refused(name, "stale grant", store.as_mut(), &base, stale, &conflict);

        // The same attempt under the fence's own grant commits.
        committed(ok(admit(store.as_mut(), &base)));
        assert_eq!(head_of(store.as_ref(), base.timeline), head(1, 3), "{name}");
    }
}

#[test]
fn a_retry_records_no_second_row_and_a_rebuilt_tick_conflicts() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in recording_stores(&clock) {
        let fixture = prepare(store.as_mut());
        let timeline = fixture.timeline;
        let first = attempt(&fixture, 1, 0);
        let receipt = committed(ok(admit(store.as_mut(), &first)));
        let before = state_of(store.as_ref(), timeline);

        assert_eq!(
            ok(admit(store.as_mut(), &first)),
            PipelineOutcomeV1::RecoveredDuplicate(receipt),
            "{name}"
        );
        assert_eq!(state_of(store.as_ref(), timeline), before, "{name}");

        // A pass rebuilt after the commit declares another Tick. Tick 7 is not
        // the next Tick either, but the receipt lookup precedes every
        // dependency check, so the answer is the conflict of a changed basis.
        let later = Attempt {
            tick: 7,
            ..first.clone()
        };
        assert_eq!(
            ok(admit(store.as_mut(), &later)),
            PipelineOutcomeV1::AdmissionConflict,
            "{name}"
        );
        assert_eq!(state_of(store.as_ref(), timeline), before, "{name}");
    }
}

#[test]
fn a_fork_binds_only_the_events_of_the_ticks_below_its_cut() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in recording_stores(&clock) {
        let fixture = prepare(store.as_mut());
        let parent = fixture.timeline;
        let first = attempt(&fixture, 1, 0);
        committed(ok(admit(store.as_mut(), &first)));

        // A Fork inside Tick 1 has cut Tick 0: the parent's bindings of Events
        // 1 and 2 are invisible to it, so its own first Tick may bind them.
        let mid = FactualCutV1::MidTick {
            cut_tick: 0,
            split_tick: 1,
        };
        let cut = ok(store.cut_tick_at(parent, Seq::from_u64(2)));
        assert_eq!(cut, mid, "{name}");
        let inside = ok(store.fork(parent, Seq::from_u64(2), "inside")).id();
        ok(store.set_pipeline_admission_fence(inside, fixture.fence));
        assert_eq!(head_of(store.as_ref(), inside), head(0, 0), "{name}");
        let inherited = ok(store.read(inside, SeqRange::all()));
        let child = Attempt {
            timeline: inside,
            tick: 1,
            ..scheduled_after(&first, 2, 2)
        };
        let rebound = vec![ingress_event(&inherited[0]), ingress_event(&inherited[1])];
        let declaration = valid_declaration(&child, rebound);
        let outcome = ok(store.admit_pipeline_batch(&basis_declaring(&child, declaration)));
        assert_eq!(receipt_positions(&committed(outcome)), [3, 4, 5], "{name}");
        assert_eq!(head_of(store.as_ref(), inside), head(1, 5), "{name}");
        let seqs = [1, 2].map(Seq::from_u64);
        let own = ok(store.nodes_for_committed_events(inside, &seqs));
        let theirs = ok(store.nodes_for_committed_events(parent, &seqs));
        assert!(own.iter().all(Option::is_some), "{name}");
        assert!(theirs.iter().all(Option::is_some), "{name}");
        assert_ne!(own, theirs, "{name}");

        // A Fork on the Tick boundary has cut Tick 1: Event 2 is bound below
        // the cut and cannot be bound again; without it the first Tick is 2.
        let boundary = ok(store.fork(parent, Seq::from_u64(3), "boundary")).id();
        ok(store.set_pipeline_admission_fence(boundary, fixture.fence));
        assert_eq!(head_of(store.as_ref(), boundary), head(1, 3), "{name}");
        let inherited = ok(store.read(boundary, SeqRange::all()));
        let later = Attempt {
            timeline: boundary,
            ..scheduled_after(&first, 3, 3)
        };
        let again = valid_declaration(&later, vec![ingress_event(&inherited[1])]);
        let invalid = PipelineOutcomeV1::InvalidDependencyDeclaration;
        assert_refused(name, "bound below the cut", store.as_mut(), &later, again, &invalid);
        let plain = valid_declaration(&later, Vec::new());
        committed(ok(store.admit_pipeline_batch(&basis_declaring(&later, plain))));
        assert_eq!(head_of(store.as_ref(), boundary), head(2, 6), "{name}");
    }
}
