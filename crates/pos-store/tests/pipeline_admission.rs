//! ADR-021 admitted-batch contract shared by `MemoryStore` and `SqliteStore`.

use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use pos_core::output_policy::OutputAuthorityV1;
use pos_core::{
    assemble_factual_tick, factual_artifact_digest, factual_fold_history_content_digest,
    factual_ingress_content_digest, pipeline_authority_revision_v1,
    pipeline_delegation_revision_v1, pipeline_erasure_revision_v1, AdmissionClock, AppendDedupKey,
    AppendDedupScope, AppendIdentity, AuthorityGranteeV1, AuthorityPersistenceHostV1,
    AuthorityPersistencePortV1, AuthorityRegistrySnapshotV1, AuthorityRoleV1, CanonicalBytes,
    CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityRevocationDraftV1, CapabilityRevocationV1,
    CapabilityScopeDraftV1, CapabilityScopeV1, ConsentAuthority, ConsentGrantedV1,
    ConsentRevokedV1, CoreError, CounterfactualDependencyReadPortV1, DelegateClassV1,
    DependencyEdgeRecordV1, DependencyNodeCoordinateV1, DependencyNodeRecordV1,
    DependencyPageRequestV1, DependencyReadScopeV1, EntityId, ErasureContainmentGateV1, Event,
    EventDraft, EventNodeBindingV1, EventStore, FactualCutV1, FactualDriverStepV1,
    FactualFoldBindingV1, FactualFoldSourceV1, FactualHeadV1, FactualIngressEventV1,
    FactualInputV1, FactualNodeKeyV1, FactualOutputV1, FactualOwnerIdV1, FactualPrefixReadPortV1,
    FactualPriorNodeV1, FactualScheduledTickV1, FactualTickContextV1, FactualTickDependenciesV1,
    FactualTickShapeV1, Hash, Kind, OutputNodeBindingV1, PipelineAdmissionBasisDraftV1,
    PipelineAdmissionBasisV1, PipelineAdmissionFencePublisherV1, PipelineAdmissionFenceV1,
    PipelineAdmissionPortV1, PipelineAttemptDraftV1, PipelineAttemptIdV1, PipelineAttemptV1,
    PipelineCommitReceiptV1, PipelineDraftBatchV1, PipelineEvidenceRefV1, PipelineIngressV1,
    PipelineObservationAnchorV1, PipelineOutcomeV1, PipelinePreconditionV1,
    PipelineReceiptLookupV1, PipelineSecurityRevisionsDraftV1, PipelineSecurityRevisionsV1,
    PrincipalRefV1, RecordedDependencyClassV1, RecordedNodeOriginV1, RecordedSetCountsV1, Seq,
    SeqRange, TentativePipelineResultV1, TickDependencyRecordV1, TimelineId, WallTime,
    APPEND_IDENTITY_RETENTION_MICROS, DELEGATE_ACTION_V1, EVENT_TYPE_CONSENT_GRANTED_V1,
    EVENT_TYPE_CONSENT_REVOKED_V1, FACTUAL_FOLD_HISTORY_SCHEMA_ID_V1, GEOGRAPHIC_EVENT_TYPE,
    HOST_CONSENT_CLOSED_EVENT_TYPE, MAX_DEPENDENCY_NODE_INPUTS_V1, MAX_DEPENDENCY_PAGE_ROWS_V1,
    MAX_RECORDED_DEPENDENCY_NODES_V1, MAX_TICK_DEPENDENCY_EDGES_V1, MAX_TICK_DEPENDENCY_NODES_V1,
    MODALITY_LOCATION, PIPELINE_CONTRACT_VERSION_V1,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};
use tempfile::tempdir;
use ulid::Ulid;

trait Harness:
    EventStore
    + PipelineAdmissionPortV1
    + PipelineAdmissionFencePublisherV1
    + AuthorityPersistencePortV1
    + CounterfactualDependencyReadPortV1
    + FactualPrefixReadPortV1
{
}

impl<T> Harness for T where
    T: EventStore
        + PipelineAdmissionPortV1
        + PipelineAdmissionFencePublisherV1
        + AuthorityPersistencePortV1
        + CounterfactualDependencyReadPortV1
        + FactualPrefixReadPortV1
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
        fold: None,
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
        let parent = fixture.timeline;
        assert_recorded(name, store.as_ref(), parent, head(1, 3), 3, &[1, 2, 3]);
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
        assert_recorded(name, store.as_ref(), child, head(1, 5), 3, &[3, 4, 5]);
        assert_recorded(name, store.as_ref(), parent, head(1, 3), 3, &[1, 2, 3]);

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
        let guard = ok(shared.lock());
        assert_eq!(event_count(guard.as_ref(), child), 8, "{name}");
        // Only the winner recorded its Tick; the loser left no row.
        let bound = [3, 4, 5, 6, 7, 8];
        assert_recorded(name, guard.as_ref(), child, head(2, 8), 6, &bound);
        assert_recorded(name, guard.as_ref(), parent, head(1, 3), 3, &[1, 2, 3]);
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
        let parent = fixture.timeline;
        assert_recorded(name, store.as_ref(), parent, head(1, 3), 3, &[1, 2, 3]);

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
        assert_recorded(name, store.as_ref(), child, head(2, 6), 3, &[4, 5, 6]);
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

/// A trigger that aborts every insert into `table`.
fn insert_fault(table: &str) -> String {
    format!(
        "CREATE TRIGGER injected_fault BEFORE INSERT ON {table}
         BEGIN SELECT RAISE(ABORT, 'injected fault'); END;"
    )
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

    let empty = RecordedSetCountsV1 {
        nodes: 0,
        edges: 0,
        inputs: 0,
    };
    let triggers = [
        "CREATE TRIGGER injected_fault BEFORE INSERT ON events WHEN NEW.seq = 2
         BEGIN SELECT RAISE(ABORT, 'injected member fault'); END;"
            .to_owned(),
        insert_fault("pipeline_admission_receipts"),
        insert_fault("counterfactual_dependency_records"),
        insert_fault("counterfactual_dependency_nodes"),
        insert_fault("counterfactual_dependency_commit_ranges"),
        insert_fault("counterfactual_dependency_event_nodes"),
    ];
    for trigger in triggers {
        execute(&path, &trigger);
        let mut faulted = open_file(&path, &clock);
        assert!(admit(&mut faulted, &first).is_err());
        assert_eq!(event_count(&faulted, first.timeline), 0);
        assert_eq!(remaining_budget(&faulted, first.timeline), Some(10));
        assert_eq!(head_of(&faulted, first.timeline), head(0, 0));
        assert_eq!(ok(faulted.factual_set_counts(first.timeline)), empty);
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

#[test]
fn sqlite_an_exhausted_dependency_set_refuses_both_ingresses_and_commits_nothing() {
    let clock = TestClock::at(1_000);
    let directory = ok(tempdir());
    let ingresses = [
        PipelineIngressV1::HumanProposedAction,
        PipelineIngressV1::ScheduledAiDriver,
    ];
    for (index, ingress) in ingresses.into_iter().enumerate() {
        let path = directory
            .path()
            .join(format!("admission-exhausted-{index}.db"));
        let first = {
            let mut store = ok(SqliteStore::open_with_clock(
                path.to_str().unwrap_or_default(),
                Box::new(clock.clone()),
            ));
            let base = attempt(&prepare(&mut store), 1, 0);
            Attempt { ingress, ..base }
        };
        // A set that earlier Ticks filled to the node cap takes no further Tick.
        execute(
            &path,
            &format!(
                "INSERT INTO counterfactual_dependency_records
                 (timeline_id, generation, record_tick, node_count, edge_count, input_count)
                 VALUES ('{}', -1, 0, {MAX_RECORDED_DEPENDENCY_NODES_V1}, 0, 0);",
                first.timeline
            ),
        );

        let mut store = open_file(&path, &clock);
        assert_eq!(
            ok(admit(&mut store, &first)),
            PipelineOutcomeV1::DependencySetExhausted
        );
        assert_eq!(event_count(&store, first.timeline), 0);
        assert_eq!(remaining_budget(&store, first.timeline), Some(10));
        assert_eq!(head_of(&store, first.timeline), head(0, 0));
        let full = RecordedSetCountsV1 {
            nodes: MAX_RECORDED_DEPENDENCY_NODES_V1,
            edges: 0,
            inputs: 0,
        };
        assert_eq!(ok(store.factual_set_counts(first.timeline)), full);
    }
}

// ── Recorded factual Ticks (ADR-064 Revision 3, R3.7.2, R3.7.4, R3.7.5) ────
//
// Both adapters check the Tick declaration and record its rows with the
// Events, so every case below runs against each of them unchanged.

/// The request that reads every recorded row of the Timeline.
fn all_rows_request(timeline: TimelineId) -> DependencyPageRequestV1 {
    let scope = DependencyReadScopeV1::ParentPrefix {
        timeline,
        through_tick: u64::MAX,
    };
    ok(DependencyPageRequestV1::try_new(
        scope,
        None,
        MAX_DEPENDENCY_PAGE_ROWS_V1,
    ))
}

fn recorded_nodes(store: &dyn Harness, timeline: TimelineId) -> Vec<DependencyNodeRecordV1> {
    let request = all_rows_request(timeline);
    ok(store.read_dependency_nodes(&request)).items().to_vec()
}

fn recorded_edges(store: &dyn Harness, timeline: TimelineId) -> Vec<DependencyEdgeRecordV1> {
    let request = all_rows_request(timeline);
    ok(store.read_dependency_edges(&request)).items().to_vec()
}

const fn head(tick: u64, last_seq: u64) -> FactualHeadV1 {
    FactualHeadV1 {
        tick,
        last_seq: Seq::from_u64(last_seq),
    }
}

fn head_of(store: &dyn Harness, timeline: TimelineId) -> FactualHeadV1 {
    ok(store.last_committed_factual_tick(timeline))
}

/// What a refused attempt must leave as it found it: the factual head, the
/// recorded row counts, the Events and the fence budget.
fn state_of(
    store: &dyn Harness,
    timeline: TimelineId,
) -> (FactualHeadV1, RecordedSetCountsV1, usize, Option<u64>) {
    (
        head_of(store, timeline),
        ok(store.factual_set_counts(timeline)),
        event_count(store, timeline),
        remaining_budget(store, timeline),
    )
}

/// Require that the Timeline's factual head is `at`, its own recorded set
/// holds `nodes` nodes of human-ingress Ticks (no edge, no input) and `bound`
/// are the committed `seq`s that are bound to a node.
fn assert_recorded(
    name: &str,
    store: &dyn Harness,
    timeline: TimelineId,
    at: FactualHeadV1,
    nodes: usize,
    bound: &[u64],
) {
    assert_eq!(head_of(store, timeline), at, "{name}");
    let counts = RecordedSetCountsV1 {
        nodes,
        edges: 0,
        inputs: 0,
    };
    assert_eq!(ok(store.factual_set_counts(timeline)), counts, "{name}");
    let seqs: Vec<Seq> = bound.iter().copied().map(Seq::from_u64).collect();
    let found = ok(store.nodes_for_committed_events(timeline, &seqs));
    assert!(found.iter().all(Option::is_some), "{name}");
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
        fold: None,
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
        declaration.fold().clone(),
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

/// The node of the record whose owner is `owner`.
fn node_of<'a>(record: &'a TickDependencyRecordV1, owner: &str) -> &'a DependencyNodeRecordV1 {
    let found = record
        .nodes()
        .iter()
        .find(|node| node.coordinate().owner_id() == owner);
    found.unwrap_or_else(|| std::panic::resume_unwind(Box::new("no such node")))
}

/// The artifact digest of the node of `owner` at ordinal zero.
fn digest_of_host(record: &TickDependencyRecordV1, owner: &str) -> Hash {
    node_of(record, owner).coordinate().artifact_digest()
}

/// The artifact digest of the node at `index` of the record.
fn digest_at(record: &TickDependencyRecordV1, index: u32) -> Hash {
    let at = ok(usize::try_from(index));
    record.nodes()[at].coordinate().artifact_digest()
}

/// The index of the node with the artifact digest `digest` in the record.
fn index_of(record: &TickDependencyRecordV1, digest: Hash) -> u32 {
    let nodes = record.nodes();
    let found = nodes
        .iter()
        .position(|node| node.coordinate().artifact_digest() == digest);
    let at = found.unwrap_or_else(|| std::panic::resume_unwind(Box::new("no such node")));
    ok(u32::try_from(at))
}

/// The node with another class and input list, otherwise as it was.
fn node_like(
    node: &DependencyNodeRecordV1,
    class: RecordedDependencyClassV1,
    inputs: Vec<Hash>,
) -> DependencyNodeRecordV1 {
    ok(DependencyNodeRecordV1::try_new(
        node.coordinate().clone(),
        class,
        RecordedNodeOriginV1::Committed,
        inputs,
        node.provenance_digest(),
    ))
}

/// The ordinal of the nodes `extra_node` adds: no Driver or host node has it.
const EXTRA_ORDINAL: u32 = 99;

/// A node beside the nodes of a record: the Tick, position, schema and class of
/// `template`, the ordinal `EXTRA_ORDINAL`, and the given owner and digest.
fn extra_node(
    template: &DependencyNodeRecordV1,
    owner: &str,
    digest: Hash,
) -> DependencyNodeRecordV1 {
    let at = template.coordinate();
    let coordinate = ok(DependencyNodeCoordinateV1::try_new(
        at.tick(),
        at.scheduler_position(),
        owner.to_owned(),
        EXTRA_ORDINAL,
        at.schema_id(),
        digest,
    ));
    ok(DependencyNodeRecordV1::try_new(
        coordinate,
        template.class(),
        RecordedNodeOriginV1::Committed,
        Vec::new(),
        template.provenance_digest(),
    ))
}

/// The nodes of the record and `node`.
fn nodes_plus(
    record: &TickDependencyRecordV1,
    node: DependencyNodeRecordV1,
) -> Vec<DependencyNodeRecordV1> {
    let mut nodes = record.nodes().to_vec();
    nodes.push(node);
    nodes
}

/// A committed record over `nodes`, put in canonical order, with the edges of
/// `record` whose source is not `dropped`.
fn record_over(
    record: &TickDependencyRecordV1,
    mut nodes: Vec<DependencyNodeRecordV1>,
    dropped: Option<Hash>,
) -> TickDependencyRecordV1 {
    nodes.sort_by(|left, right| left.coordinate().cmp(right.coordinate()));
    let edges = record
        .edges()
        .iter()
        .filter(|edge| Some(edge.source_digest()) != dropped)
        .cloned()
        .collect();
    ok(TickDependencyRecordV1::try_new(
        record.tick(),
        RecordedNodeOriginV1::Committed,
        nodes,
        edges,
    ))
}

/// The declaration over `record`, every binding of `valid` pointed at the same
/// node by artifact digest. `renamed` is a node whose digest changed:
/// `(old digest, new digest)`.
fn rebound(
    valid: &FactualTickDependenciesV1,
    record: TickDependencyRecordV1,
    renamed: Option<(Hash, Hash)>,
) -> FactualTickDependenciesV1 {
    let old = valid.record();
    let index = |at: u32| {
        let digest = digest_at(old, at);
        let (_, now) = renamed
            .filter(|(from, _)| *from == digest)
            .unwrap_or((digest, digest));
        index_of(&record, now)
    };
    let outputs = valid
        .output_bindings()
        .iter()
        .map(|binding| OutputNodeBindingV1 {
            draft_index: binding.draft_index,
            node_index: index(binding.node_index),
        })
        .collect();
    let events = valid
        .event_nodes()
        .iter()
        .map(|binding| EventNodeBindingV1 {
            seq: binding.seq,
            node_index: index(binding.node_index),
        })
        .collect();
    FactualTickDependenciesV1::new(valid.tick(), record, outputs, events, valid.fold().clone())
}

/// The declaration with `node` added to its record, unbound.
fn with_node(
    valid: &FactualTickDependenciesV1,
    node: DependencyNodeRecordV1,
) -> FactualTickDependenciesV1 {
    let record = valid.record();
    let nodes = nodes_plus(record, node);
    rebound(valid, record_over(record, nodes, None), None)
}

/// The declaration with other output bindings, the record unchanged.
fn redeclared(
    valid: &FactualTickDependenciesV1,
    outputs: Vec<OutputNodeBindingV1>,
) -> FactualTickDependenciesV1 {
    FactualTickDependenciesV1::new(
        valid.tick(),
        valid.record().clone(),
        outputs,
        valid.event_nodes().to_vec(),
        valid.fold().clone(),
    )
}

/// The declaration with other Event bindings, the record unchanged.
fn with_events(
    valid: &FactualTickDependenciesV1,
    events: Vec<EventNodeBindingV1>,
) -> FactualTickDependenciesV1 {
    FactualTickDependenciesV1::new(
        valid.tick(),
        valid.record().clone(),
        valid.output_bindings().to_vec(),
        events,
        valid.fold().clone(),
    )
}

/// The edge with its authorization field replaced by an empty byte string,
/// which reads back as no digest.
fn without_authorization(edge: &DependencyEdgeRecordV1) -> DependencyEdgeRecordV1 {
    let mut field = vec![0x58, 0x20];
    field.extend_from_slice(hash(1).as_bytes());
    let bytes = edge.as_bytes();
    let found = bytes
        .windows(field.len())
        .position(|window| window == field.as_slice());
    let at = found.unwrap_or_else(|| std::panic::resume_unwind(Box::new("no authorization")));
    let mut cut = bytes[..at].to_vec();
    cut.push(0x40);
    cut.extend_from_slice(&bytes[at + field.len()..]);
    ok(DependencyEdgeRecordV1::try_from_canonical(
        cut,
        edge.consumer().clone(),
        edge.source_digest(),
    ))
}

/// The declaration whose first edge carries an authorization that is no digest.
fn with_unreadable_authorization(valid: &FactualTickDependenciesV1) -> FactualTickDependenciesV1 {
    let record = valid.record();
    let mut edges = record.edges().to_vec();
    edges[0] = without_authorization(&edges[0]);
    let unreadable = ok(TickDependencyRecordV1::try_new(
        record.tick(),
        RecordedNodeOriginV1::Committed,
        record.nodes().to_vec(),
        edges,
    ));
    with_record(valid, unreadable)
}

/// The declaration whose ingress node sits at Tick 1, its artifact digest
/// recomputed for that Tick, so that only its Tick is wrong. The step node no
/// longer consumes it.
fn ingress_at_tick_one(
    timeline: TimelineId,
    valid: &FactualTickDependenciesV1,
    event: &Event,
) -> FactualTickDependenciesV1 {
    let record = valid.record();
    let old = node_of(record, "host.ingress");
    let spot = old.coordinate();
    let key = FactualNodeKeyV1 {
        tick: 1,
        scheduler_position: spot.scheduler_position(),
        owner: spot.owner_id(),
        output_ordinal: spot.output_ordinal(),
        schema_id: spot.schema_id(),
    };
    let content = factual_ingress_content_digest(event.payload_hash, event.seq);
    let digest = factual_artifact_digest(timeline, key, content);
    let coordinate = ok(DependencyNodeCoordinateV1::try_new(
        1,
        spot.scheduler_position(),
        spot.owner_id().to_owned(),
        spot.output_ordinal(),
        spot.schema_id(),
        digest,
    ));
    let moved = ok(DependencyNodeRecordV1::try_new(
        coordinate,
        old.class(),
        RecordedNodeOriginV1::Committed,
        Vec::new(),
        old.provenance_digest(),
    ));
    let gone = spot.artifact_digest();
    let mut nodes: Vec<DependencyNodeRecordV1> = record
        .nodes()
        .iter()
        .filter(|node| node.coordinate().artifact_digest() != gone)
        .map(|node| {
            let kept = node.input_digests().iter().copied();
            let inputs = kept.filter(|input| *input != gone).collect();
            node_like(node, node.class(), inputs)
        })
        .collect();
    nodes.push(moved);
    let replaced = record_over(record, nodes, Some(gone));
    rebound(valid, replaced, Some((gone, digest)))
}

/// Offer `declaration` for `attempt` and require the refusal `expected`, with
/// the store exactly as it was.
fn assert_refused(
    name: &str,
    case: &str,
    store: &mut dyn Harness,
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

/// The refusal of `declaration` as invalid, for the given attempt.
const fn invalid_for(
    case: &'static str,
    attempt: Attempt,
    declaration: FactualTickDependenciesV1,
) -> RefusalCase {
    (
        case,
        attempt,
        declaration,
        PipelineOutcomeV1::InvalidDependencyDeclaration,
    )
}

/// The refusal of `declaration` as a conflict, for the given attempt.
const fn conflict_for(
    case: &'static str,
    attempt: Attempt,
    declaration: FactualTickDependenciesV1,
) -> RefusalCase {
    (
        case,
        attempt,
        declaration,
        PipelineOutcomeV1::AdmissionConflict,
    )
}

/// What the refusal cases share: the scheduled attempt under test, its correct
/// declaration (which records the ingress node of Event 4), the Events of the
/// Timeline and the nodes Tick 1 recorded.
struct Refusals<'a> {
    second: &'a Attempt,
    events: &'a [Event],
    stored: &'a [DependencyNodeRecordV1],
    valid: FactualTickDependenciesV1,
}

impl Refusals<'_> {
    /// The ingress Events a correct declaration records: Event 4.
    fn real(&self) -> Vec<FactualIngressEventV1> {
        vec![ingress_event(&self.events[3])]
    }

    /// A scheduled declaration over `snapshot`, recording `ingress_events` and
    /// declaring the `extra` Driver inputs.
    fn shaped(
        &self,
        snapshot: Hash,
        ingress_events: Vec<FactualIngressEventV1>,
        extra: Vec<FactualInputV1>,
    ) -> FactualTickDependenciesV1 {
        let shape = scheduled_shape_of(&self.second.drafts, snapshot, ingress_events, extra);
        declared(self.second, hash(1), &shape)
    }

    /// The refusal of `declaration` as invalid, for the scheduled attempt.
    fn invalid(&self, case: &'static str, declaration: FactualTickDependenciesV1) -> RefusalCase {
        invalid_for(case, self.second.clone(), declaration)
    }
}

/// Every way the declaration of `second` can be wrong that R3.7.2 names, over
/// a Timeline whose Tick 1 recorded Events 1 to 3 and whose Event 4 is
/// unbound. `stored` holds the nodes Tick 1 recorded.
///
/// An oversized record cannot reach the store: `TickDependencyRecordV1::try_new`
/// refuses it host-side, and that refusal is covered where `try_new` is.
fn refusal_cases(
    second: &Attempt,
    events: &[Event],
    stored: &[DependencyNodeRecordV1],
) -> Vec<RefusalCase> {
    let valid = valid_declaration(second, vec![ingress_event(&events[3])]);
    let refusals = Refusals {
        second,
        events,
        stored,
        valid,
    };
    [
        grant_and_tick_cases(&refusals),
        output_cases(&refusals),
        ingress_cases(&refusals),
        edge_cases(&refusals),
        node_cases(&refusals),
        human_cases(&refusals),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// R3.7.2 (i) and (ii): the fence's grant and the Tick. An authorization that
/// is no digest cannot equal the fence's grant, so it is the same conflict as
/// a digest of another grant: a fence that moved. The Tick must be the next
/// one: a replay of the last Tick and Tick 0 are as wrong as one in the future.
fn grant_and_tick_cases(r: &Refusals<'_>) -> Vec<RefusalCase> {
    let (second, valid) = (r.second, &r.valid);
    let record = valid.record();
    let shape = scheduled_shape_of(&second.drafts, hash(61), r.real(), Vec::new());
    let stale = declared(second, hash(2), &shape);
    let unreadable = with_unreadable_authorization(valid);
    let moved = Attempt {
        tick: 3,
        ..second.clone()
    };
    let wrong_tick = valid_declaration(&moved, r.real());
    let replayed = Attempt {
        tick: 1,
        ..second.clone()
    };
    let replay = valid_declaration(&replayed, r.real());
    let initial = Attempt {
        tick: 0,
        ..second.clone()
    };
    let tick_zero = valid_declaration(&initial, r.real());
    let asserted = FactualTickDependenciesV1::new(
        3,
        record.clone(),
        valid.output_bindings().to_vec(),
        valid.event_nodes().to_vec(),
        valid.fold().clone(),
    );
    let origin = RecordedNodeOriginV1::Provisional;
    let provisional_record = rebuilt(record, origin, inputs_unchanged, |_| true);
    let provisional = with_record(valid, provisional_record);
    vec![
        conflict_for("stale fence grant", second.clone(), stale),
        conflict_for(
            "authorization that is no digest",
            second.clone(),
            unreadable,
        ),
        invalid_for("wrong Tick", moved, wrong_tick),
        invalid_for("replay of the last Tick", replayed, replay),
        invalid_for("Tick 0", initial, tick_zero),
        r.invalid("asserted Tick differs from the record", asserted),
        r.invalid("provisional record", provisional),
    ]
}

/// R3.7.2 (iii), outputs and snapshot.
fn output_cases(r: &Refusals<'_>) -> Vec<RefusalCase> {
    let valid = &r.valid;
    let wrong_snapshot = r.shaped(hash(99), r.real(), Vec::new());
    let mut swapped = valid.output_bindings().to_vec();
    let (left, right) = (swapped[0].node_index, swapped[1].node_index);
    swapped[0].node_index = right;
    swapped[1].node_index = left;
    let crossed = redeclared(valid, swapped);
    let first_two = valid.output_bindings()[..2].to_vec();
    let short = redeclared(valid, first_two);
    vec![
        r.invalid("wrong snapshot digest", wrong_snapshot),
        r.invalid("output binding names another draft's node", crossed),
        r.invalid("missing output binding", short),
    ]
}

/// R3.7.2 (iv): the Event bindings of the ingress nodes.
fn ingress_cases(r: &Refusals<'_>) -> Vec<RefusalCase> {
    let (second, valid) = (r.second, &r.valid);
    let absent = FactualIngressEventV1 {
        seq: Seq::from_u64(99),
        event_type: "world.action".to_owned(),
        payload_hash: hash(70),
    };
    let wrong_hash = FactualIngressEventV1 {
        payload_hash: hash(77),
        ..ingress_event(&r.events[3])
    };
    let missing = r.shaped(hash(61), vec![absent], Vec::new());
    let bound = r.shaped(hash(61), vec![ingress_event(&r.events[1])], Vec::new());
    let mismatched = r.shaped(hash(61), vec![wrong_hash], Vec::new());
    // Event 4 exists, but the observation of this attempt ends at Event 3.
    let late = Attempt {
        observed_through: 3,
        ..second.clone()
    };
    let beyond = valid_declaration(&late, r.real());
    let binding = valid.event_nodes()[0];
    let twice = with_events(valid, vec![binding, binding]);
    let earlier = ingress_at_tick_one(second.timeline, valid, &r.events[3]);
    vec![
        r.invalid("binding of an Event that does not exist", missing),
        r.invalid("binding of an Event a Tick already bound", bound),
        r.invalid("binding with the wrong payload digest", mismatched),
        invalid_for("binding of an Event past the observation", late, beyond),
        r.invalid("binding list that repeats a seq", twice),
        r.invalid("ingress node of another Tick", earlier),
    ]
}

/// The inputs of `node`, except that the outputs of the test Driver declare
/// none.
fn outputs_unfed(node: &DependencyNodeRecordV1) -> Vec<Hash> {
    if is_driver_node(node, 1) {
        Vec::new()
    } else {
        inputs_unchanged(node)
    }
}

/// The inputs of `node`, without `dropped` when the node is the step or the
/// output of `ordinal` of the test Driver.
fn inputs_without(node: &DependencyNodeRecordV1, ordinal: u32, dropped: Hash) -> Vec<Hash> {
    let kept = node.input_digests().iter().copied();
    let owned = is_driver_node(node, ordinal);
    kept.filter(|digest| !owned || *digest != dropped).collect()
}

/// Whether the edge is not one of the Driver's outputs.
fn no_output_edge(edge: &DependencyEdgeRecordV1) -> bool {
    !consumes_as(edge, 1)
}

/// R3.7.2 (vii) and (viii), the edges: sources that resolve, outputs that
/// input their step, steps that input the snapshot.
fn edge_cases(r: &Refusals<'_>) -> Vec<RefusalCase> {
    let valid = &r.valid;
    let record = valid.record();
    let origin = RecordedNodeOriginV1::Committed;
    let snapshot = digest_of_host(record, "host.observation");
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
    let unresolved = r.shaped(hash(61), r.real(), vec![nowhere]);
    let omitted_record = rebuilt(record, origin, inputs_unchanged, no_output_edge);
    let unfed_record = rebuilt(record, origin, outputs_unfed, no_output_edge);
    let blind_inputs = |node: &DependencyNodeRecordV1| inputs_without(node, 0, snapshot);
    let blind_edges =
        |edge: &DependencyEdgeRecordV1| !(consumes_as(edge, 0) && edge.source_digest() == snapshot);
    let blind_record = rebuilt(record, origin, blind_inputs, blind_edges);
    let omitted = with_record(valid, omitted_record);
    let unfed = with_record(valid, unfed_record);
    let blind = with_record(valid, blind_record);
    vec![
        r.invalid("edge source that resolves nowhere", unresolved),
        r.invalid("omitted required edge", omitted),
        r.invalid("output without its step node", unfed),
        r.invalid("step node without the snapshot node", blind),
    ]
}

/// R3.7.2 (v) and (viii), the nodes: a position key Tick 1 recorded, and the
/// class and owner of a host node.
fn node_cases(r: &Refusals<'_>) -> Vec<RefusalCase> {
    let valid = &r.valid;
    let record = valid.record();
    // The record stays shape-valid: only the repeated node can refuse it.
    let repeated = with_node(valid, r.stored[0].clone());
    let exogenous = RecordedDependencyClassV1::ExogenousFrozen;
    let reclassed = record
        .nodes()
        .iter()
        .map(|node| {
            let host = node.coordinate().owner_id() == "host.observation";
            let class = if host { exogenous } else { node.class() };
            node_like(node, class, inputs_unchanged(node))
        })
        .collect();
    let misclassed = rebound(valid, record_over(record, reclassed, None), None);
    let template = node_of(record, "host.observation");
    let stranger = extra_node(template, "host.mystery", hash(0xab));
    let unknown = with_node(valid, stranger);
    vec![
        r.invalid("node repeated from an earlier Tick", repeated),
        r.invalid("host node of the wrong class", misclassed),
        r.invalid("host node of an unknown owner", unknown),
    ]
}

/// R3.7.2 (iii) and (viii), a human record: one node per draft and no more,
/// each bound to a draft it was derived from.
fn human_cases(r: &Refusals<'_>) -> Vec<RefusalCase> {
    let human = Attempt {
        ingress: PipelineIngressV1::HumanProposedAction,
        drafts: r.second.drafts[..1].to_vec(),
        ..r.second.clone()
    };
    let shape = FactualTickShapeV1::Human(human.drafts.clone());
    let own = declared(&human, hash(1), &shape);
    let template = &own.record().nodes()[0];
    let owner = template.coordinate().owner_id();
    let extra = with_node(&own, extra_node(template, owner, hash(0xac)));
    let other = FactualTickShapeV1::Human(drafts(&[b"other"]));
    let rewritten = declared(&human, hash(1), &other);
    vec![
        invalid_for("human record with an extra node", human.clone(), extra),
        invalid_for("human output of another digest", human, rewritten),
    ]
}

#[test]
fn a_commit_records_nodes_edges_range_and_bindings_with_its_events() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        let fixture = prepare(store.as_mut());
        let timeline = fixture.timeline;
        assert_eq!(head_of(store.as_ref(), timeline), head(0, 0), "{name}");

        // A human action: one human-ingress node per Event and no edge.
        let first = attempt(&fixture, 1, 0);
        committed(ok(admit(store.as_mut(), &first)));
        let nodes = recorded_nodes(store.as_ref(), timeline);
        assert_eq!(nodes.len(), 3, "{name}");
        let human_edges = recorded_edges(store.as_ref(), timeline);
        assert!(human_edges.is_empty(), "{name}");
        assert_eq!(head_of(store.as_ref(), timeline), head(1, 3), "{name}");
        let seqs = [1, 2, 3, 4].map(Seq::from_u64);
        let bound = ok(store.nodes_for_committed_events(timeline, &seqs));
        let expected = [0_usize, 1, 2].map(|at| Some(nodes[at].clone()));
        assert_eq!(bound[..3], expected, "{name}");
        assert_eq!(bound[3], None, "{name}");

        // A scheduled Tick: a snapshot, a step and three outputs, joined by
        // four edges, and a fold node over Events 1 to 3 that the snapshot
        // node inputs: four edges more, all carrying the fence's grant.
        let second = scheduled_after(&first, 2, 3);
        let declaration = folded_declaration(store.as_ref(), &second, Vec::new());
        commit_declared(store.as_mut(), &second, declaration);
        let counts = RecordedSetCountsV1 {
            nodes: 9,
            edges: 8,
            inputs: 8,
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
    for (name, mut store) in stores(&clock) {
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
        // records the ingress node of Event 4 once, beside its outputs, and a
        // fold node over Events 1 to 4 that shares it.
        let ingress = vec![ingress_event(&events[3])];
        let valid = folded_declaration(store.as_ref(), &second, ingress);
        let outcome = ok(store.admit_pipeline_batch(&basis_declaring(&second, valid)));
        let receipt = committed(outcome);
        assert_eq!(receipt_positions(&receipt), [5, 6, 7], "{name}");
        assert_eq!(head_of(store.as_ref(), timeline), head(2, 7), "{name}");
        let counts = RecordedSetCountsV1 {
            nodes: 10,
            edges: 10,
            inputs: 10,
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
    for (name, mut store) in stores(&clock) {
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
    for (name, mut store) in stores(&clock) {
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

        // Once the receipt expires its key is released (see
        // `basis_free_lookup_recovers_only_the_exact_retained_attempt`), and
        // the same basis is judged as a new admission against the head that has
        // since moved: it is never recovered as a duplicate and records no
        // second row.
    }
}

#[test]
fn a_fork_binds_only_the_events_of_the_ticks_below_its_cut() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
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
        let declaration = folded_declaration(store.as_ref(), &child, rebound);
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
        let case = "bound below the cut";
        assert_refused(name, case, store.as_mut(), &later, again, &invalid);
        let plain = folded_declaration(store.as_ref(), &later, Vec::new());
        committed(ok(
            store.admit_pipeline_batch(&basis_declaring(&later, plain))
        ));
        assert_eq!(head_of(store.as_ref(), boundary), head(2, 6), "{name}");
    }
}

// ── Fold-head rows (ADR-064 Revision 4, Redmine #751) ──────────────────────
//
// A scheduled Tick writes one fold-head row with its Events; a human Tick
// writes none, and a retry nothing new. The store checks the shape of the fold
// part (the amended check (viii)) and recomputes its content (checks (ix), (x)).

/// The fold source a builder reads for a scheduled Tick observed through
/// `observed`: the store's fold cursor and the window after it.
fn fold_source(store: &dyn Harness, timeline: TimelineId, observed: u64) -> FactualFoldSourceV1 {
    let cursor = ok(store.fold_cursor(timeline));
    let after = cursor
        .as_ref()
        .map_or(Seq::ZERO, |found| found.scanned_through);
    let observed_through = Seq::from_u64(observed);
    let window = ok(store.fold_window(timeline, after, observed_through));
    FactualFoldSourceV1 {
        observed_through,
        cursor,
        window,
    }
}

/// The declaration of a scheduled `attempt` whose one Driver outputs its
/// drafts, with the fold part of `source`.
fn fold_declared(attempt: &Attempt, source: FactualFoldSourceV1) -> FactualTickDependenciesV1 {
    fold_declared_as(attempt, source, OutputAuthorityV1::Authoritative)
}

/// [`fold_declared`], every output of the given `authority`.
fn fold_declared_as(
    attempt: &Attempt,
    source: FactualFoldSourceV1,
    authority: OutputAuthorityV1,
) -> FactualTickDependenciesV1 {
    let outputs = attempt
        .drafts
        .iter()
        .map(|draft| FactualOutputV1 {
            draft: draft.clone(),
            authority,
            direct_inputs: Vec::new(),
        })
        .collect();
    let driver = FactualDriverStepV1 {
        owner: FactualOwnerIdV1::new("plugin:test".to_owned()),
        policy_identity: hash(8),
        step_inputs: Vec::new(),
        outputs,
    };
    let shape = FactualTickShapeV1::Scheduled(FactualScheduledTickV1 {
        snapshot_digest: hash(61),
        prefix_contents: Vec::new(),
        history_contents: Vec::new(),
        ingress_events: Vec::new(),
        drivers: vec![driver],
        fold: Some(Box::new(source)),
    });
    declared(attempt, hash(1), &shape)
}

/// Commit `declaration` for `attempt`, and return the declaration.
fn commit_declared(
    store: &mut dyn Harness,
    attempt: &Attempt,
    declaration: FactualTickDependenciesV1,
) -> FactualTickDependenciesV1 {
    let basis = basis_declaring(attempt, declaration.clone());
    committed(ok(store.admit_pipeline_batch(&basis)));
    declaration
}

/// The artifact digest of the last fold checkpoint node of a declaration.
fn last_fold_digest(declaration: &FactualTickDependenciesV1) -> Hash {
    let checkpoints = &declaration.fold().checkpoints;
    let last = checkpoints.last().copied();
    let index = last.unwrap_or_else(|| std::panic::resume_unwind(Box::new("no fold node")));
    digest_at(declaration.record(), index)
}

/// The Timeline's fold cursor as its scanned-through `seq` and head digest,
/// 32 zero bytes for no head.
fn cursor_of(store: &dyn Harness, timeline: TimelineId) -> Option<(u64, Hash)> {
    let cursor = ok(store.fold_cursor(timeline));
    cursor.map(|found| {
        let head = found
            .head
            .map_or_else(Hash::zero, |node| node.coordinate().artifact_digest());
        (found.scanned_through.as_u64(), head)
    })
}

/// The declaration with another fold binding, the record unchanged.
fn with_fold(
    valid: &FactualTickDependenciesV1,
    checkpoints: Vec<u32>,
    history: Vec<u32>,
) -> FactualTickDependenciesV1 {
    FactualTickDependenciesV1::new(
        valid.tick(),
        valid.record().clone(),
        valid.output_bindings().to_vec(),
        valid.event_nodes().to_vec(),
        FactualFoldBindingV1 {
            checkpoints,
            history,
        },
    )
}

/// ADR-064 R4.3: every scheduled Tick writes one fold-head row through its
/// `observed_through`, naming its last fold node, or the head it keeps when
/// it records none. A human Tick writes none, and a retry nothing new.
#[test]
fn every_scheduled_tick_writes_one_fold_head_row_and_a_human_tick_none() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        let fixture = prepare(store.as_mut());
        let timeline = fixture.timeline;
        let first = attempt(&fixture, 1, 0);
        committed(ok(admit(store.as_mut(), &first)));
        assert_eq!(cursor_of(store.as_ref(), timeline), None, "{name}");

        // Tick 2 folds the human Events 1 to 3 through their nodes.
        let second = Attempt {
            drafts: drafts(&[b"x"]),
            ..scheduled_after(&first, 2, 3)
        };
        let source = fold_source(store.as_ref(), timeline, 3);
        let declaration = fold_declared(&second, source);
        let two = commit_declared(store.as_mut(), &second, declaration);
        let head_two = last_fold_digest(&two);
        let row_two = Some((3, head_two));
        assert_eq!(cursor_of(store.as_ref(), timeline), row_two, "{name}");

        // The retry returns the retained outcome and writes nothing new.
        let retried = ok(store.admit_pipeline_batch(&basis_declaring(&second, two)));
        let recovered = matches!(retried, PipelineOutcomeV1::RecoveredDuplicate(_));
        assert!(recovered, "{name}");
        assert_eq!(cursor_of(store.as_ref(), timeline), row_two, "{name}");

        // Tick 3 chains its fold node to the head and folds Tick 2's output.
        let third = scheduled_after(&second, 3, 4);
        let source = fold_source(store.as_ref(), timeline, 4);
        let declaration = fold_declared(&third, source);
        let three = commit_declared(store.as_mut(), &third, declaration);
        let at = ok(usize::try_from(three.fold().checkpoints[0]));
        let fold_node = &three.record().nodes()[at];
        assert!(fold_node.input_digests().contains(&head_two), "{name}");
        let head_three = last_fold_digest(&three);
        let row_three = Some((4, head_three));
        assert_eq!(cursor_of(store.as_ref(), timeline), row_three, "{name}");

        // Tick 4 observes nothing new: no fold node, the snapshot node inputs
        // the head, and the row keeps the head.
        let fourth = Attempt {
            observed_through: 4,
            ..scheduled_after(&third, 4, 5)
        };
        let source = fold_source(store.as_ref(), timeline, 4);
        let declaration = fold_declared(&fourth, source);
        let four = commit_declared(store.as_mut(), &fourth, declaration);
        assert!(four.fold().checkpoints.is_empty(), "{name}");
        let snapshot = node_of(four.record(), "host.observation");
        assert_eq!(snapshot.input_digests(), [head_three], "{name}");
        assert_eq!(cursor_of(store.as_ref(), timeline), row_three, "{name}");
    }
}

/// ADR-064 R4.3, check (viii) as amended: the fold binding names exactly the
/// fold nodes of the record, in chain order and at most five, the fold-history
/// node at most once, and the snapshot node inputs the last fold node. Each
/// break is refused before anything is appended; the valid declaration then
/// commits. A forged truncation is refused too: the store reads its own
/// window, which holds every Event of the range.
#[test]
fn the_store_refuses_a_fold_part_of_the_wrong_shape() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        let fixture = prepare(store.as_mut());
        let timeline = fixture.timeline;
        let first = attempt(&fixture, 1, 0);
        committed(ok(admit(store.as_mut(), &first)));
        let second = Attempt {
            drafts: drafts(&[b"x"]),
            ..scheduled_after(&first, 2, 3)
        };
        let source = fold_source(store.as_ref(), timeline, 3);
        let mut forged = source.clone();
        forged.window.truncated = true;
        let truncated = fold_declared(&second, forged);
        assert_eq!(truncated.fold().history.len(), 1, "{name}");
        let valid = fold_declared(&second, source);
        let checkpoint = valid.fold().checkpoints[0];
        let output = valid.output_bindings()[0].node_index;
        let record = valid.record();
        let snapshot = digest_of_host(record, "host.observation");
        let last = last_fold_digest(&valid);
        let unfed = |node: &DependencyNodeRecordV1| {
            if node.coordinate().artifact_digest() == snapshot {
                Vec::new()
            } else {
                inputs_unchanged(node)
            }
        };
        let origin = RecordedNodeOriginV1::Committed;
        let blind = rebuilt(record, origin, unfed, |edge| edge.source_digest() != last);
        let history = valid.fold().history.clone();
        let foreign = with_fold(&valid, vec![output], history.clone());
        let left_out = with_fold(&valid, Vec::new(), history.clone());
        let six = with_fold(&valid, vec![checkpoint; 6], history);
        let misnamed = with_fold(&valid, vec![checkpoint], vec![checkpoint]);
        let unfed_snapshot = with_record(&valid, blind);
        let cases = [
            ("binding of a node that is no fold node", foreign),
            ("fold node the binding leaves out", left_out),
            ("six fold nodes", six),
            ("history binding of a fold node", misnamed),
            ("snapshot node without the fold node", unfed_snapshot),
            ("fold-history node over a window that is whole", truncated),
        ];
        let invalid = PipelineOutcomeV1::InvalidDependencyDeclaration;
        for (case, declaration) in cases {
            assert_refused(name, case, store.as_mut(), &second, declaration, &invalid);
        }
        assert_eq!(cursor_of(store.as_ref(), timeline), None, "{name}");

        commit_declared(store.as_mut(), &second, valid);
        let row = Some((3, last));
        assert_eq!(cursor_of(store.as_ref(), timeline), row, "{name}");
    }
}

/// [`fold_declared`], with one verified-prefix node and one history node.
fn coarse_declared(attempt: &Attempt, source: FactualFoldSourceV1) -> FactualTickDependenciesV1 {
    let outputs = attempt
        .drafts
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
    let shape = FactualTickShapeV1::Scheduled(FactualScheduledTickV1 {
        snapshot_digest: hash(61),
        prefix_contents: vec![hash(62)],
        history_contents: vec![hash(63)],
        ingress_events: Vec::new(),
        drivers: vec![driver],
        fold: Some(Box::new(source)),
    });
    declared(attempt, hash(1), &shape)
}

/// `valid` with the inputs and edges of the nodes of `owner` replaced by
/// `inputs`: the node declares exactly them, and an edge for each.
fn with_inputs_of(
    valid: &FactualTickDependenciesV1,
    owner: &'static str,
    inputs: &[Hash],
) -> FactualTickDependenciesV1 {
    let record = valid.record();
    let origin = RecordedNodeOriginV1::Committed;
    let replaced = |node: &DependencyNodeRecordV1| {
        if node.coordinate().owner_id() == owner {
            inputs.to_vec()
        } else {
            inputs_unchanged(node)
        }
    };
    let kept = |edge: &DependencyEdgeRecordV1| edge.consumer().owner_id() != owner;
    let stripped = rebuilt(record, origin, replaced, kept);
    with_record(valid, stripped)
}

/// ADR-064 R6, 4.3, check (xi): the verified-prefix and history nodes of a
/// scheduled Tick input exactly what its snapshot node inputs. A node with no
/// input, or with another one, is refused and nothing is recorded.
#[test]
fn the_store_refuses_prefix_and_history_nodes_that_differ_from_the_snapshot_input() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        let fixture = prepare(store.as_mut());
        let timeline = fixture.timeline;
        let first = attempt(&fixture, 1, 0);
        committed(ok(admit(store.as_mut(), &first)));
        let second = Attempt {
            drafts: drafts(&[b"x"]),
            ..scheduled_after(&first, 2, 3)
        };
        let source = fold_source(store.as_ref(), timeline, 3);
        let valid = coarse_declared(&second, source);
        let record = valid.record();
        let last = last_fold_digest(&valid);
        let prefix = digest_of_host(record, "host.prefix");
        assert_eq!(node_of(record, "host.prefix").input_digests(), [last]);
        assert_eq!(
            node_of(record, "host.visible-history").input_digests(),
            [last]
        );

        let others = [prefix];
        let mut twice = [last, prefix];
        twice.sort();
        let cases: [(&str, &'static str, &[Hash]); 5] = [
            ("prefix node without its input", "host.prefix", &[]),
            (
                "history node without its input",
                "host.visible-history",
                &[],
            ),
            (
                "history node inputting another node",
                "host.visible-history",
                &others,
            ),
            ("prefix node inputting two nodes", "host.prefix", &twice),
            (
                "history node inputting two nodes",
                "host.visible-history",
                &twice,
            ),
        ];
        let invalid = PipelineOutcomeV1::InvalidDependencyDeclaration;
        for (case, owner, inputs) in cases {
            let forged = with_inputs_of(&valid, owner, inputs);
            assert_refused(name, case, store.as_mut(), &second, forged, &invalid);
        }
        assert_eq!(cursor_of(store.as_ref(), timeline), None, "{name}");

        commit_declared(store.as_mut(), &second, valid);
        assert_eq!(
            cursor_of(store.as_ref(), timeline),
            Some((3, last)),
            "{name}"
        );
    }
}

/// ADR-064 R4.3: the fold-head row commits atomically with the Tick. A failing
/// insert of the row rolls the whole scheduled Tick back; the retry commits
/// it with exactly one row.
#[test]
fn sqlite_a_failing_fold_head_insert_rolls_back_the_whole_scheduled_tick() {
    let clock = TestClock::at(1_000);
    let directory = ok(tempdir());
    let path = directory.path().join("admission-fold-head-fault.db");
    let (second, declaration) = {
        let mut store = ok(SqliteStore::open_with_clock(
            path.to_str().unwrap_or_default(),
            Box::new(clock.clone()),
        ));
        let fixture = prepare(&mut store);
        let first = attempt(&fixture, 1, 0);
        committed(ok(admit(&mut store, &first)));
        let second = scheduled_after(&first, 2, 3);
        let source = fold_source(&store, fixture.timeline, 3);
        let declaration = fold_declared(&second, source);
        (second, declaration)
    };
    let timeline = second.timeline;
    let basis = basis_declaring(&second, declaration);

    execute(&path, &insert_fault("counterfactual_dependency_fold_heads"));
    let mut faulted = open_file(&path, &clock);
    assert!(faulted.admit_pipeline_batch(&basis).is_err());
    assert_eq!(event_count(&faulted, timeline), 3);
    assert_eq!(head_of(&faulted, timeline), head(1, 3));
    assert_eq!(cursor_of(&faulted, timeline), None);
    drop(faulted);
    execute(&path, "DROP TRIGGER injected_fault;");

    let mut store = open_file(&path, &clock);
    committed(ok(store.admit_pipeline_batch(&basis)));
    assert_eq!(head_of(&store, timeline), head(2, 6));
    let connection = ok(rusqlite::Connection::open(&path));
    let rows = connection.query_row(
        "SELECT COUNT(*) FROM counterfactual_dependency_fold_heads",
        [],
        |row| row.get::<_, i64>(0),
    );
    assert_eq!(ok(rows), 1);
}

// ── Fold recomputation (ADR-064 Revision 4, checks (ix) and (x), #752) ─────
//
// The store derives the fold part of a scheduled Tick from the Events it
// holds, through its own fold cursor and window, and refuses any other.

/// The declaration of a scheduled `attempt` whose one Driver outputs its
/// drafts and consumes the ingress nodes of `ingress_events`, with the fold
/// part of the store's own fold cursor and window.
fn folded_declaration(
    store: &dyn Harness,
    attempt: &Attempt,
    ingress_events: Vec<FactualIngressEventV1>,
) -> FactualTickDependenciesV1 {
    let source = fold_source(store, attempt.timeline, attempt.observed_through);
    let mut shape = scheduled_shape_of(&attempt.drafts, hash(61), ingress_events, Vec::new());
    if let FactualTickShapeV1::Scheduled(tick) = &mut shape {
        tick.fold = Some(Box::new(source));
    }
    declared(attempt, hash(1), &shape)
}

fn sorted(mut digests: Vec<Hash>) -> Vec<Hash> {
    digests.sort();
    digests
}

/// The sorted inputs of the fold checkpoint node of ordinal `at`.
fn fold_inputs(declaration: &FactualTickDependenciesV1, at: usize) -> Vec<Hash> {
    let index = declaration.fold().checkpoints[at];
    let node = &declaration.record().nodes()[ok(usize::try_from(index))];
    sorted(node.input_digests().to_vec())
}

/// The artifact digest of the node the committed Event at `seq` is bound to.
fn node_digest(store: &dyn Harness, timeline: TimelineId, seq: u64) -> Hash {
    let found = ok(store.nodes_for_committed_events(timeline, &[Seq::from_u64(seq)]));
    let node = found.into_iter().flatten().next();
    let held = node.unwrap_or_else(|| std::panic::resume_unwind(Box::new("no node")));
    held.coordinate().artifact_digest()
}

/// The `seq`s a declaration binds to ingress nodes.
fn bound_seqs(declaration: &FactualTickDependenciesV1) -> Vec<u64> {
    let bindings = declaration.event_nodes();
    let seqs = bindings.iter().map(|binding| binding.seq.as_u64());
    seqs.collect()
}

/// Append a consent grant at `first_seq` and its revocation after it through
/// the Gateway's consent seam: the generic append refuses consent drafts, and
/// the seam requires each Event's entity to be its subject and its payload
/// well formed.
fn append_consent(store: &mut dyn Harness, timeline: TimelineId, first_seq: u64) {
    let authority = ConsentAuthority::new();
    ok(store.bind_consent_authority(authority.append_permit()));
    let subject = entity(50);
    let grant = ConsentGrantedV1 {
        subject_id: subject,
        grantee_id: entity(51),
        purpose: "fold".to_owned(),
        modalities: MODALITY_LOCATION,
        min_geo_resolution: 1,
        fork_permitted: false,
        export_permitted: false,
        retention_days: 1,
        expiry_secs: 0,
        grant_seq: first_seq,
    };
    let revocation = ConsentRevokedV1 {
        subject_id: subject,
        grantee_id: grant.grantee_id,
        grant_seq: first_seq,
        fence_seq: first_seq + 1,
    };
    let granted = Kind::new(EVENT_TYPE_CONSENT_GRANTED_V1);
    let revoked = Kind::new(EVENT_TYPE_CONSENT_REVOKED_V1);
    let consent = [
        EventDraft::new(subject, granted, ok(grant.encode())),
        EventDraft::new(subject, revoked, ok(revocation.encode())),
    ];
    let permit = authority.append_permit();
    let appended = ok(store.append_consent_bounded(timeline, &consent, permit, 10));
    assert_eq!(appended.as_ref().map(Vec::len), Some(2));
}

/// A Timeline whose Tick 1 is a human action over Events 1 to 3 and whose
/// scheduled Tick 2 folds them and outputs Event 4; then a consent grant (5),
/// its revocation (6) and a plain Event (7). Returns Tick 2's declaration and
/// the attempt of Tick 3, observed through Event 7.
fn consent_timeline(store: &mut dyn Harness) -> (FactualTickDependenciesV1, Attempt) {
    let fixture = prepare(store);
    let timeline = fixture.timeline;
    let first = attempt(&fixture, 1, 0);
    committed(ok(admit(store, &first)));
    let second = Attempt {
        drafts: drafts(&[b"x"]),
        ..scheduled_after(&first, 2, 3)
    };
    let declaration = folded_declaration(store, &second, Vec::new());
    let two = commit_declared(store, &second, declaration);
    append_consent(store, timeline, 5);
    ok(store.append(timeline, &drafts(&[b"raw"])));
    let third = Attempt {
        drafts: drafts(&[b"y"]),
        ..scheduled_after(&second, 3, 7)
    };
    (two, third)
}

/// Conformance test 1 of ADR-064 R4 on one store: three scheduled Ticks.
fn assert_three_folded_ticks(name: &str, store: &mut dyn Harness) {
    let (two, third) = consent_timeline(store);
    let timeline = third.timeline;
    // Tick 2's fold node inputs exactly the nodes of the human Events.
    let reader: &dyn Harness = store;
    let human: Vec<Hash> = (1..=3)
        .map(|seq| node_digest(reader, timeline, seq))
        .collect();
    assert_eq!(fold_inputs(&two, 0), sorted(human), "{name}");
    let head_two = last_fold_digest(&two);

    // Tick 3 chains to Tick 2's fold node and inputs Tick 2's output, the
    // revocation and the plain Event, the last two through new ingress
    // nodes; the consent grant is no fold input.
    let declaration = folded_declaration(store, &third, Vec::new());
    let three = commit_declared(store, &third, declaration);
    assert_eq!(bound_seqs(&three), [6, 7], "{name}");
    let output = node_digest(store, timeline, 4);
    let revoked = node_digest(store, timeline, 6);
    let plain = node_digest(store, timeline, 7);
    let expected = sorted(vec![head_two, output, revoked, plain]);
    assert_eq!(fold_inputs(&three, 0), expected, "{name}");
    let head_three = last_fold_digest(&three);

    // Tick 4 observes nothing new: no fold node, the snapshot node inputs the
    // head, and the fold-head row keeps it.
    let fourth = Attempt {
        observed_through: 7,
        ..scheduled_after(&third, 4, 8)
    };
    let declaration = folded_declaration(store, &fourth, Vec::new());
    let four = commit_declared(store, &fourth, declaration);
    assert!(four.fold().checkpoints.is_empty(), "{name}");
    let snapshot = node_of(four.record(), "host.observation");
    assert_eq!(snapshot.input_digests(), [head_three], "{name}");
    assert_eq!(cursor_of(store, timeline), Some((7, head_three)), "{name}");
}

/// ADR-064 R4 conformance test 1: three scheduled Ticks chain their fold
/// nodes over exactly the fold inputs between them, each recomputed and
/// accepted by the store, real consent Events included; a Tick with no new
/// fold input records none and writes its fold-head row. `SQLite` holds one
/// fold-head row per scheduled Tick.
#[test]
fn three_scheduled_ticks_chain_their_fold_nodes_over_exactly_the_fold_inputs() {
    let clock = TestClock::at(1_000);
    let mut memory = MemoryStore::with_clock(Box::new(clock.clone()));
    assert_three_folded_ticks("memory", &mut memory);
    let directory = ok(tempdir());
    let path = directory.path().join("admission-fold-chain.db");
    let mut sqlite = ok(SqliteStore::open_with_clock(
        path.to_str().unwrap_or_default(),
        Box::new(clock),
    ));
    assert_three_folded_ticks("sqlite", &mut sqlite);
    drop(sqlite);
    let connection = ok(rusqlite::Connection::open(&path));
    let rows = connection.query_row(
        "SELECT COUNT(*) FROM counterfactual_dependency_fold_heads",
        [],
        |row| row.get::<_, i64>(0),
    );
    assert_eq!(ok(rows), 3);
}

/// The fold source with the Event at `seq` left out of the window.
fn without_event(source: &FactualFoldSourceV1, seq: u64) -> FactualFoldSourceV1 {
    let mut forged = source.clone();
    forged
        .window
        .events
        .retain(|event| event.seq.as_u64() != seq);
    forged
}

/// The fold source with the Event at `seq` reported as a plain Event.
fn retyped(source: &FactualFoldSourceV1, seq: u64) -> FactualFoldSourceV1 {
    let mut forged = source.clone();
    let events = forged.window.events.iter_mut();
    for event in events.filter(|event| event.seq.as_u64() == seq) {
        event.event_type = Kind::new("world.action");
    }
    forged
}

/// The fold source with the cursor's head replaced by `head`.
fn with_head(
    source: &FactualFoldSourceV1,
    head: Option<DependencyNodeRecordV1>,
) -> FactualFoldSourceV1 {
    let mut forged = source.clone();
    if let Some(cursor) = forged.cursor.as_mut() {
        cursor.head = head;
    }
    forged
}

/// The declaration with the snapshot node's input and its edge removed.
fn without_snapshot_input(valid: &FactualTickDependenciesV1) -> FactualTickDependenciesV1 {
    let record = valid.record();
    let snapshot = digest_of_host(record, "host.observation");
    let unfed = |node: &DependencyNodeRecordV1| {
        if node.coordinate().artifact_digest() == snapshot {
            Vec::new()
        } else {
            inputs_unchanged(node)
        }
    };
    let origin = RecordedNodeOriginV1::Committed;
    let kept = |edge: &DependencyEdgeRecordV1| edge.consumer().owner_id() != "host.observation";
    let blind = rebuilt(record, origin, unfed, kept);
    with_record(valid, blind)
}

/// Offer each refused case and require that nothing changed, the fold
/// cursor included.
fn assert_all_refused(name: &str, store: &mut dyn Harness, cases: Vec<RefusalCase>) {
    for (case, offered, declaration, expected) in cases {
        let cursor = cursor_of(store, offered.timeline);
        assert_refused(name, case, store, &offered, declaration, &expected);
        assert_eq!(cursor_of(store, offered.timeline), cursor, "{name}: {case}");
    }
}

/// Conformance test 2 of ADR-064 R4 and the refusals of checks (ix) and (x),
/// on one store.
fn assert_fold_refusals(name: &str, store: &mut dyn Harness) {
    let (_, third) = consent_timeline(store);
    let timeline = third.timeline;
    let source = fold_source(store, timeline, 7);
    let stale = Attempt {
        observed_through: 2,
        ..third.clone()
    };
    let valid = fold_declared(&third, source.clone());
    let unfed = without_snapshot_input(&valid);
    let cases = vec![
        invalid_for(
            "fold node that omits a fold input",
            third.clone(),
            fold_declared(&third, without_event(&source, 7)),
        ),
        invalid_for(
            "fold node that inputs a consent grant",
            third.clone(),
            fold_declared(&third, retyped(&source, 5)),
        ),
        invalid_for(
            "fold node without the head edge",
            third.clone(),
            fold_declared(&third, with_head(&source, None)),
        ),
        invalid_for("snapshot node without its fold node", third.clone(), unfed),
        invalid_for(
            "no fold node over unscanned fold inputs",
            third.clone(),
            valid_declaration(&third, Vec::new()),
        ),
        invalid_for(
            "anchor below the fold cursor",
            stale.clone(),
            valid_declaration(&stale, Vec::new()),
        ),
    ];
    assert_all_refused(name, store, cases);
    let three = commit_declared(store, &third, valid);

    // Check (x): with no fold node, the snapshot node inputs exactly the head
    // the fold-head index names, not another prior node, and not nothing.
    let fourth = Attempt {
        observed_through: 7,
        ..scheduled_after(&third, 4, 8)
    };
    let source = fold_source(store, timeline, 7);
    let step = node_of(three.record(), "plugin:test").clone();
    let cases = vec![
        invalid_for(
            "snapshot node that inputs a step node as the head",
            fourth.clone(),
            fold_declared(&fourth, with_head(&source, Some(step))),
        ),
        invalid_for(
            "snapshot node without the head",
            fourth.clone(),
            fold_declared(&fourth, with_head(&source, None)),
        ),
    ];
    assert_all_refused(name, store, cases);
    commit_declared(store, &fourth, fold_declared(&fourth, source));
}

/// ADR-064 R4 conformance test 2 and checks (ix) and (x): a basis that omits
/// a fold input, adds an excluded Event, omits the head edge or the
/// snapshot's fold input, records no fold node over unscanned fold inputs,
/// anchors below the fold cursor, or names another head than the fold-head
/// index's is refused before anything is appended or recorded.
#[test]
fn the_store_refuses_a_fold_part_it_does_not_derive_from_its_events() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        assert_fold_refusals(name, store.as_mut());
    }
}

/// Append `count` Events of type `kind` to the Timeline.
fn append_many(store: &mut dyn Harness, timeline: TimelineId, kind: &str, count: usize) {
    let all: Vec<EventDraft> = (0..count)
        .map(|index| {
            let payload = CanonicalBytes::from_vec(index.to_be_bytes().to_vec());
            EventDraft::new(entity(5), Kind::new(kind), payload)
        })
        .collect();
    for batch in all.chunks(1_024) {
        ok(store.append(timeline, batch));
    }
}

/// Commit the scheduled Tick after `previous`, observed through the head
/// `head`, one draft, with the fold part the store derives, its outputs of
/// `authority`.
fn commit_folded(
    store: &mut dyn Harness,
    previous: &Attempt,
    head: u64,
    authority: OutputAuthorityV1,
) -> (Attempt, FactualTickDependenciesV1) {
    let key = previous.key + 1;
    let next = Attempt {
        drafts: drafts(&[&[key]]),
        ..scheduled_after(previous, key, head)
    };
    let source = fold_source(store, next.timeline, head);
    let declaration = fold_declared_as(&next, source, authority);
    let committed = commit_declared(store, &next, declaration);
    (next, committed)
}

/// The artifact digest of the fold-history node over `(from, through)` at
/// the Tick `tick` of the Timeline.
fn fold_history_digest(timeline: TimelineId, tick: u64, from: u64, through: u64) -> Hash {
    let range = (Seq::from_u64(from), Seq::from_u64(through));
    let content = factual_fold_history_content_digest(range.0, range.1);
    let key = FactualNodeKeyV1 {
        tick,
        scheduler_position: 0,
        owner: "host.fold-history",
        output_ordinal: 0,
        schema_id: FACTUAL_FOLD_HISTORY_SCHEMA_ID_V1,
    };
    factual_artifact_digest(timeline, key, content)
}

/// The artifact digest of the fold-history node of a declaration.
fn history_of(declaration: &FactualTickDependenciesV1) -> Hash {
    digest_at(declaration.record(), declaration.fold().history[0])
}

/// The first scheduled attempt of the fixture's Timeline, as the attempt
/// before it: Tick 0, observed through nothing.
fn before_first(fixture: &Fixture) -> Attempt {
    Attempt {
        ingress: PipelineIngressV1::ScheduledAiDriver,
        tick: 0,
        ..attempt(fixture, 1, 0)
    }
}

/// The store part of conformance test 4 of ADR-064 R4, chunking and
/// collapse, on one store.
fn assert_chunks_and_collapse(name: &str, store: &mut dyn Harness) {
    let fixture = prepare(store);
    let timeline = fixture.timeline;
    let authoritative = OutputAuthorityV1::Authoritative;
    // 4,094 fold inputs take one fold node.
    append_many(store, timeline, "world.action", 4_094);
    let (one, folded) = commit_folded(store, &before_first(&fixture), 4_094, authoritative);
    assert_eq!(folded.fold().checkpoints.len(), 1, "{name}");
    // Tick 1's output and 4,094 more: 4,095 take two.
    append_many(store, timeline, "world.action", 4_094);
    let (two, folded) = commit_folded(store, &one, 8_189, authoritative);
    assert_eq!(folded.fold().checkpoints.len(), 2, "{name}");
    assert!(folded.fold().history.is_empty(), "{name}");
    // 16,384 take five, with no fold-history node.
    append_many(store, timeline, "world.action", 16_383);
    let (three, folded) = commit_folded(store, &two, 24_573, authoritative);
    assert_eq!(folded.fold().checkpoints.len(), 5, "{name}");
    assert!(folded.fold().history.is_empty(), "{name}");
    // 16,385 collapse exactly the oldest, Tick 3's output at 24,574.
    append_many(store, timeline, "world.action", 16_384);
    let fourth = Attempt {
        drafts: drafts(&[b"d"]),
        ..scheduled_after(&three, 5, 40_958)
    };
    let source = fold_source(store, timeline, 40_958);
    let valid = fold_declared(&fourth, source);
    let expected = fold_history_digest(timeline, 4, 24_574, 24_574);
    assert_eq!(history_of(&valid), expected, "{name}");
    assert_eq!(valid.fold().checkpoints.len(), 5, "{name}");
    let mut six = valid.fold().checkpoints.clone();
    six.push(six[4]);
    let history = valid.fold().history.clone();
    let twice = vec![history[0], history[0]];
    let checkpoints = valid.fold().checkpoints.clone();
    let cases = vec![
        invalid_for(
            "six checkpoints",
            fourth.clone(),
            with_fold(&valid, six, history),
        ),
        invalid_for(
            "two history entries",
            fourth.clone(),
            with_fold(&valid, checkpoints, twice),
        ),
    ];
    assert_all_refused(name, store, cases);
    commit_declared(store, &fourth, valid);
}

/// ADR-064 R4 conformance test 4, store part: the store accepts the fold
/// part of 4,094 fold inputs in one node, 4,095 in two, 16,384 in five
/// without a fold-history node, and of 16,385 with a fold-history node over
/// exactly the oldest, and refuses six checkpoints or two history entries.
#[test]
fn the_store_recomputes_the_chunks_and_the_collapse_of_large_windows() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        assert_chunks_and_collapse(name, store.as_mut());
    }
}

/// The store part of conformance test 4 of ADR-064 R4, a truncated window,
/// on one store.
fn assert_truncated_window(name: &str, store: &mut dyn Harness) {
    let fixture = prepare(store);
    let timeline = fixture.timeline;
    // 65,537 Events without a fold input: the oldest is left out of the
    // window and collapsed with the rest of the range into the fold-history
    // node, and one fold node with an empty chunk stands behind it.
    append_many(store, timeline, HOST_CONSENT_CLOSED_EVENT_TYPE, 65_537);
    let first = before_first(&fixture);
    let authoritative = OutputAuthorityV1::Authoritative;
    let (_, folded) = commit_folded(store, &first, 65_537, authoritative);
    let history = fold_history_digest(timeline, 1, 1, 65_537);
    assert_eq!(history_of(&folded), history, "{name}");
    assert_eq!(fold_inputs(&folded, 0), [history], "{name}");
}

/// ADR-064 R4 conformance test 4, store part: a window of 65,537 Events
/// without a fold input records a fold-history node over the whole range and
/// one fold node with an empty chunk. (A whole window of 65,536 records no
/// fold node; the assembly tests of `pos_core` cover that vector.)
#[test]
fn the_store_recomputes_the_collapse_of_a_truncated_window() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        assert_truncated_window(name, store.as_mut());
    }
}

/// The contents of `count` verified-prefix nodes.
fn prefix_contents(count: usize) -> Vec<Hash> {
    (0..count)
        .map(|index| {
            let mut bytes = [0_u8; 32];
            bytes[..8].copy_from_slice(&ok(u64::try_from(index)).to_be_bytes());
            Hash::from_bytes(bytes)
        })
        .collect()
}

/// One authoritative output per draft, with no input of its own.
fn authoritative_outputs(drafts: &[EventDraft]) -> Vec<FactualOutputV1> {
    let output = |draft: &EventDraft| FactualOutputV1 {
        draft: draft.clone(),
        authority: OutputAuthorityV1::Authoritative,
        direct_inputs: Vec::new(),
    };
    drafts.iter().map(output).collect()
}

/// Drivers whose step nodes input the snapshot node and verified-prefix
/// nodes, `edges` edges in all; the first also outputs `drafts`.
fn heavy_drivers(drafts: &[EventDraft], edges: usize) -> Vec<FactualDriverStepV1> {
    let per_step = MAX_DEPENDENCY_NODE_INPUTS_V1;
    (0..edges.div_ceil(per_step))
        .map(|index| {
            let inputs = (edges - index * per_step).min(per_step) - 1;
            let prefix = |at: usize| FactualInputV1::PrefixNode(ok(u32::try_from(at)));
            let outputs = if index == 0 {
                authoritative_outputs(drafts)
            } else {
                Vec::new()
            };
            FactualDriverStepV1 {
                owner: FactualOwnerIdV1::new(format!("plugin:heavy-{index}")),
                policy_identity: hash(8),
                step_inputs: (0..inputs).map(prefix).collect(),
                outputs,
            }
        })
        .collect()
}

/// The rest of a heavy scheduled record: its verified-prefix nodes, the
/// edges of its step nodes, and ingress nodes no step or output node inputs.
struct HeavyRest {
    prefix: usize,
    step_edges: usize,
    orphans: Vec<FactualIngressEventV1>,
}

/// The rest whose step nodes add `step_edges` edges over the most
/// verified-prefix nodes one step node can input.
const fn edge_heavy(step_edges: usize) -> HeavyRest {
    HeavyRest {
        prefix: MAX_DEPENDENCY_NODE_INPUTS_V1 - 1,
        step_edges,
        orphans: Vec::new(),
    }
}

/// The declaration of a scheduled `attempt` whose rest is `rest` and one
/// output edge per draft, with the fold part of `source`.
fn heavy_declared(
    attempt: &Attempt,
    rest: HeavyRest,
    source: Option<FactualFoldSourceV1>,
) -> FactualTickDependenciesV1 {
    let shape = FactualTickShapeV1::Scheduled(FactualScheduledTickV1 {
        snapshot_digest: hash(61),
        prefix_contents: prefix_contents(rest.prefix),
        history_contents: Vec::new(),
        ingress_events: rest.orphans,
        drivers: heavy_drivers(&attempt.drafts, rest.step_edges),
        fold: source.map(Box::new),
    });
    declared(attempt, hash(1), &shape)
}

/// The store part of conformance test 4 of ADR-064 R4, the fit and the
/// reserved headroom, on one store.
fn assert_fit_and_reserve(name: &str, store: &mut dyn Harness) {
    let fixture = prepare(store);
    let timeline = fixture.timeline;
    let first = attempt(&fixture, 1, 0);
    committed(ok(admit(store, &first)));
    let (second, _) = commit_folded(store, &first, 3, OutputAuthorityV1::Authoritative);
    // Tick 2's output (4) and 499 plain Events: 500 fold inputs behind the head.
    append_many(store, timeline, "world.action", 499);
    let third = scheduled_after(&second, 3, 503);
    // A rest of 262,142 edges, one over the 262,141 the reserve leaves it.
    let over = edge_heavy(MAX_TICK_DEPENDENCY_EDGES_V1 - 3);
    let crowded = heavy_declared(&third, over, None);
    let case = invalid_for("rest over the reserve", third.clone(), crowded);
    assert_all_refused(name, store, vec![case]);
    // A rest of 262,144 - 103 edges keeps the newest 100 fold inputs. Each of
    // the 4,095 prefix nodes inputs the fold head (ADR-064 R6), so the step
    // nodes carry that many edges fewer.
    let source = fold_source(store, timeline, 503);
    let head = source.head().cloned();
    let rest = edge_heavy(MAX_TICK_DEPENDENCY_EDGES_V1 - 104 - (MAX_DEPENDENCY_NODE_INPUTS_V1 - 1));
    let fitted = heavy_declared(&third, rest, Some(source));
    let total = fitted.record().edges().len();
    assert_eq!(total, MAX_TICK_DEPENDENCY_EDGES_V1, "{name}");
    let history = fold_history_digest(timeline, 3, 4, 403);
    assert_eq!(history_of(&fitted), history, "{name}");
    let kept: Vec<u64> = (404..=503).collect();
    assert_eq!(bound_seqs(&fitted), kept, "{name}");
    let inputs = fold_inputs(&fitted, 0);
    assert_eq!(inputs.len(), 102, "{name}");
    let head_digest = head.map(|node| node.coordinate().artifact_digest());
    let chained = head_digest.is_some_and(|digest| inputs.contains(&digest));
    assert!(chained, "{name}");
    commit_declared(store, &third, fitted);
}

/// ADR-064 R4 conformance test 4, store part, and the reserved headroom: with
/// a head, a whole window of 500 fold inputs and a rest of 262,144 - 103
/// edges, the store derives the same fit as the builder (the newest 100 in
/// one fold node behind a fold-history node) and accepts it; a basis whose
/// rest exceeds 262,141 edges is refused.
#[test]
fn the_store_recomputes_the_fit_and_refuses_a_rest_over_the_reserve() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        assert_fit_and_reserve(name, store.as_mut());
    }
}

/// The node part of the reserved headroom, on one store: a rest of 65,535
/// nodes is refused, and a rest of exactly 65,534 keeps the minimal fold part
/// plus what needs no new node. The rest holds an orphan: an ingress node no
/// step or output node inputs. The builder counts it in the rest, as a
/// forwarded Event, and the store, once it is kept, in the fold part; both
/// derive the same fit.
fn assert_node_reserve(name: &str, store: &mut dyn Harness) {
    let fixture = prepare(store);
    let timeline = fixture.timeline;
    append_many(store, timeline, "world.action", 3);
    let events = ok(store.read(timeline, SeqRange::all()));
    let first = Attempt {
        drafts: drafts(&[b"n"]),
        ..scheduled_after(&before_first(&fixture), 2, 3)
    };
    // Snapshot, prefix nodes, one step node and one output node: 65,535.
    let crowded = HeavyRest {
        prefix: MAX_TICK_DEPENDENCY_NODES_V1 - 4,
        step_edges: 1,
        orphans: Vec::new(),
    };
    // A bare record: the reserve guard refuses it before any fold part is
    // derived (without the guard the bare record would still mismatch).
    let over = heavy_declared(&first, crowded, None);
    let case = invalid_for("rest over the node reserve", first.clone(), over);
    assert_all_refused(name, store, vec![case]);
    // The same with one prefix node fewer and the orphan of Event 3: 65,534.
    // Events 1 and 2 would each need a new node, so only Event 3 is kept,
    // behind a fold-history node over Events 1 and 2.
    let boundary = HeavyRest {
        prefix: MAX_TICK_DEPENDENCY_NODES_V1 - 6,
        step_edges: 1,
        orphans: vec![ingress_event(&events[2])],
    };
    let source = fold_source(store, timeline, 3);
    let fitted = heavy_declared(&first, boundary, Some(source));
    let nodes = fitted.record().nodes().len();
    assert_eq!(nodes, MAX_TICK_DEPENDENCY_NODES_V1, "{name}");
    let history = fold_history_digest(timeline, 1, 1, 2);
    assert_eq!(history_of(&fitted), history, "{name}");
    let orphan = digest_at(fitted.record(), fitted.event_nodes()[0].node_index);
    let expected = sorted(vec![history, orphan]);
    assert_eq!(fold_inputs(&fitted, 0), expected, "{name}");
    commit_declared(store, &first, fitted);
}

/// ADR-064 R4.2 reserved headroom, nodes: the store refuses a basis whose
/// rest exceeds 65,534 nodes and recomputes the fit of one whose rest is
/// exactly 65,534, an orphan ingress node included.
#[test]
fn the_store_refuses_a_rest_over_the_node_reserve_and_fits_one_at_it() {
    let clock = TestClock::at(1_000);
    for (name, mut store) in stores(&clock) {
        assert_node_reserve(name, store.as_mut());
    }
}
