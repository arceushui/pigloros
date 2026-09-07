use pos_core::{
    AppendDedupKey, AppendDedupScope, AppendIdentity, CanonicalBytes, CorrelationId, EntityId,
    Event, EventDraft, EventId, Hash, Kind, PipelineAdmissionBasisDraftV1,
    PipelineAdmissionBasisV1, PipelineAttemptDraftV1, PipelineAttemptIdV1, PipelineAttemptV1,
    PipelineCommitReceiptV1, PipelineContractErrorV1, PipelineDraftBatchV1, PipelineEvidenceRefV1,
    PipelineIngressV1, PipelineObservationAnchorV1, PipelineOutcomeV1, PipelinePreconditionV1,
    PipelineSecurityRevisionsDraftV1, PipelineSecurityRevisionsV1, SchemaVersion, Seq,
    TentativePipelineResultV1, TimelineId, WallTime, MAX_PIPELINE_DRAFTS_PER_BATCH,
    MAX_PIPELINE_DRAFT_BATCH_BYTES, PIPELINE_CONTRACT_VERSION_V1,
};
use ulid::Ulid;

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
    })
}

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

fn timeline(value: u128) -> TimelineId {
    TimelineId::from_ulid(Ulid::from(value))
}

fn entity(value: u128) -> EntityId {
    EntityId::from_ulid(Ulid::from(value))
}

fn event_id(value: u128) -> EventId {
    EventId::from_ulid(Ulid::from(value))
}

fn attempt(ingress: PipelineIngressV1) -> PipelineAttemptV1 {
    ok(PipelineAttemptV1::try_from_draft(PipelineAttemptDraftV1 {
        contract_version: PIPELINE_CONTRACT_VERSION_V1,
        attempt_id: Some(ok(PipelineAttemptIdV1::try_new([1; 16]))),
        ingress: Some(ingress),
        observation: Some(ok(PipelineObservationAnchorV1::try_new(
            timeline(1),
            Seq::from_u64(7),
            hash(2),
        ))),
        idempotency: Some(AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([3; 32]),
            AppendDedupScope::from_keyed_hash([4; 32]),
        )),
    }))
}

fn revisions() -> PipelineSecurityRevisionsV1 {
    ok(PipelineSecurityRevisionsV1::try_from_draft(
        PipelineSecurityRevisionsDraftV1 {
            authority: hash(10),
            consent: hash(11),
            capability: hash(12),
            delegation: hash(13),
            policy: hash(14),
            execution_profile: hash(15),
            erasure: hash(16),
        },
    ))
}

fn draft(payload: &'static [u8]) -> EventDraft {
    let mut draft = EventDraft::new(
        entity(2),
        Kind::new("world.action"),
        CanonicalBytes::from_static(payload),
    );
    draft.causation_id = Some(event_id(30));
    draft.correlation_id = Some(CorrelationId::from_ulid(Ulid::from(31_u128)));
    draft
}

fn basis(
    ingress: PipelineIngressV1,
    tentative_result: TentativePipelineResultV1,
    drafts: Vec<EventDraft>,
) -> PipelineAdmissionBasisV1 {
    ok(PipelineAdmissionBasisV1::try_from_draft(
        PipelineAdmissionBasisDraftV1 {
            contract_version: PIPELINE_CONTRACT_VERSION_V1,
            attempt: Some(attempt(ingress)),
            tentative_result: Some(tentative_result),
            precondition: Some(PipelinePreconditionV1::ExpectedLogicalHead(Seq::from_u64(
                8,
            ))),
            security_revisions: Some(revisions()),
            batch: Some(ok(PipelineDraftBatchV1::try_new(drafts))),
        },
    ))
}

fn committed(source: &EventDraft, id: u128, seq: u64) -> Event {
    Event {
        id: event_id(id),
        entity: source.entity,
        event_type: source.event_type.clone(),
        payload: source.payload.clone(),
        wall_time: WallTime::from_micros(100 + seq),
        seq: Seq::from_u64(seq),
        causation_id: source.causation_id,
        correlation_id: source.correlation_id,
        schema_version: source.schema_version,
        signature: None,
        signature_identity: None,
        payload_hash: hash(90),
    }
}

#[test]
fn human_and_ai_results_share_a_basis_without_erasing_ingress() {
    let human_evidence = ok(PipelineEvidenceRefV1::try_new(hash(20)));
    let human = basis(
        PipelineIngressV1::HumanProposedAction,
        TentativePipelineResultV1::HumanDomainApproval(human_evidence),
        vec![draft(b"human")],
    );
    let ai_evidence = ok(PipelineEvidenceRefV1::try_new(hash(21)));
    let ai = basis(
        PipelineIngressV1::ScheduledAiDriver,
        TentativePipelineResultV1::AiProviderValidation(ai_evidence),
        vec![draft(b"ai")],
    );

    assert_eq!(
        human.attempt().ingress(),
        PipelineIngressV1::HumanProposedAction
    );
    assert_eq!(human.tentative_result().evidence(), human_evidence);
    assert_eq!(human_evidence.digest(), hash(20));
    assert_eq!(
        human.precondition(),
        PipelinePreconditionV1::ExpectedLogicalHead(Seq::from_u64(8))
    );
    assert_eq!(human.security_revisions(), revisions());
    assert_eq!(ai.attempt().ingress(), PipelineIngressV1::ScheduledAiDriver);
    assert_eq!(ai.tentative_result().evidence(), ai_evidence);
    assert_ne!(human.batch().digest(), ai.batch().digest());
}

#[test]
fn attempt_rejects_unknown_version_incomplete_and_zero_idempotency() {
    let mut value = PipelineAttemptDraftV1 {
        contract_version: 2,
        attempt_id: Some(ok(PipelineAttemptIdV1::try_new([1; 16]))),
        ingress: Some(PipelineIngressV1::HumanProposedAction),
        observation: Some(ok(PipelineObservationAnchorV1::try_new(
            timeline(1),
            Seq::ZERO,
            hash(1),
        ))),
        idempotency: Some(AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([2; 32]),
            AppendDedupScope::from_keyed_hash([3; 32]),
        )),
    };
    assert_eq!(
        PipelineAttemptV1::try_from_draft(value),
        Err(PipelineContractErrorV1::UnsupportedVersion)
    );
    value.contract_version = PIPELINE_CONTRACT_VERSION_V1;
    value.observation = None;
    assert_eq!(
        PipelineAttemptV1::try_from_draft(value),
        Err(PipelineContractErrorV1::Incomplete)
    );
    value.observation = Some(ok(PipelineObservationAnchorV1::try_new(
        timeline(1),
        Seq::ZERO,
        hash(1),
    )));
    value.idempotency = Some(AppendIdentity::new(
        AppendDedupKey::from_keyed_hash([0; 32]),
        AppendDedupScope::from_keyed_hash([3; 32]),
    ));
    assert_eq!(
        PipelineAttemptV1::try_from_draft(value),
        Err(PipelineContractErrorV1::FieldOutOfBounds)
    );
}

#[test]
fn anchors_evidence_revisions_and_preconditions_fail_closed() {
    assert_eq!(
        PipelineAttemptIdV1::try_new([0; 16]),
        Err(PipelineContractErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        PipelineObservationAnchorV1::try_new(timeline(0), Seq::ZERO, hash(1)),
        Err(PipelineContractErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        PipelineObservationAnchorV1::try_new(timeline(1), Seq::ZERO, Hash::zero()),
        Err(PipelineContractErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        PipelineEvidenceRefV1::try_new(Hash::zero()),
        Err(PipelineContractErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        PipelinePreconditionV1::try_domain_state_revision(Hash::zero()),
        Err(PipelineContractErrorV1::FieldOutOfBounds)
    );
    let mut value = revisions().as_draft();
    value.erasure = Hash::zero();
    assert_eq!(
        PipelineSecurityRevisionsV1::try_from_draft(value),
        Err(PipelineContractErrorV1::Incomplete)
    );
}

#[test]
fn admission_basis_rejects_incomplete_unknown_and_cross_path_evidence() {
    let human = TentativePipelineResultV1::HumanDomainApproval(ok(PipelineEvidenceRefV1::try_new(
        hash(20),
    )));
    let mut value = PipelineAdmissionBasisDraftV1 {
        contract_version: 2,
        attempt: Some(attempt(PipelineIngressV1::HumanProposedAction)),
        tentative_result: Some(human),
        precondition: Some(ok(PipelinePreconditionV1::try_domain_state_revision(hash(
            21,
        )))),
        security_revisions: Some(revisions()),
        batch: Some(ok(PipelineDraftBatchV1::try_new(vec![draft(b"x")]))),
    };
    assert_eq!(
        PipelineAdmissionBasisV1::try_from_draft(value.clone()),
        Err(PipelineContractErrorV1::UnsupportedVersion)
    );
    value.contract_version = PIPELINE_CONTRACT_VERSION_V1;
    value.precondition = None;
    assert_eq!(
        PipelineAdmissionBasisV1::try_from_draft(value.clone()),
        Err(PipelineContractErrorV1::Incomplete)
    );
    value.precondition = Some(PipelinePreconditionV1::ExpectedLogicalHead(Seq::ZERO));
    value.tentative_result = Some(TentativePipelineResultV1::AiProviderValidation(ok(
        PipelineEvidenceRefV1::try_new(hash(22)),
    )));
    assert_eq!(
        PipelineAdmissionBasisV1::try_from_draft(value),
        Err(PipelineContractErrorV1::IngressMismatch)
    );
}

#[test]
fn draft_batches_are_nonempty_bounded_and_order_sensitive() {
    assert_eq!(
        PipelineDraftBatchV1::try_new(Vec::new()),
        Err(PipelineContractErrorV1::EmptyBatch)
    );
    let mut invalid = draft(b"x");
    invalid.event_type = Kind::new("");
    assert_eq!(
        PipelineDraftBatchV1::try_new(vec![invalid]),
        Err(PipelineContractErrorV1::InvalidDraft)
    );
    let count = vec![draft(b"x"); MAX_PIPELINE_DRAFTS_PER_BATCH + 1];
    assert_eq!(
        PipelineDraftBatchV1::try_new(count),
        Err(PipelineContractErrorV1::BatchCountExceeded)
    );
    let bytes = EventDraft::new(
        entity(2),
        Kind::new("world.action"),
        CanonicalBytes::from_vec(vec![0; MAX_PIPELINE_DRAFT_BATCH_BYTES]),
    );
    assert_eq!(
        PipelineDraftBatchV1::try_new(vec![bytes]),
        Err(PipelineContractErrorV1::BatchBytesExceeded)
    );
    let first = ok(PipelineDraftBatchV1::try_new(vec![
        draft(b"a"),
        draft(b"b"),
    ]));
    let reversed = ok(PipelineDraftBatchV1::try_new(vec![
        draft(b"b"),
        draft(b"a"),
    ]));
    assert_ne!(first.digest(), reversed.digest());
    assert_eq!(first.drafts().len(), 2);
    assert!(first.content_bytes() > 2);
}

#[test]
fn receipt_requires_exact_committed_content_and_contiguous_store_order() {
    let drafts = vec![draft(b"a"), draft(b"b")];
    let basis = basis(
        PipelineIngressV1::HumanProposedAction,
        TentativePipelineResultV1::HumanDomainApproval(ok(PipelineEvidenceRefV1::try_new(hash(
            20,
        )))),
        drafts.clone(),
    );
    let events = vec![committed(&drafts[0], 40, 9), committed(&drafts[1], 41, 10)];
    let receipt = ok(PipelineCommitReceiptV1::try_from_committed_events(
        &basis,
        timeline(1),
        &events,
    ));
    assert_eq!(receipt.attempt_id(), basis.attempt().attempt_id());
    assert_eq!(receipt.timeline_id(), timeline(1));
    assert_eq!(receipt.draft_batch_digest(), basis.batch().digest());
    assert_eq!(receipt.committed_events()[0].event_id(), event_id(40));
    assert_eq!(receipt.committed_events()[1].seq(), Seq::from_u64(10));
    assert_eq!(
        PipelineOutcomeV1::Committed(receipt.clone()),
        PipelineOutcomeV1::Committed(receipt.clone())
    );
    assert_ne!(
        PipelineOutcomeV1::Committed(receipt.clone()),
        PipelineOutcomeV1::RecoveredDuplicate(receipt)
    );

    let mut changed = events.clone();
    changed[1].payload = CanonicalBytes::from_static(b"changed");
    assert_eq!(
        PipelineCommitReceiptV1::try_from_committed_events(&basis, timeline(1), &changed),
        Err(PipelineContractErrorV1::CommittedBatchMismatch)
    );
    let mut non_contiguous = events.clone();
    non_contiguous[1].seq = Seq::from_u64(11);
    assert_eq!(
        PipelineCommitReceiptV1::try_from_committed_events(&basis, timeline(1), &non_contiguous),
        Err(PipelineContractErrorV1::NonContiguousCommit)
    );
    let mut duplicate_id = events;
    duplicate_id[1].id = duplicate_id[0].id;
    assert_eq!(
        PipelineCommitReceiptV1::try_from_committed_events(&basis, timeline(1), &duplicate_id),
        Err(PipelineContractErrorV1::InvalidCommittedIdentity)
    );
}

#[test]
fn outcome_set_distinguishes_every_fail_closed_state() {
    let outcomes = [
        PipelineOutcomeV1::Rejected,
        PipelineOutcomeV1::InvalidObservation,
        PipelineOutcomeV1::AuthorityRevoked,
        PipelineOutcomeV1::AuthorityExpired,
        PipelineOutcomeV1::PolicyIndeterminate,
        PipelineOutcomeV1::ResourceExhausted,
        PipelineOutcomeV1::InvalidPluginResult,
        PipelineOutcomeV1::InvalidProviderResult,
        PipelineOutcomeV1::DomainConflict,
        PipelineOutcomeV1::AdmissionConflict,
    ];
    for (index, left) in outcomes.iter().enumerate() {
        for (other_index, right) in outcomes.iter().enumerate() {
            assert_eq!(left == right, index == other_index);
        }
    }
}

#[test]
fn getter_contracts_return_exact_bound_values() {
    let attempt_id = ok(PipelineAttemptIdV1::try_new([8; 16]));
    assert_eq!(attempt_id.as_bytes(), [8; 16]);
    let anchor = ok(PipelineObservationAnchorV1::try_new(
        timeline(8),
        Seq::from_u64(9),
        hash(10),
    ));
    assert_eq!(anchor.timeline_id(), timeline(8));
    assert_eq!(anchor.observed_through(), Seq::from_u64(9));
    assert_eq!(anchor.snapshot_digest(), hash(10));
    assert_eq!(
        TentativePipelineResultV1::AiProviderValidation(ok(PipelineEvidenceRefV1::try_new(hash(
            11
        )),))
        .ingress(),
        PipelineIngressV1::ScheduledAiDriver
    );
    assert_eq!(
        attempt(PipelineIngressV1::HumanProposedAction)
            .observation()
            .timeline_id(),
        timeline(1)
    );
    assert_eq!(
        attempt(PipelineIngressV1::HumanProposedAction)
            .idempotency()
            .scope
            .as_bytes(),
        [4; 32]
    );
    assert_eq!(revisions().as_draft().policy, hash(14));
}

#[test]
fn receipt_rejects_timeline_count_identity_and_zero_order() {
    let source = draft(b"a");
    let single_event_basis = basis(
        PipelineIngressV1::ScheduledAiDriver,
        TentativePipelineResultV1::AiProviderValidation(ok(PipelineEvidenceRefV1::try_new(hash(
            20,
        )))),
        vec![source.clone()],
    );
    let committed_event = committed(&source, 39, 8);
    assert_eq!(
        PipelineCommitReceiptV1::try_from_committed_events(
            &single_event_basis,
            timeline(2),
            &[committed_event],
        ),
        Err(PipelineContractErrorV1::CommittedTimelineMismatch)
    );
    assert_eq!(
        PipelineCommitReceiptV1::try_from_committed_events(&single_event_basis, timeline(1), &[]),
        Err(PipelineContractErrorV1::CommittedBatchMismatch)
    );
    let nil = committed(&source, 0, 8);
    assert_eq!(
        PipelineCommitReceiptV1::try_from_committed_events(
            &single_event_basis,
            timeline(1),
            &[nil],
        ),
        Err(PipelineContractErrorV1::InvalidCommittedIdentity)
    );

    let zero_seq = committed(&source, 40, 0);
    assert_eq!(
        PipelineCommitReceiptV1::try_from_committed_events(
            &single_event_basis,
            timeline(1),
            &[zero_seq],
        ),
        Err(PipelineContractErrorV1::NonContiguousCommit)
    );

    let second_source = draft(b"b");
    let two_event_basis = basis(
        PipelineIngressV1::ScheduledAiDriver,
        TentativePipelineResultV1::AiProviderValidation(ok(PipelineEvidenceRefV1::try_new(hash(
            21,
        )))),
        vec![source.clone(), second_source.clone()],
    );
    let leading_zero = [committed(&source, 41, 0), committed(&second_source, 42, 1)];
    assert_eq!(
        PipelineCommitReceiptV1::try_from_committed_events(
            &two_event_basis,
            timeline(1),
            &leading_zero,
        ),
        Err(PipelineContractErrorV1::NonContiguousCommit)
    );
}

#[test]
fn draft_digest_binds_optional_ids_schema_and_explicit_wall_time() {
    let base = draft(b"a");
    let original = ok(PipelineDraftBatchV1::try_new(vec![base.clone()]));
    let mut without_cause = base.clone();
    without_cause.causation_id = None;
    let without_cause = ok(PipelineDraftBatchV1::try_new(vec![without_cause]));
    assert_ne!(original.digest(), without_cause.digest());
    let mut without_correlation = base.clone();
    without_correlation.correlation_id = None;
    let without_correlation = ok(PipelineDraftBatchV1::try_new(vec![without_correlation]));
    assert_ne!(original.digest(), without_correlation.digest());

    let mut with_wall_time = base;
    with_wall_time.wall_time = Some(WallTime::from_micros(999));
    let with_wall_time_batch = ok(PipelineDraftBatchV1::try_new(vec![with_wall_time.clone()]));
    assert_ne!(original.digest(), with_wall_time_batch.digest());
    assert_eq!(
        with_wall_time_batch.content_bytes(),
        original.content_bytes() + 8
    );

    let with_wall_time_basis = basis(
        PipelineIngressV1::HumanProposedAction,
        TentativePipelineResultV1::HumanDomainApproval(ok(PipelineEvidenceRefV1::try_new(hash(
            22,
        )))),
        vec![with_wall_time.clone()],
    );
    let matching = Event {
        wall_time: WallTime::from_micros(999),
        ..committed(&with_wall_time, 50, 9)
    };
    assert!(PipelineCommitReceiptV1::try_from_committed_events(
        &with_wall_time_basis,
        timeline(1),
        &[matching],
    )
    .is_ok());
    let mismatched = committed(&with_wall_time, 51, 9);
    assert_eq!(
        PipelineCommitReceiptV1::try_from_committed_events(
            &with_wall_time_basis,
            timeline(1),
            &[mismatched],
        ),
        Err(PipelineContractErrorV1::CommittedBatchMismatch)
    );
    assert_eq!(SchemaVersion::V1.as_u32(), 1);
}
