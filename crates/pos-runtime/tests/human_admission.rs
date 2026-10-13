//! ADR-021 human `ProposedAction` admission through the shared host seam (#319).
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use pos_core::{
    ActionApprover, ActionRejected, AppendDedupKey, AppendDedupScope, AppendIdentity,
    CanonicalBytes, Capability, CoreError, EntityId, ErasureContainmentGateV1, EventDraft,
    FactualDependencyErrorV1, Hash, Kind, PipelineAdmissionBasisV1, PipelineAdmissionPortV1,
    PipelineAttemptIdV1, PipelineContractErrorV1, PipelineEvidenceRefV1,
    PipelineObservationAnchorV1, PipelineOutcomeV1, PipelineReceiptLookupV1,
    PipelineSecurityRevisionsV1, Plugin, PluginId, ProposedAction, RecordedDependencyClassV1,
    RecordedSetCountsV1, Seq, SeqRange, TimelineId,
};
use pos_runtime::{
    ActionSubmissionError, HumanActionAdmissionErrorV1, HumanActionAdmissionV1,
    HumanActionReceiptV1, LocalScheduledAdmissionHostV1, PluginRegistry, ScheduledAdmissionStoreV1,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore};
use ulid::Ulid;

const ACTION: &str = "world.action";
const CAPABILITY: &str = "world.action.submit";

#[cfg_attr(coverage_nightly, coverage(off))]
fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
    })
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn err<T: std::fmt::Debug, E>(result: Result<T, E>) -> E {
    match result {
        Ok(value) => std::panic::resume_unwind(Box::new(format!("unexpected success: {value:?}"))),
        Err(error) => error,
    }
}

struct ActionPlugin(PluginId);

impl Plugin for ActionPlugin {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn id(&self) -> PluginId {
        self.0
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn name(&self) -> &'static str {
        "human-action-policy"
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(ACTION)],
            ..Capability::default()
        }
    }
}

/// The owning domain policy; it counts every invocation.
struct CountingApprover(Arc<AtomicUsize>);

impl ActionApprover for CountingApprover {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn approve(&self, proposal: &ProposedAction) -> Result<EventDraft, ActionRejected> {
        self.0.fetch_add(1, Ordering::SeqCst);
        if proposal.payload.as_slice() == b"deny" {
            return Err(ActionRejected::DomainValidationFailed("denied".to_owned()));
        }
        Ok(EventDraft::new(
            proposal.actor_entity_id,
            proposal.event_type.clone(),
            proposal.payload.clone(),
        ))
    }
}

struct Harness {
    name: &'static str,
    store: Box<dyn ScheduledAdmissionStoreV1>,
    registry: PluginRegistry,
    approvals: Arc<AtomicUsize>,
    timeline: TimelineId,
    revisions: PipelineSecurityRevisionsV1,
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn harnesses() -> Vec<Harness> {
    let stores: Vec<(&'static str, Box<dyn ScheduledAdmissionStoreV1>)> = vec![
        ("memory", Box::new(MemoryStore::new())),
        ("sqlite", Box::new(ok(SqliteStore::open(":memory:")))),
    ];
    stores
        .into_iter()
        .map(|(name, mut store)| {
            let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
            ok(store.bind_erasure_gate(Arc::clone(&gate)));
            let timeline = ok(store.create_timeline("human-admission")).id();
            let approvals = Arc::new(AtomicUsize::new(0));
            let mut registry = PluginRegistry::new().with_erasure_gate(gate);
            ok(registry.register_generated_with_approver(
                &ActionPlugin(PluginId::new()),
                None,
                None,
                Some(Box::new(CountingApprover(Arc::clone(&approvals)))),
                [Kind::new(ACTION)],
            ));
            let revisions = ok(ok(LocalScheduledAdmissionHostV1::shared()).observe(
                &registry,
                store.as_mut(),
                timeline,
            ));
            Harness {
                name,
                store,
                registry,
                approvals,
                timeline,
                revisions,
            }
        })
        .collect()
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn proposal(actor: EntityId, payload: &'static [u8]) -> ProposedAction {
    ProposedAction::new(
        Kind::new(ACTION),
        actor,
        CanonicalBytes::from_static(payload),
        Kind::new(CAPABILITY),
    )
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn admission(harness: &Harness, key: u8, attempt: u8, observed: u64) -> HumanActionAdmissionV1 {
    let host = ok(LocalScheduledAdmissionHostV1::shared());
    HumanActionAdmissionV1 {
        attempt_id: ok(PipelineAttemptIdV1::try_new([attempt; 16])),
        idempotency: AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([key; 32]),
            AppendDedupScope::from_keyed_hash([77; 32]),
        ),
        observation: ok(PipelineObservationAnchorV1::try_new(
            harness.timeline,
            Seq::from_u64(observed),
            Hash::from_bytes([u8::try_from(observed).unwrap_or(u8::MAX).saturating_add(1); 32]),
        )),
        authorization: ok(PipelineEvidenceRefV1::try_new(Hash::from_bytes([5; 32]))),
        security_revisions: harness.revisions,
        authority_grant: host.authority_grant(),
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn admit(
    harness: &mut Harness,
    proposal: &ProposedAction,
    admission: &HumanActionAdmissionV1,
) -> Result<HumanActionReceiptV1, HumanActionAdmissionErrorV1> {
    harness
        .registry
        .admit_human_action(harness.store.as_mut(), proposal, admission)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn admit_with(
    harness: &mut Harness,
    proposal: &ProposedAction,
    key: u8,
    attempt: u8,
    observed: u64,
) -> Result<HumanActionReceiptV1, HumanActionAdmissionErrorV1> {
    let admission = admission(harness, key, attempt, observed);
    admit(harness, proposal, &admission)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn events(harness: &Harness) -> usize {
    ok(harness.store.read(harness.timeline, SeqRange::all())).len()
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn approvals(harness: &Harness) -> usize {
    harness.approvals.load(Ordering::SeqCst)
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_local_host_admits_a_human_action_on_the_human_path() {
    for mut harness in harnesses() {
        let name = harness.name;
        let actor = EntityId::new();
        let head = ok(harness.store.logical_head(harness.timeline));

        let admitted = ok(ok(LocalScheduledAdmissionHostV1::shared()).admit_action(
            &harness.registry,
            harness.store.as_mut(),
            &proposal(actor, b"walk"),
            harness.revisions,
            (harness.timeline, head),
        ));

        assert!(!admitted.recovered(), "{name}");
        let committed = admitted.receipt().committed_events();
        assert_eq!(committed.len(), 1, "{name}");
        assert_eq!(committed[0].seq(), Seq::from_u64(1), "{name}");
        let stored = ok(harness.store.read(harness.timeline, SeqRange::all()));
        assert_eq!(stored[0].id, committed[0].event_id(), "{name}");
        assert_eq!(stored[0].entity, actor, "{name}");
        assert_eq!(approvals(&harness), 1, "{name}");
    }
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn an_exact_retry_recovers_the_receipt_without_invoking_the_approver() {
    for mut harness in harnesses() {
        let name = harness.name;
        let actor = EntityId::new();
        let first = admission(&harness, 1, 1, 0);
        let committed = ok(admit(&mut harness, &proposal(actor, b"first"), &first));
        ok(admit_with(
            &mut harness,
            &proposal(actor, b"second"),
            2,
            2,
            1,
        ));
        assert_eq!(approvals(&harness), 2, "{name}");

        // The Logical Head moved, so only the retained receipt can answer.
        let retry = ok(admit(&mut harness, &proposal(actor, b"first"), &first));

        assert!(retry.recovered(), "{name}");
        assert_eq!(retry.receipt(), committed.receipt(), "{name}");
        assert_eq!(approvals(&harness), 2, "{name}: approval is not rerun");
        assert_eq!(events(&harness), 2, "{name}");
    }
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_reused_key_is_a_conflict_before_any_approval() {
    for mut harness in harnesses() {
        let name = harness.name;
        let actor = EntityId::new();
        ok(admit_with(
            &mut harness,
            &proposal(actor, b"first"),
            1,
            1,
            0,
        ));

        let conflict = err(admit_with(
            &mut harness,
            &proposal(actor, b"other"),
            1,
            9,
            1,
        ));

        assert!(
            matches!(conflict, HumanActionAdmissionErrorV1::IdempotencyConflict),
            "{name}"
        );
        assert_eq!(approvals(&harness), 1, "{name}");
        assert_eq!(events(&harness), 1, "{name}");
    }
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn denial_missing_plugin_stale_state_and_changed_authority_commit_nothing() {
    for mut harness in harnesses() {
        let name = harness.name;
        let actor = EntityId::new();

        let denied = err(admit_with(&mut harness, &proposal(actor, b"deny"), 1, 1, 0));
        let missing = err(admit_with(
            &mut harness,
            &ProposedAction::new(
                Kind::new("world.unowned"),
                actor,
                CanonicalBytes::from_static(b"walk"),
                Kind::new("world.unowned.submit"),
            ),
            2,
            2,
            0,
        ));
        let ahead = err(admit_with(&mut harness, &proposal(actor, b"walk"), 3, 3, 4));
        ok(admit_with(
            &mut harness,
            &proposal(actor, b"current"),
            4,
            4,
            0,
        ));
        let stale = err(admit_with(&mut harness, &proposal(actor, b"walk"), 5, 5, 0));
        let mut changed_authority = admission(&harness, 6, 6, 1);
        let mut revisions = harness.revisions.as_draft();
        revisions.authority = Hash::from_bytes([99; 32]);
        changed_authority.security_revisions =
            ok(PipelineSecurityRevisionsV1::try_from_draft(revisions));
        let changed = err(admit(
            &mut harness,
            &proposal(actor, b"walk"),
            &changed_authority,
        ));

        assert!(
            matches!(
                denied,
                HumanActionAdmissionErrorV1::Submission(ActionSubmissionError::Rejected(
                    ActionRejected::DomainValidationFailed(_)
                ))
            ),
            "{name}"
        );
        assert!(
            matches!(
                missing,
                HumanActionAdmissionErrorV1::Submission(ActionSubmissionError::Rejected(
                    ActionRejected::UnknownEventType
                ))
            ),
            "{name}"
        );
        for (error, expected) in [
            (ahead, PipelineOutcomeV1::InvalidObservation),
            (stale, PipelineOutcomeV1::AdmissionConflict),
            (changed, PipelineOutcomeV1::AdmissionConflict),
        ] {
            assert!(
                matches!(&error, HumanActionAdmissionErrorV1::NotAdmitted(outcome) if **outcome == expected),
                "{name}: {error:?}"
            );
        }
        assert_eq!(events(&harness), 1, "{name}");
    }
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn an_approved_draft_that_cannot_form_a_basis_is_a_contract_error() {
    for mut harness in harnesses() {
        let name = harness.name;
        let nil_actor = EntityId::from_ulid(Ulid::nil());

        let error = err(admit_with(
            &mut harness,
            &proposal(nil_actor, b"walk"),
            1,
            1,
            0,
        ));

        assert!(
            matches!(
                error,
                HumanActionAdmissionErrorV1::Contract(PipelineContractErrorV1::InvalidDraft)
            ),
            "{name}"
        );
        assert_eq!(events(&harness), 0, "{name}");
    }
}

/// A port that commits through the real store but never returns its outcome.
struct LostOutcomePort<'a>(&'a mut dyn ScheduledAdmissionStoreV1);

impl PipelineAdmissionPortV1 for LostOutcomePort<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        self.0.admit_pipeline_batch(basis).and_then(|_| {
            Err(CoreError::StorageOutcomeUnknown(
                "injected lost commit acknowledgement".to_owned(),
            ))
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn lookup_pipeline_receipt(
        &mut self,
        timeline: TimelineId,
        key: AppendDedupKey,
        attempt_id: PipelineAttemptIdV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        self.0.lookup_pipeline_receipt(timeline, key, attempt_id)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: std::num::NonZeroUsize,
    ) -> Result<pos_core::PurgeOutcome, CoreError> {
        self.0.purge_expired_pipeline_receipts_bounded(limit)
    }
}

impl pos_core::FactualPrefixReadPortV1 for LostOutcomePort<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn last_committed_factual_tick(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<pos_core::FactualHeadV1, pos_core::CoreError> {
        self.0.last_committed_factual_tick(timeline)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cut_tick_at(
        &self,
        timeline: pos_core::TimelineId,
        seq: pos_core::Seq,
    ) -> Result<pos_core::FactualCutV1, pos_core::CoreError> {
        self.0.cut_tick_at(timeline, seq)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nodes_for_committed_events(
        &self,
        timeline: pos_core::TimelineId,
        seqs: &[pos_core::Seq],
    ) -> Result<Vec<Option<pos_core::DependencyNodeRecordV1>>, pos_core::CoreError> {
        self.0.nodes_for_committed_events(timeline, seqs)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nodes_by_digest(
        &self,
        timeline: pos_core::TimelineId,
        digests: &[pos_core::Hash],
    ) -> Result<Vec<Option<pos_core::factual_dependency::BoundFactualNodeV1>>, pos_core::CoreError>
    {
        self.0.nodes_by_digest(timeline, digests)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn last_step_node(
        &self,
        timeline: pos_core::TimelineId,
        owner: &pos_core::FactualOwnerIdV1,
    ) -> Result<Option<pos_core::DependencyNodeRecordV1>, pos_core::CoreError> {
        self.0.last_step_node(timeline, owner)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn factual_set_counts(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<pos_core::RecordedSetCountsV1, pos_core::CoreError> {
        self.0.factual_set_counts(timeline)
    }
}

/// A port whose basis-free lookup never finds a receipt, so only the
/// store's own exact-retry comparison can recognize a duplicate. It records
/// every basis it submits, so a test can resubmit the retained one. When
/// `replay` holds an outcome, the store is bypassed and that outcome returned.
struct ForgetfulLookupPort<'a> {
    store: &'a mut dyn ScheduledAdmissionStoreV1,
    submitted: &'a mut Vec<PipelineAdmissionBasisV1>,
    replay: Option<PipelineOutcomeV1>,
}

impl PipelineAdmissionPortV1 for ForgetfulLookupPort<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        self.submitted.push(basis.clone());
        self.replay
            .clone()
            .map_or_else(|| self.store.admit_pipeline_batch(basis), Ok)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn lookup_pipeline_receipt(
        &mut self,
        _timeline: TimelineId,
        _key: AppendDedupKey,
        _attempt_id: PipelineAttemptIdV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        Ok(PipelineReceiptLookupV1::Absent)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: std::num::NonZeroUsize,
    ) -> Result<pos_core::PurgeOutcome, CoreError> {
        self.store.purge_expired_pipeline_receipts_bounded(limit)
    }
}

impl pos_core::FactualPrefixReadPortV1 for ForgetfulLookupPort<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn last_committed_factual_tick(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<pos_core::FactualHeadV1, pos_core::CoreError> {
        self.store.last_committed_factual_tick(timeline)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cut_tick_at(
        &self,
        timeline: pos_core::TimelineId,
        seq: pos_core::Seq,
    ) -> Result<pos_core::FactualCutV1, pos_core::CoreError> {
        self.store.cut_tick_at(timeline, seq)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nodes_for_committed_events(
        &self,
        timeline: pos_core::TimelineId,
        seqs: &[pos_core::Seq],
    ) -> Result<Vec<Option<pos_core::DependencyNodeRecordV1>>, pos_core::CoreError> {
        self.store.nodes_for_committed_events(timeline, seqs)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nodes_by_digest(
        &self,
        timeline: pos_core::TimelineId,
        digests: &[pos_core::Hash],
    ) -> Result<Vec<Option<pos_core::factual_dependency::BoundFactualNodeV1>>, pos_core::CoreError>
    {
        self.store.nodes_by_digest(timeline, digests)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn last_step_node(
        &self,
        timeline: pos_core::TimelineId,
        owner: &pos_core::FactualOwnerIdV1,
    ) -> Result<Option<pos_core::DependencyNodeRecordV1>, pos_core::CoreError> {
        self.store.last_step_node(timeline, owner)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn factual_set_counts(
        &self,
        timeline: pos_core::TimelineId,
    ) -> Result<pos_core::RecordedSetCountsV1, pos_core::CoreError> {
        self.store.factual_set_counts(timeline)
    }
}

/// A port whose lookup fails before any approval.
struct UnavailablePort;

impl PipelineAdmissionPortV1 for UnavailablePort {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn admit_pipeline_batch(
        &mut self,
        _basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        Err(CoreError::Storage("unreachable admission".to_owned()))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn lookup_pipeline_receipt(
        &mut self,
        _timeline: TimelineId,
        _key: AppendDedupKey,
        _attempt_id: PipelineAttemptIdV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        Err(CoreError::Storage("injected lookup failure".to_owned()))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        _limit: std::num::NonZeroUsize,
    ) -> Result<pos_core::PurgeOutcome, CoreError> {
        Err(CoreError::Storage("unreachable purge".to_owned()))
    }
}

impl pos_core::FactualPrefixReadPortV1 for UnavailablePort {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn last_committed_factual_tick(
        &self,
        _: pos_core::TimelineId,
    ) -> Result<pos_core::FactualHeadV1, pos_core::CoreError> {
        Ok(pos_core::FactualHeadV1 {
            tick: 0,
            last_seq: pos_core::Seq::ZERO,
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cut_tick_at(
        &self,
        _: pos_core::TimelineId,
        _: pos_core::Seq,
    ) -> Result<pos_core::FactualCutV1, pos_core::CoreError> {
        Ok(pos_core::FactualCutV1::Boundary { cut_tick: 0 })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nodes_for_committed_events(
        &self,
        _: pos_core::TimelineId,
        seqs: &[pos_core::Seq],
    ) -> Result<Vec<Option<pos_core::DependencyNodeRecordV1>>, pos_core::CoreError> {
        Ok(seqs.iter().map(|_| None).collect())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nodes_by_digest(
        &self,
        _: pos_core::TimelineId,
        digests: &[pos_core::Hash],
    ) -> Result<Vec<Option<pos_core::factual_dependency::BoundFactualNodeV1>>, pos_core::CoreError>
    {
        Ok(digests.iter().map(|_| None).collect())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn last_step_node(
        &self,
        _: pos_core::TimelineId,
        _: &pos_core::FactualOwnerIdV1,
    ) -> Result<Option<pos_core::DependencyNodeRecordV1>, pos_core::CoreError> {
        Ok(None)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn factual_set_counts(
        &self,
        _: pos_core::TimelineId,
    ) -> Result<pos_core::RecordedSetCountsV1, pos_core::CoreError> {
        Ok(pos_core::RecordedSetCountsV1::default())
    }
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_lost_commit_outcome_is_recovered_by_an_exact_retry_without_reapproval() {
    for mut harness in harnesses() {
        let name = harness.name;
        let actor = EntityId::new();
        let attempt = admission(&harness, 1, 1, 0);
        let action = proposal(actor, b"walk");

        let lost = err(harness.registry.admit_human_action(
            &mut LostOutcomePort(harness.store.as_mut()),
            &action,
            &attempt,
        ));
        assert!(
            matches!(
                lost,
                HumanActionAdmissionErrorV1::Store(CoreError::StorageOutcomeUnknown(_))
            ),
            "{name}"
        );
        assert_eq!(events(&harness), 1, "{name}: the batch did commit");

        let recovered = ok(admit(&mut harness, &action, &attempt));

        assert!(recovered.recovered(), "{name}");
        assert_eq!(recovered.receipt().committed_events().len(), 1, "{name}");
        assert_eq!(approvals(&harness), 1, "{name}: recovery reran nothing");
        assert_eq!(events(&harness), 1, "{name}");
    }
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_store_comparison_still_recognizes_an_exact_retry() {
    for mut harness in harnesses() {
        let name = harness.name;
        let actor = EntityId::new();
        let attempt = admission(&harness, 1, 1, 0);
        let action = proposal(actor, b"walk");
        let mut submitted = Vec::new();
        let first = ok(harness.registry.admit_human_action(
            &mut ForgetfulLookupPort {
                store: harness.store.as_mut(),
                submitted: &mut submitted,
                replay: None,
            },
            &action,
            &attempt,
        ));
        assert!(!first.recovered(), "{name}");
        assert_eq!(submitted.len(), 1, "{name}");

        // R3.8: the receipt lookup precedes every dependency check, so the
        // retained basis is an exact retry. A rebuilt basis would declare the
        // next Tick and conflict on an adapter that records Ticks.
        let retained = ok(submitted.first().ok_or("no basis was submitted"));
        let retry = ok(harness.store.admit_pipeline_batch(retained));

        assert_eq!(
            retry,
            PipelineOutcomeV1::RecoveredDuplicate(first.receipt().clone()),
            "{name}"
        );
        assert_eq!(events(&harness), 1, "{name}");
    }
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_store_reported_duplicate_is_a_recovered_receipt() {
    for mut harness in harnesses() {
        let name = harness.name;
        let attempt = admission(&harness, 1, 1, 0);
        let action = proposal(EntityId::new(), b"walk");
        let committed = ok(admit(&mut harness, &action, &attempt));
        let replay = PipelineOutcomeV1::RecoveredDuplicate(committed.receipt().clone());
        let mut submitted = Vec::new();

        let duplicate = ok(harness.registry.admit_human_action(
            &mut ForgetfulLookupPort {
                store: harness.store.as_mut(),
                submitted: &mut submitted,
                replay: Some(replay),
            },
            &action,
            &attempt,
        ));

        assert!(duplicate.recovered(), "{name}");
        assert_eq!(duplicate.receipt(), committed.receipt(), "{name}");
        assert_eq!(submitted.len(), 1, "{name}");
        assert_eq!(events(&harness), 1, "{name}");
    }
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn a_failed_lookup_stops_before_approval() {
    for harness in harnesses() {
        let name = harness.name;
        let error = err(harness.registry.admit_human_action(
            &mut UnavailablePort,
            &proposal(EntityId::new(), b"walk"),
            &admission(&harness, 1, 1, 0),
        ));

        assert!(
            matches!(
                error,
                HumanActionAdmissionErrorV1::Store(CoreError::Storage(_))
            ),
            "{name}"
        );
        assert_eq!(approvals(&harness), 0, "{name}");
        assert!(
            error.to_string().contains("injected lookup failure"),
            "{name}"
        );
    }
}

// ── Set-capacity preflight (ADR-064 Revision 3, R3.10) ─────────────────────

/// The recorded-set counts one node, edge or declared input past the preflight
/// threshold: one worst-case Tick no longer fits.
///
/// The thresholds are the caps less one worst-case Tick: 934,464 nodes is
/// 1,000,000 - 65,536, and 3,737,856 edges or inputs is 4,000,000 - 262,144.
const fn exhausted_counts() -> [RecordedSetCountsV1; 3] {
    [
        RecordedSetCountsV1 {
            nodes: 934_465,
            edges: 0,
            inputs: 0,
        },
        RecordedSetCountsV1 {
            nodes: 0,
            edges: 3_737_857,
            inputs: 0,
        },
        RecordedSetCountsV1 {
            nodes: 0,
            edges: 0,
            inputs: 3_737_857,
        },
    ]
}

/// The counts exactly at the threshold: one worst-case Tick still fits.
///
/// 934,464 is 1,000,000 - 65,536 and 3,737,856 is 4,000,000 - 262,144.
const AT_THRESHOLD: RecordedSetCountsV1 = RecordedSetCountsV1 {
    nodes: 934_464,
    edges: 3_737_856,
    inputs: 3_737_856,
};

/// A port over the real store that reports fixed recorded-set counts.
struct SetCountsPort<'a> {
    inner: &'a mut dyn ScheduledAdmissionStoreV1,
    counts: RecordedSetCountsV1,
    bases: Vec<PipelineAdmissionBasisV1>,
}

impl PipelineAdmissionPortV1 for SetCountsPort<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        self.bases.push(basis.clone());
        self.inner.admit_pipeline_batch(basis)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: std::num::NonZeroUsize,
    ) -> Result<pos_core::PurgeOutcome, CoreError> {
        self.inner.purge_expired_pipeline_receipts_bounded(limit)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn lookup_pipeline_receipt(
        &mut self,
        timeline: TimelineId,
        key: AppendDedupKey,
        attempt_id: PipelineAttemptIdV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        self.inner
            .lookup_pipeline_receipt(timeline, key, attempt_id)
    }
}

impl pos_core::FactualPrefixReadPortV1 for SetCountsPort<'_> {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn last_committed_factual_tick(
        &self,
        timeline: TimelineId,
    ) -> Result<pos_core::FactualHeadV1, CoreError> {
        self.inner.last_committed_factual_tick(timeline)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cut_tick_at(
        &self,
        timeline: TimelineId,
        seq: Seq,
    ) -> Result<pos_core::FactualCutV1, CoreError> {
        self.inner.cut_tick_at(timeline, seq)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nodes_for_committed_events(
        &self,
        timeline: TimelineId,
        seqs: &[Seq],
    ) -> Result<Vec<Option<pos_core::DependencyNodeRecordV1>>, CoreError> {
        self.inner.nodes_for_committed_events(timeline, seqs)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn nodes_by_digest(
        &self,
        timeline: TimelineId,
        digests: &[Hash],
    ) -> Result<Vec<Option<pos_core::factual_dependency::BoundFactualNodeV1>>, CoreError> {
        self.inner.nodes_by_digest(timeline, digests)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn last_step_node(
        &self,
        timeline: TimelineId,
        owner: &pos_core::FactualOwnerIdV1,
    ) -> Result<Option<pos_core::DependencyNodeRecordV1>, CoreError> {
        self.inner.last_step_node(timeline, owner)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn factual_set_counts(&self, _: TimelineId) -> Result<RecordedSetCountsV1, CoreError> {
        Ok(self.counts)
    }
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn an_exhausted_timeline_refuses_the_action_before_the_approver_runs() {
    for mut harness in harnesses() {
        let name = harness.name;
        let actor = EntityId::new();
        for counts in exhausted_counts() {
            let attempt = admission(&harness, 1, 1, 0);
            let mut port = SetCountsPort {
                inner: harness.store.as_mut(),
                counts,
                bases: Vec::new(),
            };
            let walk = proposal(actor, b"walk");
            let registry = &harness.registry;
            let refused = err(registry.admit_human_action(&mut port, &walk, &attempt));
            assert!(
                matches!(
                    refused,
                    HumanActionAdmissionErrorV1::DependencyDeclaration(
                        FactualDependencyErrorV1::SetExhausted
                    )
                ),
                "{name}"
            );
        }
        // The approver was never invoked.
        assert_eq!(approvals(&harness), 0, "{name}");
        assert_eq!(events(&harness), 0, "{name}");

        // Exactly at the threshold one more worst-case Tick fits.
        let attempt = admission(&harness, 2, 2, 0);
        let mut port = SetCountsPort {
            inner: harness.store.as_mut(),
            counts: AT_THRESHOLD,
            bases: Vec::new(),
        };
        let walk = proposal(actor, b"walk");
        let registry = &harness.registry;
        ok(registry.admit_human_action(&mut port, &walk, &attempt));
        assert_eq!(approvals(&harness), 1, "{name}");
        assert_eq!(events(&harness), 1, "{name}");
    }
}

/// ADR-064 R3.4.5: the basis a human action submits declares one
/// human-ingress node per approved draft and no edge.
#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn the_submitted_basis_declares_one_human_ingress_node_per_draft() {
    for mut harness in harnesses() {
        let name = harness.name;
        let attempt = admission(&harness, 1, 1, 0);
        let mut port = SetCountsPort {
            inner: harness.store.as_mut(),
            counts: RecordedSetCountsV1::default(),
            bases: Vec::new(),
        };
        let walk = proposal(EntityId::new(), b"walk");
        let registry = &harness.registry;
        ok(registry.admit_human_action(&mut port, &walk, &attempt));

        let dependencies = port.bases[0].dependencies();
        assert_eq!(dependencies.tick(), 1, "{name}");
        let record = dependencies.record();
        let nodes = record.nodes();
        assert_eq!(nodes.len(), 1, "{name}");
        assert_eq!(nodes[0].coordinate().owner_id(), "host.ingress", "{name}");
        let class = RecordedDependencyClassV1::ExogenousFrozen;
        assert_eq!(nodes[0].class(), class, "{name}");
        assert!(nodes[0].input_digests().is_empty(), "{name}");
        assert!(record.edges().is_empty(), "{name}");
        let bound: Vec<(u32, u32)> = dependencies
            .output_bindings()
            .iter()
            .map(|binding| (binding.draft_index, binding.node_index))
            .collect();
        assert_eq!(bound, [(0, 0)], "{name}");
        assert!(dependencies.event_nodes().is_empty(), "{name}");
    }
}
