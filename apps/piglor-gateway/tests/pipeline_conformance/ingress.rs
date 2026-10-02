//! Ingress parity, failure precedence, recovery, Replay and evaluation
//! non-authority through the host admission seams (#316, #318, #319, #320).

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use pos_core::{
    ActionRejected, AppendDedupKey, AppendDedupScope, AppendIdentity, CanonicalBytes, CoreError,
    EntityId, ErasureContainmentGateV1, EventStore, Hash, Kind, PipelineAdmissionFencePublisherV1,
    PipelineAdmissionFenceV1, PipelineAttemptIdV1, PipelineCommitEvidenceV1, PipelineEvidenceRefV1,
    PipelineObservationAnchorV1, PipelineSecurityRevisionsV1, ProposedAction, Seq, TimelineId,
};
use pos_experiment::{
    CommittedRangeIntegrityEvaluatorV1, Experiment, ExperimentConfig, ExperimentSession,
    PipelineEvaluationOutcomeV1, StopCondition, TickOutcome,
};
use pos_runtime::{
    ActionSubmissionError, HumanActionAdmissionErrorV1, HumanActionAdmissionV1,
    LocalScheduledAdmissionHostV1, PluginRegistry, RuntimeError, ScheduledAdmissionStoreV1,
    ScheduledPassAdmissionV1,
};
use pos_store::{sqlite::SqliteStore, StoreConfig};

use super::{
    harness::Capture,
    support::{
        draft, events, exact_claim, expect_err, experiment_stores, gated_registry, pass,
        profile_tag, stage, stores, CountingApprover, FailingWritePort, FixturePlugin,
        LostOutcomePort, ScriptedDriver, TestOk,
    },
};

/// The fixture action type shared by the human and AI paths.
const ACTION: &str = "conformance.action";
const CAPABILITY: &str = "conformance.action.submit";
const INTEGRITY: &str = "committed-range-integrity";

fn proposal(actor: EntityId, payload: &'static [u8]) -> ProposedAction {
    ProposedAction::new(
        Kind::new(ACTION),
        actor,
        CanonicalBytes::from_static(payload),
        Kind::new(CAPABILITY),
    )
}

/// The action-owning fixture Plugin, with an approver and optional Driver.
fn register_action_plugin(
    registry: &mut PluginRegistry,
    approvals: &Arc<AtomicUsize>,
    driver: Option<ScriptedDriver>,
) {
    let has_driver = driver.is_some();
    registry
        .register_generated_with_approver(
            &FixturePlugin::new("conformance-action", &[ACTION], has_driver),
            None,
            driver.map(|driver| Box::new(driver) as Box<dyn pos_runtime::Driver>),
            Some(Box::new(CountingApprover(Arc::clone(approvals)))),
            [Kind::new(ACTION)],
        )
        .test_ok();
}

/// Host-issued human admission inputs for one attempt.
fn human_admission(
    timeline: TimelineId,
    key: u8,
    observed: u64,
    revisions: PipelineSecurityRevisionsV1,
) -> HumanActionAdmissionV1 {
    HumanActionAdmissionV1 {
        attempt_id: PipelineAttemptIdV1::try_new([key; 16]).test_ok(),
        idempotency: AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([key; 32]),
            AppendDedupScope::from_keyed_hash([77; 32]),
        ),
        observation: PipelineObservationAnchorV1::try_new(
            timeline,
            Seq::from_u64(observed),
            Hash::from_bytes([key.wrapping_add(100); 32]),
        )
        .test_ok(),
        authorization: PipelineEvidenceRefV1::try_new(Hash::from_bytes([5; 32])).test_ok(),
        security_revisions: revisions,
    }
}

/// A stable name for one typed human admission outcome.
fn human_outcome(error: &HumanActionAdmissionErrorV1) -> String {
    match error {
        HumanActionAdmissionErrorV1::Submission(ActionSubmissionError::Rejected(
            ActionRejected::DomainValidationFailed(_),
        )) => "domain-rejected".to_owned(),
        HumanActionAdmissionErrorV1::NotAdmitted(outcome) => format!("not-admitted:{outcome:?}"),
        HumanActionAdmissionErrorV1::Store(CoreError::Storage(_)) => "store-failure".to_owned(),
        HumanActionAdmissionErrorV1::Store(CoreError::StorageOutcomeUnknown(_)) => {
            "outcome-unknown".to_owned()
        }
        other => format!("{other:?}"),
    }
}

/// One runtime store with the action Plugin and a published local fence.
struct HostFixture {
    store: Box<dyn ScheduledAdmissionStoreV1>,
    registry: PluginRegistry,
    approvals: Arc<AtomicUsize>,
    timeline: TimelineId,
    revisions: PipelineSecurityRevisionsV1,
}

fn host_fixture(
    mut store: Box<dyn ScheduledAdmissionStoreV1>,
    driver: Option<ScriptedDriver>,
) -> HostFixture {
    let timeline = store.create_timeline("pipeline-conformance").test_ok().id();
    let approvals = Arc::new(AtomicUsize::new(0));
    let mut registry = gated_registry(None);
    register_action_plugin(&mut registry, &approvals, driver);
    let revisions = LocalScheduledAdmissionHostV1::shared()
        .test_ok()
        .observe(&registry, store.as_mut(), timeline)
        .test_ok();
    HostFixture {
        store,
        registry,
        approvals,
        timeline,
        revisions,
    }
}

impl HostFixture {
    fn approvals(&self) -> usize {
        self.approvals.load(Ordering::SeqCst)
    }

    fn committed(&self) -> usize {
        events(self.store.as_ref(), self.timeline).len()
    }
}

/// An experiment session whose one Plugin owns the action on both paths.
fn parity_session(
    store_config: StoreConfig,
    approvals: &Arc<AtomicUsize>,
    driver: ScriptedDriver,
) -> ExperimentSession {
    let mut experiment = Experiment::new(ExperimentConfig {
        name: "pipeline-conformance".to_owned(),
        stop: StopCondition::MaxTicks(16),
        store_config,
    });
    experiment
        .register_generated_with_approver(
            &FixturePlugin::new("conformance-action", &[ACTION], true),
            None,
            Some(Box::new(driver)),
            Some(Box::new(CountingApprover(Arc::clone(approvals)))),
            [Kind::new(ACTION)],
        )
        .test_ok();
    experiment.start().test_ok()
}

fn range(evidence: &PipelineCommitEvidenceV1) -> String {
    let range = evidence.committed_range();
    format!("{}..{}", range.first().as_u64(), range.last().as_u64())
}

/// PCF-ING-001: a human request and an AI scheduled pass commit the same
/// action meaning through their own ingress and trust paths.
pub(super) fn ingress_parity() -> Capture {
    let mut capture = Capture::default();
    let (_directory, configs) = experiment_stores();
    for (store, config) in configs {
        let actor = EntityId::new();
        let approvals = Arc::new(AtomicUsize::new(0));
        let driver = ScriptedDriver::new("conformance-ai", vec![draft(actor, ACTION, b"move")]);
        let steps = Arc::clone(&driver.steps);
        let mut session = parity_session(config, &approvals, driver);

        session.submit_action(&proposal(actor, b"move")).test_ok();
        let human = session.last_pipeline_evidence().test_ok().clone();
        let tick = session.step_tick().test_ok();
        let ai = session.last_pipeline_evidence().test_ok().clone();
        let committed = session.source_events().test_ok();

        capture.record(store, "human.ingress", format!("{:?}", human.ingress()));
        capture.record(store, "ai.ingress", format!("{:?}", ai.ingress()));
        capture.record(store, "human.range", range(&human));
        capture.record(store, "ai.range", range(&ai));
        capture.record(
            store,
            "ai.tick",
            matches!(
                tick,
                TickOutcome::Advanced {
                    emitted_events: 1,
                    ..
                }
            ),
        );
        capture.record(
            store,
            "meaning.equivalent",
            committed.len() == 2
                && committed[0].event_type == committed[1].event_type
                && committed[0].entity == committed[1].entity
                && committed[0].payload == committed[1].payload,
        );
        capture.record(
            store,
            "receipts.name-committed-events",
            human.receipt().committed_events()[0].event_id() == committed[0].id
                && ai.receipt().committed_events()[0].event_id() == committed[1].id,
        );
        capture.record(
            store,
            "folded-before-visible",
            human
                .projection_cut()
                .is_some_and(|cut| cut.contains(human.committed_range()))
                && ai
                    .projection_cut()
                    .is_some_and(|cut| cut.contains(ai.committed_range())),
        );
        capture.record(store, "approvals", approvals.load(Ordering::SeqCst));
        capture.record(store, "driver.steps", steps.load(Ordering::SeqCst));
        capture.record(
            store,
            super::harness::PROFILE_KEY,
            profile_tag(human.observation_profile()),
        );
        capture.record(
            store,
            super::harness::PROFILE_KEY,
            profile_tag(ai.observation_profile()),
        );
    }
    capture
}

/// PCF-ING-002: the human path commits only through host admission and
/// returns the store's receipt.
pub(super) fn human_admission_receipt() -> Capture {
    let mut capture = Capture::default();
    for (store, backend) in stores() {
        let mut fixture = host_fixture(backend, None);
        let actor = EntityId::new();
        let head = fixture.store.logical_head(fixture.timeline).test_ok();
        let admitted = LocalScheduledAdmissionHostV1::shared()
            .test_ok()
            .admit_action(
                &fixture.registry,
                fixture.store.as_mut(),
                &proposal(actor, b"walk"),
                fixture.revisions,
                (fixture.timeline, head),
            )
            .test_ok();
        let committed = events(fixture.store.as_ref(), fixture.timeline);
        let receipt = admitted.receipt().committed_events();
        capture.record(store, "recovered", admitted.recovered());
        capture.record(store, "receipt.events", receipt.len());
        capture.record(store, "receipt.seq", receipt[0].seq().as_u64());
        capture.record(
            store,
            "receipt.names-event",
            receipt[0].event_id() == committed[0].id,
        );
        capture.record(store, "entity.is-actor", committed[0].entity == actor);
        capture.record(store, "approvals", fixture.approvals());
    }
    capture
}

/// PCF-FP-002: domain approval precedes the store comparison, which checks
/// revisions, then the observation, then the budget; a store write failure
/// is typed. Nothing commits.
pub(super) fn store_failure_precedence() -> Capture {
    let mut capture = Capture::default();
    for (store, backend) in stores() {
        let mut fixture = host_fixture(backend, None);
        let timeline = fixture.timeline;
        let revisions = fixture.revisions;
        let grant = LocalScheduledAdmissionHostV1::shared()
            .test_ok()
            .authority_grant();
        let mut forged = revisions.as_draft();
        forged.authority = Hash::from_bytes([99; 32]);
        let forged = PipelineSecurityRevisionsV1::try_from_draft(forged).test_ok();
        let actor = EntityId::new();
        PipelineAdmissionFencePublisherV1::set_pipeline_admission_fence(
            fixture.store.as_mut(),
            timeline,
            PipelineAdmissionFenceV1::try_new(grant, revisions, None, 0).test_ok(),
        )
        .test_ok();

        let domain = expect_err(fixture.registry.admit_human_action(
            &mut FailingWritePort(fixture.store.as_mut()),
            &proposal(actor, b"deny"),
            &human_admission(timeline, 1, 5, forged),
        ));
        let revision = expect_err(fixture.registry.admit_human_action(
            fixture.store.as_mut(),
            &proposal(actor, b"walk"),
            &human_admission(timeline, 2, 5, forged),
        ));
        let observation = expect_err(fixture.registry.admit_human_action(
            fixture.store.as_mut(),
            &proposal(actor, b"walk"),
            &human_admission(timeline, 3, 5, revisions),
        ));
        let budget = expect_err(fixture.registry.admit_human_action(
            fixture.store.as_mut(),
            &proposal(actor, b"walk"),
            &human_admission(timeline, 4, 0, revisions),
        ));
        PipelineAdmissionFencePublisherV1::set_pipeline_admission_fence(
            fixture.store.as_mut(),
            timeline,
            PipelineAdmissionFenceV1::try_new(grant, revisions, None, 100).test_ok(),
        )
        .test_ok();
        let write = expect_err(fixture.registry.admit_human_action(
            &mut FailingWritePort(fixture.store.as_mut()),
            &proposal(actor, b"walk"),
            &human_admission(timeline, 5, 0, revisions),
        ));

        capture.record(store, "rung.domain", human_outcome(&domain));
        capture.record(store, "rung.revisions", human_outcome(&revision));
        capture.record(store, "rung.observation", human_outcome(&observation));
        capture.record(store, "rung.budget", human_outcome(&budget));
        capture.record(store, "rung.store-write", human_outcome(&write));
        capture.record(store, "approvals", fixture.approvals());
        capture.record(store, "committed", fixture.committed());
    }
    capture
}

/// PCF-FP-003: a failing Driver discards every Driver's output of the
/// scheduled pass; the next pass commits the whole batch in schedule order.
pub(super) fn scheduled_pass_discard() -> Capture {
    let mut capture = Capture::default();
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("discard").test_ok().id();
        let entity = EntityId::new();
        let first =
            ScriptedDriver::new("conformance-first", vec![draft(entity, "first.tick", b"1")]);
        let second = ScriptedDriver::new(
            "conformance-second",
            vec![draft(entity, "second.tick", b"2")],
        );
        let first_aborts = Arc::clone(&first.aborts);
        let failing = Arc::clone(&second.failing);
        failing.store(true, Ordering::SeqCst);
        let mut registry = gated_registry(None);
        registry
            .register_generated(
                &FixturePlugin::new("conformance-first", &["first.tick"], true),
                None,
                Some(Box::new(first)),
            )
            .test_ok();
        registry
            .register_generated(
                &FixturePlugin::new("conformance-second", &["second.tick"], true),
                None,
                Some(Box::new(second)),
            )
            .test_ok();

        let failed = expect_err(pass(&mut registry, backend.as_mut(), timeline, None));
        capture.record(store, "failed-pass", failed);
        capture.record(
            store,
            "failed-pass.committed",
            events(backend.as_ref(), timeline).len(),
        );
        capture.record(store, "first.aborted", first_aborts.load(Ordering::SeqCst));

        failing.store(false, Ordering::SeqCst);
        let committed = pass(&mut registry, backend.as_mut(), timeline, None).test_ok();
        let order: Vec<String> = events(backend.as_ref(), timeline)
            .iter()
            .map(|event| format!("{}@{}", event.event_type.as_str(), event.seq.as_u64()))
            .collect();
        capture.record(store, "next-pass.committed", committed);
        capture.record(store, "next-pass.order", order.join(","));
    }
    capture
}

/// PCF-REC-001: after a disconnect following the commit, an exact retry on
/// the restarted store returns the original receipt without approval.
pub(super) fn disconnect_after_commit() -> Capture {
    let mut capture = Capture::default();
    let directory = tempfile::tempdir().test_ok();
    let path = directory
        .path()
        .join("disconnect.sqlite")
        .to_string_lossy()
        .into_owned();
    let open = || -> Box<dyn ScheduledAdmissionStoreV1> {
        let mut store = SqliteStore::open(&path).test_ok();
        EventStore::bind_erasure_gate(
            &mut store,
            Arc::new(ErasureContainmentGateV1::new_test_open()),
        )
        .test_ok();
        Box::new(store)
    };
    let actor = EntityId::new();
    let (timeline, attempt, lost) = {
        let mut fixture = host_fixture(open(), None);
        let attempt = human_admission(fixture.timeline, 1, 0, fixture.revisions);
        let lost = fixture
            .registry
            .admit_human_action(fixture.store.as_mut(), &proposal(actor, b"walk"), &attempt)
            .test_ok();
        (fixture.timeline, attempt, lost)
    };

    let mut restarted = open();
    let approvals = Arc::new(AtomicUsize::new(0));
    let mut registry = gated_registry(None);
    register_action_plugin(&mut registry, &approvals, None);
    let recovered = registry
        .admit_human_action(restarted.as_mut(), &proposal(actor, b"walk"), &attempt)
        .test_ok();
    capture.record("sqlite", "first.recovered", lost.recovered());
    capture.record("sqlite", "retry.recovered", recovered.recovered());
    capture.record(
        "sqlite",
        "retry.receipt-equal",
        recovered.receipt() == lost.receipt(),
    );
    capture.record(
        "sqlite",
        "retry.approvals",
        approvals.load(Ordering::SeqCst),
    );
    capture.record(
        "sqlite",
        "committed",
        events(restarted.as_ref(), timeline).len(),
    );
    capture
}

/// PCF-REC-002: a lost commit acknowledgement on either ingress path is
/// recovered from committed evidence without rerunning approval or a Driver.
pub(super) fn lost_acknowledgement_recovery() -> Capture {
    let mut capture = Capture::default();
    for (store, backend) in stores() {
        let mut fixture = host_fixture(backend, None);
        let actor = EntityId::new();
        let attempt = human_admission(fixture.timeline, 1, 0, fixture.revisions);
        let lost = expect_err(fixture.registry.admit_human_action(
            &mut LostOutcomePort(fixture.store.as_mut()),
            &proposal(actor, b"walk"),
            &attempt,
        ));
        let committed_before_retry = fixture.committed();
        let retry = fixture
            .registry
            .admit_human_action(fixture.store.as_mut(), &proposal(actor, b"walk"), &attempt)
            .test_ok();
        capture.record(store, "human.lost", human_outcome(&lost));
        capture.record(
            store,
            "human.committed-before-retry",
            committed_before_retry,
        );
        capture.record(store, "human.retry-recovered", retry.recovered());
        capture.record(store, "human.approvals", fixture.approvals());
        capture.record(store, "human.committed", fixture.committed());
    }
    for (store, mut backend) in stores() {
        let timeline = backend.create_timeline("scheduled-recovery").test_ok().id();
        let entity = EntityId::new();
        let driver = ScriptedDriver::new("conformance-ai", vec![draft(entity, "ai.tick", b"1")]);
        let steps = Arc::clone(&driver.steps);
        let mut registry = gated_registry(None);
        registry
            .register_generated(
                &FixturePlugin::new("conformance-ai", &["ai.tick"], true),
                None,
                Some(Box::new(driver)),
            )
            .test_ok();
        let revisions = LocalScheduledAdmissionHostV1::shared()
            .test_ok()
            .observe(&registry, backend.as_mut(), timeline)
            .test_ok();
        let (head, _) = stage(&mut registry, backend.as_ref(), timeline, None).test_ok();
        let admission = ScheduledPassAdmissionV1 {
            attempt_id: PipelineAttemptIdV1::try_new([9; 16]).test_ok(),
            idempotency: AppendIdentity::new(
                AppendDedupKey::from_keyed_hash([9; 32]),
                AppendDedupScope::from_keyed_hash([10; 32]),
            ),
            provider_validation: PipelineEvidenceRefV1::try_new(Hash::from_bytes([11; 32]))
                .test_ok(),
            security_revisions: revisions,
            commit_head: head,
            commit_now_secs: 0,
        };
        let lost = expect_err(
            registry.admit_scheduled_pass(&mut LostOutcomePort(backend.as_mut()), &admission),
        );
        let committed_before_recovery = events(backend.as_ref(), timeline).len();
        let recovered = registry
            .recover_scheduled_pass(backend.as_mut())
            .test_ok()
            .test_ok();
        capture.record(
            store,
            "scheduled.lost",
            matches!(
                lost,
                RuntimeError::Store(CoreError::StorageOutcomeUnknown(_))
            ),
        );
        capture.record(
            store,
            "scheduled.committed-before-recovery",
            committed_before_recovery,
        );
        capture.record(
            store,
            "scheduled.recovered-events",
            recovered.committed_events().len(),
        );
        capture.record(
            store,
            "scheduled.driver-steps",
            steps.load(Ordering::SeqCst),
        );
        capture.record(
            store,
            "scheduled.committed",
            events(backend.as_ref(), timeline).len(),
        );
    }
    capture
}

/// PCF-REC-003: an exact retry returns the retained receipt without
/// approval; the same key for another attempt is a typed conflict.
pub(super) fn exact_retry_and_conflict() -> Capture {
    let mut capture = Capture::default();
    for (store, backend) in stores() {
        let mut fixture = host_fixture(backend, None);
        let actor = EntityId::new();
        let timeline = fixture.timeline;
        let first = human_admission(timeline, 1, 0, fixture.revisions);
        let committed = fixture
            .registry
            .admit_human_action(fixture.store.as_mut(), &proposal(actor, b"first"), &first)
            .test_ok();
        fixture
            .registry
            .admit_human_action(
                fixture.store.as_mut(),
                &proposal(actor, b"second"),
                &human_admission(timeline, 2, 1, fixture.revisions),
            )
            .test_ok();
        // The Logical Head moved, so only the retained receipt can answer.
        let retry = fixture
            .registry
            .admit_human_action(fixture.store.as_mut(), &proposal(actor, b"first"), &first)
            .test_ok();
        let mut reused = human_admission(timeline, 1, 2, fixture.revisions);
        reused.attempt_id = PipelineAttemptIdV1::try_new([42; 16]).test_ok();
        let conflict = expect_err(fixture.registry.admit_human_action(
            fixture.store.as_mut(),
            &proposal(actor, b"other"),
            &reused,
        ));
        capture.record(store, "retry.recovered", retry.recovered());
        capture.record(
            store,
            "retry.receipt-equal",
            retry.receipt() == committed.receipt(),
        );
        capture.record(store, "conflict", conflict);
        capture.record(store, "approvals", fixture.approvals());
        capture.record(store, "committed", fixture.committed());
    }
    capture
}

/// PCF-RPL-001: Replay folds committed Events and never resubmits a
/// proposal to its approver or reruns a Driver.
pub(super) fn replay_never_resubmits() -> Capture {
    let mut capture = Capture::default();
    for (store, backend) in stores() {
        let entity = EntityId::new();
        let driver = ScriptedDriver::new("conformance-ai", vec![draft(entity, ACTION, b"move")]);
        let steps = Arc::clone(&driver.steps);
        let mut fixture = host_fixture(backend, Some(driver));
        let timeline = fixture.timeline;
        let head = fixture.store.logical_head(timeline).test_ok();
        LocalScheduledAdmissionHostV1::shared()
            .test_ok()
            .admit_action(
                &fixture.registry,
                fixture.store.as_mut(),
                &proposal(entity, b"move"),
                fixture.revisions,
                (timeline, head),
            )
            .test_ok();
        pass(
            &mut fixture.registry,
            fixture.store.as_mut(),
            timeline,
            None,
        )
        .test_ok();
        let committed = events(fixture.store.as_ref(), timeline);
        let head = fixture.store.logical_head(timeline).test_ok();

        let mut replay = PluginRegistry::new_replay()
            .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()));
        let replay_driver = ScriptedDriver {
            steps: Arc::clone(&steps),
            ..ScriptedDriver::new("conformance-ai", vec![draft(entity, ACTION, b"move")])
        };
        register_action_plugin(&mut replay, &fixture.approvals, Some(replay_driver));
        replay.fold_events(timeline, &committed);
        let replay_step =
            expect_err(replay.step_all_anchored_with_events(timeline, head, &committed));
        let replay_submit = expect_err(replay.submit_action(timeline, &proposal(entity, b"move")));

        capture.record(store, "live.committed", committed.len());
        capture.record(
            store,
            "replay.step",
            matches!(replay_step, RuntimeError::ModeMismatch { .. }),
        );
        capture.record(
            store,
            "replay.submit",
            matches!(
                replay_submit,
                ActionSubmissionError::Rejected(ActionRejected::UnknownEventType)
            ),
        );
        capture.record(store, "approvals", fixture.approvals());
        capture.record(store, "driver.steps", steps.load(Ordering::SeqCst));
        capture.record(store, "committed-after-replay", fixture.committed());
    }
    capture
}

/// PCF-EVL-001: evaluation names its range and cut, carries the
/// non-participant profile, and cannot append, approve or change evidence.
pub(super) fn evaluation_non_authority() -> Capture {
    let mut capture = Capture::default();
    let (_directory, configs) = experiment_stores();
    for (store, config) in configs {
        let actor = EntityId::new();
        let approvals = Arc::new(AtomicUsize::new(0));
        let driver = ScriptedDriver::new("conformance-ai", vec![draft(actor, ACTION, b"move")]);
        let enabled = Arc::clone(&driver.enabled);
        let mut session = parity_session(config, &approvals, driver);
        session
            .register_pipeline_evaluator(Box::new(CommittedRangeIntegrityEvaluatorV1))
            .test_ok();
        session.submit_action(&proposal(actor, b"move")).test_ok();
        session.step_tick().test_ok();
        enabled.store(false, Ordering::SeqCst);
        let events_before = session.source_events().test_ok();
        let evidence_before = session.last_pipeline_evidence().test_ok().clone();
        let approvals_before = approvals.load(Ordering::SeqCst);

        let record = session
            .evaluate_pipeline_evidence(INTEGRITY, &exact_claim())
            .test_ok()
            .test_ok();
        let integrity = match record.outcome() {
            PipelineEvaluationOutcomeV1::EventIntegrity(integrity) => {
                format!(
                    "checked={},intact={}",
                    integrity.checked_events, integrity.intact
                )
            }
            other => format!("{other:?}"),
        };
        capture.record(store, "integrity", integrity);
        capture.record(
            store,
            "names-committed-range",
            record.committed_range() == evidence_before.committed_range(),
        );
        capture.record(
            store,
            "events-unchanged",
            session.source_events().test_ok() == events_before,
        );
        capture.record(
            store,
            "evidence-unchanged",
            session.last_pipeline_evidence() == Some(&evidence_before),
        );
        capture.record(
            store,
            "approvals-unchanged",
            approvals.load(Ordering::SeqCst) == approvals_before,
        );
        capture.record(
            store,
            "next-boundary",
            matches!(session.step_tick().test_ok(), TickOutcome::Quiescent),
        );
        capture.record(
            store,
            super::harness::PROFILE_KEY,
            profile_tag(record.observation_profile()),
        );
    }
    capture
}
