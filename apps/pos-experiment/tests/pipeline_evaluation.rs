//! ADR-021 section 5 (#320): commit, Projection fold, and evaluation evidence
//! through the experiment session's public seams.

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex, MutexGuard,
};

use pos_core::{
    clock::Seq,
    event::{CanonicalBytes, Event, EventDraft, Kind},
    ids::{EntityId, PluginId, TimelineId},
    plugin::{ActionApprover, ActionRejected, Capability, Plugin, ProposedAction},
    store::{EventStore, PurgeOutcome},
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactRedactionStateV1,
    ArtifactStateV1, ArtifactTransitionRuleV1, AuthorityCommitOutcomeV1, AuthorityMutationPermitV1,
    AuthorityPersistenceBindingV1, AuthorityPersistenceErrorV1, AuthorityPersistencePortV1,
    CapabilityGrantV1, CapabilityRevocationV1, ConsentAuthority, CoreError, ErasureArtifactClassV1,
    ErasureContainmentGateV1, ErasureKeyRoleV1, ErasureReferenceV1, ErasureReplayClaimV1, Hash,
    PersistedAuthorityV1, PipelineAdmissionBasisV1, PipelineAdmissionFencePublisherV1,
    PipelineAdmissionFenceV1, PipelineAdmissionPortV1, PipelineIngressV1, PipelineOutcomeV1,
    RegisteredArtifactV1, ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1, Timeline,
};
use pos_experiment::{
    CalibrationReportEvaluatorV1, CommittedRangeIntegrityEvaluatorV1, Experiment, ExperimentConfig,
    ExperimentError, ExperimentSession, PipelineEvaluationClassV1, PipelineEvaluationInputV1,
    PipelineEvaluationOutcomeV1, PipelineEvaluationRecordV1, PipelineEvaluationScopeV1,
    PipelineEvaluationUnavailableV1, PipelineEvaluatorOutputV1, PipelineEvaluatorV1,
    PipelineEventIntegrityV1, StopCondition, TickOutcome,
};
use pos_plugin_eval::{
    draft_outcome, draft_prediction, CalibrationReport, EvalPlugin, EvalReducer,
    EVENT_TYPE_OUTCOME, EVENT_TYPE_PREDICTION,
};
use pos_runtime::{Driver, ObservationView, RuntimeError, StepOutput};
use pos_store::{memory::MemoryStore, SeqRange, StoreConfig};

trait TestValueExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
        })
    }
}

impl<T> TestValueExt<T> for Option<T> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test value")))
    }
}

const EVIDENCE_EVENT: &str = "fixture.evidence";
const INTEGRITY: &str = "committed-range-integrity";
const CALIBRATION: &str = "calibration-report";
const REPORT: ErasureReferenceV1 = ErasureReferenceV1::from_digest([0x41; 32]);

// ── Fixtures ────────────────────────────────────────────────────────────────

struct EvidencePlugin {
    id: PluginId,
}

impl Plugin for EvidencePlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "evidence"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(EVIDENCE_EVENT)],
            owned_entity_kinds: Vec::new(),
            has_driver: true,
            has_reducer: false,
        }
    }
}

/// Forwards every proposal and counts approvals, so a resubmission is visible.
struct CountingApprover {
    approvals: Arc<AtomicU64>,
}

impl ActionApprover for CountingApprover {
    fn approve(&self, proposal: &ProposedAction) -> Result<EventDraft, ActionRejected> {
        self.approvals.fetch_add(1, Ordering::SeqCst);
        Ok(EventDraft::new(
            proposal.actor_entity_id,
            proposal.event_type.clone(),
            proposal.payload.clone(),
        ))
    }
}

/// Emits two Events per scheduled pass while enabled.
struct PairDriver {
    entity: EntityId,
    enabled: Arc<AtomicBool>,
}

impl Driver for PairDriver {
    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        let drafts = if self.enabled.load(Ordering::SeqCst) {
            (0_u8..2)
                .map(|index| {
                    EventDraft::new(
                        self.entity,
                        Kind::new(EVIDENCE_EVENT),
                        CanonicalBytes::from_vec(vec![b'a', index]),
                    )
                })
                .collect()
        } else {
            Vec::new()
        };
        Ok(StepOutput::new(drafts))
    }

    fn name(&self) -> &'static str {
        "evidence-pair"
    }
}

struct Fixture {
    approvals: Arc<AtomicU64>,
    driver_enabled: Arc<AtomicBool>,
    actor: EntityId,
}

impl Fixture {
    fn new() -> Self {
        Self {
            approvals: Arc::new(AtomicU64::new(0)),
            driver_enabled: Arc::new(AtomicBool::new(false)),
            actor: EntityId::new(),
        }
    }

    fn experiment(&self, name: &str, store_config: StoreConfig) -> Experiment {
        let mut experiment = Experiment::new(ExperimentConfig {
            name: name.to_owned(),
            stop: StopCondition::MaxTicks(16),
            store_config,
        });
        experiment
            .register_generated_with_approver(
                &EvidencePlugin {
                    id: PluginId::new(),
                },
                None,
                Some(Box::new(PairDriver {
                    entity: self.actor,
                    enabled: Arc::clone(&self.driver_enabled),
                })),
                Some(Box::new(CountingApprover {
                    approvals: Arc::clone(&self.approvals),
                })),
                [Kind::new(EVIDENCE_EVENT)],
            )
            .test_ok();
        experiment
            .register_generated_with_approver(
                &EvalPlugin::new(),
                Some(Box::new(EvalReducer)),
                None,
                Some(Box::new(CountingApprover {
                    approvals: Arc::clone(&self.approvals),
                })),
                [
                    Kind::new(EVENT_TYPE_PREDICTION),
                    Kind::new(EVENT_TYPE_OUTCOME),
                ],
            )
            .test_ok();
        experiment
    }

    fn proposal(&self, event_type: &str, payload: CanonicalBytes) -> ProposedAction {
        ProposedAction::new(
            Kind::new(event_type),
            self.actor,
            payload,
            Kind::new(format!("{event_type}.submit")),
        )
    }

    fn evidence_action(&self) -> ProposedAction {
        self.proposal(EVIDENCE_EVENT, CanonicalBytes::from_static(b"human"))
    }

    fn prediction(&self) -> ProposedAction {
        let draft = draft_prediction(self.actor, "subject", 0.8, "p1");
        self.proposal(EVENT_TYPE_PREDICTION, draft.payload)
    }

    fn outcome(&self) -> ProposedAction {
        let draft = draft_outcome(self.actor, "p1", true);
        self.proposal(EVENT_TYPE_OUTCOME, draft.payload)
    }

    fn approvals(&self) -> u64 {
        self.approvals.load(Ordering::SeqCst)
    }
}

fn claim(rule: ArtifactTransitionRuleV1, state: ArtifactStateV1) -> ReplayClaimEvaluationV1 {
    ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::Exact,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::CalibrationReport,
                REPORT,
                ArtifactDataClassV1::AggregateData,
                Some(ErasureKeyRoleV1::DataEncryption),
                ErasureReferenceV1::from_digest([0x42; 32]),
                ArtifactOptionalityV1::Required,
                rule,
            ),
            current_claim: ErasureReplayClaimV1::Exact,
            state,
        }],
    )
    .test_ok()
}

fn exact() -> ReplayClaimEvaluationV1 {
    claim(
        ArtifactTransitionRuleV1::PreserveExact,
        ArtifactStateV1::Retained,
    )
}

fn redacted() -> ReplayClaimEvaluationV1 {
    claim(
        ArtifactTransitionRuleV1::RedactViews,
        ArtifactStateV1::TransitionApplied,
    )
}

fn structural() -> ReplayClaimEvaluationV1 {
    claim(
        ArtifactTransitionRuleV1::RetainStructure,
        ArtifactStateV1::TransitionApplied,
    )
}

fn evaluate(
    session: &ExperimentSession,
    evaluator: &'static str,
    claim: &ReplayClaimEvaluationV1,
) -> PipelineEvaluationRecordV1 {
    session
        .evaluate_pipeline_evidence(evaluator, claim)
        .test_ok()
        .test_ok()
}

const fn unavailable(
    record: &PipelineEvaluationRecordV1,
) -> Option<PipelineEvaluationUnavailableV1> {
    match record.outcome() {
        PipelineEvaluationOutcomeV1::Unavailable(reason) => Some(*reason),
        _ => None,
    }
}

const fn integrity(record: &PipelineEvaluationRecordV1) -> Option<PipelineEventIntegrityV1> {
    match record.outcome() {
        PipelineEvaluationOutcomeV1::EventIntegrity(integrity) => Some(*integrity),
        _ => None,
    }
}

fn sqlite_config(directory: &tempfile::TempDir, name: &str) -> StoreConfig {
    StoreConfig::Sqlite {
        path: directory.path().join(name).to_string_lossy().into_owned(),
    }
}

// ── Human and AI paths on MemoryStore and SQLite ───────────────────────────

/// Commit one human action and one scheduled AI pass, and check that each
/// evidence record names its exact committed range and the folding cut.
fn assert_human_and_ai_evidence(store_config: StoreConfig) {
    let fixture = Fixture::new();
    let mut session = fixture
        .experiment("pipeline-evidence", store_config)
        .start()
        .test_ok();
    assert!(session.last_pipeline_evidence().is_none());
    assert!(session
        .evaluate_pipeline_evidence(INTEGRITY, &exact())
        .test_ok()
        .is_none());
    session
        .register_pipeline_evaluator(Box::new(CommittedRangeIntegrityEvaluatorV1))
        .test_ok();

    assert_eq!(
        session.submit_action(&fixture.evidence_action()).test_ok(),
        1
    );
    let human = session.last_pipeline_evidence().test_ok().clone();
    let committed: Vec<Event> = session.source_events().test_ok();
    let last = committed.last().test_ok();
    assert_eq!(human.ingress(), PipelineIngressV1::HumanProposedAction);
    assert_eq!(
        human.committed_range().timeline_id(),
        session.timeline().id()
    );
    assert_eq!(human.committed_range().first(), last.seq);
    assert_eq!(human.committed_range().last(), last.seq);
    assert_eq!(human.receipt().committed_events()[0].event_id(), last.id);
    let human_cut = human.projection_cut().test_ok();
    assert_eq!(human_cut.timeline_id(), session.timeline().id());
    assert_eq!(human_cut.folded_through(), last.seq);

    let record = evaluate(&session, INTEGRITY, &exact());
    assert_eq!(record.evaluator(), INTEGRITY);
    assert_eq!(record.committed_range(), human.committed_range());
    assert_eq!(record.projection_cut(), None, "event-only names no cut");
    assert_eq!(record.replay_claim(), ErasureReplayClaimV1::Exact);
    assert_eq!(record.redaction_state(), ArtifactRedactionStateV1::None);
    assert_eq!(
        integrity(&record),
        Some(PipelineEventIntegrityV1 {
            checked_events: 1,
            intact: true,
        })
    );

    fixture.driver_enabled.store(true, Ordering::SeqCst);
    assert!(matches!(
        session.step_tick().test_ok(),
        TickOutcome::Advanced {
            emitted_events: 2,
            ..
        }
    ));
    let ai = session.last_pipeline_evidence().test_ok().clone();
    assert_eq!(ai.ingress(), PipelineIngressV1::ScheduledAiDriver);
    let range = ai.committed_range();
    assert_eq!(range.first().as_u64() + 1, range.last().as_u64());
    assert!(range.first() > human.committed_range().last());
    let ai_cut = ai.projection_cut().test_ok();
    assert!(ai_cut.contains(range));
    assert_eq!(
        integrity(&evaluate(&session, INTEGRITY, &exact())),
        Some(PipelineEventIntegrityV1 {
            checked_events: 2,
            intact: true,
        })
    );

    // A boundary that commits nothing keeps the first cut that folded the range.
    fixture.driver_enabled.store(false, Ordering::SeqCst);
    session.step_tick().test_ok();
    assert_eq!(session.last_pipeline_evidence(), Some(&ai));
}

#[test]
fn memory_human_and_ai_commits_name_their_range_and_folding_cut() {
    assert_human_and_ai_evidence(StoreConfig::Memory);
}

#[test]
fn sqlite_human_and_ai_commits_name_their_range_and_folding_cut() {
    let directory = tempfile::tempdir().test_ok();
    assert_human_and_ai_evidence(sqlite_config(&directory, "pipeline-evidence.sqlite"));
}

// ── State-dependent evaluation ─────────────────────────────────────────────

#[test]
fn calibration_report_waits_for_and_names_the_folding_cut() {
    let fixture = Fixture::new();
    let mut session = fixture
        .experiment("pipeline-calibration", StoreConfig::Memory)
        .start()
        .test_ok();
    session
        .register_pipeline_evaluator(Box::new(CalibrationReportEvaluatorV1::new(REPORT)))
        .test_ok();
    assert!(matches!(
        session.register_pipeline_evaluator(Box::new(CalibrationReportEvaluatorV1::new(REPORT))),
        Err(ExperimentError::DuplicatePipelineEvaluator)
    ));

    session.submit_action(&fixture.prediction()).test_ok();
    let unresolved = evaluate(&session, CALIBRATION, &exact());
    assert!(
        matches!(
            unresolved.outcome(),
            PipelineEvaluationOutcomeV1::InsufficientEvidence
        ),
        "an unresolved prediction yields no fabricated report"
    );

    session.submit_action(&fixture.outcome()).test_ok();
    let evidence = session.last_pipeline_evidence().test_ok().clone();
    let record = evaluate(&session, CALIBRATION, &exact());
    assert_eq!(record.evaluator(), CALIBRATION);
    assert_eq!(record.committed_range(), evidence.committed_range());
    assert_eq!(record.projection_cut(), evidence.projection_cut());
    assert!(record
        .projection_cut()
        .test_ok()
        .contains(evidence.committed_range()));
    let PipelineEvaluationOutcomeV1::CalibrationReport(report) = record.outcome() else {
        std::panic::resume_unwind(Box::new(format!("expected a report: {record:?}")));
    };
    assert_eq!(report.n_predictions, 1);
    assert_eq!(report.n_resolved, 1);
    assert!((report.brier_score - 0.04).abs() < 1e-12);
}

#[test]
fn sqlite_calibration_rejects_an_unregistered_report_artifact() {
    let directory = tempfile::tempdir().test_ok();
    let fixture = Fixture::new();
    let mut session = fixture
        .experiment(
            "pipeline-calibration-artifact",
            sqlite_config(&directory, "pipeline-calibration.sqlite"),
        )
        .start()
        .test_ok();
    session
        .register_pipeline_evaluator(Box::new(CalibrationReportEvaluatorV1::new(
            ErasureReferenceV1::from_digest([0x43; 32]),
        )))
        .test_ok();
    session.submit_action(&fixture.prediction()).test_ok();
    session.submit_action(&fixture.outcome()).test_ok();
    let record = evaluate(&session, CALIBRATION, &exact());
    assert_eq!(
        unavailable(&record),
        Some(PipelineEvaluationUnavailableV1::EvidenceUnavailable)
    );
}

// ── Missing Plugin, redaction, and insufficient evidence ───────────────────

#[test]
fn missing_evaluator_is_a_typed_unavailable_state_not_a_default() {
    let fixture = Fixture::new();
    let mut session = fixture
        .experiment("pipeline-missing-evaluator", StoreConfig::Memory)
        .start()
        .test_ok();
    session.submit_action(&fixture.evidence_action()).test_ok();
    for name in [INTEGRITY, CALIBRATION, "absent"] {
        let record = evaluate(&session, name, &exact());
        assert_eq!(record.evaluator(), name);
        assert_eq!(
            unavailable(&record),
            Some(PipelineEvaluationUnavailableV1::MissingEvaluator)
        );
        assert_eq!(record.projection_cut(), None);
    }
}

#[test]
fn redacted_or_erased_evidence_only_preserves_or_weakens_the_claim() {
    let fixture = Fixture::new();
    let mut session = fixture
        .experiment("pipeline-redaction", StoreConfig::Memory)
        .start()
        .test_ok();
    session
        .register_pipeline_evaluator(Box::new(CommittedRangeIntegrityEvaluatorV1))
        .test_ok();
    session
        .register_pipeline_evaluator(Box::new(CalibrationReportEvaluatorV1::new(REPORT)))
        .test_ok();
    session.submit_action(&fixture.prediction()).test_ok();
    session.submit_action(&fixture.outcome()).test_ok();

    let event_only = evaluate(&session, INTEGRITY, &redacted());
    assert_eq!(
        event_only.replay_claim(),
        ErasureReplayClaimV1::ExactAuthoritativeWithRedactedViews
    );
    assert_eq!(
        event_only.redaction_state(),
        ArtifactRedactionStateV1::RedactedViews
    );
    assert!(integrity(&event_only).test_ok().intact);

    let state = evaluate(&session, CALIBRATION, &redacted());
    assert_eq!(
        unavailable(&state),
        Some(PipelineEvaluationUnavailableV1::EvidenceUnavailable)
    );
    assert_eq!(
        state.redaction_state(),
        ArtifactRedactionStateV1::RedactedViews
    );

    for name in [INTEGRITY, CALIBRATION] {
        let erased = evaluate(&session, name, &structural());
        assert_eq!(erased.replay_claim(), ErasureReplayClaimV1::StructuralOnly);
        assert_eq!(
            erased.redaction_state(),
            ArtifactRedactionStateV1::StructuralOnly
        );
        assert_eq!(
            unavailable(&erased),
            Some(PipelineEvaluationUnavailableV1::EvidenceUnavailable)
        );
    }
}

// ── Evaluator non-authority ────────────────────────────────────────────────

/// An event-only evaluator that forges a state-dependent Calibration Report.
struct ForgingEvaluator;

impl PipelineEvaluatorV1 for ForgingEvaluator {
    fn name(&self) -> &'static str {
        "forging"
    }

    fn scope(&self) -> PipelineEvaluationScopeV1 {
        PipelineEvaluationScopeV1::EventOnly
    }

    fn evaluate(&self, _: &PipelineEvaluationInputV1<'_>) -> PipelineEvaluatorOutputV1 {
        PipelineEvaluatorOutputV1::CalibrationReport(Box::new(CalibrationReport {
            replay_claim: ErasureReplayClaimV1::Exact,
            redaction_state: ArtifactRedactionStateV1::None,
            brier_score: 0.0,
            crps: 0.0,
            lift_vs_personal_base_rate: 1.0,
            ece: 0.0,
            lift_vs_population_avg: 1.0,
            lift_vs_persistence: 1.0,
            n_predictions: 1_000,
            n_resolved: 1_000,
            reliability_bins: Vec::new(),
        }))
    }
}

/// A state-dependent evaluator that rewrites its copies of the evidence.
struct TamperingEvaluator {
    seen: Arc<Mutex<Vec<usize>>>,
}

impl PipelineEvaluatorV1 for TamperingEvaluator {
    fn name(&self) -> &'static str {
        "tampering"
    }

    fn scope(&self) -> PipelineEvaluationScopeV1 {
        PipelineEvaluationScopeV1::StateDependent
    }

    fn evaluate(&self, input: &PipelineEvaluationInputV1<'_>) -> PipelineEvaluatorOutputV1 {
        let mut copies = input.folded_prefix().to_vec();
        for event in &mut copies {
            event.payload = CanonicalBytes::from_static(b"rewritten");
            event.seq = Seq::from_u64(event.seq.as_u64() + 100);
        }
        self.seen.lock().test_ok().push(copies.len());
        PipelineEvaluatorOutputV1::StateEvaluation(Hash::from_bytes([0x44; 32]))
    }
}

#[test]
fn evaluators_cannot_mutate_the_world_widen_their_class_or_resubmit() {
    let fixture = Fixture::new();
    let mut session = fixture
        .experiment("pipeline-non-authority", StoreConfig::Memory)
        .start()
        .test_ok();
    let seen = Arc::new(Mutex::new(Vec::new()));
    session
        .register_pipeline_evaluator(Box::new(ForgingEvaluator))
        .test_ok();
    session
        .register_pipeline_evaluator(Box::new(TamperingEvaluator {
            seen: Arc::clone(&seen),
        }))
        .test_ok();
    session.submit_action(&fixture.evidence_action()).test_ok();
    session.submit_action(&fixture.evidence_action()).test_ok();
    let events_before = session.source_events().test_ok();
    let evidence_before = session.last_pipeline_evidence().test_ok().clone();
    let approvals_before = fixture.approvals();
    assert_eq!(approvals_before, 2);

    let forged = evaluate(&session, "forging", &exact());
    assert_eq!(
        unavailable(&forged),
        Some(PipelineEvaluationUnavailableV1::InvalidEvaluatorOutput)
    );
    assert_eq!(
        PipelineEvaluationClassV1::CalibrationReport.scope(),
        PipelineEvaluationScopeV1::StateDependent
    );
    assert_eq!(
        PipelineEvaluationClassV1::EventIntegrity.scope(),
        PipelineEvaluationScopeV1::EventOnly
    );

    let tampered = evaluate(&session, "tampering", &exact());
    assert!(matches!(
        tampered.outcome(),
        PipelineEvaluationOutcomeV1::StateEvaluation(digest) if *digest == Hash::from_bytes([0x44; 32])
    ));
    assert_eq!(tampered.projection_cut(), evidence_before.projection_cut());
    assert_eq!(*seen.lock().test_ok(), vec![events_before.len()]);

    // Evaluation appended nothing, changed no committed Event, left the
    // evidence unchanged, and never re-ran the owning ActionApprover.
    assert_eq!(session.source_events().test_ok(), events_before);
    assert_eq!(session.last_pipeline_evidence(), Some(&evidence_before));
    assert_eq!(fixture.approvals(), approvals_before);
    assert!(matches!(
        session.step_tick().test_ok(),
        TickOutcome::Quiescent
    ));
}

#[test]
fn integrity_adapter_detects_every_mismatch_in_its_input() {
    let fixture = Fixture::new();
    let mut session = fixture
        .experiment("pipeline-integrity-adapter", StoreConfig::Memory)
        .start()
        .test_ok();
    session.submit_action(&fixture.evidence_action()).test_ok();
    let evidence = session.last_pipeline_evidence().test_ok().clone();
    let claim = exact();
    let committed = session.source_events().test_ok();
    let evaluate_events = |events: &[Event]| {
        let input = PipelineEvaluationInputV1::new(&evidence, &claim, events, &[]);
        assert_eq!(input.evidence(), &evidence);
        assert_eq!(input.claim(), &claim);
        assert!(input.folded_prefix().is_empty());
        match CommittedRangeIntegrityEvaluatorV1.evaluate(&input) {
            PipelineEvaluatorOutputV1::EventIntegrity(integrity) => integrity,
            other => std::panic::resume_unwind(Box::new(format!("unexpected output {other:?}"))),
        }
    };

    assert_eq!(
        evaluate_events(&committed),
        PipelineEventIntegrityV1 {
            checked_events: 1,
            intact: true,
        }
    );
    assert_eq!(
        evaluate_events(&[]),
        PipelineEventIntegrityV1 {
            checked_events: 0,
            intact: false,
        }
    );
    let mut wrong_id = committed.clone();
    wrong_id[0].id = pos_core::ids::EventId::new();
    assert!(!evaluate_events(&wrong_id).intact);
    let mut wrong_seq = committed;
    wrong_seq[0].seq = Seq::from_u64(wrong_seq[0].seq.as_u64() + 1);
    assert!(!evaluate_events(&wrong_seq).intact);
}

#[test]
fn closed_consent_scope_refuses_evaluation() {
    let fixture = Fixture::new();
    let mut session = fixture
        .experiment("pipeline-consent", StoreConfig::Memory)
        .with_consent_authority(ConsentAuthority::new())
        .start()
        .test_ok();
    session
        .register_pipeline_evaluator(Box::new(CommittedRangeIntegrityEvaluatorV1))
        .test_ok();
    session.submit_action(&fixture.evidence_action()).test_ok();
    assert!(integrity(&evaluate(&session, INTEGRITY, &exact())).is_some());

    session.close_session_at_boundary();
    assert!(matches!(
        session.evaluate_pipeline_evidence(INTEGRITY, &exact()),
        Err(ExperimentError::ConsentRevokedV1)
    ));
    session.step_tick().test_ok();
    assert!(matches!(
        session.evaluate_pipeline_evidence(INTEGRITY, &exact()),
        Err(ExperimentError::ConsentRevokedV1)
    ));
}

// ── Fold failure ───────────────────────────────────────────────────────────

/// Delegates to a `MemoryStore`, and once armed fails every Logical Head read
/// after the next admitted batch commits, so the post-commit fold fails.
#[derive(Clone)]
struct FoldFaultStore {
    store: Arc<Mutex<MemoryStore>>,
    armed: Arc<AtomicBool>,
    failing: Arc<AtomicBool>,
    gate: Arc<ErasureContainmentGateV1>,
    gate_bound: Arc<AtomicBool>,
}

impl FoldFaultStore {
    fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(MemoryStore::new())),
            armed: Arc::new(AtomicBool::new(false)),
            failing: Arc::new(AtomicBool::new(false)),
            gate: Arc::new(ErasureContainmentGateV1::new_test_open()),
            gate_bound: Arc::new(AtomicBool::new(false)),
        }
    }

    fn store(&self) -> MutexGuard<'_, MemoryStore> {
        self.store.lock().test_ok()
    }
}

impl EventStore for FoldFaultStore {
    fn bind_erasure_gate(&mut self, gate: Arc<ErasureContainmentGateV1>) -> Result<(), CoreError> {
        if self.gate_bound.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.store().bind_erasure_gate(gate)
    }

    fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
        self.store().create_timeline(name)
    }

    fn append(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        self.store().append(timeline, drafts)
    }

    fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        self.store().read(timeline, range)
    }

    fn fork(&mut self, parent: TimelineId, at_seq: Seq, name: &str) -> Result<Timeline, CoreError> {
        self.store().fork(parent, at_seq, name)
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
        self.store().list_timelines()
    }

    fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
        self.store().get_timeline(id)
    }

    fn logical_head(&self, id: TimelineId) -> Result<Seq, CoreError> {
        if self.failing.load(Ordering::SeqCst) {
            return Err(CoreError::Storage(
                "injected post-commit head failure".to_owned(),
            ));
        }
        self.store().logical_head(id)
    }
}

impl PipelineAdmissionPortV1 for FoldFaultStore {
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        let outcome = self.store().admit_pipeline_batch(basis);
        if self.armed.load(Ordering::SeqCst) {
            self.failing.store(true, Ordering::SeqCst);
        }
        outcome
    }

    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: std::num::NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        self.store().purge_expired_pipeline_receipts_bounded(limit)
    }

    fn lookup_pipeline_receipt(
        &mut self,
        timeline: TimelineId,
        key: pos_core::AppendDedupKey,
        attempt_id: pos_core::PipelineAttemptIdV1,
    ) -> Result<pos_core::PipelineReceiptLookupV1, CoreError> {
        self.store()
            .lookup_pipeline_receipt(timeline, key, attempt_id)
    }
}

impl PipelineAdmissionFencePublisherV1 for FoldFaultStore {
    fn set_pipeline_admission_fence(
        &mut self,
        timeline: TimelineId,
        fence: PipelineAdmissionFenceV1,
    ) -> Result<(), CoreError> {
        self.store().set_pipeline_admission_fence(timeline, fence)
    }

    fn pipeline_admission_fence(
        &self,
        timeline: TimelineId,
    ) -> Result<Option<PipelineAdmissionFenceV1>, CoreError> {
        self.store().pipeline_admission_fence(timeline)
    }
}

impl AuthorityPersistencePortV1 for FoldFaultStore {
    fn bind_authority_persistence(
        &mut self,
        binding: AuthorityPersistenceBindingV1,
    ) -> Result<(), AuthorityPersistenceErrorV1> {
        self.store().bind_authority_persistence(binding)
    }

    fn issue_capability_grant(
        &mut self,
        permit: AuthorityMutationPermitV1,
        grant: &CapabilityGrantV1,
    ) -> Result<AuthorityCommitOutcomeV1, AuthorityPersistenceErrorV1> {
        self.store().issue_capability_grant(permit, grant)
    }

    fn revoke_capability_grant(
        &mut self,
        permit: AuthorityMutationPermitV1,
        revocation: &CapabilityRevocationV1,
    ) -> Result<AuthorityCommitOutcomeV1, AuthorityPersistenceErrorV1> {
        self.store().revoke_capability_grant(permit, revocation)
    }

    fn load_authority(
        &self,
        leaf_grant_id: Hash,
    ) -> Result<PersistedAuthorityV1, AuthorityPersistenceErrorV1> {
        self.store().load_authority(leaf_grant_id)
    }
}

#[test]
fn fold_failure_leaves_commit_evidence_without_a_projection_cut() {
    let fixture = Fixture::new();
    let adapter = FoldFaultStore::new();
    let mut session = fixture
        .experiment("pipeline-fold-failure", StoreConfig::Memory)
        .with_erasure_gate(Arc::clone(&adapter.gate))
        .start_with_store(Box::new(adapter.clone()))
        .test_ok();
    session
        .register_pipeline_evaluator(Box::new(CommittedRangeIntegrityEvaluatorV1))
        .test_ok();
    session
        .register_pipeline_evaluator(Box::new(CalibrationReportEvaluatorV1::new(REPORT)))
        .test_ok();

    adapter.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        session.submit_action(&fixture.evidence_action()),
        Err(ExperimentError::Store(_))
    ));
    let evidence = session.last_pipeline_evidence().test_ok();
    assert_eq!(evidence.ingress(), PipelineIngressV1::HumanProposedAction);
    assert_eq!(
        evidence.projection_cut(),
        None,
        "the commit receipt never claims its state was folded"
    );

    // Event-only integrity may run after commit; state-dependent waits.
    let event_only = evaluate(&session, INTEGRITY, &exact());
    assert_eq!(
        integrity(&event_only),
        Some(PipelineEventIntegrityV1 {
            checked_events: 1,
            intact: true,
        })
    );
    let state = evaluate(&session, CALIBRATION, &exact());
    assert_eq!(
        unavailable(&state),
        Some(PipelineEvaluationUnavailableV1::ProjectionNotFolded)
    );
    assert_eq!(state.projection_cut(), None);
    assert!(matches!(
        session.step_tick(),
        Err(ExperimentError::SessionFaulted)
    ));
    assert_eq!(fixture.approvals(), 1);
}
