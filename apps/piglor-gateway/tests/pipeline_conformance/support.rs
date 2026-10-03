//! Shared public-seam fixtures for the pipeline conformance runners.

use std::{
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};

use pos_core::{
    ActionApprover, ActionRejected, AppendDedupKey, ArtifactClaimInputV1, ArtifactDataClassV1,
    ArtifactOptionalityV1, ArtifactStateV1, ArtifactTransitionRuleV1, CanonicalBytes, Capability,
    ConsentAuthority, ConsentCapabilityToken, ConsentGrantedV1, CoreError, EntityId,
    ErasureArtifactClassV1, ErasureContainmentGateV1, ErasureReferenceV1, ErasureReplayClaimV1,
    Event, EventDraft, Kind, PipelineAdmissionBasisV1, PipelineAdmissionPortV1,
    PipelineAttemptIdV1, PipelineOutcomeV1, PipelineReceiptLookupV1, Plugin, PluginId,
    ProposedAction, PurgeOutcome, Reducer, RegisteredArtifactV1, ReplayClaimEvaluationV1,
    ReplayClaimEvaluatorV1, ScheduledObservationProfileV1, Seq, SeqRange, State, TimelineId,
    MODALITY_PERSONA,
};
use pos_runtime::{
    Driver, LocalScheduledAdmissionHostV1, ObservationView, PluginRegistry, RuntimeError,
    ScheduledAdmissionStoreV1, StepOutput,
};
use pos_store::{memory::MemoryStore, sqlite::SqliteStore, StoreConfig};

/// Unwrap a fixture step, failing the runner with the unexpected error.
///
/// `resume_unwind` is deliberate: the workspace denies `unwrap`, `expect` and
/// `panic!`, and the suite harness catches the unwind and reports it as a
/// `RunnerPanicked` failure of the case rather than aborting the profile.
pub trait TestOk<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestOk<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected fixture error: {error:?}")))
        })
    }
}

impl<T> TestOk<T> for Option<T> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected a fixture value")))
    }
}

/// The error of a step that must fail, or a runner failure if it succeeds.
#[must_use]
pub fn expect_err<T: std::fmt::Debug, E>(result: Result<T, E>) -> E {
    result.map_or_else(
        |error| error,
        |value| std::panic::resume_unwind(Box::new(format!("expected a failure, got {value:?}"))),
    )
}

/// The capture tag of a scheduled observation profile.
#[must_use]
pub const fn profile_tag(profile: ScheduledObservationProfileV1) -> &'static str {
    match profile {
        ScheduledObservationProfileV1::NonParticipant => "non-participant",
        ScheduledObservationProfileV1::ParticipantBound => "participant-bound",
    }
}

/// `MemoryStore` and in-memory `SQLite`, each bound to an open erasure gate.
#[must_use]
pub fn stores() -> Vec<(&'static str, Box<dyn ScheduledAdmissionStoreV1>)> {
    let mut stores: Vec<(&'static str, Box<dyn ScheduledAdmissionStoreV1>)> = vec![
        ("memory", Box::new(MemoryStore::new())),
        ("sqlite", Box::new(SqliteStore::open(":memory:").test_ok())),
    ];
    for (_, store) in &mut stores {
        store
            .bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
            .test_ok();
    }
    stores
}

/// A registry bound to an open erasure gate and, when given, a consent authority.
#[must_use]
pub fn gated_registry(authority: Option<&ConsentAuthority>) -> PluginRegistry {
    let mut registry = PluginRegistry::new()
        .with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()));
    if let Some(authority) = authority {
        registry = registry.with_consent_authority(authority.clone());
    }
    registry
}

/// The registered Calibration Report artifact used by every evaluation.
pub const REPORT: ErasureReferenceV1 = ErasureReferenceV1::from_digest([0x41; 32]);

/// `MemoryStore` and a `SQLite` file for an experiment session; the
/// returned directory keeps the file alive.
#[must_use]
pub fn experiment_stores() -> (tempfile::TempDir, Vec<(&'static str, StoreConfig)>) {
    let directory = tempfile::tempdir().test_ok();
    let path = directory
        .path()
        .join("experiment.sqlite")
        .to_string_lossy()
        .into_owned();
    (
        directory,
        vec![
            ("memory", StoreConfig::Memory),
            ("sqlite", StoreConfig::Sqlite { path }),
        ],
    )
}

/// An exact, retained host claim for the [`REPORT`] artifact.
#[must_use]
pub fn exact_claim() -> ReplayClaimEvaluationV1 {
    ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::Exact,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::CalibrationReport,
                REPORT,
                ArtifactDataClassV1::AggregateData,
                None,
                ErasureReferenceV1::from_digest([0x42; 32]),
                ArtifactOptionalityV1::Required,
                ArtifactTransitionRuleV1::PreserveExact,
            ),
            current_claim: ErasureReplayClaimV1::Exact,
            state: ArtifactStateV1::Retained,
        }],
    )
    .test_ok()
}

/// A Persona-modality consent capability for `subject` on `timeline`.
#[must_use]
pub fn persona_token(
    authority: &ConsentAuthority,
    timeline: TimelineId,
    subject: EntityId,
) -> ConsentCapabilityToken {
    authority.record_grant_on_timeline(
        timeline,
        &ConsentGrantedV1 {
            subject_id: subject,
            grantee_id: EntityId::new(),
            purpose: "pipeline-conformance".to_owned(),
            modalities: MODALITY_PERSONA,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        },
    )
}

/// Every committed Event of `timeline`.
#[must_use]
pub fn events(store: &dyn ScheduledAdmissionStoreV1, timeline: TimelineId) -> Vec<Event> {
    store.read(timeline, SeqRange::all()).test_ok()
}

/// The committed Events of one type.
#[must_use]
pub fn of_type<'a>(events: &'a [Event], event_type: &str) -> Vec<&'a Event> {
    events
        .iter()
        .filter(|event| event.event_type.as_str() == event_type)
        .collect()
}

/// Stage one anchored pass over the complete committed prefix, protected
/// by `token` when one is given.
///
/// These runners are a host without Participants: before staging, it
/// explicitly composes every Driver it registered as non-participant
/// (ADR-021 Revision 3 Decision 2).
///
/// # Errors
///
/// Returns the composition error that refused the pass, or the runtime error
/// that discarded the staged pass.
pub fn stage(
    registry: &mut PluginRegistry,
    store: &dyn ScheduledAdmissionStoreV1,
    timeline: TimelineId,
    token: Option<&ConsentCapabilityToken>,
) -> Result<(Seq, Vec<EventDraft>), RuntimeError> {
    registry.compose_non_participant_drivers()?;
    let head = store.logical_head(timeline).test_ok();
    let prefix = store.read(timeline, SeqRange::all()).test_ok();
    if let Some(token) = token {
        return registry
            .step_all_anchored_protected(timeline, head, token.clone(), 0, &prefix)
            .map(|drafts| (head, drafts));
    }
    registry
        .step_all_anchored_with_events(timeline, head, &prefix)
        .map(|drafts| (head, drafts))
}

/// Observe, stage and atomically admit one scheduled pass through the local
/// host. Returns the number of committed drafts.
///
/// # Errors
///
/// Returns the runtime error that discarded or refused the pass.
pub fn pass(
    registry: &mut PluginRegistry,
    store: &mut dyn ScheduledAdmissionStoreV1,
    timeline: TimelineId,
    token: Option<&ConsentCapabilityToken>,
) -> Result<usize, RuntimeError> {
    let host = LocalScheduledAdmissionHostV1::shared()?;
    let revisions = host.observe(registry, &mut *store, timeline)?;
    let (head, drafts) = stage(registry, &*store, timeline, token)?;
    if drafts.is_empty() {
        registry.commit_step_at(head, 0)?;
    } else {
        host.admit(registry, &mut *store, revisions, head, 0)?;
    }
    Ok(drafts.len())
}

/// A fixture Plugin that owns a fixed set of Event types.
pub struct FixturePlugin {
    pub id: PluginId,
    pub name: &'static str,
    pub owned: Vec<&'static str>,
    pub has_driver: bool,
}

impl FixturePlugin {
    #[must_use]
    pub fn new(name: &'static str, owned: &[&'static str], has_driver: bool) -> Self {
        Self {
            id: PluginId::new(),
            name,
            owned: owned.to_vec(),
            has_driver,
        }
    }
}

impl Plugin for FixturePlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: self.owned.iter().copied().map(Kind::new).collect(),
            has_driver: self.has_driver,
            ..Capability::default()
        }
    }
}

/// The owning domain policy. It counts every invocation and denies the
/// payload `deny`.
pub struct CountingApprover(pub Arc<AtomicUsize>);

impl ActionApprover for CountingApprover {
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

/// A scheduled Driver that counts its invocations and, while enabled,
/// emits a fixed draft vector or fails.
pub struct ScriptedDriver {
    pub name: &'static str,
    pub drafts: Vec<EventDraft>,
    pub steps: Arc<AtomicUsize>,
    pub aborts: Arc<AtomicUsize>,
    pub enabled: Arc<AtomicBool>,
    pub failing: Arc<AtomicBool>,
}

impl ScriptedDriver {
    #[must_use]
    pub fn new(name: &'static str, drafts: Vec<EventDraft>) -> Self {
        Self {
            name,
            drafts,
            steps: Arc::new(AtomicUsize::new(0)),
            aborts: Arc::new(AtomicUsize::new(0)),
            enabled: Arc::new(AtomicBool::new(true)),
            failing: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Driver for ScriptedDriver {
    fn name(&self) -> &'static str {
        self.name
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        self.steps.fetch_add(1, Ordering::SeqCst);
        if self.failing.load(Ordering::SeqCst) {
            return Err(RuntimeError::InvalidPayload {
                event_type: self.name.to_owned(),
                reason: "injected driver failure".to_owned(),
            });
        }
        if self.enabled.load(Ordering::SeqCst) {
            Ok(StepOutput::new(self.drafts.clone()))
        } else {
            Ok(StepOutput::empty())
        }
    }

    fn abort_step(&mut self) {
        self.aborts.fetch_add(1, Ordering::SeqCst);
    }
}

/// A Reducer that keeps no state, for registrations that only need one.
pub struct IdleReducer;

impl Reducer for IdleReducer {
    fn initial(&self) -> State {
        State::new()
    }

    fn apply(&self, _: &mut State, _: &Event) {}
}

/// Register `plugin` on the generated path with idle components matching
/// its declared capability.
///
/// # Errors
///
/// Returns the registration error.
pub fn register_declared(
    registry: &mut PluginRegistry,
    plugin: &dyn Plugin,
) -> Result<(), RuntimeError> {
    let capability = plugin.capability();
    let reducer: Option<Box<dyn Reducer>> = capability
        .has_reducer
        .then(|| Box::new(IdleReducer) as Box<dyn Reducer>);
    let driver: Option<Box<dyn Driver>> = capability
        .has_driver
        .then(|| Box::new(ScriptedDriver::new(plugin.name(), Vec::new())) as Box<dyn Driver>);
    registry.register_generated(plugin, reducer, driver)
}

/// One fixed draft of `event_type` for `entity`.
#[must_use]
pub fn draft(entity: EntityId, event_type: &str, payload: &'static [u8]) -> EventDraft {
    EventDraft::new(
        entity,
        Kind::new(event_type),
        CanonicalBytes::from_static(payload),
    )
}

/// A port that commits through the real store but loses the acknowledgement.
pub struct LostOutcomePort<'a>(pub &'a mut dyn ScheduledAdmissionStoreV1);

impl PipelineAdmissionPortV1 for LostOutcomePort<'_> {
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

    fn lookup_pipeline_receipt(
        &mut self,
        timeline: TimelineId,
        key: AppendDedupKey,
        attempt_id: PipelineAttemptIdV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        self.0.lookup_pipeline_receipt(timeline, key, attempt_id)
    }

    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        self.0.purge_expired_pipeline_receipts_bounded(limit)
    }
}

/// A port whose store write fails after a successful receipt lookup.
pub struct FailingWritePort<'a>(pub &'a mut dyn ScheduledAdmissionStoreV1);

impl PipelineAdmissionPortV1 for FailingWritePort<'_> {
    fn admit_pipeline_batch(
        &mut self,
        _basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        Err(CoreError::Storage(
            "injected store write failure".to_owned(),
        ))
    }

    fn lookup_pipeline_receipt(
        &mut self,
        timeline: TimelineId,
        key: AppendDedupKey,
        attempt_id: PipelineAttemptIdV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        self.0.lookup_pipeline_receipt(timeline, key, attempt_id)
    }

    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        self.0.purge_expired_pipeline_receipts_bounded(limit)
    }
}

/// A port that records each basis it is offered and admits none of them.
#[derive(Default)]
pub struct RecordingPort {
    pub offered: Vec<PipelineAdmissionBasisV1>,
}

impl PipelineAdmissionPortV1 for RecordingPort {
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        self.offered.push(basis.clone());
        Ok(PipelineOutcomeV1::Rejected)
    }

    fn lookup_pipeline_receipt(
        &mut self,
        _timeline: TimelineId,
        _key: AppendDedupKey,
        _attempt_id: PipelineAttemptIdV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        Ok(PipelineReceiptLookupV1::Absent)
    }

    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        _limit: NonZeroUsize,
    ) -> Result<PurgeOutcome, CoreError> {
        Err(CoreError::Storage(
            "a recording port retains nothing".to_owned(),
        ))
    }
}
