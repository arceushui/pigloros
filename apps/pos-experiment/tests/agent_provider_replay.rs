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

use pos_core::{
    clock::Seq,
    event::{CanonicalBytes, Event, EventDraft, Kind},
    ids::{EntityId, PluginId, TimelineId},
    store::EventStore,
    ConsentAuthority, ConsentGranted, CoreError, Timeline,
};
use pos_experiment::{
    BacktestConfig, BacktestRunner, Experiment, ExperimentConfig, ExperimentError,
    ExperimentSession, ReproductionRecipe, StopCondition, TickOutcome,
};
use pos_plugin_agent::{
    protocol::{
        ActionCatalogueV1, AgentDecisionRequestV1, AgentProviderProvenanceV1, BoundedProviderBytes,
        ProviderAttempt,
    },
    AgentDecisionProvider, AgentDecisionReplayVerifier, AgentPlugin, AgentReducer,
    FixtureAgentDecisionProvider, ProviderBackedAgentDriver, EVENT_TYPE_ACTION,
};
use pos_runtime::{
    recorder::RECORDER_EVENT_TYPE, Driver, DriverRecoveryEvidence, ObservationView, PluginRegistry,
    ProjectionKey, RecoveryEventHeader, RuntimeError, StepOutput, TimelineHistorySegment,
};
use pos_store::{memory::MemoryStore, SeqRange, StoreConfig};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::Duration,
};

const PLUGIN_VERSION: &str = "1.0.0";
const PROVIDER_ID: &str = "fixture-local";
const PROVIDER_VERSION: &str = "fixture-v1";
const PLUGIN_HASH: [u8; 32] = [0x31; 32];
const PROVIDER_HASH: [u8; 32] = [0x32; 32];
const CONFIDENCE: u32 = 750_000;

struct TickRecordingProvider {
    response: BoundedProviderBytes,
    ticks: Arc<Mutex<Vec<u64>>>,
}

impl AgentDecisionProvider for TickRecordingProvider {
    fn decide(&mut self, request: &AgentDecisionRequestV1) -> ProviderAttempt {
        self.ticks.lock().test_ok().push(request.driver_tick());
        ProviderAttempt::Response(self.response.clone())
    }
}

#[derive(Clone)]
struct HostFixture {
    agent: EntityId,
    plugin: PluginId,
    catalogue: ActionCatalogueV1,
    provenance: AgentProviderProvenanceV1,
    catalogue_hash: [u8; 32],
}

impl HostFixture {
    fn new() -> Self {
        let agent = EntityId::new();
        let plugin = PluginId::new();
        let catalogue =
            ActionCatalogueV1::try_new(vec!["move".to_owned(), "wait".to_owned()]).test_ok();
        let provenance = AgentProviderProvenanceV1::try_new(
            plugin,
            PLUGIN_VERSION.to_owned(),
            PLUGIN_HASH,
            PROVIDER_ID.to_owned(),
            PROVIDER_VERSION.to_owned(),
            PROVIDER_HASH,
        )
        .test_ok();
        let catalogue_hash = blake3::derive_key(
            "pigloros.agent.catalogue.v1",
            &catalogue_bytes(&["move", "wait"]),
        );
        Self {
            agent,
            plugin,
            catalogue,
            provenance,
            catalogue_hash,
        }
    }

    fn experiment(
        &self,
        name: &str,
        attempts: Vec<ProviderAttempt>,
    ) -> (
        Experiment,
        pos_plugin_agent::FixtureProviderCallCount,
        DriverTickProbe,
    ) {
        self.experiment_with_store(name, attempts, StoreConfig::Memory)
    }

    fn experiment_with_store(
        &self,
        name: &str,
        attempts: Vec<ProviderAttempt>,
        store_config: StoreConfig,
    ) -> (
        Experiment,
        pos_plugin_agent::FixtureProviderCallCount,
        DriverTickProbe,
    ) {
        let provider = FixtureAgentDecisionProvider::new(attempts);
        let calls = provider.call_count_handle();
        let provider_driver = ProviderBackedAgentDriver::new(
            self.agent,
            self.catalogue.clone(),
            self.provenance.clone(),
            Box::new(provider),
        );
        let committed_tick = DriverTickProbe::default();
        let driver = ObservableProviderDriver {
            inner: provider_driver,
            committed_tick: committed_tick.clone(),
        };
        let plugin = AgentPlugin::new();
        let mut experiment = Experiment::new(ExperimentConfig {
            name: name.to_owned(),
            stop: StopCondition::MaxTicks(2),
            store_config,
        });
        experiment
            .register(
                &plugin,
                Some(Box::new(AgentReducer)),
                Some(Box::new(driver)),
            )
            .test_ok();
        (experiment, calls, committed_tick)
    }

    fn expected_record(
        &self,
        timeline: TimelineId,
        observed_through: u64,
        driver_tick: u64,
        response: &[u8],
        result: ExpectedResult,
    ) -> Vec<u8> {
        let request = request_bytes(self, timeline, observed_through, driver_tick);
        let request_hash = blake3::derive_key("pigloros.agent.request.v1", &request);
        let response_digest = blake3::derive_key("pigloros.agent.response.v1", response);
        record_bytes(
            self,
            timeline,
            observed_through,
            driver_tick,
            request_hash,
            response_digest,
            result,
        )
    }

    fn verifier(&self, timeline: TimelineId) -> AgentDecisionReplayVerifier {
        AgentDecisionReplayVerifier::try_new_with_timeline_ancestry(
            vec![TimelineHistorySegment::new(timeline, Seq::from_u64(32))],
            self.agent,
            self.provenance.clone(),
            self.catalogue.clone(),
        )
        .test_ok()
    }

    fn forkable_experiment(
        &self,
        name: &str,
        parent_attempts: Vec<ProviderAttempt>,
        child_attempts: Vec<ProviderAttempt>,
    ) -> Experiment {
        let plugin = Arc::new(AgentPlugin::new());
        let child_plugin = Arc::clone(&plugin);
        let child_host = self.clone();
        let mut experiment = Experiment::new(ExperimentConfig {
            name: name.to_owned(),
            stop: StopCondition::MaxTicks(2),
            store_config: StoreConfig::Memory,
        })
        .with_fork_registry_factory(move || {
            let provider = FixtureAgentDecisionProvider::new(child_attempts.clone());
            let driver = ProviderBackedAgentDriver::new(
                child_host.agent,
                child_host.catalogue.clone(),
                child_host.provenance.clone(),
                Box::new(provider),
            );
            let mut registry = PluginRegistry::new();
            registry.register(
                child_plugin.as_ref(),
                Some(Box::new(AgentReducer)),
                Some(Box::new(driver)),
            )?;
            Ok(registry)
        });
        let parent_provider = FixtureAgentDecisionProvider::new(parent_attempts);
        let parent_driver = ProviderBackedAgentDriver::new(
            self.agent,
            self.catalogue.clone(),
            self.provenance.clone(),
            Box::new(parent_provider),
        );
        experiment
            .register(
                plugin.as_ref(),
                Some(Box::new(AgentReducer)),
                Some(Box::new(parent_driver)),
            )
            .test_ok();
        experiment
    }
}

#[derive(Clone, Default)]
struct DriverTickProbe {
    committed: Arc<AtomicU64>,
    restore_stage_attempts: Arc<AtomicU64>,
}

impl DriverTickProbe {
    fn load(&self) -> u64 {
        self.committed.load(Ordering::SeqCst)
    }

    fn restore_stage_attempts(&self) -> u64 {
        self.restore_stage_attempts.load(Ordering::SeqCst)
    }
}

struct ObservableProviderDriver {
    inner: ProviderBackedAgentDriver,
    committed_tick: DriverTickProbe,
}

impl Driver for ObservableProviderDriver {
    fn step(
        &mut self,
        timeline: TimelineId,
        observations: ObservationView<'_>,
    ) -> Result<StepOutput, RuntimeError> {
        self.inner.step(timeline, observations)
    }

    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn tick_interval(&self) -> Duration {
        self.inner.tick_interval()
    }

    fn subscriptions(&self) -> &[ProjectionKey] {
        self.inner.subscriptions()
    }

    fn requires_snapshot_anchor(&self) -> bool {
        self.inner.requires_snapshot_anchor()
    }

    fn commit_step(&mut self) {
        self.inner.commit_step();
        self.committed_tick
            .committed
            .store(self.inner.committed_tick(), Ordering::SeqCst);
    }

    fn abort_step(&mut self) {
        self.inner.abort_step();
        self.committed_tick
            .committed
            .store(self.inner.committed_tick(), Ordering::SeqCst);
    }

    fn needs_recovery_payload(&self, header: &RecoveryEventHeader) -> bool {
        self.inner.needs_recovery_payload(header)
    }

    fn stage_restore_from_history(
        &mut self,
        evidence: &DriverRecoveryEvidence,
    ) -> Result<(), RuntimeError> {
        self.committed_tick
            .restore_stage_attempts
            .fetch_add(1, Ordering::SeqCst);
        self.inner.stage_restore_from_history(evidence)
    }

    fn commit_restore_from_history(&mut self) {
        self.inner.commit_restore_from_history();
        self.committed_tick
            .committed
            .store(self.inner.committed_tick(), Ordering::SeqCst);
    }

    fn abort_restore_from_history(&mut self) {
        self.inner.abort_restore_from_history();
    }
}

#[derive(Clone, Copy)]
enum ExpectedResult {
    Accepted { action_index: u8, confidence: u32 },
    NoAction { code: u8 },
}

#[derive(Default)]
struct AdapterControl {
    append_batch_sizes: Vec<usize>,
    fail_next_append: bool,
    next_read_fault: Option<ReadFault>,
    logical_head_reads: usize,
    metadata_reads: usize,
    next_metadata_fault: Option<MetadataFault>,
}

#[derive(Clone, Copy)]
enum ReadFault {
    DropFirstEvent,
    FailRead,
    ReportZeroHead,
    FailSecondHead,
}

#[derive(Clone, Copy)]
enum MetadataFault {
    Fail,
    ReturnWrongTimeline,
    ReturnWrongTimelineOnSecondGet,
    ReturnCycleOnSecondGet,
}

enum BoundaryDriver {
    Empty,
    Fails,
    EmitsUnknown,
}

impl Driver for BoundaryDriver {
    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        match self {
            Self::Empty => Ok(StepOutput::new(Vec::new())),
            Self::Fails => Err(RuntimeError::UnknownEventType(
                "fixture.driver.failure".to_owned(),
            )),
            Self::EmitsUnknown => Ok(StepOutput::new(vec![EventDraft::new(
                EntityId::new(),
                Kind::new("fixture.unregistered"),
                CanonicalBytes::from_vec(Vec::new()),
            )])),
        }
    }

    fn name(&self) -> &'static str {
        "boundary-fixture"
    }
}

#[derive(Clone)]
struct SharedMemoryAdapter {
    store: Arc<Mutex<MemoryStore>>,
    control: Arc<Mutex<AdapterControl>>,
}

impl SharedMemoryAdapter {
    fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(MemoryStore::new())),
            control: Arc::new(Mutex::new(AdapterControl::default())),
        }
    }

    fn fail_next_append(&self) {
        self.control().fail_next_append = true;
    }

    fn append_batch_sizes(&self) -> Vec<usize> {
        self.control().append_batch_sizes.clone()
    }

    fn drop_first_on_next_read(&self) {
        self.control().next_read_fault = Some(ReadFault::DropFirstEvent);
    }

    fn fail_next_read(&self) {
        self.control().next_read_fault = Some(ReadFault::FailRead);
    }

    fn fail_next_get_timeline(&self) {
        self.control().next_metadata_fault = Some(MetadataFault::Fail);
    }

    fn return_wrong_timeline_on_next_get(&self) {
        self.control().next_metadata_fault = Some(MetadataFault::ReturnWrongTimeline);
    }

    fn return_wrong_timeline_on_second_get(&self) {
        let mut control = self.control();
        control.metadata_reads = 0;
        control.next_metadata_fault = Some(MetadataFault::ReturnWrongTimelineOnSecondGet);
    }

    fn return_cycle_on_second_get(&self) {
        let mut control = self.control();
        control.metadata_reads = 0;
        control.next_metadata_fault = Some(MetadataFault::ReturnCycleOnSecondGet);
    }

    fn report_zero_head_on_next_read(&self) {
        self.control().next_read_fault = Some(ReadFault::ReportZeroHead);
    }

    fn fail_after_first_logical_head(&self) {
        let mut control = self.control();
        control.logical_head_reads = 0;
        control.next_read_fault = Some(ReadFault::FailSecondHead);
    }

    fn source_events(&self, timeline: TimelineId) -> Vec<Event> {
        self.store().read(timeline, SeqRange::all()).test_ok()
    }

    fn store(&self) -> MutexGuard<'_, MemoryStore> {
        self.store.lock().test_ok()
    }

    fn control(&self) -> MutexGuard<'_, AdapterControl> {
        self.control.lock().test_ok()
    }
}

impl EventStore for SharedMemoryAdapter {
    fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
        self.store().create_timeline(name)
    }

    fn append(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        let should_fail = {
            let mut control = self.control();
            control.append_batch_sizes.push(drafts.len());
            std::mem::take(&mut control.fail_next_append)
        };
        if should_fail {
            Err(CoreError::Storage("injected append failure".to_owned()))
        } else {
            self.store().append(timeline, drafts)
        }
    }

    fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        let fault = self.control().next_read_fault.take();
        if matches!(fault, Some(ReadFault::FailRead)) {
            return Err(CoreError::Storage("injected read failure".to_owned()));
        }
        let mut events = self.store().read(timeline, range)?;
        let should_drop_first = matches!(fault, Some(ReadFault::DropFirstEvent));
        if should_drop_first && !events.is_empty() {
            events.remove(0);
        }
        Ok(events)
    }

    fn fork(&mut self, parent: TimelineId, at_seq: Seq, name: &str) -> Result<Timeline, CoreError> {
        self.store().fork(parent, at_seq, name)
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
        self.store().list_timelines()
    }

    fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
        let fault = {
            let mut control = self.control();
            control.metadata_reads += 1;
            match control.next_metadata_fault {
                Some(MetadataFault::ReturnWrongTimelineOnSecondGet)
                    if control.metadata_reads < 2 =>
                {
                    None
                }
                Some(MetadataFault::ReturnCycleOnSecondGet) if control.metadata_reads < 2 => None,
                _ => control.next_metadata_fault.take(),
            }
        };
        if matches!(fault, Some(MetadataFault::Fail)) {
            return Err(CoreError::Storage(
                "injected Timeline metadata failure".to_owned(),
            ));
        }
        let mut timeline = self.store().get_timeline(id)?;
        if matches!(
            fault,
            Some(
                MetadataFault::ReturnWrongTimeline | MetadataFault::ReturnWrongTimelineOnSecondGet,
            )
        ) {
            if let Some(timeline) = &mut timeline {
                timeline.meta.id = TimelineId::new();
            }
        }
        if matches!(fault, Some(MetadataFault::ReturnCycleOnSecondGet)) {
            if let Some(timeline) = &mut timeline {
                timeline.meta.fork_point = Some((timeline.id(), Seq::ZERO));
            }
        }
        Ok(timeline)
    }

    fn logical_head(&self, id: TimelineId) -> Result<Seq, CoreError> {
        let fault = {
            let mut control = self.control();
            match control.next_read_fault {
                Some(ReadFault::ReportZeroHead) => {
                    control.next_read_fault.take();
                    Some(ReadFault::ReportZeroHead)
                }
                Some(ReadFault::FailSecondHead) => {
                    control.logical_head_reads += 1;
                    (control.logical_head_reads >= 2)
                        .then(|| control.next_read_fault.take())
                        .flatten()
                }
                _ => None,
            }
        };
        match fault {
            Some(ReadFault::ReportZeroHead) => Ok(Seq::ZERO),
            Some(ReadFault::FailSecondHead) => Err(CoreError::Storage(
                "injected second head failure".to_owned(),
            )),
            _ => self.store().logical_head(id),
        }
    }
}

fn assert_supplied_store_has_no_recovery_recipe(
    adapter: &SharedMemoryAdapter,
    session: ExperimentSession,
) {
    adapter.drop_first_on_next_read();
    assert!(session.source_events().is_err());

    let result = session.run_to_completion().test_ok();
    assert!(result.store_config.is_none());
    assert!(matches!(
        result.branch("must-not-reopen"),
        Err(ExperimentError::MissingStoreRecoveryRecipe)
    ));
}

fn boundary_experiment(name: &str, driver: BoundaryDriver) -> Experiment {
    let plugin = AgentPlugin::new();
    let mut experiment = Experiment::new(ExperimentConfig {
        name: name.to_owned(),
        stop: StopCondition::MaxTicks(1),
        store_config: StoreConfig::Memory,
    });
    experiment
        .register(
            &plugin,
            Some(Box::new(AgentReducer)),
            Some(Box::new(driver)),
        )
        .test_ok();
    experiment
}

#[test]
fn backtest_runner_completes_both_empty_phases() {
    let result = BacktestRunner::new(
        BacktestConfig {
            experiment_name: "agent-provider-backtest".to_owned(),
            train_ticks: 1,
            eval_ticks: 1,
            store_config: StoreConfig::Memory,
        },
        PluginRegistry::new,
    )
    .run()
    .test_ok();
    assert_eq!(result.train_events, 0);
    assert_eq!(result.eval_events, 0);
    assert!(matches!(
        result.train_result.store_config,
        Some(StoreConfig::Memory)
    ));
    assert!(matches!(
        result.eval_result.store_config,
        Some(StoreConfig::Memory)
    ));
}

#[test]
fn backtest_runner_reads_train_history_before_non_empty_eval() {
    let host = HostFixture::new();
    let plugin = Arc::new(AgentPlugin::new());
    let accepted = accepted_response_bytes(0, CONFIDENCE);
    let runner_host = host;
    let runner_plugin = Arc::clone(&plugin);
    let result = BacktestRunner::new(
        BacktestConfig {
            experiment_name: "agent-provider-backtest-non-empty".to_owned(),
            train_ticks: 1,
            eval_ticks: 1,
            store_config: StoreConfig::Memory,
        },
        move || {
            let provider = FixtureAgentDecisionProvider::new(vec![response_attempt(&accepted)]);
            let driver = ProviderBackedAgentDriver::new(
                runner_host.agent,
                runner_host.catalogue.clone(),
                runner_host.provenance.clone(),
                Box::new(provider),
            );
            let mut registry = PluginRegistry::new();
            registry
                .register(
                    runner_plugin.as_ref(),
                    Some(Box::new(AgentReducer)),
                    Some(Box::new(driver)),
                )
                .test_ok();
            registry
        },
    )
    .run()
    .test_ok();
    assert!(result.train_events > 0);
    assert!(result.eval_events > 0);
    assert_eq!(result.train_result.ticks, 1);
    assert_eq!(result.eval_result.ticks, 1);
}

#[test]
fn backtest_eval_restores_driver_tick_before_first_provider_decision() {
    let host = HostFixture::new();
    let accepted = BoundedProviderBytes::try_from(accepted_response_bytes(0, CONFIDENCE)).test_ok();
    let train_ticks = Arc::new(Mutex::new(Vec::new()));
    let eval_ticks = Arc::new(Mutex::new(Vec::new()));
    let factory_calls = Arc::new(AtomicU64::new(0));
    let result = BacktestRunner::new(
        BacktestConfig {
            experiment_name: "agent-provider-backtest-tick-continuity".to_owned(),
            train_ticks: 1,
            eval_ticks: 1,
            store_config: StoreConfig::Memory,
        },
        {
            let train_ticks = Arc::clone(&train_ticks);
            let eval_ticks = Arc::clone(&eval_ticks);
            let factory_calls = Arc::clone(&factory_calls);
            move || {
                let phase = factory_calls.fetch_add(1, Ordering::SeqCst);
                let ticks = if phase == 0 {
                    Arc::clone(&train_ticks)
                } else {
                    Arc::clone(&eval_ticks)
                };
                let driver = ProviderBackedAgentDriver::new(
                    host.agent,
                    host.catalogue.clone(),
                    host.provenance.clone(),
                    Box::new(TickRecordingProvider {
                        response: accepted.clone(),
                        ticks,
                    }),
                );
                let mut registry = PluginRegistry::new();
                registry
                    .register(
                        &AgentPlugin::new(),
                        Some(Box::new(AgentReducer)),
                        Some(Box::new(driver)),
                    )
                    .test_ok();
                registry
            }
        },
    )
    .run()
    .test_ok();

    assert_eq!(factory_calls.load(Ordering::SeqCst), 2);
    assert_eq!(*train_ticks.lock().test_ok(), vec![0]);
    assert_eq!(*eval_ticks.lock().test_ok(), vec![1]);
    assert_eq!(result.train_result.ticks, 1);
    assert_eq!(result.eval_result.ticks, 1);
    assert_eq!(result.train_events, 2);
    assert_eq!(result.eval_events, 2);
}

#[test]
fn boundary_driver_paths_cover_quiescence_runtime_and_schema_failures() {
    let result = boundary_experiment("boundary-empty", BoundaryDriver::Empty)
        .run()
        .test_ok();
    assert_eq!(result.total_events, 0);

    for (name, driver) in [
        ("boundary-runtime", BoundaryDriver::Fails),
        ("boundary-schema", BoundaryDriver::EmitsUnknown),
    ] {
        let mut session = boundary_experiment(name, driver).start().test_ok();
        assert!(session.step_tick().is_err());
        assert!(matches!(
            session.step_tick(),
            Err(ExperimentError::SessionFaulted)
        ));
    }
}

#[test]
fn public_branch_guards_reject_protected_history_and_invalid_capabilities() {
    let config = |name: &str| ExperimentConfig {
        name: name.to_owned(),
        stop: StopCondition::MaxTicks(1),
        store_config: StoreConfig::Memory,
    };
    let grant = |fork_permitted: bool| ConsentGranted {
        subject_id: EntityId::new(),
        grantee_id: EntityId::new(),
        purpose: "public-branch-guard".to_owned(),
        modalities: 0,
        min_geo_resolution: 0,
        fork_permitted,
        export_permitted: false,
        retention_days: 0,
        expiry_secs: 0,
        grant_seq: 1,
    };

    let protected_name = "public-branch-protected";
    let mut protected_store = MemoryStore::new();
    let protected_timeline = protected_store.create_timeline(protected_name).test_ok();
    protected_store
        .append(
            protected_timeline.id(),
            &[EventDraft::new(
                EntityId::new(),
                Kind::new("consent.granted.v1"),
                CanonicalBytes::from_static(b"host-owned"),
            )],
        )
        .test_ok();
    assert!(matches!(
        Experiment::new(config(protected_name)).branch("protected-child", &mut protected_store),
        Err(ExperimentError::Runtime(
            RuntimeError::ConsentOperationUnavailable
        ))
    ));

    let authority = ConsentAuthority::new();
    let protected_token = authority.record_grant_on_timeline(protected_timeline.id(), &grant(true));
    let mut missing_timeline_store = MemoryStore::new();
    assert!(matches!(
        Experiment::new(config(protected_name)).branch_with_token(
            "missing-child",
            &mut missing_timeline_store,
            &protected_token,
            0,
        ),
        Err(ExperimentError::Store(CoreError::Storage(_)))
    ));

    let no_gate_name = "public-branch-no-gate";
    let mut no_gate_store = MemoryStore::new();
    let no_gate_timeline = no_gate_store.create_timeline(no_gate_name).test_ok();
    let no_gate_token = authority.record_grant_on_timeline(no_gate_timeline.id(), &grant(true));
    assert!(matches!(
        Experiment::new(config(no_gate_name))
            .without_consent_gate()
            .branch_with_token("no-gate-child", &mut no_gate_store, &no_gate_token, 0),
        Err(ExperimentError::Runtime(
            RuntimeError::ConsentOperationUnavailable
        ))
    ));

    let denied_name = "public-branch-denied";
    let mut denied_store = MemoryStore::new();
    let denied_timeline = denied_store.create_timeline(denied_name).test_ok();
    let denied_token = authority.record_grant_on_timeline(denied_timeline.id(), &grant(false));
    assert!(matches!(
        Experiment::new(config(denied_name)).branch_with_token(
            "denied-child",
            &mut denied_store,
            &denied_token,
            0,
        ),
        Err(ExperimentError::Runtime(RuntimeError::Consent(
            pos_core::ConsentError::ForkNotPermitted
        )))
    ));
}

#[test]
fn protected_result_export_and_faulted_projection_fail_closed() {
    let authority = ConsentAuthority::new();
    let experiment = Experiment::new(ExperimentConfig {
        name: "protected-result-export".to_owned(),
        stop: StopCondition::MaxTicks(1),
        store_config: StoreConfig::Memory,
    })
    .with_consent_authority(authority.clone());
    let session = experiment.start().test_ok();
    let token = authority.record_grant_on_timeline(
        session.timeline().id(),
        &ConsentGranted {
            subject_id: EntityId::new(),
            grantee_id: EntityId::new(),
            purpose: "protected-result-export".to_owned(),
            modalities: 0,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        },
    );
    let result = session
        .with_protected_token(token, 0)
        .run_to_completion()
        .test_ok();
    assert!(matches!(
        result.into_reproduction_manifest(ReproductionRecipe::new(
            "protected-result-export",
            1,
            serde_json::json!({}),
        )),
        Err(ExperimentError::Runtime(RuntimeError::Consent(
            pos_core::ConsentError::ExportNotPermitted
        )))
    ));

    let fault_authority = ConsentAuthority::new();
    let mut faulted = boundary_experiment("protected-projection-fault", BoundaryDriver::Fails)
        .with_consent_authority(fault_authority.clone())
        .start()
        .test_ok();
    let fault_token = fault_authority.record_grant_on_timeline(
        faulted.timeline().id(),
        &ConsentGranted {
            subject_id: EntityId::new(),
            grantee_id: EntityId::new(),
            purpose: "protected-projection-fault".to_owned(),
            modalities: 0,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        },
    );
    assert!(faulted.step_tick().is_err());
    assert!(matches!(
        faulted.projection_state_for_reducer("agent", EntityId::new(), &fault_token, 0),
        Err(ExperimentError::SessionFaulted)
    ));
}

#[test]
fn post_append_capture_failure_faults_the_session() {
    let host = HostFixture::new();
    let response = accepted_response_bytes(0, CONFIDENCE);
    let (experiment, _, _) = host.experiment(
        "agent-provider-post-capture-fault",
        vec![response_attempt(&response)],
    );
    let adapter = SharedMemoryAdapter::new();
    adapter.fail_after_first_logical_head();
    let mut session = experiment.start_with_store(Box::new(adapter)).test_ok();
    assert!(matches!(
        session.step_tick(),
        Err(ExperimentError::Store(_))
    ));
    assert!(matches!(
        session.step_tick(),
        Err(ExperimentError::SessionFaulted)
    ));
}

#[test]
fn resume_rejects_mismatched_ancestry_metadata() {
    let host = HostFixture::new();
    let accepted = accepted_response_bytes(0, CONFIDENCE);
    let adapter = SharedMemoryAdapter::new();
    let experiment = host.forkable_experiment(
        "agent-provider-ancestry-metadata",
        vec![response_attempt(&accepted)],
        vec![],
    );
    let mut parent = experiment
        .start_with_store(Box::new(adapter.clone()))
        .test_ok();
    parent.step_tick().test_ok();
    let child = parent.fork("child").test_ok();
    adapter.return_wrong_timeline_on_second_get();
    let fresh = host.experiment("agent-provider-ancestry-resume", vec![]).0;
    assert!(fresh
        .resume_with_store(child.timeline().id(), Box::new(adapter))
        .is_err());
}

#[test]
fn resume_rejects_cyclic_ancestry_metadata() {
    let host = HostFixture::new();
    let accepted = accepted_response_bytes(0, CONFIDENCE);
    let adapter = SharedMemoryAdapter::new();
    let experiment = host
        .experiment(
            "agent-provider-cyclic-ancestry",
            vec![response_attempt(&accepted)],
        )
        .0;
    let mut original = experiment
        .start_with_store(Box::new(adapter.clone()))
        .test_ok();
    original.step_tick().test_ok();
    let timeline = original.timeline().id();
    adapter.return_cycle_on_second_get();
    let fresh = host.experiment("agent-provider-cyclic-resume", vec![]).0;
    assert!(fresh
        .resume_with_store(timeline, Box::new(adapter))
        .is_err());
}

#[test]
fn live_boundaries_are_atomic_byte_stable_and_provider_free_on_replay() {
    let host = HostFixture::new();
    let accepted_response = accepted_response_bytes(0, CONFIDENCE);
    let no_action_response = no_action_response_bytes();
    let (experiment, calls, committed_tick) = host.experiment(
        "agent-provider-replay-live",
        vec![
            response_attempt(&accepted_response),
            response_attempt(&no_action_response),
        ],
    );
    let adapter = SharedMemoryAdapter::new();
    let authority = ConsentAuthority::new();
    let mut session = experiment
        .with_consent_authority(authority.clone())
        .start_with_store(Box::new(adapter.clone()))
        .test_ok();
    let timeline = session.timeline().id();
    let token = authority.record_grant_on_timeline(
        timeline,
        &ConsentGranted {
            subject_id: host.agent,
            grantee_id: EntityId::new(),
            purpose: "agent-projection-test".to_owned(),
            modalities: 0,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        },
    );

    assert_eq!(
        session.step_tick().test_ok(),
        TickOutcome::Advanced {
            folded_events: 2,
            emitted_events: 2,
        }
    );
    assert_eq!(committed_tick.load(), 1);
    assert_eq!(
        session.step_tick().test_ok(),
        TickOutcome::Advanced {
            folded_events: 1,
            emitted_events: 1,
        }
    );
    assert_eq!(committed_tick.load(), 2);
    assert_eq!(calls.get(), 2);
    assert_eq!(adapter.append_batch_sizes(), [2, 1]);

    let events = session.source_events().test_ok();
    assert_live_record_evidence(
        &host,
        timeline,
        &events,
        &accepted_response,
        &no_action_response,
    );
    assert_agent_projection_state(&session, host.agent, &token);

    let before_replay_calls = calls.get();
    let checkpoint = host.verifier(timeline).verify(&events, None).test_ok();
    assert_eq!(checkpoint.last_verified(), Seq::from_u64(3));
    assert_eq!(calls.get(), before_replay_calls);

    assert_supplied_store_has_no_recovery_recipe(&adapter, session);
}

fn assert_live_record_evidence(
    host: &HostFixture,
    timeline: TimelineId,
    events: &[Event],
    accepted_response: &[u8],
    no_action_response: &[u8],
) {
    assert_eq!(
        events
            .iter()
            .map(|event| event.seq.as_u64())
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert_eq!(
        events
            .iter()
            .map(|event| event.event_type.as_str())
            .collect::<Vec<_>>(),
        [RECORDER_EVENT_TYPE, EVENT_TYPE_ACTION, RECORDER_EVENT_TYPE]
    );
    assert!(events.iter().all(|event| event.entity == host.agent));
    let accepted_record = host.expected_record(
        timeline,
        0,
        0,
        accepted_response,
        ExpectedResult::Accepted {
            action_index: 0,
            confidence: CONFIDENCE,
        },
    );
    let accepted_record_hash = blake3::derive_key("pigloros.agent.record.v1", &accepted_record);
    let expected_action = action_bytes(
        "move",
        CONFIDENCE,
        0,
        host.catalogue_hash,
        accepted_record_hash,
    );
    let no_action_record = host.expected_record(
        timeline,
        2,
        1,
        no_action_response,
        ExpectedResult::NoAction { code: 5 },
    );
    assert_eq!(events[0].payload.as_slice(), accepted_record);
    assert_eq!(events[1].payload.as_slice(), expected_action);
    assert_eq!(events[2].payload.as_slice(), no_action_record);
}

fn assert_agent_projection_state(
    session: &ExperimentSession,
    agent: EntityId,
    token: &pos_core::ConsentCapabilityToken,
) {
    let state = session
        .projection_state_for_reducer("agent", agent, token, 0)
        .test_ok()
        .test_ok();
    assert_eq!(
        state
            .get("action_count")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        state.get("last_action").and_then(serde_json::Value::as_str),
        Some("move")
    );
}

#[test]
fn append_fault_commits_neither_pair_nor_tick_and_fresh_session_recovers() {
    let host = HostFixture::new();
    let accepted_response = accepted_response_bytes(0, CONFIDENCE);
    let adapter = SharedMemoryAdapter::new();
    adapter.fail_next_append();
    let authority = ConsentAuthority::new();
    let (experiment, failed_calls, failed_tick) = host.experiment(
        "agent-provider-replay-fault",
        vec![response_attempt(&accepted_response)],
    );
    let mut failed_session = experiment
        .with_consent_authority(authority.clone())
        .start_with_store(Box::new(adapter.clone()))
        .test_ok();
    let timeline = failed_session.timeline().id();
    let token = authority.record_grant_on_timeline(
        timeline,
        &ConsentGranted {
            subject_id: host.agent,
            grantee_id: EntityId::new(),
            purpose: "agent-projection-recovery-test".to_owned(),
            modalities: 0,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        },
    );

    assert!(matches!(
        failed_session.step_tick(),
        Err(ExperimentError::Store(_))
    ));
    assert_eq!(failed_calls.get(), 1);
    assert_eq!(failed_tick.load(), 0);
    assert!(adapter.source_events(timeline).is_empty());
    assert!(failed_session.source_events().test_ok().is_empty());
    assert_eq!(adapter.append_batch_sizes(), [2]);

    let (recovery, recovery_calls, recovery_tick) = host.experiment(
        "agent-provider-replay-recovery",
        vec![response_attempt(&accepted_response)],
    );
    let mut recovered = recovery
        .with_consent_authority(authority)
        .resume_with_store(timeline, Box::new(adapter.clone()))
        .test_ok();
    assert_eq!(
        recovered.step_tick().test_ok(),
        TickOutcome::Advanced {
            folded_events: 2,
            emitted_events: 2,
        }
    );
    assert_eq!(recovery_tick.load(), 1);

    let events = recovered.source_events().test_ok();
    let expected_record = host.expected_record(
        timeline,
        0,
        0,
        &accepted_response,
        ExpectedResult::Accepted {
            action_index: 0,
            confidence: CONFIDENCE,
        },
    );
    let record_hash = blake3::derive_key("pigloros.agent.record.v1", &expected_record);
    assert_eq!(events.len(), 2);
    assert_eq!(
        events
            .iter()
            .map(|event| event.seq.as_u64())
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(events[0].payload.as_slice(), expected_record);
    assert_eq!(
        events[1].payload.as_slice(),
        action_bytes("move", CONFIDENCE, 0, host.catalogue_hash, record_hash,)
    );
    assert_eq!(adapter.append_batch_sizes(), [2, 2]);
    assert_eq!(failed_calls.get(), 1);
    assert_eq!(recovery_calls.get(), 1);
    let recovered_state = recovered
        .projection_state_for_reducer("agent", host.agent, &token, 0)
        .test_ok()
        .test_ok();
    assert_eq!(
        recovered_state
            .get("action_count")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );

    let total_live_calls = failed_calls.get() + recovery_calls.get();
    let checkpoint = host.verifier(timeline).verify(&events, None).test_ok();
    assert_eq!(checkpoint.last_verified(), Seq::from_u64(2));
    assert_eq!(failed_calls.get() + recovery_calls.get(), total_live_calls);
}

#[test]
fn committed_history_restores_driver_tick_for_resume_and_fork() {
    let host = HostFixture::new();
    let accepted = accepted_response_bytes(0, CONFIDENCE);
    let no_action = no_action_response_bytes();
    let adapter = SharedMemoryAdapter::new();
    let (experiment, _, _) = host.experiment(
        "agent-provider-resume-tick",
        vec![response_attempt(&accepted)],
    );
    let mut original = experiment
        .start_with_store(Box::new(adapter.clone()))
        .test_ok();
    let timeline = original.timeline().id();
    original.step_tick().test_ok();

    let (resume, _, resumed_tick) = host.experiment(
        "agent-provider-resumed-tick",
        vec![response_attempt(&no_action)],
    );
    let mut resumed = resume
        .resume_with_store(timeline, Box::new(adapter))
        .test_ok();
    assert_eq!(resumed_tick.load(), 1);
    resumed.step_tick().test_ok();
    assert_eq!(resumed_tick.load(), 2);
    let resumed_events = resumed.source_events().test_ok();
    assert_eq!(resumed_events.len(), 3);
    assert_eq!(
        host.verifier(timeline)
            .verify(&resumed_events, None)
            .test_ok()
            .last_verified(),
        Seq::from_u64(3)
    );

    let fork_adapter = SharedMemoryAdapter::new();
    let forkable = host.forkable_experiment(
        "agent-provider-fork-tick",
        vec![response_attempt(&accepted)],
        vec![response_attempt(&no_action)],
    );
    let mut parent = forkable.start_with_store(Box::new(fork_adapter)).test_ok();
    parent.step_tick().test_ok();
    let parent_timeline = parent.timeline().id();
    let mut child = parent.fork("agent-provider-child").test_ok();
    let child_timeline = child.timeline().id();
    child.step_tick().test_ok();
    let child_events = child.source_events().test_ok();
    let verifier = AgentDecisionReplayVerifier::try_new_with_timeline_ancestry(
        vec![
            TimelineHistorySegment::new(parent_timeline, Seq::from_u64(2)),
            TimelineHistorySegment::new(child_timeline, Seq::from_u64(3)),
        ],
        host.agent,
        host.provenance.clone(),
        host.catalogue,
    )
    .test_ok();
    assert_eq!(
        verifier
            .verify(&child_events, None)
            .test_ok()
            .last_verified(),
        Seq::from_u64(3)
    );
}

#[test]
fn fork_recovery_fails_closed_when_prefix_or_ancestry_read_is_untrustworthy() {
    let host = HostFixture::new();
    let accepted = accepted_response_bytes(0, CONFIDENCE);

    let prefix_adapter = SharedMemoryAdapter::new();
    let prefix_experiment = host.forkable_experiment(
        "agent-provider-fork-prefix-read-failure",
        vec![response_attempt(&accepted)],
        vec![],
    );
    let mut prefix_parent = prefix_experiment
        .start_with_store(Box::new(prefix_adapter.clone()))
        .test_ok();
    prefix_parent.step_tick().test_ok();
    prefix_adapter.fail_next_read();
    assert!(matches!(
        prefix_parent.fork("prefix-read-failure"),
        Err(ExperimentError::Store(_))
    ));

    let ancestry_adapter = SharedMemoryAdapter::new();
    let ancestry_experiment = host.forkable_experiment(
        "agent-provider-fork-ancestry-read-failure",
        vec![response_attempt(&accepted)],
        vec![],
    );
    let mut ancestry_parent = ancestry_experiment
        .start_with_store(Box::new(ancestry_adapter.clone()))
        .test_ok();
    ancestry_parent.step_tick().test_ok();
    ancestry_adapter.return_wrong_timeline_on_second_get();
    assert!(matches!(
        ancestry_parent.fork("ancestry-read-failure"),
        Err(ExperimentError::Store(_))
    ));

    let cycle_adapter = SharedMemoryAdapter::new();
    let cycle_experiment = host.forkable_experiment(
        "agent-provider-fork-cyclic-ancestry",
        vec![response_attempt(&accepted)],
        vec![],
    );
    let mut cycle_parent = cycle_experiment
        .start_with_store(Box::new(cycle_adapter.clone()))
        .test_ok();
    cycle_parent.step_tick().test_ok();
    cycle_adapter.return_cycle_on_second_get();
    assert!(matches!(
        cycle_parent.fork("cyclic-ancestry"),
        Err(ExperimentError::Store(_))
    ));
}

#[test]
fn supplied_store_read_failure_prevents_driver_restore() {
    let host = HostFixture::new();
    let accepted = accepted_response_bytes(0, CONFIDENCE);
    let adapter = SharedMemoryAdapter::new();
    let (experiment, _, _) = host.experiment(
        "agent-provider-supplied-store-read-source",
        vec![response_attempt(&accepted)],
    );
    let mut original = experiment
        .start_with_store(Box::new(adapter.clone()))
        .test_ok();
    original.step_tick().test_ok();
    let timeline = original.timeline().id();
    drop(original);

    adapter.fail_next_read();
    let (recovery, calls, tick) = host.experiment(
        "agent-provider-supplied-store-read-recovery",
        vec![ProviderAttempt::NoResponse],
    );
    let result = recovery.resume_with_store(timeline, Box::new(adapter));

    assert!(matches!(
        result,
        Err(ExperimentError::Store(CoreError::Storage(message)))
            if message == "injected read failure"
    ));
    assert_eq!(calls.get(), 0);
    assert_eq!(tick.load(), 0);
    assert_eq!(tick.restore_stage_attempts(), 0);
}

#[test]
fn source_events_validates_empty_metadata_and_completed_head() {
    let host = HostFixture::new();
    let adapter = SharedMemoryAdapter::new();
    let (experiment, _, _) = host.experiment("agent-provider-source-validation", vec![]);
    let mut session = experiment
        .start_with_store(Box::new(adapter.clone()))
        .test_ok();

    adapter.fail_next_get_timeline();
    assert!(session.source_events().is_err());

    adapter.return_wrong_timeline_on_next_get();
    assert!(session.source_events().is_err());

    session.step_tick().test_ok();
    assert_eq!(session.source_events().test_ok().len(), 1);
    adapter.report_zero_head_on_next_read();
    assert!(session.source_events().is_err());

    let (experiment, _, _) = host.experiment("agent-provider-capture-regression", vec![]);
    let mut session = experiment
        .start_with_store(Box::new(adapter.clone()))
        .test_ok();
    session.step_tick().test_ok();
    adapter.report_zero_head_on_next_read();
    assert!(session.step_tick().is_err());

    let (experiment, _, _) = host.experiment("agent-provider-capture-gap", vec![]);
    let mut session = experiment
        .start_with_store(Box::new(adapter.clone()))
        .test_ok();
    let timeline = session.timeline().id();
    adapter
        .store()
        .append(
            timeline,
            &[EventDraft::new(
                EntityId::new(),
                pos_core::event::Kind::new("external.pending"),
                pos_core::event::CanonicalBytes::from_static(b"pending"),
            )],
        )
        .test_ok();
    adapter.drop_first_on_next_read();
    assert!(session.step_tick().is_err());
}

#[test]
fn resume_rejects_mismatched_initial_timeline_metadata() {
    let host = HostFixture::new();
    let adapter = SharedMemoryAdapter::new();
    let (experiment, _, _) = host.experiment("agent-provider-resume-metadata", vec![]);
    let session = experiment
        .start_with_store(Box::new(adapter.clone()))
        .test_ok();
    let timeline = session.timeline().id();
    drop(session);

    adapter.return_wrong_timeline_on_next_get();
    let (resume, _, _) = host.experiment("agent-provider-resume-metadata", vec![]);
    assert!(resume
        .resume_with_store(timeline, Box::new(adapter))
        .is_err());
}

#[test]
fn resume_fails_closed_when_the_durable_prefix_or_metadata_is_untrustworthy() {
    let host = HostFixture::new();
    let adapter = SharedMemoryAdapter::new();
    let (experiment, _, _) = host.experiment(
        "agent-provider-resume-fail-closed",
        vec![ProviderAttempt::NoResponse],
    );
    let mut session = experiment
        .start_with_store(Box::new(adapter.clone()))
        .test_ok();
    session.step_tick().test_ok();
    let timeline = session.timeline().id();
    drop(session);

    adapter.drop_first_on_next_read();
    let (resume, _, _) = host.experiment("agent-provider-resume-corrupt", vec![]);
    assert!(resume
        .resume_with_store(timeline, Box::new(adapter.clone()))
        .is_err());

    adapter.fail_next_get_timeline();
    let (resume, _, _) = host.experiment("agent-provider-resume-metadata", vec![]);
    assert!(resume
        .resume_with_store(timeline, Box::new(adapter))
        .is_err());
}

#[test]
fn durable_recipe_reopens_branches_and_resumes_the_child_history() {
    let host = HostFixture::new();
    let directory = tempfile::tempdir().test_ok();
    let path = directory.path().join("agent-provider-recovery.sqlite");
    let store_config = StoreConfig::Sqlite {
        path: path.to_string_lossy().into_owned(),
    };
    let (experiment, _, _) = host.experiment_with_store(
        "agent-provider-durable-recipe",
        vec![ProviderAttempt::NoResponse, ProviderAttempt::NoResponse],
        store_config.clone(),
    );
    let mut result = experiment.start().test_ok().run_to_completion().test_ok();
    assert!(matches!(
        result.store_config,
        Some(StoreConfig::Sqlite { .. })
    ));

    let child = result.branch("agent-provider-durable-child").test_ok();
    let (resume, calls, restored_tick) = host.experiment_with_store(
        "agent-provider-durable-child-resume",
        vec![ProviderAttempt::NoResponse],
        store_config,
    );
    let mut resumed = resume.resume(child.id()).test_ok();
    assert_eq!(calls.get(), 0, "resume must not call the provider");
    assert_eq!(restored_tick.load(), 2);
    assert_eq!(resumed.source_events().test_ok().len(), 2);
    assert!(matches!(
        resumed.step_tick().test_ok(),
        TickOutcome::Advanced { .. }
    ));
    assert_eq!(calls.get(), 1);

    result.store_config = Some(StoreConfig::Memory);
    assert!(result.branch("missing-from-memory-store").is_err());
}

#[test]
fn completed_run_wraps_the_host_reproduction_recipe() {
    let host = HostFixture::new();
    let (experiment, _, _) = host.experiment("agent-provider-reproduction-manifest", vec![]);
    let result = experiment.start().test_ok().run_to_completion().test_ok();
    let timeline_id = result.timeline_id;
    let manifest = result
        .into_reproduction_manifest(ReproductionRecipe::new(
            "pigloros.agent-provider",
            1,
            serde_json::json!({"provider": "fixture-local"}),
        ))
        .test_ok();

    assert_eq!(manifest.recipe.host_id, "pigloros.agent-provider");
    assert_eq!(manifest.recipe.format_version, 1);
    assert_eq!(
        manifest.recipe.configuration,
        serde_json::json!({"provider": "fixture-local"})
    );
    assert_eq!(manifest.manifest.timeline_id, timeline_id);
}

#[test]
fn configured_resume_rejects_an_absent_timeline() {
    let host = HostFixture::new();
    let (experiment, calls, restored_tick) =
        host.experiment("agent-provider-configured-missing", vec![]);

    assert!(experiment.resume(TimelineId::new()).is_err());
    assert_eq!(calls.get(), 0);
    assert_eq!(restored_tick.load(), 0);
}

fn response_attempt(response: &[u8]) -> ProviderAttempt {
    ProviderAttempt::Response(BoundedProviderBytes::try_from(response.to_vec()).test_ok())
}

fn accepted_response_bytes(action_index: u8, confidence: u32) -> Vec<u8> {
    let mut output = IndependentCbor::default();
    output.array(5);
    output.bytes(b"PDP1");
    output.uint(1);
    output.uint(0);
    output.uint(u64::from(action_index));
    output.uint(u64::from(confidence));
    output.finish()
}

fn no_action_response_bytes() -> Vec<u8> {
    let mut output = IndependentCbor::default();
    output.array(3);
    output.bytes(b"PDP1");
    output.uint(1);
    output.uint(1);
    output.finish()
}

fn catalogue_bytes(actions: &[&str]) -> Vec<u8> {
    let mut output = IndependentCbor::default();
    output.array(3);
    output.bytes(b"PAC1");
    output.uint(1);
    output.array(actions.len());
    for action in actions {
        output.text(action);
    }
    output.finish()
}

fn request_bytes(
    host: &HostFixture,
    timeline: TimelineId,
    observed_through: u64,
    driver_tick: u64,
) -> Vec<u8> {
    let mut output = IndependentCbor::default();
    output.array(13);
    output.bytes(b"PQR1");
    output.uint(1);
    write_request_fields(&mut output, host, timeline, observed_through, driver_tick);
    output.finish()
}

fn record_bytes(
    host: &HostFixture,
    timeline: TimelineId,
    observed_through: u64,
    driver_tick: u64,
    request_hash: [u8; 32],
    response_digest: [u8; 32],
    result: ExpectedResult,
) -> Vec<u8> {
    let mut output = IndependentCbor::default();
    output.array(16);
    output.bytes(b"PDR1");
    output.uint(1);
    write_request_fields(&mut output, host, timeline, observed_through, driver_tick);
    output.bytes(&request_hash);
    output.array(2);
    output.uint(1);
    output.bytes(&response_digest);
    match result {
        ExpectedResult::Accepted {
            action_index,
            confidence,
        } => {
            output.array(3);
            output.uint(0);
            output.uint(u64::from(action_index));
            output.uint(u64::from(confidence));
        }
        ExpectedResult::NoAction { code } => {
            output.array(2);
            output.uint(1);
            output.uint(u64::from(code));
        }
    }
    output.finish()
}

fn write_request_fields(
    output: &mut IndependentCbor,
    host: &HostFixture,
    timeline: TimelineId,
    observed_through: u64,
    driver_tick: u64,
) {
    output.bytes(&timeline.inner().to_bytes());
    output.uint(observed_through);
    output.bytes(&host.agent.inner().to_bytes());
    output.uint(driver_tick);
    output.bytes(&host.catalogue_hash);
    output.bytes(&host.plugin.inner().to_bytes());
    output.text(PLUGIN_VERSION);
    output.bytes(&PLUGIN_HASH);
    output.text(PROVIDER_ID);
    output.text(PROVIDER_VERSION);
    output.bytes(&PROVIDER_HASH);
}

fn action_bytes(
    action_id: &str,
    confidence: u32,
    driver_tick: u64,
    catalogue_hash: [u8; 32],
    record_hash: [u8; 32],
) -> Vec<u8> {
    let mut output = IndependentCbor::default();
    output.array(7);
    output.bytes(b"PAA1");
    output.uint(1);
    output.text(action_id);
    output.uint(u64::from(confidence));
    output.uint(driver_tick);
    output.bytes(&catalogue_hash);
    output.bytes(&record_hash);
    output.finish()
}

#[derive(Default)]
struct IndependentCbor(Vec<u8>);

impl IndependentCbor {
    fn array(&mut self, len: usize) {
        self.major(4, u64::try_from(len).test_ok());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.major(2, u64::try_from(value.len()).test_ok());
        self.0.extend_from_slice(value);
    }

    fn text(&mut self, value: &str) {
        self.major(3, u64::try_from(value.len()).test_ok());
        self.0.extend_from_slice(value.as_bytes());
    }

    fn uint(&mut self, value: u64) {
        self.major(0, value);
    }

    fn major(&mut self, major: u8, value: u64) {
        let prefix = major << 5;
        match value {
            0..=23 => self.0.push(prefix | u8::try_from(value).test_ok()),
            24..=0xff => {
                self.0.push(prefix | 0x18);
                self.0.push(u8::try_from(value).test_ok());
            }
            0x100..=0xffff => {
                self.0.push(prefix | 0x19);
                self.0
                    .extend_from_slice(&u16::try_from(value).test_ok().to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.0.push(prefix | 0x1a);
                self.0
                    .extend_from_slice(&u32::try_from(value).test_ok().to_be_bytes());
            }
            _ => {
                self.0.push(prefix | 0x1b);
                self.0.extend_from_slice(&value.to_be_bytes());
            }
        }
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }
}
