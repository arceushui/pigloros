/// Private compatibility adapter over the host's generation-bound senders.
///
/// The concrete `MemoryStore` or `SQLite` adapter remains exclusively owned by
/// `ErasureExecutionHostV1`; experiment code cannot recover raw store or gate
/// publication authority through this wrapper.
struct HostedExperimentStore {
    host: Mutex<pos_runtime::ErasureExecutionHostV1>,
    gate: Arc<dyn pos_core::ErasureGate>,
}

impl HostedExperimentStore {
    fn open(config: pos_store::StoreConfig) -> Result<Self, ErasureHostErrorV1> {
        let composition = pos_runtime::ErasureCoordinatorCompositionV1::closed();
        Self::open_with_authority(config, &composition)
    }

    fn open_with_authority(
        config: pos_store::StoreConfig,
        composition: &pos_runtime::ErasureCoordinatorCompositionV1,
    ) -> Result<Self, ErasureHostErrorV1> {
        pos_runtime::ErasureExecutionHostV1::open_with_authority(
            config,
            composition,
            pos_core::ErasureRecoveryLimitsV1::compiled_maximum(),
        )
        .map(|host| {
            let gate = host.containment_gate();
            Self {
                host: Mutex::new(host),
                gate,
            }
        })
    }

    fn containment_gate(&self) -> Arc<dyn pos_core::ErasureGate> {
        Arc::clone(&self.gate)
    }

    fn with_host<T>(
        &self,
        operation: impl FnOnce(
            &mut pos_runtime::ErasureExecutionHostV1,
        ) -> Result<T, ErasureHostErrorV1>,
    ) -> Result<T, CoreError> {
        self.host
            .lock()
            .map_err(|_| CoreError::ErasureContainmentUnavailable)
            .and_then(|mut host| operation(&mut host).map_err(host_error))
    }
}

impl EventStore for HostedExperimentStore {
    fn bind_erasure_gate(
        &mut self,
        _gate: Arc<pos_core::ErasureContainmentGateV1>,
    ) -> Result<(), CoreError> {
        // The host owns the concrete gate; this adapter exposes only its read-only view.
        Err(CoreError::ErasureContainmentUnavailable)
    }

    fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
        self.with_host(|host| {
            host.command_sender()
                .and_then(|mut sender| sender.create_timeline(name))
        })
    }

    fn append(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        self.with_host(|host| {
            host.command_sender()
                .and_then(|mut sender| sender.append(timeline, drafts))
        })
    }

    fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        self.read_bounded(
            timeline,
            range,
            EventReadBounds::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX),
        )
    }

    fn read_bounded(
        &self,
        timeline: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
    ) -> Result<Vec<Event>, CoreError> {
        self.with_host(|host| {
            host.read_sender()
                .and_then(|mut sender| sender.read_bounded(timeline, range, bounds))
        })
    }

    fn fork(&mut self, parent: TimelineId, at_seq: Seq, name: &str) -> Result<Timeline, CoreError> {
        self.with_host(|host| {
            host.command_sender()
                .and_then(|mut sender| sender.fork_timeline(parent, at_seq, name))
        })
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
        self.with_host(|host| host.read_sender().and_then(|mut sender| sender.timelines()))
    }

    fn get_timeline(&self, timeline: TimelineId) -> Result<Option<Timeline>, CoreError> {
        self.with_host(|host| {
            host.read_sender()
                .and_then(|mut sender| sender.timeline(timeline))
        })
    }

    fn logical_head(&self, timeline: TimelineId) -> Result<Seq, CoreError> {
        self.with_host(|host| {
            host.read_sender()
                .and_then(|mut sender| sender.logical_head(timeline))
        })
    }
}

fn host_error(error: ErasureHostErrorV1) -> CoreError {
    match error {
        ErasureHostErrorV1::AccessFrozen => CoreError::ErasureAccessFrozen,
        ErasureHostErrorV1::RecoveryUnavailable | ErasureHostErrorV1::StaleGeneration => {
            CoreError::ErasureContainmentUnavailable
        }
        ErasureHostErrorV1::AuthorizationDenied
        | ErasureHostErrorV1::Conflict
        | ErasureHostErrorV1::AdapterFailure => {
            CoreError::Storage("erasure host rejected experiment operation".to_owned())
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod host_store_tests {
    use super::*;
    use pos_core::{CanonicalBytes, Capability, EntityId, Kind, Plugin, PluginId, Reducer, State};
    use std::cell::Cell;

    struct ProjectionProbe {
        id: PluginId,
    }

    impl Plugin for ProjectionProbe {
        fn id(&self) -> PluginId {
            self.id
        }

        fn name(&self) -> &'static str {
            "projection-probe"
        }

        fn capability(&self) -> Capability {
            Capability {
                owned_event_types: vec![Kind::new("projection.public")],
                owned_entity_kinds: vec![],
                has_driver: false,
                has_reducer: true,
            }
        }
    }

    struct CountReducer;

    impl Reducer for CountReducer {
        fn initial(&self) -> State {
            State::new()
        }

        fn apply(&self, state: &mut State, _: &Event) {
            let count = state
                .get("count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            state.set("count", serde_json::json!(count + 1));
        }
    }

    struct FailSecondTimelineLookupStore {
        inner: Box<dyn EventStore>,
        lookups: Cell<u32>,
    }

    impl EventStore for FailSecondTimelineLookupStore {
        fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
            self.inner.create_timeline(name)
        }

        fn append(
            &mut self,
            timeline: TimelineId,
            drafts: &[EventDraft],
        ) -> Result<Vec<Event>, CoreError> {
            self.inner.append(timeline, drafts)
        }

        fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
            self.inner.read(timeline, range)
        }

        fn fork(
            &mut self,
            parent: TimelineId,
            at_seq: Seq,
            name: &str,
        ) -> Result<Timeline, CoreError> {
            self.inner.fork(parent, at_seq, name)
        }

        fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
            self.inner.list_timelines()
        }

        fn get_timeline(&self, timeline: TimelineId) -> Result<Option<Timeline>, CoreError> {
            let call = self.lookups.get() + 1;
            self.lookups.set(call);
            if call == 2 {
                Err(CoreError::Storage(
                    "injected prefix lookup failure".to_owned(),
                ))
            } else {
                self.inner.get_timeline(timeline)
            }
        }

        fn logical_head(&self, timeline: TimelineId) -> Result<Seq, CoreError> {
            self.inner.logical_head(timeline)
        }
    }

    #[test]
    fn delegates_the_experiment_store_surface() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = HostedExperimentStore::open(pos_store::StoreConfig::Memory)?;
        assert!(store
            .bind_erasure_gate(Arc::new(pos_core::ErasureContainmentGateV1::new_test_open()))
            .is_err());

        let parent = store.create_timeline("parent")?;
        let drafts = [EventDraft::new(
            EntityId::new(),
            Kind::new("experiment.host.test"),
            CanonicalBytes::from_vec(b"payload".to_vec()),
        )];
        let appended = store.append(parent.id(), &drafts)?;
        assert_eq!(appended.len(), 1);
        assert_eq!(store.read(parent.id(), SeqRange::all())?.len(), 1);
        assert_eq!(
            store
                .read_bounded(
                    parent.id(),
                    SeqRange::all(),
                    EventReadBounds::new(16, 32, 4, 4),
                )?
                .len(),
            1
        );
        assert_eq!(store.logical_head(parent.id())?, Seq::from_u64(1));
        assert_eq!(
            store
                .get_timeline(parent.id())?
                .map(|timeline| timeline.id()),
            Some(parent.id())
        );
        assert_eq!(store.list_timelines()?.len(), 1);
        let child = store.fork(parent.id(), Seq::from_u64(1), "child")?;
        assert_eq!(child.meta.fork_point, Some((parent.id(), Seq::from_u64(1))));
        Ok(())
    }

    #[test]
    fn restored_fork_rejects_stale_projection_before_creating_child(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut store = HostedExperimentStore::open(pos_store::StoreConfig::Memory)?;
        let parent = store.create_timeline("projection-parent")?;
        let events = store.append(
            parent.id(),
            &[EventDraft::new(
                EntityId::new(),
                Kind::new("projection.public"),
                CanonicalBytes::from_vec(Vec::new()),
            )],
        )?;
        let head = events.last().map_or(Seq::ZERO, |event| event.seq);
        let mut registry =
            pos_runtime::PluginRegistry::new().with_erasure_gate(store.containment_gate());
        registry.fold_events(parent.id(), &events);
        registry.restore_driver_state(
            &[pos_runtime::TimelineHistorySegment::new(parent.id(), head)],
            &events,
        )?;

        let unrelated = store.create_timeline("new-generation")?;
        assert!(matches!(
            registry.fork_restored_timeline(&mut store, parent.id(), head, "stale-child"),
            Err(pos_runtime::RuntimeError::Authority(
                pos_core::AuthorityErrorV1::SourceUnavailable
            ))
        ));
        let timelines = store.list_timelines()?;
        assert_eq!(timelines.len(), 2);
        assert!(timelines
            .iter()
            .any(|timeline| timeline.id() == parent.id()));
        assert!(timelines
            .iter()
            .any(|timeline| timeline.id() == unrelated.id()));
        Ok(())
    }

    #[test]
    fn host_generation_change_refolds_the_captured_prefix() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut store = HostedExperimentStore::open(pos_store::StoreConfig::Memory)?;
        let timeline = store.create_timeline("projection-source")?;
        let entity = EntityId::new();
        let events = store.append(
            timeline.id(),
            &[EventDraft::new(
                entity,
                Kind::new("projection.public"),
                CanonicalBytes::from_vec(Vec::new()),
            )],
        )?;
        let mut registry =
            pos_runtime::PluginRegistry::new().with_erasure_gate(store.containment_gate());
        registry.register_generated(
            &ProjectionProbe {
                id: PluginId::new(),
            },
            Some(Box::new(CountReducer)),
            None,
        )?;
        registry.fold_events(timeline.id(), &events);
        assert!(registry.validate_projection_source(timeline.id()).is_ok());

        store.create_timeline("inventory-successor")?;
        assert!(registry.validate_projection_source(timeline.id()).is_err());
        registry.fold_events(timeline.id(), &events);
        assert!(registry.validate_projection_source(timeline.id()).is_err());

        let shared: SharedEventStore = Arc::new(Mutex::new(Box::new(store)));
        let captured = lock_store(&shared)
            .and_then(|store| capture_pending_range(store.as_ref(), timeline.id(), Seq::ZERO))?;
        let mut boundary = TickBoundaryCoordinator {
            folded_through: Seq::ZERO,
        };
        assert_eq!(
            fold_host_captured_range(&shared, &mut boundary, &mut registry, &captured)?,
            FoldedEventCount(1)
        );
        assert_eq!(boundary.folded_through, captured.through);
        assert!(registry.validate_projection_source(timeline.id()).is_ok());

        assert!(refold_host_projection_prefix(
            &shared,
            &mut registry,
            TimelineId::new(),
            captured.through
        )
        .is_err());
        let projections = registry.into_authorized_projections(
            timeline.id(),
            captured.through,
            0,
            None,
            Some(&events),
        )?;
        assert_eq!(
            projections
                .state_for_reducer(timeline.id(), "projection-probe", &entity)?
                .and_then(|state| state.get("count").and_then(serde_json::Value::as_u64)),
            Some(1)
        );
        let mut registry = pos_runtime::PluginRegistry::new().without_erasure_gate();
        assert!(
            fold_host_captured_range(&shared, &mut boundary, &mut registry, &captured).is_err()
        );
        Ok(())
    }

    #[test]
    fn session_refreshes_projection_source_after_inventory_change(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "generation-refresh".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: pos_store::StoreConfig::Memory,
        });
        experiment.register_generated(
            &ProjectionProbe {
                id: PluginId::new(),
            },
            Some(Box::new(CountReducer)),
            None,
        )?;
        let mut session = experiment.start()?;
        let timeline = session.timeline.id();
        let entity = EntityId::new();
        lock_store(&session.store)?.append(
            timeline,
            &[EventDraft::new(
                entity,
                Kind::new("projection.public"),
                CanonicalBytes::from_vec(Vec::new()),
            )],
        )?;
        assert!(matches!(
            session.step_tick()?,
            TickOutcome::Advanced {
                folded_events: 1,
                ..
            }
        ));
        lock_store(&session.store)?.create_timeline("new-generation-before-tick")?;
        let (folded, committed) = session.prepare_tick()?;
        assert_eq!(folded, 0);
        assert_eq!(committed.len(), 1);
        assert!(session
            .registry
            .validate_projection_source(timeline)
            .is_ok());

        lock_store(&session.store)?.create_timeline("new-generation-before-result")?;
        let result = session.run_to_completion()?;
        assert_eq!(result.total_events, 1);
        assert_eq!(result.timeline_id, timeline);
        assert_eq!(
            result
                .projections
                .state_for_reducer(timeline, "projection-probe", &entity)?
                .and_then(|state| state.get("count").and_then(serde_json::Value::as_u64)),
            Some(1)
        );
        Ok(())
    }

    #[test]
    fn failed_projection_refresh_faults_the_session() -> Result<(), Box<dyn std::error::Error>> {
        let mut session = Experiment::new(ExperimentConfig {
            name: "failed-refresh".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: pos_store::StoreConfig::Memory,
        })
        .start()?;
        session.registry = std::mem::take(&mut session.registry).without_erasure_gate();
        let captured = lock_store(&session.store).and_then(|store| {
            capture_pending_range(store.as_ref(), session.timeline.id(), Seq::ZERO)
        })?;
        assert!(session.fold_captured_range_or_fault(&captured).is_err());
        assert_eq!(session.health, SessionHealth::Faulted);

        let mut retry = Experiment::new(ExperimentConfig {
            name: "failed-tick-refresh".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: pos_store::StoreConfig::Memory,
        })
        .start()?;
        retry.registry = std::mem::take(&mut retry.registry).without_erasure_gate();
        assert!(retry.prepare_tick().is_err());
        assert_eq!(retry.health, SessionHealth::Faulted);

        let mut read_failure = Experiment::new(ExperimentConfig {
            name: "prefix-read-failure".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: pos_store::StoreConfig::Memory,
        })
        .start()?;
        {
            let mut store = lock_store(&read_failure.store)?;
            let inner = std::mem::replace(&mut *store, Box::new(test_memory_store()));
            *store = Box::new(FailSecondTimelineLookupStore {
                inner,
                lookups: Cell::new(0),
            });
        }
        assert!(read_failure.prepare_tick().is_err());

        let mut experiment = Experiment::new(ExperimentConfig {
            name: "failed-append-refresh".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: pos_store::StoreConfig::Memory,
        });
        experiment.register_generated(
            &ProjectionProbe {
                id: PluginId::new(),
            },
            Some(Box::new(CountReducer)),
            None,
        )?;
        let mut append_session = experiment.start()?;
        append_session.registry =
            std::mem::take(&mut append_session.registry).without_erasure_gate();
        assert!(append_session
            .append_events(&[EventDraft::new(
                EntityId::new(),
                Kind::new("projection.public"),
                CanonicalBytes::from_vec(Vec::new()),
            )])
            .is_err());
        assert_eq!(append_session.health, SessionHealth::Faulted);

        let mut terminal = Experiment::new(ExperimentConfig {
            name: "failed-result-refresh".to_owned(),
            stop: StopCondition::MaxTicks(0),
            store_config: pos_store::StoreConfig::Memory,
        })
        .start()?;
        terminal.registry = std::mem::take(&mut terminal.registry).without_erasure_gate();
        assert!(terminal.run_to_completion().is_err());
        Ok(())
    }

    #[test]
    fn poisoned_host_and_host_errors_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let store = HostedExperimentStore::open(pos_store::StoreConfig::Memory)?;
        drop(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || {
                let _guard = store
                    .host
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                std::panic::resume_unwind(Box::new("poison hosted experiment store"));
            },
        )));
        assert!(matches!(
            store.list_timelines(),
            Err(CoreError::ErasureContainmentUnavailable)
        ));

        assert!(matches!(
            host_error(ErasureHostErrorV1::AccessFrozen),
            CoreError::ErasureAccessFrozen
        ));
        for error in [
            ErasureHostErrorV1::RecoveryUnavailable,
            ErasureHostErrorV1::StaleGeneration,
        ] {
            assert!(matches!(
                host_error(error),
                CoreError::ErasureContainmentUnavailable
            ));
        }
        for error in [
            ErasureHostErrorV1::AuthorizationDenied,
            ErasureHostErrorV1::Conflict,
            ErasureHostErrorV1::AdapterFailure,
        ] {
            assert!(matches!(host_error(error), CoreError::Storage(_)));
        }
        Ok(())
    }
}
