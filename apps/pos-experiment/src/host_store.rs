/// Forward the scheduled-admission ports of a test store decorator to one
/// field that holds the wrapped store.
#[cfg(test)]
macro_rules! forward_scheduled_admission_ports {
    ($store:ty, $field:ident) => {
        impl pos_core::PipelineAdmissionPortV1 for $store {
            fn admit_pipeline_batch(
                &mut self,
                basis: &pos_core::PipelineAdmissionBasisV1,
            ) -> Result<pos_core::PipelineOutcomeV1, pos_core::CoreError> {
                <dyn pos_runtime::ScheduledAdmissionStoreV1 as pos_core::PipelineAdmissionPortV1>::admit_pipeline_batch(
                    &mut self.$field,
                    basis,
                )
            }

            fn purge_expired_pipeline_receipts_bounded(
                &mut self,
                limit: std::num::NonZeroUsize,
            ) -> Result<pos_core::store::PurgeOutcome, pos_core::CoreError> {
                <dyn pos_runtime::ScheduledAdmissionStoreV1 as pos_core::PipelineAdmissionPortV1>::purge_expired_pipeline_receipts_bounded(
                    &mut self.$field,
                    limit,
                )
            }
        }

        forward_scheduled_admission_fence_and_authority!($store, $field);
    };
}

/// Forward only the admission-fence and authority ports of a test store
/// decorator that customizes its admitted-batch port.
#[cfg(test)]
macro_rules! forward_scheduled_admission_fence_and_authority {
    ($store:ty, $field:ident) => {
        impl pos_core::PipelineAdmissionFencePublisherV1 for $store {
            fn set_pipeline_admission_fence(
                &mut self,
                timeline: pos_core::TimelineId,
                fence: pos_core::PipelineAdmissionFenceV1,
            ) -> Result<(), pos_core::CoreError> {
                <dyn pos_runtime::ScheduledAdmissionStoreV1 as pos_core::PipelineAdmissionFencePublisherV1>::set_pipeline_admission_fence(
                    &mut self.$field,
                    timeline,
                    fence,
                )
            }

            fn pipeline_admission_fence(
                &self,
                timeline: pos_core::TimelineId,
            ) -> Result<Option<pos_core::PipelineAdmissionFenceV1>, pos_core::CoreError> {
                <dyn pos_runtime::ScheduledAdmissionStoreV1 as pos_core::PipelineAdmissionFencePublisherV1>::pipeline_admission_fence(
                    &self.$field,
                    timeline,
                )
            }
        }

        impl pos_core::AuthorityPersistencePortV1 for $store {
            fn bind_authority_persistence(
                &mut self,
                binding: pos_core::AuthorityPersistenceBindingV1,
            ) -> Result<(), pos_core::AuthorityPersistenceErrorV1> {
                <dyn pos_runtime::ScheduledAdmissionStoreV1 as pos_core::AuthorityPersistencePortV1>::bind_authority_persistence(
                    &mut self.$field,
                    binding,
                )
            }

            fn issue_capability_grant(
                &mut self,
                permit: pos_core::AuthorityMutationPermitV1,
                grant: &pos_core::CapabilityGrantV1,
            ) -> Result<pos_core::AuthorityCommitOutcomeV1, pos_core::AuthorityPersistenceErrorV1>
            {
                <dyn pos_runtime::ScheduledAdmissionStoreV1 as pos_core::AuthorityPersistencePortV1>::issue_capability_grant(
                    &mut self.$field,
                    permit,
                    grant,
                )
            }

            fn revoke_capability_grant(
                &mut self,
                permit: pos_core::AuthorityMutationPermitV1,
                revocation: &pos_core::CapabilityRevocationV1,
            ) -> Result<pos_core::AuthorityCommitOutcomeV1, pos_core::AuthorityPersistenceErrorV1>
            {
                <dyn pos_runtime::ScheduledAdmissionStoreV1 as pos_core::AuthorityPersistencePortV1>::revoke_capability_grant(
                    &mut self.$field,
                    permit,
                    revocation,
                )
            }

            fn load_authority(
                &self,
                leaf_grant_id: pos_core::Hash,
            ) -> Result<pos_core::PersistedAuthorityV1, pos_core::AuthorityPersistenceErrorV1>
            {
                <dyn pos_runtime::ScheduledAdmissionStoreV1 as pos_core::AuthorityPersistencePortV1>::load_authority(
                    &self.$field,
                    leaf_grant_id,
                )
            }
        }
    };
}

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

    /// Run one scheduled-admission operation on the host-owned store.
    fn with_admission<T>(
        &self,
        operation: impl FnOnce(&mut dyn pos_runtime::ScheduledAdmissionStoreV1) -> T,
    ) -> Result<T, CoreError> {
        self.with_host(|host| {
            host.command_sender()
                .and_then(|mut sender| sender.with_scheduled_admission(operation))
        })
    }
}

impl pos_core::PipelineAdmissionPortV1 for HostedExperimentStore {
    fn admit_pipeline_batch(
        &mut self,
        basis: &pos_core::PipelineAdmissionBasisV1,
    ) -> Result<pos_core::PipelineOutcomeV1, CoreError> {
        self.with_admission(|store| store.admit_pipeline_batch(basis))
            .and_then(std::convert::identity)
    }

    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        limit: std::num::NonZeroUsize,
    ) -> Result<pos_core::store::PurgeOutcome, CoreError> {
        self.with_admission(|store| store.purge_expired_pipeline_receipts_bounded(limit))
            .and_then(std::convert::identity)
    }
}

impl pos_core::PipelineAdmissionFencePublisherV1 for HostedExperimentStore {
    fn set_pipeline_admission_fence(
        &mut self,
        timeline: TimelineId,
        fence: pos_core::PipelineAdmissionFenceV1,
    ) -> Result<(), CoreError> {
        self.with_admission(|store| store.set_pipeline_admission_fence(timeline, fence))
            .and_then(std::convert::identity)
    }

    fn pipeline_admission_fence(
        &self,
        timeline: TimelineId,
    ) -> Result<Option<pos_core::PipelineAdmissionFenceV1>, CoreError> {
        self.with_admission(|store| store.pipeline_admission_fence(timeline))
            .and_then(std::convert::identity)
    }
}

/// Authority persistence through the host; a host failure is reported as the
/// closed `Unavailable` persistence error.
impl pos_core::AuthorityPersistencePortV1 for HostedExperimentStore {
    fn bind_authority_persistence(
        &mut self,
        binding: pos_core::AuthorityPersistenceBindingV1,
    ) -> Result<(), pos_core::AuthorityPersistenceErrorV1> {
        self.with_admission(|store| store.bind_authority_persistence(binding))
            .unwrap_or(Err(pos_core::AuthorityPersistenceErrorV1::Unavailable))
    }

    fn issue_capability_grant(
        &mut self,
        permit: pos_core::AuthorityMutationPermitV1,
        grant: &pos_core::CapabilityGrantV1,
    ) -> Result<pos_core::AuthorityCommitOutcomeV1, pos_core::AuthorityPersistenceErrorV1> {
        self.with_admission(|store| store.issue_capability_grant(permit, grant))
            .unwrap_or(Err(pos_core::AuthorityPersistenceErrorV1::Unavailable))
    }

    fn revoke_capability_grant(
        &mut self,
        permit: pos_core::AuthorityMutationPermitV1,
        revocation: &pos_core::CapabilityRevocationV1,
    ) -> Result<pos_core::AuthorityCommitOutcomeV1, pos_core::AuthorityPersistenceErrorV1> {
        self.with_admission(|store| store.revoke_capability_grant(permit, revocation))
            .unwrap_or(Err(pos_core::AuthorityPersistenceErrorV1::Unavailable))
    }

    fn load_authority(
        &self,
        leaf_grant_id: pos_core::Hash,
    ) -> Result<pos_core::PersistedAuthorityV1, pos_core::AuthorityPersistenceErrorV1> {
        self.with_admission(|store| store.load_authority(leaf_grant_id))
            .unwrap_or(Err(pos_core::AuthorityPersistenceErrorV1::Unavailable))
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
        inner: Box<dyn pos_runtime::ScheduledAdmissionStoreV1>,
        lookups: Cell<u32>,
    }

    forward_scheduled_admission_ports!(FailSecondTimelineLookupStore, inner);

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
            .and_then(|store| capture_pending_range(&**store, timeline.id(), Seq::ZERO))?;
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
        let captured = lock_store(&session.store)
            .and_then(|store| capture_pending_range(&**store, session.timeline.id(), Seq::ZERO))?;
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

    const fn admission_hash(value: u8) -> pos_core::Hash {
        pos_core::Hash::from_bytes([value; 32])
    }

    /// One registry-attested root grant and its revocation.
    fn admission_authority_fixture() -> Result<
        (
            pos_core::AuthorityPersistenceHostV1,
            pos_core::CapabilityGrantV1,
            pos_core::CapabilityRevocationV1,
        ),
        Box<dyn std::error::Error>,
    > {
        let principal = pos_core::PrincipalRefV1::try_new([7; 16], "local.test")?;
        let authority_timeline = TimelineId::new();
        let grant =
            pos_core::CapabilityGrantV1::try_from_draft(pos_core::CapabilityGrantDraftV1 {
                grant_id: admission_hash(1),
                grantor: principal.clone(),
                grantee: pos_core::AuthorityGranteeV1::Principal(principal),
                trust_domain: "local.test".to_owned(),
                scope: pos_core::CapabilityScopeV1::try_from_draft(
                    pos_core::CapabilityScopeDraftV1 {
                        resources: vec!["world".to_owned()],
                        actions: vec!["act".to_owned()],
                        purposes: vec!["simulation".to_owned()],
                        audiences: vec!["local-host".to_owned()],
                        actor_entity_ids: vec![EntityId::new()],
                        subject_ids: Vec::new(),
                        participant_ids: Vec::new(),
                        plugin_id: None,
                        principal_roles: vec![pos_core::AuthorityRoleV1::Actor],
                        max_uses: 10,
                        budget: 100,
                        environment_constraints: vec!["local-only".to_owned()],
                    },
                )?,
                valid_from_position: Seq::from_u64(1),
                valid_until_position: Seq::from_u64(100),
                parent_grant_id: None,
                delegation_depth: 0,
                max_delegation_depth: 0,
                permitted_delegate_classes: Vec::new(),
                consent_references: Vec::new(),
                policy_revision: admission_hash(9),
                issuance_timeline: authority_timeline,
                issuance_seq: Seq::from_u64(1),
                revocation_epoch: 0,
                revocation_fence: None,
                authority_registry_digest: admission_hash(7),
            })?;
        let registry = pos_core::AuthorityRegistrySnapshotV1::try_new(
            admission_hash(7),
            vec![admission_hash(200)],
            vec![grant.binding_digest()?],
            Vec::new(),
        )?;
        let revocation = pos_core::CapabilityRevocationV1::try_from_draft(
            pos_core::CapabilityRevocationDraftV1 {
                grant_id: admission_hash(1),
                authority_timeline,
                fence_position: Seq::from_u64(2),
                revocation_epoch: 1,
                policy_revision: admission_hash(9),
                authority_registry_digest: admission_hash(7),
            },
        )?;
        Ok((
            pos_core::AuthorityPersistenceHostV1::new(&registry),
            grant,
            revocation,
        ))
    }

    #[test]
    fn hosted_store_forwards_every_scheduled_admission_port(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use pos_core::{
            AuthorityPersistencePortV1, PipelineAdmissionFencePublisherV1, PipelineAdmissionPortV1,
        };

        let mut store = HostedExperimentStore::open(pos_store::StoreConfig::Memory)?;
        let timeline = store.create_timeline("hosted-admission")?.id();
        let purged = store.purge_expired_pipeline_receipts_bounded(std::num::NonZeroUsize::MIN)?;
        assert_eq!(purged.removed, 0);
        assert!(store.pipeline_admission_fence(timeline)?.is_none());

        let (authority, grant, revocation) = admission_authority_fixture()?;
        store.bind_authority_persistence(authority.persistence_binding())?;
        store.issue_capability_grant(authority.authorize_grant(&grant)?, &grant)?;
        assert_eq!(
            store.load_authority(grant.grant_id())?.revocation_epoch(),
            0
        );
        store.revoke_capability_grant(
            authority.authorize_revocation(&grant, &revocation)?,
            &revocation,
        )?;
        assert_eq!(
            store.load_authority(grant.grant_id())?.revocation_epoch(),
            1
        );
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
