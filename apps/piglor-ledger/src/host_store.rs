use super::HostedLedgerStore;
use pos_core::{
    store::{EventReadBounds, EventStore, SeqRange},
    CoreError, ErasureHostErrorV1, Event, EventDraft, Hash, KeyDestructionBeginOutcomeV1,
    KeyDestructionOutcomeV1, KeyDestructionRequestV1, KeyRegistryStateV1, Seq, Timeline,
    TimelineId,
};

impl HostedLedgerStore {
    fn with_host<T>(
        &self,
        operation: impl FnOnce(
            &mut pos_runtime::ErasureExecutionHostV1,
        ) -> Result<T, ErasureHostErrorV1>,
    ) -> Result<T, CoreError> {
        let mut host = self
            .host
            .lock()
            .map_err(|_| CoreError::ErasureContainmentUnavailable)?;
        operation(&mut host).map_err(host_error)
    }

    fn known_ledger_timeline(&self) -> Result<Option<TimelineId>, CoreError> {
        if let Some(timeline) = self.ledger_timeline {
            return Ok(Some(timeline));
        }
        self.list_timelines().map(|timelines| {
            timelines
                .into_iter()
                .find(|timeline| timeline.meta.name.as_deref() == Some("ledger"))
                .map(|timeline| timeline.id())
        })
    }
}

impl EventStore for HostedLedgerStore {
    fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
        self.with_host(|host| host.command_sender()?.create_timeline(name))
    }

    fn append(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, CoreError> {
        self.with_host(|host| host.command_sender()?.append(timeline, drafts))
    }

    fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
        self.with_host(|host| {
            host.read_sender()?.read_bounded(
                timeline,
                range,
                EventReadBounds::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX),
            )
        })
    }

    fn read_bounded(
        &self,
        timeline: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
    ) -> Result<Vec<Event>, CoreError> {
        self.with_host(|host| host.read_sender()?.read_bounded(timeline, range, bounds))
    }

    fn fork(&mut self, parent: TimelineId, at_seq: Seq, name: &str) -> Result<Timeline, CoreError> {
        self.with_host(|host| host.command_sender()?.fork_timeline(parent, at_seq, name))
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
        self.with_host(|host| host.read_sender()?.timelines())
    }

    fn root_timeline_count_bounded(&self, maximum: usize) -> Result<usize, CoreError> {
        self.with_host(|host| host.read_sender()?.root_timeline_count_bounded(maximum))
    }

    fn get_timeline(&self, timeline: TimelineId) -> Result<Option<Timeline>, CoreError> {
        self.with_host(|host| host.read_sender()?.timeline(timeline))
    }

    fn logical_head(&self, timeline: TimelineId) -> Result<Seq, CoreError> {
        self.with_host(|host| host.read_sender()?.logical_head(timeline))
    }

    fn load_key_registry(&self) -> Result<Option<KeyRegistryStateV1>, CoreError> {
        self.with_host(|host| host.read_sender()?.key_registry())
    }

    fn save_key_registry(&mut self, registry: &KeyRegistryStateV1) -> Result<(), CoreError> {
        let timeline = self
            .known_ledger_timeline()?
            .ok_or_else(|| CoreError::Storage("ledger Timeline is unavailable".to_owned()))?;
        self.with_host(|host| host.command_sender()?.save_key_registry(timeline, registry))
    }

    fn initialize_timeline_with_key_registry(
        &mut self,
        name: &str,
        expected_registry: &KeyRegistryStateV1,
    ) -> Result<Timeline, CoreError> {
        let timeline = self.with_host(|host| {
            host.command_sender()?
                .initialize_timeline_with_key_registry(name, expected_registry)
        })?;
        self.ledger_timeline = Some(timeline.id());
        Ok(timeline)
    }

    fn append_signed_authorized(
        &mut self,
        timeline: TimelineId,
        expected_registry: &KeyRegistryStateV1,
        create_event: &mut dyn FnMut(&KeyRegistryStateV1, Seq) -> Result<Event, CoreError>,
    ) -> Result<(), CoreError> {
        self.with_host(|host| {
            host.command_sender()?.append_signed_authorized(
                timeline,
                expected_registry,
                create_event,
            )
        })
    }

    fn begin_key_registry_destruction(
        &mut self,
        request: KeyDestructionRequestV1,
    ) -> Result<(KeyDestructionBeginOutcomeV1, KeyRegistryStateV1), CoreError> {
        let timeline = self
            .known_ledger_timeline()?
            .ok_or_else(|| CoreError::Storage("ledger Timeline is unavailable".to_owned()))?;
        self.with_host(|host| {
            host.command_sender()?
                .begin_key_registry_destruction(timeline, request)
        })
    }

    fn complete_key_registry_destruction(
        &mut self,
        request: KeyDestructionRequestV1,
        deletion_receipt: Hash,
    ) -> Result<(KeyDestructionOutcomeV1, KeyRegistryStateV1), CoreError> {
        let timeline = self
            .known_ledger_timeline()?
            .ok_or_else(|| CoreError::Storage("ledger Timeline is unavailable".to_owned()))?;
        self.with_host(|host| {
            host.command_sender()?.complete_key_registry_destruction(
                timeline,
                request,
                deletion_receipt,
            )
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
            CoreError::Storage("erasure host rejected ledger operation".to_owned())
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_core::{
        CanonicalBytes, EntityId, ErasureErrorV1, ErasureVerifiedInventoryQueryV1,
        ErasureVerifiedInventoryV1, KeyIdentityV1, KeyRegistrationV1, KeyRoleV1, Kind,
    };
    use pos_crypto::key_roles::key_material_digest;

    fn signing_registry(
    ) -> Result<(ed25519_dalek::SigningKey, KeyIdentityV1, KeyRegistryStateV1), CoreError> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[41; 32]);
        let identity = KeyIdentityV1::new("ledger-owner", KeyRoleV1::TimelineIntegritySigning, 1);
        let mut registry = KeyRegistryStateV1::new();
        registry
            .register_key(KeyRegistrationV1::new(
                identity,
                key_material_digest(&signing_key.to_bytes()),
                Some(pos_crypto::signing::public_key_from_verifying_key(
                    &signing_key.verifying_key(),
                )),
            ))
            .map_err(|error| CoreError::Storage(error.to_string()))?;
        Ok((signing_key, identity, registry))
    }

    #[test]
    fn hosted_store_delegates_the_complete_ledger_adapter_surface(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut store = HostedLedgerStore::open(pos_store::StoreConfig::Memory)?;
        let timeline = store.create_timeline("ledger")?;
        let draft = EventDraft::new(
            EntityId::new(),
            Kind::new("ledger.adapter.test"),
            CanonicalBytes::from_vec(b"payload".to_vec()),
        );
        let appended = store.append(timeline.id(), std::slice::from_ref(&draft))?;
        assert_eq!(appended.len(), 1);
        assert_eq!(store.read(timeline.id(), SeqRange::all())?.len(), 1);
        assert_eq!(
            store
                .read_bounded(
                    timeline.id(),
                    SeqRange::all(),
                    EventReadBounds::new(64, 64, 4, 4),
                )?
                .len(),
            1
        );
        assert_eq!(store.list_timelines()?.len(), 1);
        assert_eq!(store.root_timeline_count_bounded(2)?, 1);
        assert_eq!(
            store.get_timeline(timeline.id())?.map(|value| value.id()),
            Some(timeline.id())
        );
        assert_eq!(store.logical_head(timeline.id())?.as_u64(), 1);

        let registry = KeyRegistryStateV1::new();
        store.save_key_registry(&registry)?;
        assert_eq!(store.load_key_registry()?, Some(registry));
        let child = store.fork(timeline.id(), Seq::from_u64(1), "ledger-child")?;
        assert_eq!(
            child.meta.fork_point,
            Some((timeline.id(), Seq::from_u64(1)))
        );
        Ok(())
    }

    #[test]
    fn hosted_store_serializes_key_destruction_through_the_cached_ledger_scope(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (signing_key, identity, registry) = signing_registry()?;
        let mut store = HostedLedgerStore::open(pos_store::StoreConfig::Memory)?;
        let timeline = store.initialize_timeline_with_key_registry("ledger", &registry)?;
        assert_eq!(store.known_ledger_timeline()?, Some(timeline.id()));

        let request = KeyDestructionRequestV1::new(
            identity,
            key_material_digest(&signing_key.to_bytes()),
            Hash::from_bytes([42; 32]),
        );
        let (_, pending) = store.begin_key_registry_destruction(request)?;
        assert!(pending
            .active_key(&identity.owner_id, KeyRoleV1::TimelineIntegritySigning)
            .is_none());
        let (_, destroyed) = store
            .complete_key_registry_destruction(request, pos_core::deletion_receipt(&request))?;
        assert!(destroyed.tombstone(identity).is_some());
        Ok(())
    }

    #[test]
    fn hosted_store_maps_closed_host_errors_without_exposing_payloads(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(host_error(ErasureHostErrorV1::AccessFrozen)
            .to_string()
            .contains("frozen"));
        for error in [
            ErasureHostErrorV1::RecoveryUnavailable,
            ErasureHostErrorV1::StaleGeneration,
        ] {
            assert!(host_error(error).to_string().contains("unavailable"));
        }
        for error in [
            ErasureHostErrorV1::AuthorizationDenied,
            ErasureHostErrorV1::Conflict,
            ErasureHostErrorV1::AdapterFailure,
        ] {
            assert!(host_error(error).to_string().contains("rejected"));
        }

        let store = HostedLedgerStore::open(pos_store::StoreConfig::Memory)?;
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = store
                .host
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::panic::resume_unwind(Box::new("poison hosted ledger lock"));
        }));
        assert!(poisoned.is_err());
        assert!(store
            .list_timelines()
            .err()
            .is_some_and(|error| error.to_string().contains("unavailable")));
        Ok(())
    }

    struct FailingInventory;

    impl ErasureVerifiedInventoryQueryV1 for FailingInventory {
        fn verified_inventory(
            &mut self,
            _maximum_requests: usize,
        ) -> Result<ErasureVerifiedInventoryV1, ErasureErrorV1> {
            Err(ErasureErrorV1::ProvenanceMissing)
        }
    }

    #[test]
    fn poisoned_host_denies_every_ledger_adapter_operation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let identity = KeyIdentityV1::new("ledger-owner", KeyRoleV1::TimelineIntegritySigning, 1);
        let request = KeyDestructionRequestV1::new(
            identity,
            Hash::from_bytes([1; 32]),
            Hash::from_bytes([2; 32]),
        );
        let registry = KeyRegistryStateV1::new();
        let mut missing_timeline = HostedLedgerStore::open(pos_store::StoreConfig::Memory)?;
        assert!(missing_timeline.save_key_registry(&registry).is_err());
        assert!(missing_timeline
            .begin_key_registry_destruction(request)
            .is_err());
        assert!(missing_timeline
            .complete_key_registry_destruction(request, pos_core::deletion_receipt(&request),)
            .is_err());

        let mut host = pos_runtime::ErasureExecutionHostV1::open_verified_empty(
            pos_store::StoreConfig::Memory,
            pos_core::ERASURE_MAX_INVENTORY_REQUESTS,
        )?;
        assert!(host
            .install_inventory(
                &mut FailingInventory,
                pos_core::ERASURE_MAX_INVENTORY_REQUESTS,
            )
            .is_err());
        let timeline = TimelineId::new();
        let draft = EventDraft::new(
            EntityId::new(),
            Kind::new("ledger.adapter.denied"),
            CanonicalBytes::from_vec(Vec::new()),
        );
        let mut create_event = |_registry: &KeyRegistryStateV1, _seq: Seq| {
            Err(CoreError::Storage("callback must not run".to_owned()))
        };
        let mut store = HostedLedgerStore::from_host(host);
        assert!(store.save_key_registry(&registry).is_err());
        assert!(store.begin_key_registry_destruction(request).is_err());
        assert!(store
            .complete_key_registry_destruction(request, pos_core::deletion_receipt(&request),)
            .is_err());
        store.ledger_timeline = Some(timeline);

        assert!(store.create_timeline("denied").is_err());
        assert!(store
            .append(timeline, std::slice::from_ref(&draft))
            .is_err());
        assert!(store.read(timeline, SeqRange::all()).is_err());
        assert!(store
            .read_bounded(timeline, SeqRange::all(), EventReadBounds::new(1, 1, 1, 1),)
            .is_err());
        assert!(store.fork(timeline, Seq::ZERO, "denied-child").is_err());
        assert!(store.list_timelines().is_err());
        assert!(store.root_timeline_count_bounded(1).is_err());
        assert!(store.get_timeline(timeline).is_err());
        assert!(store.logical_head(timeline).is_err());
        assert!(store.load_key_registry().is_err());
        assert!(store.save_key_registry(&registry).is_err());
        assert!(store
            .initialize_timeline_with_key_registry("denied", &registry)
            .is_err());
        assert!(store
            .append_signed_authorized(timeline, &registry, &mut create_event)
            .is_err());
        assert!(store.begin_key_registry_destruction(request).is_err());
        assert!(store
            .complete_key_registry_destruction(request, pos_core::deletion_receipt(&request),)
            .is_err());
        Ok(())
    }
}
