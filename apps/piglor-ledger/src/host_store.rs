use std::sync::Mutex;

use pos_core::{
    store::{EventReadBounds, EventStore, SeqRange},
    CoreError, ErasureHostErrorV1, Event, EventDraft, Hash, KeyDestructionBeginOutcomeV1,
    KeyDestructionOutcomeV1, KeyDestructionRequestV1, KeyRegistryStateV1, Seq, Timeline,
    TimelineId, ERASURE_MAX_INVENTORY_REQUESTS,
};
use pos_runtime::ErasureExecutionHostV1;
use pos_store::StoreConfig;

/// Private compatibility adapter for the ledger domain port.
///
/// The concrete store never escapes the execution host. Every implemented
/// `EventStore` operation delegates to a generation-bound host sender; all
/// other trait operations retain their fail-closed defaults.
pub struct HostedLedgerStore {
    host: Mutex<ErasureExecutionHostV1>,
    ledger_timeline: Option<TimelineId>,
}

impl HostedLedgerStore {
    pub fn open(config: StoreConfig) -> Result<Self, CoreError> {
        ErasureExecutionHostV1::open_verified_empty(config, ERASURE_MAX_INVENTORY_REQUESTS)
            .map(Self::from_host)
            .map_err(host_error)
    }

    pub fn open_read_only(path: &str) -> Result<Self, CoreError> {
        ErasureExecutionHostV1::open_read_only_verified_empty(path, ERASURE_MAX_INVENTORY_REQUESTS)
            .map(Self::from_host)
            .map_err(host_error)
    }

    const fn from_host(host: ErasureExecutionHostV1) -> Self {
        Self {
            host: Mutex::new(host),
            ledger_timeline: None,
        }
    }

    fn with_host<T>(
        &self,
        operation: impl FnOnce(&mut ErasureExecutionHostV1) -> Result<T, ErasureHostErrorV1>,
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
        let Some(timeline) = self.known_ledger_timeline()? else {
            return Ok(None);
        };
        self.with_host(|host| host.read_sender()?.key_registry(timeline))
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
