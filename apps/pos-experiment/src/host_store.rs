use pos_core::{
    store::{EventReadBounds, EventStore, SeqRange},
    CoreError, ErasureGate, ErasureHostErrorV1, Event, EventDraft, Seq, Timeline, TimelineId,
};
use std::sync::{Arc, Mutex};

/// Private compatibility adapter over the host's generation-bound senders.
///
/// The concrete `MemoryStore` or `SQLite` adapter remains exclusively owned by
/// `ErasureExecutionHostV1`; experiment code cannot recover raw store or gate
/// publication authority through this wrapper.
pub(crate) struct HostedExperimentStore {
    host: Mutex<pos_runtime::ErasureExecutionHostV1>,
    gate: Arc<dyn ErasureGate>,
}

impl HostedExperimentStore {
    pub(crate) fn open(config: pos_store::StoreConfig) -> Result<Self, ErasureHostErrorV1> {
        let host = pos_runtime::ErasureExecutionHostV1::open_verified_empty(
            config,
            pos_core::ERASURE_MAX_INVENTORY_REQUESTS,
        )?;
        let gate = host.containment_gate();
        Ok(Self {
            host: Mutex::new(host),
            gate,
        })
    }

    pub(crate) fn containment_gate(&self) -> Arc<dyn ErasureGate> {
        Arc::clone(&self.gate)
    }

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
}

impl EventStore for HostedExperimentStore {
    fn bind_erasure_gate(&mut self, gate: Arc<dyn ErasureGate>) -> Result<(), CoreError> {
        if Arc::ptr_eq(&self.gate, &gate) {
            Ok(())
        } else {
            Err(CoreError::ErasureContainmentUnavailable)
        }
    }

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
        self.with_host(|host| host.read_sender()?.read_bounded(timeline, range, bounds))
    }

    fn fork(&mut self, parent: TimelineId, at_seq: Seq, name: &str) -> Result<Timeline, CoreError> {
        self.with_host(|host| host.command_sender()?.fork_timeline(parent, at_seq, name))
    }

    fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
        self.with_host(|host| host.read_sender()?.timelines())
    }

    fn get_timeline(&self, timeline: TimelineId) -> Result<Option<Timeline>, CoreError> {
        self.with_host(|host| host.read_sender()?.timeline(timeline))
    }

    fn logical_head(&self, timeline: TimelineId) -> Result<Seq, CoreError> {
        self.with_host(|host| host.read_sender()?.logical_head(timeline))
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
mod tests {
    use super::*;
    use pos_core::{CanonicalBytes, EntityId, Kind};

    #[test]
    fn delegates_the_experiment_store_surface() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = HostedExperimentStore::open(pos_store::StoreConfig::Memory)?;
        let host_gate = store.containment_gate();
        store.bind_erasure_gate(Arc::clone(&host_gate))?;
        assert!(store
            .bind_erasure_gate(Arc::new(pos_core::ErasureContainmentGateV1::new()))
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
                    EventReadBounds::new(16, 16, 4, 4),
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
    fn poisoned_host_and_host_errors_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let store = HostedExperimentStore::open(pos_store::StoreConfig::Memory)?;
        drop(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || {
                let _guard = store.host.lock().unwrap_or_else(|error| error.into_inner());
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
