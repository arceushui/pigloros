//! Single-owner execution boundary for erasure-protected store operations.

use std::sync::Arc;

use pos_core::{
    store::{EventReadBounds, EventStore, SeqRange},
    CoreError, ErasureContainmentGateV1, ErasureGate, ErasureHostErrorV1,
    ErasureInventoryPersistencePortV1, ErasureReferenceV1, ErasureVerifiedInventoryQueryV1,
    ErasureVerifiedInventoryV1, Event, EventDraft, Timeline, TimelineId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostStateV1 {
    Closed,
    Ready(ErasureReferenceV1),
    Poisoned,
}

struct OneShotInventoryV1(Option<ErasureVerifiedInventoryV1>);

impl ErasureVerifiedInventoryQueryV1 for OneShotInventoryV1 {
    fn verified_inventory(
        &mut self,
        _maximum_requests: usize,
    ) -> Result<ErasureVerifiedInventoryV1, pos_core::ErasureErrorV1> {
        self.0
            .take()
            .ok_or(pos_core::ErasureErrorV1::ProvenanceMissing)
    }
}

/// Host-owned store and erasure gate with no raw adapter escape hatch.
///
/// Callers receive either a mutation-capable [`ErasureCommandSenderV1`] or a
/// read-only [`ErasureReadSenderV1`]. Both borrow the one host mutably, which
/// gives synchronous callers one logical command order. Async composition
/// roots place this host behind their existing single-consumer command queue.
pub struct ErasureExecutionHostV1<S> {
    store: S,
    gate: Arc<ErasureContainmentGateV1>,
    state: HostStateV1,
}

impl<S: EventStore> ErasureExecutionHostV1<S> {
    /// Bind an owned store to one fail-closed gate.
    ///
    /// # Errors
    /// Returns [`ErasureHostErrorV1::AdapterFailure`] when the adapter refuses
    /// the unique host gate binding.
    pub fn new_closed(mut store: S) -> Result<Self, ErasureHostErrorV1> {
        let gate = Arc::new(ErasureContainmentGateV1::new_fail_closed());
        let store_gate: Arc<dyn ErasureGate> = gate.clone();
        store
            .bind_erasure_gate(store_gate)
            .map_err(|_| ErasureHostErrorV1::AdapterFailure)?;
        Ok(Self {
            store,
            gate,
            state: HostStateV1::Closed,
        })
    }

    /// Install one complete inventory before any protected sender is granted.
    ///
    /// # Errors
    /// Returns a closed recovery error and leaves the host closed when the
    /// query fails or the candidate inventory cannot be published.
    pub fn install_inventory<Q: ErasureVerifiedInventoryQueryV1>(
        &mut self,
        query: &mut Q,
        maximum_requests: usize,
    ) -> Result<ErasureReferenceV1, ErasureHostErrorV1> {
        if self.state == HostStateV1::Poisoned {
            return Err(ErasureHostErrorV1::RecoveryUnavailable);
        }
        self.state = HostStateV1::Closed;
        let generation = match self
            .gate
            .install_from_verified_inventory_query(query, maximum_requests)
            .map_err(ErasureHostErrorV1::from)
        {
            Ok(generation) => generation,
            Err(error) => {
                self.state = HostStateV1::Poisoned;
                return Err(error);
            }
        };
        self.state = HostStateV1::Ready(generation);
        Ok(generation)
    }

    /// Borrow the mutation-capable sender for the installed generation.
    ///
    /// # Errors
    /// Returns [`ErasureHostErrorV1::RecoveryUnavailable`] while closed.
    pub fn command_sender(&mut self) -> Result<ErasureCommandSenderV1<'_, S>, ErasureHostErrorV1> {
        let generation = self.ready_generation()?;
        Ok(ErasureCommandSenderV1 {
            host: self,
            generation,
        })
    }

    /// Borrow the read-only sender for the installed generation.
    ///
    /// # Errors
    /// Returns [`ErasureHostErrorV1::RecoveryUnavailable`] while closed.
    pub fn read_sender(&mut self) -> Result<ErasureReadSenderV1<'_, S>, ErasureHostErrorV1> {
        let generation = self.ready_generation()?;
        Ok(ErasureReadSenderV1 {
            host: self,
            generation,
        })
    }

    fn ready_generation(&self) -> Result<ErasureReferenceV1, ErasureHostErrorV1> {
        match self.state {
            HostStateV1::Ready(generation)
                if self.gate.inventory_generation() == Ok(generation) =>
            {
                Ok(generation)
            }
            HostStateV1::Closed | HostStateV1::Ready(_) | HostStateV1::Poisoned => {
                Err(ErasureHostErrorV1::RecoveryUnavailable)
            }
        }
    }

    fn ensure_generation(
        &mut self,
        expected: ErasureReferenceV1,
    ) -> Result<(), ErasureHostErrorV1> {
        match self.ready_generation() {
            Ok(current) if current == expected => Ok(()),
            Ok(_) => Err(ErasureHostErrorV1::StaleGeneration),
            Err(error) => {
                self.state = HostStateV1::Poisoned;
                Err(error)
            }
        }
    }
}

impl<S> ErasureExecutionHostV1<S>
where
    S: EventStore + ErasureInventoryPersistencePortV1,
{
    /// Recover a new store only when its complete durable request set is empty.
    ///
    /// # Errors
    /// A non-empty request set, failed adapter snapshot, or rejected gate
    /// binding fails closed. Production recovery for a non-empty set must use
    /// [`Self::new_closed`] followed by [`Self::install_inventory`].
    pub fn recover_verified_empty(
        mut store: S,
        maximum_requests: usize,
    ) -> Result<Self, ErasureHostErrorV1> {
        let snapshot = store
            .complete_erasure_inventory_snapshot(maximum_requests)
            .map_err(|_| ErasureHostErrorV1::RecoveryUnavailable)?;
        let inventory =
            ErasureVerifiedInventoryV1::from_verified_empty_snapshot(snapshot, maximum_requests)
                .map_err(|_| ErasureHostErrorV1::RecoveryUnavailable)?;
        let mut host = Self::new_closed(store)?;
        let mut query = OneShotInventoryV1(Some(inventory));
        host.install_inventory(&mut query, maximum_requests)?;
        Ok(host)
    }
}

/// Mutation-capable, generation-bound host sender.
pub struct ErasureCommandSenderV1<'host, S> {
    host: &'host mut ErasureExecutionHostV1<S>,
    generation: ErasureReferenceV1,
}

impl<S: EventStore> ErasureCommandSenderV1<'_, S> {
    /// Append authoritative Events inside the installed erasure fence.
    ///
    /// # Errors
    /// Returns only payload-free host errors.
    pub fn append(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        self.host
            .store
            .append(timeline, drafts)
            .map_err(map_store_error)
    }
}

/// Read-only, generation-bound host sender used by Replay and query paths.
pub struct ErasureReadSenderV1<'host, S> {
    host: &'host mut ErasureExecutionHostV1<S>,
    generation: ErasureReferenceV1,
}

impl<S: EventStore> ErasureReadSenderV1<'_, S> {
    /// Read a bounded Timeline range under the current inventory generation.
    ///
    /// # Errors
    /// Returns only payload-free host errors.
    pub fn read_bounded(
        &mut self,
        timeline: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
    ) -> Result<Vec<Event>, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        self.host
            .store
            .read_bounded(timeline, range, bounds)
            .map_err(map_store_error)
    }

    /// Read one Timeline's metadata under the current inventory generation.
    ///
    /// # Errors
    /// Returns only payload-free host errors.
    pub fn timeline(
        &mut self,
        timeline: TimelineId,
    ) -> Result<Option<Timeline>, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        self.host
            .store
            .get_timeline(timeline)
            .map_err(map_store_error)
    }
}

fn map_store_error(error: CoreError) -> ErasureHostErrorV1 {
    match error {
        CoreError::ErasureAccessFrozen => ErasureHostErrorV1::AccessFrozen,
        CoreError::ErasureContainmentUnavailable => ErasureHostErrorV1::RecoveryUnavailable,
        _ => ErasureHostErrorV1::AdapterFailure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_store::memory::MemoryStore;

    struct FailingInventoryV1;

    impl ErasureVerifiedInventoryQueryV1 for FailingInventoryV1 {
        fn verified_inventory(
            &mut self,
            _maximum_requests: usize,
        ) -> Result<ErasureVerifiedInventoryV1, pos_core::ErasureErrorV1> {
            Err(pos_core::ErasureErrorV1::ProvenanceMissing)
        }
    }

    #[test]
    fn host_stays_closed_until_positive_empty_inventory_is_installed() {
        let mut closed =
            ErasureExecutionHostV1::new_closed(MemoryStore::new().without_erasure_gate())
                .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert!(matches!(
            closed.read_sender(),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        ));

        let mut ready = ErasureExecutionHostV1::recover_verified_empty(
            MemoryStore::new().without_erasure_gate(),
            4,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert!(ready.read_sender().is_ok());
        assert!(ready.command_sender().is_ok());
    }

    #[test]
    fn failed_install_permanently_closes_the_host_instance() {
        let mut host =
            ErasureExecutionHostV1::new_closed(MemoryStore::new().without_erasure_gate())
                .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert_eq!(
            host.install_inventory(&mut FailingInventoryV1, 4),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        );
        assert!(matches!(
            host.command_sender(),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        ));
        assert_eq!(
            host.install_inventory(&mut FailingInventoryV1, 4),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        );
    }

    #[test]
    fn host_error_mapping_is_payload_free() {
        assert_eq!(
            map_store_error(CoreError::ErasureAccessFrozen),
            ErasureHostErrorV1::AccessFrozen
        );
        assert_eq!(
            map_store_error(CoreError::ErasureContainmentUnavailable),
            ErasureHostErrorV1::RecoveryUnavailable
        );
        assert_eq!(
            map_store_error(CoreError::IdGenerationOverflow),
            ErasureHostErrorV1::AdapterFailure
        );
    }
}
