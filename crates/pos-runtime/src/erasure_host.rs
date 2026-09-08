//! Single-owner execution boundary for erasure-protected store operations.

use std::sync::Arc;

use pos_core::{
    store::{EventReadBounds, SeqRange},
    CoreError, ErasureCasOutcomeV1, ErasureContainmentGateV1, ErasureErrorV1, ErasureGate,
    ErasureHostErrorV1, ErasureHostStoreV1, ErasureReferenceV1, ErasureVerifiedInventoryQueryV1,
    ErasureVerifiedInventoryV1, Event, EventDraft, PreparedErasureForkBatchV1, Seq, Timeline,
    TimelineId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostStateV1 {
    Closed,
    Ready {
        generation: ErasureReferenceV1,
        maximum_requests: usize,
        request_count: usize,
    },
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
pub struct ErasureExecutionHostV1 {
    store: Box<dyn ErasureHostStoreV1>,
    gate: Arc<ErasureContainmentGateV1>,
    inventory: Option<ErasureVerifiedInventoryV1>,
    state: HostStateV1,
    #[cfg(test)]
    fail_inventory_publication: bool,
}

impl ErasureExecutionHostV1 {
    /// Bind an owned store to one fail-closed gate.
    ///
    /// # Errors
    /// Returns [`ErasureHostErrorV1::AdapterFailure`] when the adapter refuses
    /// the unique host gate binding.
    pub fn new_closed(mut store: Box<dyn ErasureHostStoreV1>) -> Result<Self, ErasureHostErrorV1> {
        let gate = Arc::new(ErasureContainmentGateV1::new_fail_closed());
        let store_gate: Arc<dyn ErasureGate> = gate.clone();
        store
            .bind_erasure_gate(store_gate)
            .map_err(|_| ErasureHostErrorV1::AdapterFailure)?;
        Ok(Self {
            store,
            gate,
            inventory: None,
            state: HostStateV1::Closed,
            #[cfg(test)]
            fail_inventory_publication: false,
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
        self.inventory = None;
        let Ok(inventory) = query.verified_inventory(maximum_requests) else {
            self.state = HostStateV1::Poisoned;
            return Err(ErasureHostErrorV1::RecoveryUnavailable);
        };
        self.publish_inventory(inventory, maximum_requests)
    }

    /// Borrow the mutation-capable sender for the installed generation.
    ///
    /// # Errors
    /// Returns [`ErasureHostErrorV1::RecoveryUnavailable`] while closed.
    pub fn command_sender(&mut self) -> Result<ErasureCommandSenderV1<'_>, ErasureHostErrorV1> {
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
    pub fn read_sender(&mut self) -> Result<ErasureReadSenderV1<'_>, ErasureHostErrorV1> {
        let generation = self.ready_generation()?;
        Ok(ErasureReadSenderV1 {
            host: self,
            generation,
        })
    }

    fn ready_generation(&self) -> Result<ErasureReferenceV1, ErasureHostErrorV1> {
        match self.state {
            HostStateV1::Ready { generation, .. }
                if self.gate.inventory_generation() == Ok(generation) =>
            {
                self.inventory
                    .as_ref()
                    .filter(|inventory| inventory.generation() == generation)
                    .map(|_| generation)
                    .ok_or(ErasureHostErrorV1::RecoveryUnavailable)
            }
            HostStateV1::Closed | HostStateV1::Ready { .. } | HostStateV1::Poisoned => {
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
                self.inventory = None;
                Err(error)
            }
        }
    }

    fn publish_inventory(
        &mut self,
        inventory: ErasureVerifiedInventoryV1,
        maximum_requests: usize,
    ) -> Result<ErasureReferenceV1, ErasureHostErrorV1> {
        let request_count = inventory.request_count();
        let retained_inventory = inventory.clone();
        let mut query = OneShotInventoryV1(Some(inventory));
        #[cfg(test)]
        let publication = if self.fail_inventory_publication {
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        } else {
            self.gate
                .install_from_verified_inventory_query(&mut query, maximum_requests)
                .map_err(ErasureHostErrorV1::from)
        };
        #[cfg(not(test))]
        let publication = self
            .gate
            .install_from_verified_inventory_query(&mut query, maximum_requests)
            .map_err(ErasureHostErrorV1::from);
        let generation = match publication {
            Ok(generation) => generation,
            Err(error) => {
                self.state = HostStateV1::Poisoned;
                self.inventory = None;
                return Err(error);
            }
        };
        self.inventory = Some(retained_inventory);
        self.state = HostStateV1::Ready {
            generation,
            maximum_requests,
            request_count,
        };
        Ok(generation)
    }

    fn apply_empty_topology_change(
        &mut self,
        change: impl FnOnce(&mut dyn ErasureHostStoreV1) -> Result<Timeline, CoreError>,
    ) -> Result<(Timeline, ErasureReferenceV1), ErasureHostErrorV1> {
        let maximum_requests = match self.state {
            HostStateV1::Ready {
                maximum_requests,
                request_count: 0,
                ..
            } => maximum_requests,
            HostStateV1::Closed | HostStateV1::Ready { .. } | HostStateV1::Poisoned => {
                return Err(ErasureHostErrorV1::RecoveryUnavailable)
            }
        };
        let timeline = change(self.store.as_mut()).map_err(|error| map_store_error(&error))?;
        let Ok(inventory) = self
            .store
            .complete_erasure_inventory_snapshot(maximum_requests)
            .and_then(|snapshot| {
                ErasureVerifiedInventoryV1::from_verified_empty_snapshot(snapshot, maximum_requests)
            })
        else {
            self.state = HostStateV1::Poisoned;
            self.inventory = None;
            return Err(ErasureHostErrorV1::RecoveryUnavailable);
        };
        self.publish_inventory(inventory, maximum_requests)
            .map(|generation| (timeline, generation))
    }

    fn apply_fork_batch(
        &mut self,
        admission: PreparedErasureForkBatchV1,
    ) -> Result<(Timeline, ErasureReferenceV1), ErasureHostErrorV1> {
        let current_generation = self.ready_generation()?;
        let maximum_requests = self.maximum_requests()?;
        let expected_generation = admission.expected_inventory_generation();
        let successor = admission.successor_inventory().clone();
        let successor_generation = successor.generation();
        if current_generation != expected_generation && current_generation != successor_generation {
            return Err(ErasureHostErrorV1::StaleGeneration);
        }
        let child = Timeline::new(admission.child().clone());
        let outcome = self
            .store
            .commit_fork_admission(admission)
            .map_err(map_erasure_error)?;
        match (current_generation == expected_generation, outcome) {
            (true, ErasureCasOutcomeV1::Applied | ErasureCasOutcomeV1::ExactRetry) => self
                .publish_inventory(successor, maximum_requests)
                .map(|generation| (child, generation)),
            (false, ErasureCasOutcomeV1::ExactRetry) => Ok((child, current_generation)),
            (false, ErasureCasOutcomeV1::Applied) => {
                self.state = HostStateV1::Poisoned;
                self.inventory = None;
                Err(ErasureHostErrorV1::RecoveryUnavailable)
            }
        }
    }

    const fn maximum_requests(&self) -> Result<usize, ErasureHostErrorV1> {
        match self.state {
            HostStateV1::Ready {
                maximum_requests, ..
            } => Ok(maximum_requests),
            HostStateV1::Closed | HostStateV1::Poisoned => {
                Err(ErasureHostErrorV1::RecoveryUnavailable)
            }
        }
    }
    /// Recover a new store only when its complete durable request set is empty.
    ///
    /// # Errors
    /// A non-empty request set, failed adapter snapshot, or rejected gate
    /// binding fails closed. Production recovery for a non-empty set must use
    /// [`Self::new_closed`] followed by [`Self::install_inventory`].
    pub fn recover_verified_empty(
        mut store: Box<dyn ErasureHostStoreV1>,
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
pub struct ErasureCommandSenderV1<'host> {
    host: &'host mut ErasureExecutionHostV1,
    generation: ErasureReferenceV1,
}

impl ErasureCommandSenderV1<'_> {
    /// Create a root Timeline and publish its successor inventory generation.
    ///
    /// Topology changes are admitted only for a positively verified empty
    /// active-request inventory. Once any erasure request exists, topology
    /// changes require the atomic scope-extension path rather than this seam.
    ///
    /// # Errors
    /// Returns a payload-free host error. If persistence succeeds but successor
    /// publication fails, the host is poisoned and no further sender is issued.
    pub fn create_timeline(&mut self, name: &str) -> Result<Timeline, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        let (timeline, generation) = self
            .host
            .apply_empty_topology_change(|store| store.create_timeline(name))?;
        self.generation = generation;
        Ok(timeline)
    }

    /// Fork a Timeline and publish its successor inventory generation.
    ///
    /// This seam is limited to the positively verified empty active-request
    /// case. Active erasure requests require atomic ERSE1 admission and are
    /// rejected before the child can be persisted.
    ///
    /// # Errors
    /// Returns a payload-free host error and fails closed if successor
    /// inventory publication cannot complete.
    pub fn fork_timeline(
        &mut self,
        parent: TimelineId,
        at_seq: Seq,
        name: &str,
    ) -> Result<Timeline, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        let (timeline, generation) = self
            .host
            .apply_empty_topology_change(|store| store.fork(parent, at_seq, name))?;
        self.generation = generation;
        Ok(timeline)
    }

    /// Commit a complete-set future-Fork batch and publish its successor fence.
    ///
    /// The adapter persists every required ERSE1 mutation and the child under
    /// one atomic boundary. The already verified successor inventory becomes
    /// visible before this method returns the child. Replaying the same batch
    /// after a lost reply returns the same child without another write.
    ///
    /// # Errors
    /// Returns a payload-free stale, conflict, recovery, or adapter error. A
    /// post-commit publication failure permanently poisons this host instance.
    pub fn commit_fork_admission(
        &mut self,
        admission: PreparedErasureForkBatchV1,
    ) -> Result<Timeline, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        let (timeline, generation) = self.host.apply_fork_batch(admission)?;
        self.generation = generation;
        Ok(timeline)
    }

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
            .map_err(|error| map_store_error(&error))
    }
}

/// Read-only, generation-bound host sender used by Replay and query paths.
pub struct ErasureReadSenderV1<'host> {
    host: &'host mut ErasureExecutionHostV1,
    generation: ErasureReferenceV1,
}

impl ErasureReadSenderV1<'_> {
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
            .map_err(|error| map_store_error(&error))
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
            .map_err(|error| map_store_error(&error))
    }

    /// List only Timelines classified by the installed inventory generation.
    ///
    /// # Errors
    /// Returns only payload-free host errors.
    pub fn timelines(&mut self) -> Result<Vec<Timeline>, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        self.host
            .store
            .list_timelines()
            .map_err(|error| map_store_error(&error))
    }

    /// Count visible root Timelines without exceeding `maximum + 1`.
    ///
    /// # Errors
    /// Returns only payload-free host errors.
    pub fn root_timeline_count_bounded(
        &mut self,
        maximum: usize,
    ) -> Result<usize, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        self.host
            .store
            .root_timeline_count_bounded(maximum)
            .map_err(|error| map_store_error(&error))
    }

    /// Return the logical head of one inventory-classified Timeline.
    ///
    /// # Errors
    /// Returns only payload-free host errors.
    pub fn logical_head(&mut self, timeline: TimelineId) -> Result<Seq, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        self.host
            .store
            .logical_head(timeline)
            .map_err(|error| map_store_error(&error))
    }
}

const fn map_store_error(error: &CoreError) -> ErasureHostErrorV1 {
    match error {
        CoreError::ErasureAccessFrozen => ErasureHostErrorV1::AccessFrozen,
        CoreError::ErasureContainmentUnavailable => ErasureHostErrorV1::RecoveryUnavailable,
        _ => ErasureHostErrorV1::AdapterFailure,
    }
}

const fn map_erasure_error(error: ErasureErrorV1) -> ErasureHostErrorV1 {
    match error {
        ErasureErrorV1::Unauthorized => ErasureHostErrorV1::AuthorizationDenied,
        ErasureErrorV1::ScopeInvalid | ErasureErrorV1::PolicyConflict => {
            ErasureHostErrorV1::Conflict
        }
        ErasureErrorV1::InvalidEncoding
        | ErasureErrorV1::UnsupportedVersion
        | ErasureErrorV1::AccessFreezeFailed
        | ErasureErrorV1::TrustSnapshotInvalid
        | ErasureErrorV1::ProvenanceMissing => ErasureHostErrorV1::RecoveryUnavailable,
        ErasureErrorV1::KeyRegistryUnavailable
        | ErasureErrorV1::KeyDestructionFailed
        | ErasureErrorV1::ArtifactDeletionFailed
        | ErasureErrorV1::ReplicaTimeout
        | ErasureErrorV1::ReplicaNegativeAcknowledgement
        | ErasureErrorV1::BackupInventoryIncomplete
        | ErasureErrorV1::BackupDeletionPending
        | ErasureErrorV1::ReceiptCommitFailed => ErasureHostErrorV1::AdapterFailure,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_core::{
        CanonicalBytes, EntityId, ErasureForkAdmissionInputV1,
        ErasurePersistenceInventorySnapshotV1, Kind, TimelineMeta, TimelineMode,
    };
    use pos_store::memory::MemoryStore;

    struct FaultStoreV1 {
        inner: MemoryStore,
        fail_nonempty_inventory: bool,
        misreport_exact_retry: bool,
    }

    impl pos_core::EventStore for FaultStoreV1 {
        fn bind_erasure_gate(&mut self, gate: Arc<dyn ErasureGate>) -> Result<(), CoreError> {
            self.inner.bind_erasure_gate(gate)
        }

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

        fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
            self.inner.get_timeline(id)
        }
    }

    impl pos_core::ErasureInventoryPersistencePortV1 for FaultStoreV1 {
        fn complete_erasure_inventory_snapshot(
            &mut self,
            maximum_requests: usize,
        ) -> Result<ErasurePersistenceInventorySnapshotV1, ErasureErrorV1> {
            let snapshot = self
                .inner
                .complete_erasure_inventory_snapshot(maximum_requests)?;
            if self.fail_nonempty_inventory && !snapshot.topology().is_empty() {
                Err(ErasureErrorV1::ProvenanceMissing)
            } else {
                Ok(snapshot)
            }
        }
    }

    impl pos_core::ErasureForkPersistencePortV1 for FaultStoreV1 {
        fn commit_fork_admission(
            &mut self,
            admission: PreparedErasureForkBatchV1,
        ) -> Result<ErasureCasOutcomeV1, ErasureErrorV1> {
            let outcome = self.inner.commit_fork_admission(admission)?;
            if self.misreport_exact_retry && outcome == ErasureCasOutcomeV1::ExactRetry {
                Ok(ErasureCasOutcomeV1::Applied)
            } else {
                Ok(outcome)
            }
        }
    }

    fn fault_store(fail_nonempty_inventory: bool, misreport_exact_retry: bool) -> FaultStoreV1 {
        FaultStoreV1 {
            inner: MemoryStore::new().without_erasure_gate(),
            fail_nonempty_inventory,
            misreport_exact_retry,
        }
    }

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
            ErasureExecutionHostV1::new_closed(Box::new(MemoryStore::new().without_erasure_gate()))
                .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert!(matches!(
            closed.read_sender(),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        ));

        let mut ready = ErasureExecutionHostV1::recover_verified_empty(
            Box::new(MemoryStore::new().without_erasure_gate()),
            4,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert!(ready.read_sender().is_ok());
        assert!(ready.command_sender().is_ok());
    }

    #[test]
    fn failed_install_permanently_closes_the_host_instance() {
        let mut host =
            ErasureExecutionHostV1::new_closed(Box::new(MemoryStore::new().without_erasure_gate()))
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
            map_store_error(&CoreError::ErasureAccessFrozen),
            ErasureHostErrorV1::AccessFrozen
        );
        assert_eq!(
            map_store_error(&CoreError::ErasureContainmentUnavailable),
            ErasureHostErrorV1::RecoveryUnavailable
        );
        assert_eq!(
            map_store_error(&CoreError::IdGenerationOverflow),
            ErasureHostErrorV1::AdapterFailure
        );
        assert_eq!(
            map_erasure_error(ErasureErrorV1::Unauthorized),
            ErasureHostErrorV1::AuthorizationDenied
        );
        assert_eq!(
            map_erasure_error(ErasureErrorV1::ScopeInvalid),
            ErasureHostErrorV1::Conflict
        );
        assert_eq!(
            map_erasure_error(ErasureErrorV1::InvalidEncoding),
            ErasureHostErrorV1::RecoveryUnavailable
        );
        assert_eq!(
            map_erasure_error(ErasureErrorV1::KeyRegistryUnavailable),
            ErasureHostErrorV1::AdapterFailure
        );
    }

    #[test]
    fn stale_or_internally_inconsistent_generation_fails_closed() {
        let mut host = ErasureExecutionHostV1::recover_verified_empty(
            Box::new(MemoryStore::new().without_erasure_gate()),
            4,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert_eq!(
            host.ensure_generation(ErasureReferenceV1::from_digest([9; 32])),
            Err(ErasureHostErrorV1::StaleGeneration)
        );
        host.inventory = None;
        assert_eq!(
            host.ensure_generation(ErasureReferenceV1::from_digest([9; 32])),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        );
        assert_eq!(host.state, HostStateV1::Poisoned);
        assert_eq!(
            host.maximum_requests(),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        );
    }

    #[test]
    fn active_requests_cannot_use_the_empty_topology_path() {
        let mut host = ErasureExecutionHostV1::recover_verified_empty(
            Box::new(MemoryStore::new().without_erasure_gate()),
            4,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let generation = host
            .ready_generation()
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        host.state = HostStateV1::Ready {
            generation,
            maximum_requests: 4,
            request_count: 1,
        };
        assert_eq!(
            host.command_sender()
                .and_then(|mut sender| sender.create_timeline("denied")),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        );
    }

    #[test]
    fn failed_successor_inventory_refresh_poisons_the_host() {
        let mut host =
            ErasureExecutionHostV1::recover_verified_empty(Box::new(fault_store(true, false)), 4)
                .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert_eq!(
            host.command_sender()
                .and_then(|mut sender| sender.create_timeline("unpublishable")),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        );
        assert!(matches!(
            host.read_sender(),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        ));
    }

    #[test]
    fn failed_gate_publication_poisons_the_host() {
        let mut host = ErasureExecutionHostV1::recover_verified_empty(
            Box::new(MemoryStore::new().without_erasure_gate()),
            4,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        host.fail_inventory_publication = true;
        assert_eq!(
            host.command_sender()
                .and_then(|mut sender| sender.create_timeline("unpublished")),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        );
        assert!(matches!(
            host.command_sender(),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        ));
    }

    #[test]
    fn read_sender_exposes_generation_bound_events_and_metadata() {
        let mut host = ErasureExecutionHostV1::recover_verified_empty(
            Box::new(MemoryStore::new().without_erasure_gate()),
            4,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let timeline = host
            .command_sender()
            .and_then(|mut sender| {
                let timeline = sender.create_timeline("host")?;
                sender.append(
                    timeline.id(),
                    &[
                        EventDraft::new(
                            EntityId::new(),
                            Kind::new("host.fixture"),
                            CanonicalBytes::from_vec(Vec::new()),
                        ),
                        EventDraft::new(
                            EntityId::new(),
                            Kind::new("host.second-fixture"),
                            CanonicalBytes::from_vec(Vec::new()),
                        ),
                    ],
                )?;
                Ok(timeline)
            })
            .unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!("host fixture failed: {error:?}")))
            });
        let mut reader = host
            .read_sender()
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let bounds = EventReadBounds::new(16, 32, 4, 4);
        assert_eq!(
            reader
                .read_bounded(timeline.id(), SeqRange::all(), bounds)
                .map(|events| events.len()),
            Ok(2)
        );
        assert_eq!(
            reader
                .timeline(timeline.id())
                .map(|result| result.map(|item| item.id())),
            Ok(Some(timeline.id()))
        );
        assert_eq!(
            reader
                .timelines()
                .map(|items| items.into_iter().map(|item| item.id()).collect()),
            Ok(vec![timeline.id()])
        );
        assert_eq!(reader.root_timeline_count_bounded(1), Ok(1));
        assert_eq!(reader.logical_head(timeline.id()), Ok(Seq::from_u64(2)));
    }

    fn assert_empty_topology_changes(store: Box<dyn ErasureHostStoreV1>) {
        let mut host = ErasureExecutionHostV1::recover_verified_empty(store, 4)
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let (first, second, child) = host
            .command_sender()
            .and_then(|mut sender| {
                let first = sender.create_timeline("first")?;
                sender.append(
                    first.id(),
                    &[EventDraft::new(
                        EntityId::new(),
                        Kind::new("host.parent-fixture"),
                        CanonicalBytes::from_vec(Vec::new()),
                    )],
                )?;
                let second = sender.create_timeline("second")?;
                let child = sender.fork_timeline(first.id(), Seq::from_u64(1), "child")?;
                Ok((first, second, child))
            })
            .unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!("host creation failed: {error:?}")))
            });

        let mut reader = host
            .read_sender()
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let timelines = reader.timelines().unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("host listing failed: {error:?}")))
        });
        assert_eq!(timelines.len(), 3);
        assert!(timelines.iter().any(|timeline| timeline.id() == first.id()));
        assert!(timelines
            .iter()
            .any(|timeline| timeline.id() == second.id()));
        assert!(timelines.iter().any(|timeline| timeline.id() == child.id()));
        assert_eq!(reader.root_timeline_count_bounded(2), Ok(2));
        assert_eq!(
            reader
                .read_bounded(
                    child.id(),
                    SeqRange::all(),
                    EventReadBounds::new(32, 32, 4, 2),
                )
                .map(|events| events.len()),
            Ok(1)
        );
    }

    #[test]
    fn memory_topology_changes_republish_the_empty_inventory_generation() {
        assert_empty_topology_changes(Box::new(MemoryStore::new().without_erasure_gate()));
    }

    #[test]
    fn sqlite_topology_changes_republish_the_empty_inventory_generation() {
        let store = pos_store::sqlite::SqliteStore::open_in_memory().map_or_else(
            |error| {
                std::panic::resume_unwind(Box::new(format!("SQLite fixture failed: {error:?}")))
            },
            pos_store::sqlite::SqliteStore::without_erasure_gate,
        );
        assert_empty_topology_changes(Box::new(store));
    }

    fn empty_fork_batch(
        parent: TimelineId,
        child: TimelineId,
        operation: ErasureReferenceV1,
    ) -> Result<PreparedErasureForkBatchV1, ErasureErrorV1> {
        let inventory = ErasureVerifiedInventoryV1::from_verified_empty_snapshot(
            ErasurePersistenceInventorySnapshotV1::new(Vec::new(), vec![parent], 4)?,
            4,
        )?;
        inventory.clone().prepare_fork_batch(
            ErasureForkAdmissionInputV1 {
                operation,
                expected_inventory_generation: inventory.generation(),
                child_scope: operation,
                child: TimelineMeta {
                    id: child,
                    mode: TimelineMode::Historical,
                    name: None,
                    owner: None,
                    fork_point: Some((parent, Seq::ZERO)),
                },
            },
            Vec::new(),
        )
    }

    #[test]
    fn empty_inventory_rejects_invalid_fork_batch_shapes() {
        let parent = TimelineId::new();
        let child = TimelineId::new();
        let inventory = ErasureVerifiedInventoryV1::from_verified_empty_snapshot(
            ErasurePersistenceInventorySnapshotV1::new(Vec::new(), vec![parent], 4)
                .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}")))),
            4,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let input = ErasureForkAdmissionInputV1 {
            operation: ErasureReferenceV1::from_digest([6; 32]),
            expected_inventory_generation: inventory.generation(),
            child_scope: ErasureReferenceV1::from_digest([7; 32]),
            child: TimelineMeta {
                id: child,
                mode: TimelineMode::Historical,
                name: None,
                owner: None,
                fork_point: Some((parent, Seq::ZERO)),
            },
        };
        let mut root = input.clone();
        root.child.fork_point = None;
        assert_eq!(
            inventory.clone().prepare_fork_batch(root, Vec::new()),
            Err(ErasureErrorV1::PolicyConflict)
        );
        let mut live = input.clone();
        live.child.mode = TimelineMode::Live;
        assert_eq!(
            inventory.clone().prepare_fork_batch(live, Vec::new()),
            Err(ErasureErrorV1::PolicyConflict)
        );
        let mut stale = input.clone();
        stale.expected_inventory_generation = ErasureReferenceV1::from_digest([8; 32]);
        assert_eq!(
            inventory.clone().prepare_fork_batch(stale, Vec::new()),
            Err(ErasureErrorV1::PolicyConflict)
        );
        let mut existing = input.clone();
        existing.child.id = parent;
        assert_eq!(
            inventory.clone().prepare_fork_batch(existing, Vec::new()),
            Err(ErasureErrorV1::PolicyConflict)
        );
        let mut missing_parent = input;
        missing_parent.child.fork_point = Some((TimelineId::new(), Seq::ZERO));
        assert_eq!(
            inventory.prepare_fork_batch(missing_parent, Vec::new()),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }

    #[test]
    fn host_publishes_atomic_unaffected_fork_and_returns_exact_retry() {
        let mut host = ErasureExecutionHostV1::recover_verified_empty(
            Box::new(MemoryStore::new().without_erasure_gate()),
            4,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let parent = host
            .command_sender()
            .and_then(|mut sender| sender.create_timeline("parent"))
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let child = TimelineId::new();
        let batch = empty_fork_batch(parent.id(), child, ErasureReferenceV1::from_digest([7; 32]))
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let mut sender = host
            .command_sender()
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert_eq!(
            sender
                .commit_fork_admission(batch.clone())
                .map(|timeline| timeline.id()),
            Ok(child)
        );
        assert_eq!(
            sender
                .commit_fork_admission(batch)
                .map(|timeline| timeline.id()),
            Ok(child)
        );
    }

    #[test]
    fn host_rejects_a_fork_batch_after_an_intervening_topology_change() {
        let mut host = ErasureExecutionHostV1::recover_verified_empty(
            Box::new(MemoryStore::new().without_erasure_gate()),
            4,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let parent = host
            .command_sender()
            .and_then(|mut sender| sender.create_timeline("parent"))
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let batch = empty_fork_batch(
            parent.id(),
            TimelineId::new(),
            ErasureReferenceV1::from_digest([8; 32]),
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let mut sender = host
            .command_sender()
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert!(sender.create_timeline("intervening").is_ok());
        assert_eq!(
            sender.commit_fork_admission(batch),
            Err(ErasureHostErrorV1::StaleGeneration)
        );
    }

    #[test]
    fn impossible_applied_retry_poisons_the_host() {
        let mut host =
            ErasureExecutionHostV1::recover_verified_empty(Box::new(fault_store(false, true)), 4)
                .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let parent = host
            .command_sender()
            .and_then(|mut sender| sender.create_timeline("parent"))
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let batch = empty_fork_batch(
            parent.id(),
            TimelineId::new(),
            ErasureReferenceV1::from_digest([10; 32]),
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        {
            let mut sender = host
                .command_sender()
                .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
            assert!(sender.commit_fork_admission(batch.clone()).is_ok());
            assert_eq!(
                sender.commit_fork_admission(batch),
                Err(ErasureHostErrorV1::RecoveryUnavailable)
            );
        }
        assert!(matches!(
            host.command_sender(),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        ));
    }
}
