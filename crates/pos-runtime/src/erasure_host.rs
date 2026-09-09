//! Single-owner execution boundary for erasure-protected store operations.

use std::sync::Arc;

use pos_core::{
    geo_admission::{GeoLocationAdmissionOutcome, GeoLocationAdmissionRequestV1},
    store::{
        AppendDedupScope, AppendIdentity, AppendIntent, AppendOrDuplicateOutcome, EventReadBounds,
        PurgeOutcome, SeqRange,
    },
    ConsentAppendPermit, CoreError, ErasureCasOutcomeV1, ErasureContainmentGateV1, ErasureErrorV1,
    ErasureForkPersistencePortV1, ErasureForkRecoveryV1, ErasureGate, ErasureHostErrorV1,
    ErasureInventoryPersistencePortV1, ErasureProtectedOperationV1, ErasureReferenceV1,
    ErasureVerifiedInventoryQueryV1, ErasureVerifiedInventoryV1, Event, EventDraft, EventId,
    OwnTracksIngressInputV1, PreparedErasureForkBatchV1, PreparedOwnTracksIngressV1, Seq, Timeline,
    TimelineId,
};
use pos_store::StoreConfig;
use std::num::NonZeroUsize;

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

trait ErasureHostStore:
    pos_core::store::EventStore + ErasureInventoryPersistencePortV1 + ErasureForkPersistencePortV1
{
}

impl<T> ErasureHostStore for T where
    T: pos_core::store::EventStore
        + ErasureInventoryPersistencePortV1
        + ErasureForkPersistencePortV1
{
}

trait ErasureGatewayHostStore:
    ErasureHostStore
    + pos_core::geo_admission::GeoLocationAdmissionStore
    + pos_core::OwnTracksIngressStore
{
}

impl<T> ErasureGatewayHostStore for T where
    T: ErasureHostStore
        + pos_core::geo_admission::GeoLocationAdmissionStore
        + pos_core::OwnTracksIngressStore
{
}

enum OwnedErasureStoreV1 {
    Standard(Box<dyn ErasureHostStore>),
    Gateway(Box<dyn ErasureGatewayHostStore>),
}

impl OwnedErasureStoreV1 {
    fn host_store(&mut self) -> &mut dyn ErasureHostStore {
        match self {
            Self::Standard(store) => store.as_mut(),
            Self::Gateway(store) => store.as_mut(),
        }
    }

    fn gateway_store(&mut self) -> Result<&mut dyn ErasureGatewayHostStore, ErasureHostErrorV1> {
        match self {
            Self::Gateway(store) => Ok(store.as_mut()),
            Self::Standard(_) => Err(ErasureHostErrorV1::AuthorizationDenied),
        }
    }
}

fn open_host_store(config: StoreConfig) -> Result<Box<dyn ErasureHostStore>, CoreError> {
    match config {
        StoreConfig::Memory => Ok(Box::new(pos_store::memory::MemoryStore::new())),
        StoreConfig::Sqlite { path } => pos_store::sqlite::SqliteStore::open(&path)
            .map(|store| Box::new(store) as Box<dyn ErasureHostStore>),
        StoreConfig::SqliteInMemory => pos_store::sqlite::SqliteStore::open_in_memory()
            .map(|store| Box::new(store) as Box<dyn ErasureHostStore>),
    }
}

fn open_gateway_host_store(
    config: StoreConfig,
) -> Result<Box<dyn ErasureGatewayHostStore>, CoreError> {
    match config {
        StoreConfig::Memory => Ok(Box::new(pos_store::memory::MemoryStore::new())),
        StoreConfig::Sqlite { path } => pos_store::sqlite::SqliteStore::open(&path)
            .map(|store| Box::new(store) as Box<dyn ErasureGatewayHostStore>),
        StoreConfig::SqliteInMemory => pos_store::sqlite::SqliteStore::open_in_memory()
            .map(|store| Box::new(store) as Box<dyn ErasureGatewayHostStore>),
    }
}

/// Host-owned store and erasure gate with no raw adapter escape hatch.
///
/// Callers receive either a mutation-capable [`ErasureCommandSenderV1`] or a
/// read-only [`ErasureReadSenderV1`]. Both borrow the one host mutably, which
/// gives synchronous callers one logical command order. Async composition
/// roots place this host behind their existing single-consumer command queue.
pub struct ErasureExecutionHostV1 {
    store: OwnedErasureStoreV1,
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
    fn new_closed(store: Box<dyn ErasureHostStore>) -> Result<Self, ErasureHostErrorV1> {
        Self::new_closed_store(OwnedErasureStoreV1::Standard(store))
    }

    /// Bind an owned Gateway-capable store to one fail-closed gate.
    ///
    /// # Errors
    /// Returns [`ErasureHostErrorV1::AdapterFailure`] when the adapter refuses
    /// the unique host gate binding.
    fn new_gateway_closed(
        store: Box<dyn ErasureGatewayHostStore>,
    ) -> Result<Self, ErasureHostErrorV1> {
        Self::new_closed_store(OwnedErasureStoreV1::Gateway(store))
    }

    fn new_closed_store(mut store: OwnedErasureStoreV1) -> Result<Self, ErasureHostErrorV1> {
        let gate = Arc::new(ErasureContainmentGateV1::new_fail_closed());
        let store_gate: Arc<dyn ErasureGate> = gate.clone();
        store
            .host_store()
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

    /// Open and recover an exclusively owned store only when its durable
    /// erasure inventory is verified empty.
    ///
    /// The adapter never crosses this boundary as an `EventStore`; callers
    /// receive only the recovered host and its bounded command capabilities.
    ///
    /// # Errors
    /// Returns a closed adapter or recovery error before any sender is issued.
    pub fn open_verified_empty(
        config: StoreConfig,
        maximum_requests: usize,
    ) -> Result<Self, ErasureHostErrorV1> {
        let store = open_host_store(config).map_err(|_| ErasureHostErrorV1::AdapterFailure)?;
        Self::recover_verified_empty(store, maximum_requests)
    }

    /// Open and recover an exclusively owned store from one independently
    /// verified complete inventory.
    ///
    /// # Errors
    /// Returns a closed adapter or recovery error before any sender is issued.
    pub fn open_from_verified_query<Q: ErasureVerifiedInventoryQueryV1 + ?Sized>(
        config: StoreConfig,
        query: &mut Q,
        maximum_requests: usize,
    ) -> Result<Self, ErasureHostErrorV1> {
        let store = open_host_store(config).map_err(|_| ErasureHostErrorV1::AdapterFailure)?;
        Self::recover_from_verified_query(store, query, maximum_requests)
    }

    /// Open and recover a Gateway-capable exclusively owned store only when
    /// its durable erasure inventory is verified empty.
    ///
    /// # Errors
    /// Returns a closed adapter or recovery error before any sender is issued.
    pub fn open_gateway_verified_empty(
        config: StoreConfig,
        maximum_requests: usize,
    ) -> Result<Self, ErasureHostErrorV1> {
        let store =
            open_gateway_host_store(config).map_err(|_| ErasureHostErrorV1::AdapterFailure)?;
        Self::recover_verified_empty_gateway(store, maximum_requests)
    }

    /// Open and recover a Gateway-capable exclusively owned store from one
    /// independently verified complete inventory.
    ///
    /// # Errors
    /// Returns a closed adapter or recovery error before any sender is issued.
    pub fn open_gateway_from_verified_query<Q: ErasureVerifiedInventoryQueryV1 + ?Sized>(
        config: StoreConfig,
        query: &mut Q,
        maximum_requests: usize,
    ) -> Result<Self, ErasureHostErrorV1> {
        let store =
            open_gateway_host_store(config).map_err(|_| ErasureHostErrorV1::AdapterFailure)?;
        Self::recover_gateway_from_verified_query(store, query, maximum_requests)
    }

    /// Clone the host's read-only containment view for consumers sequenced by
    /// this host. The returned trait object cannot publish or replace gate
    /// state; the host remains the sole owner of those operations.
    #[must_use]
    pub fn containment_gate(&self) -> Arc<dyn ErasureGate> {
        self.gate.clone()
    }

    /// Bind the independently owned consent authority before Gateway commands
    /// enter the host command stream.
    ///
    /// # Errors
    /// Returns a payload-free host error while recovery is unavailable or when
    /// the owned adapter rejects the authority binding.
    pub fn bind_consent_authority(
        &mut self,
        permit: ConsentAppendPermit,
    ) -> Result<(), ErasureHostErrorV1> {
        self.ready_generation()?;
        self.store
            .host_store()
            .bind_consent_authority(permit)
            .map_store_error()
    }

    /// Install one complete inventory before any protected sender is granted.
    ///
    /// # Errors
    /// Returns a closed recovery error and leaves the host closed when the
    /// query fails or the candidate inventory cannot be published.
    pub fn install_inventory<Q: ErasureVerifiedInventoryQueryV1 + ?Sized>(
        &mut self,
        query: &mut Q,
        maximum_requests: usize,
    ) -> Result<ErasureReferenceV1, ErasureHostErrorV1> {
        if self.state == HostStateV1::Poisoned {
            return Err(ErasureHostErrorV1::RecoveryUnavailable);
        }
        self.state = HostStateV1::Closed;
        self.inventory = None;
        let Ok(inventory) = query
            .verified_inventory(maximum_requests)
            .and_then(|inventory| self.verify_current_inventory(inventory, maximum_requests))
        else {
            self.state = HostStateV1::Poisoned;
            return Err(ErasureHostErrorV1::RecoveryUnavailable);
        };
        self.publish_inventory(inventory, maximum_requests)
    }

    fn verify_current_inventory(
        &mut self,
        inventory: ErasureVerifiedInventoryV1,
        maximum_requests: usize,
    ) -> Result<ErasureVerifiedInventoryV1, ErasureErrorV1> {
        let snapshot = self
            .store
            .host_store()
            .complete_erasure_inventory_snapshot(maximum_requests)?;
        if snapshot.generation() == inventory.generation() {
            Ok(inventory)
        } else {
            Err(ErasureErrorV1::ProvenanceMissing)
        }
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
        let HostStateV1::Ready { generation, .. } = self.state else {
            return Err(ErasureHostErrorV1::RecoveryUnavailable);
        };
        if self.gate.inventory_generation() != Ok(generation) {
            return Err(ErasureHostErrorV1::RecoveryUnavailable);
        }
        self.inventory
            .as_ref()
            .filter(|inventory| inventory.generation() == generation)
            .map(|_| generation)
            .ok_or(ErasureHostErrorV1::RecoveryUnavailable)
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
        let publication = self
            .gate
            .install_from_verified_inventory_query(&mut query, maximum_requests)
            .map_err(ErasureHostErrorV1::from);
        #[cfg(test)]
        let publication = if self.fail_inventory_publication {
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        } else {
            publication
        };
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
        change: impl FnOnce(&mut dyn ErasureHostStore) -> Result<Timeline, CoreError>,
    ) -> Result<(Timeline, ErasureReferenceV1), ErasureHostErrorV1> {
        let HostStateV1::Ready {
            maximum_requests,
            request_count: 0,
            ..
        } = self.state
        else {
            return Err(ErasureHostErrorV1::RecoveryUnavailable);
        };
        let timeline = change(self.store.host_store()).map_store_error()?;
        let Ok(inventory) = self
            .store
            .host_store()
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
            .host_store()
            .commit_fork_admission(admission)
            .map_err(map_erasure_error)?;
        match (current_generation == expected_generation, outcome) {
            (true, ErasureCasOutcomeV1::Applied) => self
                .publish_inventory(successor, maximum_requests)
                .map(|generation| (child, generation)),
            (false, ErasureCasOutcomeV1::ExactRetry) => Ok((child, current_generation)),
            (true, ErasureCasOutcomeV1::ExactRetry) | (false, ErasureCasOutcomeV1::Applied) => {
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
            _ => Err(ErasureHostErrorV1::RecoveryUnavailable),
        }
    }
    /// Recover a new store only when its complete durable request set is empty.
    ///
    /// # Errors
    /// A non-empty request set, failed adapter snapshot, or rejected gate
    /// binding fails closed. Production recovery for a non-empty set enters
    /// through [`Self::open_from_verified_query`].
    fn recover_verified_empty(
        mut store: Box<dyn ErasureHostStore>,
        maximum_requests: usize,
    ) -> Result<Self, ErasureHostErrorV1> {
        let inventory = store
            .complete_erasure_inventory_snapshot(maximum_requests)
            .and_then(|snapshot| {
                ErasureVerifiedInventoryV1::from_verified_empty_snapshot(snapshot, maximum_requests)
            })
            .map_err(|_| ErasureHostErrorV1::RecoveryUnavailable)?;
        let mut query = OneShotInventoryV1(Some(inventory));
        Self::recover_from_verified_query(store, &mut query, maximum_requests)
    }

    /// Recover a store from one complete, independently verified inventory.
    ///
    /// The host compares the opaque inventory generation with a fresh complete
    /// snapshot from the exact store it owns before publishing the gate or
    /// granting a sender. A stale, omitted, or cross-store query therefore
    /// leaves the host permanently closed.
    ///
    /// # Errors
    /// Returns a closed recovery or adapter error when gate binding, inventory
    /// verification, current-store matching, or publication fails.
    fn recover_from_verified_query<Q: ErasureVerifiedInventoryQueryV1 + ?Sized>(
        store: Box<dyn ErasureHostStore>,
        query: &mut Q,
        maximum_requests: usize,
    ) -> Result<Self, ErasureHostErrorV1> {
        let mut host = Self::new_closed(store)?;
        host.install_inventory(query, maximum_requests)?;
        Ok(host)
    }

    /// Recover a Gateway-capable store only when its durable request set is empty.
    ///
    /// # Errors
    /// A non-empty request set, failed adapter snapshot, or rejected gate
    /// binding fails closed.
    fn recover_verified_empty_gateway(
        mut store: Box<dyn ErasureGatewayHostStore>,
        maximum_requests: usize,
    ) -> Result<Self, ErasureHostErrorV1> {
        let inventory = store
            .complete_erasure_inventory_snapshot(maximum_requests)
            .and_then(|snapshot| {
                ErasureVerifiedInventoryV1::from_verified_empty_snapshot(snapshot, maximum_requests)
            })
            .map_err(|_| ErasureHostErrorV1::RecoveryUnavailable)?;
        let mut query = OneShotInventoryV1(Some(inventory));
        Self::recover_gateway_from_verified_query(store, &mut query, maximum_requests)
    }

    /// Recover a Gateway-capable store from one complete verified inventory.
    ///
    /// # Errors
    /// Returns a closed recovery or adapter error under the same current-store
    /// generation checks as [`Self::open_from_verified_query`].
    fn recover_gateway_from_verified_query<Q: ErasureVerifiedInventoryQueryV1 + ?Sized>(
        store: Box<dyn ErasureGatewayHostStore>,
        query: &mut Q,
        maximum_requests: usize,
    ) -> Result<Self, ErasureHostErrorV1> {
        let mut host = Self::new_gateway_closed(store)?;
        host.install_inventory(query, maximum_requests)?;
        Ok(host)
    }
}

/// Mutation-capable, generation-bound host sender.
pub struct ErasureCommandSenderV1<'host> {
    host: &'host mut ErasureExecutionHostV1,
    generation: ErasureReferenceV1,
}

impl ErasureCommandSenderV1<'_> {
    /// Run one protected effect while retaining the host's current Tick
    /// Boundary fence for its complete execution.
    ///
    /// Nested store and Plugin operations reauthorize against the same gate
    /// state without releasing the outer fence. The callback receives only
    /// this generation-bound sender, never the owned `EventStore` adapter.
    ///
    /// # Errors
    /// Returns a payload-free host error when this sender is stale or the
    /// protected operation is frozen or unavailable.
    pub fn with_protected_effect_fence(
        &mut self,
        timeline: TimelineId,
        operation: ErasureProtectedOperationV1,
        effect: &mut dyn FnMut(&mut Self),
    ) -> Result<(), ErasureHostErrorV1> {
        let generation = self.generation;
        self.host
            .ensure_generation(generation)
            .and_then(|()| {
                let gate = Arc::clone(&self.host.gate);
                let mut fenced_effect = || effect(self);
                gate.with_fence(timeline, operation, &mut fenced_effect)
                    .map_err(ErasureHostErrorV1::from)
            })
            .and_then(|()| self.host.ensure_generation(self.generation))
    }

    /// Read one Timeline's metadata inside a larger host command fence.
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
            .host_store()
            .get_timeline(timeline)
            .map_store_error()
    }

    /// Read one Event by durable identifier inside a larger host command
    /// fence.
    ///
    /// # Errors
    /// Returns only payload-free host errors.
    pub fn event_by_id(
        &mut self,
        timeline: TimelineId,
        event: EventId,
    ) -> Result<Option<Event>, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation).and_then(|()| {
            self.host
                .store
                .host_store()
                .read_event_by_id(timeline, event)
                .map_store_error()
        })
    }

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

    /// Recover the original durable Fork result after a lost reply or restart.
    ///
    /// This operation never allocates a child or writes ERSE1 evidence. A
    /// missing operation returns `None`; corrupt or incomplete adapter evidence
    /// fails closed through the recovery capability.
    ///
    /// # Errors
    /// Returns only payload-free host errors for stale sender state, corrupt
    /// durable evidence, or an unavailable adapter.
    pub fn recover_fork_admission(
        &mut self,
        operation: ErasureReferenceV1,
    ) -> Result<Option<ErasureForkRecoveryV1>, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        match self
            .host
            .store
            .host_store()
            .recover_fork_admission(operation)
        {
            Ok(result) => Ok(result),
            Err(error) => {
                self.host.state = HostStateV1::Poisoned;
                self.host.inventory = None;
                Err(map_erasure_error(error))
            }
        }
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
            .host_store()
            .append(timeline, drafts)
            .map_store_error()
    }

    /// Atomically append Events when they fit the owned-event ceiling.
    ///
    /// # Errors
    /// Returns only payload-free host errors.
    pub fn append_bounded(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
        maximum: u64,
    ) -> Result<Option<Vec<Event>>, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        self.host
            .store
            .host_store()
            .append_bounded(timeline, drafts, maximum)
            .map_store_error()
    }

    /// Append a Gateway-owned consent Event inside the current fence.
    ///
    /// # Errors
    /// Returns only payload-free host errors.
    pub fn append_consent_bounded(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
        permit: ConsentAppendPermit,
        maximum: u64,
    ) -> Result<Option<Vec<Event>>, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        self.host
            .store
            .host_store()
            .append_consent_bounded(timeline, drafts, permit, maximum)
            .map_store_error()
    }

    /// Append a consent revocation and its cleanup marker atomically.
    ///
    /// # Errors
    /// Returns only payload-free host errors.
    pub fn append_consent_revocation_bounded(
        &mut self,
        timeline: TimelineId,
        drafts: &[EventDraft],
        permit: ConsentAppendPermit,
        maximum: u64,
        cleanup_scope: AppendDedupScope,
    ) -> Result<Option<Vec<Event>>, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        self.host
            .store
            .host_store()
            .append_consent_revocation_bounded(timeline, drafts, permit, maximum, cleanup_scope)
            .map_store_error()
    }

    /// Append an identified intent or return its exact prior admission.
    ///
    /// # Errors
    /// Returns only payload-free host errors.
    pub fn append_intent_or_duplicate_bounded(
        &mut self,
        timeline: TimelineId,
        identity: AppendIdentity,
        intent: AppendIntent,
        maximum: u64,
    ) -> Result<Option<AppendOrDuplicateOutcome>, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        self.host
            .store
            .host_store()
            .append_intent_or_duplicate_bounded(timeline, identity, intent, maximum)
            .map_store_error()
    }

    /// Remove one bounded batch of expired append identities.
    ///
    /// # Errors
    /// Returns only payload-free host errors.
    pub fn purge_expired_append_identities_bounded(
        &mut self,
        limit: NonZeroUsize,
    ) -> Result<PurgeOutcome, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        self.host
            .store
            .host_store()
            .purge_expired_append_identities_bounded(limit)
            .map_store_error()
    }

    /// Remove one bounded batch of append identities for a revoked scope.
    ///
    /// # Errors
    /// Returns only payload-free host errors.
    pub fn remove_append_identities_bounded(
        &mut self,
        scope: AppendDedupScope,
        limit: NonZeroUsize,
    ) -> Result<PurgeOutcome, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        self.host
            .store
            .host_store()
            .remove_append_identities_bounded(scope, limit)
            .map_store_error()
    }

    /// Return the next durable append-identity cleanup marker.
    ///
    /// # Errors
    /// Returns only payload-free host errors.
    pub fn pending_append_identity_cleanup(
        &mut self,
    ) -> Result<Option<AppendDedupScope>, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        self.host
            .store
            .host_store()
            .pending_append_identity_cleanup()
            .map_store_error()
    }

    /// Prepare minimized `OwnTracks` ingress through the owned Gateway store.
    ///
    /// # Errors
    /// Returns a payload-free error when the sender is stale, the store lacks
    /// the Gateway capability set, or ingress preparation is rejected.
    pub fn prepare_owntracks_ingress(
        &mut self,
        input: OwnTracksIngressInputV1,
    ) -> Result<PreparedOwnTracksIngressV1, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        self.host
            .store
            .gateway_store()?
            .prepare_owntracks_ingress(input)
            .map_store_error()
    }

    /// Admit one minimized geographic observation through the owned store.
    ///
    /// # Errors
    /// Returns a payload-free error when the sender is stale, the store lacks
    /// the Gateway capability set, or geographic admission is rejected.
    pub fn admit_geo_location(
        &mut self,
        request: GeoLocationAdmissionRequestV1,
    ) -> Result<GeoLocationAdmissionOutcome, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        self.host
            .store
            .gateway_store()?
            .admit_geo_location(request)
            .map_store_error()
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
            .host_store()
            .read_bounded(timeline, range, bounds)
            .map_store_error()
    }

    /// Read one Event by its durable identifier under the current generation.
    ///
    /// # Errors
    /// Returns only payload-free host errors.
    pub fn event_by_id(
        &mut self,
        timeline: TimelineId,
        event: EventId,
    ) -> Result<Option<Event>, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        self.host
            .store
            .host_store()
            .read_event_by_id(timeline, event)
            .map_store_error()
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
            .host_store()
            .get_timeline(timeline)
            .map_store_error()
    }

    /// List only Timelines classified by the installed inventory generation.
    ///
    /// # Errors
    /// Returns only payload-free host errors.
    pub fn timelines(&mut self) -> Result<Vec<Timeline>, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        self.host
            .store
            .host_store()
            .list_timelines()
            .map_store_error()
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
            .host_store()
            .root_timeline_count_bounded(maximum)
            .map_store_error()
    }

    /// Return the logical head of one inventory-classified Timeline.
    ///
    /// # Errors
    /// Returns only payload-free host errors.
    pub fn logical_head(&mut self, timeline: TimelineId) -> Result<Seq, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        self.host
            .store
            .host_store()
            .logical_head(timeline)
            .map_store_error()
    }

    /// Return the protected logical head used by geographic admission.
    ///
    /// # Errors
    /// Returns a payload-free error when the sender is stale, the store lacks
    /// the Gateway capability set, or the protected head cannot be read.
    pub fn protected_logical_head(
        &mut self,
        timeline: TimelineId,
    ) -> Result<Seq, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation)?;
        let result = match &mut self.host.store {
            OwnedErasureStoreV1::Standard(store) => store.logical_head(timeline),
            OwnedErasureStoreV1::Gateway(store) => store.protected_logical_head(timeline),
        };
        result.map_store_error()
    }
}

const fn map_store_error(error: &CoreError) -> ErasureHostErrorV1 {
    match error {
        CoreError::ErasureAccessFrozen => ErasureHostErrorV1::AccessFrozen,
        CoreError::ErasureContainmentUnavailable => ErasureHostErrorV1::RecoveryUnavailable,
        _ => ErasureHostErrorV1::AdapterFailure,
    }
}

trait MapStoreErrorV1<T> {
    fn map_store_error(self) -> Result<T, ErasureHostErrorV1>;
}

impl<T> MapStoreErrorV1<T> for Result<T, CoreError> {
    fn map_store_error(self) -> Result<T, ErasureHostErrorV1> {
        self.map_err(|error| map_store_error(&error))
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
        geo_admission::GeoLocationAdmissionInputV1, AppendDedupKey, CanonicalBytes,
        ConsentAuthority, ConsentGrantedV1, ConsentRevokedV1, EntityId,
        ErasureForkAdmissionInputV1, ErasurePersistenceInventorySnapshotV1, Kind, TimelineMeta,
        TimelineMode, MODALITY_LOCATION,
    };
    use pos_store::memory::MemoryStore;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum FaultModeV1 {
        BindGate,
        InventorySnapshot,
        NonemptyRequestInventory,
        NonemptyInventory,
        MisreportInitialExactRetry,
        MisreportExactRetry,
        ForkCommit,
        Recovery,
        EventStore,
    }

    struct FaultStoreV1 {
        inner: MemoryStore,
        fault: FaultModeV1,
    }

    impl pos_core::EventStore for FaultStoreV1 {
        fn bind_erasure_gate(&mut self, gate: Arc<dyn ErasureGate>) -> Result<(), CoreError> {
            if self.fault == FaultModeV1::BindGate {
                Err(CoreError::Storage("fault bind".to_owned()))
            } else {
                self.inner.bind_erasure_gate(gate)
            }
        }

        fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
            if self.fault == FaultModeV1::EventStore {
                Err(CoreError::Storage("fault create".to_owned()))
            } else {
                self.inner.create_timeline(name)
            }
        }

        fn append(
            &mut self,
            timeline: TimelineId,
            drafts: &[EventDraft],
        ) -> Result<Vec<Event>, CoreError> {
            if self.fault == FaultModeV1::EventStore {
                Err(CoreError::Storage("fault append".to_owned()))
            } else {
                self.inner.append(timeline, drafts)
            }
        }

        fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
            if self.fault == FaultModeV1::EventStore {
                Err(CoreError::Storage("fault read".to_owned()))
            } else {
                self.inner.read(timeline, range)
            }
        }

        fn fork(
            &mut self,
            parent: TimelineId,
            at_seq: Seq,
            name: &str,
        ) -> Result<Timeline, CoreError> {
            if self.fault == FaultModeV1::EventStore {
                Err(CoreError::Storage("fault fork".to_owned()))
            } else {
                self.inner.fork(parent, at_seq, name)
            }
        }

        fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
            if self.fault == FaultModeV1::EventStore {
                Err(CoreError::Storage("fault list".to_owned()))
            } else {
                self.inner.list_timelines()
            }
        }

        fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
            if self.fault == FaultModeV1::EventStore {
                Err(CoreError::Storage("fault timeline".to_owned()))
            } else {
                self.inner.get_timeline(id)
            }
        }
    }

    impl pos_core::ErasureInventoryPersistencePortV1 for FaultStoreV1 {
        fn complete_erasure_inventory_snapshot(
            &mut self,
            maximum_requests: usize,
        ) -> Result<ErasurePersistenceInventorySnapshotV1, ErasureErrorV1> {
            if self.fault == FaultModeV1::InventorySnapshot {
                return Err(ErasureErrorV1::ProvenanceMissing);
            }
            if self.fault == FaultModeV1::NonemptyRequestInventory {
                let request = ErasureReferenceV1::from_digest([34; 32]);
                let manifest = ErasureReferenceV1::from_digest([35; 32]);
                return ErasurePersistenceInventorySnapshotV1::new(
                    vec![(request, manifest)],
                    Vec::new(),
                    maximum_requests,
                );
            }
            let snapshot = self
                .inner
                .complete_erasure_inventory_snapshot(maximum_requests)?;
            if self.fault == FaultModeV1::NonemptyInventory && !snapshot.topology().is_empty() {
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
            if self.fault == FaultModeV1::ForkCommit {
                return Err(ErasureErrorV1::PolicyConflict);
            }
            if self.fault == FaultModeV1::MisreportInitialExactRetry {
                return Ok(ErasureCasOutcomeV1::ExactRetry);
            }
            let outcome = self.inner.commit_fork_admission(admission)?;
            if self.fault == FaultModeV1::MisreportExactRetry
                && outcome == ErasureCasOutcomeV1::ExactRetry
            {
                Ok(ErasureCasOutcomeV1::Applied)
            } else {
                Ok(outcome)
            }
        }

        fn recover_fork_admission(
            &mut self,
            operation: ErasureReferenceV1,
        ) -> Result<Option<ErasureForkRecoveryV1>, ErasureErrorV1> {
            if self.fault == FaultModeV1::Recovery {
                Err(ErasureErrorV1::ProvenanceMissing)
            } else {
                self.inner.recover_fork_admission(operation)
            }
        }
    }

    fn fault_store(fault: FaultModeV1) -> FaultStoreV1 {
        FaultStoreV1 {
            inner: MemoryStore::new().without_erasure_gate(),
            fault,
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
        assert_eq!(
            closed.bind_consent_authority(ConsentAuthority::new().append_permit()),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        );

        let mut ready = ErasureExecutionHostV1::recover_verified_empty(
            Box::new(MemoryStore::new().without_erasure_gate()),
            4,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert!(ready.read_sender().is_ok());
        assert!(ready.command_sender().is_ok());
    }

    #[test]
    fn gateway_store_operations_share_the_recovered_host_generation() {
        let authority = ConsentAuthority::new();
        let mut host = ErasureExecutionHostV1::recover_verified_empty(
            Box::new(MemoryStore::new().without_erasure_gate()),
            4,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert!(Arc::ptr_eq(
            &host.containment_gate(),
            &host.containment_gate()
        ));
        host.bind_consent_authority(authority.append_permit())
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let timeline = host
            .command_sender()
            .and_then(|mut sender| sender.create_timeline("gateway-host"))
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let subject = EntityId::new();
        let ordinary = EventDraft::new(
            subject,
            Kind::new("gateway.hosted"),
            CanonicalBytes::from_vec(vec![1]),
        );
        let first = host
            .command_sender()
            .and_then(|mut sender| {
                sender.append_bounded(timeline.id(), std::slice::from_ref(&ordinary), 8)
            })
            .and_then(|events| events.ok_or(ErasureHostErrorV1::Conflict))
            .and_then(|mut events| events.pop().ok_or(ErasureHostErrorV1::Conflict))
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let identified = EventDraft::new(
            subject,
            Kind::new("gateway.identified"),
            CanonicalBytes::from_vec(vec![2]),
        );
        let identity = AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([3; 32]),
            AppendDedupScope::from_keyed_hash([4; 32]),
        );
        assert!(host
            .command_sender()
            .and_then(|mut sender| sender.append_intent_or_duplicate_bounded(
                timeline.id(),
                identity,
                AppendIntent::new(&identified),
                8,
            ))
            .is_ok());
        let cleanup_scope = append_consent_fixture(&mut host, timeline.id(), subject, &authority);
        {
            let mut sender = host
                .command_sender()
                .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
            assert!(sender.pending_append_identity_cleanup().is_ok());
            assert!(sender
                .remove_append_identities_bounded(cleanup_scope, NonZeroUsize::MIN)
                .is_ok());
            assert!(sender
                .purge_expired_append_identities_bounded(NonZeroUsize::MIN)
                .is_ok());
        }
        assert_eq!(
            host.read_sender()
                .and_then(|mut sender| sender.event_by_id(timeline.id(), first.id))
                .map(|event| event.map(|event| event.id)),
            Ok(Some(first.id))
        );
    }

    fn append_consent_fixture(
        host: &mut ErasureExecutionHostV1,
        timeline: TimelineId,
        subject: EntityId,
        authority: &ConsentAuthority,
    ) -> AppendDedupScope {
        let grant = ConsentGrantedV1 {
            subject_id: subject,
            grantee_id: EntityId::new(),
            purpose: "host-parity".to_owned(),
            modalities: MODALITY_LOCATION,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 1,
            expiry_secs: 0,
            grant_seq: 3,
        };
        let grant_draft = EventDraft::new(
            subject,
            Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1),
            grant
                .encode()
                .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}")))),
        );
        assert!(host
            .command_sender()
            .and_then(|mut sender| sender.append_consent_bounded(
                timeline,
                &[grant_draft],
                authority.append_permit(),
                8,
            ))
            .is_ok());
        let revocation = ConsentRevokedV1 {
            subject_id: subject,
            grantee_id: grant.grantee_id,
            grant_seq: grant.grant_seq,
            fence_seq: 4,
        };
        let revocation_draft = EventDraft::new(
            subject,
            Kind::new(pos_core::EVENT_TYPE_CONSENT_REVOKED_V1),
            revocation
                .encode()
                .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}")))),
        );
        let cleanup_scope = AppendDedupScope::from_keyed_hash([4; 32]);
        assert!(host
            .command_sender()
            .and_then(|mut sender| sender.append_consent_revocation_bounded(
                timeline,
                &[revocation_draft],
                authority.append_permit(),
                8,
                cleanup_scope,
            ))
            .is_ok());
        cleanup_scope
    }

    #[test]
    fn host_creation_rejects_an_adapter_that_refuses_its_unique_gate() {
        assert!(matches!(
            ErasureExecutionHostV1::new_closed(Box::new(fault_store(FaultModeV1::BindGate))),
            Err(ErasureHostErrorV1::AdapterFailure)
        ));
        assert!(ErasureExecutionHostV1::new_gateway_closed(Box::new(
            MemoryStore::new().without_erasure_gate(),
        ))
        .is_ok());
        let mut prebound_gateway = MemoryStore::new().without_erasure_gate();
        assert!(pos_core::store::EventStore::bind_erasure_gate(
            &mut prebound_gateway,
            Arc::new(ErasureContainmentGateV1::new()),
        )
        .is_ok());
        assert!(matches!(
            ErasureExecutionHostV1::new_gateway_closed(Box::new(prebound_gateway)),
            Err(ErasureHostErrorV1::AdapterFailure)
        ));
    }

    #[test]
    fn one_shot_inventory_cannot_be_replayed() {
        let inventory = ErasureVerifiedInventoryV1::from_verified_empty_snapshot(
            ErasurePersistenceInventorySnapshotV1::new(Vec::new(), Vec::new(), 1).unwrap_or_else(
                |error| std::panic::resume_unwind(Box::new(format!("snapshot failed: {error:?}"))),
            ),
            1,
        )
        .unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("inventory failed: {error:?}")))
        });
        let mut query = OneShotInventoryV1(Some(inventory));
        assert!(query.verified_inventory(1).is_ok());
        assert_eq!(
            query.verified_inventory(1),
            Err(ErasureErrorV1::ProvenanceMissing)
        );
    }

    #[test]
    fn empty_recovery_fails_closed_for_unavailable_or_nonempty_request_inventory() {
        assert!(matches!(
            ErasureExecutionHostV1::recover_verified_empty(
                Box::new(fault_store(FaultModeV1::InventorySnapshot)),
                4,
            ),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        ));

        assert!(matches!(
            ErasureExecutionHostV1::recover_verified_empty(
                Box::new(fault_store(FaultModeV1::NonemptyRequestInventory)),
                4,
            ),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        ));
        assert!(matches!(
            ErasureExecutionHostV1::recover_verified_empty(
                Box::new(fault_store(FaultModeV1::BindGate)),
                4,
            ),
            Err(ErasureHostErrorV1::AdapterFailure)
        ));
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
        assert_eq!(
            map_erasure_error(ErasureErrorV1::PolicyConflict),
            ErasureHostErrorV1::Conflict
        );
        for error in [
            ErasureErrorV1::UnsupportedVersion,
            ErasureErrorV1::AccessFreezeFailed,
            ErasureErrorV1::TrustSnapshotInvalid,
            ErasureErrorV1::ProvenanceMissing,
        ] {
            assert_eq!(
                map_erasure_error(error),
                ErasureHostErrorV1::RecoveryUnavailable
            );
        }
        for error in [
            ErasureErrorV1::KeyDestructionFailed,
            ErasureErrorV1::ArtifactDeletionFailed,
            ErasureErrorV1::ReplicaTimeout,
            ErasureErrorV1::ReplicaNegativeAcknowledgement,
            ErasureErrorV1::BackupInventoryIncomplete,
            ErasureErrorV1::BackupDeletionPending,
            ErasureErrorV1::ReceiptCommitFailed,
        ] {
            assert_eq!(map_erasure_error(error), ErasureHostErrorV1::AdapterFailure);
        }
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
    fn gate_generation_mismatch_poisons_the_host() {
        let mut host = ErasureExecutionHostV1::recover_verified_empty(
            Box::new(MemoryStore::new().without_erasure_gate()),
            4,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let generation = host
            .ready_generation()
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        host.gate = Arc::new(ErasureContainmentGateV1::new_fail_closed());
        assert_eq!(
            host.ensure_generation(generation),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        );
        assert_eq!(host.state, HostStateV1::Poisoned);
        assert!(host.inventory.is_none());
    }

    #[test]
    fn every_host_sender_rejects_a_stale_generation_before_adapter_access() {
        let mut host = ErasureExecutionHostV1::recover_verified_empty(
            Box::new(MemoryStore::new().without_erasure_gate()),
            4,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let root = host
            .command_sender()
            .and_then(|mut sender| sender.create_timeline("stale-sender-root"))
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let batch = empty_fork_batch(
            root.id(),
            TimelineId::new(),
            ErasureReferenceV1::from_digest([31; 32]),
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let stale = ErasureReferenceV1::from_digest([32; 32]);

        {
            let mut sender = host
                .command_sender()
                .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
            sender.generation = stale;
            assert_eq!(
                sender.create_timeline("stale"),
                Err(ErasureHostErrorV1::StaleGeneration)
            );
            assert_eq!(
                sender.fork_timeline(root.id(), Seq::ZERO, "stale"),
                Err(ErasureHostErrorV1::StaleGeneration)
            );
            assert_eq!(
                sender.commit_fork_admission(batch),
                Err(ErasureHostErrorV1::StaleGeneration)
            );
            assert_eq!(
                sender.recover_fork_admission(ErasureReferenceV1::from_digest([33; 32])),
                Err(ErasureHostErrorV1::StaleGeneration)
            );
            assert_eq!(
                sender.append(root.id(), &[]),
                Err(ErasureHostErrorV1::StaleGeneration)
            );
        }

        let mut reader = host
            .read_sender()
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        reader.generation = stale;
        assert_eq!(
            reader.read_bounded(root.id(), SeqRange::all(), EventReadBounds::new(1, 1, 1, 1),),
            Err(ErasureHostErrorV1::StaleGeneration)
        );
        assert_eq!(
            reader.timeline(root.id()),
            Err(ErasureHostErrorV1::StaleGeneration)
        );
        assert_eq!(reader.timelines(), Err(ErasureHostErrorV1::StaleGeneration));
        assert_eq!(
            reader.root_timeline_count_bounded(1),
            Err(ErasureHostErrorV1::StaleGeneration)
        );
        assert_eq!(
            reader.logical_head(root.id()),
            Err(ErasureHostErrorV1::StaleGeneration)
        );
    }

    #[test]
    fn specialized_host_senders_reject_stale_generation_before_adapter_access() {
        let mut host = ErasureExecutionHostV1::recover_verified_empty(
            Box::new(MemoryStore::new().without_erasure_gate()),
            4,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let root = host
            .command_sender()
            .and_then(|mut sender| sender.create_timeline("specialized-stale-sender-root"))
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let stale = ErasureReferenceV1::from_digest([32; 32]);
        let draft = EventDraft::new(
            EntityId::new(),
            Kind::new("stale.sender"),
            CanonicalBytes::from_static(b"stale"),
        );
        let identity = AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([41; 32]),
            AppendDedupScope::from_keyed_hash([42; 32]),
        );
        let cleanup_scope = AppendDedupScope::from_keyed_hash([43; 32]);
        let authority = ConsentAuthority::new();
        {
            let mut sender = host
                .command_sender()
                .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
            sender.generation = stale;
            assert_eq!(
                sender.append_bounded(root.id(), &[], 1),
                Err(ErasureHostErrorV1::StaleGeneration)
            );
            assert_eq!(
                sender.append_consent_bounded(root.id(), &[], authority.append_permit(), 1),
                Err(ErasureHostErrorV1::StaleGeneration)
            );
            assert_eq!(
                sender.append_consent_revocation_bounded(
                    root.id(),
                    &[],
                    authority.append_permit(),
                    1,
                    cleanup_scope,
                ),
                Err(ErasureHostErrorV1::StaleGeneration)
            );
            assert_eq!(
                sender.append_intent_or_duplicate_bounded(
                    root.id(),
                    identity,
                    AppendIntent::new(&draft),
                    1,
                ),
                Err(ErasureHostErrorV1::StaleGeneration)
            );
            assert_eq!(
                sender.purge_expired_append_identities_bounded(NonZeroUsize::MIN),
                Err(ErasureHostErrorV1::StaleGeneration)
            );
            assert_eq!(
                sender.remove_append_identities_bounded(cleanup_scope, NonZeroUsize::MIN),
                Err(ErasureHostErrorV1::StaleGeneration)
            );
            assert_eq!(
                sender.pending_append_identity_cleanup(),
                Err(ErasureHostErrorV1::StaleGeneration)
            );
            assert_eq!(
                sender.prepare_owntracks_ingress(owntracks_input()),
                Err(ErasureHostErrorV1::StaleGeneration)
            );
            assert_eq!(
                sender.admit_geo_location(geo_request(root.id())),
                Err(ErasureHostErrorV1::StaleGeneration)
            );
        }
        let mut reader = host
            .read_sender()
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        reader.generation = stale;
        assert_eq!(
            reader.event_by_id(root.id(), EventId::new()),
            Err(ErasureHostErrorV1::StaleGeneration)
        );
        assert_eq!(
            reader.protected_logical_head(root.id()),
            Err(ErasureHostErrorV1::StaleGeneration)
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
    fn closed_and_poisoned_hosts_reject_empty_topology_changes() {
        let mut host =
            ErasureExecutionHostV1::new_closed(Box::new(MemoryStore::new().without_erasure_gate()))
                .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert_eq!(
            host.apply_empty_topology_change(|store| store.create_timeline("closed")),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        );
        assert_eq!(
            host.maximum_requests(),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        );
        host.state = HostStateV1::Poisoned;
        assert_eq!(
            host.apply_empty_topology_change(|store| store.create_timeline("poisoned")),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        );
    }

    #[test]
    fn failed_successor_inventory_refresh_poisons_the_host() {
        let mut host = ErasureExecutionHostV1::recover_verified_empty(
            Box::new(fault_store(FaultModeV1::NonemptyInventory)),
            4,
        )
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

    fn assert_empty_topology_changes(store: Box<dyn ErasureHostStore>) {
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
        let operation = batch.operation();
        let expected_result = batch
            .recovery_result()
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
            sender.recover_fork_admission(operation),
            Ok(Some(expected_result))
        );
        assert_eq!(
            sender.recover_fork_admission(ErasureReferenceV1::from_digest([99; 32])),
            Ok(None)
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
    fn host_maps_fork_commit_failure_without_payload() {
        let mut host = ErasureExecutionHostV1::recover_verified_empty(
            Box::new(fault_store(FaultModeV1::ForkCommit)),
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
            ErasureReferenceV1::from_digest([38; 32]),
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let direct_batch = batch.clone();
        assert_eq!(
            host.command_sender()
                .and_then(|mut sender| sender.commit_fork_admission(batch)),
            Err(ErasureHostErrorV1::Conflict)
        );
        host.state = HostStateV1::Closed;
        assert_eq!(
            host.apply_fork_batch(direct_batch),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        );
    }

    #[test]
    fn impossible_applied_retry_poisons_the_host() {
        let mut host = ErasureExecutionHostV1::recover_verified_empty(
            Box::new(fault_store(FaultModeV1::MisreportExactRetry)),
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

    #[test]
    fn impossible_initial_exact_retry_poisons_the_host() {
        let mut host = ErasureExecutionHostV1::recover_verified_empty(
            Box::new(fault_store(FaultModeV1::MisreportInitialExactRetry)),
            4,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let root = host
            .command_sender()
            .and_then(|mut sender| sender.create_timeline("exact-retry-parent"))
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let batch = empty_fork_batch(
            root.id(),
            TimelineId::new(),
            ErasureReferenceV1::from_digest([36; 32]),
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert_eq!(
            host.command_sender()
                .and_then(|mut sender| sender.commit_fork_admission(batch)),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        );
        assert_eq!(host.state, HostStateV1::Poisoned);
        assert!(host.inventory.is_none());
    }

    #[test]
    fn corrupt_fork_recovery_poisons_the_host() {
        let mut host = ErasureExecutionHostV1::recover_verified_empty(
            Box::new(fault_store(FaultModeV1::Recovery)),
            4,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert_eq!(
            host.command_sender().and_then(|mut sender| {
                sender.recover_fork_admission(ErasureReferenceV1::from_digest([11; 32]))
            }),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        );
        assert!(matches!(
            host.command_sender(),
            Err(ErasureHostErrorV1::RecoveryUnavailable)
        ));
    }

    #[test]
    fn every_hosted_event_store_failure_is_payload_free() {
        let mut host = ErasureExecutionHostV1::recover_verified_empty(
            Box::new(fault_store(FaultModeV1::EventStore)),
            4,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let timeline = TimelineId::new();
        {
            let mut command = host
                .command_sender()
                .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
            assert_eq!(
                command.create_timeline("fault"),
                Err(ErasureHostErrorV1::AdapterFailure)
            );
            assert_eq!(
                command.fork_timeline(timeline, Seq::ZERO, "fault"),
                Err(ErasureHostErrorV1::AdapterFailure)
            );
            assert_eq!(
                command.append(
                    timeline,
                    &[EventDraft::new(
                        EntityId::new(),
                        Kind::new("test.fault"),
                        CanonicalBytes::from_vec(vec![1]),
                    )],
                ),
                Err(ErasureHostErrorV1::AdapterFailure)
            );
        }

        let bounds = EventReadBounds::new(8, 16, 1, 1);
        let mut reader = host
            .read_sender()
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert_eq!(
            reader.read_bounded(timeline, SeqRange::all(), bounds),
            Err(ErasureHostErrorV1::AdapterFailure)
        );
        assert_eq!(
            reader.timeline(timeline),
            Err(ErasureHostErrorV1::AdapterFailure)
        );
        assert_eq!(reader.timelines(), Err(ErasureHostErrorV1::AdapterFailure));
        assert_eq!(
            reader.root_timeline_count_bounded(1),
            Err(ErasureHostErrorV1::AdapterFailure)
        );
        assert_eq!(
            reader.logical_head(timeline),
            Err(ErasureHostErrorV1::AdapterFailure)
        );
    }

    #[test]
    fn standard_host_rejects_gateway_only_commands() {
        let mut host = ErasureExecutionHostV1::recover_verified_empty(
            Box::new(MemoryStore::new().without_erasure_gate()),
            4,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let timeline = host
            .command_sender()
            .and_then(|mut sender| sender.create_timeline("standard"))
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let mut sender = host
            .command_sender()
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert_eq!(
            sender.prepare_owntracks_ingress(owntracks_input()),
            Err(ErasureHostErrorV1::AuthorizationDenied)
        );
        assert_eq!(
            sender.admit_geo_location(geo_request(timeline.id())),
            Err(ErasureHostErrorV1::AuthorizationDenied)
        );
        assert_eq!(
            host.read_sender()
                .and_then(|mut reader| reader.protected_logical_head(timeline.id())),
            Ok(Seq::ZERO)
        );
    }

    #[test]
    fn gateway_host_keeps_specialized_store_capabilities_contained() {
        let mut host = ErasureExecutionHostV1::recover_verified_empty_gateway(
            Box::new(MemoryStore::new().without_erasure_gate()),
            4,
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let timeline = host
            .command_sender()
            .and_then(|mut sender| sender.create_timeline("gateway"))
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        let mut sender = host
            .command_sender()
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))));
        assert_eq!(
            sender.prepare_owntracks_ingress(owntracks_input()),
            Err(ErasureHostErrorV1::AdapterFailure)
        );
        assert_eq!(
            sender.admit_geo_location(geo_request(timeline.id())),
            Err(ErasureHostErrorV1::AdapterFailure)
        );
        assert_eq!(
            host.read_sender()
                .and_then(|mut reader| reader.protected_logical_head(timeline.id())),
            Ok(Seq::ZERO)
        );
    }

    fn owntracks_input() -> OwnTracksIngressInputV1 {
        OwnTracksIngressInputV1::new(
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            CanonicalBytes::from_static(b"payload"),
        )
    }

    fn geo_request(timeline: TimelineId) -> GeoLocationAdmissionRequestV1 {
        GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
            timeline,
            EntityId::new(),
            CanonicalBytes::from_static(b"payload"),
            0,
            ([0; 32], 0, [0; 32]),
            (0, false, 0),
            ([0; 32], [0; 32]),
        ))
    }
}
