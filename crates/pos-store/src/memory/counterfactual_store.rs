//! `MemoryStore` adapter for the ADR-064 counterfactual storage port.
//!
//! Every write stages before it installs: the adapter rechecks the persisted
//! [`CounterfactualBasisV1`] against the committed state first, then appends
//! the Tick's Events to a scratch copy of the Fork Timeline's head metadata
//! (never its committed Events), builds the receipt or Tick outcome from the
//! staged head, and only then installs the staged Events and, for an
//! invalidation, applies the next generation in place. Installing is
//! infallible, so a conflict, an error, or an injected failure leaves the
//! store unchanged, and a commit copies neither the Fork's committed Events
//! nor the retained `RCF1`/`SIV1` bytes of earlier generations.
//!
//! # ADR gap decisions
//!
//! - **Host-published facts.** `MemoryStore` owns no counterfactual plan,
//!   dependency graph, or trust/revocation/erasure epoch. The host publishes
//!   them per Fork with
//!   [`CounterfactualStorePortV1::publish_counterfactual_facts`]; the first
//!   publication starts the Fork at generation 0, and a republication
//!   replaces only the facts, never the generation or the stored artifacts,
//!   so the generation never decreases. The adapter rechecks against
//!   whatever facts were published last.
//! - **Epoch monotonicity.** The store does not require a republished trust,
//!   revocation, or erasure epoch to be at least the previously published
//!   one; keeping the published epochs monotonic is a host obligation.
//! - **Logical Head.** The rechecked head is the Fork Timeline's committed
//!   logical head (inherited prefix plus its own Events), matching the
//!   admitted-batch adapter.
//! - **Recheck order.** The basis is rechecked before any Tick is staged, so
//!   a stale invalidation or later Tick reports its conflict even when its
//!   drafts could not be appended (including drafts the non-geographic/consent
//!   guard rejects), matching the `SQLite` adapter.
//! - **Tick admission.** The first and every later recomputation Tick apply
//!   the generic append guard `ensure_non_geographic_drafts`; a rejected
//!   draft is concealed as `ForkNotFound` and commits nothing.
//! - **Readable artifacts.** The committed `RCF1` and `SIV1` bytes become
//!   readable by their self-digests at the new generation. Bytes committed by
//!   an earlier generation stay readable at later generations unless they
//!   were quarantined: they are retained audit records by design, not
//!   authoritative Fork state. Staging later recomputed outputs is owned by
//!   the coordinator slices, not this adapter.
//! - **Quarantine by generation.** The adapter keeps, per artifact digest,
//!   its bytes with the latest generation that wrote them, and the latest
//!   [`CounterfactualInvalidationCommandV1::quarantines_through`] of a
//!   committed index or eviction set that named it, and resolves every read
//!   with [`ForkGenerationV1::resolve_read`]. Quarantined bytes written at or
//!   before that generation stay retained for audit only; the same bytes
//!   written again by a later generation are readable there. A quarantined
//!   digest this store holds no bytes for reads as absent.
//! - **Recovery read.** Every invalidation persists its receipt's
//!   [`CounterfactualGenerationRecordV1`] keyed by its new generation, and
//!   [`CounterfactualStorePortV1::committed_generation_receipt`] rebuilds the
//!   receipt from it, under the same erasure read fence as every other read.
//! - **Outcome unknown.** Backend failures map through the crate's shared
//!   `counterfactual_port_error`, so a `CoreError::StorageOutcomeUnknown`
//!   would surface as `OutcomeUnknown`. `MemoryStore` never produces one on
//!   these paths: every fallible step runs on staged copies, and installing
//!   is infallible, so a write either commits entirely or fails having
//!   committed nothing, and its state is always settled.
//! - **Deleted Forks.** Deleting a Fork Timeline keeps its counterfactual
//!   state, exactly like the `SQLite` adapter, so a generation never
//!   decreases and the audit bytes are retained. Publication, reads, Tick
//!   appends, and commits on a deleted Fork still report `ForkNotFound`.
//! - **Containment.** The invalidation commit and later Tick appends add
//!   Events, so they run under the ADR-060 erasure write fence and, like every
//!   generic Fork append, are rejected on an ADR-099 admitted Fork whose
//!   appends are reserved for the classified append authority. The
//!   generation, basis, receipt, and artifact reads are derived from the Fork
//!   Timeline, so they run under the ADR-060 erasure read fence like every
//!   other `MemoryStore` Timeline read, and fail closed without a bound
//!   erasure gate. Both fences validate the bound erasure inventory
//!   generation. Publishing facts writes host-owned facts only, touches no
//!   Timeline Event or derived artifact, and is not fenced.
//! - **No data-version check.** The `SQLite` adapter also compares the
//!   database's `PRAGMA data_version` with the bound erasure inventory inside
//!   every counterfactual write transaction (publication, commit, and Tick
//!   append), because another connection may change the same file. A
//!   `MemoryStore` is owned by one handle and has no other writer, so it has
//!   no equivalent check.
//! - **Errors.** A missing, deleted, non-Fork, unpublished, or protected
//!   Timeline, and a Tick draft the generic append guard rejects, is
//!   `ForkNotFound`; a staged head that did not advance is `CorruptState`;
//!   every other backend failure, including a containment denial or an
//!   admitted Fork, is `StorageFailure`.

use std::collections::{BTreeMap, HashSet};

use pos_core::{
    clock::Seq,
    crypto::Hash,
    error::CoreError,
    hasher::Hasher,
    ids::{EventId, TimelineId},
    CounterfactualBasisV1, CounterfactualFactsV1, CounterfactualGenerationReceiptV1,
    CounterfactualGenerationRecordV1, CounterfactualInvalidationCommandV1,
    CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1, CounterfactualStorePortV1,
    CounterfactualTickOutcomeV1, ErasureProtectedOperationV1, ForkGenerationV1,
    PipelineDraftBatchV1, StoredCounterfactualArtifactV1,
};

use super::{MemoryStore, TimelineState};
use crate::counterfactual_adapter::{counterfactual_port_error, COUNTERFACTUAL_SEAL};

/// Test-only fault injected at the staged head, after staging and before
/// installing anything.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InjectedFaultV1 {
    /// Staging fails with a backend error.
    Storage,
    /// The staged head reports no advance past the committed head.
    StalledHead,
}

#[cfg(test)]
thread_local! {
    /// Test-only fault consumed by the next staged Tick.
    static INJECTED_COUNTERFACTUAL_FAULT: std::cell::Cell<Option<InjectedFaultV1>> =
        const { std::cell::Cell::new(None) };
}

/// Retained bytes of one artifact digest.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ArtifactBytesV1 {
    bytes: Vec<u8>,
    /// Latest generation that wrote these bytes.
    written_generation: u64,
}

/// Committed counterfactual state of one Fork.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CounterfactualForkStateV1 {
    facts: CounterfactualFactsV1,
    generation: u64,
    artifacts: BTreeMap<Hash, ArtifactBytesV1>,
    /// Latest generation each digest was quarantined through.
    quarantined: BTreeMap<Hash, u64>,
    /// Receipt record of every committed generation, keyed by generation.
    receipts: BTreeMap<u64, CounterfactualGenerationRecordV1>,
}

impl CounterfactualForkStateV1 {
    const fn new(facts: CounterfactualFactsV1) -> Self {
        Self {
            facts,
            generation: 0,
            artifacts: BTreeMap::new(),
            quarantined: BTreeMap::new(),
            receipts: BTreeMap::new(),
        }
    }

    /// The persisted basis every write is rechecked against.
    const fn basis(&self, fork_logical_head: Seq) -> CounterfactualBasisV1 {
        CounterfactualBasisV1 {
            fork_logical_head,
            generation: self.generation,
            facts: self.facts,
        }
    }

    /// This store's view of one artifact digest, for
    /// [`ForkGenerationV1::resolve_read`].
    fn stored(&self, digest: Hash) -> StoredCounterfactualArtifactV1 {
        self.artifacts
            .get(&digest)
            .map_or(StoredCounterfactualArtifactV1::Absent, |artifact| {
                StoredCounterfactualArtifactV1::Stored {
                    bytes: artifact.bytes.clone(),
                    written_generation: artifact.written_generation,
                    quarantined_through: self.quarantined.get(&digest).copied(),
                }
            })
    }

    /// Apply the command's whole generation in place. Infallible, so it runs
    /// only after every fallible step of the commit succeeded.
    ///
    /// Generations only increase, so overwriting keeps the latest writing and
    /// quarantining generation per digest.
    fn advance(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
        record: CounterfactualGenerationRecordV1,
    ) {
        let generation = command.new_generation().generation;
        let through = command.quarantines_through();
        self.generation = generation;
        self.quarantined.extend(
            command
                .invalid_artifacts()
                .iter()
                .chain(command.evictions())
                .map(|digest| (*digest, through)),
        );
        for (digest, bytes) in [
            (command.frontier().digest(), command.frontier().as_bytes()),
            (
                command.invalidation().digest(),
                command.invalidation().as_bytes(),
            ),
        ] {
            self.artifacts.insert(
                digest,
                ArtifactBytesV1 {
                    bytes: bytes.to_vec(),
                    written_generation: generation,
                },
            );
        }
        self.receipts.insert(generation, record);
    }
}

/// One visible, published Fork's entries, looked up once so the recheck,
/// staging, and install all use the same Timeline and counterfactual state.
struct ForkEntriesV1<'s> {
    fork: TimelineId,
    timeline: &'s mut TimelineState,
    counterfactual: &'s mut CounterfactualForkStateV1,
    event_ids: &'s mut HashSet<EventId>,
    hasher: &'s dyn Hasher,
}

impl ForkEntriesV1<'_> {
    /// The Fork's committed head, generation, and published facts.
    fn persisted_basis(&self) -> CounterfactualBasisV1 {
        self.counterfactual
            .basis(committed_logical_head(self.timeline))
    }

    /// Stage one Tick under the generic append guard on a scratch copy of the
    /// Fork head that holds none of its committed Events. Nothing is
    /// installed, so a failure leaves no partial state.
    fn stage_tick(
        &self,
        drafts: &PipelineDraftBatchV1,
    ) -> Result<StagedTickV1, CounterfactualStoreErrorV1> {
        let mut timeline = TimelineState {
            timeline: self.timeline.timeline.clone(),
            events: Vec::new(),
            chain_head: self.timeline.chain_head,
        };
        crate::ensure_non_geographic_drafts(drafts.drafts(), self.fork)
            .and_then(|()| {
                drafts.drafts().iter().try_for_each(|draft| {
                    MemoryStore::append_one_to_state(&mut timeline, draft, self.hasher).map(drop)
                })
            })
            .and_then(|()| staged_tick_head(&timeline))
            .map(|head| StagedTickV1 { timeline, head })
            .map_err(|error| counterfactual_port_error(&error))
    }

    /// Install a staged Tick's Events on the Fork Timeline. Infallible.
    fn install_tick(&mut self, tick: StagedTickV1) {
        let staged = tick.timeline;
        self.event_ids
            .extend(staged.events.iter().map(|event| event.id));
        self.timeline.chain_head = staged.chain_head;
        self.timeline.timeline.head = staged.timeline.head;
        self.timeline.events.extend(staged.events);
    }
}

/// One recomputation Tick staged on a scratch copy of the Fork head.
struct StagedTickV1 {
    /// The Fork's head metadata with only the Tick's Events appended.
    timeline: TimelineState,
    /// Fork Logical Head after the Tick.
    head: Seq,
}

/// The inherited logical prefix of one Timeline state.
fn logical_prefix(state: &TimelineState) -> u64 {
    state
        .timeline
        .meta
        .fork_point
        .map_or(0, |(_, fork)| fork.as_u64())
}

/// The logical head of one committed Timeline state: inherited prefix plus
/// own Events. Every committed Event's logical sequence was checked when it
/// was appended, so the sum cannot overflow.
fn committed_logical_head(state: &TimelineState) -> Seq {
    Seq::from_u64(logical_prefix(state).saturating_add(state.timeline.head.as_u64()))
}

/// The staged head after a Tick, the last fallible step before anything is
/// installed.
fn staged_tick_head(staged: &TimelineState) -> Result<Seq, CoreError> {
    #[cfg(test)]
    match INJECTED_COUNTERFACTUAL_FAULT.with(std::cell::Cell::take) {
        Some(InjectedFaultV1::Storage) => {
            return Err(CoreError::Storage(
                "injected counterfactual install failure".to_owned(),
            ));
        }
        Some(InjectedFaultV1::StalledHead) => return Ok(Seq::from_u64(logical_prefix(staged))),
        None => {}
    }
    crate::checked_logical_head(logical_prefix(staged), staged.timeline.head.as_u64())
        .map(Seq::from_u64)
}

impl MemoryStore {
    fn ensure_visible_fork(&self, fork: TimelineId) -> Result<(), CounterfactualStoreErrorV1> {
        self.ensure_generic_timeline_visibility(fork)
            .map_err(|error| counterfactual_port_error(&error))
            .and_then(|()| {
                if self.state(fork).timeline.meta.fork_point.is_some() {
                    Ok(())
                } else {
                    Err(CounterfactualStoreErrorV1::ForkNotFound)
                }
            })
    }

    fn counterfactual_fork(
        &self,
        fork: TimelineId,
    ) -> Result<&CounterfactualForkStateV1, CounterfactualStoreErrorV1> {
        self.ensure_visible_fork(fork).and_then(|()| {
            self.counterfactual_forks
                .get(&fork)
                .ok_or(CounterfactualStoreErrorV1::ForkNotFound)
        })
    }

    /// Borrow one visible, published Fork's entries for a write.
    fn fork_entries(
        &mut self,
        fork: TimelineId,
    ) -> Result<ForkEntriesV1<'_>, CounterfactualStoreErrorV1> {
        self.ensure_visible_fork(fork)?;
        let Self {
            ref mut timelines,
            ref mut counterfactual_forks,
            ref mut event_ids,
            ref hasher,
            ..
        } = *self;
        let hasher: &dyn Hasher = hasher.as_ref();
        timelines
            .get_mut(&fork)
            .zip(counterfactual_forks.get_mut(&fork))
            .map(move |(timeline, counterfactual)| ForkEntriesV1 {
                fork,
                timeline,
                counterfactual,
                event_ids,
                hasher,
            })
            .ok_or(CounterfactualStoreErrorV1::ForkNotFound)
    }

    /// The Fork's committed head, generation, and published facts.
    fn persisted_counterfactual_basis(
        &self,
        fork: TimelineId,
    ) -> Result<CounterfactualBasisV1, CounterfactualStoreErrorV1> {
        self.counterfactual_fork(fork)
            .map(|state| state.basis(committed_logical_head(self.state(fork))))
    }

    /// Recheck the persisted basis, stage the first Tick, build the receipt,
    /// and only then install the Tick and the generation.
    fn commit_visible_counterfactual(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
    ) -> Result<CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1> {
        let mut entries = self.fork_entries(command.fork())?;
        let persisted = entries.persisted_basis();
        if let Some(conflict) = command.expected_basis().first_conflict(&persisted) {
            return Ok(CounterfactualInvalidationOutcomeV1::InvalidationConflict(
                conflict,
            ));
        }
        let tick = entries.stage_tick(command.first_tick_drafts())?;
        // The receipt is built before anything is installed, so even its
        // `CorruptState` rejection commits nothing.
        command
            .committed_receipt(&COUNTERFACTUAL_SEAL, tick.head)
            .map(|receipt| {
                entries.install_tick(tick);
                entries.counterfactual.advance(command, receipt.record());
                CounterfactualInvalidationOutcomeV1::Committed(Box::new(receipt))
            })
    }

    /// Recheck the persisted basis, stage one later Tick, build its outcome,
    /// and only then install the Tick.
    fn append_visible_counterfactual_tick(
        &mut self,
        fork: TimelineId,
        expected: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
    ) -> Result<CounterfactualTickOutcomeV1, CounterfactualStoreErrorV1> {
        let mut entries = self.fork_entries(fork)?;
        let persisted = entries.persisted_basis();
        if let Some(conflict) = expected.first_conflict(&persisted) {
            return Ok(CounterfactualTickOutcomeV1::Stale(conflict));
        }
        let tick = entries.stage_tick(drafts)?;
        // The outcome is built before the Tick is installed, so even its
        // `CorruptState` rejection commits nothing.
        persisted
            .committed_tick(&COUNTERFACTUAL_SEAL, tick.head)
            .inspect(|_| entries.install_tick(tick))
    }
}

impl CounterfactualStorePortV1 for MemoryStore {
    fn publish_counterfactual_facts(
        &mut self,
        fork: TimelineId,
        facts: CounterfactualFactsV1,
    ) -> Result<ForkGenerationV1, CounterfactualStoreErrorV1> {
        self.ensure_visible_fork(fork).map(|()| {
            let state = self
                .counterfactual_forks
                .entry(fork)
                .or_insert_with(|| CounterfactualForkStateV1::new(facts));
            state.facts = facts;
            ForkGenerationV1 {
                fork,
                generation: state.generation,
            }
        })
    }

    fn commit_counterfactual_invalidation(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
    ) -> Result<CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1> {
        let fork = command.fork();
        self.with_erasure_fence(fork, ErasureProtectedOperationV1::Append, |store| {
            store
                .ensure_generic_fork_append_is_rejected(fork)
                .map(|()| store.commit_visible_counterfactual(command))
        })
        .map_err(|error| counterfactual_port_error(&error))
        .and_then(std::convert::identity)
    }

    fn append_counterfactual_tick(
        &mut self,
        fork: TimelineId,
        expected: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
    ) -> Result<CounterfactualTickOutcomeV1, CounterfactualStoreErrorV1> {
        self.with_erasure_fence(fork, ErasureProtectedOperationV1::Append, |store| {
            store
                .ensure_generic_fork_append_is_rejected(fork)
                .map(|()| store.append_visible_counterfactual_tick(fork, expected, drafts))
        })
        .map_err(|error| counterfactual_port_error(&error))
        .and_then(std::convert::identity)
    }

    fn current_fork_generation(
        &self,
        fork: TimelineId,
    ) -> Result<ForkGenerationV1, CounterfactualStoreErrorV1> {
        self.with_erasure_read_fence(fork, ErasureProtectedOperationV1::Read, |store| {
            Ok(store
                .counterfactual_fork(fork)
                .map(|state| ForkGenerationV1 {
                    fork,
                    generation: state.generation,
                }))
        })
        .map_err(|error| counterfactual_port_error(&error))
        .and_then(std::convert::identity)
    }

    fn current_counterfactual_basis(
        &self,
        fork: TimelineId,
    ) -> Result<CounterfactualBasisV1, CounterfactualStoreErrorV1> {
        self.with_erasure_read_fence(fork, ErasureProtectedOperationV1::Read, |store| {
            Ok(store.persisted_counterfactual_basis(fork))
        })
        .map_err(|error| counterfactual_port_error(&error))
        .and_then(std::convert::identity)
    }

    fn committed_generation_receipt(
        &self,
        at: ForkGenerationV1,
    ) -> Result<Option<CounterfactualGenerationReceiptV1>, CounterfactualStoreErrorV1> {
        self.with_erasure_read_fence(at.fork, ErasureProtectedOperationV1::Read, |store| {
            Ok(store
                .counterfactual_fork(at.fork)
                .map(|state| state.receipts.get(&at.generation).copied()))
        })
        .map_err(|error| counterfactual_port_error(&error))
        .and_then(std::convert::identity)
        .and_then(|record| {
            record
                .map(|record| {
                    CounterfactualGenerationReceiptV1::from_record(&COUNTERFACTUAL_SEAL, record)
                })
                .transpose()
        })
    }

    fn read_generation_artifact(
        &self,
        at: ForkGenerationV1,
        artifact_digest: Hash,
    ) -> Result<Option<Vec<u8>>, CounterfactualStoreErrorV1> {
        self.with_erasure_read_fence(at.fork, ErasureProtectedOperationV1::Read, |store| {
            Ok(store
                .counterfactual_fork(at.fork)
                .and_then(|state| at.resolve_read(state.generation, state.stored(artifact_digest))))
        })
        .map_err(|error| counterfactual_port_error(&error))
        .and_then(std::convert::identity)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pos_core::counterfactual_store::test_fixtures::{
        frontier_frame, hash_field, id_field, invalidation_frame, invalidation_middle, uint,
    };
    use pos_core::{
        event::Event, CanonicalBytes, CounterfactualInvalidationInputV1, EntityId,
        ErasureContainmentGateV1, EventDraft, EventStore, ForkAdmissionRecordInputV1,
        ForkAdmissionRecordV1, ForkAttributionOriginV1, InvalidationConflictV1, Kind, OwnerIdV1,
        RecomputationFrontierBytesV1, SuffixInvalidationBytesV1,
    };

    use super::*;

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
        })
    }

    /// Arm one fault for the next staged Tick.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn inject(fault: InjectedFaultV1) {
        INJECTED_COUNTERFACTUAL_FAULT.with(|armed| armed.set(Some(fault)));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn draft(value: u8) -> EventDraft {
        EventDraft::new(
            EntityId::new(),
            Kind::new("counterfactual.tick"),
            CanonicalBytes::from_vec(vec![value]),
        )
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn command(fork: TimelineId) -> CounterfactualInvalidationCommandV1 {
        command_with_trust_epoch(fork, 0)
    }

    /// One invalidation command expecting `trust_epoch`.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn command_with_trust_epoch(
        fork: TimelineId,
        trust_epoch: u64,
    ) -> CounterfactualInvalidationCommandV1 {
        let frontier = ok(RecomputationFrontierBytesV1::try_from_canonical(
            frontier_frame(
                &[
                    id_field([1; 16]),
                    hash_field(Hash::from_bytes([5; 32])),
                    hash_field(Hash::from_bytes([2; 32])),
                    hash_field(Hash::from_bytes([3; 32])),
                    vec![0x01],
                ]
                .concat(),
                0,
            ),
        ));
        let invalidation = ok(SuffixInvalidationBytesV1::try_from_canonical(
            invalidation_frame(
                &[
                    id_field([4; 16]),
                    hash_field(Hash::from_bytes([5; 32])),
                    id_field(fork.inner().to_bytes()),
                    vec![0x00, 0x01],
                    hash_field(frontier.digest()),
                    invalidation_middle(),
                    // Commit coordinate: the Fork, its expected head, the first Tick.
                    vec![0x83],
                    id_field(fork.inner().to_bytes()),
                    uint(1),
                    uint(1),
                ]
                .concat(),
                0,
            ),
        ));
        ok(CounterfactualInvalidationCommandV1::try_new(
            CounterfactualInvalidationInputV1 {
                fork,
                fork_logical_head: Seq::from_u64(1),
                trust_epoch,
                revocation_epoch: 0,
                erasure_epoch: 0,
                frontier,
                invalidation,
                invalid_artifacts: vec![Hash::from_bytes([9; 32])],
                evictions: Vec::new(),
                first_tick: 1,
                first_tick_drafts: ok(PipelineDraftBatchV1::try_new(vec![draft(1)])),
            },
        ))
    }

    /// The facts every test Fork is published with.
    #[cfg_attr(coverage_nightly, coverage(off))]
    const fn facts() -> CounterfactualFactsV1 {
        CounterfactualFactsV1 {
            plan_digest: Hash::from_bytes([5; 32]),
            dependency_graph_digest: Hash::from_bytes([3; 32]),
            trust_epoch: 0,
            revocation_epoch: 0,
            erasure_epoch: 0,
        }
    }

    /// A store with an open erasure gate and a published Fork at logical Seq 1.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn published_store() -> (MemoryStore, TimelineId) {
        let mut store = MemoryStore::new();
        ok(store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open())));
        let root = ok(store.create_timeline("counterfactual-root")).id();
        ok(store.append(root, &[draft(0)]));
        let fork = ok(store.fork(root, Seq::from_u64(1), "counterfactual-fork")).id();
        ok(store.publish_counterfactual_facts(fork, facts()));
        (store, fork)
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn injected_install_failure_leaves_the_store_unchanged() {
        let (mut store, fork) = published_store();
        let command = command(fork);
        let saved_state = store.counterfactual_forks.clone();
        let events = store.state(fork).events.clone();
        let head = store.state(fork).timeline.head;
        let chain_head = store.state(fork).chain_head;
        let event_ids = store.event_ids.clone();

        inject(InjectedFaultV1::Storage);
        let failure = store.commit_counterfactual_invalidation(&command);

        assert_eq!(failure, Err(CounterfactualStoreErrorV1::StorageFailure));
        assert_eq!(store.counterfactual_forks, saved_state);
        assert_eq!(store.state(fork).events, events);
        assert_eq!(store.state(fork).timeline.head, head);
        assert_eq!(store.state(fork).chain_head, chain_head);
        assert_eq!(store.event_ids, event_ids);
        let retried = store.commit_counterfactual_invalidation(&command);
        assert_eq!(
            retried,
            Ok(CounterfactualInvalidationOutcomeV1::Committed(Box::new(
                ok(command.committed_receipt(&COUNTERFACTUAL_SEAL, Seq::from_u64(2)))
            )))
        );
        assert_eq!(store.state(fork).events.len(), 1);
        assert_eq!(store.event_ids.len(), event_ids.len() + 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn conflict_is_reported_before_the_first_tick_is_staged() {
        let (mut store, fork) = published_store();
        let saved_state = store.counterfactual_forks.clone();

        // The armed fault stands in for a first Tick that cannot be staged.
        inject(InjectedFaultV1::Storage);
        let outcome = store.commit_counterfactual_invalidation(&command_with_trust_epoch(fork, 1));
        let staging_ran = INJECTED_COUNTERFACTUAL_FAULT
            .with(std::cell::Cell::take)
            .is_none();

        assert_eq!(
            outcome,
            Ok(CounterfactualInvalidationOutcomeV1::InvalidationConflict(
                InvalidationConflictV1::TrustEpoch
            ))
        );
        assert!(!staging_ran);
        assert_eq!(store.counterfactual_forks, saved_state);
        assert!(store.state(fork).events.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn admitted_fork_commit_fails_closed_without_committing() {
        let (mut store, fork) = published_store();
        store.fork_admissions.insert(
            fork,
            ok(ForkAdmissionRecordV1::new(ForkAdmissionRecordInputV1 {
                operation_id: Hash::from_bytes([1; 32]),
                principal_owner_binding_digest: Hash::from_bytes([2; 32]),
                creator: OwnerIdV1::from_static("test-owner"),
                parent_timeline_id: TimelineId::new(),
                child_timeline_id: fork,
                room_revision_descriptor_hash: Hash::from_bytes([3; 32]),
                parent_logical_head: 0,
                parent_chain_head_hash: Hash::from_bytes([4; 32]),
                completed_fold_cursor: 0,
                post_fold_tick_boundary: 0,
                plugin_composition_hash: Hash::from_bytes([5; 32]),
                attribution_required: false,
                origin: ForkAttributionOriginV1::Local,
            })),
        );
        let saved_state = store.counterfactual_forks.clone();
        let event_ids = store.event_ids.clone();
        let command = command(fork);

        assert_eq!(
            store.commit_counterfactual_invalidation(&command),
            Err(CounterfactualStoreErrorV1::StorageFailure)
        );
        assert_eq!(
            store.append_counterfactual_tick(
                fork,
                &command.expected_basis(),
                command.first_tick_drafts()
            ),
            Err(CounterfactualStoreErrorV1::StorageFailure)
        );
        assert_eq!(
            store.current_fork_generation(fork),
            Ok(ForkGenerationV1 {
                fork,
                generation: 0
            })
        );
        assert_eq!(store.counterfactual_forks, saved_state);
        assert!(store.state(fork).events.is_empty());
        assert_eq!(store.event_ids, event_ids);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn deleted_fork_is_not_found_but_keeps_its_counterfactual_state() {
        let (mut store, fork) = published_store();
        let command = command(fork);
        ok(store.commit_counterfactual_invalidation(&command));
        let saved_state = store.counterfactual_forks.get(&fork).cloned();

        ok(store.delete_timeline(fork));

        assert_eq!(
            store.current_fork_generation(fork),
            Err(CounterfactualStoreErrorV1::ForkNotFound)
        );
        assert_eq!(
            store.read_generation_artifact(
                ForkGenerationV1 {
                    fork,
                    generation: 1
                },
                command.frontier().digest()
            ),
            Err(CounterfactualStoreErrorV1::ForkNotFound)
        );
        assert_eq!(
            store.commit_counterfactual_invalidation(&command),
            Err(CounterfactualStoreErrorV1::ForkNotFound)
        );
        assert_eq!(
            store.publish_counterfactual_facts(fork, facts()),
            Err(CounterfactualStoreErrorV1::ForkNotFound)
        );
        assert_eq!(store.counterfactual_forks.get(&fork).cloned(), saved_state);
        assert_eq!(
            saved_state.map(|state| (state.generation, state.artifacts.len())),
            Some((1, 2))
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn geographic_evidence_protected_fork_is_not_found() {
        let (mut store, fork) = published_store();
        store.geographic_timelines.insert(fork);

        assert_eq!(
            store.publish_counterfactual_facts(fork, facts()),
            Err(CounterfactualStoreErrorV1::ForkNotFound)
        );
        assert_eq!(
            store.current_fork_generation(fork),
            Err(CounterfactualStoreErrorV1::ForkNotFound)
        );
        assert_eq!(
            store.read_generation_artifact(
                ForkGenerationV1 {
                    fork,
                    generation: 0
                },
                Hash::from_bytes([9; 32])
            ),
            Err(CounterfactualStoreErrorV1::ForkNotFound)
        );
        assert_eq!(
            store.commit_counterfactual_invalidation(&command(fork)),
            Err(CounterfactualStoreErrorV1::ForkNotFound)
        );
        assert_eq!(
            store.append_counterfactual_tick(
                fork,
                &command(fork).expected_basis(),
                command(fork).first_tick_drafts()
            ),
            Err(CounterfactualStoreErrorV1::ForkNotFound)
        );
        assert_eq!(
            store.current_counterfactual_basis(fork),
            Err(CounterfactualStoreErrorV1::ForkNotFound)
        );
        assert!(store.state(fork).events.is_empty());
        assert_eq!(
            store
                .counterfactual_forks
                .get(&fork)
                .map(|state| state.generation),
            Some(0)
        );
    }

    /// Fork state, Events, chain head, and Event ID count of one Fork.
    type ForkSnapshot = (Option<CounterfactualForkStateV1>, Vec<Event>, Hash, usize);

    /// Snapshot one Fork to prove nothing committed.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn snapshot(store: &MemoryStore, fork: TimelineId) -> ForkSnapshot {
        (
            store.counterfactual_forks.get(&fork).cloned(),
            store.state(fork).events.clone(),
            store.state(fork).chain_head,
            store.event_ids.len(),
        )
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn stalled_first_tick_head_is_corrupt_and_commits_nothing() {
        let (mut store, fork) = published_store();
        let before = snapshot(&store, fork);

        inject(InjectedFaultV1::StalledHead);
        let outcome = store.commit_counterfactual_invalidation(&command(fork));

        assert_eq!(outcome, Err(CounterfactualStoreErrorV1::CorruptState));
        assert_eq!(snapshot(&store, fork), before);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn stalled_later_tick_head_is_corrupt_and_commits_nothing() {
        let (mut store, fork) = published_store();
        let receipt = match ok(store.commit_counterfactual_invalidation(&command(fork))) {
            CounterfactualInvalidationOutcomeV1::Committed(receipt) => receipt,
            other @ CounterfactualInvalidationOutcomeV1::InvalidationConflict(_) => {
                std::panic::resume_unwind(Box::new(format!("expected a commit, got {other:?}")))
            }
        };
        let expected = receipt.tick_basis(receipt.first_tick_head());
        let drafts = ok(PipelineDraftBatchV1::try_new(vec![draft(2)]));
        let before = snapshot(&store, fork);

        inject(InjectedFaultV1::StalledHead);
        let stalled = store.append_counterfactual_tick(fork, &expected, &drafts);
        inject(InjectedFaultV1::Storage);
        let failed = store.append_counterfactual_tick(fork, &expected, &drafts);

        assert_eq!(stalled, Err(CounterfactualStoreErrorV1::CorruptState));
        assert_eq!(failed, Err(CounterfactualStoreErrorV1::StorageFailure));
        assert_eq!(snapshot(&store, fork), before);
        assert_eq!(
            store.append_counterfactual_tick(fork, &expected, &drafts),
            Ok(CounterfactualTickOutcomeV1::Committed {
                head: Seq::from_u64(3)
            })
        );
    }
}
