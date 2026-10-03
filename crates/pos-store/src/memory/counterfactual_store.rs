//! `MemoryStore` adapter for the ADR-064 counterfactual storage port.
//!
//! One invalidation commits as a single clone-and-swap: the adapter rechecks
//! the persisted [`CounterfactualBasisV1`] against the committed state first,
//! then stages the first recomputation Tick on a copy of the Fork Timeline
//! and the next generation on a copy of the Fork's counterfactual state, and
//! installs both only after every fallible step succeeded. A conflict, an
//! error, or an injected failure therefore leaves the store unchanged.
//! Cloning the per-Fork state is acceptable here: `MemoryStore` is the
//! unindexed in-process reference adapter for tests and benchmarks.
//!
//! # ADR gap decisions
//!
//! - **Host-published facts.** `MemoryStore` owns no counterfactual plan,
//!   dependency graph, or trust/revocation/erasure epoch. The host publishes
//!   them per Fork with [`MemoryStore::publish_counterfactual_facts`]; the
//!   first publication starts the Fork at generation 0, and a republication
//!   replaces only the facts, never the generation or the stored artifacts,
//!   so the generation never decreases. The adapter rechecks against
//!   whatever facts were published last.
//! - **Epoch monotonicity.** The store does not require a republished trust,
//!   revocation, or erasure epoch to be at least the previously published
//!   one; keeping the published epochs monotonic is a host obligation.
//! - **Logical Head.** The rechecked head is the Fork Timeline's committed
//!   logical head (inherited prefix plus its own Events), matching the
//!   admitted-batch adapter.
//! - **Recheck order.** The basis is rechecked before the first Tick is
//!   staged, so a stale command reports `InvalidationConflict` even when its
//!   drafts could not be appended, matching the `SQLite` adapter.
//! - **Readable artifacts.** The committed `RCF1` and `SIV1` bytes become
//!   readable by their self-digests at the new generation. Bytes committed by
//!   an earlier generation stay readable at later generations unless they
//!   were quarantined: they are retained audit records by design, not
//!   authoritative Fork state. Staging later recomputed outputs is owned by
//!   the coordinator slices, not this adapter.
//! - **Quarantine.** Every digest in a committed invalid-artifact index or
//!   eviction set is quarantined permanently: reads report it as
//!   [`StoredCounterfactualArtifactV1::Quarantined`] even when this store
//!   holds its bytes, which stay retained for audit only.
//! - **Deleted Forks.** Deleting a Fork Timeline keeps its counterfactual
//!   state, exactly like the `SQLite` adapter, so a generation never
//!   decreases and the audit bytes are retained. Publication, reads, and
//!   commits on a deleted Fork still report `ForkNotFound`.
//! - **Containment.** The commit appends Events, so it runs under the
//!   ADR-060 erasure write fence and, like every generic Fork append, is
//!   rejected on an ADR-099 admitted Fork whose appends are reserved for the
//!   classified append authority. The generation and artifact reads are
//!   derived from the Fork Timeline, so they run under the ADR-060 erasure
//!   read fence like every other `MemoryStore` Timeline read, and fail closed
//!   without a bound erasure gate. Publishing facts writes host-owned facts
//!   only, touches no Timeline Event or derived artifact, and is not fenced.
//! - **Errors.** A missing, deleted, non-Fork, unpublished, or protected
//!   Timeline is `ForkNotFound`; every other backend failure, including a
//!   containment denial or an admitted Fork, is `StorageFailure`.

use std::collections::{BTreeMap, BTreeSet};

use pos_core::{
    clock::Seq, crypto::Hash, error::CoreError, event::Event, ids::TimelineId,
    CounterfactualBasisV1, CounterfactualInvalidationCommandV1,
    CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1, CounterfactualStorePortV1,
    ErasureProtectedOperationV1, ForkGenerationV1, StoredCounterfactualArtifactV1,
};

use super::{MemoryStore, TimelineState};

#[cfg(test)]
thread_local! {
    /// Test-only fault injected after staging and before installing a generation.
    static FAIL_NEXT_COUNTERFACTUAL_INSTALL: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Host-published facts every invalidation of one Fork is rechecked against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryCounterfactualFactsV1 {
    /// Admitted counterfactual plan digest.
    pub plan_digest: Hash,
    /// Committed dependency-graph digest frontiers are derived from.
    pub dependency_graph_digest: Hash,
    /// Current trust-policy epoch.
    pub trust_epoch: u64,
    /// Current authority revocation epoch.
    pub revocation_epoch: u64,
    /// Current erasure epoch.
    pub erasure_epoch: u64,
}

/// Committed counterfactual state of one Fork.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CounterfactualForkStateV1 {
    facts: MemoryCounterfactualFactsV1,
    generation: u64,
    artifacts: BTreeMap<Hash, Vec<u8>>,
    quarantined: BTreeSet<Hash>,
}

impl CounterfactualForkStateV1 {
    const fn new(facts: MemoryCounterfactualFactsV1) -> Self {
        Self {
            facts,
            generation: 0,
            artifacts: BTreeMap::new(),
            quarantined: BTreeSet::new(),
        }
    }

    /// The persisted basis an invalidation is rechecked against.
    const fn basis(&self, fork_logical_head: Seq) -> CounterfactualBasisV1 {
        CounterfactualBasisV1 {
            fork_logical_head,
            plan_digest: self.facts.plan_digest,
            dependency_graph_digest: self.facts.dependency_graph_digest,
            generation: self.generation,
            trust_epoch: self.facts.trust_epoch,
            revocation_epoch: self.facts.revocation_epoch,
            erasure_epoch: self.facts.erasure_epoch,
        }
    }

    /// This store's view of one artifact digest; quarantine wins over bytes.
    fn stored(&self, digest: Hash) -> StoredCounterfactualArtifactV1 {
        if self.quarantined.contains(&digest) {
            StoredCounterfactualArtifactV1::Quarantined
        } else {
            self.artifacts.get(&digest).cloned().map_or(
                StoredCounterfactualArtifactV1::Absent,
                StoredCounterfactualArtifactV1::Authoritative,
            )
        }
    }

    /// A copy of this state with the command's whole generation applied.
    fn advanced(&self, command: &CounterfactualInvalidationCommandV1) -> Self {
        let mut next = self.clone();
        next.generation = command.new_generation().generation;
        next.quarantined.extend(
            command
                .invalid_artifacts()
                .iter()
                .chain(command.evictions())
                .copied(),
        );
        next.artifacts.insert(
            command.frontier().digest(),
            command.frontier().as_bytes().to_vec(),
        );
        next.artifacts.insert(
            command.invalidation().digest(),
            command.invalidation().as_bytes().to_vec(),
        );
        next
    }
}

/// The first recomputation Tick staged on a copy of the Fork Timeline.
struct StagedFirstTickV1 {
    /// Fork Timeline state with the first Tick's Events appended.
    timeline: TimelineState,
    /// The first Tick's committed Events.
    events: Vec<Event>,
    /// Fork Logical Head after the first Tick.
    head: Seq,
}

/// Map a backend failure onto the closed port errors.
const fn store_error(error: &CoreError) -> CounterfactualStoreErrorV1 {
    if matches!(error, CoreError::TimelineNotFound(_)) {
        CounterfactualStoreErrorV1::ForkNotFound
    } else {
        CounterfactualStoreErrorV1::StorageFailure
    }
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

/// The staged head after the first Tick, the last fallible step before a
/// staged generation is installed.
fn staged_first_tick_head(staged: &TimelineState) -> Result<Seq, CoreError> {
    #[cfg(test)]
    if FAIL_NEXT_COUNTERFACTUAL_INSTALL.with(|fail| fail.replace(false)) {
        return Err(CoreError::Storage(
            "injected counterfactual install failure".to_owned(),
        ));
    }
    crate::checked_logical_head(logical_prefix(staged), staged.timeline.head.as_u64())
        .map(Seq::from_u64)
}

impl MemoryStore {
    /// Publish the host-owned counterfactual facts of one Fork.
    ///
    /// The first publication starts the Fork at generation 0. A later one
    /// replaces only the facts; the committed generation and artifacts stay.
    ///
    /// # Errors
    /// Returns `ForkNotFound` unless `fork` is a visible Fork Timeline.
    pub fn publish_counterfactual_facts(
        &mut self,
        fork: TimelineId,
        facts: MemoryCounterfactualFactsV1,
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

    fn ensure_visible_fork(&self, fork: TimelineId) -> Result<(), CounterfactualStoreErrorV1> {
        self.ensure_generic_timeline_visibility(fork)
            .map_err(|error| store_error(&error))
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

    /// Recheck the persisted basis, then stage the first Tick and install the
    /// whole generation, inside the erasure write fence.
    fn commit_visible_counterfactual(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
    ) -> Result<CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1> {
        let fork = command.fork();
        let state = self.counterfactual_fork(fork)?;
        let prior_head = committed_logical_head(self.state(fork));
        if let Some(conflict) = command
            .expected_basis()
            .first_conflict(&state.basis(prior_head))
        {
            return Ok(CounterfactualInvalidationOutcomeV1::InvalidationConflict(
                conflict,
            ));
        }
        let next = state.advanced(command);
        let tick = self
            .stage_first_tick(command)
            .map_err(|error| store_error(&error))?;
        // The receipt is built before anything is installed, so even its
        // `CorruptState` rejection commits nothing.
        command.committed_receipt(tick.head).map(|receipt| {
            self.event_ids
                .extend(tick.events.iter().map(|event| event.id));
            self.timelines.insert(fork, tick.timeline);
            self.counterfactual_forks.insert(fork, next);
            CounterfactualInvalidationOutcomeV1::Committed(receipt)
        })
    }

    /// Stage the first Tick on a copy of the Fork Timeline. Nothing is
    /// installed, so a failure leaves no partial state.
    fn stage_first_tick(
        &self,
        command: &CounterfactualInvalidationCommandV1,
    ) -> Result<StagedFirstTickV1, CoreError> {
        let mut timeline = self.state(command.fork()).clone();
        let hasher = self.hasher.as_ref();
        command
            .first_tick_drafts()
            .drafts()
            .iter()
            .map(|draft| Self::append_one_to_state(&mut timeline, draft, hasher))
            .collect::<Result<Vec<_>, _>>()
            .and_then(|events| staged_first_tick_head(&timeline).map(|head| (events, head)))
            .map(|(events, head)| StagedFirstTickV1 {
                timeline,
                events,
                head,
            })
    }
}

impl CounterfactualStorePortV1 for MemoryStore {
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
        .map_err(|error| store_error(&error))
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
        .map_err(|error| store_error(&error))
        .and_then(std::convert::identity)
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
        .map_err(|error| store_error(&error))
        .and_then(std::convert::identity)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pos_core::{
        CanonicalBytes, CounterfactualInvalidationInputV1, EntityId, ErasureContainmentGateV1,
        EventDraft, EventStore, ForkAdmissionRecordInputV1, ForkAdmissionRecordV1,
        ForkAttributionOriginV1, InvalidationConflictV1, Kind, OwnerIdV1, PipelineDraftBatchV1,
        RecomputationFrontierBytesV1, SuffixInvalidationBytesV1,
    };

    use super::*;

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn draft(value: u8) -> EventDraft {
        EventDraft::new(
            EntityId::new(),
            Kind::new("counterfactual.tick"),
            CanonicalBytes::from_vec(vec![value]),
        )
    }

    /// Frame fields after the version as one self-digested record.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn frame(heads: (u8, u8), magic: &[u8; 4], domain: &[u8], fields: &[u8]) -> Vec<u8> {
        let mut bytes = vec![heads.0, 0x64];
        bytes.extend_from_slice(magic);
        bytes.push(0x01);
        bytes.extend_from_slice(fields);
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(&[0, heads.1]);
        hasher.update(&bytes[1..]);
        bytes.extend_from_slice(&[0x58, 0x20]);
        bytes.extend_from_slice(hasher.finalize().as_bytes());
        bytes
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn digest_field(value: Hash) -> Vec<u8> {
        [&[0x58, 0x20][..], &value.as_bytes()[..]].concat()
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn id_field(value: [u8; 16]) -> Vec<u8> {
        [&[0x50][..], &value[..]].concat()
    }

    /// Encode one shortest-form CBOR unsigned integer.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn uint(value: u64) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        match value {
            0..=23 => vec![bytes[7]],
            24..=0xff => vec![0x18, bytes[7]],
            0x100..=0xffff => [&[0x19][..], &bytes[6..]].concat(),
            0x1_0000..=0xffff_ffff => [&[0x1a][..], &bytes[4..]].concat(),
            _ => [&[0x1b][..], &bytes[..]].concat(),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn text_field(value: &str) -> Vec<u8> {
        let mut encoded = uint(ok(u64::try_from(value.len())));
        encoded[0] |= 3 << 5;
        [encoded, value.as_bytes().to_vec()].concat()
    }

    /// Encode one six-field dependency-node coordinate.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn node_field(tick: u64, owner: &str) -> Vec<u8> {
        [
            vec![0x86],
            uint(tick),
            uint(0),
            text_field(owner),
            uint(0),
            uint(7),
            digest_field(Hash::from_bytes([21; 32])),
        ]
        .concat()
    }

    /// Encode `SIV1` fields 8 through 14, as the `pos-core` port tests do.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn invalidation_middle() -> Vec<u8> {
        [
            node_field(5, "agent-a"),
            node_field(4_294_967_296, "an-owner-identifier-of-thirty-"),
            vec![0x81, 0x86],
            text_field("event"),
            uint(70_000),
            digest_field(Hash::from_bytes([22; 32])),
            node_field(5, "agent-a"),
            uint(300),
            uint(0),
            vec![0x81],
            digest_field(Hash::from_bytes([23; 32])),
            vec![0x80, 0x80],
            uint(0),
        ]
        .concat()
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
        let frontier = ok(RecomputationFrontierBytesV1::try_from_canonical(frame(
            (0x91, 0x90),
            b"RCF1",
            b"PiglorOS.RecomputationFrontier.v1",
            &[
                id_field([1; 16]),
                digest_field(Hash::from_bytes([5; 32])),
                digest_field(Hash::from_bytes([2; 32])),
                digest_field(Hash::from_bytes([3; 32])),
                vec![0x01],
            ]
            .concat(),
        )));
        let invalidation = ok(SuffixInvalidationBytesV1::try_from_canonical(frame(
            (0x92, 0x91),
            b"SIV1",
            b"PiglorOS.SuffixInvalidation.v1",
            &[
                id_field([4; 16]),
                digest_field(Hash::from_bytes([5; 32])),
                id_field(fork.inner().to_bytes()),
                vec![0x00, 0x01],
                digest_field(frontier.digest()),
                invalidation_middle(),
                // Commit coordinate: the Fork, its expected head, the first Tick.
                vec![0x83],
                id_field(fork.inner().to_bytes()),
                uint(1),
                uint(1),
            ]
            .concat(),
        )));
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
    const fn facts() -> MemoryCounterfactualFactsV1 {
        MemoryCounterfactualFactsV1 {
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

        FAIL_NEXT_COUNTERFACTUAL_INSTALL.with(|fail| fail.set(true));
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
            Ok(CounterfactualInvalidationOutcomeV1::Committed(ok(
                command.committed_receipt(Seq::from_u64(2))
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
        FAIL_NEXT_COUNTERFACTUAL_INSTALL.with(|fail| fail.set(true));
        let outcome = store.commit_counterfactual_invalidation(&command_with_trust_epoch(fork, 1));
        let staging_ran = !FAIL_NEXT_COUNTERFACTUAL_INSTALL.with(|fail| fail.replace(false));

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
        assert!(store.state(fork).events.is_empty());
        assert_eq!(
            store
                .counterfactual_forks
                .get(&fork)
                .map(|state| state.generation),
            Some(0)
        );
    }
}
