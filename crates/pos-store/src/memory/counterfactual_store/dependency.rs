//! `MemoryStore` adapter for the ADR-064 counterfactual dependency record.
//!
//! The recording methods are thin compositions of the counterfactual write
//! path in the parent module: they validate the record against the stored
//! set, run the existing recheck/stage/install commit, and add the record's
//! rows only after that commit installed. Reads page the stored rows through
//! [`DependencyPageV1`].
//!
//! # ADR gap decisions
//!
//! - **Storage layout.** Provisional rows live in the Fork's counterfactual
//!   state, in the one set of the generation that has a record: the rows keyed
//!   by their own page cursor (the canonical node and `IDP1` edge order, so a
//!   read is a keyset range scan and never depends on insertion order), the
//!   artifact digests of the nodes, the largest persisted record Tick, and the
//!   stored row counts. The state holds that single set as a generation and
//!   its rows, and a dependency write of the current generation replaces a set
//!   of any other generation, so the rows of a quarantined generation, which
//!   no read can reach, are dropped by the next write. The Fork's receipt of
//!   the current generation persists its first Tick, which bounds the first
//!   record of the set.
//! - **Atomicity is structural.** Every fallible step (the record checks, the
//!   basis recheck, staging, and the receipt) runs before anything is
//!   installed, and the rows are added by an infallible step that runs only
//!   after the Tick's Events and the generation were installed. A conflict, an
//!   error, or an injected failure therefore leaves the Events, the
//!   generation, and the dependency rows unchanged. The same holds for
//!   `OutcomeUnknown`, which `MemoryStore` never produces.
//! - **Check order.** An invalidation checks its record before the basis,
//!   mirroring the contract, so a misplaced record is a `BindingMismatch` even
//!   for a stale basis. A later Tick rechecks the basis first, so a stale
//!   basis is `Stale` even for a misplaced record; the record is then checked
//!   in the order provisional, Tick, node identity, and set capacity.
//! - **No capacity check for an invalidation.** The set of a new generation
//!   is empty and a record is capped far below the set bounds, so the
//!   capacity check of the first record cannot fail and is not made. Later
//!   records check capacity against the stored counts.
//! - **A generation without a persisted first Tick takes no record.** A Fork
//!   that was published but never invalidated (generation 0), or that was
//!   re-created at its generation floor, has no receipt and so no first Tick
//!   to bound its first record. A later Tick with a record there is a
//!   `BindingMismatch`, and the dependency set of a generation starts at an
//!   invalidation. This is stricter than the contract's reference model,
//!   which starts with a first Tick; it is the confirmed decision.
//! - **Parent-cut Ticks are not enforced.** The contract leaves this to the
//!   coordinator (#552). A Memory Fork row has no cut Tick, only a
//!   `fork_point` (a parent Timeline and a `Seq`), so the adapter cannot
//!   compare, and roots may legitimately carry Ticks below the first
//!   Tick.
//! - **Committed prefix.** The committed prefix of a parent Timeline is kept
//!   once per parent Timeline, outside any Fork, and served as
//!   [`DependencyReadScopeV1::ParentPrefix`] up to its `through_tick`. No write
//!   path exists for it yet (#554), so it stays empty in production and the
//!   unit tests seed it directly. Deleting the parent Timeline purges it.
//! - **Reads and fences.** A parent-prefix read of an unknown or concealed
//!   Timeline is `ForkNotFound`, and one of an existing Timeline without rows
//!   is an empty page. It runs under that Timeline's own erasure read fence
//!   including its inherited scopes. A Fork-generation read runs under the
//!   Fork's read fence like every other counterfactual read and is
//!   `ForkNotFound` for a Fork that is not visible and published, and
//!   `MixedForkGeneration` for any generation but the current one. Both fail
//!   closed without a bound erasure gate; writes run under the write fence
//!   and the admitted-Fork guard of the Tick append they compose.
//! - **Purge.** Deleting a Fork drops its dependency sets with the rest of its
//!   counterfactual state (the generation floor stays), so a re-created Fork
//!   starts with no rows.
//! - **Corrupt rows.** A stored row that fails page re-validation reads back
//!   as `CorruptState`; a request cursor of the other row kind is the
//!   caller's `BindingMismatch`.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

use pos_core::{
    CounterfactualBasisV1, CounterfactualDependencyErrorV1, CounterfactualDependencyReadPortV1,
    CounterfactualDependencyRecordingPortV1, CounterfactualInvalidationCommandV1,
    CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1, CounterfactualTickOutcomeV1,
    DependencyEdgeRecordV1, DependencyNodeRecordV1, DependencyPageCursorV1,
    DependencyPageRequestV1, DependencyPageV1, DependencyPagedRowV1, DependencyReadScopeV1,
    ErasureProtectedOperationV1, ForkGenerationV1, Hash, PipelineDraftBatchV1, RecordedSetCountsV1,
    TickDependencyRecordV1, TimelineId,
};

use super::{fenced_result, CounterfactualForkStateV1};
use crate::memory::MemoryStore;

type StoreError = CounterfactualStoreErrorV1;
/// Rows are keyed by their own page cursor: the canonical coordinate order of
/// nodes and the `IDP1` edge-list order of edges.
type RowKey = DependencyPageCursorV1;
/// Picks the node rows or the edge rows of a set.
type Select<T> = fn(&DependencyRowsV1) -> &BTreeMap<RowKey, T>;

const READ: ErasureProtectedOperationV1 = ErasureProtectedOperationV1::Read;
const APPEND: ErasureProtectedOperationV1 = ErasureProtectedOperationV1::Append;

/// The rows of a Timeline or Fork generation that has none.
static NO_ROWS: DependencyRowsV1 = DependencyRowsV1::new();
/// The set of a generation that has no record.
static NO_SET: ForkDependencySetV1 = ForkDependencySetV1::new();

/// The nodes and edges of one recorded set.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(in crate::memory) struct DependencyRowsV1 {
    nodes: BTreeMap<RowKey, DependencyNodeRecordV1>,
    edges: BTreeMap<RowKey, DependencyEdgeRecordV1>,
}

/// Each row with the cursor that keys it.
fn keyed<T: DependencyPagedRowV1 + Clone>(rows: &[T]) -> Vec<(RowKey, T)> {
    rows.iter().map(|r| (r.cursor(), r.clone())).collect()
}

impl DependencyRowsV1 {
    const fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
        }
    }

    /// Add the rows of one record. Infallible.
    fn extend(&mut self, record: &TickDependencyRecordV1) {
        self.nodes.extend(keyed(record.nodes()));
        self.edges.extend(keyed(record.edges()));
    }
}

/// The provisional rows of one Fork generation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct ForkDependencySetV1 {
    rows: DependencyRowsV1,
    /// Artifact digests of the recorded nodes.
    digests: BTreeSet<Hash>,
    /// Largest Tick of a persisted record, kept apart from the node Ticks.
    last_record_tick: Option<u64>,
    /// Stored row counts of the set.
    counts: RecordedSetCountsV1,
}

impl ForkDependencySetV1 {
    const fn new() -> Self {
        Self {
            rows: DependencyRowsV1::new(),
            digests: BTreeSet::new(),
            last_record_tick: None,
            counts: RecordedSetCountsV1 {
                nodes: 0,
                edges: 0,
                inputs: 0,
            },
        }
    }

    /// Check a later record against the set and the generation's first Tick.
    fn admit(
        &self,
        first_tick: Option<u64>,
        record: &TickDependencyRecordV1,
    ) -> Result<(), StoreError> {
        record
            .ensure_provisional()
            .and_then(|()| self.ensure_tick_order(first_tick, record.tick()))
            .and_then(|()| self.ensure_unrecorded(record))
            .and_then(|()| self.ensure_capacity(record))
    }

    /// The Tick must be strictly after the last record's, or, in an empty
    /// set, not before the generation's first Tick.
    fn ensure_tick_order(&self, first_tick: Option<u64>, tick: u64) -> Result<(), StoreError> {
        let previous = self.last_record_tick;
        let earliest = previous.map_or(first_tick, |recorded| recorded.checked_add(1));
        let fits = earliest.is_some_and(|floor| tick >= floor);
        require_that(fits, StoreError::BindingMismatch)
    }

    /// No node may reuse a recorded position key or artifact digest.
    fn ensure_unrecorded(&self, record: &TickDependencyRecordV1) -> Result<(), StoreError> {
        let repeats = record.nodes().iter().any(|row| self.records(row));
        require_that(!repeats, StoreError::DuplicateIdentity)
    }

    /// Whether the set holds the node's position key or artifact digest.
    fn records(&self, row: &DependencyNodeRecordV1) -> bool {
        self.digests.contains(&row.coordinate().artifact_digest())
            || self.rows.nodes.contains_key(&row.cursor())
    }

    /// The record must fit the set's bounds on top of the stored counts.
    fn ensure_capacity(&self, record: &TickDependencyRecordV1) -> Result<(), StoreError> {
        record
            .ensure_set_capacity(self.counts)
            .map_err(StoreError::from)
    }

    /// Add an admitted record. Infallible.
    fn insert(&mut self, record: &TickDependencyRecordV1) {
        self.rows.extend(record);
        for row in record.nodes() {
            self.digests.insert(row.coordinate().artifact_digest());
        }
        let counts = self.counts;
        self.counts = RecordedSetCountsV1 {
            nodes: counts.nodes.saturating_add(record.nodes().len()),
            edges: counts.edges.saturating_add(record.edges().len()),
            inputs: counts.inputs.saturating_add(record.declared_input_count()),
        };
        self.last_record_tick = Some(record.tick());
    }
}

impl CounterfactualForkStateV1 {
    /// The set of the current generation, if it has a record.
    fn current_set(&self) -> Option<&ForkDependencySetV1> {
        let current = self.dependencies.as_ref();
        current
            .filter(|(held, _)| *held == self.generation)
            .map(|(_, set)| set)
    }

    /// Check a record against the set of the current generation, whose
    /// receipt persists its first Tick.
    fn admit_dependencies(&self, record: &TickDependencyRecordV1) -> Result<(), StoreError> {
        let receipt = self.receipts.get(&self.generation);
        let first_tick = receipt.map(|persisted| persisted.first_tick);
        let set = self.current_set().unwrap_or(&NO_SET);
        set.admit(first_tick, record)
    }

    /// Record under the current generation, replacing any other generation's
    /// set.
    fn record_dependencies(&mut self, record: &TickDependencyRecordV1) {
        let generation = self.generation;
        let kept = self.dependencies.take();
        let held = kept.filter(|(other, _)| *other == generation);
        let mut set = held.map_or_else(ForkDependencySetV1::new, |(_, set)| set);
        set.insert(record);
        self.dependencies = Some((generation, set));
    }

    /// One page of the current generation's rows; a request for any other
    /// generation is a mixed generation.
    fn page_of_current<T: DependencyPagedRowV1 + Clone>(
        &self,
        request: &DependencyPageRequestV1,
        select: Select<T>,
    ) -> Result<DependencyPageV1<T>, StoreError> {
        let current = request.scope().ensure_current(self.generation);
        current.and_then(|()| {
            let rows = self.current_set().map_or(&NO_ROWS, |held| &held.rows);
            page_after(select(rows), request)
        })
    }
}

/// The first record of an invalidation: provisional and at its first Tick.
fn admit_first(first_tick: u64, record: &TickDependencyRecordV1) -> Result<(), StoreError> {
    let tick_check = require_that(record.tick() == first_tick, StoreError::BindingMismatch);
    record.ensure_provisional().and(tick_check)
}

/// `Ok` if `holds`, else `error`.
fn require_that(holds: bool, error: StoreError) -> Result<(), StoreError> {
    holds.then_some(()).ok_or(error)
}

/// Page the rows after the request cursor and within its Tick bound.
fn page_after<T: DependencyPagedRowV1 + Clone>(
    rows: &BTreeMap<RowKey, T>,
    request: &DependencyPageRequestV1,
) -> Result<DependencyPageV1<T>, StoreError> {
    let through = request.scope().through_tick().unwrap_or(u64::MAX);
    let after = request.after().cloned();
    let start = after.map_or(Bound::Unbounded, Bound::Excluded);
    let limit = request.limit().saturating_add(1);
    let later = rows.range((start, Bound::Unbounded));
    let within = later.take_while(|(cursor, _)| cursor.tick() <= through);
    let window: Vec<T> = within.take(limit).map(|(_, row)| row.clone()).collect();
    DependencyPageV1::from_ordered(request, &window)
        .map_err(StoreError::from)
        .and_then(|page| revalidated(request, &page))
}

/// Re-validate a page of stored rows; a failure is corrupt state, not a
/// caller fault.
fn revalidated<T: DependencyPagedRowV1 + Clone>(
    request: &DependencyPageRequestV1,
    page: &DependencyPageV1<T>,
) -> Result<DependencyPageV1<T>, StoreError> {
    // Copying the page is bounded by the page cap, so it stays cheap.
    let items = page.items().to_vec();
    DependencyPageV1::try_new(request, items, page.next().cloned())
        .or(Err(CounterfactualDependencyErrorV1::READ_BACK_FAULT))
}

impl MemoryStore {
    /// Check the first record of an invalidation against its command, once the
    /// Fork resolves.
    fn admit_first_record(
        &self,
        command: &CounterfactualInvalidationCommandV1,
        record: &TickDependencyRecordV1,
    ) -> Result<(), StoreError> {
        let state = self.counterfactual_fork(command.fork());
        state.and_then(|_| admit_first(command.first_tick(), record))
    }

    /// Check a later record against the Fork's stored set, once the Fork
    /// resolves.
    fn admit_later_record(
        &self,
        fork: TimelineId,
        record: &TickDependencyRecordV1,
    ) -> Result<(), StoreError> {
        let state = self.counterfactual_fork(fork);
        state.and_then(|persisted| persisted.admit_dependencies(record))
    }

    /// Add a record to the Fork's current generation. Infallible.
    fn install_dependencies(&mut self, fork: TimelineId, record: &TickDependencyRecordV1) {
        let install = |state: &mut CounterfactualForkStateV1| state.record_dependencies(record);
        let forks = &mut self.counterfactual_forks;
        // Infallible by design: the checks before the commit proved the Fork
        // exists, so a missing Fork is deliberately ignored, not an error.
        forks.get_mut(&fork).into_iter().for_each(install);
    }

    /// Admit the first record, commit the invalidation, and record the rows
    /// under the new generation only if it committed.
    fn commit_recorded(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
        record: &TickDependencyRecordV1,
    ) -> Result<CounterfactualInvalidationOutcomeV1, StoreError> {
        let admitted = self.admit_first_record(command, record);
        let committed = admitted.and_then(|()| self.commit_visible_counterfactual(command));
        if let Ok(CounterfactualInvalidationOutcomeV1::Committed(_)) = &committed {
            self.install_dependencies(command.fork(), record);
        }
        committed
    }

    /// Recheck the basis, admit the record, append the Tick, and record the
    /// rows only after it installed.
    fn append_recorded(
        &mut self,
        fork: TimelineId,
        expected: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
        record: &TickDependencyRecordV1,
    ) -> Result<CounterfactualTickOutcomeV1, StoreError> {
        let basis = self.persisted_counterfactual_basis(fork);
        basis.and_then(|persisted| {
            let found = expected.first_conflict(&persisted);
            found.map_or_else(
                || self.admit_and_append(fork, expected, drafts, record),
                |conflict| Ok(CounterfactualTickOutcomeV1::Stale(conflict)),
            )
        })
    }

    /// Admit the record, append the Tick, and record the rows only after it
    /// installed. The caller just rechecked the basis, so `Stale` is
    /// unreachable here and any `Ok` append is the committed Tick.
    fn admit_and_append(
        &mut self,
        fork: TimelineId,
        expected: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
        record: &TickDependencyRecordV1,
    ) -> Result<CounterfactualTickOutcomeV1, StoreError> {
        let admitted = self.admit_later_record(fork, record);
        admitted.and_then(|()| {
            let appended = self.append_visible_counterfactual_tick(fork, expected, drafts);
            appended.inspect(|_| self.install_dependencies(fork, record))
        })
    }

    /// The stored committed prefix rows of a parent Timeline, if any.
    fn prefix_rows(&self, parent: TimelineId) -> &DependencyRowsV1 {
        self.dependency_prefixes.get(&parent).unwrap_or(&NO_ROWS)
    }

    /// One page of a parent Timeline's committed prefix rows.
    fn prefix_page<T: DependencyPagedRowV1 + Clone>(
        &self,
        parent: TimelineId,
        request: &DependencyPageRequestV1,
        select: Select<T>,
    ) -> Result<DependencyPageV1<T>, StoreError> {
        page_after(select(self.prefix_rows(parent)), request)
    }

    /// One page of a Fork generation's rows, once the Fork resolves.
    fn fork_page<T: DependencyPagedRowV1 + Clone>(
        &self,
        at: ForkGenerationV1,
        request: &DependencyPageRequestV1,
        select: Select<T>,
    ) -> Result<DependencyPageV1<T>, StoreError> {
        let state = self.counterfactual_fork(at.fork);
        state.and_then(|persisted| persisted.page_of_current(request, select))
    }

    fn read_prefix_page<T: DependencyPagedRowV1 + Clone>(
        &self,
        parent: TimelineId,
        request: &DependencyPageRequestV1,
        select: Select<T>,
    ) -> Result<DependencyPageV1<T>, StoreError> {
        let read = self.with_erasure_read_fence(parent, READ, |store| {
            store
                .ensure_generic_timeline_visibility(parent)
                .and_then(|()| store.authorize_inherited_scopes(parent, READ))
                .map(|()| store.prefix_page(parent, request, select))
        });
        fenced_result(read)
    }

    fn read_fork_page<T: DependencyPagedRowV1 + Clone>(
        &self,
        at: ForkGenerationV1,
        request: &DependencyPageRequestV1,
        select: Select<T>,
    ) -> Result<DependencyPageV1<T>, StoreError> {
        let read = self.with_erasure_read_fence(at.fork, READ, |store| {
            Ok(store.fork_page(at, request, select))
        });
        fenced_result(read)
    }

    fn read_dependency_page<T: DependencyPagedRowV1 + Clone>(
        &self,
        request: &DependencyPageRequestV1,
        select: Select<T>,
    ) -> Result<DependencyPageV1<T>, StoreError> {
        match request.scope() {
            DependencyReadScopeV1::ParentPrefix { timeline, .. } => {
                self.read_prefix_page(timeline, request, select)
            }
            DependencyReadScopeV1::ForkGeneration(at) => self.read_fork_page(at, request, select),
        }
    }
}

impl CounterfactualDependencyRecordingPortV1 for MemoryStore {
    fn commit_counterfactual_invalidation_with_dependencies(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
        record: &TickDependencyRecordV1,
    ) -> Result<CounterfactualInvalidationOutcomeV1, CounterfactualStoreErrorV1> {
        let fork = command.fork();
        let write = self.with_erasure_fence(fork, APPEND, |store| {
            store
                .ensure_generic_fork_append_is_rejected(fork)
                .map(|()| store.commit_recorded(command, record))
        });
        fenced_result(write)
    }

    fn append_counterfactual_tick_with_dependencies(
        &mut self,
        fork: TimelineId,
        expected: &CounterfactualBasisV1,
        drafts: &PipelineDraftBatchV1,
        record: &TickDependencyRecordV1,
    ) -> Result<CounterfactualTickOutcomeV1, CounterfactualStoreErrorV1> {
        let write = self.with_erasure_fence(fork, APPEND, |store| {
            store
                .ensure_generic_fork_append_is_rejected(fork)
                .map(|()| store.append_recorded(fork, expected, drafts, record))
        });
        fenced_result(write)
    }
}

impl CounterfactualDependencyReadPortV1 for MemoryStore {
    fn read_dependency_nodes(
        &self,
        request: &DependencyPageRequestV1,
    ) -> Result<DependencyPageV1<DependencyNodeRecordV1>, CounterfactualStoreErrorV1> {
        self.read_dependency_page(request, |rows| &rows.nodes)
    }

    fn read_dependency_edges(
        &self,
        request: &DependencyPageRequestV1,
    ) -> Result<DependencyPageV1<DependencyEdgeRecordV1>, CounterfactualStoreErrorV1> {
        self.read_dependency_page(request, |rows| &rows.edges)
    }
}

#[cfg(test)]
mod tests {
    use pos_core::counterfactual_store::test_fixtures::{hash_field, text_field, uint};
    use pos_core::{
        CounterfactualStorePortV1, DependencyNodeCoordinateV1, EventStore,
        ForkAdmissionRecordInputV1, ForkAdmissionRecordV1, ForkAttributionOriginV1, OwnerIdV1,
        RecordedDependencyClassV1, RecordedNodeOriginV1, Seq, MAX_RECORDED_DEPENDENCY_EDGES_V1,
        MAX_RECORDED_DEPENDENCY_NODES_V1,
    };

    use super::super::tests::{command, draft, facts, inject, ok, published_store, snapshot};
    use super::super::InjectedFaultV1;
    use super::*;

    type NodeRow = DependencyNodeRecordV1;
    type EdgeRow = DependencyEdgeRecordV1;
    type Coordinate = DependencyNodeCoordinateV1;
    type Scope = DependencyReadScopeV1;
    /// One capacity case: stored counts and a record that crosses one bound.
    type CapacityCase = (RecordedSetCountsV1, fn(u64) -> TickDependencyRecordV1);

    const ENDOGENOUS: RecordedDependencyClassV1 = RecordedDependencyClassV1::EndogenousRecomputed;
    const PROVISIONAL: RecordedNodeOriginV1 = RecordedNodeOriginV1::Provisional;
    const COMMITTED: RecordedNodeOriginV1 = RecordedNodeOriginV1::Committed;

    // These builders mirror those of the public test and the `SQLite` adapter's
    // tests; consolidating them is a follow-up: Redmine #559.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn coordinate(tick: u64, owner: &str, digest: u8) -> Coordinate {
        let digest = Hash::from_bytes([digest; 32]);
        ok(Coordinate::try_new(tick, 0, owner.to_owned(), 0, 7, digest))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn node(
        coordinate: &Coordinate,
        origin: RecordedNodeOriginV1,
        inputs: Vec<Hash>,
    ) -> DependencyNodeRecordV1 {
        let provenance = Hash::from_bytes([99; 32]);
        ok(DependencyNodeRecordV1::try_new(
            coordinate.clone(),
            ENDOGENOUS,
            origin,
            inputs,
            provenance,
        ))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn node_bytes(node: &Coordinate) -> Vec<u8> {
        [
            vec![0x86],
            uint(node.tick()),
            uint(u64::from(node.scheduler_position())),
            text_field(node.owner_id()),
            uint(u64::from(node.output_ordinal())),
            uint(u64::from(node.schema_id())),
            hash_field(node.artifact_digest()),
        ]
        .concat()
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn edge(consumer: &Coordinate, source: &Coordinate) -> DependencyEdgeRecordV1 {
        let tail = [
            uint(2),
            vec![0x82],
            uint(3),
            uint(5),
            hash_field(Hash::from_bytes([0x33; 32])),
            vec![0x82],
            text_field("adr064.classification"),
            uint(1),
            hash_field(Hash::from_bytes([0x44; 32])),
        ]
        .concat();
        let head = vec![0x89, 0x64, b'I', b'D', b'P', b'1', 0x01];
        let bytes = [head, node_bytes(consumer), node_bytes(source), tail].concat();
        ok(DependencyEdgeRecordV1::try_from_canonical(
            bytes,
            consumer.clone(),
            source.artifact_digest(),
        ))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn record_of(
        tick: u64,
        nodes: Vec<DependencyNodeRecordV1>,
        edges: Vec<DependencyEdgeRecordV1>,
    ) -> TickDependencyRecordV1 {
        ok(TickDependencyRecordV1::try_new(
            tick,
            PROVISIONAL,
            nodes,
            edges,
        ))
    }

    /// A record of one provisional node `n` at `tick`, digest `tick`.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn lone_node(tick: u64) -> TickDependencyRecordV1 {
        let digest = u8::try_from(tick).unwrap_or(u8::MAX);
        let row = node(&coordinate(tick, "n", digest), PROVISIONAL, Vec::new());
        record_of(tick, vec![row], Vec::new())
    }

    /// A record of one node declaring one input, with no edge.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn input_node(tick: u64) -> TickDependencyRecordV1 {
        let digest = u8::try_from(tick).unwrap_or(u8::MAX);
        let inputs = vec![Hash::from_bytes([200; 32])];
        let row = node(&coordinate(tick, "n", digest), PROVISIONAL, inputs);
        record_of(tick, vec![row], Vec::new())
    }

    /// A record of one node declaring one input, with its edge.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn edge_node(tick: u64) -> TickDependencyRecordV1 {
        let digest = u8::try_from(tick).unwrap_or(u8::MAX);
        let consumer = coordinate(tick, "n", digest);
        let inputs = vec![Hash::from_bytes([200; 32])];
        let edges = vec![edge(&consumer, &coordinate(0, "w", 200))];
        record_of(tick, vec![node(&consumer, PROVISIONAL, inputs)], edges)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    const fn fork_scope(fork: TimelineId, generation: u64) -> Scope {
        Scope::ForkGeneration(ForkGenerationV1 { fork, generation })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    const fn prefix_through(timeline: TimelineId, through_tick: u64) -> Scope {
        Scope::ParentPrefix {
            timeline,
            through_tick,
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_nodes(
        store: &MemoryStore,
        scope: Scope,
        limit: usize,
    ) -> Result<DependencyPageV1<NodeRow>, StoreError> {
        let request = ok(DependencyPageRequestV1::try_new(scope, None, limit));
        store.read_dependency_nodes(&request)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn read_edges(
        store: &MemoryStore,
        scope: Scope,
        limit: usize,
    ) -> Result<DependencyPageV1<EdgeRow>, StoreError> {
        let request = ok(DependencyPageRequestV1::try_new(scope, None, limit));
        store.read_dependency_edges(&request)
    }

    /// The Fork's current-generation rows, which are generation 1 here.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_nodes(store: &MemoryStore, fork: TimelineId) -> Vec<NodeRow> {
        ok(read_nodes(store, fork_scope(fork, 1), 100))
            .items()
            .to_vec()
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn parent_of(store: &MemoryStore, fork: TimelineId) -> TimelineId {
        let point = store.state(fork).timeline.meta.fork_point;
        ok(point.ok_or("not a Fork")).0
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seed_prefix(
        store: &mut MemoryStore,
        parent: TimelineId,
        nodes: &[NodeRow],
        edges: &[EdgeRow],
    ) {
        let rows = store.dependency_prefixes.entry(parent).or_default();
        rows.nodes.extend(keyed(nodes));
        rows.edges.extend(keyed(edges));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn dependency_set(store: &mut MemoryStore, fork: TimelineId) -> &mut ForkDependencySetV1 {
        let state = ok(store.counterfactual_forks.get_mut(&fork).ok_or("no state"));
        let held = state.dependencies.as_mut().map(|(_, set)| set);
        ok(held.ok_or("no set"))
    }

    /// A store whose Fork committed generation 1 with the tick 1 record `a`.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn recorded_store() -> (MemoryStore, TimelineId) {
        let (mut store, fork) = published_store();
        let first = lone_node(1);
        let invalidation = command(fork);
        let outcome =
            store.commit_counterfactual_invalidation_with_dependencies(&invalidation, &first);
        assert!(outcome.is_ok());
        (store, fork)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_record(
        store: &mut MemoryStore,
        fork: TimelineId,
        record: &TickDependencyRecordV1,
    ) -> Result<CounterfactualTickOutcomeV1, StoreError> {
        let expected = ok(store.current_counterfactual_basis(fork));
        let drafts = ok(PipelineDraftBatchV1::try_new(vec![draft(2)]));
        store.append_counterfactual_tick_with_dependencies(fork, &expected, &drafts, record)
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn c2_injected_failures_record_nothing() {
        let (mut store, fork) = published_store();
        let first = lone_node(1);
        let invalidation = command(fork);
        let before = snapshot(&store, fork);

        inject(InjectedFaultV1::Storage);
        let failed =
            store.commit_counterfactual_invalidation_with_dependencies(&invalidation, &first);
        inject(InjectedFaultV1::StalledHead);
        let stalled =
            store.commit_counterfactual_invalidation_with_dependencies(&invalidation, &first);

        assert_eq!(failed, Err(StoreError::StorageFailure));
        assert_eq!(stalled, Err(StoreError::CorruptState));
        assert_eq!(snapshot(&store, fork), before);
        let committed =
            store.commit_counterfactual_invalidation_with_dependencies(&invalidation, &first);
        assert!(committed.is_ok());
        assert_eq!(fork_nodes(&store, fork), first.nodes().to_vec());

        let second = lone_node(2);
        let after = snapshot(&store, fork);
        inject(InjectedFaultV1::Storage);
        let failed = append_record(&mut store, fork, &second);
        inject(InjectedFaultV1::StalledHead);
        let stalled = append_record(&mut store, fork, &second);

        assert_eq!(failed, Err(StoreError::StorageFailure));
        assert_eq!(stalled, Err(StoreError::CorruptState));
        assert_eq!(snapshot(&store, fork), after);
        assert!(append_record(&mut store, fork, &second).is_ok());
        assert_eq!(fork_nodes(&store, fork).len(), 2);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn c3_set_capacity_is_checked_against_the_stored_counts() {
        let limit_nodes = MAX_RECORDED_DEPENDENCY_NODES_V1;
        let limit_edges = MAX_RECORDED_DEPENDENCY_EDGES_V1;
        let cases: [CapacityCase; 3] = [
            (
                RecordedSetCountsV1 {
                    nodes: limit_nodes - 1,
                    ..RecordedSetCountsV1::default()
                },
                lone_node,
            ),
            (
                RecordedSetCountsV1 {
                    edges: limit_edges - 1,
                    ..RecordedSetCountsV1::default()
                },
                edge_node,
            ),
            (
                RecordedSetCountsV1 {
                    inputs: limit_edges - 1,
                    ..RecordedSetCountsV1::default()
                },
                input_node,
            ),
        ];
        for (counts, make) in cases {
            let (mut store, fork) = recorded_store();
            dependency_set(&mut store, fork).counts = counts;

            // The record that reaches the bound exactly is accepted.
            assert!(append_record(&mut store, fork, &make(2)).is_ok());
            let full = snapshot(&store, fork);
            // One more row of the same kind is over the bound.
            let over = append_record(&mut store, fork, &make(3));

            assert_eq!(over, Err(StoreError::FieldOutOfBounds));
            assert_eq!(snapshot(&store, fork), full);
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn c5_no_record_tick_follows_the_largest_tick() {
        let (mut store, fork) = recorded_store();
        dependency_set(&mut store, fork).last_record_tick = Some(u64::MAX);
        let before = snapshot(&store, fork);

        let outcome = append_record(&mut store, fork, &lone_node(u64::MAX));

        assert_eq!(outcome, Err(StoreError::BindingMismatch));
        assert_eq!(snapshot(&store, fork), before);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn c7_a_write_keeps_only_the_current_generations_set() {
        let (mut store, fork) = recorded_store();
        let state = ok(store.counterfactual_forks.get_mut(&fork).ok_or("no state"));
        let first = state.dependencies.as_ref().map(|(held, _)| *held);
        assert_eq!(first, Some(1));
        state.generation = 2;
        let second = lone_node(5);

        state.record_dependencies(&second);

        let (generation, set) = ok(state.dependencies.as_ref().ok_or("no set"));
        assert_eq!(*generation, 2);
        let nodes: Vec<NodeRow> = set.rows.nodes.values().cloned().collect();
        assert_eq!(nodes, second.nodes().to_vec());
        assert_eq!(set.counts.nodes, 1);
        assert_eq!(set.last_record_tick, Some(5));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn c8_sibling_forks_share_one_prefix_and_stitch_by_concatenation() {
        let (mut store, fork) = recorded_store();
        let root = parent_of(&store, fork);
        let sibling = ok(store.fork(root, Seq::from_u64(1), "sibling")).id();
        ok(store.publish_counterfactual_facts(sibling, facts()));
        let first = lone_node(1);
        let invalidation = command(sibling);
        let outcome =
            store.commit_counterfactual_invalidation_with_dependencies(&invalidation, &first);
        assert!(outcome.is_ok());
        assert!(append_record(&mut store, fork, &lone_node(2)).is_ok());
        let cut = 0;
        let committed_rows = [
            node(&coordinate(cut, "p", 61), COMMITTED, Vec::new()),
            node(&coordinate(cut, "q", 62), COMMITTED, Vec::new()),
        ];
        seed_prefix(&mut store, root, &committed_rows, &[]);
        let prefix_of = |at| {
            let scope = prefix_through(parent_of(&store, at), cut);
            ok(read_nodes(&store, scope, 10))
        };
        let ticks_of = |rows: &[NodeRow]| -> Vec<u64> {
            rows.iter().map(|row| row.coordinate().tick()).collect()
        };

        let shared = prefix_of(fork);

        assert_eq!(prefix_of(sibling), shared);
        assert_eq!(shared.items(), committed_rows.as_slice());
        assert!(ticks_of(shared.items()).iter().all(|tick| *tick <= cut));
        for (own_fork, expected) in [(fork, vec![1, 2]), (sibling, vec![1])] {
            let own = ok(read_nodes(&store, fork_scope(own_fork, 1), 10));
            let read_ticks = ticks_of(own.items());
            assert_eq!(read_ticks, expected);
            assert!(read_ticks.iter().all(|tick| *tick > cut));
            let stitched = [shared.items(), own.items()].concat();
            assert_eq!(ticks_of(&stitched), [vec![cut, cut], expected].concat());
            let cursors: Vec<RowKey> = stitched.iter().map(DependencyPagedRowV1::cursor).collect();
            assert!(cursors.windows(2).all(|pair| pair[0] < pair[1]));
        }
    }

    /// The committed node `p<tick>` at `tick`, digest `tick`.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn prefix_coordinate(tick: u64) -> Coordinate {
        coordinate(tick, &format!("p{tick}"), u8::try_from(tick).unwrap_or(0))
    }

    /// Committed prefix: nodes `p1`..`p4` at ticks 1 to 4, edges consumed by
    /// `p2` and `p4`.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn seeded_prefix() -> (MemoryStore, TimelineId, TimelineId) {
        let (mut store, fork) = published_store();
        let root = parent_of(&store, fork);
        let source = coordinate(0, "w", 200);
        let inputs = vec![Hash::from_bytes([200; 32])];
        let coordinates: Vec<Coordinate> = (1..=4).map(prefix_coordinate).collect();
        let nodes: Vec<NodeRow> = coordinates
            .iter()
            .map(|at| node(at, COMMITTED, inputs.clone()))
            .collect();
        let edges = [&coordinates[1], &coordinates[3]].map(|at| edge(at, &source));
        seed_prefix(&mut store, root, &nodes, &edges);
        (store, root, fork)
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn c8_parent_prefix_serves_committed_rows_through_the_tick() {
        let (store, root, fork) = seeded_prefix();
        let ticks = |scope, limit| -> Vec<u64> {
            let page = ok(read_nodes(&store, scope, limit));
            let rows = page.items().iter();
            rows.map(|row| row.coordinate().tick()).collect()
        };
        let edge_ticks = |scope| -> Vec<u64> {
            let page = ok(read_edges(&store, scope, 10));
            let rows = page.items().iter();
            rows.map(|row| row.consumer().tick()).collect()
        };

        assert_eq!(ticks(prefix_through(root, 4), 10), vec![1, 2, 3, 4]);
        assert_eq!(ticks(prefix_through(root, 3), 10), vec![1, 2, 3]);
        assert_eq!(ticks(prefix_through(root, 2), 10), vec![1, 2]);
        assert_eq!(ticks(prefix_through(root, 0), 10), Vec::<u64>::new());
        assert_eq!(edge_ticks(prefix_through(root, 4)), vec![2, 4]);
        assert_eq!(edge_ticks(prefix_through(root, 3)), vec![2]);
        assert_eq!(edge_ticks(prefix_through(root, 1)), Vec::<u64>::new());
        // Another Timeline's prefix and the Fork's own rows are not served.
        assert_eq!(ticks(prefix_through(fork, 4), 10), Vec::<u64>::new());
        let unrecorded = ok(read_nodes(&store, fork_scope(fork, 0), 10));
        assert!(unrecorded.items().is_empty());
        // Paging resumes after the page's last row and stops at the bound.
        let first = ok(read_nodes(&store, prefix_through(root, 3), 2));
        let after = first.next().cloned();
        let request = ok(DependencyPageRequestV1::try_new(
            prefix_through(root, 3),
            after,
            2,
        ));
        let second = ok(store.read_dependency_nodes(&request));
        assert_eq!(first.items().len(), 2);
        assert_eq!(second.items().len(), 1);
        assert!(second.next().is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn c8_corrupt_stored_rows_read_back_as_corrupt_state() {
        let (mut store, fork) = recorded_store();
        let root = parent_of(&store, fork);
        let committed = node(&coordinate(30, "q", 31), COMMITTED, Vec::new());
        dependency_set(&mut store, fork)
            .rows
            .nodes
            .insert(committed.cursor(), committed);
        let provisional = node(&coordinate(8, "w", 32), PROVISIONAL, Vec::new());
        seed_prefix(&mut store, root, &[provisional], &[]);

        assert_eq!(
            read_nodes(&store, fork_scope(fork, 1), 5).map(drop),
            Err(StoreError::CorruptState)
        );
        assert_eq!(
            read_nodes(&store, prefix_through(root, 9), 5).map(drop),
            Err(StoreError::CorruptState)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn c9_concealed_geographic_timelines_are_not_found() {
        let (mut store, fork) = recorded_store();
        let root = parent_of(&store, fork);
        let expected = ok(store.current_counterfactual_basis(fork));
        let drafts = ok(PipelineDraftBatchV1::try_new(vec![draft(2)]));
        let second = lone_node(2);
        store.geographic_timelines.insert(root);
        store.geographic_timelines.insert(fork);

        for scope in [prefix_through(root, 5), fork_scope(fork, 1)] {
            assert_eq!(
                read_nodes(&store, scope, 5).map(drop),
                Err(StoreError::ForkNotFound)
            );
        }
        let before = snapshot(&store, fork);
        let appended =
            store.append_counterfactual_tick_with_dependencies(fork, &expected, &drafts, &second);
        assert_eq!(appended, Err(StoreError::ForkNotFound));
        assert_eq!(snapshot(&store, fork), before);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn c9_admitted_fork_writes_fail_closed_without_recording() {
        let (mut store, fork) = recorded_store();
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
        let before = snapshot(&store, fork);
        let first = lone_node(1);
        let invalidation = command(fork);

        let commit =
            store.commit_counterfactual_invalidation_with_dependencies(&invalidation, &first);

        assert_eq!(commit, Err(StoreError::StorageFailure));
        assert_eq!(
            append_record(&mut store, fork, &lone_node(2)).map(drop),
            Err(StoreError::StorageFailure)
        );
        assert_eq!(snapshot(&store, fork), before);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn c12_deleting_timelines_purges_their_dependency_rows() {
        let (mut store, fork) = recorded_store();
        let root = parent_of(&store, fork);
        let root_row = node(&coordinate(1, "p", 40), COMMITTED, Vec::new());
        let fork_row = node(&coordinate(1, "p", 41), COMMITTED, Vec::new());
        seed_prefix(&mut store, root, &[root_row], &[]);
        seed_prefix(&mut store, fork, &[fork_row], &[]);

        // A refused delete (the root still has a Fork) keeps every row.
        assert!(store.delete_timeline(root).is_err());
        assert!(store.dependency_prefixes.contains_key(&root));
        assert!(!dependency_set(&mut store, fork).rows.nodes.is_empty());

        ok(store.delete_timeline(fork));
        assert!(!store.counterfactual_forks.contains_key(&fork));
        assert!(!store.dependency_prefixes.contains_key(&fork));
        assert!(store.dependency_prefixes.contains_key(&root));
        ok(store.delete_timeline(root));
        assert!(store.dependency_prefixes.is_empty());
    }
}
