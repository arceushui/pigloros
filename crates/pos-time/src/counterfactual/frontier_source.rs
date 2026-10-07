//! The production ADR-064 frontier source over the recorded dependency graph.
//!
//! [`RecordedFrontierSourceV1`] is the host-side
//! [`CounterfactualFrontierSourceV1`] of the counterfactual coordinator. ADR-064
//! derives the frontier from "the closed dependency graph from committed
//! dependency edges for the parent prefix and every provisional Fork
//! generation through the requested horizon"; this source builds that graph
//! from the rows the store recorded under the `pos-core` dependency record
//! contract (`pos_core::counterfactual_dependency`). For one CFP1
//! [`CounterfactualPlanV1`] it:
//!
//! 1. pages the recorded nodes and edges of the parent Timeline's committed
//!    prefix through the plan's parent-cut Tick
//!    ([`DependencyReadScopeV1::ParentPrefix`]) and of the Fork generation it
//!    was built for ([`DependencyReadScopeV1::ForkGeneration`]) through the
//!    plan's horizon, through a [`CounterfactualDependencyReadPortV1`];
//! 2. converts every node row to a [`DependencyGraphNodeV1`] and decodes
//!    every edge row's exact `IDP1` bytes into an [`InputDependencyV1`];
//! 3. validates the stitched graph with [`validate_dependency_graph_v1`]
//!    under the plan's unknown-edge policy;
//! 4. derives the sealed `RCF1` frontier with
//!    [`derive_recomputation_frontier_v1`] and reports every `Provisional`
//!    node as a provisional output of the generation.
//!
//! The coordinator never trusts the result: it re-validates the frontier,
//! binds it to the plan, and compares the frontier's dependency-graph digest
//! with the digest the host published
//! (`CounterfactualStorePortV1::publish_counterfactual_facts`). The host
//! derives that digest from the same recorded graph with
//! [`RecordedFrontierSourceV1::recorded_graph_digest`].
//!
//! # Contract decisions
//!
//! - **Scopes.** The parent prefix is addressed by the plan: its
//!   `parent_timeline_id` and `parent_cut_tick`, which the coordinator has
//!   already proven to be the Fork's recorded parent cut. The Fork generation
//!   is the [`ForkGenerationV1`] the source was built for, the committed
//!   generation the host read before the admission. The read port serves only
//!   the committed generation, so a quarantined earlier generation never
//!   contributes, and a source built for a generation the Fork has moved past
//!   fails closed with `Store(MixedForkGeneration)`.
//! - **Stitching.** The contract keeps the two scopes' Tick windows disjoint
//!   and each scope canonically ordered, so the graph is the prefix rows
//!   followed by the Fork rows; the validator re-checks the order and the
//!   digest uniqueness of the stitched list.
//! - **Horizon.** A parent-prefix read is bounded by the adapter at the cut.
//!   A Fork read has no Tick bound, so the source stops paging the Fork scope
//!   at the first row whose Tick, a node's own or an edge consumer's, passes
//!   the horizon, and drops that row and the rest of its page: the graph is
//!   the recorded generation through the requested horizon.
//! - **Bounds.** Pages are converted as they arrive and never held whole. At
//!   most [`DependencyGraphBoundsV1::max_nodes`] nodes and
//!   [`DependencyGraphBoundsV1::max_edges`] edges, each clamped to the hard
//!   maximum, are ever held; one row more stops reading with
//!   [`CounterfactualAdmissionErrorV1::DependencyGraphInvalid`], the error
//!   the validator's `ResourceLimitExceeded` maps to. Pages hold at most
//!   [`MAX_DEPENDENCY_PAGE_ROWS_V1`] rows; a smaller page is a host choice
//!   ([`RecordedFrontierSourceV1::with_page_limit`]) and never changes the
//!   result.
//! - **Errors.** A missing required edge under `Reject` is
//!   [`CounterfactualAdmissionErrorV1::DependencyGraphIncomplete`] and an
//!   undeclared edge or endpoint
//!   [`CounterfactualAdmissionErrorV1::UnknownDependencyEdge`], both with the
//!   validator's canonical coordinate; every other validation or derivation
//!   failure is [`CounterfactualAdmissionErrorV1::DependencyGraphInvalid`].
//!   A port failure is [`CounterfactualAdmissionErrorV1::Store`] with the
//!   port's error: `ForkNotFound` for an unknown or erased parent Timeline or
//!   Fork (never an empty graph), `MixedForkGeneration` for a generation
//!   that is not the committed one, `StorageFailure` for a failed read. A
//!   recorded edge the conformance `IDP1` codec rejects, or a page
//!   continuation outside its own scope, is corrupt stored state:
//!   `Store(CorruptState)`.
//! - **Reader obligation.** The record contract requires a generation to be
//!   read only after its final Tick record is committed, because a root node
//!   may ride a later record. The source cannot tell and reads the committed
//!   state as it stands: a generation still being written validates as what
//!   is recorded so far, usually `DependencyGraphInvalid` for a missing
//!   Intervention node, and a digest derived from it must not be published.
//! - **Empty graph.** The committed prefix has no write path yet (#554), so
//!   a parent Timeline's prefix is empty in production, and a Fork whose
//!   generation has no records has an empty graph, which the validator
//!   rejects as `DependencyGraphInvalid` (`InterventionNodeMissing`). The
//!   first generation of a Fork is therefore admitted from a host-built
//!   graph; once its suffix is recorded, this source serves every later
//!   admission of the Fork from the recorded generation.
//! - **Determinism.** The output is a pure function of the committed rows,
//!   the plan, and the bounds; the page limit never changes it.

use pos_conformance::counterfactual::dependency::InputDependencyV1;
use pos_conformance::counterfactual::plan::CounterfactualPlanV1;
use pos_conformance::{DependencyClassV1, DependencyNodeV1};
use pos_core::{
    CounterfactualDependencyErrorV1, CounterfactualDependencyReadPortV1,
    CounterfactualStoreErrorV1, DependencyEdgeRecordV1, DependencyNodeRecordV1,
    DependencyPageCursorV1, DependencyPageRequestV1, DependencyPageV1, DependencyPagedRowV1,
    DependencyReadScopeV1, ForkGenerationV1, RecordedDependencyClassV1, RecordedNodeOriginV1,
    TimelineId, MAX_DEPENDENCY_PAGE_ROWS_V1,
};
use pos_runtime::counterfactual::coordinator::{
    CounterfactualAdmissionErrorV1, CounterfactualFrontierDerivationV1,
    CounterfactualFrontierSourceV1, CounterfactualProvisionalOutputV1,
};
use ulid::Ulid;

use super::dependency_graph::{
    validate_dependency_graph_v1, DependencyGraphBoundsV1, DependencyGraphErrorV1,
    DependencyGraphNodeOriginV1, DependencyGraphNodeV1, ValidatedDependencyGraphV1,
    MAX_DEPENDENCY_GRAPH_EDGES_V1, MAX_DEPENDENCY_GRAPH_NODES_V1,
};
use super::frontier::{dependency_graph_digest_v1, derive_recomputation_frontier_v1};

/// The production frontier source over the recorded dependency graph.
///
/// It owns the read port `P` (a store, or a host wrapper around one) and is
/// built for one Fork generation; see the module documentation.
#[derive(Clone, Debug)]
pub struct RecordedFrontierSourceV1<P> {
    port: P,
    generation: ForkGenerationV1,
    bounds: DependencyGraphBoundsV1,
    page_limit: usize,
}

/// Why the recorded graph could not be read: a port fault or a graph the
/// validator rejects. Kept small so that every helper can return it.
enum RecordedGraphFaultV1 {
    Store(CounterfactualStoreErrorV1),
    Graph(DependencyGraphErrorV1),
}

impl From<CounterfactualStoreErrorV1> for RecordedGraphFaultV1 {
    fn from(error: CounterfactualStoreErrorV1) -> Self {
        Self::Store(error)
    }
}

impl From<DependencyGraphErrorV1> for RecordedGraphFaultV1 {
    fn from(error: DependencyGraphErrorV1) -> Self {
        Self::Graph(error)
    }
}

/// One scope to page, with the Tick after which the source stops reading it.
#[derive(Clone, Copy)]
struct ScopeReadV1 {
    scope: DependencyReadScopeV1,
    through_tick: u64,
}

/// One recorded row kind the source pages, with its graph counterpart.
trait RecordedRowV1: DependencyPagedRowV1 + Sized {
    /// The graph element one row converts to.
    type Graph;

    /// Read one page of this row kind.
    fn read<P: CounterfactualDependencyReadPortV1>(
        port: &P,
        request: &DependencyPageRequestV1,
    ) -> Result<DependencyPageV1<Self>, CounterfactualStoreErrorV1>;

    /// The Tick the row is ordered and horizon-bounded by.
    fn tick(&self) -> u64;

    /// Convert the row; a stored row the codec rejects is `CorruptState`.
    fn convert(&self) -> Result<Self::Graph, CounterfactualStoreErrorV1>;
}

impl RecordedRowV1 for DependencyNodeRecordV1 {
    type Graph = DependencyGraphNodeV1;

    fn read<P: CounterfactualDependencyReadPortV1>(
        port: &P,
        request: &DependencyPageRequestV1,
    ) -> Result<DependencyPageV1<Self>, CounterfactualStoreErrorV1> {
        port.read_dependency_nodes(request)
    }

    fn tick(&self) -> u64 {
        self.coordinate().tick()
    }

    fn convert(&self) -> Result<DependencyGraphNodeV1, CounterfactualStoreErrorV1> {
        Ok(graph_node(self))
    }
}

impl RecordedRowV1 for DependencyEdgeRecordV1 {
    type Graph = InputDependencyV1;

    fn read<P: CounterfactualDependencyReadPortV1>(
        port: &P,
        request: &DependencyPageRequestV1,
    ) -> Result<DependencyPageV1<Self>, CounterfactualStoreErrorV1> {
        port.read_dependency_edges(request)
    }

    fn tick(&self) -> u64 {
        self.consumer().tick()
    }

    fn convert(&self) -> Result<InputDependencyV1, CounterfactualStoreErrorV1> {
        InputDependencyV1::from_canonical_cbor(self.as_bytes())
            .or(Err(CounterfactualDependencyErrorV1::READ_BACK_FAULT))
    }
}

impl<P> RecordedFrontierSourceV1<P> {
    /// Build a source over `port` for the Fork generation `generation`,
    /// validating under `bounds` and reading full pages.
    #[must_use]
    pub const fn new(
        port: P,
        generation: ForkGenerationV1,
        bounds: DependencyGraphBoundsV1,
    ) -> Self {
        Self {
            port,
            generation,
            bounds,
            page_limit: MAX_DEPENDENCY_PAGE_ROWS_V1,
        }
    }

    /// Read at most `page_limit` rows per page, clamped to 1 through
    /// [`MAX_DEPENDENCY_PAGE_ROWS_V1`]; the result never depends on it.
    #[must_use]
    pub fn with_page_limit(self, page_limit: usize) -> Self {
        Self {
            page_limit: page_limit.clamp(1, MAX_DEPENDENCY_PAGE_ROWS_V1),
            ..self
        }
    }

    /// Borrow the read port.
    #[must_use]
    pub const fn port(&self) -> &P {
        &self.port
    }

    /// Return the Fork generation the source reads.
    #[must_use]
    pub const fn generation(&self) -> ForkGenerationV1 {
        self.generation
    }

    /// Return the validation bounds.
    #[must_use]
    pub const fn bounds(&self) -> DependencyGraphBoundsV1 {
        self.bounds
    }

    /// Return the rows read per page.
    #[must_use]
    pub const fn page_limit(&self) -> usize {
        self.page_limit
    }
}

impl<P: CounterfactualDependencyReadPortV1> RecordedFrontierSourceV1<P> {
    /// Page the recorded graph for `plan` and validate it.
    ///
    /// # Errors
    /// Returns the errors listed in the module documentation: the validator's
    /// `DependencyGraphIncomplete` and `UnknownDependencyEdge` with their
    /// coordinate, `DependencyGraphInvalid` for any other rejected graph, and
    /// `Store` for a port failure or corrupt stored rows.
    pub fn recorded_graph(
        &self,
        plan: &CounterfactualPlanV1,
    ) -> Result<ValidatedDependencyGraphV1, CounterfactualAdmissionErrorV1> {
        self.read_graph(plan).map_err(admission_error)
    }

    /// Page and validate the recorded graph for `plan` and return its
    /// dependency-graph digest, the value the host publishes with
    /// `publish_counterfactual_facts`.
    ///
    /// # Errors
    /// Exactly those of [`Self::recorded_graph`].
    pub fn recorded_graph_digest(
        &self,
        plan: &CounterfactualPlanV1,
    ) -> Result<[u8; 32], CounterfactualAdmissionErrorV1> {
        self.recorded_graph(plan)
            .map(|graph| dependency_graph_digest_v1(&graph))
    }

    /// Page both scopes, nodes then edges, and validate the stitched graph.
    fn read_graph(
        &self,
        plan: &CounterfactualPlanV1,
    ) -> Result<ValidatedDependencyGraphV1, RecordedGraphFaultV1> {
        let max_nodes = self.bounds.max_nodes.min(MAX_DEPENDENCY_GRAPH_NODES_V1);
        let max_edges = self.bounds.max_edges.min(MAX_DEPENDENCY_GRAPH_EDGES_V1);
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        for read in scope_reads(plan, self.generation) {
            self.collect::<DependencyNodeRecordV1>(read, max_nodes, &mut nodes)?;
            self.collect::<DependencyEdgeRecordV1>(read, max_edges, &mut edges)?;
        }
        validate_dependency_graph_v1(plan, self.bounds, nodes, edges)
            .map_err(RecordedGraphFaultV1::Graph)
    }

    /// Page one row kind of one scope into `out`, converting every row as its
    /// page arrives, until the last page, the first row past the scope's
    /// Tick bound, or one row more than `max_rows`.
    fn collect<R: RecordedRowV1>(
        &self,
        read: ScopeReadV1,
        max_rows: usize,
        out: &mut Vec<R::Graph>,
    ) -> Result<(), RecordedGraphFaultV1> {
        let mut after: Option<DependencyPageCursorV1> = None;
        loop {
            // The cursor came from the port, so one outside its own scope is
            // corrupt stored state, not a caller fault.
            let request =
                DependencyPageRequestV1::try_new(read.scope, after.take(), self.page_limit)
                    .or(Err(CounterfactualDependencyErrorV1::READ_BACK_FAULT))?;
            let page = R::read(&self.port, &request)?;
            let rows = page.items();
            let within = rows.partition_point(|row| row.tick() <= read.through_tick);
            if out.len().saturating_add(within) > max_rows {
                return Err(DependencyGraphErrorV1::ResourceLimitExceeded.into());
            }
            for row in &rows[..within] {
                out.push(row.convert()?);
            }
            match page.next() {
                Some(cursor) if within == rows.len() => after = Some(cursor.clone()),
                _ => return Ok(()),
            }
        }
    }
}

impl<P: CounterfactualDependencyReadPortV1> CounterfactualFrontierSourceV1
    for RecordedFrontierSourceV1<P>
{
    fn derive_frontier(
        &mut self,
        plan: &CounterfactualPlanV1,
        frontier_id: [u8; 16],
        provenance_digest: [u8; 32],
    ) -> Result<CounterfactualFrontierDerivationV1, CounterfactualAdmissionErrorV1> {
        let graph = self.recorded_graph(plan)?;
        let frontier =
            derive_recomputation_frontier_v1(plan, &graph, frontier_id, provenance_digest)
                .or(Err(CounterfactualAdmissionErrorV1::DependencyGraphInvalid))?;
        Ok(CounterfactualFrontierDerivationV1 {
            frontier,
            provisional_outputs: provisional_outputs(&graph),
        })
    }
}

/// The two scopes of the plan's graph, in stitching order: the parent prefix,
/// which the adapter bounds at the cut, then the Fork generation, which the
/// source bounds at the horizon.
const fn scope_reads(
    plan: &CounterfactualPlanV1,
    generation: ForkGenerationV1,
) -> [ScopeReadV1; 2] {
    [
        ScopeReadV1 {
            scope: DependencyReadScopeV1::ParentPrefix {
                timeline: TimelineId::from_ulid(Ulid::from_bytes(plan.parent_timeline_id)),
                through_tick: plan.parent_cut_tick,
            },
            through_tick: u64::MAX,
        },
        ScopeReadV1 {
            scope: DependencyReadScopeV1::ForkGeneration(generation),
            through_tick: plan.horizon_tick,
        },
    ]
}

/// Map a read fault to the coordinator's closed error: the validator's edge
/// coordinates are kept, every other graph fault is `DependencyGraphInvalid`,
/// and a port fault is `Store`.
fn admission_error(fault: RecordedGraphFaultV1) -> CounterfactualAdmissionErrorV1 {
    match fault {
        RecordedGraphFaultV1::Store(error) => CounterfactualAdmissionErrorV1::Store(error),
        RecordedGraphFaultV1::Graph(DependencyGraphErrorV1::DependencyGraphIncomplete(
            coordinate,
        )) => CounterfactualAdmissionErrorV1::DependencyGraphIncomplete(*coordinate),
        RecordedGraphFaultV1::Graph(DependencyGraphErrorV1::UnknownDependencyEdge(coordinate)) => {
            CounterfactualAdmissionErrorV1::UnknownDependencyEdge(*coordinate)
        }
        RecordedGraphFaultV1::Graph(_) => CounterfactualAdmissionErrorV1::DependencyGraphInvalid,
    }
}

/// The graph node of one recorded node row.
fn graph_node(record: &DependencyNodeRecordV1) -> DependencyGraphNodeV1 {
    let coordinate = record.coordinate();
    DependencyGraphNodeV1 {
        node: DependencyNodeV1 {
            tick: coordinate.tick(),
            scheduler_position: coordinate.scheduler_position(),
            owner_id: coordinate.owner_id().to_owned(),
            output_ordinal: coordinate.output_ordinal(),
            schema_id: coordinate.schema_id(),
            artifact_digest: *coordinate.artifact_digest().as_bytes(),
        },
        class: graph_class(record.class()),
        origin: graph_origin(record.origin()),
        input_digests: record
            .input_digests()
            .iter()
            .map(|digest| *digest.as_bytes())
            .collect(),
        provenance_digest: *record.provenance_digest().as_bytes(),
    }
}

/// The IDP1 class of a recorded class; both are the same closed set.
const fn graph_class(class: RecordedDependencyClassV1) -> DependencyClassV1 {
    match class {
        RecordedDependencyClassV1::ExogenousFrozen => DependencyClassV1::ExogenousFrozen,
        RecordedDependencyClassV1::InterventionAssigned => DependencyClassV1::InterventionAssigned,
        RecordedDependencyClassV1::EndogenousRecomputed => DependencyClassV1::EndogenousRecomputed,
        RecordedDependencyClassV1::FixedPolicy => DependencyClassV1::FixedPolicy,
        RecordedDependencyClassV1::PresentationOnly => DependencyClassV1::PresentationOnly,
    }
}

const fn graph_origin(origin: RecordedNodeOriginV1) -> DependencyGraphNodeOriginV1 {
    match origin {
        RecordedNodeOriginV1::Committed => DependencyGraphNodeOriginV1::Committed,
        RecordedNodeOriginV1::Provisional => DependencyGraphNodeOriginV1::Provisional,
    }
}

/// Every `Provisional` node of the validated graph, in canonical order.
fn provisional_outputs(
    graph: &ValidatedDependencyGraphV1,
) -> Vec<CounterfactualProvisionalOutputV1> {
    graph
        .nodes()
        .iter()
        .filter(|node| node.origin == DependencyGraphNodeOriginV1::Provisional)
        .map(|node| CounterfactualProvisionalOutputV1 {
            node: node.node.clone(),
            class: node.class,
        })
        .collect()
}
