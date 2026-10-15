//! The ADR-064 composite frontier source: the recorded parent prefix plus a
//! host-supplied provisional graph.
//!
//! [`PrefixSeededFrontierSourceV1`] admits the first counterfactual generation
//! of a Fork, which has no recorded Fork records before its admission
//! (decision D17-A). It is the host-side
//! [`CounterfactualFrontierSourceV1`] for that admission. For one CFP1
//! [`CounterfactualPlanV1`] it:
//!
//! 1. pages the recorded nodes and edges of the parent Timeline's committed
//!    prefix through the plan's parent-cut Tick, through a
//!    [`CounterfactualDependencyReadPortV1`], with the paging and conversion
//!    [`RecordedFrontierSourceV1`](super::frontier_source::RecordedFrontierSourceV1)
//!    uses;
//! 2. appends the provisional nodes and edges the host built for the
//!    generation being admitted;
//! 3. validates the stitched graph, derives the sealed `RCF1` frontier, and
//!    reports every `Provisional` node as a provisional output, exactly as
//!    the recorded source does.
//!
//! Once the generation's suffix is recorded, the recorded source derives the
//! same graph, and so the same digest, from the store alone.
//!
//! # Contract decisions
//!
//! - **Order.** The provisional graph must follow the contract's canonical
//!   order, which places it after the prefix rows; the validator re-checks the
//!   order and the digest uniqueness of the stitched list, so a misordered or
//!   overlapping provisional graph fails closed with `DependencyGraphInvalid`.
//! - **Horizon.** The host supplies the generation through the horizon; the
//!   source does not filter it.
//! - **Bounds.** The prefix read stops one row past the bounds, as in the
//!   recorded source, and the validator bounds the stitched graph.
//! - **Errors.** The errors of the recorded source apply: a port failure is
//!   `Store`, a rejected graph `DependencyGraphInvalid`, with the validator's
//!   coordinate for a missing or unknown edge. An empty prefix with an empty
//!   provisional graph is `DependencyGraphInvalid`.
//! - **Determinism.** The output is a pure function of the committed prefix
//!   rows, the provisional graph, the plan, and the bounds; the page limit
//!   never changes it.

use pos_conformance::counterfactual::dependency::InputDependencyV1;
use pos_conformance::counterfactual::plan::CounterfactualPlanV1;
use pos_core::{CounterfactualDependencyReadPortV1, MAX_DEPENDENCY_PAGE_ROWS_V1};
use pos_runtime::counterfactual::coordinator::{
    CounterfactualAdmissionErrorV1, CounterfactualFrontierDerivationV1,
    CounterfactualFrontierSourceV1,
};

use super::dependency_graph::{
    validate_dependency_graph_v1, DependencyGraphBoundsV1, DependencyGraphNodeV1,
    ValidatedDependencyGraphV1,
};
use super::frontier::dependency_graph_digest_v1;
use super::frontier_source::{
    admission_error, derive_validated, prefix_read, read_scope, row_caps, RecordedGraphFaultV1,
};

/// The composite frontier source over the recorded parent prefix and a
/// host-supplied provisional graph.
///
/// It owns the read port `P` and the provisional nodes and edges of the
/// generation being admitted; see the module documentation.
#[derive(Clone, Debug)]
pub struct PrefixSeededFrontierSourceV1<P> {
    port: P,
    nodes: Vec<DependencyGraphNodeV1>,
    edges: Vec<InputDependencyV1>,
    bounds: DependencyGraphBoundsV1,
    page_limit: usize,
}

impl<P> PrefixSeededFrontierSourceV1<P> {
    /// Build a source over `port` for the provisional `nodes` and `edges` of
    /// the generation being admitted, validating under `bounds` and reading
    /// full pages.
    #[must_use]
    pub const fn new(
        port: P,
        nodes: Vec<DependencyGraphNodeV1>,
        edges: Vec<InputDependencyV1>,
        bounds: DependencyGraphBoundsV1,
    ) -> Self {
        Self {
            port,
            nodes,
            edges,
            bounds,
            page_limit: MAX_DEPENDENCY_PAGE_ROWS_V1,
        }
    }

    /// Read at most `page_limit` prefix rows per page, clamped to 1 through
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

impl<P: CounterfactualDependencyReadPortV1> PrefixSeededFrontierSourceV1<P> {
    /// Page the recorded prefix for `plan`, append the provisional graph, and
    /// validate the stitched graph.
    ///
    /// # Errors
    /// Returns the errors listed in the module documentation, boxed because
    /// the admission error is large.
    pub fn recorded_graph(
        &self,
        plan: &CounterfactualPlanV1,
    ) -> Result<ValidatedDependencyGraphV1, Box<CounterfactualAdmissionErrorV1>> {
        self.read_graph(plan)
            .map_err(|fault| Box::new(admission_error(fault)))
    }

    /// Build and validate the graph for `plan` and return its
    /// dependency-graph digest, the value the host publishes with
    /// `publish_counterfactual_facts`.
    ///
    /// # Errors
    /// Exactly those of [`Self::recorded_graph`].
    pub fn recorded_graph_digest(
        &self,
        plan: &CounterfactualPlanV1,
    ) -> Result<[u8; 32], Box<CounterfactualAdmissionErrorV1>> {
        self.recorded_graph(plan)
            .map(|graph| dependency_graph_digest_v1(&graph))
    }

    /// Page the prefix scope, nodes then edges, append the provisional graph,
    /// and validate it.
    fn read_graph(
        &self,
        plan: &CounterfactualPlanV1,
    ) -> Result<ValidatedDependencyGraphV1, RecordedGraphFaultV1> {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        read_scope(
            &self.port,
            self.page_limit,
            prefix_read(plan),
            row_caps(self.bounds),
            &mut nodes,
            &mut edges,
        )?;
        nodes.extend(self.nodes.iter().cloned());
        edges.extend(self.edges.iter().cloned());
        validate_dependency_graph_v1(plan, self.bounds, nodes, edges)
            .map_err(RecordedGraphFaultV1::Graph)
    }
}

impl<P: CounterfactualDependencyReadPortV1> CounterfactualFrontierSourceV1
    for PrefixSeededFrontierSourceV1<P>
{
    fn derive_frontier(
        &mut self,
        plan: &CounterfactualPlanV1,
        frontier_id: [u8; 16],
        provenance_digest: [u8; 32],
    ) -> Result<CounterfactualFrontierDerivationV1, CounterfactualAdmissionErrorV1> {
        let graph = self.read_graph(plan).map_err(admission_error)?;
        derive_validated(plan, &graph, frontier_id, provenance_digest)
            .ok_or(CounterfactualAdmissionErrorV1::DependencyGraphInvalid)
    }
}
