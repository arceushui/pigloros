//! ADR-064 counterfactual Fork recomputation over committed Timelines.
//!
//! The wire contracts (INT1, IDP1, CFP1, RCF1, SIV1, ...) live in
//! `pos_conformance::counterfactual`; this module owns the temporal
//! algorithms that consume them. Each algorithm owns one submodule.

pub mod dependency_graph;
pub mod frontier;
pub mod frontier_source;
