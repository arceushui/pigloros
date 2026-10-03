//! ADR-064 counterfactual coordination owned by the core runtime.
//!
//! The wire contracts (INT1, CFP1, RCF1, SIV1, ...) live in
//! `pos_conformance::counterfactual` and the storage transaction port in
//! `pos_core::counterfactual_store`; this module owns the core
//! `CounterfactualCoordinator` that drives them. Each coordinator slice owns
//! one submodule.

pub mod coordinator;
