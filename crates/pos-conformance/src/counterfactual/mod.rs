//! ADR-064 deterministic counterfactual contracts.
//!
//! Each schema owns one module. This module is public instead of re-exported
//! at the crate root so that the INT1 [`InterventionV1`] and the IDP1
//! [`dependency::InputDependencyV1`] do not collide with the proof-local
//! [`crate::InterventionV1`] and [`crate::InputDependencyV1`] evidence
//! records. IDP1 items are reached through the [`dependency`] path. The
//! crate-private CBOR helpers the schemas share live in `codec`.

mod codec;
pub mod dependency;
pub mod intervention;

pub use intervention::{
    validate_plan_interventions_v1, InterventionContractErrorV1, InterventionOperationV1,
    InterventionV1, ProofInterventionBindingV1, INTERVENTION_MAGIC_V1,
    MAX_INTERVENTIONS_PER_PLAN_V1, MAX_INTERVENTION_BYTES_V1,
};
