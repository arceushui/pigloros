//! ADR-064 deterministic counterfactual contracts.
//!
//! Each schema owns one module; this module only declares and re-exports them,
//! and keeps the crate-private CBOR helpers they share in `codec`.
//! It is public instead of re-exported at the crate root so that the INT1
//! [`InterventionV1`] does not collide with the proof-local
//! [`crate::InterventionV1`] evidence record.

mod codec;
pub mod dependency;
pub mod intervention;

pub use intervention::{
    validate_plan_interventions_v1, InterventionContractErrorV1, InterventionOperationV1,
    InterventionV1, ProofInterventionBindingV1, INTERVENTION_MAGIC_V1,
    MAX_INTERVENTIONS_PER_PLAN_V1, MAX_INTERVENTION_BYTES_V1,
};
