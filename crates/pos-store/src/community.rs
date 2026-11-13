//! Sealed retained community lifecycle persistence (ADR-128 §4, ADR-129 §3).
//!
//! Store owns the community key vault, native metadata envelopes and the
//! bootstrap of a protected domain. Runtime derives the current
//! metadata-service decision and the Supervisor host-composition module
//! coordinates both (ADR-133). Nothing here exposes raw keys, material,
//! records, State or the backing store.

mod memory_domain;
mod private_hash;
mod sealer;
mod vault;

pub use memory_domain::{
    CommunityBootstrapRequestV1, CommunityDomainBindingV1, CommunityDomainOpenedV1,
    MemoryCommunityDomainV1,
};
