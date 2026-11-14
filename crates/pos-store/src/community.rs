//! Sealed retained community lifecycle persistence (ADR-128 §4, ADR-129 §3).
//!
//! Store owns the community key vault, native metadata envelopes and the
//! bootstrap of a protected domain. The domain itself evaluates its current
//! metadata-service authority over its own persisted grant chain (ADR-129
//! §3, "the concrete owner obtains current metadata-only service
//! authority"), and the Supervisor host-composition module coordinates it
//! (ADR-133). Nothing here exposes raw keys, material,
//! records, State or the backing store.

mod memory_domain;
mod metadata_authority;
mod private_hash;
mod sealer;
mod vault;

pub use memory_domain::{
    CommunityBootstrapRequestV1, CommunityDomainBindingV1, CommunityDomainOpenedV1,
    MemoryCommunityDomainV1,
};
pub use metadata_authority::{
    metadata_resource, CommunityMetadataAuthorityInputV1, CommunityMetadataAuthorityV1,
};
