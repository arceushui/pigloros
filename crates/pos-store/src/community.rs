//! Sealed retained community lifecycle persistence (ADR-128 §4, ADR-129 §3).
//!
//! Store owns the community key vault, native metadata envelopes and the
//! bootstrap of a protected domain. The domain itself evaluates its current
//! metadata-service authority over its own persisted grant chain (ADR-129
//! §3, "the concrete owner obtains current metadata-only service
//! authority"), and the Supervisor host-composition module coordinates it
//! (ADR-133). Nothing here exposes raw keys, material,
//! records, State or the backing store.

mod attestation;
mod extractor;
mod initializer;
mod lifecycle_authority;
mod memory_domain;
mod metadata_authority;
mod native_graph;
mod planner;
mod private_hash;
mod protection;
mod sealer;
mod store_domain;
mod vault;

pub use extractor::{
    prepare_community_artifact_batch_v1, CommunityArtifactBatchInputV1, CommunityArtifactBatchV1,
    CommunityArtifactRecordInputV1,
};
pub use initializer::CommunityInitializerOwnerV1;
pub use lifecycle_authority::{
    CommunityAdministrativeActionV1, CommunityAdministrativeOperationV1,
    CommunityAdministrativeRequestV1, CommunityAuthorityAdmissionV1, CommunityAuthorityCallV1,
    CommunityLifecycleAuthorityInputV1, CommunityLifecycleAuthorityV1, CommunityMemberActionV1,
};
pub use memory_domain::{
    CommunityBootstrapRequestV1, CommunityDomainBindingV1, CommunityDomainOpenedV1,
    MemoryCommunityDomainV1,
};
pub use metadata_authority::{
    metadata_resource, CommunityMetadataAuthorityInputV1, CommunityMetadataAuthorityV1,
};
pub use native_graph::{
    CommunityAssembledRecordV1, CommunityInitializationGraphInputV1,
    CommunityInitializationGraphV1, CommunityInitializationMemberV1,
};
pub use planner::{
    CommunityInitializationBindingsV1, CommunityInitializationInstallationV1,
    CommunityInitializationPlannerV1, CommunityInitializationRecordsV1, CommunityInitializeFormV1,
};
pub use protection::{
    CommunityArtifactProtectorV1, CommunityProtectedRecordV1, CommunityProtectionCohortV1,
    CommunityRecordEvidenceV1,
};
