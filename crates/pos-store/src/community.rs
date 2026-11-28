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
#[cfg(target_os = "linux")]
mod current_view_head;
mod erasure_budget;
mod extractor;
#[cfg(target_os = "linux")]
mod initialize;
mod initializer;
mod lifecycle_authority;
mod memory_domain;
mod metadata_authority;
mod native_graph;
mod observation;
#[cfg(target_os = "linux")]
mod pass_abort;
mod pass_install;
mod pass_planner;
#[cfg(target_os = "linux")]
mod pass_publish;
#[cfg(target_os = "linux")]
mod pass_record;
#[cfg(target_os = "linux")]
mod pass_seal;
#[cfg(target_os = "linux")]
mod pass_state;
#[cfg(target_os = "linux")]
mod pass_writer;
mod planner;
mod private_hash;
mod protection;
#[cfg(target_os = "linux")]
mod quarantine;
mod sealer;
mod store_domain;
mod vault;

pub use extractor::{
    prepare_community_artifact_batch_v1, prepare_community_pass_control_batch_v1,
    CommunityArtifactBatchFormV1, CommunityArtifactBatchInputV1, CommunityArtifactBatchV1,
    CommunityArtifactRecordInputV1, CommunityControlBatchInputV1, CommunityPassControlBatchInputV1,
};
#[cfg(target_os = "linux")]
pub use initialize::{
    CommunityInitializationContextV1, CommunityInitializationReceiptV1, CommunityInitializeCallV1,
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
pub use observation::{
    prepare_community_observation_v1, CommunityObservationBindingsV1,
    CommunityObservationConsumerV1, CommunityObservationEventV1,
    CommunityObservationInstallationV1, CommunityObservationMaterializationInputV1,
    CommunityObservationMaterializationV1, CommunityObservationPassV1, CommunityObservationQuoteV1,
    CommunityObservationRecordsV1, CommunityObservationSourcesV1,
};
#[cfg(target_os = "linux")]
pub use pass_abort::{
    CommunityObservedFailureV1, CommunityPassAbortCallV1, CommunityPassAbortFailureCallV1,
    CommunityPassAbortFailureInputV1, CommunityPassAbortFailureV1, CommunityPassAbortReceiptV1,
    CommunityPassAbortScopeV1,
};
pub use pass_install::{
    community_reservation_horizons_v1, community_reuse_horizon_v1,
    community_roster_quarantine_keys_v1, install_community_pass_profile_v1,
    CommunityOwnerHorizonsV1, CommunityReservationHorizonsV1,
};
pub use pass_planner::{
    plan_community_pass_v1, CommunityPassDueV1, CommunityPassInstallationV1,
    CommunityPassMemberViewV1, CommunityPassObservationUseV1, CommunityPassPlanV1,
    CommunityPassQuotedV1, CommunityPassRequestV1, CommunityPassStepInputsV1, CommunityPassViewV1,
};
#[cfg(target_os = "linux")]
pub use pass_publish::{CommunityOriginalReserveV1, CommunityReservePublicationV1};
#[cfg(target_os = "linux")]
pub use pass_record::{
    CommunityPassCountsV1, CommunityPassMemberDigestsV1, CommunityPassStatusV1,
    CommunityReservedPassV1,
};
#[cfg(target_os = "linux")]
pub use pass_seal::{
    CommunityAnnotationPlanV1, CommunitySealCandidateV1, CommunitySealInputV1,
    CommunitySealInvocationV1, CommunitySealedPassV1, CommunityStagedSealV1,
};
#[cfg(target_os = "linux")]
pub use pass_writer::{
    community_reserve_selection_v1, CommunityCommitInputV1, CommunityMintedObservationV1,
    CommunityObservationCutV1, CommunityReserveInputV1, CommunityReservePassFactsV1,
    CommunityStagedAbortV1, CommunityStagedCommitV1, CommunityStagedReserveV1,
};
pub use planner::{
    CommunityInitializationAuthorityV1, CommunityInitializationBindingsV1,
    CommunityInitializationEvidenceInputV1, CommunityInitializationInstallationV1,
    CommunityInitializationPlannerV1, CommunityInitializationRecordsV1,
    CommunityInitializationViewV1, CommunityInitializeFormV1,
};
pub use protection::{
    CommunityArtifactProtectorV1, CommunityProtectedRecordV1, CommunityProtectionCohortV1,
    CommunityRecordEvidenceV1,
};
#[cfg(target_os = "linux")]
pub use quarantine::{
    CommunityPreExecutionFailureInputV1, CommunityPreExecutionFailureV1,
    CommunityPreExecutionTrustV1, CommunityQuarantineContextV1, CommunityQuarantineReceiptV1,
    CommunityQuarantineResetCallV1, CommunitySetReasonCallV1,
};
