#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-core` — the five kernel primitives.
//!
//! No I/O or async. Everything else depends on this crate.
//! Core-owned security policy may live here when an accepted ADR requires a
//! non-bypassable cross-cutting boundary; Plugins remain forbidden from owning
//! those protected domain concepts.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

pub mod authority;
#[cfg(test)]
extern crate self as pos_core;

pub mod clock;
pub mod consent;
pub mod crypto;
pub mod entity;
pub mod erasure;
pub mod error;
pub mod event;
pub mod geo_access;
pub mod geo_admission;
pub mod geo_cell_admission;
pub mod hasher;
pub mod ids;
pub mod key_registry;
pub mod manifest;
pub mod owntracks_enrollment;
pub mod owntracks_ingress;
pub mod plugin;
pub mod state;
pub mod store;
pub mod timeline;
pub mod world_transform;

// Re-export commonly used types at the crate root.
pub use authority::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    AuthorityErrorV1, AuthorityEvaluatorV1, AuthorityGranteeV1, AuthorityRegistrySnapshotV1,
    AuthorityRoleV1, AuthorizationDecisionV1, AuthorizationOutcomeV1, AuthorizationRequestDraftV1,
    AuthorizationRequestV1, CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityScopeDraftV1,
    CapabilityScopeV1, ConsentEvidenceV1, ConsentGrantRefDraftV1, ConsentGrantRefV1,
    ConsentGrantStatusV1, DelegateClassV1, DelegationChainV1, PrincipalRefV1, DELEGATE_ACTION_V1,
    MAX_AUTHORITY_DELEGATION_DEPTH, MAX_AUTHORITY_REGISTRY_BINDINGS, MAX_AUTHORITY_SCOPE_MEMBERS,
    MAX_AUTHORITY_SELECTORS, MAX_AUTHORITY_TEXT_BYTES, MAX_CAPABILITY_CONSENT_REFERENCES,
    MAX_CAPABILITY_RECORD_BYTES, MAX_DECISION_RECORD_BYTES, MAX_PRINCIPAL_RECORD_BYTES,
};
pub use clock::{
    AdmissionClock, FixedAdmissionClock, Seq, SimDuration, SimTime, SystemAdmissionClock, WallTime,
};
pub use consent::{
    is_consent_event_type, required_modality_for_event, ConsentAppendPermit, ConsentAuthority,
    ConsentCapabilityToken, ConsentCodecError, ConsentError, ConsentGate, ConsentGrantedV1,
    ConsentRevocationFoldListener, ConsentRevocationReservation, ConsentRevokedV1, FieldStateV1,
    EVENT_TYPE_CONSENT_GRANTED_V1, EVENT_TYPE_CONSENT_REVOKED_V1, HOST_CONSENT_CLOSED_EVENT_TYPE,
    MAX_CONSENT_HISTORY_EVENTS, MODALITY_EXPORT, MODALITY_LOCATION, MODALITY_MODEL_FIT,
    MODALITY_PERSONA,
};
pub use crypto::{Hash, PublicKey, Signature};
pub use entity::{Entity, EntityKind, Relationship, RelationshipKind};
pub use erasure::{
    acknowledgement_inventory_reference, destruction_command_reference,
    erasure_evidence_set_reference, selected_obligations_reference,
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceInputV1,
    ErasureAcknowledgementProvenanceV1, ErasureAcknowledgementV1,
    ErasureAdministrativeResolutionActionV1, ErasureAdministrativeResolutionInputV1,
    ErasureAdministrativeResolutionV1, ErasureApplicabilityDecisionV1, ErasureArtifactClassV1,
    ErasureArtifactTransitionV1, ErasureAtomicFreezeAdmissionInputV1,
    ErasureAtomicFreezeAdmissionV1, ErasureAtomicFreezeResultV1, ErasureAttemptOutcomeInputV1,
    ErasureAttemptOutcomeV1, ErasureAttemptQuotaReservationV1,
    ErasureAuthorizationRejectionInputV1, ErasureAuthorizationRejectionV1, ErasureCasEffectV1,
    ErasureCasOutcomeV1, ErasureCoordinator, ErasureCoordinatorPortV1,
    ErasureCoordinatorStateMachineV1, ErasureCorrectionProvenanceInputV1,
    ErasureCorrectionProvenanceV1, ErasureDestructionCommandV1, ErasureErrorV1,
    ErasureFreezeAdmissionEvidenceInputV1, ErasureFreezeAdmissionEvidenceV1,
    ErasureFreezeApplicabilityRowV1, ErasureFreezeAuthorizationEvidenceInputV1,
    ErasureFreezeAuthorizationEvidenceV1, ErasureFreezeAuthorizationVerifierV1,
    ErasureFreezeFailureInputV1, ErasureFreezeFailureV1, ErasureFreezeProvenanceInputV1,
    ErasureFreezeProvenanceV1, ErasureIndexInsertV1, ErasureInventoryCategoryV1,
    ErasureInventoryResultV1, ErasureKeyRoleV1, ErasureLifecycleV1, ErasureObligationInputV1,
    ErasureObligationSetInputV1, ErasureObligationSetV1, ErasureObligationV1,
    ErasurePersistedStateV1, ErasurePersistenceObjectV1, ErasurePersistencePortV1,
    ErasureReceiptInputV1, ErasureReceiptInventoriesV1, ErasureReceiptProvenanceInputV1,
    ErasureReceiptProvenanceV1, ErasureReceiptV1, ErasureRecoveryAuthorizationVerifierV1,
    ErasureReferenceV1, ErasureReplayClaimV1, ErasureRequestInputV1, ErasureRequestV1,
    ErasureRequiredTargetV1, ErasureRetryAdmissionInputV1, ErasureRetryAdmissionV1,
    ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1, ErasureScopeExtensionInputV1,
    ErasureScopeExtensionV1, ErasureScopeV1, ErasureStateResolverV1, ErasureStateTransitionV1,
    ErasureStateV1, ErasureVerifiedStateQueryV1, ErasureVerifiedStateV1, PreparedErasureCasV1,
    StoredErasureManifestV1, ERASURE_ACKNOWLEDGEMENT_PROVENANCE_TAG_V1,
    ERASURE_ADMINISTRATIVE_RESOLUTION_TAG_V1, ERASURE_ATTEMPT_OUTCOME_TAG_V1,
    ERASURE_AUTHORIZATION_REJECTION_TAG_V1, ERASURE_COORDINATOR_RECORD_MAX_BYTES,
    ERASURE_CORRECTION_PROVENANCE_TAG_V1, ERASURE_FREEZE_ADMISSION_AUTHORIZATION_TAG_V1,
    ERASURE_FREEZE_ADMISSION_EVIDENCE_MAX_BYTES, ERASURE_FREEZE_ADMISSION_EVIDENCE_TAG_V1,
    ERASURE_FREEZE_AUTHORIZATION_EVIDENCE_TAG_V1, ERASURE_FREEZE_FAILURE_TAG_V1,
    ERASURE_FREEZE_PROVENANCE_TAG_V1, ERASURE_MAX_ACKNOWLEDGEMENTS_PER_ATTEMPT,
    ERASURE_MAX_ADMINISTRATIVE_RESOLUTIONS, ERASURE_MAX_ATTEMPT_OUTCOMES,
    ERASURE_MAX_INVENTORY_RESULTS, ERASURE_MAX_OBLIGATIONS, ERASURE_MAX_OBLIGATIONS_PER_CATEGORY,
    ERASURE_MAX_OUTCOME_OWNERS, ERASURE_MAX_REFERENCES, ERASURE_MAX_SCOPE_EXTENSIONS,
    ERASURE_MAX_TARGETS, ERASURE_OBLIGATION_SET_MAX_BYTES, ERASURE_OBLIGATION_SET_TAG_V1,
    ERASURE_OBLIGATION_TAG_V1, ERASURE_PORTABLE_RECORD_MAX_BYTES, ERASURE_RECEIPT_MAX_BYTES,
    ERASURE_RECEIPT_PROVENANCE_TAG_V1, ERASURE_RECEIPT_TAG_V1, ERASURE_REQUEST_OR_STATE_MAX_BYTES,
    ERASURE_RETRY_ADMISSION_MAX_BYTES, ERASURE_RETRY_ADMISSION_TAG_V1,
    ERASURE_SCOPE_COMMITMENT_TAG_V1, ERASURE_SCOPE_EXTENSION_HEAD_TAG_V1,
    ERASURE_SCOPE_EXTENSION_TAG_V1, ERASURE_SCOPE_LEDGER_MAX_BYTES,
};
pub use error::CoreError;
pub use event::{CanonicalBytes, Determinism, Event, EventDraft, Kind, RunMode, SchemaVersion};
pub use geo_access::{is_geographic_event_type, GEOGRAPHIC_CELL_EVENT_TYPE, GEOGRAPHIC_EVENT_TYPE};
pub use geo_admission::{GeoLocationAdmissionFenceV1, GEO_LOCATION_V1_RESOLUTION};
pub use geo_cell_admission::{
    hash_admission_consent_record_bytes, hash_admission_snapshot_bytes, AdmissionConsentRecordV1,
    AdmissionEntitlementDraftV1, AdmissionEntitlementSnapshotV1, AdmissionSnapshotHash,
    AdmissionSnapshotId, AdmissionSnapshotLinkageV1, ConsentRecordHash, GeoCellAdmissionFenceV1,
    GeoCellAdmissionInputV1, GeoCellAdmissionRequestV1, GeoCellObservationPolicyVersion,
    GeographicAdmissionAdmin, GeographicAdmissionConsentResolver, GeographicAdmissionFingerprintV1,
    GeographicAdmissionIntentV1, GeographicAdmissionOutcome, GeographicAdmissionStore,
    GeographicObservationV1, GeographicReplayEvidenceV1, GeographicReplayVerifier,
    SourceTimeBucket, ValidatedGeoCellV1, ValidatedGeographicAdmissionV1,
};
pub use hasher::Hasher;
pub use ids::{CorrelationId, EntityId, EventId, PluginId, RelationshipId, TimelineId};
pub use key_registry::{
    deletion_receipt, KeyDestructionBeginOutcomeV1, KeyDestructionOutcomeV1, KeyDestructionPortV1,
    KeyDestructionRequestV1, KeyIdentityV1, KeyRecordV1, KeyRegistrationOutcomeV1,
    KeyRegistrationV1, KeyRegistryEncryptionPortV1, KeyRegistryErrorV1, KeyRegistryPortV1,
    KeyRegistrySigningPortV1, KeyRegistryStateV1, KeyRoleV1, KeyTombstoneV1, OwnerIdV1,
};
pub use manifest::{AdapterRecord, ReproManifest};
pub use owntracks_enrollment::{
    OwnTracksEnrollmentRequestV1, OwnTracksEnrollmentStateV1, OwnTracksEnrollmentStatusV1,
    OwnTracksEnrollmentStatusViewV1, OwnTracksEnrollmentStore,
};
pub use owntracks_ingress::{
    OwnTracksIngressInputV1, OwnTracksIngressRateKeyV1, OwnTracksIngressStore,
    PreparedOwnTracksIngressV1,
};
pub use plugin::{
    ActionApprover, ActionRejected, Capability, Plugin, ProposedAction,
    MAX_PROPOSED_ACTION_PAYLOAD_BYTES,
};
pub use state::{Reducer, State, StateRegistry};
pub use store::{
    append_identity_expires_at, checked_append_identity_expires_at, export_timeline,
    export_timeline_cow, export_timeline_own, export_timeline_raw, import_committed_with_rollback,
    import_timeline, import_timeline_with_id, validate_committed_batch, AppendDedupKey,
    AppendDedupScope, AppendIdentity, AppendIntent, AppendOrDuplicateOutcome, EventReadBounds,
    EventStore, PurgeOutcome, SeqRange, TimelineExport, APPEND_IDENTITY_RETENTION_MICROS,
};
pub use timeline::{Timeline, TimelineMeta, TimelineMode};
pub use world_transform::{
    Wgs84PositionV1, WorldCoordinateV1, WorldGeographicEvidenceCapabilityV1,
    WorldOriginReferenceV1, WorldOriginRegistryV1, WorldOriginV1, WorldTransformError,
    WorldTransformV1,
};
