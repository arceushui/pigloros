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

pub mod adapter_admission;
pub mod adapter_transcript;
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
pub mod executable_budget;
pub mod fork_admission;
pub mod fork_admission_authority;
pub mod fork_admission_command;
pub mod fork_attribution;
pub mod fork_authentication;
pub mod fork_event_provenance;
pub mod geo_access;
pub mod geo_admission;
pub mod geo_cell_admission;
pub mod hasher;
pub mod ids;
pub mod key_registry;
pub mod local_cut_seal;
pub mod manifest;
pub mod manifest_owner_link;
pub mod output_policy;
pub mod owntracks_enrollment;
pub mod owntracks_ingress;
pub mod pipeline;
pub mod plugin;
<<<<<<< HEAD
pub mod recipient_key;
pub mod repro_manifest_root;
pub mod retention;
pub mod state;
pub mod store;
pub mod timeline;
pub mod timeline_envelope;
pub mod world_artifact;
pub mod world_closure_binding;
pub mod world_consumer_set;
pub mod world_dependency_directory;
pub mod world_history;
pub mod world_key_evidence;
pub mod world_recording_receipt;
pub mod world_replay;
pub mod world_replay_handle;
pub mod world_transform;

/// Write the preferred definite-length CBOR header for one major type.
pub(crate) fn encode_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    let bytes = value.to_be_bytes();
    match value {
        0..=23 => out.push(prefix | bytes[7]),
        24..=0xff => out.extend_from_slice(&[prefix | 0x18, bytes[7]]),
        0x100..=0xffff => {
            out.push(prefix | 0x19);
            out.extend_from_slice(&bytes[6..]);
        }
        0x1_0000..=0xffff_ffff => {
            out.push(prefix | 0x1a);
            out.extend_from_slice(&bytes[4..]);
        }
        _ => {
            out.push(prefix | 0x1b);
            out.extend_from_slice(&bytes);
        }
    }
}

/// Write one preferred definite-length CBOR byte or text string.
pub(crate) fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8], major: u8) {
    encode_head(out, major, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Write one preferred definite-length CBOR hash byte string.
pub(crate) fn encode_hash(out: &mut Vec<u8>, hash: Hash) {
    encode_bytes(out, hash.as_bytes(), 2);
}

/// Low-level structural read failure for bounded definite-length CBOR records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CborReadError {
    /// The requested token, byte range, or CBOR major type is invalid.
    InvalidEncoding,
}

/// Shared byte cursor for the bounded structural CBOR codecs.
///
/// Protocol modules retain their own field bounds, semantic validation, and
/// public errors. This cursor owns only byte movement and basic CBOR heads.
pub(crate) struct CborCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CborCursor<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) const fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    pub(crate) fn consume_if(&mut self, byte: u8) -> bool {
        if self.bytes.get(self.offset) == Some(&byte) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    /// Take an exact byte range and advance the cursor.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` when the range exceeds the remaining input.
    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], CborReadError> {
        self.bytes
            .get(self.offset..)
            .and_then(|remaining| remaining.get(..length))
            .map(|value| {
                self.offset += length;
                value
            })
            .ok_or(CborReadError::InvalidEncoding)
    }

    /// Read one byte and advance the cursor.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` when no byte remains.
    pub(crate) fn byte(&mut self) -> Result<u8, CborReadError> {
        self.take(1).map(|bytes| bytes[0])
    }

    /// Match and consume an exact byte prefix.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` when the bytes do not match or are truncated.
    pub(crate) fn fixed(&mut self, expected: &[u8]) -> Result<(), CborReadError> {
        self.take(expected.len()).and_then(|actual| {
            if actual == expected {
                Ok(())
            } else {
                Err(CborReadError::InvalidEncoding)
            }
        })
    }

    /// Read a definite-length CBOR head of the expected major type.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` for a wrong major type, reserved additional
    /// information, or a truncated numeric argument.
    pub(crate) fn head(&mut self, expected_major: u8) -> Result<u64, CborReadError> {
        self.byte().and_then(|first| {
            if first >> 5 != expected_major {
                return Err(CborReadError::InvalidEncoding);
            }
            match first & 0x1f {
                small @ 0..=23 => Ok(u64::from(small)),
                24 => self.number::<1>(),
                25 => self.number::<2>(),
                26 => self.number::<4>(),
                27 => self.number::<8>(),
                _ => Err(CborReadError::InvalidEncoding),
            }
        })
    }

    /// Read an unsigned integer represented by exactly `N` big-endian bytes.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` when fewer than `N` bytes remain.
    pub(crate) fn number<const N: usize>(&mut self) -> Result<u64, CborReadError> {
        self.unsigned_bytes(N)
    }

    /// Read an unsigned integer represented by the requested big-endian width.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` when the requested width exceeds the input.
    pub(crate) fn unsigned_bytes(&mut self, length: usize) -> Result<u64, CborReadError> {
        self.take(length).map(|bytes| {
            bytes
                .iter()
                .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte))
        })
    }
}

pub use adapter_admission::{
    adapter_configuration_digest_v1, public_adapter_schema_digest_v1, AdapterAdmissionEntryV1,
    AdapterAdmissionErrorV1, AdapterAdmissionInputV1, AdapterAdmissionV1, AdapterDataClassV1,
    AdapterEffectModeV1, MAX_ADAPTER_ADMISSION_BYTES_V1, MAX_ADAPTER_ADMISSION_ENTRIES_V1,
    MAX_ADAPTER_CONFIGURATION_BYTES_V1,
};
pub use adapter_transcript::{
    adapter_output_digest_v1, AdapterInvocationInputV1, AdapterInvocationV1,
    AdapterTranscriptCallV1, AdapterTranscriptErrorV1, AdapterTranscriptInputV1,
    AdapterTranscriptV1, MAX_ADAPTER_CALL_BYTES_V1, MAX_ADAPTER_TRANSCRIPT_BYTES_V1,
    MAX_ADAPTER_TRANSCRIPT_CALLS_V1,
};
pub use local_cut_seal::{
    local_cut_tree_scope_v1, LocalCutBranchChildV1, LocalCutManifestBindingBranchV1,
    LocalCutManifestBindingPageV1, LocalCutManifestBindingRowV1, LocalCutManifestBindingTableV1,
    LocalCutSealErrorV2, LocalCutSealInputV2, LocalCutSealV2, LocalCutTableRefV1,
    MAX_LOCAL_CUT_SEAL_BYTES_V2, MAX_LOCAL_CUT_TABLE_ROWS_V1,
};
pub use manifest_owner_link::{
    ManifestAdmissionCatalogInputV1, ManifestAdmissionCatalogRowV1, ManifestAdmissionCatalogV1,
    ManifestOwnerLinkErrorV1, ManifestSlotAdmissionReceiptInputV1, ManifestSlotAdmissionReceiptV1,
    ManifestSlotBindingInputV1, ManifestSlotBindingRowV1, ManifestSlotBindingV1,
    MAX_MANIFEST_ADMISSION_CATALOG_BYTES_V1, MAX_MANIFEST_OWNER_PLUGINS_V1,
    MAX_MANIFEST_SLOT_ADMISSION_RECEIPT_BYTES_V1, MAX_MANIFEST_SLOT_BINDING_BYTES_V1,
};
pub use repro_manifest_root::{
    ReproManifestRootErrorV1, ReproManifestRootInputV1, ReproManifestRootV1,
    MAX_REPRO_MANIFEST_LABEL_BYTES_V1, MAX_REPRO_MANIFEST_ROOT_BYTES_V1,
};
pub use world_artifact::{
    WorldArtifactErrorV1, WorldArtifactKeyDependencyV1, WorldArtifactKindV1,
    WorldArtifactLeafInputV1, WorldArtifactLeafV1, MAX_WORLD_ARTIFACT_CHILDREN_V1,
    MAX_WORLD_ARTIFACT_KEYS_V1, MAX_WORLD_ARTIFACT_LEAF_BYTES_V1,
};
pub use world_closure_binding::{
    WorldClosureBindingErrorV1, WorldClosureBindingInputV1, WorldClosureBindingV1,
    WorldClosureCutCoordinateV1, WorldClosureReadLimitsV1, MAX_WORLD_CLOSURE_BINDING_BYTES_V1,
};

// Re-export commonly used types at the crate root.
pub use authority::{
    AiGoalPolicyRevisionV1, AssuranceLevelV1, AuthenticatedPrincipalDraftV1,
    AuthenticatedPrincipalResultV1, AuthorityCommitOutcomeV1, AuthorityErrorV1,
    AuthorityEvaluatorV1, AuthorityGranteeV1, AuthorityMutationPermitV1,
    AuthorityPersistenceBindingV1, AuthorityPersistenceErrorV1, AuthorityPersistenceHostV1,
    AuthorityPersistencePortV1, AuthorityPersistenceStateV1, AuthorityRegistrySnapshotV1,
    AuthorityRoleV1, AuthorizationDecisionV1, AuthorizationOutcomeV1, AuthorizationRequestDraftV1,
    AuthorizationRequestV1, BeliefRecordDraftV1, BeliefRecordV1, CapabilityGrantDraftV1,
    CapabilityGrantV1, CapabilityRevocationDraftV1, CapabilityRevocationV1, CapabilityScopeDraftV1,
    CapabilityScopeV1, ConfidenceV1, ConsentEvidenceV1, ConsentGrantRefDraftV1, ConsentGrantRefV1,
    ConsentGrantStatusV1, DelegateClassV1, DelegationChainV1, KnowledgeSnapshotDraftV1,
    KnowledgeSnapshotV1, MemoryPolicyRevisionV1, ObservationArtifactV1, ObservationRecordDraftV1,
    ObservationRecordV1, ObservationSnapshotDraftV1, ObservationSnapshotV1, ObservationStatusV1,
    PersistedAuthorityV1, PreferenceValueRevisionV1, PrincipalRefV1, DELEGATE_ACTION_V1,
    MAX_AUTHORITY_DELEGATION_DEPTH, MAX_AUTHORITY_REGISTRY_BINDINGS, MAX_AUTHORITY_SCOPE_MEMBERS,
    MAX_AUTHORITY_SELECTORS, MAX_AUTHORITY_TEXT_BYTES, MAX_CAPABILITY_CONSENT_REFERENCES,
    MAX_CAPABILITY_RECORD_BYTES, MAX_DECISION_RECORD_BYTES, MAX_KNOWLEDGE_SNAPSHOT_BYTES,
    MAX_KNOWLEDGE_SNAPSHOT_RECORDS, MAX_OBSERVATION_ARTIFACT_BYTES, MAX_OBSERVATION_RECORD_BYTES,
    MAX_OBSERVATION_SNAPSHOT_BYTES, MAX_OBSERVATION_SNAPSHOT_RECORDS,
    MAX_PERSISTED_AUTHORITY_GRANTS, MAX_PERSISTED_AUTHORITY_STATE_BYTES,
    MAX_PRINCIPAL_RECORD_BYTES,
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
    erasure_evidence_set_reference, extract_adapter_admission_registration_v1,
    extract_adapter_transcript_registration_v1, extract_repro_manifest_root_registration_v1,
    inspect_artifact_registration_graph_v1, prepare_artifact_registration_batch_v1,
    selected_obligations_reference, validate_artifact_registration_catalog_graph_v1,
    AdapterArtifactRegistrationErrorV1, ArtifactChildEdgeV1, ArtifactClaimInputV1,
    ArtifactDataClassV1, ArtifactDestructionDispositionV1, ArtifactKeyDependencyV1,
    ArtifactOptionalityV1, ArtifactRedactionStateV1, ArtifactRegistrationCatalogRowV1,
    ArtifactRegistrationCommitOutcomeV1, ArtifactRegistrationErrorV1, ArtifactRegistrationFieldsV1,
    ArtifactRegistrationGraphErrorV1, ArtifactRegistrationGraphNodeV1,
    ArtifactRegistrationGraphSummaryV1, ArtifactRegistrationInputV1,
    ArtifactRegistrationOwnerVerificationErrorV1, ArtifactRegistrationOwnerVerifierV1,
    ArtifactRegistrationPersistenceErrorV1, ArtifactRegistrationPersistencePortV1,
    ArtifactRegistrationPreparationErrorV1, ArtifactRegistrationV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, ErasureAcknowledgementOutcomeV1,
    ErasureAcknowledgementProvenanceInputV1, ErasureAcknowledgementProvenanceV1,
    ErasureAcknowledgementV1, ErasureAdministrativeResolutionActionV1,
    ErasureAdministrativeResolutionInputV1, ErasureAdministrativeResolutionV1,
    ErasureAdmittedForkContextV1, ErasureApplicabilityDecisionV1, ErasureArtifactClassV1,
    ErasureArtifactTransitionV1, ErasureAtomicFreezeAdmissionInputV1,
    ErasureAtomicFreezeAdmissionV1, ErasureAtomicFreezeResultV1, ErasureAttemptOutcomeInputV1,
    ErasureAttemptOutcomeV1, ErasureAttemptQuotaReservationV1, ErasureAuthorizationDecisionV1,
    ErasureAuthorizationRejectionInputV1, ErasureAuthorizationRejectionV1, ErasureCasEffectV1,
    ErasureCasOutcomeV1, ErasureContainmentErrorV1, ErasureContainmentGateV1, ErasureCoordinator,
    ErasureCoordinatorPortV1, ErasureCoordinatorStateMachineV1, ErasureCorrectionProvenanceInputV1,
    ErasureCorrectionProvenanceV1, ErasureDestructionCommandV1, ErasureErrorV1,
    ErasureForkAdmissionInputV1, ErasureForkPersistencePortV1, ErasureForkRecoveryContentV1,
    ErasureForkRecoveryMutationV1, ErasureForkRecoveryProofV1, ErasureForkRecoveryV1,
    ErasureForkRetryScopeRequirementV1, ErasureForkScopeRequirementV1,
    ErasureFreezeAdmissionEvidenceInputV1, ErasureFreezeAdmissionEvidenceV1,
    ErasureFreezeApplicabilityRowV1, ErasureFreezeAuthorizationEvidenceInputV1,
    ErasureFreezeAuthorizationEvidenceV1, ErasureFreezeAuthorizationVerifierV1,
    ErasureFreezeFailureInputV1, ErasureFreezeFailureV1, ErasureFreezeProvenanceInputV1,
    ErasureFreezeProvenanceV1, ErasureGate, ErasureHostErrorV1, ErasureIndexInsertV1,
    ErasureInventoryCategoryV1, ErasureInventoryObservationV1, ErasureInventoryPersistencePortV1,
    ErasureInventoryResultV1, ErasureKeyRoleV1, ErasureLifecycleV1, ErasureObligationInputV1,
    ErasureObligationSetInputV1, ErasureObligationSetV1, ErasureObligationV1,
    ErasurePersistedStateV1, ErasurePersistenceInventorySnapshotV1, ErasurePersistenceObjectV1,
    ErasurePersistencePortV1, ErasureProtectedEffectDispositionV1,
    ErasureProtectedEffectIntervalV1, ErasureProtectedOperationV1, ErasureReceiptInputV1,
    ErasureReceiptInventoriesV1, ErasureReceiptProvenanceInputV1, ErasureReceiptProvenanceV1,
    ErasureReceiptV1, ErasureRecoveryAuthorizationVerifierV1, ErasureRecoveryErrorQueryV1,
    ErasureRecoveryErrorV1, ErasureRecoveryLimitsV1, ErasureReferenceV1, ErasureRejoinAdmissionV1,
    ErasureRejoinAttestationVerifierV1, ErasureRejoinDispositionV1, ErasureRejoinInventoryV1,
    ErasureRejoinProofInputV1, ErasureRejoinProofV1, ErasureReplayClaimV1, ErasureRequestInputV1,
    ErasureRequestV1, ErasureRequiredTargetV1, ErasureRetryAdmissionInputV1,
    ErasureRetryAdmissionV1, ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1,
    ErasureScopeExtensionInputV1, ErasureScopeExtensionV1, ErasureScopeV1, ErasureStateResolverV1,
    ErasureStateTransitionV1, ErasureStateV1, ErasureTopologyStoreBindingV1,
    ErasureTopologyTransitionPermitV1, ErasureVerifiedEmptyInventoryQueryV1,
    ErasureVerifiedInventoryQueryV1, ErasureVerifiedInventoryV1, ErasureVerifiedStateQueryV1,
    ErasureVerifiedStateV1, ErasureVerifiedTopologyObservationV1, ErasureVerifiedTopologyProofV1,
    EvaluatedArtifactClaimV1, PreparedArtifactRegistrationBatchV1,
    PreparedArtifactRegistrationRecordV1, PreparedErasureCasV1, PreparedErasureForkAdmissionV1,
    PreparedErasureForkBatchV1, PreparedErasureRecoveryErrorV1, RegisteredArtifactV1,
    ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1, ReproManifestArtifactRegistrationErrorV1,
    ReproManifestRootRegistrationInputV1, StoredErasureManifestV1,
    ERASURE_ACKNOWLEDGEMENT_PROVENANCE_TAG_V1, ERASURE_ADMINISTRATIVE_RESOLUTION_TAG_V1,
    ERASURE_ATTEMPT_OUTCOME_TAG_V1, ERASURE_AUTHORIZATION_REJECTION_TAG_V1,
    ERASURE_COORDINATOR_RECORD_MAX_BYTES, ERASURE_CORRECTION_PROVENANCE_TAG_V1,
    ERASURE_FORK_RECOVERY_PROOF_MAX_BYTES, ERASURE_FORK_RECOVERY_PROOF_TAG_V1,
    ERASURE_FREEZE_ADMISSION_AUTHORIZATION_TAG_V1, ERASURE_FREEZE_ADMISSION_EVIDENCE_MAX_BYTES,
    ERASURE_FREEZE_ADMISSION_EVIDENCE_TAG_V1, ERASURE_FREEZE_AUTHORIZATION_EVIDENCE_TAG_V1,
    ERASURE_FREEZE_FAILURE_TAG_V1, ERASURE_FREEZE_PROVENANCE_TAG_V1,
    ERASURE_MAX_ACKNOWLEDGEMENTS_PER_ATTEMPT, ERASURE_MAX_ADMINISTRATIVE_RESOLUTIONS,
    ERASURE_MAX_ATTEMPT_OUTCOMES, ERASURE_MAX_DIAGNOSTIC_KEY_INPUTS,
    ERASURE_MAX_INVENTORY_CLASSIFICATIONS, ERASURE_MAX_INVENTORY_REQUESTS,
    ERASURE_MAX_INVENTORY_RESULTS, ERASURE_MAX_INVENTORY_TIMELINES, ERASURE_MAX_OBLIGATIONS,
    ERASURE_MAX_OBLIGATIONS_PER_CATEGORY, ERASURE_MAX_OUTCOME_OWNERS, ERASURE_MAX_RECOVERY_ERRORS,
    ERASURE_MAX_REFERENCES, ERASURE_MAX_SCOPE_EXTENSIONS, ERASURE_MAX_TARGETS,
    ERASURE_OBLIGATION_SET_MAX_BYTES, ERASURE_OBLIGATION_SET_TAG_V1, ERASURE_OBLIGATION_TAG_V1,
    ERASURE_PORTABLE_RECORD_MAX_BYTES, ERASURE_RECEIPT_MAX_BYTES,
    ERASURE_RECEIPT_PROVENANCE_TAG_V1, ERASURE_RECEIPT_TAG_V1, ERASURE_RECOVERY_ERROR_TAG_V1,
    ERASURE_REJOIN_PROOF_TAG_V1, ERASURE_REQUEST_OR_STATE_MAX_BYTES,
    ERASURE_RETRY_ADMISSION_MAX_BYTES, ERASURE_RETRY_ADMISSION_TAG_V1,
    ERASURE_SCOPE_COMMITMENT_TAG_V1, ERASURE_SCOPE_EXTENSION_HEAD_TAG_V1,
    ERASURE_SCOPE_EXTENSION_TAG_V1, ERASURE_SCOPE_LEDGER_MAX_BYTES, MAX_ARTIFACT_GRAPH_DEPTH_V1,
    MAX_ARTIFACT_GRAPH_EDGES_V1, MAX_ARTIFACT_GRAPH_KEYS_V1, MAX_ARTIFACT_GRAPH_REGISTRATIONS_V1,
    MAX_ARTIFACT_GRAPH_REGISTRATION_BYTES_V1, MAX_ARTIFACT_REGISTRATION_BATCH_BYTES_V1,
    MAX_ARTIFACT_REGISTRATION_BYTES_V1, MAX_ARTIFACT_REGISTRATION_CHILDREN_V1,
    MAX_ARTIFACT_REGISTRATION_KEYS_V1,
};
pub use error::CoreError;
pub use event::{
    CanonicalBytes, Determinism, Event, EventDraft, EventOriginV1, Kind, RunMode, SchemaVersion,
};
pub use executable_budget::{
    ExecutableBudgetErrorV1, ExecutableBudgetPolicyInputV1, ExecutableBudgetPolicyV1,
    FidelityBudgetV1, PluginCpuReservationV1, WorkloadProfileV1,
    MAX_EXECUTABLE_BUDGET_POLICY_BYTES_V1, MAX_PLUGIN_CPU_RESERVATIONS_V1,
};
pub use fork_admission::{
    ForkAdmissionErrorV1, ForkAdmissionOperationKindV1, ForkAdmissionOperationResultV1,
    ForkAdmissionReceiptV1, ForkAuthorityOriginV1, PrincipalOwnerBindingInputV1,
    PrincipalOwnerBindingV1, MAX_PRINCIPAL_OWNER_BINDING_BYTES_V1,
};
pub use fork_admission_authority::{
    ForkAdmissionAuthorityCodecErrorV1, ForkAdmissionHostRecordV1,
    ForkAdmissionInitializeChallengeV1, ForkAdmissionOpenChallengeV1,
    MAX_FORK_ADMISSION_HOST_RECORD_BYTES_V1, MAX_FORK_ADMISSION_INITIALIZE_CHALLENGE_BYTES_V1,
    MAX_FORK_ADMISSION_OPEN_CHALLENGE_BYTES_V1,
};
pub use fork_admission_command::{
    ForkAdmissionCommandCodecErrorV1, ForkAdmissionCommandFactsV1, ForkAdmissionHostCommandV1,
    ForkAdmissionRecoveryCommandFactsV1, ForkAdmissionRecoveryCommandV1,
    ForkAdmissionRecoveryProofV1, ForkCreateCommandV1, ForkCreateCommitmentInputV1,
    PrincipalOwnerCommandV1, PrincipalOwnerCommitmentInputV1,
    MAX_FORK_ADMISSION_HOST_COMMAND_BYTES_V1, MAX_FORK_ADMISSION_RECOVERY_COMMAND_BYTES_V1,
    MAX_FORK_ADMISSION_RECOVERY_PROOF_BYTES_V1, MAX_FORK_CREATE_COMMAND_BYTES_V1,
    MAX_PRINCIPAL_OWNER_COMMAND_BYTES_V1,
};
pub use fork_attribution::{
    ForkAdmissionRecordInputV1, ForkAdmissionRecordV1, ForkAttributionCodecErrorV1,
    ForkAttributionOriginV1, ForkReproManifestInputV1, ForkReproManifestV1,
    SignedForkReproManifestV1, MAX_FORK_ADMISSION_RECORD_BYTES_V1,
    MAX_FORK_MANIFEST_INTERVENTIONS_V1, MAX_FORK_REPRO_MANIFEST_BYTES_V1,
    MAX_SIGNED_FORK_REPRO_MANIFEST_BYTES_V1,
};
pub use fork_authentication::{
    AuthenticatedPrincipalRecordV1, ForkAuthenticationAdapterPolicyV1, ForkAuthenticationPolicyV1,
};
pub use fork_event_provenance::{
    EventOriginRecordInputV1, EventOriginRecordV1, ForkAppendOperationInputV1,
    ForkAppendOperationV1, ForkAppendSourceIdentityV1, ForkClassifiedEventV1,
    ForkClassifiedProvenanceV1, ForkClassifierRegistrationInputV1, ForkClassifierRegistrationV1,
    ForkClassifierSourceInputV1, ForkClassifierSourceV1, ForkClassifierTableInputV1,
    ForkClassifierTableV1, ForkEventAppendRequestV1, ForkEventClassificationV1,
    ForkEventClassifierV1, ForkEventOriginKindV1, ForkEventProvenanceErrorV1,
    ForkEventSourceDescriptorV1, ForkEventSourceV1, ForkExternalInputRouteV1,
    ForkInterventionAdmissionInputV1, ForkInterventionAdmissionV1,
    MAX_EVENT_ORIGIN_RECORD_BYTES_V1, MAX_FORK_EVENT_APPEND_OPERATION_BYTES_V1,
    MAX_FORK_EVENT_APPEND_PAYLOAD_BYTES_V1, MAX_FORK_EVENT_CLASSIFIER_REGISTRATION_BYTES_V1,
    MAX_FORK_EVENT_CLASSIFIER_ROUTES_V1, MAX_FORK_EVENT_CLASSIFIER_TABLE_BYTES_V1,
    MAX_FORK_EVENT_REGISTRAR_BYTES_V1, MAX_FORK_EVENT_SOURCE_ROUTE_BYTES_V1,
    MAX_FORK_EVENT_TYPE_BYTES_V1, MAX_FORK_INTERVENTION_ADMISSION_BYTES_V1,
};
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
    KeyRegistrationV1, KeyRegistryEncryptionPortV1, KeyRegistryErrorV1,
    KeyRegistryHistoricalDecryptionPortV1, KeyRegistryPortV1, KeyRegistrySigningPortV1,
    KeyRegistryStateV1, KeyRoleV1, KeyTombstoneV1, OwnerIdV1,
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
pub use pipeline::{
    CommittedPipelineEventV1, PipelineAdmissionBasisDraftV1, PipelineAdmissionBasisV1,
    PipelineAttemptDraftV1, PipelineAttemptIdV1, PipelineAttemptV1, PipelineCommitReceiptV1,
    PipelineContractErrorV1, PipelineDraftBatchV1, PipelineEvidenceRefV1, PipelineIngressV1,
    PipelineObservationAnchorV1, PipelineOutcomeV1, PipelinePreconditionV1,
    PipelineSecurityRevisionsDraftV1, PipelineSecurityRevisionsV1, TentativePipelineResultV1,
    MAX_PIPELINE_DRAFTS_PER_BATCH, MAX_PIPELINE_DRAFT_BATCH_BYTES, PIPELINE_CONTRACT_VERSION_V1,
};
pub use plugin::{
    ActionApprover, ActionRejected, Capability, Plugin, ProposedAction,
    MAX_PROPOSED_ACTION_PAYLOAD_BYTES,
};
pub use recipient_key::{
    recipient_owner_id_from_grantee, RecipientKeyDescriptorErrorV1, RecipientKeyDescriptorV1,
};
pub use state::{Reducer, State, StateRegistry};
pub use store::{
    append_identity_expires_at, checked_append_identity_expires_at, export_timeline,
    export_timeline_cow, export_timeline_own, export_timeline_raw, import_committed_with_rollback,
    import_timeline, import_timeline_with_id, validate_committed_batch, AppendDedupKey,
    AppendDedupScope, AppendIdentity, AppendIntent, AppendOrDuplicateOutcome, EventReadBounds,
    EventStore, PreparedSubjectAppendAuthorizationV1, PurgeOutcome, SeqRange, TimelineExport,
    APPEND_IDENTITY_RETENTION_MICROS,
};
pub use timeline::{Timeline, TimelineMeta, TimelineMode};
pub use timeline_envelope::{
    TimelineEventEnvelopeErrorV1, TimelineEventEnvelopeInputV1, TimelineEventEnvelopeV1,
    TimelineEventVerificationV1, MAX_TIMELINE_EVENT_ENVELOPE_BYTES_V1,
    MAX_TIMELINE_EVENT_PAYLOAD_BYTES_V1,
};
pub use world_consumer_set::{
    WorldConsumerSetErrorV1, WorldConsumerSetInputV1, WorldConsumerSetV1, WorldConsumerV1,
    WorldProducerV1, WORLD_CONSUMER_SET_MAX_BYTES, WORLD_CONSUMER_SET_MAX_CONSUMERS,
    WORLD_CONSUMER_SET_MAX_CONSUMER_ID_BYTES, WORLD_CONSUMER_SET_MAX_PRODUCERS_OR_VIEWS,
};
pub use world_dependency_directory::{
    WorldDependencyBranchChildV1, WorldDependencyBranchErrorV1, WorldDependencyBranchInputV1,
    WorldDependencyBranchV1, WorldDependencyKeyV1, MAX_WORLD_DEPENDENCY_DIRECTORY_BYTES_V1,
    MAX_WORLD_DEPENDENCY_DIRECTORY_CHILDREN_V1, MAX_WORLD_DEPENDENCY_DIRECTORY_HEIGHT_V1,
};
pub use world_history::{
    WorldEventOccurrenceV1, WorldEventPageV1, WorldEventRowInputV1, WorldEventRowV1,
    WorldHistoryBranchInputV1, WorldHistoryBranchV1, WorldHistoryChildRecordRefV1,
    WorldHistoryChildV1, WorldHistoryErrorV1, MAX_WORLD_EVENT_OCCURRENCE_BYTES_V1,
    MAX_WORLD_EVENT_PAGE_BYTES_V1, MAX_WORLD_EVENT_PAGE_ROWS_V1, MAX_WORLD_EVENT_TYPE_BYTES_V1,
    MAX_WORLD_HISTORY_BRANCH_BYTES_V1, MAX_WORLD_HISTORY_BRANCH_CHILDREN_V1,
    MAX_WORLD_HISTORY_HEIGHT_V1,
};
pub use world_key_evidence::{
    WorldKeyEvidenceErrorV1, WorldKeyEvidenceInputV1, WorldKeyEvidenceV1,
    MAX_WORLD_KEY_EVIDENCE_BYTES_V1,
};
pub use world_recording_receipt::{
    WorldRecordingReceiptErrorV1, WorldRecordingReceiptInputV1, WorldRecordingReceiptV1,
    MAX_WORLD_RECORDING_RECEIPT_BYTES_V1,
};
#[cfg(feature = "test-support")]
pub use world_replay::WorldReplayClosureAuthorityV1;
pub use world_replay::{
    WorldReplayAdmissionV1, WorldReplayArtifactObservationV1, WorldReplayClosureErrorV1,
    WorldReplayClosureInputV1, WorldReplayClosureV1, MAX_WORLD_REPLAY_ARTIFACTS_V1,
};
pub use world_replay_handle::{
    WorldReplayHandleErrorV1, WorldReplayHandleInputV1, WorldReplayHandleV1,
    MAX_WORLD_REPLAY_HANDLE_BYTES_V1,
};
pub use world_transform::{
    Wgs84PositionV1, WorldCoordinateV1, WorldGeographicEvidenceCapabilityV1,
    WorldOriginReferenceV1, WorldOriginRegistryV1, WorldOriginV1, WorldTransformError,
    WorldTransformV1,
};
